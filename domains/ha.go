package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/dnsplan"
)

// High availability (contract §12.4 "In HA", plan Task 28): the address
// set of every added domain follows the front door. The front door
// decides which ingress nodes' addresses the main domain publishes
// (<main>, *.<main>) and writes them into frontdoor-status; the domains
// service reads that document (a read-only ConfigMap mount, refreshed by
// the kubelet within ~10 s; no Role) and writes the same addresses at
// <d> and *.<d> of each added domain with that domain's own credentials:
//   - <d> follows <main>'s set and *.<d> follows *.<main>'s;
//   - one change per name per 60 s (an add or a remove, as the front
//     door), a removal first unless it would leave its type empty, then
//     an addition; an address the front door stopped publishing (a dead
//     node, a removed one) is removed, never the last of its type;
//   - append first, delete the exact stale value (by record ID where the
//     provider needs it: porkbun, hetzner), through frontdoor.Writer, so
//     every check (public addresses only, the name, the last address)
//     runs before the provider call;
//   - fail closed: an unreadable, malformed or empty status, or one with
//     an address that isn't public, changes nothing (the sets stay as
//     they are) and a new domain gets no address set until it is good.

// haStatusMax bounds frontdoor-status's status.json.
const haStatusMax = 1 << 20

// haPoll is how often the service reads frontdoor-status (the kubelet
// refreshes the mount within ~10 s).
const haPoll = 10 * time.Second

// haWrite bounds one provider write of the follower.
const haWrite = 30 * time.Second

// haSets is the front door's published set (the follower's target):
// Apex = <main>'s addresses, Wild = *.<main>'s. OK false = unknown (Err
// says why).
type haSets struct {
	OK         bool
	Err        string
	Apex, Wild []string
	doc        string
}

// want is the target for owned name n of domain d.
func (h haSets) want(n, d string) []string {
	if strings.EqualFold(strings.TrimSuffix(n, "."), "*."+d) {
		return h.Wild
	}
	return h.Apex
}

// parseFrontdoorStatus reads the front door's sets from status.json:
// version 1, both names present, each with at least one address, every
// address public (policy) — anything else is refused whole.
func parseFrontdoorStatus(doc []byte, mainDomain string, policy frontdoor.AddrPolicy) (haSets, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	var st frontdoor.Status
	if err := dec.Decode(&st); err != nil {
		return haSets{}, errors.New("status.json doesn't decode")
	}
	if st.V != 1 {
		return haSets{}, fmt.Errorf("status.json is version %d, not 1", st.V)
	}
	get := func(name string) ([]string, error) {
		ns, ok := st.Names[name]
		if !ok {
			return nil, fmt.Errorf("status.json has no address set for %s", name)
		}
		var out []string
		for _, a := range ns.Addresses {
			if err := policy.Check(a); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			v := netip.MustParseAddr(a).String()
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("status.json has no address for %s", name)
		}
		sort.Strings(out)
		return out, nil
	}
	apex, err := get(mainDomain)
	if err != nil {
		return haSets{}, err
	}
	wild, err := get("*." + mainDomain)
	if err != nil {
		return haSets{}, err
	}
	return haSets{OK: true, Apex: apex, Wild: wild, doc: string(doc)}, nil
}

// readFrontdoorStatus reads and parses the mounted status file.
func (s *Service) readFrontdoorStatus() haSets {
	f, err := os.Open(s.cfg.FrontdoorStatusFile)
	if err != nil {
		return haSets{Err: "frontdoor-status isn't readable"}
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, haStatusMax+1))
	if err != nil || len(b) > haStatusMax {
		return haSets{Err: "frontdoor-status isn't readable (or larger than 1 MiB)"}
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return haSets{Err: "frontdoor-status is empty (the front door hasn't written it yet)"}
	}
	h, err := parseFrontdoorStatus(b, s.cfg.MainDomain, s.cfg.AddrPolicy)
	if err != nil {
		return haSets{Err: "frontdoor-status refused: " + err.Error()}
	}
	return h
}

// haRefresh reads frontdoor-status once; a change of the sets kicks the
// worker. A refused document keeps nothing of the last good one: no
// follower change runs on it (fail closed).
func (s *Service) haRefresh() {
	h := s.readFrontdoorStatus()
	s.mu.Lock()
	old := s.ha
	s.ha = h
	changed := old.OK != h.OK || !slices.Equal(old.Apex, h.Apex) || !slices.Equal(old.Wild, h.Wild)
	s.mu.Unlock()
	if !h.OK && (old.OK || old.Err != h.Err) {
		s.logf("high availability: %s: the added domains' address sets stay as they are", h.Err)
	}
	if h.OK && changed {
		s.logf("high availability: the front door publishes %s / %s", strings.Join(h.Apex, ","), strings.Join(h.Wild, ","))
		s.Kick()
	}
}

// haWatch reads frontdoor-status every 10 s until ctx ends.
func (s *Service) haWatch(ctx context.Context) {
	t := time.NewTicker(haPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.haRefresh()
		}
	}
}

// haNames are the follower's names of d.
func haNames(d string) []string { return []string{d, "*." + d} }

// haDueLocked: a domain whose address set doesn't match the front door's
// at a name whose last change is 60 s old. Caller holds mu.
func (s *Service) haDueLocked(d *Domain, now time.Time) bool {
	if !s.cfg.HA || !s.ha.OK {
		return false
	}
	for _, n := range haNames(d.Name) {
		if !sameAddrs(d.HAAddrs[n], s.ha.want(n, d.Name)) && now.Sub(d.HAChanged[n]) >= frontdoor.ChangeEvery {
			return true
		}
	}
	return false
}

func sameAddrs(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

// haNext is the one change that brings have toward want: the lowest
// stale value whose type keeps another value, else the lowest missing one.
func haNext(name string, have, want []string) *frontdoor.Change {
	var stale, missing []string
	for _, a := range have {
		if !slices.Contains(want, a) {
			stale = append(stale, a)
		}
	}
	for _, a := range want {
		if !slices.Contains(have, a) {
			missing = append(missing, a)
		}
	}
	sort.Strings(stale)
	sort.Strings(missing)
	for _, a := range stale {
		others := 0
		for _, b := range have {
			if b != a && frontdoor.AddrType(b) == frontdoor.AddrType(a) {
				others++
			}
		}
		if others > 0 {
			return &frontdoor.Change{Name: name, Op: "remove", Value: a, Type: frontdoor.AddrType(a)}
		}
	}
	if len(missing) > 0 {
		return &frontdoor.Change{Name: name, Op: "add", Value: missing[0], Type: frontdoor.AddrType(missing[0])}
	}
	return nil
}

// haFence lets the follower write: the domains service is one replica
// (Recreate, its RWO volume), so it holds no Lease; each write gets a
// bounded context.
type haFence struct{}

func (haFence) Leading() bool { return true }

func (haFence) WriteContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	c, cancel := context.WithTimeout(ctx, haWrite)
	return c, cancel, nil
}

// haResult is one follower step: the records written and removed (for
// DELETE's tracking) and each name's set and last change afterwards.
type haResult struct {
	written, removed []RecordRef
	addrs            map[string][]string
	changed          map[string]time.Time
}

// haStep makes at most one change per name of d (each name whose last
// change is 60 s old) toward the front door's set h, in zone.
func (s *Service) haStep(ctx context.Context, p dnsProvider, d *Domain, zone string, h haSets, now time.Time) (haResult, error) {
	res := haResult{addrs: map[string][]string{}, changed: map[string]time.Time{}}
	if !h.OK {
		return res, fmt.Errorf("the front door's address set is unknown (%s): high availability publishes the added domains' addresses from it", h.Err)
	}
	w := &frontdoor.Writer{Domain: d.Name, Zone: dns.Fqdn(zone), P: p, TTL: frontdoor.TTL(providerMinTTL(d.Provider)), Fence: haFence{}, Policy: s.cfg.AddrPolicy}
	pub, err := w.Published(ctx)
	if err != nil {
		return res, fmt.Errorf("reading the address set of %s: %w", d.Name, err)
	}
	var errs []error
	for _, n := range haNames(d.Name) {
		res.addrs[n] = pub[n]
		if t, ok := d.HAChanged[n]; ok {
			res.changed[n] = t
		}
		if now.Sub(d.HAChanged[n]) < frontdoor.ChangeEvery {
			continue
		}
		c := haNext(n, pub[n], h.want(n, d.Name))
		if c == nil {
			continue
		}
		c.T = now
		if err := w.Apply(ctx, *c); err != nil {
			errs = append(errs, err)
			// An attempt holds off the next one for 60 s too (the
			// front door's rule: a failing provider isn't hammered).
			res.changed[n] = now
			continue
		}
		ref := RecordRef{Name: libdns.RelativeName(dns.Fqdn(n), dns.Fqdn(zone)), Type: c.Type, Value: c.Value}
		if c.Op == "add" {
			res.written = append(res.written, ref)
			res.addrs[n] = append(slices.Clone(pub[n]), c.Value)
		} else {
			res.removed = append(res.removed, ref)
			res.addrs[n] = slices.DeleteFunc(slices.Clone(pub[n]), func(a string) bool { return a == c.Value })
		}
		sort.Strings(res.addrs[n])
		res.changed[n] = now
		s.logf("domain %s: high availability: %s %s %s (following the front door)", d.Name, c.Op, n, c.Value)
	}
	return res, errors.Join(errs...)
}

// haSpecAddrs is the plan's wanted address set in HA (dnsplan.Spec.HA):
// the front door's, or an empty one while it is unknown.
func (s *Service) haSpecAddrs() *dnsplan.HAAddrs {
	s.mu.Lock()
	h := s.ha
	s.mu.Unlock()
	out := &dnsplan.HAAddrs{}
	if !h.OK {
		return out
	}
	for _, a := range h.Apex {
		out.Apex = append(out.Apex, netip.MustParseAddr(a))
	}
	for _, a := range h.Wild {
		out.Wild = append(out.Wild, netip.MustParseAddr(a))
	}
	return out
}

// checkRecordsHA: every resolver answers <d> and a name under *.<d> with
// at least one A, and only addresses the follower published or the front
// door publishes now (a removed one may still be cached: polled again
// until its TTL ran out).
func (s *Service) checkRecordsHA(ctx context.Context, name string, allowed map[string][]string) error {
	c := &dns.Client{Timeout: 5 * time.Second}
	for _, resolver := range s.cfg.Resolvers {
		for _, n := range haNames(name) {
			host := n
			if strings.HasPrefix(n, "*.") {
				host = probeLabel + "." + name
			}
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(host), qt)
				m.RecursionDesired = true
				in, _, err := c.ExchangeContext(ctx, m, resolver)
				if err != nil {
					return fmt.Errorf("%s at %s: %w", host, resolver, err)
				}
				var got []string
				for _, rr := range in.Answer {
					switch v := rr.(type) {
					case *dns.A:
						got = append(got, v.A.String())
					case *dns.AAAA:
						got = append(got, v.AAAA.String())
					}
				}
				sort.Strings(got)
				if qt == dns.TypeA && len(got) == 0 {
					return fmt.Errorf("%s A at %s has no address yet", host, resolver)
				}
				for _, g := range got {
					if !slices.Contains(allowed[n], g) {
						return fmt.Errorf("%s %s at %s is %v: %s isn't an address the front door publishes", host, dns.TypeToString[qt], resolver, got, g)
					}
				}
			}
		}
	}
	return nil
}

// haAllowed: per name of domain name, the addresses its records may show
// — what the follower last published there and what the front door
// publishes now.
func (s *Service) haAllowed(name string) map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	d := s.doc.Domains[name]
	for _, n := range haNames(name) {
		if d != nil {
			out[n] = append(out[n], d.HAAddrs[n]...)
		}
		if s.ha.OK {
			out[n] = append(out[n], s.ha.want(n, name)...)
		}
	}
	return out
}
