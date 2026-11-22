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
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/dnsplan"
)

// High availability (contract §12.4 "In HA", plan Task 28 and its fix
// round 1): the address set of every added domain this service holds
// (its enrolled domains, nothing else) follows the front door. The front
// door decides which ingress nodes' addresses the main domain publishes
// (<main>, *.<main>) and writes them into frontdoor-status; the domains
// service reads that ConfigMap as a read-only mount (no Role) and writes
// the same addresses at <d> and *.<d> with each domain's own credentials.
//
// Which documents count (fail closed: anything else changes nothing, keeps
// the last good set and is a status problem — a plan item and one log line):
//   - written by the front door's leader: the key leader and status.json's
//     leader agree (admission lets only the front door's ServiceAccount
//     write the ConfigMap, and only as the pod its token is bound to:
//     kube/admission/policies.yaml portcullis-frontdoor-status);
//   - never older than one seen before: a generation lower than the last
//     one of the same leader, or a written_at before the last accepted
//     document's, is a rollback;
//   - current: written_at at most haStale old (the front door writes at
//     least every 30 s; the kubelet refreshes the mount at its sync period,
//     10 s on Portcullis nodes, §20.11, plus the watch's own lag);
//   - version 1, both names, each with an address, every address public
//     (FRONTDOOR_EXCLUDED_CIDRS) and the public address of an active node
//     of portcullis-cluster-addresses (nodeadm's document, mounted too): a
//     forged document can't point an added domain anywhere else.
//
// How a set moves:
//   - <d> follows <main>'s set and *.<d> follows *.<main>'s;
//   - a name followed for the first time gets the whole set in one step
//     (ruling B); later, one change per name per 60 s: a removal first
//     unless it would leave its type empty, then an addition;
//   - only addresses this service wrote are ever removed (ruling M5): a
//     foreign record at <d> stays, and so does the last address of a type;
//     both are named once as a notice (the plan's address items, the log)
//     and the set counts as converged with them (ruling I1: no records
//     step and no provider read until the front door's set, the live set
//     or the status changes);
//   - append first, then the exact stale value deleted (by record ID where
//     the provider needs it: porkbun, hetzner), through frontdoor.Writer,
//     so every check (the name, public addresses, the last address) runs
//     before the provider call.

// haStatusMax bounds frontdoor-status's status.json.
const haStatusMax = 1 << 20

// haPoll is how often the service reads the mounted documents.
const haPoll = 10 * time.Second

// haStale: a status written longer ago than this (12 of the front door's
// 10 s rounds; it writes at least every 30 s) is stale.
const haStale = 12 * frontdoor.Round

// haWrite bounds one provider write of the follower.
const haWrite = 30 * time.Second

// haSets is a front-door document as the follower judged it: Apex =
// <main>'s addresses, Wild = *.<main>'s. OK false = no change may follow
// it (Err says why).
type haSets struct {
	OK         bool
	Err        string
	Apex, Wild []string
	Leader     string
	Generation int64
	WrittenAt  time.Time
}

// want is the target for owned name n of domain d.
func (h haSets) want(n, d string) []string {
	if strings.EqualFold(strings.TrimSuffix(n, "."), "*."+d) {
		return h.Wild
	}
	return h.Apex
}

// clusterAddrs are the public addresses of portcullis-cluster-addresses'
// active nodes (§20.9).
func clusterAddrs(doc []byte) (map[string]bool, error) {
	var d struct {
		V     int `json:"v"`
		Nodes map[string]struct {
			Public []string `json:"public"`
			State  string   `json:"state"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, errors.New("portcullis-cluster-addresses doesn't decode")
	}
	if d.V != 1 {
		return nil, fmt.Errorf("portcullis-cluster-addresses is version %d, not 1", d.V)
	}
	out := map[string]bool{}
	for _, n := range d.Nodes {
		if n.State != "active" {
			continue
		}
		for _, a := range n.Public {
			if ip, err := netip.ParseAddr(a); err == nil {
				out[ip.String()] = true
			}
		}
	}
	return out, nil
}

// parseFrontdoorStatus judges status.json (exactly one JSON document)
// with the ConfigMap's leader key, at now, against the cluster's node
// addresses: version 1, the leader named twice alike, a write time and a
// generation, both names, each with at least one address, every address
// public (policy) and a node's. Freshness and rollbacks are haRefresh's.
func parseFrontdoorStatus(doc []byte, leaderKey, mainDomain string, policy frontdoor.AddrPolicy, nodes map[string]bool) (haSets, error) {
	var st frontdoor.Status
	if err := json.Unmarshal(doc, &st); err != nil {
		return haSets{}, errors.New("status.json doesn't decode")
	}
	if st.V != 1 {
		return haSets{}, fmt.Errorf("status.json is version %d, not 1", st.V)
	}
	if st.Leader == "" || st.Leader != strings.TrimSpace(leaderKey) {
		return haSets{}, errors.New("status.json's leader isn't the ConfigMap's leader (not the front door's write)")
	}
	if st.WrittenAt.IsZero() || st.Generation <= 0 {
		return haSets{}, errors.New("status.json has no write time or generation")
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
			if !nodes[v] {
				return nil, fmt.Errorf("%s: %s isn't an active node's public address (portcullis-cluster-addresses)", name, v)
			}
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
	return haSets{OK: true, Apex: apex, Wild: wild, Leader: st.Leader, Generation: st.Generation, WrittenAt: st.WrittenAt}, nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, haStatusMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > haStatusMax {
		return nil, errors.New("larger than 1 MiB")
	}
	return b, nil
}

// readFrontdoorStatus reads and judges the mounted documents.
func (s *Service) readFrontdoorStatus() haSets {
	b, err := readSmall(s.cfg.FrontdoorStatusFile)
	if err != nil {
		return haSets{Err: "frontdoor-status isn't readable"}
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return haSets{Err: "frontdoor-status is empty (the front door hasn't written it yet)"}
	}
	leader, err := readSmall(filepath.Join(filepath.Dir(s.cfg.FrontdoorStatusFile), frontdoor.StatusLeaderKey))
	if err != nil {
		return haSets{Err: "frontdoor-status has no leader key (not the front door's write)"}
	}
	cb, err := readSmall(s.cfg.ClusterAddressesFile)
	if err != nil || len(bytes.TrimSpace(cb)) == 0 {
		return haSets{Err: "portcullis-cluster-addresses isn't readable: no address can be checked against the cluster's nodes"}
	}
	nodes, err := clusterAddrs(cb)
	if err != nil {
		return haSets{Err: err.Error()}
	}
	h, err := parseFrontdoorStatus(b, string(leader), s.cfg.MainDomain, s.cfg.AddrPolicy, nodes)
	if err != nil {
		return haSets{Err: "frontdoor-status refused: " + err.Error()}
	}
	return h
}

// haRefresh reads the documents once. A good, current one becomes the
// set to follow (and the last good one); anything else stops every change
// and keeps the last good set (the records check and the plan still use
// it). A change of the set or of the problem kicks the worker or is logged.
func (s *Service) haRefresh() {
	now := s.cfg.Now()
	h := s.readFrontdoorStatus()
	s.mu.Lock()
	if h.OK {
		switch {
		case s.haSeen[h.Leader] > h.Generation:
			h = haSets{Err: fmt.Sprintf("frontdoor-status refused: generation %d of %s is older than %d seen before (a rollback)", h.Generation, h.Leader, s.haSeen[h.Leader])}
		case h.WrittenAt.Before(s.haGood.WrittenAt):
			h = haSets{Err: fmt.Sprintf("frontdoor-status refused: written %s, before the last document (%s)", h.WrittenAt.UTC().Format(time.RFC3339), s.haGood.WrittenAt.UTC().Format(time.RFC3339))}
		case now.Sub(h.WrittenAt) > haStale:
			h = haSets{Err: fmt.Sprintf("frontdoor-status is stale: written %s (%s ago); the front door isn't writing it", h.WrittenAt.UTC().Format(time.RFC3339), now.Sub(h.WrittenAt).Round(time.Second))}
		}
	}
	old := s.ha
	changed := old.OK != h.OK || !slices.Equal(old.Apex, h.Apex) || !slices.Equal(old.Wild, h.Wild)
	if changed || old.Err != h.Err {
		// The plans' address items and notices follow the document: the
		// cached plans (the main domain's included) are rebuilt.
		s.plans = map[string]cachedPlan{}
		s.mainGen++
	}
	s.ha = h
	if h.OK {
		s.haGood = h
		s.haSeen[h.Leader] = h.Generation
	}
	s.mu.Unlock()
	if !h.OK && (old.OK || old.Err != h.Err) {
		s.logf("high availability: %s: the added domains' address sets stay as they are", h.Err)
	}
	if h.OK && changed {
		s.logf("high availability: the front door (%s) publishes %s / %s", h.Leader, strings.Join(h.Apex, ","), strings.Join(h.Wild, ","))
		s.Kick()
	}
}

// haWatch reads the documents every 10 s until ctx ends.
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

// haDueLocked: a change can be made at a name of d (never followed yet, or
// its last change 60 s old) toward a set the follower may follow. A name
// whose only differences are kept records (foreign, or the last of a type)
// is converged: not due. Caller holds mu.
func (s *Service) haDueLocked(d *Domain, now time.Time) bool {
	if !s.cfg.HA || !s.ha.OK {
		return false
	}
	for _, n := range haNames(d.Name) {
		have, followed := d.HAAddrs[n]
		if !followed || now.Sub(d.HAChanged[n]) >= frontdoor.ChangeEvery {
			if len(haNext(n, have, s.ha.want(n, d.Name), d.HAOurs[n], !followed)) > 0 {
				return true
			}
		}
	}
	return false
}

// haNext are the changes that bring have toward want. first (a name never
// followed): every missing address at once. Otherwise one change: the
// lowest stale address this service wrote (ours) whose type keeps another
// of ours or the front door's, else the lowest missing one. A foreign
// address is never removed and never counts as the type's other address.
func haNext(name string, have, want, ours []string, first bool) []frontdoor.Change {
	var stale, missing []string
	for _, a := range have {
		if !slices.Contains(want, a) && slices.Contains(ours, a) {
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
	ch := func(op, a string) frontdoor.Change {
		return frontdoor.Change{Name: name, Op: op, Value: a, Type: frontdoor.AddrType(a)}
	}
	if first {
		var out []frontdoor.Change
		for _, a := range missing {
			out = append(out, ch("add", a))
		}
		return out
	}
	for _, a := range stale {
		// Another value of the type that reaches the cluster (ours or the
		// front door's): a foreign one doesn't count, or the name could be
		// left with only an old server's address.
		others := 0
		for _, b := range have {
			if b != a && frontdoor.AddrType(b) == frontdoor.AddrType(a) && (slices.Contains(ours, b) || slices.Contains(want, b)) {
				others++
			}
		}
		if others > 0 {
			return []frontdoor.Change{ch("remove", a)}
		}
	}
	if len(missing) > 0 {
		return []frontdoor.Change{ch("add", missing[0])}
	}
	return nil
}

// haResidual names the records kept at a converged name: foreign ones
// (this service never wrote them) and its own last address of a type.
func haResidual(name string, have, want, ours []string) []string {
	var out []string
	wantTypes := map[string]bool{}
	for _, a := range want {
		wantTypes[frontdoor.AddrType(a)] = true
	}
	for _, a := range have {
		if slices.Contains(want, a) {
			continue
		}
		t := frontdoor.AddrType(a)
		switch {
		case !slices.Contains(ours, a) && t == "AAAA" && !wantTypes["AAAA"]:
			out = append(out, fmt.Sprintf("foreign AAAA %s at %s kept: the front door publishes IPv4 only (remove it by hand if it doesn't reach this cluster)", a, name))
		case !slices.Contains(ours, a):
			out = append(out, fmt.Sprintf("foreign %s %s at %s kept: Portcullis didn't write it, so it never removes it (remove it by hand if it doesn't reach this cluster)", t, a, name))
		default:
			out = append(out, fmt.Sprintf("%s %s at %s kept: it is the last %s address there and the front door publishes no other", t, a, name, t))
		}
	}
	return out
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
// DELETE's tracking) and each name's live set, last change and own
// addresses afterwards. A result with nil maps (an early error: the set
// wasn't read) changes nothing that was stored.
type haResult struct {
	written, removed []RecordRef
	addrs            map[string][]string
	changed          map[string]time.Time
	ours             map[string][]string
}

// haStep makes the due changes of each name of d toward the front door's
// set h, in zone (haNext: the whole set for a name followed the first
// time, else at most one change per name per 60 s).
func (s *Service) haStep(ctx context.Context, p dnsProvider, d *Domain, zone string, h haSets, now time.Time) (haResult, error) {
	if !h.OK {
		return haResult{}, fmt.Errorf("the front door's address set can't be followed (%s): high availability publishes the added domains' addresses from it", h.Err)
	}
	w := &frontdoor.Writer{Domain: d.Name, Zone: dns.Fqdn(zone), P: p, TTL: frontdoor.TTL(providerMinTTL(d.Provider)), Fence: haFence{}, Policy: s.cfg.AddrPolicy}
	pub, err := w.Published(ctx)
	if err != nil {
		return haResult{}, fmt.Errorf("reading the address set of %s: %w", d.Name, err)
	}
	res := haResult{addrs: map[string][]string{}, changed: maps0(d.HAChanged), ours: map[string][]string{}}
	var errs []error
	for _, n := range haNames(d.Name) {
		res.addrs[n] = pub[n]
		// Our own addresses still there (one removed by hand is no longer ours).
		for _, a := range d.HAOurs[n] {
			if slices.Contains(pub[n], a) {
				res.ours[n] = append(res.ours[n], a)
			}
		}
		_, followed := d.HAAddrs[n]
		if followed && now.Sub(d.HAChanged[n]) < frontdoor.ChangeEvery {
			continue
		}
		changes := haNext(n, pub[n], h.want(n, d.Name), res.ours[n], !followed)
		for _, c := range changes {
			c.T = now
			// An attempt holds off the next one for 60 s too (the front
			// door's rule: a failing provider isn't hammered).
			res.changed[n] = now
			if err := w.Apply(ctx, c); err != nil {
				errs = append(errs, err)
				continue
			}
			ref := RecordRef{Name: libdns.RelativeName(dns.Fqdn(n), dns.Fqdn(zone)), Type: c.Type, Value: c.Value}
			if c.Op == "add" {
				res.written = append(res.written, ref)
				res.addrs[n] = append(slices.Clone(res.addrs[n]), c.Value)
				res.ours[n] = append(res.ours[n], c.Value)
			} else {
				res.removed = append(res.removed, ref)
				res.addrs[n] = slices.DeleteFunc(slices.Clone(res.addrs[n]), func(a string) bool { return a == c.Value })
				res.ours[n] = slices.DeleteFunc(res.ours[n], func(a string) bool { return a == c.Value })
			}
			s.logf("domain %s: high availability: %s %s %s (following the front door)", d.Name, c.Op, n, c.Value)
		}
		sort.Strings(res.addrs[n])
		sort.Strings(res.ours[n])
		if res.addrs[n] == nil {
			res.addrs[n] = []string{}
		}
	}
	return res, errors.Join(errs...)
}

func maps0(m map[string]time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// haNotices are domain d's follower notices: the status problem, if any,
// and the records kept at its converged names (logged once when they
// change). Caller holds mu.
func (s *Service) haNoticesLocked(d *Domain) []string {
	var out []string
	if !s.ha.OK && s.ha.Err != "" {
		out = append(out, s.ha.Err+": the address set isn't following the front door until it is good again")
	}
	if s.haGood.OK {
		for _, n := range haNames(d.Name) {
			if have, ok := d.HAAddrs[n]; ok {
				out = append(out, haResidual(n, have, s.haGood.want(n, d.Name), d.HAOurs[n])...)
			}
		}
	}
	return out
}

// haLogNotices logs d's residual notices once per change.
func (s *Service) haLogNotices(name string) {
	s.mu.Lock()
	d := s.doc.Domains[name]
	var notes []string
	if d != nil && s.haGood.OK {
		for _, n := range haNames(name) {
			if have, ok := d.HAAddrs[n]; ok {
				notes = append(notes, haResidual(n, have, s.haGood.want(n, name), d.HAOurs[n])...)
			}
		}
	}
	key := strings.Join(notes, "\n")
	logIt := key != s.haNoted[name]
	s.haNoted[name] = key
	s.mu.Unlock()
	if logIt {
		for _, n := range notes {
			s.logf("domain %s: high availability: %s", name, n)
		}
	}
}

// haSpecAddrs is the plan's wanted address set in HA (dnsplan.Spec.HA):
// the last good front-door set (none: unknown) and the notices — the
// status problem and, for domain d (nil: the main domain), its kept records.
func (s *Service) haSpecAddrs(d *Domain) *dnsplan.HAAddrs {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &dnsplan.HAAddrs{}
	if d != nil {
		out.Notices = s.haNoticesLocked(d)
	} else if !s.ha.OK && s.ha.Err != "" {
		out.Notices = []string{s.ha.Err + ": the added domains' address sets aren't following the front door"}
	}
	if !s.haGood.OK {
		return out
	}
	for _, a := range s.haGood.Apex {
		out.Apex = append(out.Apex, netip.MustParseAddr(a))
	}
	for _, a := range s.haGood.Wild {
		out.Wild = append(out.Wild, netip.MustParseAddr(a))
	}
	return out
}

// checkRecordsHA: every resolver answers <d> and a name under *.<d> with
// at least one A, and only addresses allowed there (allowed).
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
// — what the follower last read there (its own and the kept records) and
// what the last good front-door document publishes.
func (s *Service) haAllowed(name string) map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	d := s.doc.Domains[name]
	for _, n := range haNames(name) {
		if d != nil {
			out[n] = append(out[n], d.HAAddrs[n]...)
		}
		if s.haGood.OK {
			out[n] = append(out[n], s.haGood.want(n, name)...)
		}
	}
	return out
}
