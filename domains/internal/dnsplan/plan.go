// Package dnsplan is the DNS plan (contract §12.2): for one Portcullis
// name, the records Portcullis wants (record sets), what is live at the
// provider and at the public resolvers, the status of every record, the
// records under the name that aren't Portcullis' (foreign), the CAA
// judgement and the DNSSEC state — and the apply step that writes the due
// sets. The domains service and the one-shot `domains dns` tool share it.
package dnsplan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/internal/dnssec"
)

// Record sets.
const (
	SetAddress = "address"
	SetCAA     = "caa"
	SetNoMail  = "nomail"
)

// Sets lists every set, in apply order.
var Sets = []string{SetAddress, SetCAA, SetNoMail}

// TTLs per set (spec §3).
const (
	TTLAddress = 300 * time.Second
	TTLCAA     = 300 * time.Second
	TTLNoMail  = 3600 * time.Second
)

const lookupTimeout = 5 * time.Second

// ProbeLabel names the host checked under *.<d> (as the records check).
const ProbeLabel = "portcullis-probe"

type Status string

const (
	StatusOK      Status = "ok"
	StatusMissing Status = "missing"
	StatusWrong   Status = "wrong"
	StatusForeign Status = "foreign"
	StatusUnknown Status = "unknown"
)

type Severity string

const (
	SevOK      Severity = "ok"
	SevInfo    Severity = "info"
	SevWarning Severity = "warning"
	SevProblem Severity = "problem"
)

type Fix string

const (
	FixAuto   Fix = "auto"
	FixManual Fix = "manual"
	FixNone   Fix = "none"
)

// Item is one row of the plan.
type Item struct {
	Set      string   `json:"set"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Want     []string `json:"want"`
	Live     []string `json:"live"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity"`
	Fix      Fix      `json:"fix"`
	Steps    []string `json:"steps"`
}

// CAAInfo: the issuer, the account URI the plan pins (the wanted one,
// "" = CA-only) and whether the CA would issue for <d> and *.<d>.
type CAAInfo struct {
	Issuer     string `json:"issuer"`
	AccountURI string `json:"account_uri"`
	WouldIssue bool   `json:"would_issue"`
}

// DNSSECInfo is the chain check with the guidance left.
type DNSSECInfo struct {
	State           dnssec.State `json:"state"`
	Zone            string       `json:"zone"`
	ProviderCanSign bool         `json:"provider_can_sign"`
	DS              []dnssec.DS  `json:"ds"`
	Steps           []string     `json:"steps"`
}

// Plan is the plan object (contract §12.2).
type Plan struct {
	Name      string     `json:"name"`
	CheckedAt time.Time  `json:"checked_at"`
	CanWrite  bool       `json:"can_write"`
	Items     []Item     `json:"items"`
	CAA       CAAInfo    `json:"caa"`
	DNSSEC    DNSSECInfo `json:"dnssec"`
}

// Ref is a record relative to its zone; Value is libdns RR().Data.
type Ref struct{ Name, Type, Value string }

// Spec is what Portcullis wants at one name.
type Spec struct {
	Name       string
	IPv4, IPv6 netip.Addr
	// CAA: the caa set is on; Issuer "" = unknown CA (nothing written,
	// nothing judged).
	CAA        bool
	Issuer     string
	AccountURI string
	IODEF      string
	NoMail     bool
	// Owned: the CAA entries an enrolled domain wrote (removed with CAA
	// off). Main: the main domain (removal by signature instead).
	Owned []Ref
	Main  bool
}

// Provider is what the plan needs from a libdns provider.
type Provider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordDeleter
}

// Input of Build and Apply.
type Input struct {
	Spec Spec
	// Zone: the DNS zone holding the name (FQDN); "" = found by SOA.
	Zone string
	// Provider: nil = read-only (public checks only, manual steps).
	Provider Provider
	// DNSSEC: the provider's DNSSEC status reader (nil = none).
	DNSSEC       dnssec.StatusReader
	CanSign      bool
	ProviderName string
	Resolvers    []string
	Now          time.Time
}

func fqdn(n string) string { return dns.Fqdn(strings.ToLower(strings.TrimSuffix(n, "."))) }

func bare(n string) string { return strings.TrimSuffix(strings.ToLower(n), ".") }

// Wanted is every record Portcullis wants, by set (absolute names with a
// trailing dot). No caa key with CAA off or an unknown CA.
func Wanted(s Spec) map[string][]libdns.Record {
	d := fqdn(s.Name)
	out := map[string][]libdns.Record{}
	for _, n := range []string{d, "*." + d} {
		for _, ip := range []netip.Addr{s.IPv4, s.IPv6} {
			if ip.IsValid() {
				out[SetAddress] = append(out[SetAddress], libdns.Address{Name: n, TTL: TTLAddress, IP: ip})
			}
		}
	}
	if s.CAA && s.Issuer != "" {
		for _, c := range ownCAA(s) {
			c.Name = d
			out[SetCAA] = append(out[SetCAA], c)
		}
	}
	if s.NoMail {
		out[SetNoMail] = []libdns.Record{
			libdns.MX{Name: d, TTL: TTLNoMail, Preference: 0, Target: "."},
			libdns.TXT{Name: d, TTL: TTLNoMail, Text: spfNone},
			libdns.TXT{Name: "_dmarc." + d, TTL: TTLNoMail, Text: dmarcReject},
		}
	}
	return out
}

const (
	spfNone     = "v=spf1 -all"
	dmarcReject = "v=DMARC1; p=reject;"
)

func isSPF(txt string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1")
}

// ── live data ───────────────────────────────────────────

// liveRec is a provider record with its absolute name.
type liveRec struct {
	abs string // bare absolute name
	rr  libdns.RR
}

func providerRecords(ctx context.Context, p Provider, zone, name string) ([]liveRec, error) {
	recs, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	d := bare(name)
	var out []liveRec
	for _, r := range recs {
		rr := r.RR()
		abs := bare(libdns.AbsoluteName(rr.Name, zone))
		if abs == d || strings.HasSuffix(abs, "."+d) {
			out = append(out, liveRec{abs: abs, rr: rr})
		}
	}
	return out, nil
}

func pick(live []liveRec, name, typ string) []libdns.RR {
	var out []libdns.RR
	for _, l := range live {
		if l.abs == bare(name) && strings.EqualFold(l.rr.Type, typ) {
			out = append(out, l.rr)
		}
	}
	return out
}

// resolverView is what every resolver answers for one (name, type).
type resolverView struct {
	vals  [][]string // per resolver
	nx    bool       // some resolver said NXDOMAIN
	err   error
	cname []string // CNAME targets seen
}

func rrData(rr dns.RR) (string, bool) {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String(), true
	case *dns.AAAA:
		return v.AAAA.String(), true
	case *dns.CAA:
		return libdns.CAA{Flags: v.Flag, Tag: v.Tag, Value: v.Value}.RR().Data, true
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, v.Mx), true
	case *dns.TXT:
		return strings.Join(v.Txt, ""), true
	}
	return "", false
}

// lookup asks every resolver on its own (all must agree for "ok").
func lookup(ctx context.Context, resolvers []string, name string, qt uint16) resolverView {
	var v resolverView
	if len(resolvers) == 0 {
		v.err = errors.New("no resolvers configured")
		return v
	}
	for _, r := range resolvers {
		in, err := exchange(ctx, r, name, qt)
		if err != nil {
			v.err = err
			return v
		}
		if in.Rcode == dns.RcodeNameError {
			v.nx = true
		}
		var vals []string
		for _, rr := range in.Answer {
			if rr.Header().Rrtype != qt {
				if c, ok := rr.(*dns.CNAME); ok {
					v.cname = append(v.cname, c.Target)
				}
				continue
			}
			if s, ok := rrData(rr); ok {
				vals = append(vals, s)
			}
		}
		sort.Strings(vals)
		v.vals = append(v.vals, vals)
	}
	return v
}

func sameSet(a, b []string) bool {
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\x00") == strings.Join(y, "\x00")
}

// ── Build ───────────────────────────────────────────────

// Build reads the live state and returns the plan. It never writes.
func Build(ctx context.Context, in Input) Plan {
	s := in.Spec
	d := bare(s.Name)
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	p := Plan{Name: d, CheckedAt: now.UTC(), CanWrite: in.Provider != nil, Items: []Item{},
		CAA: CAAInfo{Issuer: s.Issuer, AccountURI: s.AccountURI}}
	fix := FixManual
	if in.Provider != nil {
		fix = FixAuto
	}
	zone := in.Zone
	if zone == "" && in.Provider != nil {
		zone, _ = dnssec.FindZone(ctx, in.Resolvers, d)
	}
	var live []liveRec
	var liveErr error
	if in.Provider != nil {
		if zone == "" {
			liveErr = errors.New("the DNS zone of " + d + " wasn't found")
		} else {
			live, liveErr = providerRecords(ctx, in.Provider, zone, d)
		}
		if liveErr != nil {
			p.Items = append(p.Items, Item{Set: SetAddress, Name: d, Type: "", Want: []string{}, Live: []string{}, Status: StatusUnknown, Severity: SevWarning, Fix: FixNone,
				Steps: []string{fmt.Sprintf("reading the records at %s failed: %v", in.ProviderName, liveErr)}})
		}
	}
	cnameAt := func(n string) []libdns.RR { return pick(live, n, "CNAME") }

	p.Items = append(p.Items, addressItems(ctx, in, d, fix, cnameAt)...)
	p.Items = append(p.Items, caaItems(ctx, in, d, zone, fix, live)...)
	p.Items = append(p.Items, nomailItems(ctx, in, d, fix)...)
	if in.Provider != nil && liveErr == nil {
		p.Items = append(p.Items, foreignItems(ctx, in, d, live)...)
	}
	p.CAA.WouldIssue = wouldIssue(ctx, in.Resolvers, d, s.Issuer, s.AccountURI)
	p.DNSSEC = dnssecInfo(ctx, in, d)
	return p
}

// wouldIssue: the CA would issue for <d> and *.<d> at EVERY resolver,
// each asked on its own (one may still cache an old pin), as waitCAA.
func wouldIssue(ctx context.Context, resolvers []string, d, issuer, uri string) bool {
	if issuer == "" || len(resolvers) == 0 || (uri != "" && !ValidAccountURI(uri)) {
		return false
	}
	for _, r := range resolvers {
		for _, n := range []string{d, "*." + d} {
			_, rrs, err := EffectiveCAA(ctx, []string{r}, n)
			if err != nil || !WouldIssue(rrs, issuer, uri, strings.HasPrefix(n, "*.")) {
				return false
			}
		}
	}
	return true
}

// diffSteps: the lines that make live equal want.
func diffSteps(typ, name string, want, live []string, ttl time.Duration) []string {
	var out []string
	for _, w := range want {
		if !contains(live, w) {
			out = append(out, fmt.Sprintf("add %s %s %s (TTL %d)", typ, name, w, int(ttl/time.Second)))
		}
	}
	for _, l := range live {
		if !contains(want, l) {
			out = append(out, fmt.Sprintf("remove %s %s %s", typ, name, l))
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// judge compares every resolver's answer with want: the worst wins.
func judge(v resolverView, want []string) (Status, []string) {
	if v.err != nil {
		return StatusUnknown, []string{}
	}
	st, liveVals := StatusOK, v.vals[0]
	for _, vals := range v.vals {
		switch {
		case sameSet(vals, want):
		case len(vals) == 0:
			if st == StatusOK {
				st, liveVals = StatusMissing, vals
			}
		default:
			st, liveVals = StatusWrong, vals
		}
	}
	if liveVals == nil {
		liveVals = []string{}
	}
	return st, liveVals
}

// cloudflareRanges are Cloudflare's published proxy ranges
// (https://www.cloudflare.com/ips/): a live address in them means the
// record is proxied (orange cloud), so Portcullis isn't reached directly.
var cloudflareRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func cloudflareAddr(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	for _, p := range cloudflareRanges {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func addressItems(ctx context.Context, in Input, d string, fix Fix, cnameAt func(string) []libdns.RR) []Item {
	s := in.Spec
	var out []Item
	for _, n := range []string{d, "*." + d} {
		qname := n
		if n != d {
			qname = ProbeLabel + "." + d
		}
		for _, t := range []struct {
			typ string
			qt  uint16
			ip  netip.Addr
		}{{"A", dns.TypeA, s.IPv4}, {"AAAA", dns.TypeAAAA, s.IPv6}} {
			it := Item{Set: SetAddress, Name: n, Type: t.typ, Want: []string{}, Live: []string{}, Steps: []string{}}
			if t.ip.IsValid() {
				it.Want = []string{t.ip.String()}
			}
			// Without the IPv4 the server's addresses are unknown (the
			// service gets none until a domain is enrolled): A and AAAA
			// alike can't be judged — an IPv6 published by hand isn't
			// "wrong" just because the service doesn't know it.
			if !s.IPv4.IsValid() {
				it.Want = []string{}
				// Info, not Warning: nothing failed (never a failed lookup).
				it.Status, it.Severity, it.Fix = StatusUnknown, SevInfo, FixNone
				it.Steps = []string{"the server's public addresses are unknown (./portcullis up detects them once a domain is enrolled, or set PORTCULLIS_PUBLIC_IPV4 / _IPV6 in .env)"}
				out = append(out, it)
				continue
			}
			v := lookup(ctx, in.Resolvers, qname, t.qt)
			it.Status, it.Live = judge(v, it.Want)
			if c := cnameAt(n); len(c) > 0 {
				it.Status, it.Severity, it.Fix = StatusForeign, SevProblem, FixManual
				it.Steps = []string{fmt.Sprintf("remove the CNAME %s → %s first: Portcullis can't put A/AAAA records next to it", n, c[0].Data)}
				out = append(out, it)
				continue
			}
			if t.typ == "AAAA" && len(it.Want) == 0 && it.Status == StatusOK {
				continue // no IPv6 and none published: nothing to show
			}
			switch it.Status {
			case StatusOK:
				it.Severity, it.Fix = SevOK, FixNone
			case StatusUnknown:
				it.Severity, it.Fix = SevWarning, FixNone
				it.Steps = []string{"lookup failed (retry): " + v.err.Error()}
			default:
				it.Severity, it.Fix = SevProblem, fix
				it.Steps = diffSteps(t.typ, n, it.Want, it.Live, TTLAddress)
				for _, l := range it.Live {
					if cloudflareAddr(l) {
						it.Steps = append(it.Steps, fmt.Sprintf("%s is proxied (orange cloud) at Cloudflare: switch it to DNS only", n))
						break
					}
				}
			}
			out = append(out, it)
		}
	}
	return out
}

func toCAA(vals []string) []libdns.CAA {
	var out []libdns.CAA
	for _, v := range vals {
		rr, err := libdns.RR{Type: "CAA", Data: v}.Parse()
		if err != nil {
			continue
		}
		if c, ok := rr.(libdns.CAA); ok {
			out = append(out, c)
		}
	}
	return out
}

func caaData(cs []libdns.CAA) []string {
	out := []string{}
	for _, c := range cs {
		out = append(out, c.RR().Data)
	}
	sort.Strings(out)
	return out
}

func caaItems(ctx context.Context, in Input, d, zone string, fix Fix, live []liveRec) []Item {
	s := in.Spec
	if s.CAA && s.Issuer == "" {
		return []Item{{Set: SetCAA, Name: d, Type: "CAA", Want: []string{}, Live: []string{}, Status: StatusUnknown, Severity: SevInfo, Fix: FixNone,
			Steps: []string{"CAA skipped: unknown CA (set DNS_CAA_ISSUER to its CAA issuer domain)"}}}
	}
	v := lookup(ctx, in.Resolvers, d, dns.TypeCAA)
	if v.err != nil {
		return []Item{{Set: SetCAA, Name: d, Type: "CAA", Want: []string{}, Live: []string{}, Status: StatusUnknown, Severity: SevWarning, Fix: FixNone,
			Steps: []string{"lookup failed (retry): " + v.err.Error()}}}
	}
	// The worst resolver view (a resolver still caching an old pin).
	liveVals := v.vals[0]
	if !s.CAA {
		var rm []libdns.CAA
		for _, vals := range v.vals {
			if r := removalCAA(toCAA(vals), s); len(r) > 0 {
				rm, liveVals = r, vals
			}
		}
		if len(rm) == 0 {
			return nil
		}
		return []Item{{Set: SetCAA, Name: d, Type: "CAA", Want: []string{}, Live: caaData(toCAA(liveVals)), Status: StatusWrong, Severity: SevInfo, Fix: fix,
			Steps: append([]string{"CAA is off (DNS_CAA=false): remove the entries Portcullis wrote"}, diffSteps("CAA", d, nil, caaData(rm), TTLCAA)...)}}
	}
	// Judge every resolver's view; the worst wins (a resolver still
	// caching an old pin keeps the item wrong).
	st := StatusOK
	for _, vals := range v.vals {
		cur := toCAA(vals)
		n, _ := MergeCAA(cur, s)
		if sameSet(caaData(n), caaData(cur)) {
			continue
		}
		hasOurs := false
		for _, c := range cur {
			if ours(c, s.Issuer) {
				hasOurs = true
			}
		}
		switch {
		case hasOurs:
			st, liveVals = StatusWrong, vals
		case st == StatusOK:
			st, liveVals = StatusMissing, vals
		}
	}
	next, others := MergeCAA(toCAA(liveVals), s)
	// With a provider, the merge is computed on what it holds.
	if in.Provider != nil {
		var cur []libdns.CAA
		for _, rr := range pick(live, d, "CAA") {
			if r, err := rr.Parse(); err == nil {
				if c, ok := r.(libdns.CAA); ok {
					cur = append(cur, c)
				}
			}
		}
		next, others = MergeCAA(cur, s)
	}
	cur := toCAA(liveVals)
	it := Item{Set: SetCAA, Name: d, Type: "CAA", Want: caaData(next), Live: caaData(cur), Status: st, Steps: []string{}}
	switch st {
	case StatusOK:
		it.Severity, it.Fix = SevOK, FixNone
	case StatusMissing:
		it.Severity, it.Fix = SevWarning, fix
		it.Steps = diffSteps("CAA", d, it.Want, it.Live, TTLCAA)
	default:
		it.Severity, it.Fix = SevProblem, fix
		it.Steps = diffSteps("CAA", d, it.Want, it.Live, TTLCAA)
	}
	if st != StatusOK {
		var users []string
		for _, c := range cur {
			if ours(c, s.Issuer) && !contains(it.Want, c.RR().Data) {
				users = append(users, c.RR().Data)
			}
		}
		if len(users) > 0 {
			it.Steps = append(it.Steps, fmt.Sprintf("replaces the %s entries already there (%s): Portcullis owns %s's entries at %s from now on, and DNS_CAA=false doesn't bring them back",
				s.Issuer, strings.Join(users, ", "), s.Issuer, d))
		}
	}
	if bare(zone) == d && !s.Main && st != StatusOK {
		it.Steps = append(it.Steps, "this CAA is at the zone apex: it covers every name in the zone that has no CAA of its own")
	}
	out := []Item{it}
	if len(others) > 0 {
		steps := []string{"other CAs may also issue for " + d + ": " + strings.Join(others, ", ")}
		var issueOnly []string
		for _, o := range others {
			wild := false
			for _, c := range toCAA(liveVals) {
				if strings.EqualFold(c.Tag, "issuewild") && parseValue(c.Value).issuer == o {
					wild = true
				}
			}
			if !wild {
				issueOnly = append(issueOnly, o)
			}
		}
		if len(issueOnly) > 0 {
			steps = append(steps, "writing issuewild takes wildcard issuance for *."+d+" away from "+strings.Join(issueOnly, ", "))
		}
		out = append(out, Item{Set: SetCAA, Name: d, Type: "CAA", Want: []string{}, Live: []string{}, Status: StatusForeign, Severity: SevInfo, Fix: FixNone, Steps: steps})
	}
	return out
}

func nomailItems(ctx context.Context, in Input, d string, fix Fix) []Item {
	s := in.Spec
	mx := lookup(ctx, in.Resolvers, d, dns.TypeMX)
	txt := lookup(ctx, in.Resolvers, d, dns.TypeTXT)
	if !s.NoMail {
		if mx.err != nil || txt.err != nil {
			return nil
		}
		for _, vals := range mx.vals {
			if len(vals) > 0 {
				return nil
			}
		}
		for _, vals := range txt.vals {
			for _, t := range vals {
				if isSPF(t) {
					return nil
				}
			}
		}
		steps := []string{d + " has no MX and no SPF: publishing the nomail set (null MX, SPF -all, DMARC reject) stops others sending mail as it",
			fmt.Sprintf("add MX %s 0 . (TTL %d)", d, int(TTLNoMail/time.Second)),
			fmt.Sprintf("add TXT %s %s (TTL %d)", d, spfNone, int(TTLNoMail/time.Second)),
			fmt.Sprintf("add TXT _dmarc.%s %s (TTL %d)", d, dmarcReject, int(TTLNoMail/time.Second))}
		return []Item{{Set: SetNoMail, Name: d, Type: "MX", Want: []string{"0 ."}, Live: []string{}, Status: StatusMissing, Severity: SevInfo, Fix: fix, Steps: steps}}
	}
	dm := lookup(ctx, in.Resolvers, "_dmarc."+d, dns.TypeTXT)
	spfOnly := func(v resolverView) resolverView {
		if v.err != nil {
			return v
		}
		out := v
		out.vals = nil
		for _, vals := range v.vals {
			var keep []string
			for _, t := range vals {
				if isSPF(t) {
					keep = append(keep, t)
				}
			}
			out.vals = append(out.vals, keep)
		}
		return out
	}
	var out []Item
	for _, r := range []struct {
		name, typ string
		v         resolverView
		want      string
	}{{d, "MX", mx, "0 ."}, {d, "TXT", spfOnly(txt), spfNone}, {"_dmarc." + d, "TXT", dm, dmarcReject}} {
		it := Item{Set: SetNoMail, Name: r.name, Type: r.typ, Want: []string{r.want}, Steps: []string{}}
		it.Status, it.Live = judge(r.v, it.Want)
		switch it.Status {
		case StatusOK:
			it.Severity, it.Fix = SevOK, FixNone
		case StatusUnknown:
			it.Severity, it.Fix = SevWarning, FixNone
			it.Steps = []string{"lookup failed (retry): " + r.v.err.Error()}
		default:
			it.Severity, it.Fix = SevWarning, fix
			it.Steps = diffSteps(r.typ, r.name, it.Want, it.Live, TTLNoMail)
			for _, l := range it.Live {
				if l == r.want {
					continue
				}
				switch {
				case r.typ == "MX":
					it.Steps = append(it.Steps, fmt.Sprintf("replaces the MX record %s: %s then receives no mail", l, d))
				case r.name == d:
					it.Steps = append(it.Steps, "replaces your SPF record "+l+" (other TXT records stay)")
				default:
					it.Steps = append(it.Steps, "replaces your DMARC record "+l)
				}
			}
		}
		out = append(out, it)
	}
	return out
}

func foreignItems(ctx context.Context, in Input, d string, live []liveRec) []Item {
	var out []Item
	for _, l := range live {
		t := strings.ToUpper(l.rr.Type)
		own := l.abs == d || l.abs == "*."+d
		it := Item{Set: SetAddress, Name: l.abs, Type: t, Want: []string{}, Live: []string{l.rr.Data}, Status: StatusForeign, Fix: FixManual}
		switch {
		case t == "TXT" && l.abs == "_acme-challenge."+d:
			it.Severity = SevInfo
			it.Steps = []string{fmt.Sprintf("leftover DNS-01 challenge record %s: remove it if no certificate order is running", l.abs)}
		case own:
			continue // A/AAAA judged by the address items, CNAME there too
		case t == "A" || t == "AAAA":
			ip, err := netip.ParseAddr(l.rr.Data)
			if err == nil && (ip == in.Spec.IPv4 || ip == in.Spec.IPv6) {
				continue
			}
			it.Severity = SevInfo
			it.Steps = []string{l.abs + " doesn't reach Portcullis (it overrides *." + d + ")"}
		case t == "CNAME" || t == "ALIAS":
			target := bare(l.rr.Data)
			v := lookup(ctx, in.Resolvers, target, dns.TypeA)
			if v.err == nil && v.nx {
				it.Severity = SevWarning
				it.Steps = []string{fmt.Sprintf("remove the dangling %s %s → %s (the target doesn't exist)", t, l.abs, target)}
			} else {
				it.Severity = SevInfo
				it.Steps = []string{fmt.Sprintf("%s doesn't reach Portcullis (%s → %s overrides *.%s)", l.abs, t, target, d)}
			}
		default:
			continue
		}
		out = append(out, it)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func dnssecInfo(ctx context.Context, in Input, d string) DNSSECInfo {
	r := dnssec.Check(ctx, in.Resolvers, d)
	info := DNSSECInfo{State: r.State, Zone: bare(r.Zone), ProviderCanSign: in.CanSign, DS: r.DS, Steps: []string{}}
	if in.DNSSEC != nil && r.Zone != "" {
		if _, ds, err := in.DNSSEC.DNSSECStatus(ctx, r.Zone); err == nil && len(ds) > 0 {
			info.DS = ds
		}
	}
	if info.DS == nil {
		info.DS = []dnssec.DS{}
	}
	prov := in.ProviderName
	if prov == "" {
		prov = "your DNS provider"
	}
	zone := bare(r.Zone)
	dsLine := func(x dnssec.DS) string {
		return fmt.Sprintf("key tag %d, algorithm %d, digest type %d, digest %s", x.KeyTag, x.Algorithm, x.DigestType, x.Digest)
	}
	switch r.State {
	case dnssec.Unsigned:
		switch {
		case in.CanSign:
			info.Steps = []string{fmt.Sprintf("Turn on signing at %s (one click: it signs the whole zone %s), then add the DS it shows at your registrar", prov, zone)}
		case in.ProviderName == "digitalocean":
			info.Steps = []string{"digitalocean can't sign: move the zone to sign it"}
		default:
			info.Steps = []string{fmt.Sprintf("Turn on DNSSEC signing for the zone %s at %s, then add the DS it shows at your registrar", zone, prov)}
		}
	case dnssec.DSMissing:
		for _, x := range info.DS {
			info.Steps = append(info.Steps, "Add this DS at your registrar: "+dsLine(x))
		}
	case dnssec.DSMismatch, dnssec.Bogus:
		want := make([]string, 0, len(info.DS))
		for _, x := range info.DS {
			want = append(want, dsLine(x))
		}
		info.Steps = []string{fmt.Sprintf("Validating resolvers can't reach %s. Fix the DS at the registrar to %s, or remove the DS. Never turn signing off while a DS is published", d, strings.Join(want, "; "))}
		if r.Err != "" {
			info.Steps = append(info.Steps, r.Err)
		}
	case dnssec.Insecure:
		info.Steps = []string{"The zone is signed and its DS matches, but the resolvers don't validate the parent zone above it, so the chain can't be checked (nothing to fix in this zone): " + r.Err}
	case dnssec.Unknown:
		info.Steps = []string{"DNSSEC lookups failed (retry): " + r.Err}
	}
	return info
}

// ── Apply ───────────────────────────────────────────────

// RefOf is the Ref of a record in zone.
func RefOf(r libdns.Record, zone string) Ref {
	rr := r.RR()
	return Ref{Name: libdns.RelativeName(dns.Fqdn(libdns.AbsoluteName(rr.Name, zone)), zone), Type: rr.Type, Value: rr.Data}
}

func rel(r libdns.Record, zone string) libdns.Record {
	switch v := r.(type) {
	case libdns.Address:
		v.Name = libdns.RelativeName(v.Name, zone)
		return v
	case libdns.CAA:
		v.Name = libdns.RelativeName(v.Name, zone)
		return v
	case libdns.MX:
		v.Name = libdns.RelativeName(v.Name, zone)
		return v
	case libdns.TXT:
		v.Name = libdns.RelativeName(v.Name, zone)
		return v
	}
	rr := r.RR()
	rr.Name = libdns.RelativeName(rr.Name, zone)
	return rr
}

// DataKey normalises record data for comparison (providers format it
// differently: case, trailing dots, quoting): the parsed fields.
func DataKey(typ, data string) string {
	r, err := libdns.RR{Type: typ, Data: data}.Parse()
	if err != nil {
		return typ + " " + strings.TrimSpace(data)
	}
	switch v := r.(type) {
	case libdns.Address:
		return typ + " " + v.IP.String()
	case libdns.CAA:
		return fmt.Sprintf("CAA %d %s %s", v.Flags, strings.ToLower(v.Tag), strings.TrimSpace(v.Value))
	case libdns.MX:
		return fmt.Sprintf("MX %d %s", v.Preference, fqdn(v.Target))
	case libdns.TXT:
		return "TXT " + v.Text
	case libdns.CNAME:
		return "CNAME " + fqdn(v.Target)
	}
	return typ + " " + strings.TrimSpace(data)
}

// syncSet makes the (name, type) RRset at name equal want WITHOUT
// libdns SetRecords: several libdns providers (cloudflare v0.2.2, porkbun
// v1.1.0) update one same-name/type record per input record instead of
// replacing the RRset, so a multi-value set would overwrite itself. The
// missing entries are appended FIRST and the stale ones deleted by exact
// data afterwards (the provider must delete by data: porkbun v1.1.0 and
// hetzner v1.0.0 come wrapped, domains/provider_byid.go): there is never
// a moment without the new entries (a CAA pin never disappears in
// between). Returns the deleted records.
func syncSet(ctx context.Context, p Provider, zone, name, typ string, want []libdns.Record, live []liveRec) ([]libdns.Record, error) {
	have := pick(live, name, typ)
	haveKeys := map[string]bool{}
	for _, rr := range have {
		haveKeys[DataKey(typ, rr.Data)] = true
	}
	wantKeys := map[string]bool{}
	var add []libdns.Record
	for _, w := range want {
		k := DataKey(typ, w.RR().Data)
		wantKeys[k] = true
		if !haveKeys[k] {
			add = append(add, rel(w, zone))
		}
	}
	if len(add) > 0 {
		if _, err := p.AppendRecords(ctx, zone, add); err != nil {
			return nil, err
		}
	}
	var stale []libdns.Record
	for _, rr := range have {
		if !wantKeys[DataKey(typ, rr.Data)] {
			rr.Name = libdns.RelativeName(dns.Fqdn(name), zone)
			stale = append(stale, parsedRR(rr))
		}
	}
	if len(stale) == 0 {
		return nil, nil
	}
	return p.DeleteRecords(ctx, zone, stale)
}

func parsedRR(rr libdns.RR) libdns.Record {
	if r, err := rr.Parse(); err == nil {
		return r
	}
	return rr
}

// Apply writes the given sets through the provider: written are the
// records Portcullis now owns (refs for tracking), removed the ones it
// deleted (or, CAA off, owned refs that are no longer live). It touches
// only <d>, *.<d> and _dmarc.<d>, never NS / SOA, and never uses libdns
// SetRecords (see syncSet).
func Apply(ctx context.Context, in Input, sets []string) (written, removed []Ref, err error) {
	if in.Provider == nil {
		return nil, nil, errors.New("no provider: the records must be created by hand")
	}
	s := in.Spec
	if s.AccountURI != "" && !ValidAccountURI(s.AccountURI) {
		return nil, nil, fmt.Errorf("the ACME account URI %q can't go into a CAA value", s.AccountURI)
	}
	d := fqdn(s.Name)
	zone := in.Zone
	if zone == "" {
		if zone, err = dnssec.FindZone(ctx, in.Resolvers, d); err != nil {
			return nil, nil, fmt.Errorf("finding the DNS zone of %s: %w", bare(d), err)
		}
	}
	zone = dns.Fqdn(zone)
	live, err := providerRecords(ctx, in.Provider, zone, d)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the records of %s: %w", bare(d), err)
	}
	gone := func(recs []libdns.Record) {
		for _, g := range recs {
			removed = append(removed, RefOf(g, zone))
		}
	}
	want := Wanted(s)
	for _, set := range sets {
		switch set {
		case SetAddress:
			for _, n := range []string{d, "*." + d} {
				if c := pick(live, n, "CNAME"); len(c) > 0 {
					return written, removed, fmt.Errorf("a CNAME %s → %s exists: remove it first (Portcullis doesn't put A/AAAA records next to a CNAME)", bare(n), c[0].Data)
				}
			}
			if !s.IPv4.IsValid() {
				return written, removed, errors.New("the server's public IPv4 is unknown (./portcullis up detects it once a domain is enrolled — run it again — or set PORTCULLIS_PUBLIC_IPV4 in .env)")
			}
			for _, r := range want[SetAddress] {
				written = append(written, RefOf(r, zone))
			}
			for _, n := range []string{d, "*." + d} {
				for _, typ := range []string{"A", "AAAA"} {
					var w []libdns.Record
					for _, r := range want[SetAddress] {
						if r.RR().Name == n && r.RR().Type == typ {
							w = append(w, r)
						}
					}
					del, err := syncSet(ctx, in.Provider, zone, n, typ, w, live)
					gone(del)
					if err != nil {
						return written, removed, fmt.Errorf("setting the %s records of %s: %w", typ, bare(n), err)
					}
				}
			}
		case SetCAA:
			var cur []libdns.CAA
			for _, rr := range pick(live, d, "CAA") {
				if r, err := rr.Parse(); err == nil {
					if c, ok := r.(libdns.CAA); ok {
						cur = append(cur, c)
					}
				}
			}
			if !s.CAA {
				rm := removalCAA(cur, s)
				// Owned refs no longer live (deleted by hand, another
				// format) are dropped from tracking too.
				for _, r := range s.Owned {
					if r.Type != "CAA" {
						continue
					}
					found := false
					for _, c := range cur {
						if DataKey("CAA", c.RR().Data) == DataKey("CAA", r.Value) {
							found = true
						}
					}
					if !found {
						removed = append(removed, r)
					}
				}
				if len(rm) == 0 {
					continue
				}
				var recs []libdns.Record
				for _, c := range rm {
					c.Name = libdns.RelativeName(d, zone)
					recs = append(recs, c)
				}
				del, err := in.Provider.DeleteRecords(ctx, zone, recs)
				gone(del)
				if err != nil {
					return written, removed, fmt.Errorf("removing the CAA records of %s: %w", bare(d), err)
				}
				continue
			}
			if s.Issuer == "" {
				continue // unknown CA: nothing written
			}
			next, _ := MergeCAA(cur, s)
			var w []libdns.Record
			for _, c := range next {
				c.Name = d
				w = append(w, c)
			}
			for _, r := range want[SetCAA] {
				written = append(written, RefOf(r, zone))
			}
			del, err := syncSet(ctx, in.Provider, zone, d, "CAA", w, live)
			gone(del)
			if err != nil {
				return written, removed, fmt.Errorf("setting the CAA records of %s: %w", bare(d), err)
			}
		case SetNoMail:
			if !s.NoMail {
				continue
			}
			for _, r := range want[SetNoMail] {
				written = append(written, RefOf(r, zone))
			}
			// MX at <d>: exactly the null MX. TXT at <d>: our SPF replaces
			// any other SPF; other TXT records (site verifications) stay
			// untouched. _dmarc.<d>: exactly our DMARC record.
			mx := []libdns.Record{libdns.MX{Name: d, TTL: TTLNoMail, Preference: 0, Target: "."}}
			txt := []libdns.Record{libdns.TXT{Name: d, TTL: TTLNoMail, Text: spfNone}}
			for _, rr := range pick(live, d, "TXT") {
				if !isSPF(rr.Data) {
					txt = append(txt, libdns.TXT{Name: d, TTL: rr.TTL, Text: rr.Data})
				}
			}
			dmarc := []libdns.Record{libdns.TXT{Name: "_dmarc." + d, TTL: TTLNoMail, Text: dmarcReject}}
			for _, x := range []struct {
				name, typ string
				want      []libdns.Record
			}{{d, "MX", mx}, {d, "TXT", txt}, {"_dmarc." + d, "TXT", dmarc}} {
				del, err := syncSet(ctx, in.Provider, zone, x.name, x.typ, x.want, live)
				gone(del)
				if err != nil {
					return written, removed, fmt.Errorf("setting the nomail records of %s: %w", bare(d), err)
				}
			}
		default:
			return written, removed, fmt.Errorf("unknown record set %q (one of %s)", set, strings.Join(Sets, ", "))
		}
	}
	return written, removed, nil
}

func refIn(list []Ref, r Ref) bool {
	for _, x := range list {
		if x == r {
			return true
		}
	}
	return false
}
