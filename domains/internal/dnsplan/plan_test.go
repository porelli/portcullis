package dnsplan

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/internal/dnssec"
	"github.com/portcullis/domains/internal/fakedns"
)

const (
	pd   = "portcullis.example.test"
	pz   = "example.test."
	ipv4 = "203.0.113.10"
)

type env struct {
	zone *fakedns.Zone
	in   Input
}

func newPlanEnv(t *testing.T) *env {
	t.Helper()
	z := fakedns.NewZone()
	z.SetSOA("example.test")
	z.Set("example.test", libdns.RR{Name: "@", Type: "NS", Data: "ns1.example.test.", TTL: time.Hour})
	return &env{zone: z, in: Input{
		Spec:         Spec{Name: pd, IPv4: netip.MustParseAddr(ipv4), CAA: true, Issuer: "letsencrypt.org", AccountURI: acct},
		Zone:         pz,
		Provider:     &fakedns.Provider{Zone: z, ZoneName: pz},
		ProviderName: "fake",
		Resolvers:    serveZone(t, z),
		Now:          time.Unix(1_800_000_000, 0),
	}}
}

func (e *env) ourCAA() {
	v := CAAValue("letsencrypt.org", acct)
	e.zone.Set(pd, append(e.zone.Records(pd), libdns.CAA{Name: "portcullis", TTL: TTLCAA, Tag: "issue", Value: v}.RR(),
		libdns.CAA{Name: "portcullis", TTL: TTLCAA, Tag: "issuewild", Value: v}.RR())...)
}

func (e *env) addr(name, ip string) {
	e.zone.Set(name, append(e.zone.Records(name), libdns.RR{Name: libdns.RelativeName(name+".", pz), Type: "A", Data: ip, TTL: TTLAddress})...)
}

func items(p Plan, set string) []Item {
	var out []Item
	for _, it := range p.Items {
		if it.Set == set {
			out = append(out, it)
		}
	}
	return out
}

func find(t *testing.T, p Plan, set, name, typ string, st Status) Item {
	t.Helper()
	for _, it := range p.Items {
		if it.Set == set && it.Name == name && it.Type == typ && it.Status == st {
			return it
		}
	}
	t.Fatalf("no %s %s %s %s item in %+v", set, name, typ, st, p.Items)
	return Item{}
}

func TestBuildAllOK(t *testing.T) {
	e := newPlanEnv(t)
	e.addr(pd, ipv4)
	e.addr("*."+pd, ipv4)
	e.ourCAA()
	e.in.Spec.NoMail = true
	e.zone.Set(pd, append(e.zone.Records(pd), libdns.MX{Name: "portcullis", Target: "."}.RR(), libdns.TXT{Name: "portcullis", Text: "v=spf1 -all"}.RR(),
		libdns.TXT{Name: "portcullis", Text: "google-site-verification=abc"}.RR())...)
	e.zone.Set("_dmarc."+pd, libdns.TXT{Name: "_dmarc.portcullis", Text: "v=DMARC1; p=reject;"}.RR())
	p := Build(context.Background(), e.in)
	if !p.CanWrite || p.Name != pd || !p.CAA.WouldIssue || p.CAA.AccountURI != acct || p.CAA.Issuer != "letsencrypt.org" {
		t.Fatalf("plan %+v", p)
	}
	if len(p.Items) != 6 { // A ×2, CAA, MX, SPF, DMARC
		t.Fatalf("items %+v", p.Items)
	}
	for _, it := range p.Items {
		if it.Status != StatusOK || it.Severity != SevOK || it.Fix != FixNone {
			t.Errorf("item %+v", it)
		}
	}
	if p.DNSSEC.State != dnssec.Unsigned || p.DNSSEC.Zone != "example.test" {
		t.Fatalf("dnssec %+v", p.DNSSEC)
	}
}

func TestBuildMissingAndWrong(t *testing.T) {
	e := newPlanEnv(t)
	e.addr(pd, "198.51.100.1")
	p := Build(context.Background(), e.in)
	a := find(t, p, SetAddress, pd, "A", StatusWrong)
	if a.Severity != SevProblem || a.Fix != FixAuto || strings.Join(a.Live, ",") != "198.51.100.1" {
		t.Fatalf("%+v", a)
	}
	w := find(t, p, SetAddress, "*."+pd, "A", StatusMissing)
	if w.Severity != SevProblem || len(w.Steps) != 1 || !strings.Contains(w.Steps[0], "add A *."+pd+" "+ipv4) {
		t.Fatalf("%+v", w)
	}
	c := find(t, p, SetCAA, pd, "CAA", StatusMissing)
	if c.Severity != SevWarning || len(c.Want) != 2 {
		t.Fatalf("%+v", c)
	}
	// An old account pin is wrong (Problem) and the CA wouldn't issue.
	e.in.Spec.AccountURI = "https://acme-v02.api.letsencrypt.org/acme/acct/999"
	e.ourCAA()
	p = Build(context.Background(), e.in)
	if c := find(t, p, SetCAA, pd, "CAA", StatusWrong); c.Severity != SevProblem || p.CAA.WouldIssue {
		t.Fatalf("%+v would_issue %v", c, p.CAA.WouldIssue)
	}
}

func TestBuildReadOnlyManualSteps(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Provider = nil
	e.in.Spec.IPv6 = netip.MustParseAddr("2001:db8::10")
	p := Build(context.Background(), e.in)
	if p.CanWrite {
		t.Fatal("can_write with no provider")
	}
	var steps []string
	for _, it := range p.Items {
		if it.Status != StatusOK && it.Set != SetNoMail {
			if it.Fix != FixManual {
				t.Errorf("fix %s for %+v", it.Fix, it)
			}
			steps = append(steps, it.Steps...)
		}
	}
	all := strings.Join(steps, "\n")
	v := CAAValue("letsencrypt.org", acct)
	for _, want := range []string{
		"add A " + pd + " " + ipv4 + " (TTL 300)", "add A *." + pd + " " + ipv4, "add AAAA " + pd + " 2001:db8::10", "add AAAA *." + pd + " 2001:db8::10",
		`add CAA ` + pd + ` 0 issue "` + v + `" (TTL 300)`, `add CAA ` + pd + ` 0 issuewild "` + v + `"`,
	} {
		if !strings.Contains(all, want) {
			t.Errorf("steps lack %q:\n%s", want, all)
		}
	}
}

func TestForeignDanglingShadowedChallenge(t *testing.T) {
	e := newPlanEnv(t)
	e.addr(pd, ipv4)
	e.addr("*."+pd, ipv4)
	e.zone.Set("old."+pd, libdns.CNAME{Name: "old.portcullis", Target: "gone.elsewhere.test."}.RR())
	e.zone.Set("app."+pd, libdns.RR{Name: "app.portcullis", Type: "A", Data: "198.51.100.5"})
	e.zone.Set("ok."+pd, libdns.RR{Name: "ok.portcullis", Type: "A", Data: ipv4})
	e.zone.Set("_acme-challenge."+pd, libdns.TXT{Name: "_acme-challenge.portcullis", Text: "token"}.RR())
	e.zone.Set("alias."+pd, libdns.RR{Name: "alias.portcullis", Type: "ALIAS", Data: "lb.example.test."})
	e.zone.Set("lb.example.test", libdns.RR{Name: "lb", Type: "A", Data: "198.51.100.9"})
	e.zone.Set("other.example.test", libdns.RR{Name: "other", Type: "A", Data: "198.51.100.6"})
	p := Build(context.Background(), e.in)
	if it := find(t, p, SetAddress, "old."+pd, "CNAME", StatusForeign); it.Severity != SevWarning || !strings.Contains(it.Steps[0], "remove the dangling CNAME old."+pd+" → gone.elsewhere.test") {
		t.Fatalf("%+v", it)
	}
	if it := find(t, p, SetAddress, "app."+pd, "A", StatusForeign); it.Severity != SevInfo || !strings.Contains(it.Steps[0], "app."+pd+" doesn't reach Portcullis") {
		t.Fatalf("%+v", it)
	}
	if it := find(t, p, SetAddress, "_acme-challenge."+pd, "TXT", StatusForeign); it.Severity != SevInfo {
		t.Fatalf("%+v", it)
	}
	if it := find(t, p, SetAddress, "alias."+pd, "ALIAS", StatusForeign); it.Severity != SevInfo {
		t.Fatalf("%+v", it)
	}
	for _, it := range p.Items {
		if it.Name == "ok."+pd || it.Name == "other.example.test" {
			t.Fatalf("not foreign: %+v", it)
		}
	}
	// Read-only: no foreign items (no provider data).
	e.in.Provider = nil
	for _, it := range Build(context.Background(), e.in).Items {
		if it.Status == StatusForeign {
			t.Fatalf("foreign item without a provider: %+v", it)
		}
	}
}

func TestCloudflareProxiedNamed(t *testing.T) {
	e := newPlanEnv(t)
	e.addr(pd, "104.16.1.1")
	p := Build(context.Background(), e.in)
	it := find(t, p, SetAddress, pd, "A", StatusWrong)
	if !strings.Contains(strings.Join(it.Steps, "\n"), "proxied (orange cloud)") {
		t.Fatalf("%+v", it)
	}
}

func TestCNAMEBlocksAddressApply(t *testing.T) {
	e := newPlanEnv(t)
	e.zone.Set("*."+pd, libdns.CNAME{Name: "*.portcullis", Target: "elsewhere.example.test."}.RR())
	p := Build(context.Background(), e.in)
	it := find(t, p, SetAddress, "*."+pd, "A", StatusForeign)
	if it.Fix != FixManual || it.Severity != SevProblem || !strings.Contains(it.Steps[0], "CNAME *."+pd+" → elsewhere.example.test") {
		t.Fatalf("%+v", it)
	}
	before := e.zone.Records(pd)
	_, _, err := Apply(context.Background(), e.in, []string{SetAddress})
	if err == nil || !strings.Contains(err.Error(), "CNAME *."+pd) {
		t.Fatalf("apply err %v", err)
	}
	if len(e.zone.Records(pd)) != len(before) || e.zone.Records("*." + pd)[0].Type != "CNAME" {
		t.Fatal("apply wrote next to a CNAME")
	}
}

func rrs(z *fakedns.Zone, name, typ string) []string {
	var out []string
	for _, rr := range z.Records(name) {
		if rr.Type == typ {
			out = append(out, rr.Data+" "+rr.TTL.String())
		}
	}
	sort.Strings(out)
	return out
}

func TestApplyWritesSetsTTLs(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Spec.NoMail = true
	e.zone.Set(pd, libdns.TXT{Name: "portcullis", Text: "keep-me", TTL: time.Minute}.RR(), libdns.TXT{Name: "portcullis", Text: "v=spf1 include:old -all"}.RR(),
		libdns.RR{Name: "portcullis", Type: "AAAA", Data: "2001:db8::99"})
	written, removed, err := Apply(context.Background(), e.in, []string{SetAddress, SetCAA, SetNoMail})
	if err != nil {
		t.Fatal(err)
	}
	v := CAAValue("letsencrypt.org", acct)
	check := func(name, typ string, want ...string) {
		t.Helper()
		sort.Strings(want)
		if got := rrs(e.zone, name, typ); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s %s = %v, want %v", name, typ, got, want)
		}
	}
	check(pd, "A", ipv4+" 5m0s")
	check("*."+pd, "A", ipv4+" 5m0s")
	check(pd, "AAAA")
	check(pd, "CAA", `0 issue "`+v+`" 5m0s`, `0 issuewild "`+v+`" 5m0s`)
	check(pd, "MX", "0 . 1h0m0s")
	check(pd, "TXT", "v=spf1 -all 1h0m0s", "keep-me 1m0s") // other TXT untouched
	check("_dmarc."+pd, "TXT", "v=DMARC1; p=reject; 1h0m0s")
	if len(written) != 2+2+3 {
		t.Fatalf("written %v", written)
	}
	if len(removed) != 2 || removed[0].Type != "AAAA" || removed[0].Name != "portcullis" || removed[1].Value != "v=spf1 include:old -all" {
		t.Fatalf("removed %v", removed)
	}
	for _, r := range written {
		if r.Name != "portcullis" && r.Name != "*.portcullis" && r.Name != "_dmarc.portcullis" {
			t.Fatalf("ref name %q", r.Name)
		}
	}
	// The plan now shows everything ok.
	for _, it := range Build(context.Background(), e.in).Items {
		if it.Status != StatusOK {
			t.Errorf("after apply: %+v", it)
		}
	}
}

func TestApplyCAAOffRemovesOwnedOnly(t *testing.T) {
	e := newPlanEnv(t)
	e.zone.Set(pd, libdns.CAA{Name: "portcullis", Tag: "issue", Value: "digicert.com"}.RR())
	written, _, err := Apply(context.Background(), e.in, []string{SetCAA})
	if err != nil {
		t.Fatal(err)
	}
	if got := rrs(e.zone, pd, "CAA"); len(got) != 3 {
		t.Fatalf("after on: %v", got)
	}
	e.in.Spec.CAA = false
	e.in.Spec.Owned = written
	// The plan shows the removal (Info).
	if it := find(t, Build(context.Background(), e.in), SetCAA, pd, "CAA", StatusWrong); it.Severity != SevInfo || it.Fix != FixAuto {
		t.Fatalf("%+v", it)
	}
	_, removed, err := Apply(context.Background(), e.in, []string{SetCAA})
	if err != nil {
		t.Fatal(err)
	}
	if got := rrs(e.zone, pd, "CAA"); len(got) != 1 || !strings.Contains(got[0], "digicert.com") || len(removed) != 2 {
		t.Fatalf("after off: %v removed %v", got, removed)
	}
}

func TestApplyNeverTouchesOtherNames(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Spec.NoMail = true
	e.zone.Set("other.example.test", libdns.RR{Name: "other", Type: "A", Data: "198.51.100.6"}, libdns.RR{Name: "other", Type: "CAA", Data: `0 issue "digicert.com"`})
	apex := e.zone.Records("example.test")
	other := e.zone.Records("other.example.test")
	var names []string
	e.in.Provider = &fakedns.Provider{Zone: e.zone, ZoneName: pz, Hook: func(op string, recs []libdns.Record) error {
		for _, r := range recs {
			names = append(names, op+" "+r.RR().Name+" "+r.RR().Type)
		}
		return nil
	}}
	if _, _, err := Apply(context.Background(), e.in, []string{SetAddress, SetCAA, SetNoMail}); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		f := strings.Fields(n)
		if (f[1] != "portcullis" && f[1] != "*.portcullis" && f[1] != "_dmarc.portcullis") || f[2] == "NS" || f[2] == "SOA" {
			t.Fatalf("touched %s", n)
		}
	}
	if len(e.zone.Records("example.test")) != len(apex) || len(e.zone.Records("other.example.test")) != len(other) {
		t.Fatal("other names changed")
	}
}

func TestUnknownCASkipsCAA(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Spec.Issuer = ""
	if _, ok := Wanted(e.in.Spec)[SetCAA]; ok {
		t.Fatal("caa wanted with an unknown CA")
	}
	p := Build(context.Background(), e.in)
	c := items(p, SetCAA)
	if len(c) != 1 || len(c[0].Want) != 0 || c[0].Severity != SevInfo || c[0].Fix != FixNone || !strings.Contains(c[0].Steps[0], "CAA skipped: unknown CA") {
		t.Fatalf("caa items %+v", c)
	}
	if p.CAA.WouldIssue {
		t.Fatal("would_issue with an unknown CA")
	}
	if _, _, err := Apply(context.Background(), e.in, []string{SetCAA}); err != nil {
		t.Fatal(err)
	}
	if got := rrs(e.zone, pd, "CAA"); len(got) != 0 {
		t.Fatalf("CAA written for an unknown CA: %v", got)
	}
}

func TestNoMailRecommended(t *testing.T) {
	e := newPlanEnv(t)
	p := Build(context.Background(), e.in)
	it := find(t, p, SetNoMail, pd, "MX", StatusMissing)
	if it.Severity != SevInfo || it.Fix != FixAuto {
		t.Fatalf("%+v", it)
	}
	// An SPF record (the name sends mail) or an MX: no recommendation.
	e.zone.Set(pd, libdns.TXT{Name: "portcullis", Text: "v=spf1 include:mail.test -all"}.RR())
	if n := items(Build(context.Background(), e.in), SetNoMail); len(n) != 0 {
		t.Fatalf("recommended with SPF: %+v", n)
	}
}

func TestBuildLookupFailureUnknown(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Resolvers = []string{"127.0.0.1:1"}
	e.in.Provider = nil
	e.in.Spec.NoMail = true
	p := Build(context.Background(), e.in)
	if len(p.Items) == 0 {
		t.Fatal("no items")
	}
	for _, it := range p.Items {
		if it.Status != StatusUnknown || it.Severity == SevOK {
			t.Errorf("item %+v", it)
		}
	}
	if p.CAA.WouldIssue || p.DNSSEC.State != dnssec.Unknown {
		t.Fatalf("caa %+v dnssec %+v", p.CAA, p.DNSSEC)
	}
}

// TestApplyPerRecordProviders (review C1): providers whose SetRecords
// updates one same-name/type record per input (cloudflare, porkbun) must
// still end with every entry: DigiCert kept, issue AND issuewild ours,
// the user's TXT and our SPF both present.
func TestApplyPerRecordProviders(t *testing.T) {
	for _, mode := range []string{"cloudflare", "porkbun"} {
		t.Run(mode, func(t *testing.T) {
			e := newPlanEnv(t)
			e.in.Provider = &fakedns.Provider{Zone: e.zone, ZoneName: pz, SetMode: mode}
			e.in.Spec.NoMail = true
			e.zone.Set(pd, libdns.CAA{Name: "portcullis", TTL: time.Hour, Tag: "issue", Value: "digicert.com"}.RR(),
				libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "google-site-verification=abc"}.RR(),
				libdns.RR{Name: "portcullis", Type: "A", Data: "198.51.100.1"}, libdns.RR{Name: "portcullis", Type: "A", Data: "198.51.100.2"})
			if _, _, err := Apply(context.Background(), e.in, []string{SetAddress, SetCAA, SetNoMail}); err != nil {
				t.Fatal(err)
			}
			v := CAAValue("letsencrypt.org", acct)
			caa := rrs(e.zone, pd, "CAA")
			if strings.Join(caa, "|") != `0 issue "digicert.com" 1h0m0s|0 issue "`+v+`" 5m0s|0 issuewild "`+v+`" 5m0s` {
				t.Fatalf("CAA %v", caa)
			}
			if txt := rrs(e.zone, pd, "TXT"); strings.Join(txt, "|") != "google-site-verification=abc 1h0m0s|v=spf1 -all 1h0m0s" {
				t.Fatalf("TXT %v", txt)
			}
			if a := rrs(e.zone, pd, "A"); strings.Join(a, "|") != ipv4+" 5m0s" {
				t.Fatalf("A %v", a)
			}
			// An account switch: the new pin is appended before the old one
			// goes (never a moment without issue / issuewild).
			var minIssue = 99
			e.in.Provider = &fakedns.Provider{Zone: e.zone, ZoneName: pz, SetMode: mode, Hook: func(op string, _ []libdns.Record) error {
				n := 0
				for _, c := range rrs(e.zone, pd, "CAA") {
					if strings.Contains(c, "letsencrypt.org") {
						n++
					}
				}
				if op != "get" && n < minIssue {
					minIssue = n
				}
				return nil
			}}
			e.in.Spec.AccountURI = "https://acme-v02.api.letsencrypt.org/acme/acct/456"
			if _, _, err := Apply(context.Background(), e.in, []string{SetCAA}); err != nil {
				t.Fatal(err)
			}
			if minIssue < 2 {
				t.Fatalf("a moment with %d of our entries during the switch", minIssue)
			}
			if c := rrs(e.zone, pd, "CAA"); len(c) != 3 || strings.Contains(strings.Join(c, "|"), "acct/123") {
				t.Fatalf("after the switch %v", c)
			}
		})
	}
}

func TestApplyRejectsBadAccountURI(t *testing.T) {
	e := newPlanEnv(t)
	for _, u := range []string{"https://x/acct; validationmethods=http-01", `https://x/"a`, "http://x/acct", "https:///acct", "https://x/a b"} {
		e.in.Spec.AccountURI = u
		if _, _, err := Apply(context.Background(), e.in, []string{SetCAA}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if len(rrs(e.zone, pd, "CAA")) != 0 {
		t.Fatal("a CAA was written")
	}
}

// TestWouldIssueEveryResolver (review I4): a resolver still serving an
// old pin makes would_issue false.
func TestWouldIssueEveryResolver(t *testing.T) {
	e := newPlanEnv(t)
	e.ourCAA()
	stale := fakedns.NewZone()
	old := CAAValue("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/1")
	stale.Set(pd, libdns.CAA{Name: "portcullis", Tag: "issue", Value: old}.RR(), libdns.CAA{Name: "portcullis", Tag: "issuewild", Value: old}.RR())
	e.in.Provider = nil
	if p := Build(context.Background(), e.in); !p.CAA.WouldIssue {
		t.Fatal("setup: one resolver doesn't issue")
	}
	e.in.Resolvers = append(e.in.Resolvers, serveZone(t, stale)...)
	if p := Build(context.Background(), e.in); p.CAA.WouldIssue {
		t.Fatal("would_issue with a resolver showing the old pin")
	}
}

func TestPlanStepsReplace(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Spec.NoMail = true
	e.zone.Set(pd, libdns.TXT{Name: "portcullis", Text: "v=spf1 include:mail.test -all"}.RR(),
		libdns.MX{Name: "portcullis", Preference: 10, Target: "mx.mail.test."}.RR(),
		libdns.CAA{Name: "portcullis", Tag: "issue", Value: "letsencrypt.org"}.RR())
	all := ""
	for _, it := range Build(context.Background(), e.in).Items {
		all += strings.Join(it.Steps, "\n") + "\n"
	}
	for _, want := range []string{"replaces your SPF record v=spf1 include:mail.test -all", "replaces the MX record 10 mx.mail.test.",
		`replaces the letsencrypt.org entries already there (0 issue "letsencrypt.org")`} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q in\n%s", want, all)
		}
	}
}

// TestNoServerAddressesUnknown (final review I1): without the server's
// IPv4 (the main plan before any enrolment) every address item is
// unknown / Info — a published AAAA is not judged wrong, and nothing
// failed (re-review 1: Info never counts as a failed lookup).
func TestNoServerAddressesUnknown(t *testing.T) {
	e := newPlanEnv(t)
	e.in.Provider = nil
	e.in.Spec.IPv4 = netip.Addr{}
	e.addr(pd, "203.0.113.10")
	e.zone.Set(pd, append(e.zone.Records(pd), libdns.RR{Name: "portcullis", Type: "AAAA", Data: "2001:db8::10", TTL: TTLAddress})...)
	its := items(Build(context.Background(), e.in), SetAddress)
	if len(its) == 0 {
		t.Fatal("no address items")
	}
	for _, it := range its {
		if it.Status != StatusUnknown || it.Severity != SevInfo {
			t.Errorf("%s %s: %s / %s", it.Name, it.Type, it.Status, it.Severity)
		}
	}
}

// TestDNSSECInsecureInfo (re-review 3): a signed zone under a parent the
// resolvers don't validate is "insecure", with a step that says so.
func TestDNSSECInsecureInfo(t *testing.T) {
	e := newPlanEnv(t)
	k, err := e.zone.Sign(pz)
	if err != nil {
		t.Fatal(err)
	}
	e.zone.PublishDS(pz, k.ToDS(dns.SHA256))
	info := Build(context.Background(), e.in).DNSSEC
	if info.State != dnssec.Insecure || len(info.Steps) != 1 || !strings.Contains(info.Steps[0], "parent zone") {
		t.Fatalf("%+v", info)
	}
}

// flapping is a resolver whose CAA answers at pd alternate between two
// caches (anycast shards: the deploy's finding C), first good then stale;
// every other question goes to good.
func flapping(t *testing.T, good, stale string) string {
	t.Helper()
	var n int
	var mu sync.Mutex
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		up := good
		if q := req.Question[0]; q.Qtype == dns.TypeCAA && strings.EqualFold(strings.TrimSuffix(q.Name, "."), pd) {
			mu.Lock()
			if n%2 == 1 {
				up = stale
			}
			n++
			mu.Unlock()
		}
		in, err := dns.Exchange(req, up)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		_ = w.WriteMsg(in)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestWouldIssueSameViewAsItems (deploy finding C): would_issue is judged
// on the same resolver answers as the caa item, so a resolver whose
// caches disagree between two questions can't give an ok item next to
// would_issue false.
func TestWouldIssueSameViewAsItems(t *testing.T) {
	e := newPlanEnv(t)
	e.ourCAA()
	stale := fakedns.NewZone()
	old := CAAValue("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/1")
	stale.Set(pd, libdns.CAA{Name: "portcullis", Tag: "issue", Value: old}.RR(), libdns.CAA{Name: "portcullis", Tag: "issuewild", Value: old}.RR())
	e.in.Resolvers = []string{flapping(t, e.in.Resolvers[0], serveZone(t, stale)[0])}
	e.in.Provider = nil
	p := Build(context.Background(), e.in)
	it := find(t, p, SetCAA, pd, "CAA", StatusOK)
	if !p.CAA.WouldIssue {
		t.Fatalf("caa item %s but would_issue false: two different answers judged", it.Status)
	}
}

// A CAA only at the parent: the climb still happens where <d> has none.
func TestWouldIssueClimbsFromItemView(t *testing.T) {
	e := newPlanEnv(t)
	other := CAAValue("digicert.com", "")
	e.zone.Set("example.test", append(e.zone.Records("example.test"), libdns.CAA{Name: "@", Tag: "issue", Value: other}.RR())...)
	e.in.Provider = nil
	if p := Build(context.Background(), e.in); p.CAA.WouldIssue {
		t.Fatal("would_issue under a parent CAA allowing only another CA")
	}
}
