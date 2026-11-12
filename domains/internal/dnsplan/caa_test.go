package dnsplan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/internal/fakedns"
)

const (
	leProd    = "https://acme-v02.api.letsencrypt.org/directory"
	leStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acct      = "https://acme-v02.api.letsencrypt.org/acme/acct/123"
)

func TestIssuerFor(t *testing.T) {
	for _, c := range []struct {
		ca, override, want string
		ok                 bool
	}{
		{leProd, "", "letsencrypt.org", true},
		{leStaging, "", "letsencrypt.org", true},
		{"https://pebble:14000/dir", "", "", false},
		{"https://pebble:14000/dir", "pebble.test", "pebble.test", true},
		{leProd, "Other.CA.", "other.ca", true},
	} {
		if got, ok := IssuerFor(c.ca, c.override); got != c.want || ok != c.ok {
			t.Errorf("IssuerFor(%q, %q) = %q %v", c.ca, c.override, got, ok)
		}
	}
}

func TestCAAValue(t *testing.T) {
	if v := CAAValue("letsencrypt.org", acct); v != "letsencrypt.org; accounturi="+acct+"; validationmethods=dns-01" {
		t.Fatal(v)
	}
	if v := CAAValue("letsencrypt.org", ""); v != "letsencrypt.org; validationmethods=dns-01" {
		t.Fatal(v)
	}
}

func caa(tag, value string) libdns.CAA {
	return libdns.CAA{Name: "@", TTL: time.Hour, Tag: tag, Value: value}
}

func vals(cs []libdns.CAA) string {
	var out []string
	for _, c := range cs {
		out = append(out, c.RR().Data)
	}
	return strings.Join(out, "|")
}

func TestMergeKeepsOtherIssuers(t *testing.T) {
	s := Spec{Name: "d.test", CAA: true, Issuer: "letsencrypt.org", AccountURI: acct}
	next, others := MergeCAA([]libdns.CAA{caa("issue", "digicert.com")}, s)
	v := CAAValue("letsencrypt.org", acct)
	want := `0 issue "digicert.com"|0 issue "` + v + `"|0 issuewild "` + v + `"`
	if vals(next) != want || strings.Join(others, ",") != "digicert.com" {
		t.Fatalf("next %s, others %v", vals(next), others)
	}
	for _, c := range next {
		if c.TTL != TTLCAA {
			t.Fatalf("TTL %s", c.TTL)
		}
	}
}

func TestMergeReplacesOurs(t *testing.T) {
	s := Spec{Name: "d.test", CAA: true, Issuer: "letsencrypt.org", AccountURI: acct, IODEF: "mailto:sec@d.test"}
	live := []libdns.CAA{
		caa("issue", "letsencrypt.org; accounturi=https://old/acct/1; validationmethods=dns-01"),
		caa("issuewild", "LetsEncrypt.org.; accounturi=https://old/acct/1"),
		caa("iodef", "mailto:old@d.test"),
	}
	next, others := MergeCAA(live, s)
	v := CAAValue("letsencrypt.org", acct)
	if vals(next) != `0 issue "`+v+`"|0 issuewild "`+v+`"|0 iodef "mailto:sec@d.test"` || len(others) != 0 {
		t.Fatalf("next %s others %v", vals(next), others)
	}
	// Without IODEF configured, a live iodef stays.
	s.IODEF = ""
	if next, _ := MergeCAA(live, s); !strings.Contains(vals(next), "mailto:old@d.test") {
		t.Fatalf("iodef dropped: %s", vals(next))
	}
}

func TestRemovalSignatureMain(t *testing.T) {
	live := []libdns.CAA{
		caa("issue", "letsencrypt.org"),
		caa("issue", "letsencrypt.org; validationmethods=dns-01"),
		caa("issuewild", "letsencrypt.org; accounturi="+acct+"; validationmethods=dns-01"),
		caa("issue", "digicert.com; validationmethods=dns-01"),
	}
	rm := removalCAA(live, Spec{Name: "d.test", Issuer: "letsencrypt.org", Main: true})
	if vals(rm) != vals(live[1:3]) {
		t.Fatalf("removal %s", vals(rm))
	}
	// Enrolled: exactly the owned refs.
	owned := []Ref{{Name: "@", Type: "CAA", Value: live[1].RR().Data}}
	if rm := removalCAA(live, Spec{Name: "d.test", Issuer: "letsencrypt.org", Owned: owned}); vals(rm) != vals(live[1:2]) {
		t.Fatalf("enrolled removal %s", vals(rm))
	}
}

func dcaa(flag uint8, tag, value string) *dns.CAA {
	return &dns.CAA{Flag: flag, Tag: tag, Value: value}
}

func TestWouldIssueFormatting(t *testing.T) {
	le := "letsencrypt.org"
	for _, c := range []struct {
		name     string
		rrs      []*dns.CAA
		wildcard bool
		want     bool
	}{
		{"empty set issues", nil, false, true},
		{"ours", []*dns.CAA{dcaa(0, "issue", CAAValue(le, acct))}, false, true},
		{"case, trailing dot, spaces, reordered", []*dns.CAA{dcaa(0, "ISSUE", " LetsEncrypt.org. ;validationmethods = dns-01,http-01 ; accounturi="+acct+" ")}, false, true},
		{"critical unknown tag", []*dns.CAA{dcaa(0, "issue", le), dcaa(128, "tbs", "x")}, false, false},
		{"non-critical unknown tag", []*dns.CAA{dcaa(0, "issue", le), dcaa(0, "tbs", "x")}, false, true},
		{"other account", []*dns.CAA{dcaa(0, "issue", CAAValue(le, "https://other/acct/9"))}, false, false},
		{"http-01 only", []*dns.CAA{dcaa(0, "issue", le+"; validationmethods=http-01")}, false, false},
		{"other CA", []*dns.CAA{dcaa(0, "issue", "digicert.com")}, false, false},
		{"empty issuer", []*dns.CAA{dcaa(0, "issue", ";")}, false, false},
		{"issuewild other CA blocks wildcard", []*dns.CAA{dcaa(0, "issue", le), dcaa(0, "issuewild", "digicert.com")}, true, false},
		{"issuewild other CA, not wildcard", []*dns.CAA{dcaa(0, "issue", le), dcaa(0, "issuewild", "digicert.com")}, false, true},
		{"issue only covers wildcard", []*dns.CAA{dcaa(0, "issue", le)}, true, true},
		{"iodef only", []*dns.CAA{dcaa(0, "iodef", "mailto:x@y")}, false, true},
	} {
		if got := WouldIssue(c.rrs, le, acct, c.wildcard); got != c.want {
			t.Errorf("%s: WouldIssue = %v", c.name, got)
		}
	}
	if WouldIssue(nil, "", acct, false) {
		t.Error("an unknown issuer was judged as issuing")
	}
	// CA-only judgement (no account yet) against a pinned set fails closed.
	if WouldIssue([]*dns.CAA{dcaa(0, "issue", CAAValue(le, acct))}, le, "", false) {
		t.Error("a pinned set issues for no account")
	}
}

func serveZone(t *testing.T, z *fakedns.Zone) []string {
	t.Helper()
	s, err := fakedns.Serve(z, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return []string{s.Addr}
}

func TestEffectiveCAAClimbs(t *testing.T) {
	z := fakedns.NewZone()
	z.SetSOA("example.test")
	z.Set("example.test", libdns.CAA{Name: "@", Tag: "issue", Value: "letsencrypt.org"}.RR())
	z.Set("team-a.portcullis.example.test", libdns.RR{Name: "team-a.portcullis", Type: "A", Data: "203.0.113.10"})
	r := serveZone(t, z)
	owner, rrs, err := EffectiveCAA(context.Background(), r, "team-a.portcullis.example.test")
	if err != nil || owner != "example.test" || len(rrs) != 1 || rrs[0].Value != "letsencrypt.org" {
		t.Fatalf("%q %v %v", owner, rrs, err)
	}
	if owner, _, _ := EffectiveCAA(context.Background(), r, "*.nx.example.test"); owner != "example.test" {
		t.Fatalf("wildcard / NXDOMAIN climb: %q", owner)
	}
	// Nothing anywhere: owner "", no error (stops before the TLD).
	z.Set("example.test")
	if owner, rrs, err := EffectiveCAA(context.Background(), r, "a.example.test"); owner != "" || rrs != nil || err != nil {
		t.Fatalf("%q %v %v", owner, rrs, err)
	}
	if _, _, err := EffectiveCAA(context.Background(), []string{"127.0.0.1:1"}, "a.example.test"); err == nil {
		t.Fatal("a dead resolver gave no error")
	}
}

func TestEnrolledChildOwnPin(t *testing.T) {
	z := fakedns.NewZone()
	z.SetSOA("example.test")
	main := "portcullis.example.test"
	child := "team-a." + main
	z.Set(main, libdns.CAA{Name: "portcullis", Tag: "issue", Value: CAAValue("letsencrypt.org", "https://traefik/acct/1")}.RR())
	z.Set(child, libdns.CAA{Name: "team-a.portcullis", Tag: "issue", Value: CAAValue("letsencrypt.org", acct)}.RR(),
		libdns.CAA{Name: "team-a.portcullis", Tag: "issuewild", Value: CAAValue("letsencrypt.org", acct)}.RR())
	r := serveZone(t, z)
	owner, rrs, err := EffectiveCAA(context.Background(), r, child)
	if err != nil || owner != child {
		t.Fatalf("%q %v", owner, err)
	}
	if !WouldIssue(rrs, "letsencrypt.org", acct, false) || !WouldIssue(rrs, "letsencrypt.org", acct, true) {
		t.Fatal("the child's own pin doesn't issue for its account")
	}
	// The main domain's pin stays the Traefik account's.
	_, mrrs, _ := EffectiveCAA(context.Background(), r, main)
	if WouldIssue(mrrs, "letsencrypt.org", acct, false) {
		t.Fatal("the main domain's pin was widened")
	}
}
