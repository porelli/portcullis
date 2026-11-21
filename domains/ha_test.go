package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/fakedns"
)

// High availability (contract §12.4, plan Task 28): the added domains'
// address sets follow frontdoor-status.

var haDocs = frontdoor.AddrPolicy{AllowDocumentation: true, Excluded: nil}

// haStatus is a frontdoor-status status.json with the given sets.
func haStatus(apex, wild []string) string {
	st := frontdoor.Status{V: 1, State: "leading", Names: map[string]frontdoor.NameStatus{
		testMain:        {Addresses: apex, TTL: 60, WorstCaseS: 90},
		"*." + testMain: {Addresses: wild, TTL: 60, WorstCaseS: 90},
	}}
	b, _ := json.Marshal(st)
	return string(b)
}

// newHAEnv: the service in HA mode reading a status file the test writes.
func newHAEnv(t *testing.T, status string) (*testEnv, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status.json")
	if status != "" {
		if err := os.WriteFile(path, []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e := newEnvWith(t, false, func(c *Config) {
		c.HA, c.FrontdoorStatusFile, c.AddrPolicy = true, path, haDocs
		c.IPv4 = netip.Addr{} // the server's own address isn't used in HA
	})
	return e, path
}

func (e *testEnv) setStatus(path, doc string) {
	e.t.Helper()
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		e.t.Fatal(err)
	}
	e.svc.haRefresh()
}

// addrs are the A / AAAA values at name, sorted.
func addrs(z *fakedns.Zone, name string) []string {
	var out []string
	for _, rr := range addrRecords(z, name) {
		out = append(out, rr.Data)
	}
	sort.Strings(out)
	return out
}

func (e *testEnv) waitAddrs(name string, want ...string) {
	e.t.Helper()
	sort.Strings(want)
	e.waitFor(name+" = "+strings.Join(want, ","), 20*time.Second, func() bool { return slices.Equal(addrs(e.zone, name), want) })
}

// TestHAAddedDomainFollowsFrontdoor: an added domain's <d> and *.<d>
// follow the front door's <main> and *.<main>, one change per name per
// 60 s, append first, a foreign address replaced, a dead address removed
// but never the last of its type; DELETE removes what it wrote.
func TestHAAddedDomainFollowsFrontdoor(t *testing.T) {
	const a1, a2, a99 = "198.51.100.1", "198.51.100.2", "198.51.100.99"
	e, path := newHAEnv(t, haStatus([]string{a1, a2}, []string{a1, a2}))
	const d = "team-h.example.org"
	e.zone.Set(d, libdns.RR{Name: "@", Type: "A", Data: a99, TTL: time.Hour})
	if code, body := e.do("PUT", "/domains/"+d, creds(goodToken), true); code != 202 {
		t.Fatalf("enroll = %d %s", code, body)
	}
	e.waitState(d, StateReady, 60*time.Second)
	// One change per name: <d>'s foreign a99 is its last A, so a1 is
	// appended first; *.<d> gets a1.
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a99}) {
		t.Fatalf("%s = %v, want a1 appended next to the foreign a99", d, got)
	}
	if got := addrs(e.zone, "*."+d); !slices.Equal(got, []string{a1}) {
		t.Fatalf("*.%s = %v", d, got)
	}
	for _, rr := range addrRecords(e.zone, "*."+d) {
		if rr.TTL != frontdoor.MinTTL {
			t.Errorf("TTL %s, want the front door's 60 s", rr.TTL)
		}
	}
	// Nothing more within the 60 s.
	time.Sleep(300 * time.Millisecond)
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a99}) {
		t.Fatalf("a second change within 60 s: %v", got)
	}
	// An explicit apply of the address set within the 60 s changes
	// nothing either (the step's own rate limit).
	if code, body := e.do("POST", "/domains/"+d+"/dns/apply", `{"sets":["address"]}`, true); code != 202 {
		t.Fatalf("apply = %d %s", code, body)
	}
	e.waitFor("the apply step", 10*time.Second, func() bool { return len(e.domain(d).DueSets) == 0 && e.idle(d) })
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a99}) {
		t.Fatalf("a second change within 60 s through dns/apply: %v", got)
	}
	e.clock.advance(61 * time.Second)
	e.waitAddrs(d, a1)
	e.waitAddrs("*."+d, a1, a2)
	e.clock.advance(61 * time.Second)
	e.waitAddrs(d, a1, a2)

	// The front door removes a1 (its node died): it goes at both names.
	e.clock.advance(61 * time.Second)
	e.setStatus(path, haStatus([]string{a2}, []string{a2}))
	e.waitAddrs(d, a2)
	e.waitAddrs("*."+d, a2)

	// Fail closed: a non-public address, an empty set, a broken
	// document, a missing file: nothing changes.
	for _, bad := range []string{
		haStatus([]string{a2, "10.0.0.7"}, []string{a2}),
		haStatus([]string{}, []string{a2}),
		haStatus([]string{"198.51.100.3"}, nil),
		`{"v":2}`, `{`, "",
	} {
		e.clock.advance(61 * time.Second)
		e.setStatus(path, bad)
		time.Sleep(200 * time.Millisecond)
		if got := addrs(e.zone, d); !slices.Equal(got, []string{a2}) {
			t.Fatalf("status %q changed %s to %v", bad, d, got)
		}
	}
	os.Remove(path)
	e.svc.haRefresh()
	time.Sleep(200 * time.Millisecond)
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a2}) {
		t.Fatalf("an unreadable status changed %s to %v", d, got)
	}

	// The front door publishes only an IPv6: the AAAA is appended, the
	// last A never goes.
	e.clock.advance(61 * time.Second)
	e.setStatus(path, haStatus([]string{"2001:db8::7"}, []string{a2}))
	e.waitAddrs(d, "2001:db8::7", a2)
	e.clock.advance(61 * time.Second)
	time.Sleep(300 * time.Millisecond)
	if got := addrs(e.zone, d); !slices.Contains(got, a2) {
		t.Fatalf("the last A of %s went: %v", d, got)
	}
	if !strings.Contains(e.logs.String(), "high availability: add "+d+" 198.51.100.1") {
		t.Errorf("the follower's changes aren't logged:\n%s", e.logs.String())
	}

	// DELETE removes the records the follower wrote.
	if code, _ := e.do("DELETE", "/domains/"+d, "", true); code != 204 {
		t.Fatalf("delete = %d", code)
	}
	for _, n := range []string{d, "*." + d} {
		if got := addrs(e.zone, n); len(got) != 0 {
			t.Errorf("after delete %s = %v", n, got)
		}
	}
}

// TestHAStatusUnknownNoAddresses: without a readable frontdoor-status a
// new added domain gets no address at all (no fallback to the server's
// own IPv4) and is in error, naming the front door.
func TestHAStatusUnknownNoAddresses(t *testing.T) {
	e, path := newHAEnv(t, "")
	const d = "team-u.example.org"
	e.do("PUT", "/domains/"+d, creds(goodToken), true)
	v := e.waitState(d, StateError, 60*time.Second)
	if !strings.Contains(v.LastError, "front door") {
		t.Errorf("last_error %q", v.LastError)
	}
	if got := addrs(e.zone, d); len(got) != 0 {
		t.Fatalf("%s = %v without a front door status", d, got)
	}
	// Once the front door writes its status the domain gets its set.
	e.setStatus(path, haStatus([]string{"198.51.100.5"}, []string{"198.51.100.5"}))
	e.clock.advance(2 * time.Minute) // past the backoff
	e.waitAddrs(d, "198.51.100.5")
	e.waitAddrs("*."+d, "198.51.100.5")
}

func TestParseFrontdoorStatus(t *testing.T) {
	strict := frontdoor.AddrPolicy{Excluded: nil}
	ok := haStatus([]string{"198.51.100.2", "198.51.100.1", "198.51.100.1"}, []string{"2606:4700::1"})
	h, err := parseFrontdoorStatus([]byte(ok), testMain, haDocs)
	if err != nil || !slices.Equal(h.Apex, []string{"198.51.100.1", "198.51.100.2"}) || !slices.Equal(h.Wild, []string{"2606:4700::1"}) {
		t.Fatalf("%+v %v", h, err)
	}
	for name, doc := range map[string]string{
		"documentation address in production": ok,
		"private":                             haStatus([]string{"8.8.8.8", "192.168.1.2"}, []string{"8.8.8.8"}),
		"cgnat":                               haStatus([]string{"100.64.0.1"}, []string{"8.8.8.8"}),
		"not an address":                      haStatus([]string{"x"}, []string{"8.8.8.8"}),
		"no wildcard":                         `{"v":1,"names":{"` + testMain + `":{"addresses":["8.8.8.8"]}}}`,
		"empty":                               haStatus([]string{}, []string{"8.8.8.8"}),
		"version":                             `{"v":2,"names":{}}`,
		"junk":                                `[]`,
	} {
		if _, err := parseFrontdoorStatus([]byte(doc), testMain, strict); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHANextNeverLastOfType(t *testing.T) {
	for _, c := range []struct {
		have, want []string
		op, value  string
	}{
		{[]string{"198.51.100.1"}, []string{"198.51.100.2"}, "add", "198.51.100.2"},
		{[]string{"198.51.100.1", "198.51.100.2"}, []string{"198.51.100.2"}, "remove", "198.51.100.1"},
		{[]string{"198.51.100.1"}, []string{"2001:db8::1"}, "add", "2001:db8::1"},
		{[]string{"198.51.100.1", "2001:db8::1"}, []string{"2001:db8::1"}, "", ""},
		{[]string{"198.51.100.1", "198.51.100.3"}, []string{"198.51.100.2"}, "remove", "198.51.100.1"},
		{[]string{"198.51.100.2"}, []string{"198.51.100.2"}, "", ""},
	} {
		got := haNext("x.example.org", c.have, c.want)
		if (got == nil) != (c.op == "") || got != nil && (got.Op != c.op || got.Value != c.value) {
			t.Errorf("have %v want %v: %+v, want %s %s", c.have, c.want, got, c.op, c.value)
		}
	}
}
