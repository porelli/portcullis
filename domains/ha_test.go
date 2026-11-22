package main

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/fakedns"
)

// High availability (contract §12.4, plan Task 28 and fix round 1): the
// added domains' address sets follow frontdoor-status.

var haDocs = frontdoor.AddrPolicy{AllowDocumentation: true}

// haNodes are the cluster's active nodes' public addresses (the follower
// accepts no other).
var haNodes = []string{"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.5", "2001:db8::7"}

// haFiles is the mounted directory of one test: frontdoor-status
// (status.json, leader) and portcullis-cluster-addresses.
type haFiles struct {
	dir, cluster string
	gen          int64
}

func (f *haFiles) status() string { return filepath.Join(f.dir, "status.json") }

// haDoc is a status.json from leader with the given sets, written at.
func haDoc(leader string, gen int64, at time.Time, apex, wild []string) string {
	st := frontdoor.Status{V: 1, State: "leading", Leader: leader, Generation: gen, WrittenAt: at.UTC(), Names: map[string]frontdoor.NameStatus{
		testMain:        {Addresses: apex, TTL: 60, WorstCaseS: 90},
		"*." + testMain: {Addresses: wild, TTL: 60, WorstCaseS: 90},
	}}
	b, _ := json.Marshal(st)
	return string(b)
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// newHAEnv: the service in HA mode reading the files the test writes (no
// status yet).
func newHAEnv(t *testing.T) (*testEnv, *haFiles) {
	t.Helper()
	f := &haFiles{dir: t.TempDir()}
	f.cluster = filepath.Join(t.TempDir(), "addresses.json")
	nodes := map[string]any{}
	for i, a := range haNodes {
		nodes[string(rune('a'+i))] = map[string]any{"mesh": "10.215.0.1", "public": []string{a}, "state": "active"}
	}
	nodes["gone"] = map[string]any{"mesh": "10.215.0.9", "public": []string{"198.51.100.9"}, "state": "removed"}
	b, _ := json.Marshal(map[string]any{"v": 1, "nodes": nodes})
	writeFile(t, f.cluster, string(b))
	e := newEnvWith(t, false, func(c *Config) {
		c.HA, c.FrontdoorStatusFile, c.ClusterAddressesFile, c.AddrPolicy = true, f.status(), f.cluster, haDocs
		c.IPv4 = netip.Addr{} // the server's own address isn't used in HA
	})
	return e, f
}

// publish writes a fresh document of leader fd-1 (the next generation,
// written now) and reads it.
func (e *testEnv) publish(f *haFiles, apex, wild []string) {
	e.t.Helper()
	f.gen++
	e.publishRaw(f, "fd-1", haDoc("fd-1", f.gen, e.clock.now(), apex, wild))
}

func (e *testEnv) publishRaw(f *haFiles, leaderKey, doc string) {
	e.t.Helper()
	writeFile(e.t, filepath.Join(f.dir, frontdoor.StatusLeaderKey), leaderKey)
	writeFile(e.t, f.status(), doc)
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

// settle kicks the worker and waits until the domain is ready with no
// work running, for several of the worker's ticks in a row (review nit5:
// a negative check waits on the worker, not on a fixed sleep alone).
func (e *testEnv) settle(name string) {
	e.t.Helper()
	e.svc.Kick()
	quiet := 0
	e.waitFor(name+" idle", 20*time.Second, func() bool {
		if e.idle(name) {
			quiet++
		} else {
			quiet = 0
		}
		return quiet >= 10 // 10 polls of 20 ms: four 50 ms ticks
	})
}

func (e *testEnv) planNotices(name string) string {
	e.t.Helper()
	code, body := e.do("GET", "/domains/"+name+"/dns", "", true)
	if code != 200 {
		e.t.Fatalf("plan %d %s", code, body)
	}
	return body
}

// TestHAAddedDomainFollowsFrontdoor: <d> and *.<d> follow <main> and
// *.<main>: the whole set at once the first time (ruling B), then one
// change per name per 60 s, a removed address dropped but never the last
// of its type, a foreign record never touched (ruling M5) and named;
// DELETE removes only what the follower wrote.
func TestHAAddedDomainFollowsFrontdoor(t *testing.T) {
	const a1, a2, a99 = "198.51.100.1", "198.51.100.2", "198.51.100.99"
	e, f := newHAEnv(t)
	e.publish(f, []string{a1, a2}, []string{a1, a2})
	const d = "team-h.example.org"
	e.zone.Set(d, libdns.RR{Name: "@", Type: "A", Data: a99, TTL: time.Hour})
	if code, body := e.do("PUT", "/domains/"+d, creds(goodToken), true); code != 202 {
		t.Fatalf("enroll = %d %s", code, body)
	}
	e.waitState(d, StateReady, 60*time.Second)
	// Ruling B: the whole set in the first step; the foreign a99 stays.
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a2, a99}) {
		t.Fatalf("%s = %v, want the whole set next to the foreign a99", d, got)
	}
	if got := addrs(e.zone, "*."+d); !slices.Equal(got, []string{a1, a2}) {
		t.Fatalf("*.%s = %v", d, got)
	}
	for _, rr := range addrRecords(e.zone, "*."+d) {
		if rr.TTL != frontdoor.MinTTL {
			t.Errorf("TTL %s, want the front door's 60 s", rr.TTL)
		}
	}
	if p := e.planNotices(d); !strings.Contains(p, "foreign A 198.51.100.99 at "+d+" kept") {
		t.Errorf("the plan doesn't name the kept foreign record: %s", p)
	}
	if !strings.Contains(e.logs.String(), "foreign A 198.51.100.99 at "+d+" kept") {
		t.Errorf("the kept foreign record isn't logged")
	}

	// Within the 60 s nothing more: a new document, and an explicit apply.
	e.clock.advance(10 * time.Second)
	e.publish(f, []string{a2}, []string{a2})
	if code, body := e.do("POST", "/domains/"+d+"/dns/apply", `{"sets":["address"]}`, true); code != 202 {
		t.Fatalf("apply = %d %s", code, body)
	}
	e.settle(d)
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a2, a99}) {
		t.Fatalf("a change within 60 s: %v", got)
	}
	// 60 s later the front door's removal of a1 goes, at both names.
	e.clock.advance(51 * time.Second)
	e.svc.Kick()
	e.waitAddrs(d, a2, a99)
	e.waitAddrs("*."+d, a2)

	// The front door publishes only an IPv6 (a node's): the AAAA goes in,
	// the last A (ours) stays and is named.
	e.clock.advance(61 * time.Second)
	e.publish(f, []string{"2001:db8::7"}, []string{a2})
	e.waitAddrs(d, "2001:db8::7", a2, a99)
	e.clock.advance(61 * time.Second)
	e.settle(d)
	if got := addrs(e.zone, d); !slices.Contains(got, a2) {
		t.Fatalf("the last A of %s went: %v", d, got)
	}
	if p := e.planNotices(d); !strings.Contains(p, "A 198.51.100.2 at "+d+" kept: it is the last A address there") {
		t.Errorf("the kept last A isn't named: %s", p)
	}

	// DELETE removes the follower's records only: the foreign a99 stays.
	if code, _ := e.do("DELETE", "/domains/"+d, "", true); code != 204 {
		t.Fatalf("delete = %d", code)
	}
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a99}) {
		t.Errorf("after delete %s = %v, want only the foreign a99", d, got)
	}
	if got := addrs(e.zone, "*."+d); len(got) != 0 {
		t.Errorf("after delete *.%s = %v", d, got)
	}
}

// TestHAFailClosed (review M2, M4): a document the follower can't trust
// changes nothing, keeps the last good set, and is a plan notice: not the
// front door's write (leader keys disagree, none), a rollback, a stale one,
// an address that isn't a node's, a private one, an empty set, a broken
// document, a missing cluster-addresses document.
func TestHAFailClosed(t *testing.T) {
	const a1, a2 = "198.51.100.1", "198.51.100.2"
	e, f := newHAEnv(t)
	e.publish(f, []string{a1, a2}, []string{a1, a2})
	const d = "team-f.example.org"
	e.do("PUT", "/domains/"+d, creds(goodToken), true)
	e.waitState(d, StateReady, 60*time.Second)
	e.waitAddrs(d, a1, a2)
	now := func() time.Time { return e.clock.now() }
	for _, c := range []struct {
		name, leaderKey, doc, why string
	}{
		{"another leader key", "fd-2", haDoc("fd-1", 100, now(), []string{a2}, []string{a2}), "isn't the ConfigMap's leader"},
		{"no leader", "", haDoc("", 100, now(), []string{a2}, []string{a2}), "isn't the ConfigMap's leader"},
		{"a rollback", "fd-1", haDoc("fd-1", 0+1, now(), []string{a2}, []string{a2}), "rollback"},
		{"stale", "fd-1", haDoc("fd-1", 100, now().Add(-3*time.Minute), []string{a2}, []string{a2}), "before the last document"},
		{"not a node's", "fd-1", haDoc("fd-1", 100, now(), []string{"198.51.100.9"}, []string{a2}), "isn't an active node's public address"},
		{"private", "fd-1", haDoc("fd-1", 100, now(), []string{a2, "10.0.0.7"}, []string{a2}), "not a public address"},
		{"an empty set", "fd-1", haDoc("fd-1", 100, now(), []string{}, []string{a2}), "has no address for"},
		{"broken", "fd-1", `{"v":1}{"v":1}`, "doesn't decode"},
	} {
		e.clock.advance(61 * time.Second)
		if c.name == "a rollback" {
			f.gen = 50
			e.publish(f, []string{a1, a2}, []string{a1, a2}) // generation 51 accepted
		}
		e.publishRaw(f, c.leaderKey, c.doc)
		e.settle(d)
		if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a2}) {
			t.Fatalf("%s: %s changed to %v", c.name, d, got)
		}
		if p := e.planNotices(d); !strings.Contains(p, c.why) || !strings.Contains(p, "isn't following the front door") {
			t.Errorf("%s: the plan doesn't say so (%q): %s", c.name, c.why, p)
		}
	}
	// Stale: a good document that stops being written.
	e.clock.advance(61 * time.Second)
	e.publish(f, []string{a1, a2}, []string{a1, a2})
	e.clock.advance(haStale + time.Second)
	e.svc.haRefresh()
	if p := e.planNotices(d); !strings.Contains(p, "frontdoor-status is stale") {
		t.Errorf("a stale status isn't a notice: %s", p)
	}
	// The cluster's addresses missing: nothing can be checked.
	os.Remove(f.cluster)
	e.publish(f, []string{a2}, []string{a2})
	e.settle(d)
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a2}) {
		t.Fatalf("without portcullis-cluster-addresses %s changed to %v", d, got)
	}
	// The main domain's plan names the problem too (the status line).
	if code, body := e.do("GET", "/main/dns", "", true); code != 200 || !strings.Contains(body, "portcullis-cluster-addresses isn't readable") {
		t.Errorf("main plan %d: %s", code, body)
	}
}

// TestHAConvergedNoProviderReads (review I1): a name whose only
// difference is a record the follower keeps (a foreign AAAA, the front
// door publishing IPv4 only) is converged: over several minutes no records
// step runs and the provider isn't read; the plan names the AAAA once.
func TestHAConvergedNoProviderReads(t *testing.T) {
	const a1 = "198.51.100.1"
	e, f := newHAEnv(t)
	e.publish(f, []string{a1}, []string{a1})
	const d = "team-c.example.org"
	e.zone.Set(d, libdns.RR{Name: "@", Type: "AAAA", Data: "2001:db8::99", TTL: time.Hour})
	e.do("PUT", "/domains/"+d, creds(goodToken), true)
	e.waitState(d, StateReady, 60*time.Second)
	e.waitAddrs(d, "2001:db8::99", a1)
	var gets atomic.Int32
	e.setHook(func(op string, _ []libdns.Record, _ string) error {
		if op == "get" {
			gets.Add(1)
		}
		return nil
	})
	for range 4 {
		e.clock.advance(61 * time.Second)
		e.svc.haRefresh()
		e.settle(d)
	}
	if n := gets.Load(); n != 0 {
		t.Errorf("%d provider reads while converged", n)
	}
	if p := e.planNotices(d); !strings.Contains(p, "foreign AAAA 2001:db8::99 at "+d+" kept: the front door publishes IPv4 only") {
		t.Errorf("the plan doesn't name the AAAA: %s", p)
	}
	if n := strings.Count(e.logs.String(), "foreign AAAA 2001:db8::99 at "+d+" kept"); n != 1 {
		t.Errorf("the kept AAAA logged %d times, want once", n)
	}
	// A change of the front door's set makes it due again (one read).
	e.publish(f, []string{a1, "198.51.100.2"}, []string{a1})
	e.waitAddrs(d, "2001:db8::99", a1, "198.51.100.2")
}

// TestHAEarlyErrorKeepsState (review M1): a provider read that fails
// before any change keeps the stored set and the 60 s clock.
func TestHAEarlyErrorKeepsState(t *testing.T) {
	const a1, a2 = "198.51.100.1", "198.51.100.2"
	e, f := newHAEnv(t)
	e.publish(f, []string{a1}, []string{a1})
	const d = "team-e.example.org"
	e.do("PUT", "/domains/"+d, creds(goodToken), true)
	e.waitState(d, StateReady, 60*time.Second)
	before := e.domain(d)
	if len(before.HAAddrs) != 2 || before.HAChanged[d].IsZero() {
		t.Fatalf("stored %v %v", before.HAAddrs, before.HAChanged)
	}
	e.setHook(func(op string, _ []libdns.Record, _ string) error {
		if op == "get" {
			return errors.New("provider: 503")
		}
		return nil
	})
	e.clock.advance(61 * time.Second)
	e.publish(f, []string{a1, a2}, []string{a1})
	e.waitState(d, StateError, 20*time.Second)
	after := e.domain(d)
	if !slices.Equal(after.HAAddrs[d], before.HAAddrs[d]) || !after.HAChanged[d].Equal(before.HAChanged[d]) || !slices.Equal(after.HAOurs[d], before.HAOurs[d]) {
		t.Fatalf("a failed read wiped the follower's state: %v %v → %v %v", before.HAAddrs, before.HAChanged, after.HAAddrs, after.HAChanged)
	}
	e.setHook(nil)
	e.clock.advance(2 * time.Minute) // past the backoff
	e.svc.Kick()
	e.waitAddrs(d, a1, a2)
}

// TestHARestartKeepsRateLimit (review M7): the 60 s per name survives a
// restart (HAChanged is stored).
func TestHARestartKeepsRateLimit(t *testing.T) {
	const a1, a2 = "198.51.100.1", "198.51.100.2"
	e, f := newHAEnv(t)
	e.publish(f, []string{a1}, []string{a1})
	const d = "team-r.example.org"
	e.do("PUT", "/domains/"+d, creds(goodToken), true)
	e.waitState(d, StateReady, 60*time.Second)
	e.waitAddrs(d, a1)
	e.clock.advance(61 * time.Second)
	e.publish(f, []string{a1, a2}, []string{a1})
	e.waitAddrs(d, a1, a2) // a change at T
	e.clock.advance(10 * time.Second)
	e.restart(nil)
	e.publish(f, []string{a2}, []string{a1})
	e.settle(d)
	if got := addrs(e.zone, d); !slices.Equal(got, []string{a1, a2}) {
		t.Fatalf("a change 10 s after the last one, across a restart: %v", got)
	}
	e.clock.advance(51 * time.Second)
	e.svc.Kick()
	e.waitAddrs(d, a2)
}

// TestHAStatusUnknownNoAddresses: without a readable frontdoor-status a
// new added domain gets no address at all (no fallback to the server's own
// IPv4) and is in error, naming the front door.
func TestHAStatusUnknownNoAddresses(t *testing.T) {
	e, f := newHAEnv(t)
	const d = "team-u.example.org"
	e.do("PUT", "/domains/"+d, creds(goodToken), true)
	v := e.waitState(d, StateError, 60*time.Second)
	if !strings.Contains(v.LastError, "front door") {
		t.Errorf("last_error %q", v.LastError)
	}
	if got := addrs(e.zone, d); len(got) != 0 {
		t.Fatalf("%s = %v without a front door status", d, got)
	}
	e.publish(f, []string{"198.51.100.5"}, []string{"198.51.100.5"})
	e.clock.advance(2 * time.Minute) // past the backoff
	e.svc.Kick()
	e.waitAddrs(d, "198.51.100.5")
	e.waitAddrs("*."+d, "198.51.100.5")
}

func TestParseFrontdoorStatus(t *testing.T) {
	nodes := map[string]bool{"198.51.100.1": true, "198.51.100.2": true, "2606:4700::1": true, "8.8.8.8": true, "100.64.0.1": true}
	at := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	ok := haDoc("fd", 1, at, []string{"198.51.100.2", "198.51.100.1", "198.51.100.1"}, []string{"2606:4700::1"})
	h, err := parseFrontdoorStatus([]byte(ok), "fd\n", testMain, haDocs, nodes)
	if err != nil || !slices.Equal(h.Apex, []string{"198.51.100.1", "198.51.100.2"}) || !slices.Equal(h.Wild, []string{"2606:4700::1"}) || h.Leader != "fd" || !h.WrittenAt.Equal(at) {
		t.Fatalf("%+v %v", h, err)
	}
	strict := frontdoor.AddrPolicy{}
	for name, c := range map[string]struct{ doc, leader string }{
		"documentation address in production": {ok, "fd"},
		"private":                             {haDoc("fd", 1, at, []string{"8.8.8.8", "192.168.1.2"}, []string{"8.8.8.8"}), "fd"},
		"cgnat":                               {haDoc("fd", 1, at, []string{"100.64.0.1"}, []string{"8.8.8.8"}), "fd"},
		"not a node's":                        {haDoc("fd", 1, at, []string{"1.1.1.1"}, []string{"8.8.8.8"}), "fd"},
		"another leader":                      {haDoc("fd", 1, at, []string{"8.8.8.8"}, []string{"8.8.8.8"}), "fd-2"},
		"no write time":                       {haDoc("fd", 1, time.Time{}, []string{"8.8.8.8"}, []string{"8.8.8.8"}), "fd"},
		"no generation":                       {haDoc("fd", 0, at, []string{"8.8.8.8"}, []string{"8.8.8.8"}), "fd"},
		"no wildcard":                         {`{"v":1,"leader":"fd","generation":1,"written_at":"2026-11-18T10:00:00Z","names":{"` + testMain + `":{"addresses":["8.8.8.8"]}}}`, "fd"},
		"empty":                               {haDoc("fd", 1, at, []string{}, []string{"8.8.8.8"}), "fd"},
		"version":                             {`{"v":2,"names":{}}`, "fd"},
		"trailing data":                       {haDoc("fd", 1, at, []string{"8.8.8.8"}, []string{"8.8.8.8"}) + `{"v":1}`, "fd"},
		"junk":                                {`[]`, "fd"},
	} {
		if _, err := parseFrontdoorStatus([]byte(c.doc), c.leader, testMain, strict, nodes); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHANextNeverForeignNeverLast(t *testing.T) {
	const x = "x.example.org"
	for _, c := range []struct {
		name             string
		have, want, ours []string
		first            bool
		want2            []string // "op value"
	}{
		{"first time: the whole set at once", nil, []string{"198.51.100.2", "198.51.100.1"}, nil, true, []string{"add 198.51.100.1", "add 198.51.100.2"}},
		{"first time: a foreign record stays", []string{"198.51.100.9"}, []string{"198.51.100.1"}, nil, true, []string{"add 198.51.100.1"}},
		{"one add", []string{"198.51.100.1"}, []string{"198.51.100.1", "198.51.100.2"}, []string{"198.51.100.1"}, false, []string{"add 198.51.100.2"}},
		{"our stale one goes", []string{"198.51.100.1", "198.51.100.2"}, []string{"198.51.100.2"}, []string{"198.51.100.1", "198.51.100.2"}, false, []string{"remove 198.51.100.1"}},
		{"a foreign one never goes", []string{"198.51.100.9", "198.51.100.2"}, []string{"198.51.100.2"}, []string{"198.51.100.2"}, false, nil},
		{"a foreign one isn't the type's other address", []string{"198.51.100.9", "198.51.100.1"}, []string{"2001:db8::1"}, []string{"198.51.100.1"}, false, []string{"add 2001:db8::1"}},
		{"the last A stays (IPv6 added first)", []string{"198.51.100.1"}, []string{"2001:db8::1"}, []string{"198.51.100.1"}, false, []string{"add 2001:db8::1"}},
		{"converged with the last A", []string{"198.51.100.1", "2001:db8::1"}, []string{"2001:db8::1"}, []string{"198.51.100.1", "2001:db8::1"}, false, nil},
		{"removal before addition", []string{"198.51.100.1", "198.51.100.3"}, []string{"198.51.100.2"}, []string{"198.51.100.1", "198.51.100.3"}, false, []string{"remove 198.51.100.1"}},
		{"nothing to do", []string{"198.51.100.2"}, []string{"198.51.100.2"}, []string{"198.51.100.2"}, false, nil},
	} {
		var got []string
		for _, ch := range haNext(x, c.have, c.want, c.ours, c.first) {
			got = append(got, ch.Op+" "+ch.Value)
		}
		if !slices.Equal(got, c.want2) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want2)
		}
	}
	r := haResidual(x, []string{"198.51.100.9", "2001:db8::9", "198.51.100.1"}, []string{"2001:db8::1"}, []string{"198.51.100.1"})
	if len(r) != 3 || !strings.Contains(r[0], "foreign A 198.51.100.9") || !strings.Contains(r[1], "foreign AAAA 2001:db8::9") || !strings.Contains(r[2], "last A address") {
		t.Errorf("residual %q", r)
	}
}
