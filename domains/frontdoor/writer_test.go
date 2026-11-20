package frontdoor

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// fakeProvider is a zone of A records. After every call it asserts that
// no address name it holds a record for is left empty; failDelete makes
// deletes fail.
type fakeProvider struct {
	t          *testing.T
	mu         sync.Mutex
	zone       string
	recs       map[string][]string // relative name → values
	failDelete int                 // deletes to fail
	calls      []string
	watch      []string // the names that must never be empty
}

func (f *fakeProvider) check() {
	for _, n := range f.watch {
		if len(f.recs[n]) == 0 {
			f.t.Errorf("after %v: %s has no address", f.calls, n)
		}
	}
}

func (f *fakeProvider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "get")
	var out []libdns.Record
	for n, vs := range f.recs {
		for _, v := range vs {
			out = append(out, libdns.RR{Name: n, Type: "A", Data: v, TTL: 600 * time.Second})
		}
	}
	return out, nil
}

func (f *fakeProvider) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.check()
	for _, r := range recs {
		rr := r.RR()
		f.calls = append(f.calls, "append "+rr.Name+" "+rr.Data)
		f.recs[rr.Name] = append(f.recs[rr.Name], rr.Data)
	}
	return recs, nil
}

func (f *fakeProvider) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	defer f.check()
	for _, r := range recs {
		rr := r.RR()
		f.calls = append(f.calls, "delete "+rr.Name+" "+rr.Data)
		if rr.TTL != 0 {
			f.t.Errorf("delete with a TTL (%s): Porkbun stores 600 s, an exact-TTL match would miss", rr.TTL)
		}
		if f.failDelete > 0 {
			f.failDelete--
			return nil, errors.New("provider: 500")
		}
		var keep []string
		for _, v := range f.recs[rr.Name] {
			if v != rr.Data {
				keep = append(keep, v)
			}
		}
		f.recs[rr.Name] = keep
	}
	return recs, nil
}

func (f *fakeProvider) set(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.recs[name]...)
	sort.Strings(out)
	return out
}

func newFake(t *testing.T, apex []string) *fakeProvider {
	return &fakeProvider{t: t, zone: "example.org.", recs: map[string][]string{"@": append([]string(nil), apex...), "*": append([]string(nil), apex...)}, watch: []string{"@", "*"}}
}

// staticSource is a fixed cluster: n1..n3 at one site, readiness set per
// round by the test.
type staticSource struct {
	mu    sync.Mutex
	ready map[string]bool
}

func (s *staticSource) Cluster(context.Context) (Cluster, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := map[string]bool{}
	for k, v := range s.ready {
		r[k] = v
	}
	return Cluster{Nodes: map[string]Node{
		"n1": {Site: "main", Ingress: true, Public: []string{"198.51.100.1"}},
		"n2": {Site: "main", Ingress: true, Public: []string{"198.51.100.2"}},
		"n3": {Site: "main", Ingress: true, Public: []string{"198.51.100.3"}},
	}, Ready: r}, nil
}

func (s *staticSource) Probes(context.Context, Cluster, time.Time) ([]ProbeRound, []error) {
	return nil, nil
}

type memSink struct{ docs []string }

func (m *memSink) Write(_ context.Context, b []byte) error {
	m.docs = append(m.docs, string(b))
	return nil
}

var t0 = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

// testFence leads while *lead; its writes get 5 s.
type testFence struct{ lead *bool }

func (f testFence) Leading() bool { return *f.lead }

func (f testFence) WriteContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if !*f.lead {
		return nil, nil, ErrStandingBy
	}
	c, cancel := context.WithTimeout(ctx, WriteMargin)
	return c, cancel, nil
}

// docs: the vectors' documentation addresses count as public in tests.
var docs = AddrPolicy{AllowDocumentation: true}

// TestFrontDoorPartialWriteNeverEmpty: n1 holds the only address and
// dies, n2 is healthy: the front door appends n2 first; the delete of n1
// then fails, so the set holds old + new; the delete is retried after the
// 60 s rate limit and succeeds. The fake asserts after every call that
// neither name is ever empty.
func TestFrontDoorPartialWriteNeverEmpty(t *testing.T) {
	p := newFake(t, []string{"198.51.100.1"})
	leading := true
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 600 * time.Second, Fence: testFence{&leading}, Policy: docs}
	src := &staticSource{ready: map[string]bool{"n1": false, "n2": true, "n3": false}}
	r := &Runner{Engine: NewEngine(w.Names()), Writer: w, Source: src, Status: &memSink{}}
	var failedAt time.Time
	for i := range 40 {
		now := t0.Add(time.Duration(i) * Round)
		if got := p.set("@"); len(got) == 2 && failedAt.IsZero() && strings.Contains(strings.Join(p.calls, ","), "append") {
			// The append landed: make the next delete fail once.
			p.mu.Lock()
			p.failDelete = 2 // one per name
			p.mu.Unlock()
			failedAt = now
		}
		r.Step(context.Background(), now)
	}
	if failedAt.IsZero() {
		t.Fatal("the append never happened")
	}
	for _, n := range []string{"@", "*"} {
		if got := p.set(n); len(got) != 1 || got[0] != "198.51.100.2" {
			t.Errorf("%s: %v, want only n2's address after the retried delete", n, got)
		}
	}
	// The first delete failed, the retry came ≥ 60 s later.
	deletes := 0
	for _, c := range p.calls {
		if strings.HasPrefix(c, "delete @") {
			deletes++
		}
	}
	if deletes != 2 {
		t.Errorf("%d deletes of the apex, want 2 (one failed, one retried): %v", deletes, p.calls)
	}
}

// TestFrontDoorMinorityNoWrites: without the Lease the engine still runs
// (its view moves) but the provider gets no write.
func TestFrontDoorMinorityNoWrites(t *testing.T) {
	p := newFake(t, []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"})
	leading := false
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 60 * time.Second, Fence: testFence{&leading}, Policy: docs}
	src := &staticSource{ready: map[string]bool{"n1": true, "n2": true, "n3": false}}
	sink := &memSink{}
	r := &Runner{Engine: NewEngine(w.Names()), Writer: w, Source: src, Status: sink}
	for i := range 20 {
		if cs := r.Step(context.Background(), t0.Add(time.Duration(i)*Round)); len(cs) != 0 {
			t.Fatalf("round %d: %v applied without the Lease", i, cs)
		}
	}
	for _, c := range p.calls {
		if c != "get" {
			t.Fatalf("a provider write without the Lease: %v", p.calls)
		}
	}
	if pend := r.Engine.View().Pending["example.org"]; pend == nil || pend.Value != "198.51.100.3" {
		t.Errorf("the engine didn't run: pending %+v", pend)
	}
	if last := sink.docs[len(sink.docs)-1]; !strings.Contains(last, `"state":"standing by"`) {
		t.Errorf("status %s, want standing by", last)
	}
	// And Writer.Apply itself refuses.
	if err := w.Apply(context.Background(), Change{Name: "example.org", Op: "remove", Value: "198.51.100.3", Type: "A"}); !errors.Is(err, ErrStandingBy) {
		t.Errorf("Apply without the Lease: %v", err)
	}
}

// TestFrontDoorOnlyMainRecords: a change for any name outside <d>,
// *.<d> (address and CAA) and _acme-challenge.<d> (TXT) is refused
// before any provider call.
func TestFrontDoorOnlyMainRecords(t *testing.T) {
	p := newFake(t, []string{"198.51.100.1", "198.51.100.2"})
	leading := true
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 60 * time.Second, Fence: testFence{&leading}, Policy: docs}
	for _, c := range []Change{
		{Name: "added.example", Op: "add", Value: "198.51.100.9"},
		{Name: "app.example.org", Op: "add", Value: "198.51.100.9"},
		{Name: "*.app.example.org", Op: "add", Value: "198.51.100.9"},
		{Name: "_acme-challenge.example.org", Op: "add", Value: "198.51.100.9"},
		{Name: "example.org.evil", Op: "remove", Value: "198.51.100.1"},
		{Name: "xexample.org", Op: "add", Value: "198.51.100.9"},
		{Name: "example.org", Op: "add", Value: "not-an-ip"},
		{Name: "example.org", Op: "add", Value: "198.51.100.9", Type: "AAAA"},
		{Name: "example.org", Op: "set", Value: "198.51.100.9"},
	} {
		if err := w.Apply(context.Background(), c); err == nil {
			t.Errorf("%+v: applied", c)
		}
	}
	if len(p.calls) != 0 {
		t.Errorf("provider called: %v", p.calls)
	}
	for _, ok := range []struct{ name, typ string }{
		{"example.org", "A"}, {"*.example.org", "AAAA"}, {"example.org", "CAA"}, {"*.example.org", "CAA"}, {"_acme-challenge.example.org", "TXT"}, {"EXAMPLE.ORG.", "A"},
	} {
		if err := w.Allowed(ok.name, ok.typ); err != nil {
			t.Errorf("%s %s refused: %v", ok.typ, ok.name, err)
		}
	}
	for _, no := range []struct{ name, typ string }{
		{"example.org", "TXT"}, {"example.org", "MX"}, {"_acme-challenge.example.org", "A"}, {"mail.example.org", "A"}, {"_dmarc.example.org", "TXT"},
	} {
		if err := w.Allowed(no.name, no.typ); err == nil {
			t.Errorf("%s %s allowed", no.typ, no.name)
		}
	}
	// The last address is never deleted, whatever the change says.
	p2 := newFake(t, []string{"198.51.100.1"})
	w2 := &Writer{Domain: "example.org", Zone: "example.org.", P: p2, TTL: 60 * time.Second, Fence: testFence{&leading}, Policy: docs}
	if err := w2.Apply(context.Background(), Change{Name: "example.org", Op: "remove", Value: "198.51.100.1"}); err == nil {
		t.Error("the last address removed")
	}
	for _, c := range p2.calls {
		if strings.HasPrefix(c, "delete") {
			t.Errorf("a delete of the last address reached the provider: %v", p2.calls)
		}
	}
}

func TestAddrPolicy(t *testing.T) {
	prod := AddrPolicy{Excluded: prefixes("10.215.0.0/24", "10.42.0.0/16", "10.43.0.0/16")}
	for _, ok := range []string{"8.8.8.8", "1.1.1.1", "2a00:1450:4001::1", "45.33.32.156"} {
		if err := prod.Check(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.1", "ff02::1",
		"0.0.0.0", "::", "100.64.0.1", "100.127.255.254", "192.0.0.8", "198.18.0.1", "198.19.255.1", "2001:2::1",
		"192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:db8::1", "3fff::1", "fd00::1", "240.0.0.1", "255.255.255.255",
		"10.215.0.3", "10.42.1.1", "10.43.0.10", "::ffff:8.8.8.8", "fe80::1%eth0", "not-an-ip",
	} {
		if err := prod.Check(bad); err == nil {
			t.Errorf("%s accepted as public", bad)
		}
	}
	// The test build's documentation ranges, never the cluster's own.
	test := AddrPolicy{AllowDocumentation: true, Excluded: prefixes("10.215.0.0/24")}
	if test.Check("198.51.100.7") != nil || test.Check("10.215.0.3") == nil || test.Check("100.64.0.1") == nil {
		t.Error("the test policy")
	}
}

// TestFrontDoorAddRefusesNonPublic: Writer.Apply re-checks the address
// before AppendRecords.
func TestFrontDoorAddRefusesNonPublic(t *testing.T) {
	p := newFake(t, []string{"198.51.100.1"})
	leading := true
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: time.Minute, Fence: testFence{&leading},
		Policy: AddrPolicy{Excluded: prefixes("10.215.0.0/24")}}
	for _, a := range []string{"10.215.0.2", "192.168.1.5", "100.64.0.9", "203.0.113.5"} {
		if err := w.Apply(context.Background(), Change{Name: "example.org", Op: "add", Value: a}); err == nil {
			t.Errorf("%s added", a)
		}
	}
	for _, c := range p.calls {
		if strings.HasPrefix(c, "append") {
			t.Errorf("an append reached the provider: %v", p.calls)
		}
	}
}

// TestFrontDoorLastOfType: the last address of a type is never removed
// (duplicates counted once; an AAAA doesn't stand in for the last A).
func TestFrontDoorLastOfType(t *testing.T) {
	leading := true
	p := newFake(t, []string{"198.51.100.1", "198.51.100.1"})
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: time.Minute, Fence: testFence{&leading}, Policy: docs}
	if pub, _ := w.Published(context.Background()); len(pub["example.org"]) != 1 {
		t.Errorf("duplicates not counted once: %v", pub)
	}
	if err := w.Apply(context.Background(), Change{Name: "example.org", Op: "remove", Value: "198.51.100.1"}); err == nil {
		t.Error("the last A removed (its value held twice)")
	}
	p.recs["@"] = append(p.recs["@"], "2001:db8::1")
	if err := w.Apply(context.Background(), Change{Name: "example.org", Op: "remove", Value: "198.51.100.1"}); err == nil {
		t.Error("the last A removed beside an AAAA")
	}
	for _, c := range p.calls {
		if strings.HasPrefix(c, "delete") {
			t.Errorf("a delete reached the provider: %v", p.calls)
		}
	}
	// The engine keeps the last of each type too.
	e := NewEngine([]string{"example.org"})
	nodes := map[string]Node{"n1": {Site: "main", Ingress: true, Public: []string{"198.51.100.1"}}, "n2": {Site: "main", Ingress: true, Public: []string{"2001:db8::1"}}}
	for i := range 10 {
		if cs := e.Step(t0.Add(time.Duration(i)*Round), Inputs{Lease: true, Nodes: nodes, Ready: map[string]bool{"n1": false, "n2": true},
			Published: map[string][]string{"example.org": {"198.51.100.1", "2001:db8::1"}}}); len(cs) != 0 {
			t.Fatalf("round %d: %v", i, cs)
		}
	}
}

// TestFrontDoorSeedKeepsRateLimit: a new leader seeded with the last
// written change waits out the 60 s; a change that failed to write isn't
// a last change.
func TestFrontDoorSeedKeepsRateLimit(t *testing.T) {
	nodes := map[string]Node{
		"n1": {Site: "main", Ingress: true, Public: []string{"198.51.100.1"}},
		"n2": {Site: "main", Ingress: true, Public: []string{"198.51.100.2"}},
	}
	pub := map[string][]string{"example.org": {"198.51.100.1", "198.51.100.2", "198.51.100.9"}}
	e := NewEngine([]string{"example.org"})
	e.Seed(map[string]time.Time{"example.org": t0.Add(-30 * time.Second)})
	in := Inputs{Lease: true, Nodes: nodes, Ready: map[string]bool{"n1": true, "n2": true}, Published: pub}
	if cs := e.Step(t0, in); len(cs) != 0 {
		t.Fatalf("a change 30 s after the last one: %v", cs)
	}
	if cs := e.Step(t0.Add(30*time.Second), in); len(cs) != 1 || cs[0].Value != "198.51.100.9" {
		t.Fatalf("at 60 s: %v", cs)
	}
	// Not written: LastChange stays the seeded one.
	if l := e.View().LastChange["example.org"]; !l.Equal(t0.Add(-30 * time.Second)) {
		t.Errorf("last_change %s for a change not written", l)
	}
	e.Applied("example.org", t0.Add(30*time.Second))
	if l := e.View().LastChange["example.org"]; !l.Equal(t0.Add(30 * time.Second)) {
		t.Errorf("last_change %s after Applied", l)
	}
	last, err := ParseLastChanges(`{"v":1,"state":"leading","names":{"example.org":{"addresses":[],"ttl":60,"worst_case_s":90,"last_change":"2026-11-18T09:59:30Z","pending":null}},"probes":{},"sites":{}}`)
	if err != nil || !last["example.org"].Equal(t0.Add(-30*time.Second)) {
		t.Errorf("%v %v", last, err)
	}
}
