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

func lead(b *bool) func() bool { return func() bool { return *b } }

// TestFrontDoorPartialWriteNeverEmpty: n1 holds the only address and
// dies, n2 is healthy: the front door appends n2 first; the delete of n1
// then fails, so the set holds old + new; the delete is retried after the
// 60 s rate limit and succeeds. The fake asserts after every call that
// neither name is ever empty.
func TestFrontDoorPartialWriteNeverEmpty(t *testing.T) {
	p := newFake(t, []string{"198.51.100.1"})
	leading := true
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 600 * time.Second, Leading: lead(&leading)}
	src := &staticSource{ready: map[string]bool{"n1": false, "n2": true, "n3": false}}
	r := &Runner{Engine: NewEngine(w.Names()), Writer: w, Source: src, Leading: lead(&leading), Status: &memSink{}}
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
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 60 * time.Second, Leading: lead(&leading)}
	src := &staticSource{ready: map[string]bool{"n1": true, "n2": true, "n3": false}}
	sink := &memSink{}
	r := &Runner{Engine: NewEngine(w.Names()), Writer: w, Source: src, Leading: lead(&leading), Status: sink}
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
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 60 * time.Second, Leading: lead(&leading)}
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
	w2 := &Writer{Domain: "example.org", Zone: "example.org.", P: p2, TTL: 60 * time.Second, Leading: lead(&leading)}
	if err := w2.Apply(context.Background(), Change{Name: "example.org", Op: "remove", Value: "198.51.100.1"}); err == nil {
		t.Error("the last address removed")
	}
	for _, c := range p2.calls {
		if strings.HasPrefix(c, "delete") {
			t.Errorf("a delete of the last address reached the provider: %v", p2.calls)
		}
	}
}
