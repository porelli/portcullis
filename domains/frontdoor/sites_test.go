package frontdoor

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// The front door across sites (plan Task 28): the cross-site rules run
// through Engine.Step round by round, as the Runner drives them.

// siteSim is a test cluster: every node an ingress node with one address.
type siteSim struct {
	t      *testing.T
	nodes  map[string]Node
	addr   map[string]string // node → its address
	names  []string
	e      *Engine
	pub    map[string][]string
	now    time.Time
	all    []Change
	rules  rules
	byName map[string][]time.Time
}

func newSiteSim(t *testing.T, r rules, sites map[string][]string, published []string) *siteSim {
	s := &siteSim{t: t, nodes: map[string]Node{}, addr: map[string]string{}, names: []string{"example.org", "*.example.org"},
		pub: map[string][]string{}, now: t0, rules: r, byName: map[string][]time.Time{}}
	i := 1
	for _, site := range slices.Sorted(maps.Keys(sites)) {
		for _, id := range sites[site] {
			a := "198.51.100." + strconv.Itoa(i)
			i++
			s.nodes[id] = Node{Site: site, Ingress: true, Public: []string{a}}
			s.addr[id] = a
		}
	}
	for _, n := range s.names {
		for _, id := range published {
			s.pub[n] = append(s.pub[n], s.addr[id])
		}
	}
	s.e = newEngine(s.names, r)
	return s
}

// probe is a prober's round: it reaches exactly the targets ok says (any
// target not listed is reached); egress as given.
func (s *siteSim) probe(prober string, egress bool, fails ...string) ProbeRound {
	r := ProbeRound{T: s.now, Prober: prober, Site: s.nodes[prober].Site, EgressOK: egress, Results: map[string]ProbeResult{}}
	for id := range s.nodes {
		ok := !slices.Contains(fails, id)
		r.Results[id] = ProbeResult{OK: ok, Class: map[bool]string{true: "ok", false: "timeout"}[ok]}
		r.ReachedAny = r.ReachedAny || ok
	}
	return r
}

// step runs one round 10 s after the last and applies its changes.
func (s *siteSim) step(ready map[string]bool, probes ...ProbeRound) []Change {
	s.t.Helper()
	rd := map[string]bool{}
	for id := range s.nodes {
		rd[id] = true
	}
	for id, v := range ready {
		rd[id] = v
	}
	cs := s.e.Step(s.now, Inputs{Lease: true, Nodes: s.nodes, Ready: rd, Probes: probes, Published: clone(s.pub)})
	for _, c := range cs {
		s.pub[c.Name] = applyChange(s.pub[c.Name], c)
		s.e.Applied(c.Name, c.T)
		s.byName[c.Name] = append(s.byName[c.Name], c.T)
		if len(s.pub[c.Name]) == 0 {
			s.t.Fatalf("%s: %s left %s without an address", c.T.Format(time.TimeOnly), c.Op, c.Name)
		}
	}
	s.all = append(s.all, cs...)
	s.now = s.now.Add(Round)
	return cs
}

func (s *siteSim) has(name, id string) bool { return slices.Contains(s.pub[name], s.addr[id]) }

// TestBlindProberDiscarded: the only prober at edge fails every target
// at every site, its own included, and its egress reference (its uplink
// is down): its rounds are ignored, so main's addresses stay; the round
// shows it blind and the metrics count it at edge. With the blind rule
// off, the same rounds remove a main address (the test pins the rule).
func TestBlindProberDiscarded(t *testing.T) {
	run := func(r rules) *siteSim {
		s := newSiteSim(t, r, map[string][]string{"main": {"n1", "n2"}, "edge": {"e1"}}, []string{"n1", "n2", "e1"})
		for range 12 {
			s.step(nil, s.probe("e1", false, "n1", "n2", "e1"), s.probe("n1", true), s.probe("n2", true))
		}
		return s
	}
	s := run(rules{})
	for _, id := range []string{"n1", "n2"} {
		if !s.has("example.org", id) || !s.has("*.example.org", id) {
			t.Errorf("main's %s removed on a blind prober's rounds: %v", id, s.all)
		}
	}
	v := s.e.View()
	if !v.BlindProbers["e1"] || v.BlindProbers["n1"] {
		t.Errorf("blind probers %v, want e1 only", v.BlindProbers)
	}
	c := Cluster{Nodes: s.nodes}
	sites := BuildSites(c, v)
	if sites["edge"].BlindProbers != 1 || sites["main"].BlindProbers != 0 || !sites["main"].Healthy {
		t.Errorf("sites %+v", sites)
	}
	m := NewMetrics()
	m.Update(s.now, s.pub, c, v)
	if g := gauge(t, m, "portcullis_frontdoor_blind_probers", "edge"); g != 1 {
		t.Errorf("portcullis_frontdoor_blind_probers{site=edge} = %v, want 1", g)
	}
	if g := gauge(t, m, "portcullis_frontdoor_blind_probers", "main"); g != 0 {
		t.Errorf("portcullis_frontdoor_blind_probers{site=main} = %v, want 0", g)
	}
	off := run(rules{noBlind: true})
	if off.has("example.org", "n1") && off.has("example.org", "n2") {
		t.Errorf("without the blind rule nothing was removed: the test doesn't pin it")
	}
}

// TestOneSiteUplinkDownNoRemovalElsewhere: edge's uplink is down — its
// probers are blind, main's probers fail edge's addresses (the nodes stay
// Ready over the mesh): only edge's addresses go, after 3 rounds; main's
// never; the site view and metrics say edge isn't healthy.
func TestOneSiteUplinkDownNoRemovalElsewhere(t *testing.T) {
	s := newSiteSim(t, rules{}, map[string][]string{"main": {"n1", "n2"}, "edge": {"e1", "e2"}}, []string{"n1", "n2", "e1", "e2"})
	everyone := []string{"n1", "n2", "e1", "e2"}
	for range 18 {
		s.step(nil, s.probe("e1", false, everyone...), s.probe("e2", false, everyone...),
			s.probe("n1", true, "e1", "e2"), s.probe("n2", true, "e1", "e2"))
	}
	for _, n := range s.names {
		if !s.has(n, "n1") || !s.has(n, "n2") {
			t.Errorf("%s: a main address was removed: %v", n, s.pub[n])
		}
		if s.has(n, "e1") || s.has(n, "e2") {
			t.Errorf("%s: edge's addresses still published: %v", n, s.pub[n])
		}
	}
	// The first removal is due at the third failing round (t0+20 s).
	if len(s.all) == 0 || !s.all[0].T.Equal(t0.Add(20*time.Second)) || s.all[0].Op != "remove" {
		t.Errorf("first change %+v, want a removal at +20 s", s.all)
	}
	for _, c := range s.all {
		if c.Op != "remove" || (c.Value != s.addr["e1"] && c.Value != s.addr["e2"]) {
			t.Errorf("unexpected change %+v", c)
		}
	}
	c := Cluster{Nodes: s.nodes}
	sites := BuildSites(c, s.e.View())
	if sites["edge"].Healthy || !sites["main"].Healthy || sites["edge"].BlindProbers != 2 {
		t.Errorf("sites %+v", sites)
	}
	m := NewMetrics()
	m.Update(s.now, s.pub, c, s.e.View())
	if gauge(t, m, "portcullis_frontdoor_site_healthy", "edge") != 0 || gauge(t, m, "portcullis_frontdoor_site_healthy", "main") != 1 {
		t.Errorf("portcullis_frontdoor_site_healthy: edge %v main %v", gauge(t, m, "portcullis_frontdoor_site_healthy", "edge"), gauge(t, m, "portcullis_frontdoor_site_healthy", "main"))
	}
}

// TestTwoSiteSpanRequired: three sites hold probers; target n1 (main) is
// failed by both probers at edge and passed by the one at far: a failing
// majority from one site only never removes it. With the span rule off
// it would (the test pins it).
func TestTwoSiteSpanRequired(t *testing.T) {
	run := func(r rules) *siteSim {
		s := newSiteSim(t, r, map[string][]string{"main": {"n1", "n2"}, "edge": {"e1", "e2"}, "far": {"f1"}}, []string{"n1", "n2", "e1", "e2", "f1"})
		for range 12 {
			s.step(nil, s.probe("e1", true, "n1"), s.probe("e2", true, "n1"), s.probe("f1", true), s.probe("n1", true), s.probe("n2", true))
		}
		return s
	}
	s := run(rules{})
	if len(s.all) != 0 || !s.has("example.org", "n1") {
		t.Errorf("one site's failing majority changed the set: %v", s.all)
	}
	if j := s.e.View().Judgements["n1"]; j.Verdict != Undecided || j.Eligible != 3 || j.Failing != 2 {
		t.Errorf("n1 judged %+v, want undecided on 2 of 3", j)
	}
	if off := run(rules{noSpan: true}); off.has("example.org", "n1") {
		t.Errorf("without the span rule n1 stayed: the test doesn't pin it")
	}
}

// TestOnlyOneSiteCanProbe: two sites, no hairpin at main (a same-site
// result never counts): edge's non-blind prober alone decides main's
// addresses — it fails n2, main's own probers pass it, n2 goes.
func TestOnlyOneSiteCanProbe(t *testing.T) {
	s := newSiteSim(t, rules{}, map[string][]string{"main": {"n1", "n2"}, "edge": {"e1"}}, []string{"n1", "n2", "e1"})
	for range 4 {
		s.step(nil, s.probe("e1", true, "n2"), s.probe("n1", true), s.probe("n2", true))
	}
	if s.has("example.org", "n2") || !s.has("example.org", "n1") {
		t.Errorf("edge's prober didn't decide: %v", s.pub)
	}
	if j := s.e.View().Judgements["n1"]; j.Eligible != 1 || j.InternalOnly {
		t.Errorf("n1 judged %+v: only e1's result counts", j)
	}
	// And edge's addresses are judged by main's probers only.
	if j := s.e.View().Judgements["e1"]; j.Eligible != 2 {
		t.Errorf("e1 judged %+v: main's two probers count", j)
	}
}

// TestWholeSiteDownOneNamePer60s (R11): site edge is lost — its nodes and
// Traefik not Ready, no rounds from it, main's probers fail it: its two
// addresses go one per name per 60 s; when edge held every address, the
// last one stays until main's are back.
func TestWholeSiteDownOneNamePer60s(t *testing.T) {
	s := newSiteSim(t, rules{}, map[string][]string{"main": {"n1", "n2"}, "edge": {"e1", "e2"}}, []string{"n1", "n2", "e1", "e2"})
	down := map[string]bool{"e1": false, "e2": false}
	for range 15 {
		s.step(down, s.probe("n1", true, "e1", "e2"), s.probe("n2", true, "e1", "e2"))
	}
	for _, n := range s.names {
		if len(s.pub[n]) != 2 || !s.has(n, "n1") || !s.has(n, "n2") {
			t.Errorf("%s: %v, want main's two", n, s.pub[n])
		}
		ts := s.byName[n]
		if len(ts) != 2 || ts[1].Sub(ts[0]) < ChangeEvery {
			t.Errorf("%s: changes at %v, want two at least 60 s apart", n, ts)
		}
	}
	if !s.byName["example.org"][0].Equal(t0.Add(20 * time.Second)) {
		t.Errorf("first removal at %v, want +20 s", s.byName["example.org"][0])
	}

	// Edge held every address: the last stays; main's come back after
	// 2 min of passing, and only then do edge's go.
	s = newSiteSim(t, rules{}, map[string][]string{"main": {"n1"}, "edge": {"e1", "e2"}}, []string{"e1", "e2"})
	for range 40 {
		s.step(down, s.probe("n1", true, "e1", "e2"))
	}
	for _, n := range s.names {
		if len(s.pub[n]) != 1 || !s.has(n, "n1") {
			t.Errorf("%s: %v, want n1 alone", n, s.pub[n])
		}
	}
	var first []Change
	for _, c := range s.all {
		if c.Name == "example.org" {
			first = append(first, c)
		}
	}
	// remove e1 (+20 s), add n1 (+120 s of passing), remove e2 (+60 s).
	if len(first) != 3 || first[0].Op != "remove" || first[1].Op != "add" || first[2].Op != "remove" || first[2].T.Sub(first[1].T) < ChangeEvery {
		t.Errorf("changes %+v", first)
	}
}

// TestFrontdoorCrossSiteVectors: the cross-site cases of
// frontdoor_vectors.json (the shared file, byte-copied to the Hub) run
// and pass; there are cases for each R10/R11 rule.
func TestFrontdoorCrossSiteVectors(t *testing.T) {
	n := 0
	for _, v := range loadVectors(t) {
		if !v.CrossSite {
			continue
		}
		n++
		got, _, _ := replay(v)
		if len(got) != len(v.Want.Changes) {
			t.Errorf("%s: changes %v, want %+v", v.Name, got, v.Want.Changes)
			continue
		}
		for i, w := range v.Want.Changes {
			if g := got[i]; !g.T.Equal(w.T) || g.Name != w.Name || g.Op != w.Op || g.Value != w.Value {
				t.Errorf("%s: change %d %+v, want %+v", v.Name, i, g, w)
			}
		}
	}
	if n < 4 {
		t.Fatalf("%d cross-site vectors", n)
	}
}

// writeCounter is a provider that records every write.
type writeCounter struct {
	*fakeProvider
	writes atomic.Int32
	last   atomic.Int64
}

func (w *writeCounter) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	w.writes.Add(1)
	w.last.Store(time.Now().UnixNano())
	return w.fakeProvider.AppendRecords(ctx, zone, recs)
}

func (w *writeCounter) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	w.writes.Add(1)
	w.last.Store(time.Now().UnixNano())
	return w.fakeProvider.DeleteRecords(ctx, zone, recs)
}

// TestCutOffSiteFrontdoorStops: the front door runs at a site that is
// cut off from the API server — its Lease renewals fail. After the
// RenewDeadline it writes nothing (the removal it decides is never sent
// to the provider) and its status says "standing by".
func TestCutOffSiteFrontdoorStops(t *testing.T) {
	cs := leaseClient(true)
	var cut atomic.Bool
	cs.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if cut.Load() {
			return true, nil, errors.New("the API server is unreachable")
		}
		return false, nil, nil
	})
	f := fastFence(cs, "fd-edge")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	if !eventually(3*time.Second, f.Leading) {
		t.Fatal("never led")
	}
	p := &writeCounter{fakeProvider: newFake(t, []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"})}
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: 60 * time.Second, Fence: f, Policy: docs}
	src := &staticSource{ready: map[string]bool{"n1": true, "n2": true, "n3": false}}
	sink := &memSink{}
	r := &Runner{Engine: NewEngine(w.Names()), Writer: w, Source: src, Status: sink}
	now := t0
	for range 2 { // two unhealthy rounds while leading: nothing due yet
		r.Step(ctx, now)
		now = now.Add(Round)
	}
	cut.Store(true)
	cutAt := time.Now()
	if !eventually(3*time.Second, func() bool { return !f.Leading() }) {
		t.Fatal("still leading with every renewal failing")
	}
	if d := time.Since(cutAt); d > 1500*time.Millisecond {
		t.Errorf("stood by %s after the cut (RenewDeadline 1 s)", d)
	}
	for range 10 { // the removal of n3 is due from the third round on
		if done := r.Step(ctx, now); len(done) != 0 {
			t.Fatalf("applied %v after the cut", done)
		}
		now = now.Add(Round)
	}
	if n := p.writes.Load(); n != 0 {
		t.Errorf("%d provider writes after the cut (last at %v)", n, time.Unix(0, p.last.Load()))
	}
	if pend := r.Engine.View().Pending["example.org"]; pend == nil || pend.Op != "remove" || pend.Value != "198.51.100.3" {
		t.Errorf("the engine didn't decide the removal: %+v", pend)
	}
	if last := sink.docs[len(sink.docs)-1]; !strings.Contains(last, `"state":"standing by"`) {
		t.Errorf("status %s, want standing by", last)
	}
	if err := w.Apply(ctx, Change{Name: "example.org", Op: "remove", Value: "198.51.100.3", Type: "A"}); !errors.Is(err, ErrStandingBy) {
		t.Errorf("Apply after the cut: %v", err)
	}
}

// gauge is the value of metric{site=site} in m's registry (-1: none).
func gauge(t *testing.T, m *Metrics, metric, site string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metric {
			continue
		}
		for _, mt := range mf.GetMetric() {
			for _, l := range mt.GetLabel() {
				if l.GetName() == "site" && l.GetValue() == site {
					return mt.GetGauge().GetValue()
				}
			}
		}
	}
	return -1
}
