package frontdoor

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"
)

// vector is one case of frontdoor_vectors.json (the shape
// domains/frontdoor_vectors_test.go checks strictly).
type vector struct {
	Name           string   `json:"name"`
	CrossSite      bool     `json:"cross_site"`
	Provider       string   `json:"provider"`
	ProviderName   string   `json:"provider_name"`
	ProviderMinTTL int      `json:"provider_min_ttl"`
	Lease          bool     `json:"lease"`
	Names          []string `json:"names"`
	Nodes          map[string]struct {
		Site    string   `json:"site"`
		Ingress bool     `json:"ingress"`
		Public  []string `json:"public"`
	} `json:"nodes"`
	Initial map[string][]string `json:"initial"`
	Rounds  []struct {
		T      time.Time       `json:"t"`
		Ready  map[string]bool `json:"ready"`
		Probes []ProbeRound    `json:"probes"`
	} `json:"rounds"`
	Want struct {
		Addresses map[string][]string `json:"addresses"`
		Changes   []struct {
			T     time.Time `json:"t"`
			Name  string    `json:"name"`
			Op    string    `json:"op"`
			Value string    `json:"value"`
		} `json:"changes"`
		InternalOnly bool `json:"internal_only"`
	} `json:"want"`
	WantWorstCaseText     map[string]string `json:"want_worst_case_text"`
	WantSiteWorstCaseText map[string]string `json:"want_site_worst_case_text"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("../testdata/frontdoor_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var vs []vector
	if err := dec.Decode(&vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func (v vector) nodes() map[string]Node {
	out := map[string]Node{}
	for id, n := range v.Nodes {
		out[id] = Node{Site: n.Site, Ingress: n.Ingress, Public: n.Public}
	}
	return out
}

// replay runs the engine over v's rounds, applying every change to the
// published sets as a provider would; it returns the changes and the
// last round's view.
func replay(v vector) ([]Change, map[string][]string, View) { return replayRules(v, rules{}) }

func replayRules(v vector, r rules) ([]Change, map[string][]string, View) {
	e := newEngine(v.Names, r)
	pub := map[string][]string{}
	for n, as := range v.Initial {
		pub[n] = append([]string(nil), as...)
	}
	var all []Change
	for _, r := range v.Rounds {
		cs := e.Step(r.T, Inputs{Lease: v.Lease, Nodes: v.nodes(), Ready: r.Ready, Probes: r.Probes, Published: clone(pub)})
		for _, c := range cs {
			pub[c.Name] = applyChange(pub[c.Name], c)
			e.Applied(c.Name, c.T)
		}
		all = append(all, cs...)
	}
	return all, pub, e.View()
}

func clone(m map[string][]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func applyChange(set []string, c Change) []string {
	switch c.Op {
	case "add":
		return append(set, c.Value)
	default:
		var out []string
		for _, a := range set {
			if a != c.Value {
				out = append(out, a)
			}
		}
		return out
	}
}

// TestFrontdoorVectors: Engine.Step over every case of
// frontdoor_vectors.json (single-site and cross-site) gives exactly
// want.changes and ends at want.addresses; internal_only and the
// worst-case texts follow.
func TestFrontdoorVectors(t *testing.T) {
	vs := loadVectors(t)
	if len(vs) < 25 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			got, pub, view := replay(v)
			if len(got) != len(v.Want.Changes) {
				t.Fatalf("changes %v, want %+v", got, v.Want.Changes)
			}
			for i, w := range v.Want.Changes {
				g := got[i]
				if !g.T.Equal(w.T) || g.Name != w.Name || g.Op != w.Op || g.Value != w.Value || g.Type != AddrType(w.Value) {
					t.Errorf("change %d: %+v, want %+v", i, g, w)
				}
			}
			for name, want := range v.Want.Addresses {
				g := append([]string(nil), pub[name]...)
				w := append([]string(nil), want...)
				sort.Strings(g)
				sort.Strings(w)
				if len(g) != len(w) {
					t.Errorf("%s: %v, want %v", name, g, w)
					continue
				}
				for i := range g {
					if g[i] != w[i] {
						t.Errorf("%s: %v, want %v", name, g, w)
					}
				}
			}
			internal := true
			for _, j := range view.Judgements {
				internal = internal && j.InternalOnly
			}
			if v.Want.InternalOnly && !internal {
				t.Errorf("internal_only: a node was judged by probes in a single-site cluster")
			}
			ttl := TTL(time.Duration(v.ProviderMinTTL) * time.Second)
			ws := WorstCaseSeconds(ttl)
			for _, name := range v.Names {
				if g := WorstCaseText(ws, v.ProviderName); g != v.WantWorstCaseText[name] {
					t.Errorf("worst case %q, want %q", g, v.WantWorstCaseText[name])
				}
			}
			for site, want := range v.WantSiteWorstCaseText {
				if g := SiteWorstCaseText(site, ws, v.ProviderName); g != want {
					t.Errorf("site worst case %q, want %q", g, want)
				}
			}
		})
	}
}

// TestFrontdoorVectorsPinTheRules: each rule, switched off, fails at
// least one vector (the cases discriminate; N1: the blind case must
// fail an engine without the blind rule, even one that removes the
// lowest id first).
func TestFrontdoorVectorsPinTheRules(t *testing.T) {
	vs := loadVectors(t)
	for name, r := range map[string]rules{
		"no blind rule":              {noBlind: true},
		"no two-site span":           {noSpan: true},
		"tie re-adds":                {tieReadds: true},
		"probe rounds counted again": {noFresh: true},
		"gaps not restarting":        {noGapReset: true},
		"orphans kept":               {keepOrphans: true},
		"one owner per address":      {oneOwner: true},
		"fail static on verdicts":    {verdictFailStatic: true},
	} {
		t.Run(name, func(t *testing.T) {
			failed := 0
			for _, v := range vs {
				got, _, _ := replayRules(v, r)
				if len(got) != len(v.Want.Changes) {
					failed++
					continue
				}
				for i, w := range v.Want.Changes {
					if got[i].Value != w.Value || !got[i].T.Equal(w.T) {
						failed++
						break
					}
				}
			}
			if failed == 0 {
				t.Errorf("no vector fails with %s", name)
			}
		})
	}
}

// TestFrontDoorNeverRemovesLast: every ingress node failing changes
// nothing (fail static), and a lone unhealthy address stays while no
// other node is healthy long enough to be added.
func TestFrontDoorNeverRemovesLast(t *testing.T) {
	nodes := map[string]Node{
		"n1": {Site: "main", Ingress: true, Public: []string{"198.51.100.1"}},
		"n2": {Site: "main", Ingress: true, Public: []string{"198.51.100.2"}},
	}
	e := NewEngine([]string{"example.org"})
	t0 := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	pub := map[string][]string{"example.org": {"198.51.100.1", "198.51.100.2"}}
	for i := range 30 {
		cs := e.Step(t0.Add(time.Duration(i)*10*time.Second), Inputs{Lease: true, Nodes: nodes,
			Ready: map[string]bool{"n1": false, "n2": false}, Published: pub})
		if len(cs) != 0 {
			t.Fatalf("round %d: %v with every node failing", i, cs)
		}
		if !e.View().FailStatic {
			t.Fatalf("round %d: not fail static", i)
		}
	}
	// One address published, its node dead, the other just healthy:
	// the address stays (no change can empty the set).
	e = NewEngine([]string{"example.org"})
	pub = map[string][]string{"example.org": {"198.51.100.1"}}
	for i := range 11 {
		cs := e.Step(t0.Add(time.Duration(i)*10*time.Second), Inputs{Lease: true, Nodes: nodes,
			Ready: map[string]bool{"n1": false, "n2": true}, Published: pub})
		if len(cs) != 0 {
			t.Fatalf("round %d: %v", i, cs)
		}
	}
	if p := e.View().Pending["example.org"]; p == nil || p.Op != "remove" || p.Value != "198.51.100.1" {
		t.Errorf("pending %+v, want the removal of 198.51.100.1 waiting", p)
	}
}

func TestJudgeTies(t *testing.T) {
	n := Node{Site: "main", Ingress: true, Public: []string{"198.51.100.1"}}
	round := func(prober, site string, ok bool) ProbeRound {
		return ProbeRound{Prober: prober, Site: site, ReachedAny: true, EgressOK: true, Results: map[string]ProbeResult{"n1": {OK: ok}}}
	}
	for _, c := range []struct {
		name   string
		probes []ProbeRound
		want   Verdict
	}{
		{"none", nil, Healthy},
		{"same site never counts", []ProbeRound{round("n2", "main", false)}, Healthy},
		{"2 of 2 fail", []ProbeRound{round("e1", "edge", false), round("e2", "edge", false)}, Unhealthy},
		{"tie", []ProbeRound{round("e1", "edge", false), round("e2", "edge", true)}, Undecided},
		{"2 of 3 pass", []ProbeRound{round("e1", "edge", false), round("e2", "edge", true), round("e3", "edge", true)}, Healthy},
		{"one site fails, the other passes: span", []ProbeRound{round("e1", "edge", false), round("e2", "edge", false), round("t1", "tb", true)}, Undecided},
	} {
		if g := Judge("n1", n, true, c.probes).Verdict; g != c.want {
			t.Errorf("%s: %v, want %v", c.name, g, c.want)
		}
	}
	if g := Judge("n1", n, false, nil).Verdict; g != Unhealthy {
		t.Errorf("not ready: %v", g)
	}
}

// TestNoObservationKeepsCounts (rereview N1): a round in which every
// prober that would judge a Ready target sent only a round already
// counted (or a stale one) is no observation: it neither resets the
// unhealthy streak nor counts as a healthy round (no addition is due on
// it). Switched off (a dropped round read as "no prober: healthy"), both
// halves fail.
func TestNoObservationKeepsCounts(t *testing.T) {
	nodes := map[string]Node{
		"n1": {Site: "main", Ingress: true, Public: []string{"198.51.100.1"}},
		"n2": {Site: "main", Ingress: true, Public: []string{"198.51.100.2"}},
		"e1": {Site: "edge", Ingress: true, Public: []string{"203.0.113.1"}},
		"e2": {Site: "edge", Ingress: true, Public: []string{"203.0.113.2"}},
	}
	ready := map[string]bool{"n1": true, "n2": true, "e1": true, "e2": true}
	round := func(prober, site string, at time.Time, n2ok bool) ProbeRound {
		res := map[string]ProbeResult{}
		for id := range nodes {
			res[id] = ProbeResult{OK: true, Class: "ok"}
		}
		if !n2ok {
			res["n2"] = ProbeResult{OK: false, Class: "timeout"}
		}
		return ProbeRound{T: at, Prober: prober, Site: site, ReachedAny: true, EgressOK: true, Results: res}
	}
	// probersAt: every node's round; the edge probers' taken at edgeT.
	probersAt := func(now, edgeT time.Time, n2ok bool) []ProbeRound {
		return []ProbeRound{round("n1", "main", now, true), round("n2", "main", now, true),
			round("e1", "edge", edgeT, n2ok), round("e2", "edge", edgeT, n2ok)}
	}
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	for _, off := range []bool{false, true} {
		// Removal: fail, fail, the 10 s rounds again (dropped), fail → the
		// third counted failure removes n2 at 30 s.
		e := newEngine([]string{"example.org"}, rules{noObservationHealthy: off})
		pub := map[string][]string{"example.org": {"198.51.100.1", "198.51.100.2", "203.0.113.1", "203.0.113.2"}}
		var got []Change
		for _, r := range []struct {
			now, edge int
		}{{0, 0}, {10, 10}, {20, 10}, {30, 30}} {
			got = append(got, e.Step(at(r.now), Inputs{Lease: true, Nodes: nodes, Ready: ready, Probes: probersAt(at(r.now), at(r.edge), false), Published: pub})...)
			if r.now == 20 && !off && !e.View().Judgements["n2"].NoObservation {
				t.Error("the dropped rounds were an observation")
			}
		}
		removed := len(got) == 1 && got[0].Value == "198.51.100.2" && got[0].T.Equal(at(30))
		if removed == off {
			t.Errorf("rule off=%v: changes %v (want n2 removed at 30 s with the rule)", off, got)
		}
		// Addition: n2 passing from 0 s; at 120 s the edge probers resend
		// their 110 s rounds (dropped): not due then; added at 130 s.
		e = newEngine([]string{"example.org"}, rules{noObservationHealthy: off})
		pub = map[string][]string{"example.org": {"198.51.100.1", "203.0.113.1", "203.0.113.2"}}
		got = nil
		for s := 0; s <= 130; s += 10 {
			edge := s
			if s == 120 {
				edge = 110
			}
			got = append(got, e.Step(at(s), Inputs{Lease: true, Nodes: nodes, Ready: ready, Probes: probersAt(at(s), at(edge), true), Published: pub})...)
		}
		added := len(got) == 1 && got[0].Op == "add" && got[0].T.Equal(at(130))
		if added == off {
			t.Errorf("rule off=%v: changes %v (want n2 added at 130 s with the rule)", off, got)
		}
	}
}
