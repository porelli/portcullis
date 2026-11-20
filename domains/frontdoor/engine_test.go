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
func replay(v vector) ([]Change, map[string][]string, View) {
	e := NewEngine(v.Names)
	pub := map[string][]string{}
	for n, as := range v.Initial {
		pub[n] = append([]string(nil), as...)
	}
	var all []Change
	for _, r := range v.Rounds {
		cs := e.Step(r.T, Inputs{Lease: v.Lease, Nodes: v.nodes(), Ready: r.Ready, Probes: r.Probes, Published: clone(pub)})
		for _, c := range cs {
			pub[c.Name] = applyChange(pub[c.Name], c)
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
	for name, mutate := range map[string]func(){
		"no blind rule":    func() { blindRule = false },
		"no two-site span": func() { spanRule = false },
		"tie re-adds":      func() { tieReadds = true },
	} {
		t.Run(name, func(t *testing.T) {
			mutate()
			defer func() { blindRule, spanRule, tieReadds = true, true, false }()
			failed := 0
			for _, v := range vs {
				got, _, _ := replay(v)
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
