package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// frontdoor_vectors.json (contract §20.8; byte-copied to the Hub's
// internal/hub/testdata/). A round is the front door's view at time t: the
// in-cluster readiness (node and Traefik Ready) and the probe rounds the
// nodeagents answered (GET /v1/probes, §20.4, the round shape verbatim);
// a node that is down has no probe round. A prober probes every ingress
// node, its own site and its own address included (§20.4), but only
// probers at another site count (spike S6); a single site is always
// internal-only. Cases tagged cross_site hold the multi-site rules (R10
// blind probers and the two-site span, R11 whole sites).
type fdProbeResult struct {
	OK    bool   `json:"ok"`
	Class string `json:"class"`
}

type fdProbeRound struct {
	T          time.Time                `json:"t"`
	Prober     string                   `json:"prober"`
	Site       string                   `json:"site"`
	ReachedAny bool                     `json:"reached_any"`
	EgressOK   bool                     `json:"egress_ok"`
	Results    map[string]fdProbeResult `json:"results"`
}

type fdVector struct {
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
		Probes []fdProbeRound  `json:"probes"`
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

var fdClasses = map[string]bool{"ok": true, "timeout": true, "refused": true, "tls": true, "http_status": true}

// TestFrontdoorVectorsShape: the file decodes strictly; rounds are 10 s
// apart; every prober's round has the §20.4 shape (ok iff class ok,
// reached_any iff a result is ok, never a result for itself); the
// worst-case texts follow §20.8 (TTL = max(60, the provider's minimum),
// worst_case_s = 30 + TTL, minutes floored, at least 1); the required
// cases are present.
func TestFrontdoorVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/frontdoor_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []fdVector
	if err := strictVectors(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 24 {
		t.Fatalf("%d vectors", len(vs))
	}
	cross, porkbun, internal, noLease := 0, false, false, false
	for _, v := range vs {
		if v.CrossSite {
			cross++
		}
		ttl := max(60, v.ProviderMinTTL)
		m := max(1, (30+ttl)/60)
		porkbun = porkbun || (v.ProviderName == "Porkbun" && m == 10)
		internal = internal || v.Want.InternalOnly
		noLease = noLease || !v.Lease
		for _, name := range v.Names {
			if want := fmt.Sprintf("worst case ~%d min for clients that hit the dead address first, on %s", m, v.ProviderName); v.WantWorstCaseText[name] != want {
				t.Errorf("%s: %s worst case %q, want %q", v.Name, name, v.WantWorstCaseText[name], want)
			}
			if _, ok := v.Initial[name]; !ok {
				t.Errorf("%s: no initial addresses for %s", v.Name, name)
			}
			if _, ok := v.Want.Addresses[name]; !ok {
				t.Errorf("%s: no wanted addresses for %s", v.Name, name)
			}
		}
		for _, n := range v.Nodes {
			if want := fmt.Sprintf("if site %s fails: worst case ~%d min on %s", n.Site, m, v.ProviderName); v.WantSiteWorstCaseText[n.Site] != want {
				t.Errorf("%s: site %s worst case %q, want %q", v.Name, n.Site, v.WantSiteWorstCaseText[n.Site], want)
			}
		}
		for i, r := range v.Rounds {
			if i > 0 && r.T.Sub(v.Rounds[i-1].T) != 10*time.Second {
				t.Errorf("%s: round %d isn't 10 s after the last", v.Name, i)
			}
			for _, p := range r.Probes {
				n, ok := v.Nodes[p.Prober]
				if !ok || n.Site != p.Site || !p.T.Equal(r.T) {
					t.Errorf("%s: round %d: prober %s", v.Name, i, p.Prober)
				}
				if _, own := p.Results[p.Prober]; n.Ingress && !own {
					t.Errorf("%s: round %d: ingress prober %s has no result for its own address", v.Name, i, p.Prober)
				}
				any := false
				for target, res := range p.Results {
					if !v.Nodes[target].Ingress || !fdClasses[res.Class] || res.OK != (res.Class == "ok") {
						t.Errorf("%s: round %d: %s → %s %+v", v.Name, i, p.Prober, target, res)
					}
					any = any || res.OK
				}
				if any != p.ReachedAny {
					t.Errorf("%s: round %d: %s reached_any %v", v.Name, i, p.Prober, p.ReachedAny)
				}
			}
		}
		sites := map[string]bool{}
		for _, n := range v.Nodes {
			sites[n.Site] = true
		}
		if v.Want.InternalOnly != (len(sites) == 1) {
			t.Errorf("%s: internal_only %v with %d sites (S6: exactly when single-site)", v.Name, v.Want.InternalOnly, len(sites))
		}
		if v.CrossSite != (len(sites) > 1) {
			t.Errorf("%s: cross_site %v with %d sites", v.Name, v.CrossSite, len(sites))
		}
		if !v.Lease && len(v.Want.Changes) > 0 {
			t.Errorf("%s: changes without the Lease", v.Name)
		}
		// Replay the changes: one per name per 60 s, never an empty set,
		// ending at want.addresses.
		set, last := map[string]map[string]bool{}, map[string]time.Time{}
		for name, as := range v.Initial {
			set[name] = map[string]bool{}
			for _, a := range as {
				set[name][a] = true
			}
		}
		for _, c := range v.Want.Changes {
			if l, ok := last[c.Name]; ok && c.T.Sub(l) < 60*time.Second {
				t.Errorf("%s: two changes of %s within 60 s", v.Name, c.Name)
			}
			last[c.Name] = c.T
			switch c.Op {
			case "add":
				set[c.Name][c.Value] = true
			case "remove":
				delete(set[c.Name], c.Value)
			default:
				t.Errorf("%s: op %q", v.Name, c.Op)
			}
			if len(set[c.Name]) == 0 {
				t.Errorf("%s: %s left with no address", v.Name, c.Name)
			}
		}
		for name, want := range v.Want.Addresses {
			if len(want) != len(set[name]) {
				t.Errorf("%s: %s replays to %d addresses, want %v", v.Name, name, len(set[name]), want)
			}
			for _, a := range want {
				if !set[name][a] {
					t.Errorf("%s: %s replays without %s", v.Name, name, a)
				}
			}
		}
	}
	if cross < 10 || !porkbun || !internal || !noLease {
		t.Errorf("coverage: %d cross-site cases (want ≥ 10), Porkbun ~10 min %v, internal-only %v, without the Lease %v", cross, porkbun, internal, noLease)
	}
}
