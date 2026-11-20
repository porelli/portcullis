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
// a node that is down has no probe round. Cases tagged cross_site hold the
// R10/R11 rules (blind probers, the two-site span, whole sites).
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
	Hairpin        bool     `json:"hairpin"`
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

var fdClasses = map[string]bool{"ok": true, "timeout": true, "refused": true, "tls": true, "http_status": true, "no_route_inside": true}

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
	if len(vs) < 20 {
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
				any := false
				for target, res := range p.Results {
					if target == p.Prober || !v.Nodes[target].Ingress || !fdClasses[res.Class] || res.OK != (res.Class == "ok") {
						t.Errorf("%s: round %d: %s → %s %+v", v.Name, i, p.Prober, target, res)
					}
					any = any || res.OK
				}
				if any != p.ReachedAny {
					t.Errorf("%s: round %d: %s reached_any %v", v.Name, i, p.Prober, p.ReachedAny)
				}
			}
		}
		for _, c := range v.Want.Changes {
			if c.Op != "add" && c.Op != "remove" {
				t.Errorf("%s: op %q", v.Name, c.Op)
			}
		}
	}
	if cross < 8 || !porkbun || !internal || !noLease {
		t.Errorf("coverage: %d cross-site cases (want ≥ 8), Porkbun ~10 min %v, internal-only %v, without the Lease %v", cross, porkbun, internal, noLease)
	}
}
