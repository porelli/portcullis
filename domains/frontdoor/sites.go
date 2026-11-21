package frontdoor

import (
	"slices"
	"sort"
)

// The front door across sites (§20.8, plan Task 28): the cross-site
// rules themselves (eligibility, blind probers, the two-site span, a
// whole site down) are Judge's and Engine.Step's; this is the per-site
// view of a round, for frontdoor-status.sites, the HA page and the site
// metrics.

// SiteSet is each node's site (nodeadm's snapshot).
type SiteSet map[string]string

// SitesOf is the site of every node.
func SitesOf(nodes map[string]Node) SiteSet {
	out := SiteSet{}
	for id, n := range nodes {
		out[id] = n.Site
	}
	return out
}

// Names are the sites, sorted.
func (s SiteSet) Names() []string {
	var out []string
	for _, site := range s {
		if !slices.Contains(out, site) {
			out = append(out, site)
		}
	}
	sort.Strings(out)
	return out
}

// SiteStatus is one site of frontdoor-status.sites: Healthy = an
// ingress node of the site is ok (healthy or undecided); Ingress its
// ingress nodes; Addresses their public addresses (what the site can
// publish: the HA page shows which of them each name holds); BlindProbers
// how many of its probers' counted rounds were blind (R10: its uplink is
// down, or every prober there is).
type SiteStatus struct {
	Healthy      bool     `json:"healthy"`
	Ingress      []string `json:"ingress"`
	Addresses    []string `json:"addresses"`
	BlindProbers int      `json:"blind_probers"`
}

// BuildSites is a round's per-site view: every site of the snapshot,
// with no ingress node too (not healthy, nothing to publish).
func BuildSites(c Cluster, v View) map[string]SiteStatus {
	out := map[string]SiteStatus{}
	for _, id := range sortedKeys(c.Nodes) {
		n := c.Nodes[id]
		s, ok := out[n.Site]
		if !ok {
			s = SiteStatus{Ingress: []string{}, Addresses: []string{}}
		}
		if v.BlindProbers[id] {
			s.BlindProbers++
		}
		if n.Ingress {
			s.Ingress = append(s.Ingress, id)
			if j, ok := v.Judgements[id]; ok && j.Verdict != Unhealthy {
				s.Healthy = true
			}
			for _, a := range n.Public {
				if !slices.Contains(s.Addresses, a) {
					s.Addresses = append(s.Addresses, a)
				}
			}
		}
		out[n.Site] = s
	}
	for site, s := range out {
		sort.Strings(s.Addresses)
		out[site] = s
	}
	return out
}
