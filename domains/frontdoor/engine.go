// Package frontdoor is the domains service's front-door role (`domains
// frontdoor`, integration contract §20.8): it decides which ingress
// nodes' public addresses the main domain's `address` set (<d>, *.<d>)
// publishes, from the nodes' and Traefik's readiness (nodeadm's
// GET /v1/cluster) and the nodeagents' HTTPS probes (GET /v1/probes,
// §20.4), and writes them with the main domain's own DNS credentials
// while it holds the Lease portcullis-frontdoor (§20.5).
//
// Engine is the pure decision (frontdoor_vectors.json); Writer the
// provider writes; Runner one round of both every 10 s.
package frontdoor

import (
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// The hysteresis of §20.8.
const (
	// RemoveRounds: an address goes after this many unhealthy rounds in a
	// row (10 s apart).
	RemoveRounds = 3
	// AddAfter: an address comes back after this long of passing.
	AddAfter = 2 * time.Minute
	// ChangeEvery: at most one change per name in this window.
	ChangeEvery = 60 * time.Second
	// Detection is the worst case to notice a dead address (3 rounds).
	Detection = 30 * time.Second
	// MinTTL is the front door's TTL unless the provider's minimum is
	// higher (Porkbun: 600 s).
	MinTTL = 60 * time.Second
)

// Node is one cluster node as the front door sees it (nodeadm's
// snapshot): its site, whether it is an ingress node (Traefik's
// DaemonSet runs there) and its public addresses.
type Node struct {
	Site    string
	Ingress bool
	Public  []string
}

// ProbeResult is one target's result in a probe round (§20.4).
type ProbeResult struct {
	OK    bool   `json:"ok"`
	Class string `json:"class"`
}

// ProbeRound is one prober's round, the §20.4 shape verbatim.
type ProbeRound struct {
	T          time.Time              `json:"t"`
	Prober     string                 `json:"prober"`
	Site       string                 `json:"site"`
	ReachedAny bool                   `json:"reached_any"`
	EgressOK   bool                   `json:"egress_ok"`
	Results    map[string]ProbeResult `json:"results"`
}

// Inputs is one round's view: the Lease, the nodes, their readiness
// (the node Ready and its Traefik pod Ready), each prober's newest round
// (a node that is down has none) and the address sets the provider holds
// now, per name.
type Inputs struct {
	Lease     bool
	Nodes     map[string]Node
	Ready     map[string]bool
	Probes    []ProbeRound
	Published map[string][]string
}

// Change is one write: add or remove one address of one name.
type Change struct {
	T     time.Time
	Name  string
	Type  string // A or AAAA (CAA, TXT: the certificate's writes, Task 29)
	Op    string // add or remove
	Value string
}

// Verdict is a node's health in one round.
type Verdict int

const (
	// Healthy: Ready, and no failing majority (a strict passing majority
	// when it has eligible probers).
	Healthy Verdict = iota
	// Unhealthy: not Ready, or a strict majority of the eligible
	// non-blind probers fail it (spanning 2 sites when 2 or more sites
	// hold eligible probers).
	Unhealthy
	// Undecided: Ready but neither a strict failing nor a strict passing
	// majority (a tie, or a failing majority from one site only): it is
	// neither removed nor added back.
	Undecided
)

// Blind (R10): a prober that failed every target, its own address
// included, and its egress reference has lost its own uplink; its round
// is discarded.
func Blind(r ProbeRound) bool { return !r.ReachedAny && !r.EgressOK }

// Eligible (spike S6): only a prober at another site than the target
// counts; in-cluster networking answers same-site probes.
func Eligible(proberSite, targetSite string) bool { return proberSite != targetSite }

// The rules' switches, only ever changed by the tests that prove the
// vectors pin each rule.
var (
	blindRule = true
	spanRule  = true
	tieReadds = false
)

// Judgement is a node's verdict in a round and how it was reached.
type Judgement struct {
	Verdict Verdict
	// InternalOnly: no eligible non-blind prober had a result for it, so
	// readiness alone decided.
	InternalOnly bool
}

// Judge is node id's verdict from its readiness and the probe rounds.
func Judge(id string, n Node, ready bool, probes []ProbeRound) Judgement {
	elig, failing := 0, 0
	sites, failSites := map[string]bool{}, map[string]bool{}
	for _, p := range probes {
		res, ok := p.Results[id]
		if !ok || !Eligible(p.Site, n.Site) || (blindRule && Blind(p)) {
			continue
		}
		elig++
		sites[p.Site] = true
		if !res.OK {
			failing++
			failSites[p.Site] = true
		}
	}
	j := Judgement{InternalOnly: elig == 0}
	switch {
	case !ready:
		j.Verdict = Unhealthy
	case elig == 0:
		j.Verdict = Healthy
	case 2*failing > elig && (!spanRule || len(sites) < 2 || len(failSites) >= 2):
		j.Verdict = Unhealthy
	case 2*(elig-failing) > elig || (tieReadds && 2*failing == elig):
		j.Verdict = Healthy
	default:
		j.Verdict = Undecided
	}
	return j
}

// nodeState is a node's hysteresis.
type nodeState struct {
	streak         int       // unhealthy rounds in a row
	unhealthySince time.Time // first round of the streak (zero: none)
	healthySince   time.Time // first Healthy round in a row (zero: none)
}

// Engine decides the changes, round by round. Not safe for concurrent
// use.
type Engine struct {
	names []string
	nodes map[string]*nodeState
	last  map[string]time.Time
	view  View
}

// NewEngine decides the address sets of names (<d> and *.<d>).
func NewEngine(names []string) *Engine {
	return &Engine{names: append([]string(nil), names...), nodes: map[string]*nodeState{}, last: map[string]time.Time{}}
}

// Pending is a change waiting for its hysteresis (or for the rate limit,
// or for another address before the last one can go).
type Pending struct {
	Op    string
	Value string
	Since time.Time
}

// View is what the last Step saw, for frontdoor-status and the metrics.
type View struct {
	At           time.Time
	FailStatic   bool
	Judgements   map[string]Judgement
	BlindProbers map[string]bool
	// UnhealthySince is when each unhealthy ingress node's streak began.
	UnhealthySince map[string]time.Time
	Pending        map[string]*Pending
	LastChange     map[string]time.Time
}

// View returns the last Step's view.
func (e *Engine) View() View { return e.view }

// Step judges every ingress node at now and returns the changes due:
// at most one per name per 60 s, never the last address of a name, none
// when every ingress node is unhealthy (fail static) and none without
// the Lease (the hysteresis still runs).
func (e *Engine) Step(now time.Time, in Inputs) []Change {
	v := View{At: now, Judgements: map[string]Judgement{}, BlindProbers: map[string]bool{},
		UnhealthySince: map[string]time.Time{}, Pending: map[string]*Pending{}, LastChange: map[string]time.Time{}}
	for _, p := range in.Probes {
		if Blind(p) {
			v.BlindProbers[p.Prober] = true
		}
	}
	owner := map[string]string{}
	anyOK := false
	for _, id := range sortedKeys(in.Nodes) {
		n := in.Nodes[id]
		if !n.Ingress {
			continue
		}
		for _, a := range n.Public {
			owner[a] = id
		}
		j := Judge(id, n, in.Ready[id], in.Probes)
		v.Judgements[id] = j
		anyOK = anyOK || j.Verdict != Unhealthy
	}
	for id := range e.nodes {
		if _, ok := v.Judgements[id]; !ok {
			delete(e.nodes, id)
		}
	}
	if !anyOK {
		// Fail static: every ingress node fails (every probe failing
		// included): nothing changes, nothing counts towards a removal,
		// and nothing has been passing.
		v.FailStatic = true
		for _, s := range e.nodes {
			s.healthySince = time.Time{}
		}
	}
	for id, j := range v.Judgements {
		s := e.nodes[id]
		if s == nil {
			s = &nodeState{}
			e.nodes[id] = s
		}
		if !v.FailStatic {
			if j.Verdict == Unhealthy {
				if s.streak == 0 {
					s.unhealthySince = now
				}
				s.streak++
			} else {
				s.streak, s.unhealthySince = 0, time.Time{}
			}
			if j.Verdict == Healthy {
				if s.healthySince.IsZero() {
					s.healthySince = now
				}
			} else {
				s.healthySince = time.Time{}
			}
		}
		if s.streak > 0 {
			v.UnhealthySince[id] = s.unhealthySince
		}
	}
	var out []Change
	for _, name := range e.names {
		pub := map[string]bool{}
		for _, a := range in.Published[name] {
			pub[a] = true
		}
		// Removals: published addresses of ingress nodes unhealthy for 3
		// rounds, the longest-unhealthy first. Additions: ingress nodes'
		// addresses healthy for 2 min, the longest-healthy first.
		type cand struct {
			value string
			since time.Time
			due   bool
		}
		var rm, add []cand
		for a := range pub {
			id, ok := owner[a]
			if !ok {
				continue // not an ingress node's address: left alone
			}
			if s := e.nodes[id]; s.streak > 0 {
				rm = append(rm, cand{a, s.unhealthySince, s.streak >= RemoveRounds})
			}
		}
		for _, id := range sortedKeys(in.Nodes) {
			n := in.Nodes[id]
			s := e.nodes[id]
			if !n.Ingress || s == nil || s.healthySince.IsZero() {
				continue
			}
			for _, a := range n.Public {
				if !pub[a] {
					add = append(add, cand{a, s.healthySince, now.Sub(s.healthySince) >= AddAfter})
				}
			}
		}
		order := func(cs []cand) {
			sort.Slice(cs, func(i, j int) bool {
				if !cs[i].since.Equal(cs[j].since) {
					return cs[i].since.Before(cs[j].since)
				}
				return cs[i].value < cs[j].value
			})
		}
		order(rm)
		order(add)
		if len(rm) > 0 {
			v.Pending[name] = &Pending{Op: "remove", Value: rm[0].value, Since: rm[0].since}
		} else if len(add) > 0 {
			v.Pending[name] = &Pending{Op: "add", Value: add[0].value, Since: add[0].since}
		}
		if l, ok := e.last[name]; ok {
			v.LastChange[name] = l
		}
		if v.FailStatic || !in.Lease {
			continue
		}
		if l, ok := e.last[name]; ok && now.Sub(l) < ChangeEvery {
			continue
		}
		var c *Change
		// A removal first (a dead address hurts more than a missing
		// healthy one), but never the last address: then an addition.
		if len(rm) > 0 && rm[0].due && len(pub) > 1 {
			c = &Change{T: now, Name: name, Op: "remove", Value: rm[0].value}
		} else {
			for _, a := range add {
				if a.due {
					c = &Change{T: now, Name: name, Op: "add", Value: a.value}
					break
				}
			}
		}
		if c == nil {
			continue
		}
		c.Type = AddrType(c.Value)
		e.last[name] = now
		v.LastChange[name] = now
		v.Pending[name] = nil
		out = append(out, *c)
	}
	e.view = v
	return out
}

// AddrType is the record type of an address: A, AAAA, or "" when it
// isn't one.
func AddrType(value string) string {
	ip, err := netip.ParseAddr(value)
	switch {
	case err != nil || ip.Zone() != "" || ip.Is4In6():
		return ""
	case ip.Is4():
		return "A"
	default:
		return "AAAA"
	}
}

// TTL is the front door's TTL on a provider with that minimum.
func TTL(providerMin time.Duration) time.Duration { return max(MinTTL, providerMin) }

// WorstCaseSeconds is §20.8's worst_case_s: detection plus the TTL.
func WorstCaseSeconds(ttl time.Duration) int { return int((Detection + ttl) / time.Second) }

func worstMinutes(worstS int) int { return max(1, worstS/60) }

// WorstCaseText is the HA page's per-name text (§20.8).
func WorstCaseText(worstS int, provider string) string {
	return fmt.Sprintf("worst case ~%d min for clients that hit the dead address first, on %s", worstMinutes(worstS), provider)
}

// SiteWorstCaseText is the HA page's per-site text (§20.8).
func SiteWorstCaseText(site string, worstS int, provider string) string {
	return fmt.Sprintf("if site %s fails: worst case ~%d min on %s", site, worstMinutes(worstS), provider)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
