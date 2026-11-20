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

// rules switches a rule off, only in the tests that prove the vectors
// pin each rule (the zero value is the contract's).
type rules struct {
	noBlind, noSpan, tieReadds, noFresh, noGapReset, keepOrphans, oneOwner, verdictFailStatic, noObservationHealthy bool
}

// Judgement is a node's verdict in a round and how it was reached.
type Judgement struct {
	Verdict Verdict
	// InternalOnly: no eligible non-blind prober had a result for it, so
	// readiness alone decided.
	InternalOnly bool
	// Eligible and Failing count the eligible non-blind results.
	Eligible, Failing int
	// NoObservation: the probers that would judge it sent only rounds
	// already counted or stale: this round neither counts towards a
	// removal nor as healthy.
	NoObservation bool
}

// Judge is node id's verdict from its readiness and the probe rounds.
func Judge(id string, n Node, ready bool, probes []ProbeRound) Judgement {
	return judge(rules{}, id, n, ready, probes)
}

func judge(r rules, id string, n Node, ready bool, probes []ProbeRound) Judgement {
	elig, failing := 0, 0
	sites, failSites := map[string]bool{}, map[string]bool{}
	for _, p := range probes {
		res, ok := p.Results[id]
		if !ok || !Eligible(p.Site, n.Site) || (!r.noBlind && Blind(p)) {
			continue
		}
		elig++
		sites[p.Site] = true
		if !res.OK {
			failing++
			failSites[p.Site] = true
		}
	}
	j := Judgement{InternalOnly: elig == 0, Eligible: elig, Failing: failing}
	switch {
	case !ready:
		j.Verdict = Unhealthy
	case elig == 0:
		j.Verdict = Healthy
	case 2*failing > elig && (r.noSpan || len(sites) < 2 || len(failSites) >= 2):
		j.Verdict = Unhealthy
	case 2*(elig-failing) > elig || (r.tieReadds && 2*failing == elig):
		j.Verdict = Healthy
	default:
		j.Verdict = Undecided
	}
	return j
}

// ProbeFresh: a probe round older than this isn't an observation (the
// nodeagents probe every 10 s).
const ProbeFresh = 15 * time.Second

// maxGap: rounds further apart than this aren't consecutive; every count
// starts again.
const maxGap = Round * 3 / 2

// nodeState is a node's hysteresis.
type nodeState struct {
	streak         int       // unhealthy rounds in a row
	unhealthySince time.Time // first round of the streak (zero: none)
	healthySince   time.Time // first Healthy round in a row (zero: none)
}

// Engine decides the changes, round by round. Not safe for concurrent
// use.
type Engine struct {
	names     []string
	rules     rules
	nodes     map[string]*nodeState
	attempted map[string]time.Time // the last change emitted per name
	applied   map[string]time.Time // the last change written per name
	seen      map[string]time.Time // the newest probe round counted per prober
	lastStep  time.Time
	view      View
}

// NewEngine decides the address sets of names (<d> and *.<d>).
func NewEngine(names []string) *Engine { return newEngine(names, rules{}) }

func newEngine(names []string, r rules) *Engine {
	return &Engine{names: append([]string(nil), names...), rules: r, nodes: map[string]*nodeState{},
		attempted: map[string]time.Time{}, applied: map[string]time.Time{}, seen: map[string]time.Time{}}
}

// Seed takes the last written change per name from an earlier front door
// (frontdoor-status), so a new leader keeps the one change per 60 s.
func (e *Engine) Seed(last map[string]time.Time) {
	for n, t := range last {
		if t.After(e.applied[n]) {
			e.applied[n] = t
		}
	}
}

// Applied records that a change of name was written at t.
func (e *Engine) Applied(name string, t time.Time) {
	if t.After(e.applied[name]) {
		e.applied[name] = t
	}
	if e.view.LastChange != nil {
		e.view.LastChange[name] = e.applied[name]
	}
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
	At         time.Time
	FailStatic bool
	Judgements map[string]Judgement
	// BlindProbers are the probers whose (counted) round was blind.
	BlindProbers map[string]bool
	// UnhealthySince is when each unhealthy ingress node's streak began.
	UnhealthySince map[string]time.Time
	Pending        map[string]*Pending
	// LastChange is the last change written per name.
	LastChange map[string]time.Time
}

// View returns the last Step's view.
func (e *Engine) View() View { return e.view }

// Step judges every ingress node at now and returns the changes due:
// at most one per name per 60 s, never the last address of a type of a
// name, none when every ingress node is unhealthy or every counted probe
// failed (fail static), and none without the Lease (the hysteresis still
// runs). Only consecutive rounds (at most 15 s apart) and each prober's
// fresh rounds, each counted once, are observations.
func (e *Engine) Step(now time.Time, in Inputs) []Change {
	v := View{At: now, Judgements: map[string]Judgement{}, BlindProbers: map[string]bool{},
		UnhealthySince: map[string]time.Time{}, Pending: map[string]*Pending{}, LastChange: map[string]time.Time{}}
	if !e.rules.noGapReset && !e.lastStep.IsZero() && now.Sub(e.lastStep) > maxGap {
		// A gap (a round that couldn't read the cluster or the provider):
		// the rounds before it aren't consecutive with this one.
		e.nodes = map[string]*nodeState{}
	}
	e.lastStep = now
	var probes, dropped []ProbeRound
	for _, p := range in.Probes {
		if last, ok := e.seen[p.Prober]; !e.rules.noFresh && ((ok && !p.T.After(last)) || now.Sub(p.T) > ProbeFresh || p.T.Sub(now) > ProbeFresh) {
			dropped = append(dropped, p) // a round already counted, or stale
			continue
		}
		e.seen[p.Prober] = p.T
		probes = append(probes, p)
		if Blind(p) {
			v.BlindProbers[p.Prober] = true
		}
	}
	owners := map[string][]string{}
	anyOK := false
	for _, id := range sortedKeys(in.Nodes) {
		n := in.Nodes[id]
		if !n.Ingress {
			continue
		}
		for _, a := range n.Public {
			owners[a] = append(owners[a], id)
		}
		j := judge(e.rules, id, n, in.Ready[id], probes)
		// No observation: Ready, no counted eligible result, but probers
		// that would judge it sent only rounds already counted or stale.
		// Its counts stay as they are (no reset, no healthy round).
		if in.Ready[id] && j.Eligible == 0 && !e.rules.noObservationHealthy && judge(e.rules, id, n, true, dropped).Eligible > 0 {
			j.NoObservation = true
		}
		v.Judgements[id] = j
		anyOK = anyOK || j.Verdict != Unhealthy
	}
	for id := range e.nodes {
		if _, ok := v.Judgements[id]; !ok {
			delete(e.nodes, id)
		}
	}
	// Fail static: every ingress node fails, or every counted prober
	// failed every target it probes (every probe failing; a node no
	// prober probes yet can't make such a round count): nothing changes
	// and every count starts again.
	reached := false
	for _, p := range probes {
		reached = reached || p.ReachedAny
	}
	if !anyOK || (!e.rules.verdictFailStatic && len(probes) > 0 && !reached) {
		v.FailStatic = true
		e.nodes = map[string]*nodeState{}
	}
	for id, j := range v.Judgements {
		s := e.nodes[id]
		if s == nil {
			s = &nodeState{}
			e.nodes[id] = s
		}
		if v.FailStatic || j.NoObservation {
			if s.streak > 0 {
				v.UnhealthySince[id] = s.unhealthySince
			}
			continue
		}
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
		if s.streak > 0 {
			v.UnhealthySince[id] = s.unhealthySince
		}
	}
	type cand struct {
		value  string
		since  time.Time
		due    bool
		orphan bool
	}
	var out []Change
	for _, name := range e.names {
		pub := map[string]bool{}
		for _, a := range in.Published[name] {
			pub[a] = true
		}
		// Removals: an address no ingress node owns (a removed node; not a
		// health judgement: due at once, after the unhealthy ones), and
		// addresses every owner of which has been unhealthy for 3 rounds.
		// Additions: addresses an owner of which has been healthy for 2 min.
		var rm, add []cand
		for a := range pub {
			ids := owners[a]
			if len(ids) > 1 && e.rules.oneOwner {
				ids = ids[len(ids)-1:]
			}
			if len(ids) == 0 {
				if e.rules.keepOrphans {
					continue
				}
				rm = append(rm, cand{value: a, since: now, due: true, orphan: true})
				continue
			}
			c := cand{value: a, due: true}
			all := true
			for _, id := range ids {
				s := e.nodes[id]
				if s.streak == 0 {
					all = false
					break
				}
				if s.unhealthySince.After(c.since) {
					c.since = s.unhealthySince
				}
				c.due = c.due && s.streak >= RemoveRounds
			}
			if all {
				rm = append(rm, c)
			}
		}
		for _, a := range sortedKeys(owners) {
			if pub[a] {
				continue
			}
			var since time.Time
			observed := false
			for _, id := range owners[a] {
				if s := e.nodes[id]; !s.healthySince.IsZero() && (since.IsZero() || s.healthySince.Before(since)) {
					since = s.healthySince
				}
				observed = observed || (v.Judgements[id].Verdict == Healthy && !v.Judgements[id].NoObservation)
			}
			if !since.IsZero() {
				// Due only on a round that observed an owner healthy.
				add = append(add, cand{value: a, since: since, due: observed && now.Sub(since) >= AddAfter})
			}
		}
		sort.Slice(rm, func(i, j int) bool {
			a, b := rm[i], rm[j]
			if a.due != b.due {
				return a.due
			}
			if a.orphan != b.orphan {
				return !a.orphan
			}
			if !a.since.Equal(b.since) {
				return a.since.Before(b.since)
			}
			return a.value < b.value
		})
		sort.Slice(add, func(i, j int) bool {
			if !add[i].since.Equal(add[j].since) {
				return add[i].since.Before(add[j].since)
			}
			return add[i].value < add[j].value
		})
		if len(rm) > 0 {
			v.Pending[name] = &Pending{Op: "remove", Value: rm[0].value, Since: rm[0].since}
		} else if len(add) > 0 {
			v.Pending[name] = &Pending{Op: "add", Value: add[0].value, Since: add[0].since}
		}
		if l, ok := e.applied[name]; ok {
			v.LastChange[name] = l
		}
		if v.FailStatic || !in.Lease {
			continue
		}
		last := e.applied[name]
		if a := e.attempted[name]; a.After(last) {
			last = a
		}
		if !last.IsZero() && now.Sub(last) < ChangeEvery {
			continue
		}
		var c *Change
		// A removal first (a dead address hurts more than a missing
		// healthy one), but never the last address of its type: then an
		// addition.
		for _, r := range rm {
			if r.due && sameType(pub, r.value) > 1 {
				c = &Change{T: now, Name: name, Op: "remove", Value: r.value}
				break
			}
		}
		if c == nil {
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
		e.attempted[name] = now
		v.Pending[name] = nil
		out = append(out, *c)
	}
	e.view = v
	return out
}

// sameType counts the published values of value's record type.
func sameType(pub map[string]bool, value string) int {
	n, t := 0, AddrType(value)
	for a := range pub {
		if AddrType(a) == t {
			n++
		}
	}
	return n
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
