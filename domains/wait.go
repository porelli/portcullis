package main

// apply --wait: how long to wait for the public resolvers after a write,
// from the TTLs the provider actually stored (contract §12.1).
//
// A cache may keep what it fetched before the write for the old records'
// TTL — the longer of what the provider stores (0 or 1 s = "auto" / the
// zone default: unknown) and what the authoritative servers serve — or,
// for an RRset that was empty, the zone's negative TTL; the provider may
// store a longer TTL than Portcullis asks for (porkbun raises anything
// under 600 s to 600). So --wait auto waits up to that TTL + waitMargin
// (the authoritative servers' own lag and one poll), longer while a
// resolver's answer shows it still holds the old data for longer (its
// remaining TTL), never past waitCap. --settle (the CAA relax before an
// ACME flip) also waits until every cache that may hold the old records —
// the CA's resolvers too, which nobody can ask — has expired: the write +
// that TTL + waitMargin, later if a resolver held on longer. A rerun
// passes the settle point an earlier run reported (--settle-after): it
// only sees the records that run wrote, not the old ones.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/domains/internal/dnsplan"
)

const (
	waitCap    = 15 * time.Minute
	waitMargin = time.Minute
)

// The wait's clock and the zone's authoritative servers (tests replace them).
var (
	toolNow   = time.Now
	toolSleep = func(ctx context.Context, d time.Duration) {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
	toolAuthServers = dnsplan.AuthServers
)

// waitReport is apply --wait's "wait" object (durations in seconds,
// times in Unix seconds).
type waitReport struct {
	// Visible: every resolver shows every applied set.
	Visible bool `json:"visible"`
	// Settled: visible, and every cache that may hold the records from
	// before the write has expired (settle_at is past).
	Settled bool `json:"settled"`
	// TTL: the longest TTL caches may hold the applied sets' RRsets for,
	// before or after the write: the provider's stored TTL (0 or 1 =
	// unknown), the authoritative servers' served one when longer, the
	// zone's negative TTL for an RRset that was empty.
	TTL int `json:"ttl"`
	// Limit: how long the tool would wait at most; Waited: how long it did.
	Limit  int `json:"limit"`
	Waited int `json:"waited"`
	// Pending: the resolvers that don't show every applied set yet.
	Pending []string `json:"pending"`
	// ClearsIn: when every cache of the old records has expired at the
	// latest, from now (0 = already).
	ClearsIn int `json:"clears_in"`
	// WrittenAt: this run's write; SettleAt: when every cache of the old
	// records has expired at the latest (with --settle-after, never
	// earlier than it); BeyondCap: SettleAt is past what one run waits.
	WrittenAt int64 `json:"written_at"`
	SettleAt  int64 `json:"settle_at"`
	BeyondCap bool  `json:"beyond_cap"`
	// SettleCause: what set SettleAt: "ttl" (the write + the TTL + the
	// margin), "resolver" (a resolver's remaining TTL for the old records
	// moved it later), "saved" (--settle-after, an earlier run's point).
	SettleCause string `json:"settle_cause"`
	// HeldBy: the resolvers whose reported remaining TTL for an old CAA
	// answer hasn't run out yet; HeldFor: the longest of those, from now.
	HeldBy  []string `json:"held_by"`
	HeldFor int      `json:"held_for"`
}

// applyOutput is apply's stdout: the plan, plus "wait" with --wait.
type applyOutput struct {
	dnsplan.Plan
	Wait *waitReport `json:"wait,omitempty"`
}

// waitOpts: --wait auto | <duration>, --wait-max <duration> (auto
// only, never with --settle: the tighten's 3 min, so `up` isn't held by a
// step that isn't a safety one), --settle, --settle-after <unix>.
type waitOpts struct {
	auto        bool
	fixed       time.Duration
	max         time.Duration
	settle      bool
	settleAfter int64
}

// cap: the longest an auto wait runs (waitCap, or --wait-max).
func (o waitOpts) cap() time.Duration {
	if o.max > 0 {
		return min(o.max, waitCap)
	}
	return waitCap
}

func (o waitOpts) on() bool { return o.auto || o.fixed > 0 }

// ctxBudget: the longest the wait can take.
func (o waitOpts) ctxBudget() time.Duration {
	if o.auto {
		return o.cap()
	}
	return o.fixed
}

// unknownTTL stands in for a TTL nobody reports: the whole cap.
const unknownTTL = waitCap - waitMargin

// effectiveTTLs: per RRset (Stored's keys), how long caches may hold it:
// the stored TTL (0 or 1 s is "auto" / "the zone default": unknown), or
// the TTL the authoritative servers serve when longer; unknown and not
// served = unknownTTL.
func effectiveTTLs(ctx context.Context, stored map[string]dnsplan.RRset, servers []string) (map[string]time.Duration, []string) {
	out := map[string]time.Duration{}
	var unknown []string
	for k, rs := range stored {
		ttl := rs.TTL
		if ttl <= time.Second {
			ttl = 0
		}
		name, typ, _ := strings.Cut(k, " ")
		if served, ok := dnsplan.ServedTTL(ctx, servers, name, typ); ok {
			ttl = max(ttl, served)
		}
		if ttl == 0 {
			ttl = unknownTTL
			unknown = append(unknown, k)
		}
		out[k] = ttl
	}
	sort.Strings(unknown)
	return out, unknown
}

// settlePoint: the write + ttl + the margin; with --settle-after, that
// one when this write changed nothing (the records are the ones the
// earlier run wrote), else the later of the two.
func settlePoint(o waitOpts, ttl time.Duration, writtenAt time.Time, changed bool) time.Time {
	at := writtenAt.Add(ttl + waitMargin)
	if o.settleAfter > 0 {
		after := time.Unix(o.settleAfter, 0)
		if !changed || after.After(at) {
			at = after
		}
	}
	return at
}

// ttlBound: the longest a cache may keep what it had before the write
// (before / after: the RRsets' effective TTLs around it; neg: the zone's
// negative TTL, for RRsets that were empty).
func ttlBound(before, after map[string]time.Duration, neg time.Duration) time.Duration {
	var ttl time.Duration
	for _, b := range before {
		ttl = max(ttl, b)
	}
	for k, a := range after {
		ttl = max(ttl, a)
		if _, ok := before[k]; !ok {
			ttl = max(ttl, neg)
		}
	}
	return ttl
}

func secs(d time.Duration) int {
	if d < 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// A resolver is a pool (anycast, many caches): one round where it shows
// the new records says little, the next may hit a cache still holding the
// old ones. So "visible" means stable: every resolver showed every applied
// set in stableRounds rounds in a row, spanning at least toolStableSpan
// (at the 10 s poll: 4 rounds, 30 s), and every remaining TTL a resolver
// reported for an old CAA answer has run out (G: 8.8.8.8 re-served an old
// pin with a near-fresh TTL long after the change).
const stableRounds = 4

// toolStableSpan: how long the clean rounds must span (tests shorten it).
var toolStableSpan = 30 * time.Second

// waitApplied polls every resolver on its own until each stably shows
// every applied set (and, with settle, the old records' caches have
// expired), or the limit. changed: this run's write changed an RRset
// (else, with --settle-after, the earlier run's settle point is the one
// that counts: the current records are the ones that run wrote). ok =
// done in time.
func waitApplied(ctx context.Context, e toolEnv, build func(dnsplan.Input) dnsplan.Plan, base dnsplan.Input,
	sets []string, o waitOpts, ttl time.Duration, writtenAt time.Time, changed bool) (*waitReport, bool) {
	start := toolNow()
	limit := o.fixed
	if o.auto {
		limit = min(ttl+waitMargin, o.cap())
	}
	deadline, hardStop := start.Add(limit), start.Add(limit)
	if o.auto {
		hardStop = start.Add(o.cap())
	}
	settleAt := settlePoint(o, ttl, writtenAt, changed)
	cause := "ttl"
	if !settleAt.Equal(writtenAt.Add(ttl + waitMargin)) {
		cause = "saved"
	}
	rep := &waitReport{TTL: secs(ttl), Pending: []string{}, HeldBy: []string{}, WrittenAt: writtenAt.Unix()}
	held := map[string]time.Time{} // per resolver: until when it said it keeps an old CAA answer
	var streakStart time.Time      // the first of the clean rounds in a row
	streak := 0
	var unsteady []string // the resolvers behind the last round that wasn't clean
	for {
		now := toolNow()
		var observed time.Time // the latest a pending resolver says it keeps its answer
		var pending []string
		for _, r := range e.resolvers {
			in := base
			in.Resolvers = []string{r}
			pl := build(in)
			if appliedVisible(pl, sets) {
				continue
			}
			pending = append(pending, r)
			for _, it := range pl.Items {
				if !contains(sets, it.Set) || it.Status == dnsplan.StatusForeign || it.Severity == dnsplan.SevInfo || it.Status == dnsplan.StatusOK {
					continue
				}
				rem, ok := dnsplan.RemainingTTL(ctx, r, it)
				if !ok {
					continue
				}
				until := now.Add(rem)
				if until.After(observed) {
					observed = until
				}
				if it.Set == dnsplan.SetCAA && until.After(held[r]) {
					held[r] = until
				}
			}
		}
		if !observed.IsZero() {
			// A resolver holding the old data that long means caches
			// anywhere (the CA's) may: the settle point moves too.
			ext := observed.Add(waitMargin)
			if ext.After(settleAt) {
				settleAt, cause = ext, "resolver"
			}
			if o.auto && ext.After(deadline) {
				deadline = earliest(ext, hardStop)
			}
		}
		seen := len(pending) == 0 // every resolver shows it this round
		if seen {
			if streak == 0 {
				streakStart = now
			}
			streak++
		} else {
			streak, unsteady = 0, pending
		}
		steady := seen && streak >= stableRounds && now.Sub(streakStart) >= toolStableSpan
		if o.auto && seen && !steady {
			// The clean rounds still fit in the run: wait for them.
			if need := streakStart.Add(toolStableSpan); need.After(deadline) {
				deadline = earliest(need, hardStop)
			}
		}
		var heldUntil time.Time
		rep.HeldBy = []string{}
		for _, r := range e.resolvers {
			if held[r].After(now) {
				rep.HeldBy = append(rep.HeldBy, r)
				if held[r].After(heldUntil) {
					heldUntil = held[r]
				}
			}
		}
		rep.Visible = steady && len(rep.HeldBy) == 0
		rep.Pending = []string{}
		if !rep.Visible {
			for _, r := range e.resolvers {
				if contains(pending, r) || (!steady && contains(unsteady, r)) || contains(rep.HeldBy, r) {
					rep.Pending = append(rep.Pending, r)
				}
			}
			if len(rep.Pending) == 0 { // clean so far, just not for long enough
				rep.Pending = append(rep.Pending, e.resolvers...)
			}
		}
		rep.Settled = rep.Visible && !now.Before(settleAt)
		rep.SettleAt, rep.SettleCause = settleAt.Unix(), cause
		rep.BeyondCap = settleAt.After(hardStop)
		rep.HeldFor = secs(heldUntil.Sub(now))
		rep.Limit, rep.Waited, rep.ClearsIn = secs(deadline.Sub(start)), secs(now.Sub(start)), secs(settleAt.Sub(now))
		if rep.Visible && (!o.settle || rep.Settled) {
			return rep, true
		}
		// Settling can't happen in this run: say so now rather than wait.
		if seen && o.settle && rep.BeyondCap {
			return rep, false
		}
		if !now.Before(deadline) || ctx.Err() != nil {
			return rep, false
		}
		d := min(toolPollEvery, deadline.Sub(now))
		if rep.Visible {
			d = min(d, settleAt.Sub(now))
		}
		toolSleep(ctx, d)
	}
}

// clockAt: a Unix time as "HH:MM UTC", rounded up to the minute (so
// "after HH:MM" is never early).
func clockAt(unix int64) string {
	return time.Unix((unix+59)/60*60, 0).UTC().Format("15:04 MST")
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// progressMessage: the stderr line right after the write, before the
// wait. It ends with "written_at=<unix> settle_at=<unix>" (contract
// §12.1): the shell saves the settle point from it at once, so an
// interrupted wait can't lose it.
func progressMessage(o waitOpts, ttl time.Duration, resolvers []string, writtenAt time.Time, changed bool) string {
	limit := o.fixed
	if o.auto {
		limit = min(ttl+waitMargin, o.cap())
	}
	return fmt.Sprintf("domains dns apply: written; waiting up to %s for %s (TTL %d s); written_at=%d settle_at=%d",
		limit, strings.Join(resolvers, ", "), secs(ttl), writtenAt.Unix(), settlePoint(o, ttl, writtenAt, changed).Unix())
}

// waitMessage: the stderr line after a wait that didn't finish. The
// records were written (a failed write never gets here): it says so, and
// never that anything failed. A settle point past what one run waits
// names its cause; each gives the time after which a rerun goes ahead.
func waitMessage(rep *waitReport, settle bool) string {
	at := clockAt(rep.SettleAt)
	if settle && rep.BeyondCap {
		switch rep.SettleCause {
		case "resolver":
			who := strings.Join(rep.HeldBy, ", ")
			if who == "" {
				who = "a resolver"
			}
			return fmt.Sprintf("domains dns apply: written; %s still serves the old records (%d s left), so caches (the CA's too) may hold them until %s. A rerun goes ahead after %s",
				who, rep.HeldFor, at, at)
		case "saved":
			return fmt.Sprintf("domains dns apply: written; an earlier run's settle point is %s, past what one run waits (%s). A rerun goes ahead after %s",
				at, waitCap, at)
		default:
			return fmt.Sprintf("domains dns apply: written; the old records' stored TTL (%d s) is above what one run waits (%s): caches (the CA's too) may hold them until %s. A rerun goes ahead after %s; lowering the TTL at the provider first shortens it",
				rep.TTL, waitCap, at, at)
		}
	}
	if !rep.Visible {
		left := fmt.Sprintf("they may serve the old records for up to %s more (until %s)", time.Duration(rep.ClearsIn)*time.Second, at)
		if rep.ClearsIn == 0 {
			left = "their caches of the old records should have expired by now"
		}
		return fmt.Sprintf("domains dns apply: written; not yet stable at %s after %s (TTL %d s; %s)",
			strings.Join(rep.Pending, ", "), time.Duration(rep.Waited)*time.Second, rep.TTL, left)
	}
	return fmt.Sprintf("domains dns apply: written; every resolver checked shows them, but other resolvers (the CA's) may still cache the old records for up to %s (TTL %d s; until %s)",
		time.Duration(rep.ClearsIn)*time.Second, rep.TTL, at)
}
