package main

// apply --wait: how long to wait for the public resolvers after a write,
// from the TTLs the provider actually stored (contract §12.1).
//
// A resolver may keep what it fetched before the write for the old
// records' TTL (or, for an RRset that was empty, the zone's negative TTL);
// the provider may store a longer TTL than Portcullis asks for (porkbun
// raises anything under 600 s to 600). So --wait auto waits up to that
// TTL + waitMargin (the authoritative servers' own lag and one poll),
// longer while a resolver's answer shows it still holds the old data for
// longer (its remaining TTL), never past waitCap. --settle (the CAA relax
// before an ACME flip) also waits until every cache that may hold the old
// records — the CA's resolvers too, which nobody can ask — has expired:
// the write + that TTL + waitMargin.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/portcullis/domains/internal/dnsplan"
)

const (
	waitCap    = 15 * time.Minute
	waitMargin = time.Minute
)

// The wait's clock (tests replace both).
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
)

// waitReport is apply --wait's "wait" object (all durations in seconds).
type waitReport struct {
	// Visible: every resolver shows every applied set.
	Visible bool `json:"visible"`
	// Settled: every cache that may hold the records from before the
	// write has expired (the write + ttl + the margin are past).
	Settled bool `json:"settled"`
	// TTL: the longest TTL the provider holds for the applied sets'
	// RRsets, before or after the write (or the zone's negative TTL for
	// an RRset that was empty).
	TTL int `json:"ttl"`
	// Limit: how long the tool would wait at most; Waited: how long it did.
	Limit  int `json:"limit"`
	Waited int `json:"waited"`
	// Pending: the resolvers that don't show every applied set yet.
	Pending []string `json:"pending"`
	// ClearsIn: when every cache of the old records has expired at the
	// latest, from now (0 = already).
	ClearsIn int `json:"clears_in"`
}

// applyOutput is apply's stdout: the plan, plus "wait" with --wait.
type applyOutput struct {
	dnsplan.Plan
	Wait *waitReport `json:"wait,omitempty"`
}

// waitOpts: --wait auto | <duration>, --settle.
type waitOpts struct {
	auto   bool
	fixed  time.Duration
	settle bool
}

func (o waitOpts) on() bool { return o.auto || o.fixed > 0 }

// ctxBudget: the longest the wait can take.
func (o waitOpts) ctxBudget() time.Duration {
	if o.auto {
		return waitCap
	}
	return o.fixed
}

// ttlBound: the longest a resolver may keep what it had before the write
// (before / after: the provider's RRsets around the write; neg: the zone's
// negative TTL, for RRsets that were empty).
func ttlBound(before, after map[string]dnsplan.RRset, neg time.Duration) time.Duration {
	var ttl time.Duration
	for _, b := range before {
		ttl = max(ttl, b.TTL)
	}
	for k, a := range after {
		ttl = max(ttl, a.TTL)
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

// waitApplied polls every resolver on its own until each shows every
// applied set (and, with settle, the old records' caches have expired),
// or the limit. ok = done in time.
func waitApplied(ctx context.Context, e toolEnv, build func(dnsplan.Input) dnsplan.Plan, base dnsplan.Input,
	sets []string, o waitOpts, ttl time.Duration, writtenAt time.Time) (*waitReport, bool) {
	start := toolNow()
	limit := o.fixed
	if o.auto {
		limit = min(ttl+waitMargin, waitCap)
	}
	deadline, hardStop := start.Add(limit), start.Add(limit)
	if o.auto {
		hardStop = start.Add(waitCap)
	}
	settleAt := writtenAt.Add(ttl + waitMargin)
	rep := &waitReport{TTL: secs(ttl), Pending: []string{}}
	for {
		now := toolNow()
		var observed time.Time // the latest a pending resolver says it keeps its answer
		rep.Pending = []string{}
		for _, r := range e.resolvers {
			in := base
			in.Resolvers = []string{r}
			pl := build(in)
			if appliedVisible(pl, sets) {
				continue
			}
			rep.Pending = append(rep.Pending, r)
			for _, it := range pl.Items {
				if !contains(sets, it.Set) || it.Status == dnsplan.StatusForeign || it.Severity == dnsplan.SevInfo || it.Status == dnsplan.StatusOK {
					continue
				}
				if rem, ok := dnsplan.RemainingTTL(ctx, r, it); ok && now.Add(rem).After(observed) {
					observed = now.Add(rem)
				}
			}
		}
		if o.auto && !observed.IsZero() {
			if ext := observed.Add(waitMargin); ext.After(deadline) {
				deadline = ext
				if deadline.After(hardStop) {
					deadline = hardStop
				}
			}
		}
		clearsAt := settleAt
		if observed.After(clearsAt) {
			clearsAt = observed
		}
		rep.Visible = len(rep.Pending) == 0
		rep.Settled = rep.Visible && !now.Before(settleAt)
		rep.Limit, rep.Waited, rep.ClearsIn = secs(deadline.Sub(start)), secs(now.Sub(start)), secs(clearsAt.Sub(now))
		if rep.Visible && (!o.settle || rep.Settled) {
			return rep, true
		}
		// Settling can't happen in time: say so now rather than wait.
		if rep.Visible && settleAt.After(hardStop) {
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

// waitMessage: the stderr line after a wait that didn't finish. The
// records were written (a failed write never gets here).
func waitMessage(rep *waitReport) string {
	clears := fmt.Sprintf("those caches clear within %s", time.Duration(rep.ClearsIn)*time.Second)
	if rep.ClearsIn == 0 {
		clears = "those caches should have expired by now"
	}
	if !rep.Visible {
		return fmt.Sprintf("domains dns apply: the records were written, but they are not visible yet at %s after %s (the provider stored TTL %d s; %s)",
			strings.Join(rep.Pending, ", "), time.Duration(rep.Waited)*time.Second, rep.TTL, clears)
	}
	return fmt.Sprintf("domains dns apply: the records were written and every resolver checked shows them, but other resolvers (the CA's) may still cache the old records for up to %s (the provider stored TTL %d s)",
		time.Duration(rep.ClearsIn)*time.Second, rep.TTL)
}
