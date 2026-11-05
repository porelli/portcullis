// Package limits is the gate's per-person rate limiting (integration
// contract §15.9): per person and resource a request window with a burst
// bucket and a tools/call window, per person a window across resources,
// and the confirmation and mint budgets. Limits are per person, never per
// IP (every hosted client comes from the same range). The values come
// from the gate file's limits on every call, so an edit applies at once.
package limits

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/portcullis/mcp-gate/internal/config"
)

// Defaults are §15.9's values (used while the file has none to give).
var Defaults = config.Limits{
	ResourceRPM: 120, ResourceBurst: 30, PersonRPM: 600, ToolCallsRPM: 60,
	ConfirmationsPerHour: 10, MintsPerMinute: 10, Fanout: 4,
	MaxRequestBytes: config.FixedMaxRequestBytes, MaxResultBytes: config.FixedMaxResultBytes,
	UpstreamTimeoutS: config.FixedUpstreamTimeoutS,
}

// idleFor: entries without activity for this long are forgotten (longer
// than the longest window, an hour).
const idleFor = 65 * time.Minute

// window counts events in the last span; times are oldest first and at
// most the limit long (only allowed events are recorded).
type window struct{ times []time.Time }

func (w *window) trim(now time.Time, span time.Duration) {
	cut := now.Add(-span)
	i := 0
	for i < len(w.times) && !w.times[i].After(cut) {
		i++
	}
	if i > 0 {
		w.times = append(w.times[:0], w.times[i:]...)
	}
}

// check reports whether one more event fits; if not, how long until one
// does.
func (w *window) check(now time.Time, span time.Duration, max int) (bool, time.Duration) {
	w.trim(now, span)
	if len(w.times) < max {
		return true, 0
	}
	// The event that has to leave the window for one more to fit.
	oldest := w.times[len(w.times)-max]
	return false, oldest.Add(span).Sub(now)
}

func (w *window) add(now time.Time) { w.times = append(w.times, now) }

type resEntry struct {
	reqs, calls window
	bucket      *rate.Limiter
	last        time.Time
}

type personEntry struct {
	reqs, confirms, mints window
	last                  time.Time
}

type resKey struct{ user, resource string }

// Limiter is safe for concurrent use.
type Limiter struct {
	limits func() config.Limits
	now    func() time.Time

	mu        sync.Mutex
	res       map[resKey]*resEntry
	people    map[string]*personEntry
	lastSweep time.Time
}

// New: limits is read on every call (the current snapshot's), now is the
// clock (time.Now in production).
func New(limits func() config.Limits, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if limits == nil {
		limits = func() config.Limits { return Defaults }
	}
	return &Limiter{limits: limits, now: now, res: map[resKey]*resEntry{}, people: map[string]*personEntry{}}
}

// current fills non-positive values from the defaults (the validator
// refuses them in the file; this is for a nil snapshot).
func (l *Limiter) current() config.Limits {
	c := l.limits()
	pick := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	pick(&c.ResourceRPM, Defaults.ResourceRPM)
	pick(&c.ResourceBurst, Defaults.ResourceBurst)
	pick(&c.PersonRPM, Defaults.PersonRPM)
	pick(&c.ToolCallsRPM, Defaults.ToolCallsRPM)
	pick(&c.ConfirmationsPerHour, Defaults.ConfirmationsPerHour)
	pick(&c.MintsPerMinute, Defaults.MintsPerMinute)
	return c
}

func (l *Limiter) person(user string, now time.Time) *personEntry {
	p := l.people[user]
	if p == nil {
		p = &personEntry{}
		l.people[user] = p
	}
	p.last = now
	return p
}

func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for k, e := range l.res {
		if now.Sub(e.last) > idleFor {
			delete(l.res, k)
		}
	}
	for k, p := range l.people {
		if now.Sub(p.last) > idleFor {
			delete(l.people, k)
		}
	}
}

// Allow decides one MCP request of user to resource (toolCall: it is a
// tools/call). Every limit must allow it; a refusal consumes nothing and
// says how long to wait (Retry-After).
func (l *Limiter) Allow(user, resource string, toolCall bool) (ok bool, retryAfter time.Duration) {
	c := l.current()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweepLocked(now)
	k := resKey{user, resource}
	e := l.res[k]
	if e == nil {
		e = &resEntry{bucket: rate.NewLimiter(rate.Limit(float64(c.ResourceRPM)/60), c.ResourceBurst)}
		e.bucket.SetBurstAt(now, c.ResourceBurst) // starts full at now
		l.res[k] = e
	}
	e.last = now
	p := l.person(user, now)

	var wait time.Duration
	refuse := func(d time.Duration) {
		ok = false
		if d > wait {
			wait = d
		}
	}
	ok = true
	if fits, d := e.reqs.check(now, time.Minute, c.ResourceRPM); !fits {
		refuse(d)
	}
	if fits, d := p.reqs.check(now, time.Minute, c.PersonRPM); !fits {
		refuse(d)
	}
	if toolCall {
		if fits, d := e.calls.check(now, time.Minute, c.ToolCallsRPM); !fits {
			refuse(d)
		}
	}
	if !ok {
		return false, wait
	}
	// The burst bucket follows the file too.
	if lim := rate.Limit(float64(c.ResourceRPM) / 60); e.bucket.Limit() != lim {
		e.bucket.SetLimitAt(now, lim)
	}
	if e.bucket.Burst() != c.ResourceBurst {
		e.bucket.SetBurstAt(now, c.ResourceBurst)
	}
	r := e.bucket.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Minute
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	e.reqs.add(now)
	p.reqs.add(now)
	if toolCall {
		e.calls.add(now)
	}
	return true, 0
}

// AllowConfirm: one more confirmation started by user this hour
// (confirmations_per_hour; the Hub has its own limit too).
func (l *Limiter) AllowConfirm(user string) bool {
	c := l.current()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweepLocked(now)
	p := l.person(user, now)
	if fits, _ := p.confirms.check(now, time.Hour, c.ConfirmationsPerHour); !fits {
		return false
	}
	p.confirms.add(now)
	return true
}

// AllowMint: one more mint asked for user this minute (mints_per_minute).
func (l *Limiter) AllowMint(user string) bool {
	c := l.current()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweepLocked(now)
	p := l.person(user, now)
	if fits, _ := p.mints.check(now, time.Minute, c.MintsPerMinute); !fits {
		return false
	}
	p.mints.add(now)
	return true
}

// size counts the entries kept (tests).
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.res) + len(l.people)
}
