package limits

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// Memory bounds (final review I3): rates alone let one person hold many
// maximum-size requests at once and exhaust the gate's memory (and with
// it everyone's AI access). Two caps in front of every body read:
//
//   - PerPersonInFlight POST requests per person at once, across all
//     resources (over it: 429). GET streams and DELETE carry no body and
//     aren't counted.
//   - a gate-wide body budget: each POST holds BodyFactor × its body
//     size (Content-Length, else the maximum until the body is read: the
//     body is read whole, then copied and decoded by the SDK) until it
//     ends; no room within BudgetWait = 503.
//
// One person's worst case is then PerPersonInFlight × (body + result):
// 6 × (3 × 8 MiB + 2 × 16 MiB) ≈ 336 MiB, inside the container's 1 GiB.
const (
	PerPersonInFlight = 6
	BodyFactor        = 3
	BodyBudget        = 512 << 20
	BudgetWait        = 2 * time.Second
	// minCharge: what a request with an empty or tiny body holds.
	minCharge = 64 << 10
)

var (
	// ErrPersonBusy: the person has PerPersonInFlight requests running.
	ErrPersonBusy = errors.New("too many requests in flight")
	// ErrGateBusy: the gate-wide body budget had no room in time.
	ErrGateBusy = errors.New("gate busy")
)

// InFlight is safe for concurrent use.
type InFlight struct {
	perPerson int
	budget    *semaphore.Weighted
	max       int64
	wait      time.Duration

	mu     sync.Mutex
	people map[string]int
}

// NewInFlight returns the caps above.
func NewInFlight() *InFlight {
	return NewInFlightWith(PerPersonInFlight, BodyBudget, BudgetWait)
}

// NewInFlightWith (tests).
func NewInFlightWith(perPerson int, budget int64, wait time.Duration) *InFlight {
	return &InFlight{perPerson: perPerson, budget: semaphore.NewWeighted(budget), max: budget, wait: wait, people: map[string]int{}}
}

// Ticket is one admitted request; Done exactly once (extra calls are
// no-ops).
type Ticket struct {
	f      *InFlight
	user   string
	charge int64
	once   sync.Once
}

// Charge is what a body of n bytes holds.
func Charge(n int64) int64 {
	c := n * BodyFactor
	if c < minCharge {
		c = minCharge
	}
	return c
}

// Admit takes the person's slot and charge bytes of the budget (Charge of
// the declared size, or of the maximum when unknown).
func (f *InFlight) Admit(ctx context.Context, user string, charge int64) (*Ticket, error) {
	f.mu.Lock()
	if f.people[user] >= f.perPerson {
		f.mu.Unlock()
		return nil, ErrPersonBusy
	}
	f.people[user]++
	f.mu.Unlock()
	if charge > f.max {
		charge = f.max
	}
	wctx, cancel := context.WithTimeout(ctx, f.wait)
	defer cancel()
	if err := f.budget.Acquire(wctx, charge); err != nil {
		f.leave(user)
		return nil, ErrGateBusy
	}
	return &Ticket{f: f, user: user, charge: charge}, nil
}

// Shrink gives back what the request holds above Charge(n) once its body
// is read (n bytes).
func (t *Ticket) Shrink(n int64) {
	if t == nil {
		return
	}
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	if c := Charge(n); c < t.charge {
		t.f.budget.Release(t.charge - c)
		t.charge = c
	}
}

// Done releases the slot and the budget.
func (t *Ticket) Done() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		t.f.mu.Lock()
		c := t.charge
		t.f.mu.Unlock()
		t.f.budget.Release(c)
		t.f.leave(t.user)
	})
}

func (f *InFlight) leave(user string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.people[user]--; f.people[user] <= 0 {
		delete(f.people, user)
	}
}
