package limits

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Final review I3: a person's requests in flight and the gate-wide body
// budget are capped; Done gives both back, Shrink the unused budget.
func TestInFlightCaps(t *testing.T) {
	f := NewInFlightWith(2, Charge(8<<20)*2, 50*time.Millisecond)
	ctx := context.Background()
	a1, err := f.Admit(ctx, "alice", Charge(1))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := f.Admit(ctx, "alice", Charge(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Admit(ctx, "alice", Charge(1)); !errors.Is(err, ErrPersonBusy) {
		t.Fatalf("3rd of alice's: %v", err)
	}
	a1.Done()
	a1.Done() // a second Done is a no-op
	a3, err := f.Admit(ctx, "alice", Charge(1))
	if err != nil {
		t.Fatalf("after Done: %v", err)
	}
	a2.Done()
	a3.Done()
	// Two maximum-size bodies fill the budget; a third person waits, then 503.
	b, _ := f.Admit(ctx, "bob", Charge(8<<20))
	c, _ := f.Admit(ctx, "carol", Charge(8<<20))
	if b == nil || c == nil {
		t.Fatal("budget too small for two bodies")
	}
	start := time.Now()
	if _, err := f.Admit(ctx, "dave", Charge(8<<20)); !errors.Is(err, ErrGateBusy) {
		t.Fatalf("over budget: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("the budget wait isn't bounded")
	}
	if _, err := f.Admit(ctx, "dave", Charge(8<<20)); !errors.Is(err, ErrGateBusy) {
		t.Fatal("a refused admit kept dave's slot or charge")
	}
	// bob's body was small after all: the rest goes back.
	b.Shrink(10)
	d, err := f.Admit(ctx, "dave", Charge(4<<20))
	if err != nil {
		t.Fatalf("after Shrink: %v", err)
	}
	b.Done()
	c.Done()
	d.Done()
	if len(f.people) != 0 {
		t.Errorf("people left %v", f.people)
	}
}
