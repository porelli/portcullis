package mtasts

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func on(fail bool) Inputs {
	return Inputs{Mail: "on", Reachable: true, MX: "mail.example.com", Failure: func(time.Time) bool { return fail }}
}

func TestMTASTSEnforceAfter7Days(t *testing.T) {
	d := Step(Domain{}, on(false), t0)
	if d.Mode != Testing || !strings.Contains(d.Policy, "mode: testing\nmx: mail.example.com\nmax_age: 86400") {
		t.Fatalf("start %+v", d)
	}
	if _, err := DoEnforce(d, on(false), t0.Add(6*24*time.Hour)); err == nil {
		t.Fatal("enforced before 7 days")
	}
	d = Step(d, on(false), t0.Add(8*24*time.Hour)) // testing stays without the action
	if d.Mode != Testing {
		t.Fatal("enforce without the action")
	}
	if _, err := DoEnforce(d, on(true), t0.Add(8*24*time.Hour)); err == nil {
		t.Fatal("enforced with a failure")
	}
	e, err := DoEnforce(d, on(false), t0.Add(8*24*time.Hour))
	if err != nil || e.Mode != Enforce || !strings.Contains(e.Policy, "max_age: 604800") || e.ID == d.ID {
		t.Fatalf("enforce %+v %v", e, err)
	}
}

func TestMTASTSFailureBackToTesting(t *testing.T) {
	d := Step(Domain{}, on(false), t0)
	d, _ = DoEnforce(d, on(false), t0.Add(8*24*time.Hour))
	d = Step(d, on(true), t0.Add(9*24*time.Hour))
	if d.Mode != Testing || !d.Since.Equal(t0.Add(9*24*time.Hour)) || !strings.Contains(d.Policy, "testing") {
		t.Fatalf("after a failure %+v", d)
	}
}

func TestPolicyIDChangesWithPolicy(t *testing.T) {
	d := Step(Domain{}, on(false), t0)
	id := d.ID
	if !strings.HasSuffix(id, "T1794736800") || len(strings.Split(id, "T")[0]) != 20 {
		t.Fatalf("id %s", id)
	}
	d2 := Step(d, on(false), t0.Add(time.Hour))
	if d2.ID != id {
		t.Fatal("the id changed without a policy change")
	}
	in := on(false)
	in.MX = "mx.example.com"
	d3 := Step(d2, in, t0.Add(2*time.Hour))
	if d3.ID == id {
		t.Fatal("the id didn't change with the policy")
	}
}

// Review Focus 4: mail off publishes mode none for the full max_age, then
// the domain is off (status "off" exactly when the drain is done).
func TestMailOffPublishesNoneThenRemoves(t *testing.T) {
	d := Step(Domain{}, on(false), t0)
	d, _ = DoEnforce(d, on(false), t0.Add(8*24*time.Hour))
	drain := Inputs{Mail: "draining", Reachable: true, MX: "mail.example.com"}
	at := t0.Add(9 * 24 * time.Hour)
	d = Step(d, drain, at)
	if d.Mode != None || !strings.Contains(d.Policy, "mode: none") || d.ID == "" {
		t.Fatalf("drain start %+v", d)
	}
	d = Step(d, drain, at.Add(MaxAgeEnforce*time.Second-time.Second))
	if d.Mode != None {
		t.Fatal("off before the enforce max_age")
	}
	d = Step(d, drain, at.Add(MaxAgeEnforce*time.Second))
	if d.Mode != Off || d.Policy != "" || d.ID != "" {
		t.Fatalf("after max_age %+v", d)
	}
	// From testing the wait is a day.
	d = Step(Domain{}, on(false), t0)
	d = Step(d, drain, t0.Add(time.Hour))
	d = Step(d, drain, t0.Add(time.Hour+MaxAgeTesting*time.Second))
	if d.Mode != Off {
		t.Fatalf("testing drain %+v", d)
	}
	// Never published: off at once.
	if d := Step(Domain{}, drain, t0); d.Mode != Off {
		t.Fatalf("never published %+v", d)
	}
}

// VPN-only: nothing published; a drain waits max_age from when the policy
// stopped being reachable.
func TestMTASTSUnreachable(t *testing.T) {
	d := Step(Domain{}, on(false), t0)
	hidden := on(false)
	hidden.Reachable = false
	d = Step(d, hidden, t0.Add(time.Hour))
	if d.Mode != Off || d.ID != "" || d.HiddenSince == nil {
		t.Fatalf("unreachable %+v", d)
	}
	drain := Inputs{Mail: "draining", Reachable: false, MX: "mail.example.com"}
	d = Step(d, drain, t0.Add(2*time.Hour))
	if d.Mode != None || d.ID != "" {
		t.Fatalf("drain while hidden %+v", d)
	}
	d = Step(d, drain, t0.Add(time.Hour+MaxAgeTesting*time.Second+time.Hour-time.Second))
	if d.Mode != None {
		t.Fatal("off before max_age from the later of drain start and hidden")
	}
	d = Step(d, drain, t0.Add(2*time.Hour+MaxAgeTesting*time.Second))
	if d.Mode != Off {
		t.Fatalf("not off %+v", d)
	}
	// Reachable again: testing with a new 7-day clock.
	d = Step(Domain{Mode: Off, HiddenSince: &t0}, on(false), t0.Add(3*time.Hour))
	if d.Mode != Testing || !d.Since.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("back %+v", d)
	}
}

// Final review L4: mail off without a drain never drops a published
// policy at once: enforce → testing for the enforce max_age, then off.
func TestOffWithoutDrainDwellsInTesting(t *testing.T) {
	d := Step(Domain{}, on(false), t0)
	d, _ = DoEnforce(d, on(false), t0.Add(8*24*time.Hour))
	off := Inputs{Mail: "off", Reachable: true, MX: "mail.example.com"}
	at := t0.Add(9 * 24 * time.Hour)
	d = Step(d, off, at)
	if d.Mode != Testing || !strings.Contains(d.Policy, "mode: testing") || d.ID == "" {
		t.Fatalf("enforce → off: %+v", d)
	}
	d = Step(d, off, at.Add(MaxAgeEnforce*time.Second-time.Second))
	if d.Mode != Testing {
		t.Fatalf("off before the enforce max_age: %+v", d)
	}
	d = Step(d, off, at.Add(MaxAgeEnforce*time.Second))
	if d.Mode != Off || d.Policy != "" {
		t.Fatalf("after the dwell: %+v", d)
	}
	if d = Step(d, off, at.Add(MaxAgeEnforce*time.Second+time.Hour)); d.Mode != Off {
		t.Fatalf("off stays off: %+v", d)
	}
	// From testing: a day.
	d = Step(Domain{}, on(false), t0)
	d = Step(d, off, t0.Add(time.Hour))
	if d.Mode != Testing {
		t.Fatalf("testing → off at once: %+v", d)
	}
	if d = Step(d, off, t0.Add(time.Hour+MaxAgeTesting*time.Second)); d.Mode != Off {
		t.Fatalf("testing dwell: %+v", d)
	}
	// A drain under way runs to its end.
	d = Step(Domain{}, on(false), t0)
	d = Step(d, Inputs{Mail: "draining", Reachable: true, MX: "mail.example.com"}, t0.Add(time.Hour))
	d = Step(d, off, t0.Add(2*time.Hour))
	if d.Mode != None {
		t.Fatalf("drain then off: %+v", d)
	}
	// Never published: off at once.
	if d := Step(Domain{}, off, t0); d.Mode != Off {
		t.Fatalf("never published: %+v", d)
	}
}
