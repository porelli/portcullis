package dmarc

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func TestDMARCStart(t *testing.T) {
	if Start("reject", t0).Policy != Reject || Start("none", t0).Policy != None {
		t.Fatal("start")
	}
	if Proposed(Start("reject", t0), t0.Add(100*24*time.Hour)) != "" {
		t.Fatal("reject proposes something")
	}
}

func TestDMARCPromote14Days(t *testing.T) {
	d := Start("none", t0)
	if Proposed(d, t0.Add(13*24*time.Hour)) != "" {
		t.Fatal("proposal before 14 days")
	}
	d = Observe(d, []Report{{End: t0.Add(10 * 24 * time.Hour), Failing: true}, {End: t0.Add(12 * 24 * time.Hour)}})
	if Proposed(d, t0.Add(20*24*time.Hour)) != "" {
		t.Fatal("a failure at day 10 must restart the 14 days")
	}
	if Proposed(d, t0.Add(24*24*time.Hour)) != Quarantine {
		t.Fatal("no quarantine proposal 14 days after the last failure")
	}
	if _, err := Promote(Start("none", t0), t0); err == nil {
		t.Fatal("promote without a proposal")
	}
	d, err := Promote(d, t0.Add(24*24*time.Hour))
	if err != nil || d.Policy != Quarantine {
		t.Fatalf("promote %+v %v", d, err)
	}
	if Proposed(d, t0.Add(38*24*time.Hour)) != Reject {
		t.Fatal("no reject proposal 14 days later")
	}
}
