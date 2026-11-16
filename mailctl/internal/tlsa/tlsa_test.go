package tlsa

import (
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/state"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func TestTLSAOnlyWhenSecure(t *testing.T) {
	st, _ := Update(state.TLSAState{}, "aa", "", t0)
	if len(Wanted(st, false)) != 0 {
		t.Fatal("published without secure")
	}
	if w := Wanted(st, true); len(w) != 1 || w[0] != "aa" {
		t.Fatalf("secure: %v", w)
	}
}

func TestTLSARollover(t *testing.T) {
	st, sw := Update(state.TLSAState{}, "aa", "", t0)
	if sw {
		t.Fatal("switch without a next key")
	}
	st, sw = Update(st, "aa", "bb", t0.Add(time.Hour))
	if sw || len(Wanted(st, true)) != 2 {
		t.Fatalf("both published, no switch yet: %v %v", Wanted(st, true), sw)
	}
	_, sw = Update(st, "aa", "bb", t0.Add(time.Hour+SwitchAfter-time.Second))
	if sw {
		t.Fatal("switch before 2×TTL + 1 day")
	}
	st, sw = Update(st, "aa", "bb", t0.Add(time.Hour+SwitchAfter))
	if !sw {
		t.Fatal("no switch after 2×TTL + 1 day")
	}
	// mail-cert switched: current bb, the old aa stays 2×TTL.
	at := t0.Add(2*time.Hour + SwitchAfter)
	st, _ = Update(st, "bb", "", at)
	if w := Wanted(st, true); len(w) != 2 || w[0] != "bb" || w[1] != "aa" {
		t.Fatalf("after the switch %v", w)
	}
	st, _ = Update(st, "bb", "", at.Add(DropOldAfter))
	if w := Wanted(st, true); len(w) != 1 || w[0] != "bb" {
		t.Fatalf("old not dropped %v", w)
	}
}
