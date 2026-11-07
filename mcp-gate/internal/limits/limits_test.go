package limits

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/mcp-gate/internal/config"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTest(l config.Limits) (*Limiter, *clock) {
	c := &clock{t: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)}
	return New(func() config.Limits { return l }, c.now), c
}

const res = "https://gitea.example.com/mcp"

// 120 per minute per person and resource: the 121st within a minute is
// refused even though the burst bucket (2/s, 30) would allow it.
func TestResourcePerMinute(t *testing.T) {
	l, c := newTest(Defaults)
	for i := 0; i < 120; i++ {
		if ok, _ := l.Allow("alice", res, false); !ok {
			t.Fatalf("request %d refused", i+1)
		}
		c.add(400 * time.Millisecond)
	}
	ok, ra := l.Allow("alice", res, false)
	if ok {
		t.Fatal("121st request in a minute allowed")
	}
	// The first request was at 0 s, now is 48 s: a slot frees at 60 s.
	if ra != 12*time.Second {
		t.Errorf("retry after %v, want 12s", ra)
	}
	// Bob and another resource are unaffected.
	if ok, _ := l.Allow("bob", res, false); !ok {
		t.Error("bob refused")
	}
	if ok, _ := l.Allow("alice", "https://grafana.example.com/mcp", false); !ok {
		t.Error("another resource refused")
	}
	c.add(12 * time.Second)
	if ok, _ := l.Allow("alice", res, false); !ok {
		t.Error("still refused after Retry-After")
	}
}

func TestBurst(t *testing.T) {
	l, c := newTest(Defaults)
	for i := 0; i < 30; i++ {
		if ok, _ := l.Allow("alice", res, false); !ok {
			t.Fatalf("burst request %d refused", i+1)
		}
	}
	ok, ra := l.Allow("alice", res, false)
	if ok || ra <= 0 || ra > time.Second {
		t.Fatalf("31st at once: ok=%v retry %v", ok, ra)
	}
	c.add(ra)
	if ok, _ := l.Allow("alice", res, false); !ok {
		t.Error("refused after the bucket refilled")
	}
}

func TestToolCallsPerMinute(t *testing.T) {
	l, c := newTest(Defaults)
	for i := 0; i < 60; i++ {
		if ok, _ := l.Allow("alice", res, true); !ok {
			t.Fatalf("tool call %d refused", i+1)
		}
		c.add(500 * time.Millisecond)
	}
	if ok, ra := l.Allow("alice", res, true); ok || ra <= 0 {
		t.Fatalf("61st tool call allowed (%v)", ra)
	}
	// Other requests to the resource still pass; a refused call consumed
	// nothing.
	if ok, _ := l.Allow("alice", res, false); !ok {
		t.Error("a list after the tool-call limit refused")
	}
}

func TestPersonAcrossResources(t *testing.T) {
	l, c := newTest(Defaults)
	for i := 0; i < 600; i++ {
		r := fmt.Sprintf("https://app%d.example.com/mcp", i%5)
		if ok, _ := l.Allow("alice", r, false); !ok {
			t.Fatalf("request %d refused", i+1)
		}
		c.add(80 * time.Millisecond)
	}
	if ok, ra := l.Allow("alice", "https://app9.example.com/mcp", false); ok || ra <= 0 {
		t.Fatalf("601st across resources allowed (%v)", ra)
	}
	if ok, _ := l.Allow("bob", "https://app9.example.com/mcp", false); !ok {
		t.Error("bob refused")
	}
}

// A refusal consumes nothing: requests refused by the person limit don't
// count against the resource windows.
func TestRefusalConsumesNothing(t *testing.T) {
	lim := Defaults
	lim.PersonRPM = 5
	l, c := newTest(lim)
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("alice", res, true); !ok {
			t.Fatal("refused early")
		}
	}
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow("alice", res, true); ok {
			t.Fatal("over the person limit")
		}
	}
	c.add(61 * time.Second)
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("alice", res, true); !ok {
			t.Fatalf("refusals were counted: %d", i)
		}
	}
}

func TestConfirmAndMint(t *testing.T) {
	l, c := newTest(Defaults)
	for i := 0; i < 10; i++ {
		if !l.AllowConfirm("alice") {
			t.Fatalf("confirmation %d refused", i+1)
		}
		c.add(time.Minute)
	}
	if l.AllowConfirm("alice") {
		t.Error("11th confirmation in an hour allowed")
	}
	if !l.AllowConfirm("bob") {
		t.Error("bob refused")
	}
	c.add(51 * time.Minute)
	if !l.AllowConfirm("alice") {
		t.Error("refused after the hour")
	}
	for i := 0; i < 10; i++ {
		if !l.AllowMint("alice") {
			t.Fatalf("mint %d refused", i+1)
		}
	}
	if l.AllowMint("alice") {
		t.Error("11th mint in a minute allowed")
	}
	c.add(time.Minute + time.Second)
	if !l.AllowMint("alice") {
		t.Error("mint refused after a minute")
	}
}

// Limits follow the file: a lower value applies at once.
func TestLimitsFollowTheFile(t *testing.T) {
	cur := Defaults
	var mu sync.Mutex
	c := &clock{t: time.Unix(0, 0)}
	l := New(func() config.Limits { mu.Lock(); defer mu.Unlock(); return cur }, c.now)
	for i := 0; i < 10; i++ {
		l.Allow("alice", res, true)
		c.add(time.Second)
	}
	mu.Lock()
	cur.ToolCallsRPM = 10
	mu.Unlock()
	if ok, _ := l.Allow("alice", res, true); ok {
		t.Error("the lowered tool-call limit was ignored")
	}
}

func TestSweepForgetsIdle(t *testing.T) {
	l, c := newTest(Defaults)
	for i := 0; i < 50; i++ {
		l.Allow(fmt.Sprintf("u%d", i), res, true)
		l.AllowConfirm(fmt.Sprintf("u%d", i))
	}
	c.add(2 * time.Hour)
	l.Allow("alice", res, false)
	if n := l.size(); n > 2 {
		t.Errorf("%d entries kept after two idle hours", n)
	}
}

func TestConcurrent(t *testing.T) {
	l, _ := newTest(Defaults)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if a, _ := l.Allow("alice", res, false); a {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 30 {
		t.Errorf("%d allowed at once, want the burst of 30", ok)
	}
}
