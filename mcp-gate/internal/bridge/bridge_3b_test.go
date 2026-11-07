package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Task 3b: the confirmer's decision (confirm:<id>, rate_limited, deny:…)
// is what the access log gets; its error fails closed.
func TestConfirmOutcomeDecision(t *testing.T) {
	up := newUpstream(t, nil, nil)
	fc := &fakeConfirmer{}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = fc })
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"})
	if err != nil || !r.IsError {
		t.Fatalf("pending: %v %v", r, err)
	}
	fc.mu.Lock()
	fc.out = &Outcome{Answer: isErrorResult("Too many confirmations requested; try again later"), Decision: "rate_limited"}
	fc.mu.Unlock()
	if r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"}); err != nil || resultText(r) != "Too many confirmations requested; try again later" {
		t.Fatalf("limited: %v %v", r, err)
	}
	fc.mu.Lock()
	fc.out, fc.err = nil, errors.New("hub down")
	fc.mu.Unlock()
	if r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"}); err != nil || !r.IsError || resultText(r) != "can't check this right now; try again" {
		t.Fatalf("hub down: %v %v", r, err)
	}
	// An Outcome without an answer never proceeds and never sends an
	// empty result.
	fc.mu.Lock()
	fc.out, fc.err = &Outcome{}, nil
	fc.mu.Unlock()
	if r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"}); err != nil || !r.IsError {
		t.Fatalf("empty outcome: %v %v", r, err)
	}
	if _, calls, _ := up.snapshot(); len(calls) != 0 {
		t.Errorf("upstream called: %v", calls)
	}
	want := []string{"confirm:X", "rate_limited", "deny:hub_unavailable", "confirm"}
	if got := h.decisions("tools/call"); !slices.Equal(got, want) {
		t.Errorf("decisions %v, want %v", got, want)
	}
}

// A mint refused by the gate's own mints_per_minute is rate_limited,
// never an anonymous call.
func TestMintRateLimited(t *testing.T) {
	up := newUpstream(t, nil, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	h.minter.fn = func(string, string) error { return fmt.Errorf("gate: %w", ErrRateLimited) }
	cs, _ := h.connect("bob", clientOpts{version: "2025-11-25"})
	r, err := call(t, cs, "list_issues", nil)
	if err != nil || !r.IsError || !strings.Contains(resultText(r), "Too many") {
		t.Fatalf("got %v %v", r, err)
	}
	if hs, _, _ := up.snapshot(); len(hs) != 0 {
		t.Errorf("upstream called %d times", len(hs))
	}
	if got := h.decisions("tools/call"); !slices.Equal(got, []string{"rate_limited"}) {
		t.Errorf("decisions %v", got)
	}
}

// Every forwarded event names the HTTP request it belongs to (the access
// log's one line per request); the id never reaches the upstream.
func TestEventRequestID(t *testing.T) {
	up := newUpstream(t, nil, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := cs.ListTools(ctx10(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := call(t, cs, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range h.eventList() {
		if e.RequestID == "" || !strings.HasPrefix(e.RequestID, "req-") || seen[e.RequestID] {
			t.Errorf("event %s request id %q", e.Method, e.RequestID)
		}
		seen[e.RequestID] = true
	}
	if len(seen) < 2 {
		t.Errorf("events %v", h.eventList())
	}
	hs, _, _ := up.snapshot()
	for _, hd := range hs {
		if hd.Get(RequestIDHeader) != "" {
			t.Fatal("the request id reached the upstream")
		}
	}
}

// Review fix 1: the upstream gets exactly the canonical bytes the gate
// hashed; arguments that can't round-trip are refused before anything.
func TestForwardsCanonicalArguments(t *testing.T) {
	var mu sync.Mutex
	var got []string
	extra := func(u *upstream, s *sdk.Server) {
		s.AddTool(&sdk.Tool{Name: "echo_args", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			mu.Lock()
			got = append(got, string(req.Params.Arguments))
			mu.Unlock()
			return textResult("ok"), nil
		})
	}
	up := newUpstream(t, nil, extra)
	fc := &fakeConfirmer{ok: true}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = fc })
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	for _, raw := range []string{`{"b":1.0,"a":"x","n":1e2}`, `{"n":100,"a":"x","b":1}`, `{"h":"<a&b>"}`} {
		if r, err := call(t, cs, "echo_args", json.RawMessage(raw)); err != nil || r.IsError {
			t.Fatalf("%s: %v %v", raw, r, err)
		}
	}
	// A confirmed call: the confirmer sees the same canonical bytes.
	if r, err := call(t, cs, "delete_repo", json.RawMessage(`{"z":1, "a":2.0}`)); err != nil || r.IsError {
		t.Fatalf("delete_repo: %v %v", r, err)
	}
	mu.Lock()
	if len(got) != 3 || got[0] != `{"a":"x","b":1,"n":100}` || got[1] != got[0] || got[2] != `{"h":"<a&b>"}` {
		t.Errorf("upstream got %q", got)
	}
	mu.Unlock()
	fc.mu.Lock()
	if len(fc.calls) != 1 || string(fc.calls[0].Args) != `{"a":2,"z":1}` {
		t.Errorf("confirmer got %+v", fc.calls)
	}
	fc.mu.Unlock()
	for _, e := range h.eventList() {
		if e.Tool == "echo_args" && string(e.Args) != `{"a":"x","b":1,"n":100}` && string(e.Args) != `{"h":"<a&b>"}` {
			t.Errorf("event args %s", e.Args)
		}
	}
	// U+2028 / U+2029 would be re-escaped by the encoder (not the hashed
	// bytes): refused like precision loss.
	if _, err := call(t, cs, "echo_args", json.RawMessage(`{"h":"\u2028"}`)); err == nil {
		t.Error("U+2028 accepted")
	}
	// Precision loss → bad_arguments, never forwarded.
	if _, err := call(t, cs, "echo_args", json.RawMessage(`{"id":12345678901234567890}`)); err == nil {
		t.Error("a big integer was accepted")
	}
	mu.Lock()
	if len(got) != 3 {
		t.Errorf("forwarded %q", got)
	}
	mu.Unlock()
	if d := h.decisions("tools/call"); d[len(d)-1] != "deny:bad_arguments" {
		t.Errorf("decisions %v", d)
	}
}
