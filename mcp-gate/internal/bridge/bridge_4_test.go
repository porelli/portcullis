package bridge

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Task 4: how a confirmation reaches the person's client (§15.6), by
// protocol version and declared capability, and the gate's own
// request state on 2026-07-28 retries.

const confURL = "https://people.example.com/confirm/ID"

// scriptConfirmer answers with fn; it records every Call.
type scriptConfirmer struct {
	mu    sync.Mutex
	calls []Call
	fn    func(c Call) Outcome
}

func (s *scriptConfirmer) Before(_ context.Context, c Call) (Outcome, error) {
	s.mu.Lock()
	s.calls = append(s.calls, c)
	fn := s.fn
	s.mu.Unlock()
	return fn(c), nil
}

func (s *scriptConfirmer) list() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

func (s *scriptConfirmer) set(fn func(c Call) Outcome) {
	s.mu.Lock()
	s.fn = fn
	s.mu.Unlock()
}

func newConfirmation(c Call) Outcome {
	return Outcome{
		Answer:   isErrorResult("This needs your confirmation in your browser: open " + confURL + ", then ask me to try again."),
		Decision: "confirm:ID",
		Elicit:   &sdk.ElicitParams{Mode: "url", Message: c.Tool + " on Gitea needs your confirmation in your browser.", URL: confURL, ElicitationID: "ID"},
	}
}

func pending(Call) Outcome {
	return Outcome{Answer: isErrorResult("Still waiting for your confirmation in your browser"), Decision: "deny:pending"}
}

// stateRecorder: a confirm-caught tool that reports the request state and
// input responses it got.
func stateRecorder(u *upstream, s *sdk.Server) {
	s.AddTool(&sdk.Tool{Name: "delete_rec", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		u.called(req.Params.Name)
		return textResult(fmt.Sprintf("state=%q inputs=%d", req.Params.RequestState, len(req.Params.InputResponses))), nil
	})
	// A confirm-caught tool that asks the person something first.
	s.AddTool(&sdk.Tool{Name: "delete_ask", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		u.called(req.Params.Name)
		if req.Params.InputResponses == nil {
			return &sdk.CallToolResult{InputRequests: sdk.InputRequestMap{
				"f": &sdk.ElicitParams{Mode: "form", Message: "sure?", RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}}},
			}, RequestState: "up1"}, nil
		}
		er, _ := req.Params.InputResponses["f"].(*sdk.ElicitResult)
		action := "missing"
		if er != nil {
			action = er.Action
		}
		return textResult("done state=" + req.Params.RequestState + " f=" + action), nil
	})
}

func urlCaps() *sdk.ClientCapabilities {
	return &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{URL: &sdk.URLElicitationCapabilities{}}}
}

func noMRTR(o *sdk.ClientOptions) *sdk.ClientOptions {
	o.MultiRoundTrip = &sdk.MultiRoundTripOptions{Disabled: true}
	return o
}

// TestConfirmationShape: a 2026-07-28 client that declared elicitation.url
// gets an input_required result with exactly one URL-mode elicitation; a
// 2025-11-25 one an elicitation/create request, then the text; every other
// client only the text. Never form mode, never a call.
func TestConfirmationShape(t *testing.T) {
	up := newUpstream(t, nil, stateRecorder)
	sc := &scriptConfirmer{fn: newConfirmation}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = sc })
	textAnswer := "This needs your confirmation in your browser: open " + confURL + ", then ask me to try again."

	// 2026-07-28 + elicitation.url → InputRequiredResult.
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", opts: noMRTR(&sdk.ClientOptions{Capabilities: urlCaps()})})
	r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"})
	if err != nil || !r.NeedsInput() || r.IsError || len(r.Content) != 0 || len(r.InputRequests) != 1 {
		t.Fatalf("2026 url: %+v %v", r, err)
	}
	var key string
	var ep *sdk.ElicitParams
	for k, v := range r.InputRequests {
		key, ep = k, v.(*sdk.ElicitParams)
	}
	if ep == nil || ep.Mode != "url" || ep.URL != confURL || ep.Message != "delete_repo on Gitea needs your confirmation in your browser." || ep.ElicitationID != "ID" || ep.RequestedSchema != nil {
		t.Errorf("elicitation %+v", ep)
	}
	state := r.RequestState
	if !strings.HasPrefix(state, gateStatePrefix) || len(state) < len(gateStatePrefix)+20 {
		t.Errorf("request state %q", state)
	}

	// The retry carries the person's answer: the confirmer gets it.
	sc.set(pending)
	retry := func(st string, action string, args map[string]any) *sdk.CallToolResult {
		t.Helper()
		r, err := cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: "delete_repo", Arguments: args,
			InputResponses: sdk.InputResponseMap{key: &sdk.ElicitResult{Action: action}}, RequestState: st})
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
		return r
	}
	if r := retry(state, "accept", map[string]any{"repo": "x"}); !r.IsError || resultText(r) != "Still waiting for your confirmation in your browser" {
		t.Errorf("accept retry: %+v", r)
	}
	calls := sc.list()
	if last := calls[len(calls)-1]; last.Elicited == nil || last.Elicited.Action != "accept" {
		t.Errorf("confirmer got %+v", last.Elicited)
	}
	// The state is single use: a replay is a fresh call.
	retry(state, "accept", map[string]any{"repo": "x"})
	if last := sc.list()[len(sc.list())-1]; last.Elicited != nil {
		t.Errorf("replayed state accepted: %+v", last.Elicited)
	}
	// Decline / cancel are passed on as such.
	for _, action := range []string{"decline", "cancel"} {
		sc.set(newConfirmation)
		r, _ := call(t, cs, "delete_repo", map[string]any{"repo": "x"})
		sc.set(pending)
		retry(r.RequestState, action, map[string]any{"repo": "x"})
		if last := sc.list()[len(sc.list())-1]; last.Elicited == nil || last.Elicited.Action != action {
			t.Errorf("%s: confirmer got %+v", action, last.Elicited)
		}
	}
	// The state is bound to the arguments: changed ones are a fresh call.
	sc.set(newConfirmation)
	r, _ = call(t, cs, "delete_repo", map[string]any{"repo": "x"})
	sc.set(pending)
	retry(r.RequestState, "accept", map[string]any{"repo": "y"})
	if last := sc.list()[len(sc.list())-1]; last.Elicited != nil {
		t.Errorf("state used for other arguments")
	}
	// A forged gate state never reaches the upstream, nor do the answers
	// that came with it.
	sc.set(func(Call) Outcome { return Outcome{Proceed: true} })
	r, err = cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: "delete_rec", Arguments: map[string]any{},
		InputResponses: sdk.InputResponseMap{"x": &sdk.ElicitResult{Action: "accept"}}, RequestState: gateStatePrefix + "forged"})
	if err != nil || resultText(r) != `state="" inputs=0` {
		t.Errorf("forged state: %v %v", resultTextOr(r), err)
	}
	if last := sc.list()[len(sc.list())-1]; last.Elicited != nil {
		t.Error("forged state accepted")
	}

	// Every other client gets only the text.
	var mu sync.Mutex
	var seen []string
	handler := func(answer string) func(context.Context, *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
		return func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			mu.Lock()
			seen = append(seen, req.Params.Mode+" "+req.Params.URL+" "+req.Params.ElicitationID+" "+req.Params.Message)
			mu.Unlock()
			return &sdk.ElicitResult{Action: answer}, nil
		}
	}
	sc.set(newConfirmation)
	for _, tc := range []struct {
		name    string
		version string
		opts    *sdk.ClientOptions
		elicits bool
	}{
		{"2025-11-25 url accept", "2025-11-25", &sdk.ClientOptions{ElicitationHandler: handler("accept"), Capabilities: urlCaps()}, true},
		{"2025-11-25 url decline", "2025-11-25", &sdk.ClientOptions{ElicitationHandler: handler("decline"), Capabilities: urlCaps()}, true},
		{"2025-11-25 url cancel", "2025-11-25", &sdk.ClientOptions{ElicitationHandler: handler("cancel"), Capabilities: urlCaps()}, true},
		{"2025-11-25 form only", "2025-11-25", &sdk.ClientOptions{ElicitationHandler: handler("accept"), Capabilities: &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{Form: &sdk.FormElicitationCapabilities{}}}}, false},
		{"2025-11-25 none", "2025-11-25", nil, false},
		{"2025-06-18 url", "2025-06-18", &sdk.ClientOptions{ElicitationHandler: handler("accept"), Capabilities: urlCaps()}, false},
		{"2026-07-28 none", "2026-07-28", noMRTR(&sdk.ClientOptions{}), false},
		{"2026-07-28 form only", "2026-07-28", noMRTR(&sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{Form: &sdk.FormElicitationCapabilities{}}}}), false},
	} {
		mu.Lock()
		seen = nil
		mu.Unlock()
		cs, _ := h.connect("alice", clientOpts{version: tc.version, opts: tc.opts})
		r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"})
		if err != nil || r.NeedsInput() || !r.IsError || resultText(r) != textAnswer {
			t.Errorf("%s: %v %v", tc.name, resultTextOr(r), err)
		}
		mu.Lock()
		want := []string(nil)
		if tc.elicits {
			want = []string{"url " + confURL + " ID delete_repo on Gitea needs your confirmation in your browser."}
		}
		if !slices.Equal(seen, want) {
			t.Errorf("%s: client saw %q, want %q", tc.name, seen, want)
		}
		mu.Unlock()
	}
	if _, calls, _ := up.snapshot(); !slices.Equal(calls, []string{"delete_rec"}) {
		t.Errorf("upstream calls %v", calls)
	}
	for _, e := range h.eventList() {
		if e.Tool == "delete_repo" && e.Decision != "confirm:ID" && e.Decision != "deny:pending" {
			t.Errorf("decision %q", e.Decision)
		}
	}
}

// A confirmed 2026-07-28 call whose companion then asks the person
// something continues on the gate's own single-use state: the retry isn't
// confirmed again, and the companion gets its own state back.
func TestConfirmContinuation(t *testing.T) {
	up := newUpstream(t, nil, stateRecorder)
	sc := &scriptConfirmer{fn: func(Call) Outcome { return Outcome{Proceed: true} }}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = sc })
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", opts: noMRTR(&sdk.ClientOptions{Capabilities: urlCaps()})})
	r, err := call(t, cs, "delete_ask", map[string]any{"repo": "x"})
	if err != nil || !r.NeedsInput() || r.InputRequests["f"] == nil {
		t.Fatalf("first: %+v %v", r, err)
	}
	if r.RequestState == "up1" || !strings.HasPrefix(r.RequestState, gateStatePrefix) {
		t.Errorf("the companion's state went down unwrapped: %q", r.RequestState)
	}
	st := r.RequestState
	sc.set(newConfirmation) // any further confirmation would refuse
	again := func() *sdk.CallToolResult {
		r, err := cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: "delete_ask", Arguments: map[string]any{"repo": "x"},
			InputResponses: sdk.InputResponseMap{"f": &sdk.ElicitResult{Action: "accept", Content: map[string]any{"ok": true}}}, RequestState: st})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := again(); resultText(r) != "done state=up1 f=accept" {
		t.Errorf("continued: %q", resultTextOr(r))
	}
	if n := len(sc.list()); n != 1 {
		t.Errorf("confirmer asked %d times", n)
	}
	// Single use: a replay needs a confirmation again.
	if r := again(); !r.NeedsInput() || r.InputRequests["f"] != nil {
		t.Errorf("replay: %+v", r)
	}
	if _, calls, _ := up.snapshot(); !slices.Equal(calls, []string{"delete_ask", "delete_ask"}) {
		t.Errorf("upstream calls %v", calls)
	}
}

// ---- fix round 1 ----

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// A state past its 10 minutes is a fresh call: the person's old answer
// is never applied.
func TestGateStateExpiry(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)}
	up := newUpstream(t, nil, stateRecorder)
	sc := &scriptConfirmer{fn: newConfirmation}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = sc; c.Now = clk.now })
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", opts: noMRTR(&sdk.ClientOptions{Capabilities: urlCaps()})})
	r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"})
	if err != nil || !r.NeedsInput() {
		t.Fatalf("%+v %v", r, err)
	}
	clk.add(gateStateTTL + time.Second)
	if _, err := cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: "delete_repo", Arguments: map[string]any{"repo": "x"},
		InputResponses: sdk.InputResponseMap{confirmInputKey: &sdk.ElicitResult{Action: "accept"}}, RequestState: r.RequestState}); err != nil {
		t.Fatal(err)
	}
	if last := sc.list()[len(sc.list())-1]; last.Elicited != nil {
		t.Errorf("an expired state was applied: %+v", last.Elicited)
	}

	// An expired continuation needs a new confirmation.
	sc.set(func(Call) Outcome { return Outcome{Proceed: true, ConfirmationID: "C1"} })
	r, err = call(t, cs, "delete_ask", map[string]any{"repo": "x"})
	if err != nil || !r.NeedsInput() || r.InputRequests["f"] == nil {
		t.Fatalf("%+v %v", r, err)
	}
	n := len(sc.list())
	clk.add(gateStateTTL + time.Second)
	sc.set(newConfirmation)
	r2, err := cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: "delete_ask", Arguments: map[string]any{"repo": "x"},
		InputResponses: sdk.InputResponseMap{"f": &sdk.ElicitResult{Action: "accept"}}, RequestState: r.RequestState})
	if err != nil || len(sc.list()) != n+1 || r2.InputRequests[confirmInputKey] == nil {
		t.Errorf("expired continuation: %+v %v (confirmer asked %d times)", r2, err, len(sc.list())-n)
	}
	if _, calls, _ := up.snapshot(); len(calls) != 1 {
		t.Errorf("upstream calls %v", calls)
	}
}

// fillStates puts n live states for user straight into the store.
func fillStates(t *testing.T, h *harness, user string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, ok := h.b.states.put(gateState{kind: stateConfirm, user: user, bind: fmt.Sprint(user, i)}, h.b.now()); !ok {
			t.Fatalf("put %s %d refused", user, i)
		}
	}
}

// checkFallbacks: a new confirmation falls back to the text, a confirmed
// call's continuation answers busy; nothing reaches the upstream twice.
func checkFallbacks(t *testing.T, h *harness, sc *scriptConfirmer, cs *sdk.ClientSession) {
	t.Helper()
	sc.set(newConfirmation)
	r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"})
	if err != nil || r.NeedsInput() || !r.IsError || !strings.HasPrefix(resultText(r), "This needs your confirmation in your browser: open ") {
		t.Errorf("confirmation fallback: %+v %v", r, err)
	}
	sc.set(func(Call) Outcome { return Outcome{Proceed: true, ConfirmationID: "C1"} })
	r, err = call(t, cs, "delete_ask", map[string]any{"repo": "x"})
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("continuation fallback: %+v %v", r, err)
	}
}

// Fix round 1: at most maxStatesPerUser live states per person; another
// person's states don't count.
func TestGateStatePerUserCap(t *testing.T) {
	up := newUpstream(t, nil, stateRecorder)
	sc := &scriptConfirmer{fn: newConfirmation}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = sc })
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", opts: noMRTR(&sdk.ClientOptions{Capabilities: urlCaps()})})
	fillStates(t, h, "carol", maxStatesPerUser)
	if _, ok := h.b.states.put(gateState{kind: stateConfirm, user: "carol", bind: "one more"}, h.b.now()); ok {
		t.Error("a 17th state for one person")
	}
	if r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"}); err != nil || !r.NeedsInput() {
		t.Fatalf("someone else's states counted: %+v %v", r, err)
	}
	fillStates(t, h, "alice", maxStatesPerUser-1) // with the one just issued: full
	checkFallbacks(t, h, sc, cs)
	// Expired ones don't count.
	h.b.states.mu.Lock()
	for tok, st := range h.b.states.m {
		if st.user == "alice" {
			st.exp = h.b.now().Add(-time.Second)
			h.b.states.m[tok] = st
		}
	}
	h.b.states.mu.Unlock()
	sc.set(newConfirmation)
	if r, err := call(t, cs, "delete_repo", map[string]any{"repo": "x"}); err != nil || !r.NeedsInput() {
		t.Errorf("expired states counted: %+v %v", r, err)
	}
}

// The whole store full of other people's live states: the same fallbacks.
func TestGateStateStoreFull(t *testing.T) {
	up := newUpstream(t, nil, stateRecorder)
	sc := &scriptConfirmer{fn: newConfirmation}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = sc })
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", opts: noMRTR(&sdk.ClientOptions{Capabilities: urlCaps()})})
	for i := 0; i < maxGateStates; i++ {
		fillStates(t, h, fmt.Sprint("u", i), 1)
	}
	checkFallbacks(t, h, sc, cs)
	if _, calls, _ := up.snapshot(); !slices.Equal(calls, []string{"delete_ask"}) {
		t.Errorf("upstream calls %v", calls)
	}
}

// The 2025-11-25 elicitation/create waits at most 60 s.
func TestElicitWait(t *testing.T) {
	if elicitWait != 60*time.Second {
		t.Errorf("elicitWait %v", elicitWait)
	}
}

// Fix round 1: the consumed confirmation's id is in the events of the
// call that consumed it and of every continuation of that call.
func TestContinuationLogsConfirmation(t *testing.T) {
	up := newUpstream(t, nil, stateRecorder)
	sc := &scriptConfirmer{fn: func(Call) Outcome { return Outcome{Proceed: true, ConfirmationID: "C1"} }}
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) { c.Confirm = sc })
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", opts: noMRTR(&sdk.ClientOptions{Capabilities: urlCaps()})})
	r, err := call(t, cs, "delete_ask", map[string]any{"repo": "x"})
	if err != nil || !r.NeedsInput() {
		t.Fatalf("%+v %v", r, err)
	}
	sc.set(newConfirmation)
	r, err = cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: "delete_ask", Arguments: map[string]any{"repo": "x"},
		InputResponses: sdk.InputResponseMap{"f": &sdk.ElicitResult{Action: "accept"}}, RequestState: r.RequestState})
	if err != nil || resultText(r) != "done state=up1 f=accept" {
		t.Fatalf("%v %v", resultTextOr(r), err)
	}
	var got []string
	for _, e := range h.eventList() {
		if e.Tool == "delete_ask" {
			got = append(got, e.Decision+"/"+e.Confirmation)
		}
	}
	if !slices.Equal(got, []string{"allow/C1", "allow/C1"}) {
		t.Errorf("events %v", got)
	}
}
