package main

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/portcullis/mcp-gate/internal/config"
)

// statusRT records every HTTP status the person's client gets.
type statusRT struct {
	next     http.RoundTripper
	mu       sync.Mutex
	statuses []int
}

func (s *statusRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := s.next.RoundTrip(r)
	if err == nil {
		s.mu.Lock()
		s.statuses = append(s.statuses, resp.StatusCode)
		s.mu.Unlock()
	}
	return resp, err
}

func (e *testEnv) connectWith(user, version string, opts *sdk.ClientOptions) (*sdk.ClientSession, *statusRT) {
	e.t.Helper()
	tok := e.sig.token(user, giteaURL, "mcp:gitea.gitea")
	rt := &statusRT{next: &personRT{host: "gitea.example.com", token: tok}}
	c := sdk.NewClient(&sdk.Implementation{Name: "person", Version: "1"}, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := c.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: e.srv.URL + "/mcp", HTTPClient: &http.Client{Transport: rt}, MaxRetries: -1},
		&sdk.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		e.t.Fatalf("connect %s: %v", user, err)
	}
	e.t.Cleanup(func() { _ = cs.Close() })
	return cs, rt
}

func (e *testEnv) hubCounts() (creates, consumes int) {
	e.hub.mu.Lock()
	defer e.hub.mu.Unlock()
	return len(e.hub.creates), len(e.hub.consumes)
}

// TestConfirmationShape, end to end against the fake Hub (§15.6): the
// URL elicitation by protocol version, decline / cancel never act, never
// a 401/403, never form mode.
func TestConfirmationShape(t *testing.T) {
	// Many connects at one frozen instant: room in the request limits
	// (the confirmation limit stays the file's).
	e := newEnv(t, func(f *config.File) {
		f.Limits.ResourceBurst, f.Limits.ResourceRPM, f.Limits.PersonRPM = 1000, 1000, 1000
		f.Limits.ConfirmationsPerHour = 100
	})
	urlCaps := &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{URL: &sdk.URLElicitationCapabilities{}}}
	var mu sync.Mutex
	var seen []string
	answer := "accept"
	opts := func() *sdk.ClientOptions {
		return &sdk.ClientOptions{Capabilities: urlCaps, ElicitationHandler: func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, req.Params.Mode+" "+req.Params.URL+" "+req.Params.Message)
			return &sdk.ElicitResult{Action: answer}, nil
		}}
	}
	wantSeen := "url " + peopleConf + " delete_repo on Gitea needs your confirmation in your browser."
	textAnswer := "This needs your confirmation in your browser: open " + peopleConf + ", then ask me to try again."
	args := map[string]any{"repo": "x"}
	var rts []*statusRT

	// 2026-07-28 + elicitation.url: the SDK client answers the
	// InputRequiredResult and retries at once; the Hub says pending.
	cs, rt := e.connectWith("alice", "2026-07-28", opts())
	rts = append(rts, rt)
	e.hub.mu.Lock()
	e.hub.state = "pending" // once something was created
	e.hub.mu.Unlock()
	r := callTool(t, cs, "delete_repo", args)
	if !r.IsError || text(r) != "Still waiting for your confirmation in your browser" {
		t.Errorf("2026 accept: %q", text(r))
	}
	if c, n := e.hubCounts(); c != 1 || n != 2 {
		t.Errorf("2026 accept: %d creates, %d consumes", c, n)
	}
	mu.Lock()
	if !slices.Equal(seen, []string{wantSeen}) {
		t.Errorf("2026: client saw %q", seen)
	}
	seen = nil
	mu.Unlock()
	e.hub.mu.Lock()
	e.hub.state = ""
	e.hub.mu.Unlock()

	// Decline / cancel: no call, and the retry doesn't even ask the Hub.
	for _, a := range []string{"decline", "cancel"} {
		mu.Lock()
		answer = a
		mu.Unlock()
		c0, n0 := e.hubCounts()
		r := callTool(t, cs, "delete_repo", args)
		if !r.IsError || text(r) != "You cancelled the confirmation; nothing was done" {
			t.Errorf("2026 %s: %q", a, text(r))
		}
		if c, n := e.hubCounts(); c != c0+1 || n != n0+1 {
			t.Errorf("2026 %s: %d creates, %d consumes after %d, %d", a, c, n, c0, n0)
		}
	}

	// 2025-11-25 + elicitation.url: elicitation/create, then the text,
	// whatever the person answers.
	for _, a := range []string{"accept", "decline", "cancel"} {
		mu.Lock()
		seen, answer = nil, a
		mu.Unlock()
		cs, rt := e.connectWith("alice", "2025-11-25", opts())
		rts = append(rts, rt)
		if r := callTool(t, cs, "delete_repo", args); !r.IsError || text(r) != textAnswer {
			t.Errorf("2025-11-25 %s: %q", a, text(r))
		}
		mu.Lock()
		if !slices.Equal(seen, []string{wantSeen}) {
			t.Errorf("2025-11-25 %s: client saw %q", a, seen)
		}
		mu.Unlock()
	}

	// No URL capability (or 2025-06-18): exactly the text.
	mu.Lock()
	seen, answer = nil, "accept"
	mu.Unlock()
	for _, v := range []string{"2025-06-18", "2025-11-25", "2026-07-28"} {
		for _, o := range []*sdk.ClientOptions{nil, {Capabilities: &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{Form: &sdk.FormElicitationCapabilities{}}}, ElicitationHandler: opts().ElicitationHandler}} {
			cs, rt := e.connectWith("alice", v, o)
			rts = append(rts, rt)
			if r := callTool(t, cs, "delete_repo", args); !r.IsError || text(r) != textAnswer {
				t.Errorf("%s without url: %q", v, text(r))
			}
		}
	}
	cs, rt = e.connectWith("alice", "2025-06-18", opts())
	rts = append(rts, rt)
	if r := callTool(t, cs, "delete_repo", args); !r.IsError || text(r) != textAnswer {
		t.Errorf("2025-06-18 with url: %q", text(r))
	}
	mu.Lock()
	if len(seen) != 0 {
		t.Errorf("elicitations without the capability: %q", seen)
	}
	mu.Unlock()

	// Approved → the next call acts once.
	e.hub.mu.Lock()
	e.hub.approved = true
	e.hub.mu.Unlock()
	if r := callTool(t, cs, "delete_repo", args); r.IsError || text(r) != "ok delete_repo" {
		t.Errorf("approved: %q", text(r))
	}
	if got := e.comp.callList(); !slices.Equal(got, []string{"delete_repo"}) {
		t.Errorf("upstream calls %v", got)
	}
	for _, rt := range rts {
		rt.mu.Lock()
		for _, s := range rt.statuses {
			if s == 401 || s == 403 {
				t.Errorf("HTTP %d to the client", s)
			}
		}
		rt.mu.Unlock()
	}
	var ds []string
	for _, l := range e.lines() {
		if l["method"] == "tools/call" {
			ds = append(ds, l["decision"].(string))
		}
	}
	if !slices.Contains(ds, "confirm:"+confirmID) || !slices.Contains(ds, "deny:pending") || !slices.Contains(ds, "deny:declined") || ds[len(ds)-1] != "allow" {
		t.Errorf("decisions %v", ds)
	}
}

// The 11th confirmation in an hour: refused by the gate before the Hub is
// asked, logged rate_limited.
func TestConfirmRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	cs := e.connect("alice")
	for i := 0; i < 11; i++ {
		r := callTool(t, cs, "delete_repo", map[string]any{"repo": strings.Repeat("x", i+1)})
		want := "This needs your confirmation in your browser: open " + peopleConf + ", then ask me to try again."
		if i == 10 {
			want = "Too many confirmations requested; try again later"
		}
		if !r.IsError || text(r) != want {
			t.Errorf("call %d: %q", i+1, text(r))
		}
	}
	if c, _ := e.hubCounts(); c != 10 {
		t.Errorf("%d confirmations created", c)
	}
	var ds []string
	for _, l := range e.lines() {
		if l["method"] == "tools/call" {
			ds = append(ds, l["decision"].(string))
		}
	}
	if len(ds) != 11 || ds[0] != "confirm:"+confirmID || ds[10] != "rate_limited" {
		t.Errorf("decisions %v", ds)
	}
}
