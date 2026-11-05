package confirm

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/mcp-gate/internal/bridge"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/hubapi"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

func TestArgsDigestCanonical(t *testing.T) {
	d := func(s string) string {
		t.Helper()
		var raw json.RawMessage
		if s != "" {
			raw = json.RawMessage(s)
		}
		h, err := ArgsDigest(raw)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if len(h) != 64 || strings.ToLower(h) != h {
			t.Fatalf("not lowercase hex: %q", h)
		}
		return h
	}
	a := d(`{"b":1,"a":"é"}`)
	if b := d(`{"a":"é","b":1.0}`); a != b {
		t.Error("canonical forms differ")
	}
	if c := d(`{"a":"é","b":2}`); a == c {
		t.Error("changed arguments, same digest")
	}
	empty := d(`{}`)
	if d(`null`) != empty || d(``) != empty || d(" null ") != empty {
		t.Error("absent / null arguments are not {}")
	}
	// sha256("{}")
	if empty != "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a" {
		t.Errorf("{} digest %s", empty)
	}
	if _, err := ArgsDigest(json.RawMessage(`{"a":`)); err == nil {
		t.Error("broken JSON digested")
	}
}

func TestPreview(t *testing.T) {
	p, err := Preview(json.RawMessage(`{"b":1,"a":"x"}`))
	if err != nil || p != `{"a":"x","b":1}` {
		t.Errorf("%q %v", p, err)
	}
	if p, _ := Preview(nil); p != "{}" {
		t.Errorf("nil: %q", p)
	}
	// Never truncated: too long is an error (review fix 2).
	long := `{"a":"` + strings.Repeat("é", 3000) + `"}`
	if p, err = Preview(json.RawMessage(long)); err == nil {
		t.Errorf("clipped preview %d bytes", len(p))
	}
}

type fakeHub struct {
	mu       sync.Mutex
	creates  []hubapi.ConfirmRequest
	consumes []hubapi.ConsumeRequest
	state    string // the consume answer
	consErr  error
	createID string
	url      string
	crErr    error
}

func (f *fakeHub) CreateConfirmation(_ context.Context, r hubapi.ConfirmRequest) (*hubapi.Confirmation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, r)
	if f.crErr != nil {
		return nil, f.crErr
	}
	u := f.url
	if u == "" {
		u = "https://people.example.com/confirm/" + f.createID
	}
	return &hubapi.Confirmation{ID: f.createID, URL: u, ExpiresAt: time.Now().Add(10 * time.Minute)}, nil
}

func (f *fakeHub) ConsumeConfirmation(_ context.Context, r hubapi.ConsumeRequest) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.consumes = append(f.consumes, r)
	if f.consErr != nil {
		return "", "", f.consErr
	}
	if f.state == hubapi.StateConsumed {
		return f.createID, f.state, nil
	}
	return "", f.state, nil
}

type lim struct{ n, max int }

func (l *lim) AllowConfirm(string) bool { l.n++; return l.n <= l.max }

func setup(t *testing.T) (*Gate, *fakeHub, *lim, bridge.Call) {
	snap := &config.Snapshot{File: &config.File{MainDomain: "example.com"}}
	h := &fakeHub{state: hubapi.StateNone, createID: "7Q2M-K7WX-ABCD-EFGH-IJKL-MNOP-QR"}
	l := &lim{max: 10}
	g := &Gate{Hub: h, Limits: l, Snapshot: func() *config.Snapshot { return snap }}
	res := &config.Resource{URL: "https://gitea.example.com/mcp", Label: "Gitea", Kind: config.KindCompanion}
	return g, h, l, bridge.Call{User: "alice", Client: "portcullis-ai-claude", Resource: res, Tool: "delete_repo", Args: json.RawMessage(`{"repo":"x","b":1}`), Reason: "confirm"}
}

func text(r *mcp.CallToolResult) string {
	if r == nil || len(r.Content) != 1 {
		return ""
	}
	if tc, ok := r.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestConfirmBinding(t *testing.T) {
	g, h, _, c := setup(t)
	ctx := context.Background()
	digest, _ := ArgsDigest(c.Args)

	// First call: no approved one → a new confirmation; never proceeds.
	out, err := g.Before(ctx, c)
	if err != nil || out.Proceed || out.Answer == nil || !out.Answer.IsError {
		t.Fatalf("first: %+v %v", out, err)
	}
	if got := text(out.Answer); got != "This needs your confirmation in your browser: open https://people.example.com/confirm/7Q2M-K7WX-ABCD-EFGH-IJKL-MNOP-QR, then ask me to try again." {
		t.Errorf("text %q", got)
	}
	if out.Decision != "confirm:7Q2M-K7WX-ABCD-EFGH-IJKL-MNOP-QR" {
		t.Errorf("decision %q", out.Decision)
	}
	if len(h.consumes) != 1 || h.consumes[0] != (hubapi.ConsumeRequest{User: "alice", Resource: c.Resource.URL, Tool: "delete_repo", ArgsSHA256: digest}) {
		t.Errorf("consume %+v", h.consumes)
	}
	want := hubapi.ConfirmRequest{User: "alice", Client: "portcullis-ai-claude", Resource: c.Resource.URL, Tool: "delete_repo", ArgsSHA256: digest, ArgsPreview: `{"b":1,"repo":"x"}`, Reason: "confirm"}
	if len(h.creates) != 1 || h.creates[0] != want {
		t.Errorf("create %+v", h.creates)
	}

	// Approved → consumed → proceed.
	h.state = hubapi.StateConsumed
	out, err = g.Before(ctx, c)
	if err != nil || !out.Proceed || out.Decision != "" {
		t.Errorf("consumed: %+v %v", out, err)
	}
	if len(h.creates) != 1 {
		t.Error("a confirmation was created for an approved call")
	}

	// Pending / declined.
	h.state = hubapi.StatePending
	out, _ = g.Before(ctx, c)
	if out.Proceed || text(out.Answer) != "Still waiting for your confirmation in your browser" || out.Decision != "deny:pending" || !out.Answer.IsError {
		t.Errorf("pending: %+v", out)
	}
	h.state = hubapi.StateDeclined
	out, _ = g.Before(ctx, c)
	if out.Proceed || text(out.Answer) != "You declined this in your browser" || out.Decision != "deny:declined" {
		t.Errorf("declined: %+v", out)
	}

	// Changed arguments → a different binding.
	h.state = hubapi.StateNone
	c2 := c
	c2.Args = json.RawMessage(`{"repo":"y","b":1}`)
	_, _ = g.Before(ctx, c2)
	if h.creates[len(h.creates)-1].ArgsSHA256 == digest {
		t.Error("changed arguments kept the digest")
	}
	// The destructive reason is passed on.
	c3 := c
	c3.Reason = "destructive"
	_, _ = g.Before(ctx, c3)
	if h.creates[len(h.creates)-1].Reason != "destructive" {
		t.Error("reason not passed")
	}
}

// G26: Hub errors fail closed (the bridge answers "can't check this right
// now" and never calls the upstream).
func TestConfirmFailClosed(t *testing.T) {
	ctx := context.Background()
	for name, mut := range map[string]func(h *fakeHub){
		"consume unavailable": func(h *fakeHub) { h.consErr = hubapi.ErrUnavailable },
		"create unavailable":  func(h *fakeHub) { h.crErr = hubapi.ErrUnavailable },
		"foreign url":         func(h *fakeHub) { h.url = "https://evil.example/confirm/x" },
		"hub url":             func(h *fakeHub) { h.url = "https://hub.example.com/confirm/" + h.createID },
		"other id":            func(h *fakeHub) { h.url = "https://people.example.com/confirm/AAAA" },
		"unknown state":       func(h *fakeHub) { h.state = "weird" },
	} {
		g, h, _, c := setup(t)
		mut(h)
		out, err := g.Before(ctx, c)
		if err == nil || out.Proceed {
			t.Errorf("%s: %+v %v", name, out, err)
		}
	}
	g, _, _, c := setup(t)
	c.Args = json.RawMessage(`{"a":`)
	if out, err := g.Before(ctx, c); err == nil || out.Proceed {
		t.Error("broken arguments proceeded")
	}
	g.Snapshot = func() *config.Snapshot { return nil }
	if out, err := g.Before(ctx, c); err == nil || out.Proceed {
		t.Error("no snapshot proceeded")
	}
}

func TestConfirmRateLimit(t *testing.T) {
	g, h, l, c := setup(t)
	ctx := context.Background()
	l.max = 0
	out, err := g.Before(ctx, c)
	if err != nil || out.Proceed || text(out.Answer) != "Too many confirmations requested; try again later" || out.Decision != "rate_limited" {
		t.Errorf("gate limit: %+v %v", out, err)
	}
	if len(h.creates) != 0 {
		t.Error("the Hub was asked past the gate's limit")
	}
	// An approved retry is never rate limited.
	h.state = hubapi.StateConsumed
	if out, _ := g.Before(ctx, c); !out.Proceed {
		t.Error("consumed retry refused by the limit")
	}
	// The Hub's own limit.
	h.state = hubapi.StateNone
	l.max = 100
	h.crErr = hubapi.ErrTooMany
	out, err = g.Before(ctx, c)
	if err != nil || text(out.Answer) != "Too many confirmations requested; try again later" || out.Decision != "rate_limited" {
		t.Errorf("hub limit: %+v %v", out, err)
	}
	// Not in the population (re-checked by the Hub).
	h.crErr = hubapi.ErrNotAllowed
	out, err = g.Before(ctx, c)
	if err != nil || out.Proceed || out.Decision != "deny:population" || !out.Answer.IsError {
		t.Errorf("not allowed: %+v %v", out, err)
	}
}

// Review fix 2: arguments whose canonical form exceeds the preview are
// never confirmed with a truncated preview: the call fails, the Hub is
// never asked.
func TestConfirmTooLong(t *testing.T) {
	g, h, _, c := setup(t)
	c.Args = json.RawMessage(`{"a":"` + strings.Repeat("x", 4090) + `"}`)
	out, err := g.Before(context.Background(), c)
	if err != nil || out.Proceed || text(out.Answer) != "these arguments are too long to confirm safely" || !out.Answer.IsError || out.Decision != "deny:too_long" {
		t.Fatalf("%+v %v", out, err)
	}
	if len(h.creates) != 0 || len(h.consumes) != 0 {
		t.Error("the Hub was asked")
	}
	// Exactly 4096 bytes is fine and is the whole preview.
	c.Args = json.RawMessage(`{"a":"` + strings.Repeat("x", 4096-8) + `"}`)
	out, err = g.Before(context.Background(), c)
	if err != nil || len(h.creates) != 1 || len(h.creates[0].ArgsPreview) != 4096 {
		t.Fatalf("4096: %+v %v", out, err)
	}
	if _, err := Preview(json.RawMessage(`{"a":"` + strings.Repeat("x", 5000) + `"}`)); err == nil {
		t.Error("Preview clipped instead of refusing")
	}
}

// Fix round 1: the Hub refusing to confirm (400) or not knowing the
// resource (404) is final, never the transient "try again".
func TestConfirmNotConfirmable(t *testing.T) {
	for err, dec := range map[error]string{hubapi.ErrNotConfirmable: "deny:not_confirmable", hubapi.ErrUnknownResource: "deny:off"} {
		g, h, _, c := setup(t)
		h.crErr = err
		out, e := g.Before(context.Background(), c)
		if e != nil || out.Proceed || out.Answer == nil || !out.Answer.IsError || text(out.Answer) != "Portcullis can't confirm this tool" || out.Decision != dec {
			t.Errorf("%v: %+v %v", err, out, e)
		}
	}
}
