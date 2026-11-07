package main

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	hubURL    = "https://hub.example.com/mcp"
	peopleURL = "https://people.example.com/mcp"
	mcpURL    = "https://mcp.example.com/mcp"
)

// connectTo: an SDK client on host with a real token.
func (e *testEnv) connectTo(host, tok, version string) (*sdk.ClientSession, error) {
	e.t.Helper()
	c := sdk.NewClient(&sdk.Implementation{Name: "person", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := c.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:   e.srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: &personRT{host: host, token: tok}},
		MaxRetries: -1,
	}, &sdk.ClientSessionOptions{ProtocolVersion: version})
	if err == nil {
		e.t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, err
}

func toolNames(t *testing.T, cs *sdk.ClientSession) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out []string
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, tool.Name)
	}
	slices.Sort(out)
	return out
}

// The Portcullis resources go to the Hub through the gate's pipeline (G25):
// admin tools only with mcp:portcullis.admin AND a client the admin
// resource allows; one access-log line per request with the hub or people
// URL; limits on tools/call.
func TestPortcullisThroughGate(t *testing.T) {
	e := newEnv(t, nil)
	// root, an allowed client, the admin scope → /mcp/admin.
	cs, err := e.connectTo("hub.example.com", e.sig.token("root", hubURL, "mcp:portcullis.admin"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := toolNames(t, cs); !slices.Equal(got, []string{"delete_instance", "list_instances"}) {
		t.Errorf("admin tools %v", got)
	}
	if r := callTool(t, cs, "list_instances", map[string]any{}); text(r) != "hub list_instances" {
		t.Errorf("%+v", r)
	}
	paths, hdrs := e.hub.seenMCP()
	for i, p := range paths {
		if p != "/mcp/admin" || hdrs[i].Get("X-Forwarded-User") != "root" || hdrs[i].Get("X-Portcullis-Ai-Resource") != hubURL ||
			hdrs[i].Get("X-Portcullis-Ai-Client") != "portcullis-ai-claude" || hdrs[i].Get("Authorization") != "" {
			t.Errorf("Hub request %d: %s %v", i, p, hdrs[i])
		}
	}
	n := len(paths)
	// A client the admin resource doesn't allow (portcullis-ai-generic is
	// offered, its admin flag off): 401, the Hub never asked.
	resp := e.raw("POST", "hub.example.com", e.sig.tokenFor("root", hubURL, "mcp:portcullis.admin", "portcullis-ai-generic"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, nil)
	if resp.StatusCode != 401 {
		t.Errorf("generic client on admin: %d", resp.StatusCode)
	}
	// Without the admin scope: 403 insufficient_scope.
	resp = e.raw("POST", "hub.example.com", e.sig.token("root", hubURL, "mcp:portcullis.people"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, nil)
	if resp.StatusCode != 403 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("no admin scope: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	// Not an admin (alice isn't in the admin population): 403.
	resp = e.raw("POST", "hub.example.com", e.sig.token("alice", hubURL, "mcp:portcullis.admin"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, nil)
	if resp.StatusCode != 403 {
		t.Errorf("alice on admin: %d", resp.StatusCode)
	}
	if p, _ := e.hub.seenMCP(); len(p) != n {
		t.Errorf("refused requests reached the Hub")
	}
	// people.<d>/mcp → /mcp/people, delegate tools included there.
	ps, err := e.connectTo("people.example.com", e.sig.token("alice", peopleURL, "mcp:portcullis.people"), "")
	if err != nil {
		t.Fatal(err)
	}
	if got := toolNames(t, ps); !slices.Equal(got, []string{"invite_person", "my_apps"}) {
		t.Errorf("people tools %v", got)
	}
	paths, hdrs = e.hub.seenMCP()
	if last := paths[len(paths)-1]; last != "/mcp/people" || hdrs[len(hdrs)-1].Get("X-Portcullis-Ai-Resource") != peopleURL || hdrs[len(hdrs)-1].Get("X-Forwarded-User") != "alice" {
		t.Errorf("people: %s %v", last, hdrs[len(hdrs)-1])
	}
	// The access log: one line per request naming the hub / people URL.
	var hub, people int
	for _, l := range e.lines() {
		switch l["resource"] {
		case hubURL:
			hub++
			if l["decision"] == "allow" && l["upstream_status"].(float64) != 200 {
				t.Errorf("line %v", l)
			}
			if l["method"] == "tools/call" && (l["tool"] != "list_instances" || l["args_sha256"] == "") {
				t.Errorf("tools/call line %v", l)
			}
		case peopleURL:
			people++
		}
		if l["instance"] != "" || l["via"] != "direct" {
			t.Errorf("line %v", l)
		}
	}
	if hub < 4 || people < 2 {
		t.Errorf("lines: hub %d people %d", hub, people)
	}
	// Final review M1: arguments the gate can't canonicalise (a repeated
	// inner key, an unsafe number) never reach the Hub: 400,
	// deny:bad_arguments.
	for _, args := range []string{`{"a":{"x":1,"x":2}}`, `{"n":12345678901234567890}`} {
		resp := e.raw("POST", "hub.example.com", e.sig.token("root", hubURL, "mcp:portcullis.admin"), `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_instances","arguments":`+args+`}}`, nil)
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d", args, resp.StatusCode)
		}
	}
	if p, _ := e.hub.seenMCP(); len(p) != len(paths) {
		t.Errorf("non-canonical arguments reached the Hub")
	}
	bad := 0
	for _, l := range e.lines() {
		if l["decision"] == "deny:bad_arguments" && l["resource"] == hubURL && l["tool"] == "list_instances" {
			bad++
		}
	}
	if bad != 2 {
		t.Errorf("%d deny:bad_arguments lines, want 2", bad)
	}
}

// Limits apply to the Portcullis resources' tools/call (G25).
func TestPortcullisLimits(t *testing.T) {
	e := newEnv(t, nil)
	sn := *e.sn.Load()
	f := *sn.File
	f.Limits.ToolCallsRPM = 1
	sn.File = &f
	e.sn.Store(&sn)
	cs, err := e.connectTo("people.example.com", e.sig.token("alice", peopleURL, "mcp:portcullis.people"), "2025-11-25")
	if err != nil {
		t.Fatal(err)
	}
	callTool(t, cs, "my_apps", map[string]any{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "my_apps", Arguments: map[string]any{}}); err == nil {
		t.Errorf("second tools/call allowed")
	}
	limited := false
	for _, l := range e.lines() {
		if l["resource"] == peopleURL && l["decision"] == "rate_limited" && l["tool"] == "my_apps" {
			limited = true
		}
	}
	if !limited {
		t.Errorf("no rate_limited line")
	}
}

// The aggregate end to end: a real mcp:all token; companion tools and the
// people tools (not the delegate ones); the upstream's line via aggregate.
func TestAggregateThroughGate(t *testing.T) {
	e := newEnv(t, nil)
	cs, err := e.connectTo("mcp.example.com", e.sig.token("alice", mcpURL, "mcp:all"), "")
	if err != nil {
		t.Fatal(err)
	}
	got := toolNames(t, cs)
	if !slices.Equal(got, []string{"gitea__delete_repo", "gitea__list_issues", "portcullis__my_apps"}) {
		t.Errorf("tools %v", got)
	}
	if r := callTool(t, cs, "gitea__list_issues", map[string]any{"q": argMarker}); text(r) != "ok list_issues" {
		t.Errorf("%+v", r)
	}
	if r := callTool(t, cs, "portcullis__my_apps", map[string]any{}); text(r) != "hub my_apps" {
		t.Errorf("%+v", r)
	}
	paths, _ := e.hub.seenMCP()
	for _, p := range paths {
		if p != "/mcp/people" {
			t.Errorf("the aggregate asked %s", p)
		}
	}
	var call, people bool
	for _, l := range e.lines() {
		if l["method"] == "tools/call" && l["resource"] == giteaURL {
			call = l["via"] == "aggregate" && l["tool"] == "list_issues" && l["instance"] == "gitea" && l["decision"] == "allow"
		}
		if l["method"] == "tools/call" && l["resource"] == peopleURL {
			people = l["via"] == "aggregate" && l["tool"] == "my_apps"
		}
	}
	if !call || !people {
		t.Errorf("lines: companion %v people %v: %v", call, people, e.lines())
	}
	// The companion's token never works here, nor the aggregate's on a
	// companion.
	if resp := e.raw("POST", "mcp.example.com", e.sig.token("alice", giteaURL, "mcp:gitea.gitea"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, nil); resp.StatusCode != 401 {
		t.Errorf("companion token on the aggregate: %d", resp.StatusCode)
	}
	if resp := e.raw("POST", "gitea.example.com", e.sig.token("alice", mcpURL, "mcp:all"), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, nil); resp.StatusCode != 401 {
		t.Errorf("aggregate token on gitea: %d", resp.StatusCode)
	}
}

// §15.8: confirmation_id on the call that consumed the confirmation, only.
func TestConfirmationIDLogged(t *testing.T) {
	e := newEnv(t, nil)
	cs := e.connect("alice")
	callTool(t, cs, "delete_repo", map[string]any{"repo": "x"}) // creates
	e.hub.mu.Lock()
	e.hub.approved = true
	e.hub.mu.Unlock()
	if r := callTool(t, cs, "delete_repo", map[string]any{"repo": "x"}); text(r) != "ok delete_repo" {
		t.Fatalf("%+v", r)
	}
	with := 0
	for _, l := range e.lines() {
		id, ok := l["confirmation_id"]
		if !ok {
			continue
		}
		with++
		if id != confirmID || l["decision"] != "allow" || l["tool"] != "delete_repo" {
			t.Errorf("line %v", l)
		}
	}
	if with != 1 {
		t.Errorf("%d lines with confirmation_id", with)
	}
}
