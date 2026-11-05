package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/portcullis/mcp-gate/internal/accesslog"
	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/confirm"
	"github.com/portcullis/mcp-gate/internal/hubapi"
	"github.com/portcullis/mcp-gate/internal/limits"
)

const (
	hubSecret  = "test-hub-secret-0123456789abcdefghijkl"
	aliceCred  = "alice-cred-MARKER-1"
	bobCred    = "bob-cred-MARKER-2"
	argMarker  = "argument-value-MARKER-3"
	giteaAddr  = "portcullis-mcp-gitea--gitea:8080"
	confirmID  = "7Q2M-K7WX-ABCD-EFGH-IJKL-MNOP-QR"
	giteaURL   = "https://gitea.example.com/mcp"
	peopleConf = "https://people.example.com/confirm/" + confirmID
)

// frozen is the limiter's clock in the end-to-end tests.
var frozen = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)

// signer issues real RS256 tokens the gate's verifier accepts.
type signer struct {
	jwks *httptest.Server
	sg   jose.Signer
}

func newSigner(t *testing.T) *signer {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	set, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }))
	t.Cleanup(jwks.Close)
	sg, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	return &signer{jwks: jwks, sg: sg}
}

func (s *signer) token(user, aud, scope string) string {
	n := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://auth.example.com/realms/portcullis", "aud": aud,
		"azp": "portcullis-ai-claude", "typ": "Bearer", "scope": scope, "acr": "hwk",
		"preferred_username": user, "exp": n.Add(5 * time.Minute).Unix(), "iat": n.Unix(),
	})
	obj, _ := s.sg.Sign(claims)
	tok, _ := obj.CompactSerialize()
	return tok
}

// fakeHub: the Hub's internal API (Task 13 builds the real one).
type fakeHub struct {
	srv *httptest.Server
	sn  *atomic.Pointer[config.Snapshot]

	mu        sync.Mutex
	mints     []map[string]any
	creates   []map[string]any
	consumes  []map[string]any
	approved  bool
	state     string // "pending" / "declined": the consume answer when not approved
	badSecret int
}

func newFakeHub(t *testing.T, sn *atomic.Pointer[config.Snapshot]) *fakeHub {
	h := &fakeHub{sn: sn}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Portcullis-MCP-Secret")), []byte(hubSecret)) != 1 {
			h.mu.Lock()
			h.badSecret++
			h.mu.Unlock()
			w.WriteHeader(401)
			return
		}
		var body map[string]any
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&body); err != nil {
			w.WriteHeader(400)
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		switch r.URL.Path {
		case "/internal/credentials":
			h.mints = append(h.mints, body)
			// The Hub writes the entry to the file, then answers.
			next := *h.sn.Load()
			creds := map[config.CredKey]config.Cred{}
			for k, v := range next.Creds {
				creds[k] = v
			}
			creds[config.CredKey{Instance: "gitea", Companion: "gitea", User: body["user"].(string)}] = config.Cred{ID: "8", Secret: bobCred}
			next.Creds = creds
			h.sn.Store(&next)
			_, _ = io.WriteString(w, `{"id":"8"}`)
		case "/internal/confirmations":
			h.creates = append(h.creates, body)
			w.WriteHeader(201)
			_, _ = fmt.Fprintf(w, `{"id":%q,"url":%q,"expires_at":%q}`, confirmID, peopleConf, time.Now().Add(10*time.Minute).UTC().Format(time.RFC3339))
		case "/internal/confirmations/consume":
			h.consumes = append(h.consumes, body)
			if h.approved {
				h.approved = false // single use
				_, _ = fmt.Fprintf(w, `{"id":%q}`, confirmID)
				return
			}
			if h.state != "" && (h.state != "pending" || len(h.creates) > 0) {
				w.WriteHeader(409)
				_, _ = fmt.Fprintf(w, `{"state":%q}`, h.state)
				return
			}
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// fakeCompanion: an SDK server recording headers and tool calls.
type fakeCompanion struct {
	srv     *httptest.Server
	mu      sync.Mutex
	headers []http.Header
	calls   []string
}

func newFakeCompanion(t *testing.T) *fakeCompanion {
	c := &fakeCompanion{}
	s := sdk.NewServer(&sdk.Implementation{Name: "gitea-mcp", Version: "1"}, nil)
	for _, n := range []string{"list_issues", "delete_repo"} {
		s.AddTool(&sdk.Tool{Name: n, InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			c.mu.Lock()
			c.calls = append(c.calls, req.Params.Name)
			c.mu.Unlock()
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok " + req.Params.Name}}}, nil
		})
	}
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{DisableLocalhostProtection: true})
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.headers = append(c.headers, r.Header.Clone())
		c.mu.Unlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeCompanion) callList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

type testEnv struct {
	t       *testing.T
	sn      atomic.Pointer[config.Snapshot]
	sig     *signer
	hub     *fakeHub
	comp    *fakeCompanion
	g       *gate
	srv     *httptest.Server
	logPath string
}

func newEnv(t *testing.T, mut func(f *config.File)) *testEnv {
	e := &testEnv{t: t, sig: newSigner(t)}
	sn := vectorSnapshot(t)
	if mut != nil {
		mut(sn.File)
		b, _ := sn.File.Encode()
		f, err := config.DecodeFile(b)
		if err != nil {
			t.Fatal(err)
		}
		sn.File = f
	}
	sn.Creds = map[config.CredKey]config.Cred{{Instance: "gitea", Companion: "gitea", User: "alice"}: {ID: "7", Secret: aliceCred}}
	e.sn.Store(sn)
	e.hub = newFakeHub(t, &e.sn)
	e.comp = newFakeCompanion(t)
	compAddr := e.comp.srv.Listener.Addr().String()
	base := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != giteaAddr {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			return (&net.Dialer{}).DialContext(ctx, network, compAddr)
		},
	}
	hub, err := hubapi.New(e.hub.srv.URL, hubSecret)
	if err != nil {
		t.Fatal(err)
	}
	e.logPath = filepath.Join(t.TempDir(), "data", "access.jsonl")
	e.g, err = newGate(gateOptions{
		Snapshot:  e.sn.Load,
		Verifier:  authz.NewVerifier("", e.sig.jwks.URL, e.sig.jwks.Client()),
		Hub:       hub,
		HubSecret: hubSecret,
		LogPath:   e.logPath,
		LogGroup:  os.Getgid(),
		Base:      base,
		Now:       func() time.Time { return frozen }, // limits never depend on real time
		MintWait:  3 * time.Second,
		MintPoll:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.g.Close)
	e.srv = httptest.NewServer(e.g.handler)
	t.Cleanup(e.srv.Close)
	return e
}

// personRT is the person's MCP client transport: the resource's Host and
// a real access token.
type personRT struct {
	host, token string
}

func (p *personRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = p.host
	r.Header.Set("Authorization", "Bearer "+p.token)
	return http.DefaultTransport.RoundTrip(r)
}

func (e *testEnv) connect(user string) *sdk.ClientSession {
	e.t.Helper()
	tok := e.sig.token(user, giteaURL, "mcp:gitea.gitea")
	c := sdk.NewClient(&sdk.Implementation{Name: "person", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := c.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:   e.srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: &personRT{host: "gitea.example.com", token: tok}},
	}, nil)
	if err != nil {
		e.t.Fatalf("connect %s: %v", user, err)
	}
	e.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callTool(t *testing.T, cs *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func text(r *sdk.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func (e *testEnv) lines() []map[string]any {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.g.log.Flush(ctx); err != nil {
		e.t.Fatal(err)
	}
	f, err := os.Open(e.logPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			e.t.Fatalf("bad line %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func (e *testEnv) raw(method, host, tok, body string, hdr map[string]string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+"/mcp", strings.NewReader(body))
	req.Host = host
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// TestGateEndToEnd: the bridge with the real hubapi client against a fake
// Hub, the limits and the access log, through the real handler.
func TestGateEndToEnd(t *testing.T) {
	e := newEnv(t, nil)

	// bob has no credential: the gate mints through the Hub (with the
	// secret), waits for the entry, then calls with it.
	bob := e.connect("bob")
	if r := callTool(t, bob, "list_issues", map[string]any{"q": argMarker}); r.IsError || text(r) != "ok list_issues" {
		t.Fatalf("bob: %v", text(r))
	}
	e.hub.mu.Lock()
	if len(e.hub.mints) != 1 || e.hub.mints[0]["user"] != "bob" || e.hub.mints[0]["resource"] != giteaURL {
		t.Errorf("mints %v", e.hub.mints)
	}
	e.hub.mu.Unlock()
	e.comp.mu.Lock()
	var sawBob bool
	for _, h := range e.comp.headers {
		if h.Get("Authorization") == "token "+bobCred {
			sawBob = true
		}
		if h.Get("Authorization") == "" || h.Get("X-Portcullis-Gate-Request") != "" {
			t.Errorf("upstream headers %v", h)
		}
	}
	e.comp.mu.Unlock()
	if !sawBob {
		t.Error("the minted credential was never used")
	}

	// alice: delete_repo needs a confirmation (the companion's confirm
	// list). The gate asks the Hub; the upstream is not called.
	alice := e.connect("alice")
	args := map[string]any{"repo": argMarker, "b": 1}
	r := callTool(t, alice, "delete_repo", args)
	if !r.IsError || text(r) != "This needs your confirmation in your browser: open "+peopleConf+", then ask me to try again." {
		t.Fatalf("unconfirmed: %q", text(r))
	}
	raw, _ := json.Marshal(args)
	digest, _ := confirm.ArgsDigest(raw)
	e.hub.mu.Lock()
	if len(e.hub.creates) != 1 || e.hub.creates[0]["args_sha256"] != digest || e.hub.creates[0]["reason"] != "confirm" ||
		e.hub.creates[0]["client"] != "portcullis-ai-claude" || e.hub.creates[0]["tool"] != "delete_repo" || e.hub.creates[0]["user"] != "alice" {
		t.Errorf("creates %v", e.hub.creates)
	}
	e.hub.approved = true
	e.hub.mu.Unlock()
	if got := e.comp.callList(); len(got) != 1 {
		t.Fatalf("upstream calls before approval: %v", got)
	}
	// Approved in the browser: the retry consumes it and acts once.
	if r := callTool(t, alice, "delete_repo", args); r.IsError || text(r) != "ok delete_repo" {
		t.Fatalf("approved: %q", text(r))
	}
	// Single use: the next retry needs a new one.
	if r := callTool(t, alice, "delete_repo", args); !r.IsError {
		t.Fatal("a consumed confirmation was used twice")
	}
	if got := e.comp.callList(); len(got) != 2 || got[1] != "delete_repo" {
		t.Errorf("upstream calls %v", got)
	}

	// A refused token is logged with an empty user and client.
	if resp := e.raw("POST", "gitea.example.com", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil); resp.StatusCode != 401 {
		t.Errorf("no token: %d", resp.StatusCode)
	}

	lines := e.lines()
	b, _ := os.ReadFile(e.logPath)
	for _, marker := range []string{aliceCred, bobCred, argMarker, hubSecret, "eyJ"} {
		if strings.Contains(string(b), marker) {
			t.Errorf("%q is in the access log", marker)
		}
	}
	keys := []string{"time", "user", "client", "resource", "instance", "companion", "via", "method", "tool", "args_sha256", "decision", "upstream_status", "duration_ms"}
	var decisions []string
	var sawInit, sawDeny bool
	for _, l := range lines {
		if len(l) != len(keys) {
			t.Errorf("line %v", l)
		}
		for _, k := range keys {
			if _, ok := l[k]; !ok {
				t.Errorf("key %s missing in %v", k, l)
			}
		}
		switch l["method"] {
		case "tools/call":
			if l["user"] == "alice" {
				decisions = append(decisions, l["decision"].(string))
				if l["args_sha256"] != digest {
					t.Errorf("args_sha256 %v, want %s", l["args_sha256"], digest)
				}
			}
			if l["tool"] == "" || l["instance"] != "gitea" || l["via"] != "direct" || l["client"] != "portcullis-ai-claude" {
				t.Errorf("tools/call line %v", l)
			}
		case "initialize", "server/discover": // 2025-x / 2026-07-28 clients
			sawInit = true
			if l["args_sha256"] != "" || l["tool"] != "" || l["user"] == "" {
				t.Errorf("initialize line %v", l)
			}
		}
		if strings.HasPrefix(l["decision"].(string), "deny:no_token") {
			sawDeny = true
			if l["user"] != "" || l["client"] != "" || l["resource"] != giteaURL {
				t.Errorf("deny line %v", l)
			}
		}
	}
	want := []string{"confirm:" + confirmID, "allow", "confirm:" + confirmID}
	if strings.Join(decisions, ",") != strings.Join(want, ",") {
		t.Errorf("alice's tools/call decisions %v, want %v", decisions, want)
	}
	if !sawInit || !sawDeny {
		t.Errorf("initialize line %v, deny line %v", sawInit, sawDeny)
	}
	// Exactly one line per HTTP request: two connects, four tool calls,
	// one refusal.
	n := map[string]int{}
	for _, l := range lines {
		n[l["method"].(string)]++
	}
	if n["initialize"]+n["server/discover"] != 2 || n["tools/call"] != 4 || n[""] != 1 || len(lines) != 7 {
		t.Errorf("lines per method %v (%d lines)", n, len(lines))
	}
}

// G26: the Hub down or a wrong secret: no mint, no confirmation, the call
// is refused and the upstream never called.
func TestGateHubFailClosed(t *testing.T) {
	for _, mode := range []string{"down", "wrong secret"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t, nil)
			if mode == "down" {
				e.hub.srv.Close()
			} else {
				hub, _ := hubapi.New(e.hub.srv.URL, strings.Repeat("w", 40))
				e.g.minter.hub, e.g.confirmer.Hub = hub, hub
			}
			bob := e.connect("bob")
			if r := callTool(t, bob, "list_issues", nil); !r.IsError || text(r) != "can't check this right now; try again" {
				t.Errorf("mint: %q", text(r))
			}
			alice := e.connect("alice")
			if r := callTool(t, alice, "delete_repo", map[string]any{"repo": "x"}); !r.IsError || text(r) != "can't check this right now; try again" {
				t.Errorf("confirm: %q", text(r))
			}
			if got := e.comp.callList(); len(got) != 0 {
				t.Errorf("upstream called: %v", got)
			}
			var ds []string
			for _, l := range e.lines() {
				if l["method"] == "tools/call" {
					ds = append(ds, l["decision"].(string))
				}
			}
			if strings.Join(ds, ",") != "deny:hub_unavailable,deny:hub_unavailable" {
				t.Errorf("decisions %v", ds)
			}
		})
	}
}

// G28: an unloggable tools/call is refused with 503; initialize and the
// lists still work.
func TestUnloggableToolCallRefused(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.connect("alice")
	e.g.act.healthy = func() bool { return false }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := alice.ListTools(ctx, nil); err != nil {
		t.Errorf("tools/list refused: %v", err)
	}
	tok := e.sig.token("alice", giteaURL, "mcp:gitea.gitea")
	resp := e.raw("POST", "gitea.example.com", tok, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`, nil)
	if resp.StatusCode != 503 {
		t.Errorf("tools/call: %d, want 503", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`))
	req.Host = "gitea.example.com"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("Content-Type", "application/json")
	rr, _ := http.DefaultClient.Do(req)
	body, _ := io.ReadAll(rr.Body)
	rr.Body.Close()
	if !strings.Contains(string(body), "AI activity can't be logged right now") {
		t.Errorf("body %q", body)
	}
	if got := e.comp.callList(); len(got) != 0 {
		t.Errorf("upstream called: %v", got)
	}
	// initialize still works.
	_ = e.connect("bob")
}

// TestLimits at the HTTP layer: 429 + Retry-After, logged rate_limited;
// a 9 MiB body → 413.
func TestLimitsHTTP(t *testing.T) {
	e := newEnv(t, func(f *config.File) { f.Limits.ToolCallsRPM = 2 })
	tok := e.sig.token("alice", giteaURL, "mcp:gitea.gitea")
	alice := e.connect("alice")
	callTool(t, alice, "list_issues", nil)
	callTool(t, alice, "list_issues", nil)
	resp := e.raw("POST", "gitea.example.com", tok, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`, nil)
	if resp.StatusCode != 429 {
		t.Fatalf("3rd tool call: %d", resp.StatusCode)
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || s < 1 || s > 60 {
		t.Errorf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
	if got := e.comp.callList(); len(got) != 2 {
		t.Errorf("upstream calls %v", got)
	}
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"x":"` + strings.Repeat("a", 9<<20) + `"}}`
	if resp := e.raw("POST", "gitea.example.com", tok, big, nil); resp.StatusCode != 413 {
		t.Errorf("9 MiB: %d", resp.StatusCode)
	}
	var limited, tooLarge bool
	for _, l := range e.lines() {
		if l["decision"] == "rate_limited" && l["method"] == "tools/call" && l["tool"] == "list_issues" && l["user"] == "alice" {
			limited = true
		}
		if l["decision"] == "deny:too_large" {
			tooLarge = true
		}
	}
	if !limited || !tooLarge {
		t.Errorf("rate_limited line %v, too_large line %v", limited, tooLarge)
	}

	// Requests per minute per person and resource (burst 30): plain
	// requests at once → the 31st is refused.
	e2 := newEnv(t, nil)
	tok2 := e2.sig.token("bob", giteaURL, "mcp:gitea.gitea")
	codes := map[int]int{}
	for i := 0; i < 31; i++ {
		resp := e2.raw("POST", "gitea.example.com", tok2, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)
		codes[resp.StatusCode]++
	}
	if codes[429] != 1 {
		t.Errorf("codes %v, want one 429", codes)
	}
}

// The gate's own request id header can't be forged by a client to
// suppress its access-log line.
func TestRequestIDNotForgeable(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.sig.token("alice", giteaURL, "mcp:gitea.gitea")
	_ = e.raw("POST", "gitea.example.com", tok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{"X-Portcullis-Gate-Request": "forged"})
	// A 2025-11-25 initialize (a session; not a forwarded method): the
	// handler's line.
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`
	if resp := e.raw("POST", "gitea.example.com", tok, init, map[string]string{"X-Portcullis-Gate-Request": "forged"}); resp.StatusCode != 200 {
		t.Errorf("initialize: %d", resp.StatusCode)
	}
	n := map[string]int{}
	for _, l := range e.lines() {
		if l["user"] == "alice" {
			n[l["method"].(string)+" "+l["decision"].(string)]++
		}
	}
	if n["notifications/initialized allow"] != 1 || n["initialize allow"] != 1 || len(n) != 2 {
		t.Errorf("lines %v", n)
	}
}

// testDeps: the handler's limits and access log for handler-only tests.
func testDeps(t *testing.T, sn *config.Snapshot) *handlerDeps {
	t.Helper()
	act := &activity{snap: func() *config.Snapshot { return sn }}
	l, err := accesslog.OpenWith(filepath.Join(t.TempDir(), "access.jsonl"), accesslog.Options{Group: os.Getgid(), Secrets: act.secrets})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	act.log, act.healthy = l, l.Healthy
	return &handlerDeps{lim: limits.New(nil, nil), act: act}
}

// Review fix 3: refused requests — signed-in or not — only ever take the
// low-priority half of the log queue, so a flood of them can't push an
// allowed tools/call's line out (or make it unloggable, G28).
func TestRefusalFloodKeepsRoomForCalls(t *testing.T) {
	sig := newSigner(t)
	sn := vectorSnapshot(t)
	release := make(chan struct{})
	act := &activity{snap: func() *config.Snapshot { return sn }}
	path := filepath.Join(t.TempDir(), "access.jsonl")
	l, err := accesslog.OpenWith(path, accesslog.Options{
		Group: os.Getgid(), Secrets: act.secrets, QueueSize: 16,
		WriteHook: func() error { <-release; return nil }, // the writer is stalled
	})
	if err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
		_ = l.Close()
	}()
	act.log, act.healthy = l, l.Healthy
	fw := &recordingForwarder{}
	h := newHandler(func() *config.Snapshot { return sn }, authz.NewVerifier("", sig.jwks.URL, sig.jwks.Client()), fw,
		&handlerDeps{lim: limits.New(nil, nil), act: act})
	do := func(tok, body string) int {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		r.Host = "gitea.example.com"
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{}}}`
	// bob is signed in, but his token is for another resource's scope:
	// valid, refused (403), with a user.
	bad := sig.token("bob", giteaURL, "mcp:grafana.grafana")
	for i := 0; i < 40; i++ {
		if c := do(bad, call); c != 403 {
			t.Fatalf("refusal %d: %d", i, c)
		}
	}
	// A signed-in person's rate-limited and malformed requests are
	// refusals too.
	good := sig.token("alice", giteaURL, "mcp:gitea.gitea")
	for i := 0; i < 10; i++ {
		_ = do(good, `{not json`)
	}
	if !act.healthy() {
		t.Fatal("refusals made the log unhealthy")
	}
	if c := do(good, call); c != 299 {
		t.Fatalf("allowed call: %d", c)
	}
	close(release)
	released = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = l.Flush(ctx)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"user":"alice","client":"portcullis-ai-claude","resource":"https://gitea.example.com/mcp","instance":"gitea","companion":"gitea","via":"direct","method":"tools/call","tool":"list_issues"`) ||
		!strings.Contains(string(b), `"decision":"allow"`) {
		t.Errorf("the allowed call's line is missing:\n%s", b)
	}
}

// Fix round 1: the logged tool and args_sha256 are what the SDK executes:
// parseCall decodes with the SDK's own params type, and duplicate or
// case-variant params keys are refused before anything else.
func TestParseCallStrict(t *testing.T) {
	m, tool, args, ok := parseCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","arguments":{"q":1}}}`))
	if !ok || m != "tools/call" || tool != "list_issues" || string(args) != `{"q":1}` {
		t.Errorf("plain: %q %q %s %v", m, tool, args, ok)
	}
	for _, params := range []string{
		`{"name":"list_issues","name":"delete_repo"}`,
		`{"name":"list_issues","Name":"delete_repo"}`,
		`{"NAME":"delete_repo"}`,
		`{"name":"x","Arguments":{"a":1}}`,
		`{"name":"x","arguments":{},"Arguments":{"a":1}}`,
		`{"name":"x","arguments":{},"arguments":{"a":1}}`,
		`{"name":"x","\u006eame":"y"}`,
		`[1]`,
	} {
		if _, _, _, ok := parseCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":` + params + `}`)); ok {
			t.Errorf("%s accepted", params)
		}
	}
	// Unknown keys and _meta are left to the SDK.
	if _, tool, _, ok := parseCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","_meta":{"a":1}}}`)); !ok || tool != "x" {
		t.Error("_meta refused")
	}
	// Other methods and responses are not judged here.
	if m, _, _, ok := parseCall([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)); !ok || m != "tools/list" {
		t.Error("tools/list")
	}
	if m, _, _, ok := parseCall(nil); !ok || m != "" {
		t.Error("empty body")
	}

	// Through the handler: refused (400, deny:protocol), never forwarded.
	sig := newSigner(t)
	sn := vectorSnapshot(t)
	deps := testDeps(t, sn)
	fw := &recordingForwarder{}
	h := newHandler(func() *config.Snapshot { return sn }, authz.NewVerifier("", sig.jwks.URL, sig.jwks.Client()), fw, deps)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_issues","Name":"delete_repo"}}`))
	r.Host = "gitea.example.com"
	r.Header.Set("Authorization", "Bearer "+sig.token("alice", giteaURL, "mcp:gitea.gitea"))
	r.Header.Set("MCP-Protocol-Version", "2025-11-25")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || fw.n != 0 {
		t.Errorf("handler: %d, forwarded %d", w.Code, fw.n)
	}
}

// Fix round 1: a forwarded request without any answer (the client went
// away) is deny:client_gone.
func TestFallbackDecision(t *testing.T) {
	for st, want := range map[int]string{0: "deny:client_gone", 200: "allow", 202: "allow", 400: "deny:protocol", 403: "deny:population", 404: "deny:session", 503: "deny:off", 500: "deny:refused"} {
		if got := fallbackDecision(st); got != want {
			t.Errorf("%d: %s, want %s", st, got, want)
		}
	}
}
