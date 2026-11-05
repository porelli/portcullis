package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/config"
)

// ---- fake companion: an SDK server in httptest recording what it gets ----

type upstream struct {
	t      *testing.T
	srv    *httptest.Server
	server *sdk.Server

	mu       sync.Mutex
	headers  []http.Header // every request
	methods  []string      // HTTP method of every request
	calls    []string      // tools called
	sessions []string      // session ids it handed out
}

func (u *upstream) record(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.headers = append(u.headers, r.Header.Clone())
	u.methods = append(u.methods, r.Method)
}

func (u *upstream) called(name string) {
	u.mu.Lock()
	u.calls = append(u.calls, name)
	u.mu.Unlock()
}

func (u *upstream) snapshot() ([]http.Header, []string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.headers), slices.Clone(u.calls), slices.Clone(u.methods)
}

func textResult(s string) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: s}}}
}

func boolp(b bool) *bool { return &b }

// newUpstream: versions narrows the companion's protocols; tools beyond the
// defaults come from extra.
func newUpstream(t *testing.T, versions []string, extra func(u *upstream, s *sdk.Server)) *upstream {
	u := &upstream{t: t}
	s := sdk.NewServer(&sdk.Implementation{Name: "companion", Version: "1"}, &sdk.ServerOptions{SupportedProtocolVersions: versions})
	u.server = s
	add := func(tool *sdk.Tool) {
		if tool.InputSchema == nil {
			tool.InputSchema = map[string]any{"type": "object"}
		}
		s.AddTool(tool, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			u.called(req.Params.Name)
			return textResult("ok " + req.Params.Name), nil
		})
	}
	for _, n := range []string{"list_issues", "create_issue", "repo_write", "drop_db", "delete_repo"} {
		add(&sdk.Tool{Name: n})
	}
	add(&sdk.Tool{Name: "wipe", Annotations: &sdk.ToolAnnotations{DestructiveHint: boolp(true)}})
	add(&sdk.Tool{Name: "update_write", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}})
	if extra != nil {
		extra(u, s)
	}
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{DisableLocalhostProtection: true})
	// The SDK serves 2026-07-28 only statelessly: a companion speaking both
	// routes on the version header, like the gate.
	hs := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{DisableLocalhostProtection: true, Stateless: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.record(r)
		// A companion trying to set a cookie through the gate.
		w.Header().Set("Set-Cookie", "upstream=1; Path=/")
		rw := &sidRecorder{ResponseWriter: w, u: u}
		if r.Header.Get("Mcp-Protocol-Version") >= "2026-07-28" {
			hs.ServeHTTP(rw, r)
			return
		}
		h.ServeHTTP(rw, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

type sidRecorder struct {
	http.ResponseWriter
	u    *upstream
	done bool
}

func (s *sidRecorder) WriteHeader(code int) {
	if !s.done {
		s.done = true
		if id := s.Header().Get("Mcp-Session-Id"); id != "" {
			s.u.mu.Lock()
			s.u.sessions = append(s.u.sessions, id)
			s.u.mu.Unlock()
		}
	}
	s.ResponseWriter.WriteHeader(code)
}
func (s *sidRecorder) Write(b []byte) (int, error) {
	if !s.done {
		s.WriteHeader(200)
	}
	return s.ResponseWriter.Write(b)
}
func (s *sidRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---- the gate under test ----

type fakeMinter struct {
	mu    sync.Mutex
	calls int
	fn    func(resource, user string) error
}

func (m *fakeMinter) Mint(ctx context.Context, resource, user string) error {
	m.mu.Lock()
	m.calls++
	fn := m.fn
	m.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(resource, user)
}

func (m *fakeMinter) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

type harness struct {
	t      *testing.T
	b      *Bridge
	sn     atomic.Pointer[config.Snapshot]
	gate   *httptest.Server
	minter *fakeMinter
	routes sync.Map // "host:port" → listener addr

	mu     sync.Mutex
	events []Event
}

func vectorFile(t *testing.T, mut func(f *config.File)) *config.File {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/mcp-gate.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.DecodeFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		mut(f)
	}
	out, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f, err = config.DecodeFile(out)
	if err != nil {
		t.Fatalf("mutated vector refused: %v", err)
	}
	return f
}

func resOf(f *config.File, instance string) *config.Resource {
	for i := range f.Resources {
		if f.Resources[i].Instance == instance {
			return &f.Resources[i]
		}
	}
	return nil
}

func attrsDoc(t *testing.T) *config.Attributes {
	b, _ := json.Marshal(map[string]any{
		"version": 2,
		"fields":  map[string]string{"team": "Team"},
		"users":   map[string]any{"alice": map[string][]string{"team": {"Design"}}},
		"hosts":   map[string]any{"grafana.example.com": map[string]any{"Grafana-Role": map[string]string{"alice": "Editor"}}},
	})
	a, err := config.ParseAttributes(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func baseSnapshot(t *testing.T, mut func(f *config.File)) *config.Snapshot {
	return &config.Snapshot{
		File: vectorFile(t, mut),
		Creds: map[config.CredKey]config.Cred{
			{Instance: "gitea", Companion: "gitea", User: "alice"}: {ID: "7", Secret: "s3cr3t"},
		},
		Secrets: map[string]string{"grafana/grafana": "caller-s3cret"},
		Attrs:   attrsDoc(t),
	}
}

func newHarness(t *testing.T, sn *config.Snapshot, ups map[string]*upstream, tweak func(c *Config)) *harness {
	h := &harness{t: t, minter: &fakeMinter{}}
	h.sn.Store(sn)
	for hostport, u := range ups {
		h.routes.Store(hostport, u.srv.Listener.Addr().String())
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	base := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			to, ok := h.routes.Load(addr)
			if !ok {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			return dialer.DialContext(ctx, network, to.(string))
		},
		DisableCompression: true,
	}
	cfg := Config{
		Snapshot: h.sn.Load,
		Minter:   h.minter,
		Base:     base,
		OnEvent: func(e Event) {
			h.mu.Lock()
			h.events = append(h.events, e)
			h.mu.Unlock()
		},
		MintWait: 3 * time.Second,
		MintPoll: 20 * time.Millisecond,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	h.b = New(cfg)
	t.Cleanup(h.b.Close)
	// Simulated authz (task 2 is tested on its own): X-Test-User is the
	// token's person. It is a client header like any other: it must never
	// reach the upstream either.
	h.gate = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := h.sn.Load()
		res, ok := s.Resource(r.Host, r.URL.Path)
		if !ok {
			http.Error(w, "unknown resource", 404)
			return
		}
		h.b.ServeResource(w, r, authz.Decision{
			Status: 200, Reason: "allow", User: r.Header.Get("X-Test-User"),
			Client: "portcullis-ai-claude", Resource: res,
		})
	}))
	t.Cleanup(h.gate.Close)
	return h
}

func (h *harness) eventList() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.events)
}

func (h *harness) decisions(method string) []string {
	var out []string
	for _, e := range h.eventList() {
		if method == "" || e.Method == method {
			out = append(out, e.Decision)
		}
	}
	return out
}

// clientRT: the person's client. It talks to the gate on the resource's
// Host and adds everything a hostile client could send.
type clientRT struct {
	host, user string
	extra      http.Header
	mu         sync.Mutex
	setCookies []string
	sessionIDs []string
}

func (c *clientRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = c.host
	r.Header.Set("Authorization", "Bearer the-persons-access-token")
	r.Header.Set("X-Test-User", c.user)
	for k, vs := range c.extra {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err == nil {
		c.mu.Lock()
		c.setCookies = append(c.setCookies, resp.Header.Values("Set-Cookie")...)
		if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
			c.sessionIDs = append(c.sessionIDs, id)
		}
		c.mu.Unlock()
	}
	return resp, err
}

type clientOpts struct {
	version string
	extra   http.Header
	opts    *sdk.ClientOptions
	host    string
}

func (h *harness) connect(user string, o clientOpts) (*sdk.ClientSession, *clientRT) {
	h.t.Helper()
	if o.host == "" {
		o.host = "gitea.example.com"
	}
	rt := &clientRT{host: o.host, user: user, extra: o.extra}
	c := sdk.NewClient(&sdk.Implementation{Name: "person", Version: "1"}, o.opts)
	tr := &sdk.StreamableClientTransport{Endpoint: h.gate.URL + "/mcp", HTTPClient: &http.Client{Transport: rt}, MaxRetries: -1}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cs, err := c.Connect(ctx, tr, &sdk.ClientSessionOptions{ProtocolVersion: o.version})
	if err != nil {
		h.t.Fatalf("connect as %s: %v", user, err)
	}
	h.t.Cleanup(func() { cs.Close() })
	return cs, rt
}

func ctx10(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func call(t *testing.T, cs *sdk.ClientSession, name string, args any) (*sdk.CallToolResult, error) {
	t.Helper()
	return cs.CallTool(ctx10(t), &sdk.CallToolParams{Name: name, Arguments: args})
}

func resultText(r *sdk.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// Headers the upstream may see at all (§15.5): transport headers, the MCP
// headers, and the identity mode's own.
var transportHeaders = []string{"Accept", "Content-Type", "Content-Length", "User-Agent", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Mcp-Session-Id", "Last-Event-Id"}

func checkOnlyHeaders(t *testing.T, hs []http.Header, identity ...string) {
	t.Helper()
	allowed := append(slices.Clone(transportHeaders), identity...)
	for i, h := range hs {
		for k := range h {
			if !slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, k) }) &&
				!strings.HasPrefix(http.CanonicalHeaderKey(k), "Mcp-Param-") {
				t.Errorf("upstream request %d carried %s: %q", i, k, h.Values(k))
			}
		}
	}
}

// ---- tests ----

const giteaUp = "portcullis-mcp-gitea--gitea:8080"
const grafanaUp = "portcullis-mcp-grafana--grafana:8000"

func TestIdentityAppToken(t *testing.T) {
	up := newUpstream(t, nil, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	if r, err := call(t, cs, "list_issues", map[string]any{}); err != nil || resultText(r) != "ok list_issues" {
		t.Fatalf("call: %v %v", r, err)
	}
	hs, _, _ := up.snapshot()
	if len(hs) == 0 {
		t.Fatal("upstream not called")
	}
	for i, hd := range hs {
		if got := hd.Values("Authorization"); len(got) != 1 || got[0] != "token s3cr3t" {
			t.Errorf("request %d Authorization %q", i, got)
		}
	}
	checkOnlyHeaders(t, hs, "Authorization")

	// basic_user: Basic alice:s3cr3t.
	up2 := newUpstream(t, nil, nil)
	sn := baseSnapshot(t, func(f *config.File) {
		g := resOf(f, "gitea")
		g.Identity.Format, g.Identity.BasicUser, g.Identity.Header = "", "{username}", "Authorization"
	})
	h2 := newHarness(t, sn, map[string]*upstream{giteaUp: up2}, nil)
	cs2, _ := h2.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := call(t, cs2, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	hs, _, _ = up2.snapshot()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t"))
	for i, hd := range hs {
		if got := hd.Values("Authorization"); len(got) != 1 || got[0] != want {
			t.Errorf("basic request %d Authorization %q", i, got)
		}
	}
	checkOnlyHeaders(t, hs, "Authorization")

	// A custom header name; Authorization then never reaches the upstream.
	up3 := newUpstream(t, nil, nil)
	sn3 := baseSnapshot(t, func(f *config.File) { resOf(f, "gitea").Identity.Header = "X-Gitea-Token" })
	h3 := newHarness(t, sn3, map[string]*upstream{giteaUp: up3}, nil)
	cs3, _ := h3.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := call(t, cs3, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	hs, _, _ = up3.snapshot()
	for i, hd := range hs {
		if hd.Get("Authorization") != "" || hd.Get("X-Gitea-Token") != "token s3cr3t" {
			t.Errorf("custom header request %d: %v", i, hd)
		}
	}
}

func TestIdentityHeaders(t *testing.T) {
	up := newUpstream(t, []string{"2025-11-25"}, nil)
	sn := baseSnapshot(t, func(f *config.File) {
		g := resOf(f, "grafana")
		g.Population = []string{"alice", "bob"}
	})
	h := newHarness(t, sn, map[string]*upstream{grafanaUp: up}, nil)
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25", host: "grafana.example.com"})
	if _, err := call(t, cs, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	hs, _, _ := up.snapshot()
	for i, hd := range hs {
		for k, want := range map[string]string{
			"X-Forwarded-User":              "alice",
			"X-Forwarded-Email":             "alice@example.org",
			"X-Auth-Request-Groups":         "design,users_grafana",
			"X-Forwarded-Attr-Team":         "Design",
			"X-Forwarded-Attr-Grafana-Role": "Editor",
			"Authorization":                 "Bearer caller-s3cret",
		} {
			if got := hd.Values(k); len(got) != 1 || got[0] != want {
				t.Errorf("request %d %s = %q, want %q", i, k, got, want)
			}
		}
	}
	checkOnlyHeaders(t, hs, "X-Forwarded-User", "X-Forwarded-Email", "X-Auth-Request-Groups", "X-Forwarded-Attr-Team", "X-Forwarded-Attr-Grafana-Role", "Authorization")

	// bob is in the population but not in people / attributes: only his
	// user and the caller secret, never a stale email or groups.
	n := len(hs)
	csb, _ := h.connect("bob", clientOpts{version: "2025-11-25", host: "grafana.example.com"})
	if _, err := call(t, csb, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	hs, _, _ = up.snapshot()
	for i, hd := range hs[n:] {
		if hd.Get("X-Forwarded-User") != "bob" || hd.Get("Authorization") != "Bearer caller-s3cret" {
			t.Errorf("bob request %d: %v", i, hd)
		}
		for _, k := range []string{"X-Forwarded-Email", "X-Auth-Request-Groups", "X-Forwarded-Attr-Team", "X-Forwarded-Attr-Grafana-Role"} {
			if hd.Get(k) != "" {
				t.Errorf("bob request %d has %s", i, k)
			}
		}
	}

	// No caller secret → never called without it.
	up2 := newUpstream(t, []string{"2025-11-25"}, nil)
	sn2 := baseSnapshot(t, nil)
	sn2.Secrets = nil
	h2 := newHarness(t, sn2, map[string]*upstream{grafanaUp: up2}, nil)
	cs2, _ := h2.connect("alice", clientOpts{version: "2025-11-25", host: "grafana.example.com"})
	if _, err := call(t, cs2, "list_issues", nil); err == nil {
		t.Error("call without a caller secret succeeded")
	}
	if hs, _, _ := up2.snapshot(); len(hs) != 0 {
		t.Errorf("upstream called without its caller secret: %d requests", len(hs))
	}
}

var hostile = http.Header{
	"Cookie":                    {"session=abc"},
	"Proxy-Authorization":       {"Basic cm9vdDpyb290"},
	"X-Forwarded-User":          {"root"},
	"X-Forwarded-Email":         {"root@example.com"},
	"X-Forwarded-For":           {"10.0.0.1"},
	"X-Forwarded-Host":          {"hub.example.com"},
	"X-Forwarded-Attr-Team":     {"admins"},
	"X-Auth-Request-User":       {"root"},
	"X-Auth-Request-Groups":     {"lldap_admin"},
	"Remote-User":               {"root"},
	"X-Portcullis-Proxy-Secret": {"guess"},
	"X-Portcullis-Ai-Client":    {"x"},
	"X-Real-Ip":                 {"10.0.0.1"},
	"X-Gitea-Token":             {"forged"},
}

func TestClientHeadersNeverForwarded(t *testing.T) {
	for _, mode := range []string{"app_token", "identity_headers"} {
		t.Run(mode, func(t *testing.T) {
			up := newUpstream(t, []string{"2025-11-25"}, nil)
			host, route, identity := "gitea.example.com", giteaUp, []string{"Authorization"}
			if mode == "identity_headers" {
				host, route = "grafana.example.com", grafanaUp
				identity = []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Auth-Request-Groups", "X-Forwarded-Attr-Team", "X-Forwarded-Attr-Grafana-Role", "Authorization"}
			}
			h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{route: up}, nil)
			for _, v := range []string{"2025-11-25", "2026-07-28"} {
				cs, rt := h.connect("alice", clientOpts{version: v, host: host, extra: hostile})
				if _, err := call(t, cs, "list_issues", map[string]any{}); err != nil {
					t.Fatalf("%s: %v", v, err)
				}
				if _, err := cs.ListTools(ctx10(t), nil); err != nil {
					t.Fatal(err)
				}
				rt.mu.Lock()
				if len(rt.setCookies) != 0 {
					t.Errorf("%s: the client got Set-Cookie %q", v, rt.setCookies)
				}
				rt.mu.Unlock()
			}
			hs, _, _ := up.snapshot()
			if len(hs) == 0 {
				t.Fatal("upstream not called")
			}
			checkOnlyHeaders(t, hs, identity...)
			for i, hd := range hs {
				if a := hd.Values("Authorization"); len(a) != 1 || strings.Contains(a[0], "the-persons-access-token") {
					t.Errorf("request %d Authorization %q", i, a)
				}
				if mode == "identity_headers" && (hd.Values("X-Forwarded-User")[0] != "alice" || len(hd.Values("X-Forwarded-User")) != 1) {
					t.Errorf("request %d user %q", i, hd.Values("X-Forwarded-User"))
				}
				for k := range hostile {
					for _, v := range hd.Values(k) {
						if slices.Contains(hostile[k], v) {
							t.Errorf("request %d: client value of %s reached the upstream", i, k)
						}
					}
				}
			}
		})
	}
}

func TestNoCredentialNeverAnonymous(t *testing.T) {
	up := newUpstream(t, nil, nil)
	sn := baseSnapshot(t, nil)
	h := newHarness(t, sn, map[string]*upstream{giteaUp: up}, nil)
	// The Hub mints; the entry appears in the file a little later.
	h.minter.fn = func(resource, user string) error {
		if resource != "https://gitea.example.com/mcp" || user != "bob" {
			t.Errorf("mint %s %s", resource, user)
		}
		go func() {
			time.Sleep(300 * time.Millisecond)
			next := *h.sn.Load()
			next.Creds = map[config.CredKey]config.Cred{
				{Instance: "gitea", Companion: "gitea", User: "alice"}: {ID: "7", Secret: "s3cr3t"},
				{Instance: "gitea", Companion: "gitea", User: "bob"}:   {ID: "8", Secret: "b0b"},
			}
			h.sn.Store(&next)
		}()
		return nil
	}
	cs, _ := h.connect("bob", clientOpts{version: "2025-11-25"})
	start := time.Now()
	if r, err := call(t, cs, "list_issues", nil); err != nil || resultText(r) != "ok list_issues" {
		t.Fatalf("bob: %v %v", r, err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Error("the call did not wait for the credential")
	}
	if h.minter.count() != 1 {
		t.Errorf("mints: %d", h.minter.count())
	}
	hs, _, _ := up.snapshot()
	for i, hd := range hs {
		if hd.Get("Authorization") != "token b0b" {
			t.Errorf("request %d without bob's credential: %q", i, hd.Get("Authorization"))
		}
	}

	// No entry within the wait: the JSON-RPC error, never an anonymous call.
	up2 := newUpstream(t, nil, nil)
	h2 := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up2}, func(c *Config) { c.MintWait = 400 * time.Millisecond })
	cs2, _ := h2.connect("bob", clientOpts{version: "2025-11-25"})
	_, err := call(t, cs2, "list_issues", nil)
	if err == nil || !strings.Contains(err.Error(), "Preparing your access to Gitea, try again in a moment") {
		t.Fatalf("got %v", err)
	}
	if _, err := cs2.ListTools(ctx10(t), nil); err == nil || !strings.Contains(err.Error(), "Preparing your access to Gitea") {
		t.Errorf("tools/list: %v", err)
	}
	if hs, _, _ := up2.snapshot(); len(hs) != 0 {
		t.Errorf("upstream called %d times without a credential", len(hs))
	}
	// A revoking entry is no entry (the store drops it): same answer.
	if d := h2.decisions("tools/call"); len(d) == 0 || d[0] != "deny:mint_pending" {
		t.Errorf("decisions %v", d)
	}
}

func TestMintNoAccount(t *testing.T) {
	up := newUpstream(t, nil, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	h.minter.fn = func(string, string) error { return fmt.Errorf("hub said: %w", ErrNoAccount) }
	cs, _ := h.connect("bob", clientOpts{version: "2025-11-25"})
	_, err := call(t, cs, "list_issues", nil)
	if err == nil || !strings.Contains(err.Error(), "Open Gitea (https://gitea.example.com) in your browser once, then try again") {
		t.Fatalf("got %v", err)
	}
	// Hub unreachable / 5xx (G26): fail closed, the upstream never called.
	h.minter.fn = func(string, string) error { return errors.New("dial tcp: connection refused") }
	r, err := call(t, cs, "list_issues", nil)
	if err != nil || !r.IsError || resultText(r) != "can't check this right now; try again" {
		t.Fatalf("hub down: %v %v", r, err)
	}
	h.minter.fn = func(string, string) error { return ErrMintFailed }
	if _, err := call(t, cs, "list_issues", nil); err == nil || !strings.Contains(err.Error(), "Gitea") {
		t.Errorf("mint failed: %v", err)
	}
	if hs, _, _ := up.snapshot(); len(hs) != 0 {
		t.Errorf("upstream called %d times", len(hs))
	}
	got := h.decisions("tools/call")
	if want := []string{"deny:no_account", "deny:hub_unavailable", "deny:mint_failed"}; !slices.Equal(got, want) {
		t.Errorf("decisions %v, want %v", got, want)
	}
}

func TestMintWaitSharedPerPerson(t *testing.T) {
	up := newUpstream(t, nil, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	release := make(chan struct{})
	h.minter.fn = func(string, string) error {
		<-release
		next := *h.sn.Load()
		next.Creds = map[config.CredKey]config.Cred{{Instance: "gitea", Companion: "gitea", User: "bob"}: {ID: "8", Secret: "b0b"}}
		h.sn.Store(&next)
		return nil
	}
	res := resOf(h.sn.Load().File, "gitea")
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cs, err := h.b.Upstream(ctx10(t), "bob", "portcullis-ai-claude", res)
			if err == nil {
				_, err = cs.ListTools(ctx10(t), nil)
			}
			errs <- err
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := h.minter.count(); n != 1 {
		t.Errorf("%d mints for 4 concurrent requests", n)
	}
	// Also through four clients at once.
	up2 := newUpstream(t, nil, nil)
	h2 := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up2}, nil)
	release2 := make(chan struct{})
	h2.minter.fn = func(string, string) error {
		<-release2
		next := *h2.sn.Load()
		next.Creds = map[config.CredKey]config.Cred{{Instance: "gitea", Companion: "gitea", User: "bob"}: {ID: "8", Secret: "b0b"}}
		h2.sn.Store(&next)
		return nil
	}
	var sessions []*sdk.ClientSession
	for i := 0; i < 4; i++ {
		cs, _ := h2.connect("bob", clientOpts{version: "2025-11-25"})
		sessions = append(sessions, cs)
	}
	errs2 := make(chan error, 4)
	for _, cs := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := call(t, cs, "list_issues", nil)
			errs2 <- err
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release2)
	wg.Wait()
	close(errs2)
	for err := range errs2 {
		if err != nil {
			t.Error(err)
		}
	}
	if n := h2.minter.count(); n != 1 {
		t.Errorf("%d mints for 4 concurrent sessions", n)
	}
}

func TestToolFilterThroughGate(t *testing.T) {
	up := newUpstream(t, nil, nil)
	sn := baseSnapshot(t, func(f *config.File) {
		g := resOf(f, "gitea")
		g.Mode = "read_only"
		g.Tools.Never = []string{"drop_*", "repo_write:delete"}
	})
	h := newHarness(t, sn, map[string]*upstream{giteaUp: up}, nil)
	for _, v := range []string{"2025-11-25", "2026-07-28"} {
		cs, _ := h.connect("alice", clientOpts{version: v})
		lt, err := cs.ListTools(ctx10(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		// gitea's writes include delete_*: hidden in read-only mode.
		got := strings.Split(names(lt.Tools), ",")
		slices.Sort(got)
		if !slices.Equal(got, []string{"list_issues", "wipe"}) {
			t.Errorf("%s: listed %v", v, got)
		}
		for _, c := range []struct {
			tool string
			args any
		}{{"drop_db", nil}, {"create_issue", nil}, {"repo_write", map[string]any{"method": "delete"}}, {"update_write", nil}} {
			if r, err := call(t, cs, c.tool, c.args); err == nil {
				t.Errorf("%s %s: allowed: %v", v, c.tool, r)
			}
		}
	}
	_, calls, _ := up.snapshot()
	if len(calls) != 0 {
		t.Errorf("refused tools reached the upstream: %v", calls)
	}
	got := h.decisions("tools/call")
	want := []string{"deny:never", "deny:read_only", "deny:never", "deny:read_only"}
	if !slices.Equal(got, append(want, want...)) {
		t.Errorf("decisions %v", got)
	}
	for _, e := range h.eventList() {
		if e.Method == "tools/call" && (e.Resource != "https://gitea.example.com/mcp" || e.Instance != "gitea" || e.Companion != "gitea" || e.User != "alice" || e.Client != "portcullis-ai-claude" || e.Via != "direct" || e.Tool == "") {
			t.Errorf("event %+v", e)
		}
	}
}

type fakeConfirmer struct {
	mu    sync.Mutex
	calls []Call
	ok    bool
}

func (f *fakeConfirmer) Before(ctx context.Context, c Call) (bool, *sdk.CallToolResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	if f.ok {
		return true, nil, nil
	}
	return false, &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "This needs your confirmation in your browser: open https://people.example.com/confirm/X, then ask me to try again."}}}, nil
}

func TestAnnotationAddsConfirmThroughGate(t *testing.T) {
	up := newUpstream(t, nil, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	// No tools/list first: the gate fetches the annotations itself (G23).
	r, err := call(t, cs, "wipe", nil)
	if err != nil || !r.IsError || !strings.Contains(resultText(r), "confirmation") {
		t.Fatalf("wipe without confirmations: %v %v", r, err)
	}
	r, err = call(t, cs, "delete_repo", nil)
	if err != nil || !r.IsError {
		t.Fatalf("delete_repo: %v %v", r, err)
	}
	if _, calls, _ := up.snapshot(); len(calls) != 0 {
		t.Fatalf("unconfirmed calls reached the upstream: %v", calls)
	}
	if got := h.decisions("tools/call"); !slices.Equal(got, []string{"deny:confirm_unavailable", "deny:confirm_unavailable"}) {
		t.Errorf("decisions %v", got)
	}

	// With a confirmer: it is asked with the reason; approved → forwarded.
	fc := &fakeConfirmer{}
	up2 := newUpstream(t, nil, nil)
	h2 := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up2}, func(c *Config) { c.Confirm = fc })
	cs2, _ := h2.connect("alice", clientOpts{version: "2025-11-25"})
	r, err = call(t, cs2, "wipe", map[string]any{"x": 1})
	if err != nil || !r.IsError || !strings.Contains(resultText(r), "open https://people.example.com/confirm/X") {
		t.Fatalf("pending: %v %v", r, err)
	}
	fc.mu.Lock()
	fc.ok = true
	fc.mu.Unlock()
	r, err = call(t, cs2, "wipe", map[string]any{"x": 1})
	if err != nil || resultText(r) != "ok wipe" {
		t.Fatalf("approved: %v %v", r, err)
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if len(fc.calls) != 2 || fc.calls[0].Reason != "destructive" || fc.calls[0].Tool != "wipe" || fc.calls[0].User != "alice" ||
		string(fc.calls[0].Args) != `{"x":1}` || fc.calls[0].Resource.URL != "https://gitea.example.com/mcp" {
		t.Errorf("confirmer calls %+v", fc.calls)
	}
	if _, calls, _ := up2.snapshot(); !slices.Equal(calls, []string{"wipe"}) {
		t.Errorf("upstream calls %v", calls)
	}
}

func TestServerToClientRequests(t *testing.T) {
	extra := func(u *upstream, s *sdk.Server) {
		s.AddTool(&sdk.Tool{Name: "ask", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			var out []string
			if _, err := req.Session.CreateMessage(ctx, &sdk.CreateMessageParams{MaxTokens: 5, Messages: []*sdk.SamplingMessage{{Role: "user", Content: &sdk.TextContent{Text: "hi"}}}}); err != nil {
				out = append(out, "sampling:declined")
			} else {
				out = append(out, "sampling:ANSWERED")
			}
			if _, err := req.Session.ListRoots(ctx, nil); err != nil {
				out = append(out, "roots:declined")
			} else {
				out = append(out, "roots:ANSWERED")
			}
			er, err := req.Session.Elicit(ctx, &sdk.ElicitParams{Message: "name?", RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}})
			if err == nil {
				out = append(out, "form:"+er.Action+":"+fmt.Sprint(er.Content["name"]))
			} else {
				out = append(out, "form:error")
			}
			for _, url := range []string{"https://gitea.example.com/x", "https://people.example.com/y", "https://evil.example/z", "https://auth.example.com/realms/portcullis"} {
				er, err := req.Session.Elicit(ctx, &sdk.ElicitParams{Mode: "url", Message: "open", URL: url, ElicitationID: "e1"})
				if err != nil {
					out = append(out, "url:error")
				} else {
					out = append(out, "url:"+er.Action)
				}
			}
			return textResult(strings.Join(out, " ")), nil
		})
	}
	up := newUpstream(t, []string{"2025-11-25"}, extra)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)

	var mu sync.Mutex
	var seen []string
	opts := &sdk.ClientOptions{
		CreateMessageHandler: func(context.Context, *sdk.CreateMessageRequest) (*sdk.CreateMessageResult, error) {
			mu.Lock()
			seen = append(seen, "sampling")
			mu.Unlock()
			return &sdk.CreateMessageResult{Role: "assistant", Content: &sdk.TextContent{Text: "leak"}, Model: "m"}, nil
		},
		ElicitationHandler: func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			mu.Lock()
			seen = append(seen, req.Params.Mode+":"+req.Params.URL)
			mu.Unlock()
			if req.Params.Mode == "url" {
				return &sdk.ElicitResult{Action: "accept"}, nil
			}
			return &sdk.ElicitResult{Action: "accept", Content: map[string]any{"name": "Al"}}, nil
		},
		Capabilities: &sdk.ClientCapabilities{
			RootsV2:     &sdk.RootCapabilities{},
			Elicitation: &sdk.ElicitationCapabilities{Form: &sdk.FormElicitationCapabilities{}, URL: &sdk.URLElicitationCapabilities{}},
		},
	}
	c := sdk.NewClient(&sdk.Implementation{Name: "person", Version: "1"}, opts)
	c.AddRoots(&sdk.Root{URI: "file:///home/alice/secret"})
	c.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "roots/list" {
				mu.Lock()
				seen = append(seen, "roots")
				mu.Unlock()
			}
			return next(ctx, method, req)
		}
	})
	rt := &clientRT{host: "gitea.example.com", user: "alice"}
	cs, err := c.Connect(ctx10(t), &sdk.StreamableClientTransport{Endpoint: h.gate.URL + "/mcp", HTTPClient: &http.Client{Transport: rt}, MaxRetries: -1}, &sdk.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	r, err := call(t, cs, "ask", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "sampling:declined roots:declined form:accept:Al url:accept url:accept url:decline url:decline"
	if got := resultText(r); got != want {
		t.Errorf("upstream saw %q\nwant          %q", got, want)
	}
	mu.Lock()
	if want := []string{"form:", "url:https://gitea.example.com/x", "url:https://people.example.com/y"}; !slices.Equal(seen, want) {
		t.Errorf("the person's client saw %v, want %v", seen, want)
	}
	mu.Unlock()
	d := h.decisions("")
	for _, w := range []string{"deny:url_elicitation"} {
		if !slices.Contains(d, w) {
			t.Errorf("no %s in %v", w, d)
		}
	}
	n := 0
	for _, x := range d {
		if x == "deny:url_elicitation" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d url_elicitation denials: %v", n, d)
	}
}

// A 2026-07-28 companion asks through input_required results (SEP-2322).
func TestServerToClientRequestsMultiRoundTrip(t *testing.T) {
	extra := func(u *upstream, s *sdk.Server) {
		s.AddTool(&sdk.Tool{Name: "ask", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			if req.Params.InputResponses == nil {
				return &sdk.CallToolResult{InputRequests: sdk.InputRequestMap{
					"f": &sdk.ElicitParams{Mode: "form", Message: "name?", RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}},
					"u": &sdk.ElicitParams{Mode: "url", Message: "open", URL: "https://gitea.example.com/x", ElicitationID: "e1"},
				}, RequestState: "st1"}, nil
			}
			var out []string
			for _, k := range []string{"f", "u"} {
				er, _ := req.Params.InputResponses[k].(*sdk.ElicitResult)
				if er == nil {
					out = append(out, k+":missing")
					continue
				}
				out = append(out, k+":"+er.Action+":"+fmt.Sprint(er.Content["name"]))
			}
			return textResult(strings.Join(out, " ") + " state=" + req.Params.RequestState), nil
		})
		s.AddTool(&sdk.Tool{Name: "evil", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			if req.Params.InputResponses == nil {
				return &sdk.CallToolResult{InputRequests: sdk.InputRequestMap{
					"u": &sdk.ElicitParams{Mode: "url", Message: "open", URL: "https://hub.example.com/", ElicitationID: "e2"},
				}, RequestState: "st2"}, nil
			}
			er, _ := req.Params.InputResponses["u"].(*sdk.ElicitResult)
			return textResult("evil:" + er.Action), nil
		})
		s.AddTool(&sdk.Tool{Name: "sample", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			if req.Params.InputResponses == nil {
				return &sdk.CallToolResult{InputRequests: sdk.InputRequestMap{
					"s": &sdk.CreateMessageParams{MaxTokens: 5, Messages: []*sdk.SamplingMessage{{Role: "user", Content: &sdk.TextContent{Text: "hi"}}}},
				}}, nil
			}
			return textResult("SAMPLED"), nil
		})
	}
	up := newUpstream(t, []string{"2026-07-28"}, extra)
	sn := baseSnapshot(t, func(f *config.File) { resOf(f, "gitea").Protocol = []string{"2026-07-28"} })
	h := newHarness(t, sn, map[string]*upstream{giteaUp: up}, nil)
	for _, v := range []string{"2025-11-25", "2026-07-28"} {
		var mu sync.Mutex
		var seen []string
		opts := &sdk.ClientOptions{
			CreateMessageHandler: func(context.Context, *sdk.CreateMessageRequest) (*sdk.CreateMessageResult, error) {
				mu.Lock()
				seen = append(seen, "sampling")
				mu.Unlock()
				return &sdk.CreateMessageResult{Role: "assistant", Content: &sdk.TextContent{Text: "leak"}, Model: "m"}, nil
			},
			ElicitationHandler: func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
				mu.Lock()
				seen = append(seen, req.Params.Mode+":"+req.Params.URL)
				mu.Unlock()
				if req.Params.Mode == "url" {
					return &sdk.ElicitResult{Action: "accept"}, nil
				}
				return &sdk.ElicitResult{Action: "accept", Content: map[string]any{"name": "Al"}}, nil
			},
			Capabilities: &sdk.ClientCapabilities{Elicitation: &sdk.ElicitationCapabilities{Form: &sdk.FormElicitationCapabilities{}, URL: &sdk.URLElicitationCapabilities{}}},
		}
		cs, _ := h.connect("alice", clientOpts{version: v, opts: opts})
		r, err := call(t, cs, "ask", nil)
		if err != nil || resultText(r) != "f:accept:Al u:accept:<nil> state=st1" {
			t.Errorf("%s ask: %v %v", v, r, err)
		}
		r, err = call(t, cs, "evil", nil)
		if err != nil || resultText(r) != "evil:decline" {
			t.Errorf("%s evil: %v %v", v, resultTextOr(r), err)
		}
		r, err = call(t, cs, "sample", nil)
		if err == nil && (!r.IsError || strings.Contains(resultText(r), "SAMPLED")) {
			t.Errorf("%s sample: %v", v, resultText(r))
		}
		mu.Lock()
		slices.Sort(seen)
		if want := []string{"form:", "url:https://gitea.example.com/x"}; !slices.Equal(seen, want) {
			t.Errorf("%s: the person's client saw %v", v, seen)
		}
		mu.Unlock()
	}
	d := h.decisions("")
	if !slices.Contains(d, "deny:url_elicitation") || !slices.Contains(d, "deny:sampling") {
		t.Errorf("decisions %v", d)
	}
}

func resultTextOr(r *sdk.CallToolResult) string {
	if r == nil {
		return "<nil>"
	}
	return resultText(r)
}

func rawPost(t *testing.T, h *harness, user, sessionID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", h.gate.URL+"/mcp", strings.NewReader(body))
	req.Host = "gitea.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Test-User", user)
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestSessionsBoundToPerson(t *testing.T) {
	up := newUpstream(t, []string{"2025-11-25"}, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	cs, rt := h.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := call(t, cs, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Lock()
	ids := slices.Clone(rt.sessionIDs)
	rt.mu.Unlock()
	if len(ids) == 0 || cs.ID() == "" {
		t.Fatal("no gate session id")
	}
	up.mu.Lock()
	upIDs := slices.Clone(up.sessions)
	up.mu.Unlock()
	if len(upIDs) == 0 {
		t.Fatal("the upstream gave no session id")
	}
	for _, id := range ids {
		if slices.Contains(upIDs, id) {
			t.Errorf("the client saw the upstream's session id %s", id)
		}
	}
	// bob presenting alice's session id → 404; alice herself is served.
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`
	if resp := rawPost(t, h, "bob", cs.ID(), body); resp.StatusCode != 404 {
		b, _ := io.ReadAll(resp.Body)
		t.Errorf("bob with alice's session: %d %s", resp.StatusCode, b)
	}
	if resp := rawPost(t, h, "alice", cs.ID(), body); resp.StatusCode != 200 {
		t.Errorf("alice: %d", resp.StatusCode)
	}
	// Another resource with the same session id → 404 too.
	h.routes.Store(grafanaUp, up.srv.Listener.Addr().String())
	req, _ := http.NewRequest("POST", h.gate.URL+"/mcp", strings.NewReader(body))
	req.Host = "grafana.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Test-User", "alice")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	req.Header.Set("Mcp-Session-Id", cs.ID())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("alice's session on another resource: %d", resp.StatusCode)
	}
}

func TestUpstreamProtocolNegotiation(t *testing.T) {
	up := newUpstream(t, []string{"2025-11-25"}, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{grafanaUp: up}, nil)
	cs, _ := h.connect("alice", clientOpts{version: "2026-07-28", host: "grafana.example.com"})
	if r, err := call(t, cs, "list_issues", nil); err != nil || resultText(r) != "ok list_issues" {
		t.Fatalf("%v %v", r, err)
	}
	hs, _, _ := up.snapshot()
	for i, hd := range hs {
		if v := hd.Get("Mcp-Protocol-Version"); v != "" && v != "2025-11-25" {
			t.Errorf("request %d spoke %s upstream", i, v)
		}
	}
	// gitea lists 2026-07-28 first: the gate speaks the newest it supports.
	up2 := newUpstream(t, nil, nil)
	h2 := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up2}, nil)
	cs2, _ := h2.connect("alice", clientOpts{version: "2025-06-18"})
	if _, err := call(t, cs2, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	hs, _, _ = up2.snapshot()
	if len(hs) == 0 || hs[len(hs)-1].Get("Mcp-Protocol-Version") != "2026-07-28" {
		t.Errorf("upstream version %q", hs[len(hs)-1].Get("Mcp-Protocol-Version"))
	}
}

func TestLeaverPooledSessionClosed(t *testing.T) {
	up := newUpstream(t, []string{"2025-11-25"}, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := call(t, cs, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	res := resOf(h.sn.Load().File, "gitea")
	if _, err := h.b.Upstream(ctx10(t), "alice", "portcullis-ai-claude", res); err != nil {
		t.Fatal(err)
	}
	if n := h.b.livePooled("alice"); n != 2 {
		t.Fatalf("alice has %d pooled sessions", n)
	}
	// bob keeps his.
	csb, _ := h.connect("bob", clientOpts{version: "2025-11-25"})
	h.sn.Store(baseSnapshot(t, func(f *config.File) {
		f.Resources[0].Population = []string{"alice", "bob"}
	}))
	h.minter.fn = nil
	h.sn.Load().Creds[config.CredKey{Instance: "gitea", Companion: "gitea", User: "bob"}] = config.Cred{ID: "8", Secret: "b0b"}
	if _, err := call(t, csb, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	// The next file drops alice from gitea's population.
	next := baseSnapshot(t, func(f *config.File) {
		g := resOf(f, "gitea")
		g.Population = []string{"bob"}
		g.Expiring = map[string]config.Time{}
	})
	next.Creds[config.CredKey{Instance: "gitea", Companion: "gitea", User: "bob"}] = config.Cred{ID: "8", Secret: "b0b"}
	h.sn.Store(next)
	h.b.Reconcile()
	if n := h.b.livePooled("alice"); n != 0 {
		t.Errorf("alice still has %d pooled sessions", n)
	}
	if n := h.b.livePooled("bob"); n == 0 {
		t.Error("bob lost his session")
	}
	// The upstream sessions were ended (DELETE).
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, methods := up.snapshot()
		if slices.Contains(methods, "DELETE") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no DELETE upstream: %v", methods)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Her next request is refused (403) even if authz were stale.
	if resp := rawPost(t, h, "alice", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`); resp.StatusCode != 403 {
		t.Errorf("alice after leaving: %d", resp.StatusCode)
	}
	if _, err := call(t, cs, "list_issues", nil); err == nil {
		t.Error("alice's old session still works")
	}
	if _, err := call(t, csb, "list_issues", nil); err != nil {
		t.Errorf("bob: %v", err)
	}
	// DropUser closes everything of a person at once.
	h.b.DropUser("bob")
	if n := h.b.livePooled("bob"); n != 0 {
		t.Errorf("bob after DropUser: %d", n)
	}
}

func TestResultTooLargeAndTimeout(t *testing.T) {
	extra := func(u *upstream, s *sdk.Server) {
		s.AddTool(&sdk.Tool{Name: "big", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return textResult(strings.Repeat("x", 300<<10)), nil
		})
		s.AddTool(&sdk.Tool{Name: "slow", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
			return textResult("late"), nil
		})
	}
	up := newUpstream(t, []string{"2025-11-25"}, extra)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, func(c *Config) {
		c.MaxResultBytes = 200 << 10
		c.UpstreamTimeout = 300 * time.Millisecond
	})
	cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := call(t, cs, "big", nil); err == nil || !strings.Contains(err.Error(), "result too large") {
		t.Errorf("big: %v", err)
	}
	if _, err := call(t, cs, "list_issues", nil); err != nil {
		t.Errorf("after a large result: %v", err)
	}
	start := time.Now()
	if _, err := call(t, cs, "slow", nil); err == nil || !strings.Contains(err.Error(), "took too long") {
		t.Errorf("slow: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("the timeout did not apply")
	}
}

func TestServeResourceRefusals(t *testing.T) {
	h := newHarness(t, baseSnapshot(t, nil), nil, nil)
	sn := h.sn.Load()
	agg, _ := sn.Resource("mcp.example.com", "/mcp")
	gitea, _ := sn.Resource("gitea.example.com", "/mcp")
	for name, d := range map[string]authz.Decision{
		"not allowed":   {Status: 401, User: "alice", Resource: gitea},
		"not companion": {Status: 200, User: "alice", Resource: agg},
		"outsider":      {Status: 200, User: "carol", Resource: gitea},
		"no resource":   {Status: 200, User: "alice"},
		"empty user":    {Status: 200, User: "", Resource: gitea},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(`{}`)))
		r.Host = "gitea.example.com"
		h.b.ServeResource(w, r, d)
		if w.Code == 200 || w.Header().Get("Set-Cookie") != "" {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// A snapshot in error refuses everything.
	h.sn.Store(&config.Snapshot{Err: errors.New("bad")})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/mcp", bytes.NewReader([]byte(`{}`)))
	h.b.ServeResource(w, r, authz.Decision{Status: 200, User: "alice", Resource: gitea})
	if w.Code != 503 {
		t.Errorf("snapshot error: %d", w.Code)
	}
}

// ---- fix round 1 ----

func TestDestructiveMapBounded(t *testing.T) {
	b := New(Config{Snapshot: func() *config.Snapshot { return nil }})
	defer b.Close()
	l := &link{b: b, destructive: map[string]bool{}, annLoaded: true}
	yes := true
	l.recordTools([]*sdk.Tool{
		{Name: "bad:name", Annotations: &sdk.ToolAnnotations{DestructiveHint: &yes}},
		{Name: strings.Repeat("a", 200), Annotations: &sdk.ToolAnnotations{DestructiveHint: &yes}},
		{Name: "wipe", Annotations: &sdk.ToolAnnotations{DestructiveHint: &yes}},
	})
	if len(l.destructive) != 1 || !l.destructive["wipe"] {
		t.Fatalf("recorded %v", l.destructive)
	}
	var many []*sdk.Tool
	for i := 0; i < maxDestructive; i++ {
		many = append(many, &sdk.Tool{Name: fmt.Sprintf("t%d", i), Annotations: &sdk.ToolAnnotations{DestructiveHint: &yes}})
	}
	l.recordTools(many)
	if len(l.destructive) > maxDestructive {
		t.Errorf("map grew to %d", len(l.destructive))
	}
	if _, err := l.annotation(context.Background(), nil, "list_issues"); err == nil {
		t.Error("past the cap a call was not refused")
	}
}

func TestInputRoundCapped(t *testing.T) {
	extra := func(u *upstream, s *sdk.Server) {
		s.AddTool(&sdk.Tool{Name: "flood", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			if req.Params.InputResponses != nil {
				return textResult("ANSWERED"), nil
			}
			m := sdk.InputRequestMap{}
			for i := 0; i < maxInputRequests+1; i++ {
				m[fmt.Sprint(i)] = &sdk.ElicitParams{Mode: "form", Message: "q", RequestedSchema: map[string]any{"type": "object"}}
			}
			return &sdk.CallToolResult{InputRequests: m, RequestState: "s"}, nil
		})
		s.AddTool(&sdk.Tool{Name: "eight", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			if req.Params.InputResponses != nil {
				return textResult(fmt.Sprintf("answered %d", len(req.Params.InputResponses))), nil
			}
			m := sdk.InputRequestMap{}
			for i := 0; i < maxInputRequests; i++ {
				m[fmt.Sprint(i)] = &sdk.ElicitParams{Mode: "form", Message: "q", RequestedSchema: map[string]any{"type": "object"}}
			}
			return &sdk.CallToolResult{InputRequests: m, RequestState: "s"}, nil
		})
	}
	up := newUpstream(t, []string{"2026-07-28"}, extra)
	sn := baseSnapshot(t, func(f *config.File) { resOf(f, "gitea").Protocol = []string{"2026-07-28"} })
	h := newHarness(t, sn, map[string]*upstream{giteaUp: up}, nil)
	for _, v := range []string{"2025-11-25", "2026-07-28"} {
		var asked atomic.Int64
		opts := &sdk.ClientOptions{ElicitationHandler: func(context.Context, *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
			asked.Add(1)
			return &sdk.ElicitResult{Action: "accept", Content: map[string]any{}}, nil
		}}
		cs, _ := h.connect("alice", clientOpts{version: v, opts: opts})
		r, err := call(t, cs, "flood", nil)
		if err == nil && (r == nil || !r.IsError || strings.Contains(resultText(r), "ANSWERED")) {
			t.Errorf("%s: 9 input requests passed: %v", v, resultTextOr(r))
		}
		if asked.Load() != 0 {
			t.Errorf("%s: the person was asked %d times", v, asked.Load())
		}
		if r, err := call(t, cs, "eight", nil); err != nil || resultText(r) != "answered 8" {
			t.Errorf("%s: 8 input requests: %v %v", v, resultTextOr(r), err)
		}
	}
	if d := h.decisions("tools/call"); !slices.Contains(d, "deny:too_many_inputs") {
		t.Errorf("decisions %v", d)
	}
}

func TestDownstreamSessionsCapped(t *testing.T) {
	up := newUpstream(t, []string{"2025-11-25"}, nil)
	h := newHarness(t, baseSnapshot(t, nil), map[string]*upstream{giteaUp: up}, nil)
	var sessions []*sdk.ClientSession
	for i := 0; i < maxSessionsPerKey; i++ {
		cs, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
		if _, err := call(t, cs, "list_issues", nil); err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, cs)
	}
	csb, _ := h.connect("bob", clientOpts{version: "2025-11-25"})
	h.sn.Load().Creds[config.CredKey{Instance: "gitea", Companion: "gitea", User: "bob"}] = config.Cred{ID: "8", Secret: "b0b"}
	if n := h.b.livePooled("alice"); n != maxSessionsPerKey {
		t.Fatalf("alice has %d links", n)
	}
	_, _, before := up.snapshot()
	deletes := func(ms []string) int {
		n := 0
		for _, m := range ms {
			if m == "DELETE" {
				n++
			}
		}
		return n
	}
	// The 17th initialize evicts the oldest session and its upstream session.
	last, _ := h.connect("alice", clientOpts{version: "2025-11-25"})
	if _, err := call(t, last, "list_issues", nil); err != nil {
		t.Fatal(err)
	}
	if n := h.b.liveSessions(key{user: "alice", url: "https://gitea.example.com/mcp"}); n != maxSessionsPerKey {
		t.Errorf("alice has %d live sessions", n)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, ms := up.snapshot()
		if deletes(ms) > deletes(before) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the evicted session's upstream session was not closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := call(t, sessions[0], "list_issues", nil); err == nil {
		t.Error("the evicted (oldest) session still works")
	}
	for _, cs := range sessions[1:] {
		if _, err := call(t, cs, "list_issues", nil); err != nil {
			t.Errorf("a newer session was evicted: %v", err)
		}
	}
	if _, err := call(t, csb, "list_issues", nil); err != nil {
		t.Errorf("bob was affected: %v", err)
	}
}

type countRT struct{ n atomic.Int64 }

func (c *countRT) RoundTrip(r *http.Request) (*http.Response, error) {
	c.n.Add(1)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}, Request: r}, nil
}

func TestTransportExactUpstreamPath(t *testing.T) {
	sn := baseSnapshot(t, nil)
	res := resOf(sn.File, "gitea")
	base := &countRT{}
	tr := Transport(base, func() *config.Snapshot { return sn }, res, "alice", nil)
	for _, u := range []string{
		"http://portcullis-mcp-gitea--gitea:8080/other",
		"http://portcullis-mcp-gitea--gitea:8080/mcp/",
		"http://portcullis-mcp-gitea--gitea:8080/mcp?x=1",
		"http://portcullis-mcp-gitea--gitea:8080/%6Dcp",
		"http://portcullis-mcp-gitea--gitea:8080/",
		"http://portcullis-mcp-gitea--gitea:8081/mcp",
		"https://portcullis-mcp-gitea--gitea:8080/mcp",
	} {
		req, _ := http.NewRequest("POST", u, strings.NewReader("{}"))
		if _, err := tr.RoundTrip(req); err == nil {
			t.Errorf("%s: sent", u)
		}
	}
	if base.n.Load() != 0 {
		t.Fatalf("%d requests reached the base transport", base.n.Load())
	}
	req, _ := http.NewRequest("POST", "http://portcullis-mcp-gitea--gitea:8080/mcp", strings.NewReader("{}"))
	if _, err := tr.RoundTrip(req); err != nil || base.n.Load() != 1 {
		t.Errorf("the upstream's own path: %v", err)
	}
}
