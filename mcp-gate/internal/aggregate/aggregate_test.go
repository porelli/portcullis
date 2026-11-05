package aggregate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/bridge"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/limits"
	"github.com/portcullis/mcp-gate/internal/portcullis"
)

const hubSecret = "test-hub-secret-0123456789abcdefghijkl"

// ---- names (G24) ----

func TestToolNames(t *testing.T) {
	if got := ToolName("gitea", "list_issues"); got != "gitea__list_issues" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("a", 63) // "gitea__" + 63 = 70 characters
	n1 := ToolName("gitea", long)
	if len("gitea__"+long) != 70 || len(n1) != 64 {
		t.Fatalf("70 → %d: %q", len(n1), n1)
	}
	if n1 != ToolName("gitea", long) || !strings.HasPrefix(n1, ("gitea__" + long)[:55]+"_") {
		t.Errorf("not stable or not the 55-character prefix: %q", n1)
	}
	// Two names sharing their first 55 characters stay distinct.
	n2 := ToolName("gitea", strings.Repeat("a", 62)+"b")
	if n1 == n2 || n1[:55] != n2[:55] {
		t.Errorf("%q vs %q", n1, n2)
	}
	// Exactly 64 stays as it is.
	n64 := ToolName("gitea", strings.Repeat("c", 57))
	if len(n64) != 64 || n64 != "gitea__"+strings.Repeat("c", 57) {
		t.Errorf("64: %q", n64)
	}
	// Known value: sha256 of the full name, first 8 hex digits.
	if want := ("gitea__" + long)[:55] + "_" + hex8("gitea__"+long); n1 != want {
		t.Errorf("%q != %q", n1, want)
	}
}

// Collisions, literal or after shortening, drop both tools (G24).
func TestNameTableCollisions(t *testing.T) {
	long := strings.Repeat("x", 70)
	short := ToolName("gitea", long)[len("gitea__"):] // gitea__<short> == the shortened long name
	items := []Item{
		{Prefix: "gitea", URL: "g", Name: "list_issues"},
		{Prefix: "gitea", URL: "g", Name: long},
		{Prefix: "gitea", URL: "g", Name: short},
		{Prefix: "gitea", URL: "g", Name: "Dup"},
		{Prefix: "gitea", URL: "g", Name: "dup"},
		{Prefix: "grafana", URL: "f", Name: "list_issues"},
		{Prefix: "gitea", URL: "g", Name: "portcullis__my_apps"},
		{Prefix: "portcullis", URL: "p", Name: "my_apps"},
	}
	tab, dropped := BuildTable(items)
	if len(tab) != 4 {
		t.Fatalf("table %v", tab)
	}
	for name, want := range map[string]Target{
		"gitea__list_issues":         {URL: "g", Name: "list_issues"},
		"grafana__list_issues":       {URL: "f", Name: "list_issues"},
		"gitea__portcullis__my_apps": {URL: "g", Name: "portcullis__my_apps"},
		"portcullis__my_apps":        {URL: "p", Name: "my_apps"},
	} {
		if tab[name] != want {
			t.Errorf("%s → %+v, want %+v", name, tab[name], want)
		}
	}
	if len(dropped) != 4 {
		t.Errorf("dropped %v", dropped)
	}
}

// ---- the harness: fake companions, a fake Hub, the real bridge ----

type fakeUp struct {
	srv     *httptest.Server
	server  *sdk.Server
	mu      sync.Mutex
	hdrs    []http.Header
	calls   []string
	paths   []string
	delay   time.Duration
	active  *atomic.Int64
	release chan struct{} // closed at the test's end: ends every delay
	peak    *atomic.Int64
}

func (u *fakeUp) callList() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.calls)
}

func (u *fakeUp) headers() []http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.hdrs)
}

func newUpstream(t *testing.T, stateless bool, tools []string, mut func(s *sdk.Server)) *fakeUp {
	u := &fakeUp{release: make(chan struct{})}
	s := sdk.NewServer(&sdk.Implementation{Name: "companion", Version: "1"}, nil)
	for _, n := range tools {
		s.AddTool(&sdk.Tool{Name: n, Description: "does " + n, InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			u.mu.Lock()
			u.calls = append(u.calls, req.Params.Name)
			u.mu.Unlock()
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok " + req.Params.Name}}}, nil
		})
	}
	s.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method == "tools/list" && u.active != nil {
				n := u.active.Add(1)
				for {
					p := u.peak.Load()
					if n <= p || u.peak.CompareAndSwap(p, n) {
						break
					}
				}
				sleep(ctx, u.delay, u.release)
				defer u.active.Add(-1)
			} else if method == "tools/list" && u.delay > 0 {
				sleep(ctx, u.delay, u.release)
			}
			return next(ctx, method, req)
		}
	})
	if mut != nil {
		mut(s)
	}
	u.server = s
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{DisableLocalhostProtection: true})
	hs := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{DisableLocalhostProtection: true, Stateless: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hdrs = append(u.hdrs, r.Header.Clone())
		u.paths = append(u.paths, r.URL.Path)
		u.mu.Unlock()
		if stateless || r.Header.Get("Mcp-Protocol-Version") >= "2026-07-28" {
			hs.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	t.Cleanup(func() { close(u.release) }) // runs first: Close waits for the handlers
	return u
}

func sleep(ctx context.Context, d time.Duration, release chan struct{}) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	case <-release:
	}
}

// confirmer: Task 4's answer shape, scripted.
type confirmer struct {
	mu    sync.Mutex
	calls []bridge.Call
}

func (c *confirmer) Before(ctx context.Context, call bridge.Call) (bridge.Outcome, error) {
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
	url := "https://people.example.com/confirm/ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"
	return bridge.Outcome{
		Answer:   &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "This needs your confirmation in your browser: open " + url + ", then ask me to try again."}}},
		Decision: "confirm:ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ",
	}, nil
}

type harness struct {
	t      *testing.T
	sn     atomic.Pointer[config.Snapshot]
	ups    map[string]*fakeUp // host:port → fake
	hub    *fakeUp
	b      *bridge.Bridge
	a      *Aggregate
	conf   *confirmer
	gate   *httptest.Server
	reqN   atomic.Int64
	mu     sync.Mutex
	events []bridge.Event
}

const (
	giteaUp   = "portcullis-mcp-gitea--gitea:8080"
	grafanaUp = "portcullis-mcp-grafana--grafana:8000"
)

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
		slices.SortFunc(f.Resources, func(a, b config.Resource) int { return strings.Compare(a.URL, b.URL) })
		out, err := f.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if f, err = config.DecodeFile(out); err != nil {
			t.Fatalf("mutated vector refused: %v", err)
		}
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

func snapshot(f *config.File) *config.Snapshot {
	creds := map[config.CredKey]config.Cred{}
	for _, r := range f.Resources {
		if r.Kind == config.KindCompanion && r.Identity.Mode == "app_token" {
			for _, u := range r.Population {
				creds[config.CredKey{Instance: r.Instance, Companion: r.Companion, User: u}] = config.Cred{ID: "7", Secret: "cred-" + u + "-" + r.Instance}
			}
		}
	}
	return &config.Snapshot{File: f, Creds: creds, Secrets: map[string]string{"grafana/grafana": "caller-s3cret"}}
}

func peopleTools() []string {
	return []string{"my_apps", "invite_person", "update_person", "delete_person"}
}

func newHarness(t *testing.T, f *config.File, ups map[string]*fakeUp, tweak func(c *Config)) *harness {
	h := &harness{t: t, ups: ups, conf: &confirmer{}}
	h.sn.Store(snapshot(f))
	// The fake Hub: /mcp/people and /mcp/admin are two SDK servers.
	people := newUpstream(t, true, peopleTools(), nil)
	admin := newUpstream(t, true, []string{"delete_instance"}, nil)
	h.hub = &fakeUp{}
	h.hub.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hub.mu.Lock()
		h.hub.hdrs = append(h.hub.hdrs, r.Header.Clone())
		h.hub.paths = append(h.hub.paths, r.URL.Path)
		h.hub.mu.Unlock()
		switch r.URL.Path {
		case "/mcp/people":
			people.srv.Config.Handler.ServeHTTP(w, r)
		case "/mcp/admin":
			admin.srv.Config.Handler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.hub.srv.Close)
	h.hub.server = people.server

	dialer := &net.Dialer{Timeout: time.Second}
	base := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			u, ok := h.ups[addr]
			if !ok || u == nil {
				return nil, fmt.Errorf("no route to %s", addr)
			}
			return dialer.DialContext(ctx, network, u.srv.Listener.Addr().String())
		},
		DisableCompression: true,
	}
	h.b = bridge.New(bridge.Config{
		Snapshot: h.sn.Load, Base: base, Confirm: h.conf, OnEvent: h.event,
		MintWait: time.Second, MintPoll: 20 * time.Millisecond,
	})
	t.Cleanup(h.b.Close)
	ph, err := portcullis.New(h.hub.srv.URL, hubSecret, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ph.Close)
	frozen := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	cfg := Config{
		Snapshot: h.sn.Load, Bridge: h.b, Portcullis: ph, OnEvent: h.event,
		Limits: limits.New(func() config.Limits { return h.sn.Load().File.Limits }, func() time.Time { return frozen }),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	h.a = New(cfg)
	t.Cleanup(h.a.Close)
	h.gate = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := h.sn.Load()
		res, ok := s.Resource(r.Host, r.URL.Path)
		if !ok || res.Kind != config.KindAggregate {
			http.Error(w, "unknown resource", 404)
			return
		}
		loa := 2
		if v := r.Header.Get("X-Test-LoA"); v != "" {
			loa, _ = strconv.Atoi(v)
		}
		r.Header.Set(bridge.RequestIDHeader, fmt.Sprintf("req-%d", h.reqN.Add(1)))
		h.a.ServeHTTP(w, r, authz.Decision{Status: 200, Reason: "allow", User: r.Header.Get("X-Test-User"), Client: "portcullis-ai-claude", Resource: res, LoA: loa})
	}))
	t.Cleanup(h.gate.Close)
	return h
}

func (h *harness) hubPaths() []string {
	h.hub.mu.Lock()
	defer h.hub.mu.Unlock()
	return slices.Clone(h.hub.paths)
}

func (h *harness) event(e bridge.Event) {
	h.mu.Lock()
	h.events = append(h.events, e)
	h.mu.Unlock()
}

func (h *harness) eventList() []bridge.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.events)
}

type clientRT struct{ user, loa string }

func (c *clientRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = "mcp.example.com"
	r.Header.Set("Authorization", "Bearer the-persons-token")
	r.Header.Set("X-Test-User", c.user)
	if c.loa != "" {
		r.Header.Set("X-Test-LoA", c.loa)
	}
	r.Header.Set("X-Forwarded-User", "root") // hostile
	return http.DefaultTransport.RoundTrip(r)
}

func (h *harness) connect(user, version, loa string, opts *sdk.ClientOptions) *sdk.ClientSession {
	h.t.Helper()
	c := sdk.NewClient(&sdk.Implementation{Name: "person", Version: "1"}, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cs, err := c.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: h.gate.URL + "/mcp", HTTPClient: &http.Client{Transport: &clientRT{user: user, loa: loa}}, MaxRetries: -1}, &sdk.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		h.t.Fatalf("connect %s: %v", user, err)
	}
	h.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func ctx20(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func toolMap(t *testing.T, cs *sdk.ClientSession) map[string]*sdk.Tool {
	t.Helper()
	out := map[string]*sdk.Tool{}
	for tool, err := range cs.Tools(ctx20(t), nil) {
		if err != nil {
			t.Fatal(err)
		}
		out[tool.Name] = tool
	}
	return out
}

func names(m map[string]*sdk.Tool) []string {
	var out []string
	for n := range m {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
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

var giteaTools = []string{"list_issues", "create_issue", "delete_repo"}
var grafanaTools = []string{"search_dashboards", "create_dashboard"}

func twoApps(t *testing.T) map[string]*fakeUp {
	return map[string]*fakeUp{
		giteaUp:   newUpstream(t, false, giteaTools, nil),
		grafanaUp: newUpstream(t, false, grafanaTools, nil),
	}
}

// ---- tests ----

func TestAggregateList(t *testing.T) {
	for _, v := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(v, func(t *testing.T) {
			h := newHarness(t, vectorFile(t, nil), twoApps(t), nil)
			alice := toolMap(t, h.connect("alice", v, "", nil))
			// gitea read_write: every tool; grafana read_only: writes
			// hidden; the people tools without the delegate ones (G38).
			want := []string{"gitea__create_issue", "gitea__delete_repo", "gitea__list_issues", "grafana__search_dashboards", "portcullis__my_apps"}
			if got := names(alice); !slices.Equal(got, want) {
				t.Fatalf("alice: %v", got)
			}
			if d := alice["gitea__list_issues"].Description; d != "[Gitea · gitea.example.com] does list_issues" {
				t.Errorf("description %q", d)
			}
			if d := alice["grafana__search_dashboards"].Description; d != "[Grafana · grafana.example.com] does search_dashboards" {
				t.Errorf("description %q", d)
			}
			if d := alice["portcullis__my_apps"].Description; d != "[Portcullis · people.example.com] does my_apps" {
				t.Errorf("description %q", d)
			}
			bob := toolMap(t, h.connect("bob", v, "", nil))
			if got := names(bob); !slices.Equal(got, []string{"gitea__create_issue", "gitea__delete_repo", "gitea__list_issues", "portcullis__my_apps"}) {
				t.Errorf("bob: %v", got)
			}
			// Every fakeUp list ran with via aggregate, on the
			// fakeUp's own resource.
			for _, e := range h.eventList() {
				if e.Via != "aggregate" || e.Resource == "https://mcp.example.com/mcp" {
					t.Errorf("event %+v", e)
				}
			}
		})
	}
	// aggregate: false companions are absent.
	h := newHarness(t, vectorFile(t, func(f *config.File) { resOf(f, "gitea").Aggregate = false }), twoApps(t), nil)
	if got := names(toolMap(t, h.connect("alice", "", "", nil))); !slices.Equal(got, []string{"grafana__search_dashboards", "portcullis__my_apps"}) {
		t.Errorf("gitea aggregate false: %v", got)
	}
	if n := len(h.ups[giteaUp].headers()); n != 0 {
		t.Errorf("gitea was asked %d times", n)
	}
}

// Review Focus 1: a population change drops the app from the person's
// next list, even within the 60 s cache, and tells subscribed clients.
func TestAggregateDropsAppOnPopulationChange(t *testing.T) {
	for _, v := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(v, func(t *testing.T) {
			h := newHarness(t, vectorFile(t, nil), twoApps(t), nil)
			changed := make(chan struct{}, 16)
			cs := h.connect("alice", v, "", &sdk.ClientOptions{ToolListChangedHandler: func(context.Context, *sdk.ToolListChangedRequest) {
				changed <- struct{}{}
			}})
			if _, ok := toolMap(t, cs)["grafana__search_dashboards"]; !ok {
				t.Fatal("no grafana tool before")
			}
			time.Sleep(100 * time.Millisecond)
			for len(changed) > 0 {
				<-changed
			}
			without := func() *config.Snapshot {
				return snapshot(vectorFile(t, func(f *config.File) {
					g := resOf(f, "grafana")
					g.Population = []string{}
					g.People = map[string]config.Person{}
				}))
			}
			drain := func() {
				time.Sleep(100 * time.Millisecond)
				for len(changed) > 0 {
					<-changed
				}
			}
			// 1. Within the cache, without any reconcile: the next list
			// already has no grafana tool.
			h.sn.Store(without())
			got := toolMap(t, cs)
			if _, ok := got["grafana__search_dashboards"]; ok {
				t.Errorf("grafana still listed: %v", names(got))
			}
			if _, ok := got["gitea__list_issues"]; !ok {
				t.Errorf("gitea lost: %v", names(got))
			}
			// 2. Back in, then out again: the reconcile on the snapshot
			// change alone tells her client, before she lists.
			h.sn.Store(snapshot(vectorFile(t, nil)))
			if _, ok := toolMap(t, cs)["grafana__search_dashboards"]; !ok {
				t.Fatal("grafana not back")
			}
			drain()
			h.sn.Store(without())
			h.a.Reconcile()
			select {
			case <-changed:
			case <-time.After(3 * time.Second):
				t.Errorf("no notifications/tools/list_changed")
			}
			if _, ok := toolMap(t, cs)["grafana__search_dashboards"]; ok {
				t.Errorf("grafana listed after the reconcile")
			}
			r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "grafana__search_dashboards"})
			if err == nil && !r.IsError {
				t.Errorf("grafana call after leaving: %+v", r)
			}
			if c := h.ups[grafanaUp].callList(); len(c) != 0 {
				t.Errorf("grafana called %v", c)
			}
		})
	}
}

// LoA per fakeUp: the fakeUp's own min_loa against the token's acr.
func TestAggregateLoAPerUpstream(t *testing.T) {
	f := vectorFile(t, nil)
	h := newHarness(t, f, twoApps(t), nil)
	// grafana min_loa 3 (above what any file may say; the check holds
	// anyway); the token's acr is hwk (2).
	next := vectorFile(t, nil)
	resOf(next, "grafana").MinLoA = 3
	h.sn.Store(snapshot(next))
	cs := h.connect("alice", "2025-11-25", "2", nil)
	got := toolMap(t, cs)
	if _, ok := got["grafana__search_dashboards"]; ok {
		t.Errorf("grafana listed: %v", names(got))
	}
	r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "grafana__search_dashboards"})
	if err == nil && !r.IsError {
		t.Errorf("call allowed: %+v", r)
	}
	if n := len(h.ups[grafanaUp].headers()); n != 0 {
		t.Errorf("grafana was asked %d times", n)
	}
	// A table built while grafana was allowed: the call is still refused
	// once its min_loa is above the token's.
	h.sn.Store(snapshot(f))
	cs2 := h.connect("alice", "2025-11-25", "2", nil)
	if _, ok := toolMap(t, cs2)["grafana__search_dashboards"]; !ok {
		t.Fatal("grafana missing at LoA 2")
	}
	before := len(h.ups[grafanaUp].callList())
	h.sn.Store(snapshot(next))
	r, err = cs2.CallTool(ctx20(t), &sdk.CallToolParams{Name: "grafana__search_dashboards"})
	if err == nil && !r.IsError {
		t.Errorf("call allowed after the LoA rose: %+v", r)
	}
	if len(h.ups[grafanaUp].callList()) != before {
		t.Errorf("grafana called")
	}
}

func TestAggregateUpstreamDown(t *testing.T) {
	ups := twoApps(t)
	ups[grafanaUp] = nil // unreachable
	h := newHarness(t, vectorFile(t, nil), ups, nil)
	for _, v := range []string{"2025-11-25", "2026-07-28"} {
		cs := h.connect("alice", v, "", nil)
		if ins := cs.InitializeResult().Instructions; !strings.Contains(ins, "Grafana is unavailable right now") {
			t.Errorf("%s instructions %q", v, ins)
		}
		got := names(toolMap(t, cs))
		if !slices.Contains(got, "gitea__list_issues") || slices.Contains(got, "grafana__search_dashboards") {
			t.Errorf("%s: %v", v, got)
		}
		r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "gitea__list_issues"})
		if err != nil || r.IsError || text(r) != "ok list_issues" {
			t.Errorf("%s gitea call: %v %+v", v, err, r)
		}
	}
}

func TestAggregateCallRouting(t *testing.T) {
	h := newHarness(t, vectorFile(t, nil), twoApps(t), nil)
	cs := h.connect("alice", "2025-11-25", "", nil)
	r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "gitea__list_issues", Arguments: map[string]any{"b": 1, "a": "x"}})
	if err != nil || r.IsError || text(r) != "ok list_issues" {
		t.Fatalf("%v %+v", err, r)
	}
	gitea := h.ups[giteaUp]
	if c := gitea.callList(); !slices.Equal(c, []string{"list_issues"}) {
		t.Errorf("gitea calls %v", c)
	}
	// alice's identity, nothing of the client's.
	for _, hd := range gitea.headers() {
		if hd.Get("Authorization") != "token cred-alice-gitea" || hd.Get("X-Forwarded-User") != "" {
			t.Errorf("gitea headers %v", hd)
		}
	}
	var call *bridge.Event
	for _, e := range h.eventList() {
		if e.Method == "tools/call" {
			e := e
			call = &e
		}
	}
	if call == nil || call.Resource != "https://gitea.example.com/mcp" || call.Via != "aggregate" || call.Tool != "list_issues" ||
		call.User != "alice" || call.Instance != "gitea" || call.Decision != "allow" || string(call.Args) != `{"a":"x","b":1}` || call.RequestID == "" {
		t.Errorf("event %+v", call)
	}
	// A confirm tool: the same confirmation as Task 4, bound to gitea.
	r, err = cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "gitea__delete_repo", Arguments: map[string]any{"repo": "x"}})
	if err != nil || !r.IsError || !strings.HasPrefix(text(r), "This needs your confirmation in your browser: open https://people.example.com/confirm/") {
		t.Fatalf("%v %+v", err, r)
	}
	h.conf.mu.Lock()
	cc := slices.Clone(h.conf.calls)
	h.conf.mu.Unlock()
	if len(cc) != 1 || cc[0].Resource.URL != "https://gitea.example.com/mcp" || cc[0].Tool != "delete_repo" || cc[0].User != "alice" || cc[0].Reason != "confirm" {
		t.Errorf("confirmer got %+v", cc)
	}
	if c := gitea.callList(); slices.Contains(c, "delete_repo") {
		t.Errorf("delete_repo reached gitea")
	}
	evs := h.eventList()
	last := evs[len(evs)-1]
	if last.Decision != "confirm:ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ" || last.Via != "aggregate" || last.Resource != "https://gitea.example.com/mcp" {
		t.Errorf("confirm event %+v", last)
	}
	// The people tool: the Hub's /mcp/people with alice's identity.
	r, err = cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "portcullis__my_apps"})
	if err != nil || r.IsError || text(r) != "ok my_apps" {
		t.Fatalf("my_apps: %v %+v", err, r)
	}
	evs = h.eventList()
	last = evs[len(evs)-1]
	if last.Resource != "https://people.example.com/mcp" || last.Via != "aggregate" || last.Tool != "my_apps" || last.Decision != "allow" || last.UpstreamStatus != 200 {
		t.Errorf("people event %+v", last)
	}
	// Unknown names never reach anything.
	n := len(gitea.headers())
	for _, name := range []string{"gitea__nope", "list_issues", "gitea_list_issues", "portcullis__invite_person", "portcullis__delete_instance"} {
		r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: name})
		if err == nil && !r.IsError {
			t.Errorf("%s answered %+v", name, r)
		}
	}
	if len(gitea.headers()) != n {
		t.Errorf("an unknown name reached gitea")
	}
}

// At most fanout fakeUp list calls at once per request, and a bounded
// total time.
func TestAggregateFanout(t *testing.T) {
	var active, peak atomic.Int64
	ups := twoApps(t)
	f := vectorFile(t, func(f *config.File) {
		g := *resOf(f, "gitea")
		for i := 1; i <= 6; i++ {
			r := g
			id := fmt.Sprintf("app%d", i)
			r.URL, r.Scope, r.Instance, r.Companion = "https://"+id+".example.com/mcp", "mcp:"+id+"."+id, id, id
			r.Host, r.Hosts, r.AppURL = id+".example.com", []string{id + ".example.com"}, "https://"+id+".example.com"
			r.Upstream = "http://portcullis-mcp-" + id + "--" + id + ":8080/mcp"
			r.Label = "App " + strconv.Itoa(i)
			f.Resources = append(f.Resources, r)
		}
	})
	for i := 1; i <= 6; i++ {
		u := newUpstream(t, false, []string{"thing"}, nil)
		u.active, u.peak, u.delay = &active, &peak, 150*time.Millisecond
		ups[fmt.Sprintf("portcullis-mcp-app%d--app%d:8080", i, i)] = u
	}
	for _, u := range []*fakeUp{ups[giteaUp], ups[grafanaUp]} {
		u.active, u.peak, u.delay = &active, &peak, 150*time.Millisecond
	}
	h := newHarness(t, f, ups, nil)
	got := names(toolMap(t, h.connect("alice", "2025-11-25", "", nil)))
	if len(got) != 6+3+1+1 {
		t.Errorf("tools %v", got)
	}
	if p := peak.Load(); p > 4 || p < 2 {
		t.Errorf("peak concurrent upstream lists %d", p)
	}

	// Bounded time: one fakeUp hangs; the endpoint answers in time,
	// listing it as unavailable.
	slow := twoApps(t)
	slow[grafanaUp].delay = 30 * time.Second
	h = newHarness(t, vectorFile(t, nil), slow, func(c *Config) { c.ListTimeout = time.Second })
	start := time.Now()
	cs := h.connect("alice", "2025-11-25", "", nil)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("initialize took %s", d)
	}
	if ins := cs.InitializeResult().Instructions; !strings.Contains(ins, "Grafana is unavailable right now") {
		t.Errorf("instructions %q", ins)
	}
}

// G38 and §15.9: the aggregate's Portcullis fakeUp is /mcp/people,
// never /mcp/admin, even for root; delegate tools are never in it.
func TestAggregateNeverHasAdminTools(t *testing.T) {
	h := newHarness(t, vectorFile(t, nil), twoApps(t), nil)
	cs := h.connect("root", "2026-07-28", "", nil)
	got := names(toolMap(t, cs))
	for _, n := range got {
		if strings.Contains(n, "delete_instance") || strings.Contains(n, "invite_person") || strings.Contains(n, "update_person") || strings.Contains(n, "delete_person") {
			t.Errorf("listed %s", n)
		}
	}
	if !slices.Contains(got, "portcullis__my_apps") {
		t.Errorf("no people tool: %v", got)
	}
	for _, name := range []string{"portcullis__invite_person", "portcullis__update_person", "portcullis__delete_person", "portcullis__delete_instance"} {
		r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: name})
		if err == nil && !r.IsError {
			t.Errorf("%s answered", name)
		}
	}
	paths := h.hubPaths()
	if len(paths) == 0 {
		t.Fatal("the Hub was never asked")
	}
	for _, p := range paths {
		if p != "/mcp/people" {
			t.Errorf("the aggregate asked the Hub's %s", p)
		}
	}
	h.hub.mu.Lock()
	hdrs := slices.Clone(h.hub.hdrs)
	h.hub.mu.Unlock()
	for _, hd := range hdrs {
		if hd.Get("X-Portcullis-Ai-Resource") != "https://people.example.com/mcp" || hd.Get("X-Forwarded-User") != "root" || hd.Get("X-Portcullis-Mcp-Secret") != hubSecret {
			t.Errorf("Hub headers %v", hd)
		}
	}
}

// A companion can't take over another app's or a Portcullis tool's name.
func TestAggregateNamesNotSpoofable(t *testing.T) {
	ups := twoApps(t)
	ups[giteaUp] = newUpstream(t, false, []string{"list_issues", "portcullis__my_apps", "grafana__search_dashboards"}, nil)
	h := newHarness(t, vectorFile(t, nil), ups, nil)
	cs := h.connect("alice", "2025-11-25", "", nil)
	got := names(toolMap(t, cs))
	for _, n := range []string{"gitea__portcullis__my_apps", "gitea__grafana__search_dashboards", "portcullis__my_apps", "grafana__search_dashboards"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s missing: %v", n, got)
		}
	}
	r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "portcullis__my_apps"})
	if err != nil || text(r) != "ok my_apps" {
		t.Errorf("%v %+v", err, r)
	}
	r, err = cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "grafana__search_dashboards"})
	if err != nil || text(r) != "ok search_dashboards" {
		t.Errorf("%v %+v", err, r)
	}
	if c := ups[giteaUp].callList(); len(c) != 0 {
		t.Errorf("gitea got %v", c)
	}
	if c := ups[grafanaUp].callList(); !slices.Equal(c, []string{"search_dashboards"}) {
		t.Errorf("grafana got %v", c)
	}
}

// Per-fakeUp limits: the fakeUp's own per-resource limits apply.
func TestAggregatePerUpstreamLimits(t *testing.T) {
	f := vectorFile(t, func(f *config.File) { f.Limits.ToolCallsRPM = 2 })
	h := newHarness(t, f, twoApps(t), nil)
	cs := h.connect("alice", "2025-11-25", "", nil)
	for i := 0; i < 2; i++ {
		if r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "gitea__list_issues"}); err != nil || r.IsError {
			t.Fatalf("%d: %v %+v", i, err, r)
		}
	}
	r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "gitea__list_issues"})
	if err == nil && !r.IsError {
		t.Errorf("3rd gitea call allowed")
	}
	evs := h.eventList()
	if last := evs[len(evs)-1]; last.Decision != "rate_limited" || last.Resource != "https://gitea.example.com/mcp" {
		t.Errorf("event %+v", last)
	}
	// Another fakeUp has its own budget.
	if r, err := cs.CallTool(ctx20(t), &sdk.CallToolParams{Name: "grafana__search_dashboards"}); err != nil || r.IsError {
		t.Errorf("grafana: %v %+v", err, r)
	}
	if c := h.ups[giteaUp].callList(); len(c) != 2 {
		t.Errorf("gitea calls %v", c)
	}
}

// The aggregate refuses outsiders, other kinds and refused decisions.
func TestAggregateRefusals(t *testing.T) {
	f := vectorFile(t, nil)
	h := newHarness(t, f, twoApps(t), nil)
	var agg, gitea *config.Resource
	for i := range f.Resources {
		switch f.Resources[i].Kind {
		case config.KindAggregate:
			agg = &f.Resources[i]
		}
	}
	gitea = resOf(f, "gitea")
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	for name, d := range map[string]authz.Decision{
		"refused":     {Status: 403, User: "alice", Resource: agg, LoA: 2},
		"no user":     {Status: 200, User: "", Resource: agg, LoA: 2},
		"outsider":    {Status: 200, User: "mallory", Resource: agg, LoA: 2},
		"companion":   {Status: 200, User: "alice", Resource: gitea, LoA: 2},
		"no resource": {Status: 200, User: "alice", LoA: 2},
	} {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		r.Header.Set("Mcp-Protocol-Version", "2025-11-25")
		w := httptest.NewRecorder()
		h.a.ServeHTTP(w, r, d)
		if w.Code == 200 {
			t.Errorf("%s: 200", name)
		}
		_, _ = io.Copy(io.Discard, w.Body)
	}
}
