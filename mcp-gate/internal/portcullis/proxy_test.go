package portcullis

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/config"
)

const secret = "test-hub-secret-0123456789abcdefghijkl"

type seen struct {
	path   string
	method string
	header http.Header
	body   string
}

// fakeHub records every request the gate sends to the Hub's MCP listener.
type fakeHub struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []seen
}

func newFakeHub(t *testing.T, h http.Handler) *fakeHub {
	f := &fakeHub{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, seen{path: r.URL.Path, method: r.Method, header: r.Header.Clone(), body: string(b)})
		f.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		w.Header().Set("Set-Cookie", "hub=1; Path=/")
		if h != nil {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Hub-Internal", "nope")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHub) requests() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.got)
}

func vector(t *testing.T) *config.File {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/mcp-gate.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.DecodeFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func kind(f *config.File, k string) *config.Resource {
	for i := range f.Resources {
		if f.Resources[i].Kind == k {
			return &f.Resources[i]
		}
	}
	return nil
}

// The headers the Hub may see at all: the transport's, the MCP headers
// and the four of §15.7.
var allowed = []string{
	"Accept", "Content-Type", "Content-Length", "User-Agent", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Mcp-Session-Id",
	"X-Portcullis-Mcp-Secret", "X-Forwarded-User", "X-Portcullis-Ai-Client", "X-Portcullis-Ai-Resource",
}

func checkHeaders(t *testing.T, h http.Header, user, client, resource string) {
	t.Helper()
	for k := range h {
		if !slices.Contains(allowed, http.CanonicalHeaderKey(k)) && !strings.HasPrefix(http.CanonicalHeaderKey(k), "Mcp-Param-") {
			t.Errorf("the Hub got %s: %q", k, h.Values(k))
		}
	}
	for k, want := range map[string]string{
		"X-Portcullis-Mcp-Secret": secret, "X-Forwarded-User": user,
		"X-Portcullis-Ai-Client": client, "X-Portcullis-Ai-Resource": resource,
	} {
		if v := h.Values(k); len(v) != 1 || v[0] != want {
			t.Errorf("%s = %q, want exactly %q", k, v, want)
		}
	}
}

func hostileRequest(host, body string) *http.Request {
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	r.Host = host
	r.Header.Set("Authorization", "Bearer the-persons-token")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	r.Header.Set("Mcp-Method", "tools/list")
	r.Header.Set("Cookie", "portcullis=1")
	r.Header.Set("Proxy-Authorization", "Basic eA==")
	r.Header.Set("X-Portcullis-MCP-Secret", "client-guess")
	r.Header.Add("X-Forwarded-User", "root")
	r.Header.Set("X-Forwarded-Email", "root@example.com")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.Header.Set("X-Forwarded-Host", "hub.example.com")
	r.Header.Set("X-Auth-Request-Groups", "lldap_admin")
	r.Header.Set("Remote-User", "root")
	r.Header.Set("X-Portcullis-AI-Client", "portcullis-hub")
	r.Header.Set("X-Portcullis-AI-Resource", "https://hub.example.com/mcp")
	r.Header.Set("X-Portcullis-Gate-Request", "req-1")
	r.Header.Set("Last-Event-Id", "client-made")
	return r
}

// TestPortcullisProxy: hub.<d>/mcp → /mcp/admin, people.<d>/mcp →
// /mcp/people, with exactly the secret, the person, the client and the
// resource (§15.7) plus the MCP headers; nothing the client sent of these
// passes; no cookie comes back.
func TestPortcullisProxy(t *testing.T) {
	f := vector(t)
	hub := newFakeHub(t, nil)
	p := Proxy(hub.srv.URL, secret)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	for _, tc := range []struct{ kind, host, path string }{
		{config.KindAdmin, "hub.example.com", "/mcp/admin"},
		{config.KindPeople, "people.example.com", "/mcp/people"},
	} {
		res := kind(f, tc.kind)
		w := httptest.NewRecorder()
		p(w, hostileRequest(tc.host, body), authz.Decision{Status: 200, Reason: "allow", User: "alice", Client: "portcullis-ai-claude", Resource: res})
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", tc.kind, w.Code, w.Body)
		}
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Hub-Internal") != "" {
			t.Errorf("%s: answer headers %v", tc.kind, w.Header())
		}
		if !strings.Contains(w.Body.String(), `"tools":[]`) {
			t.Errorf("%s: body %s", tc.kind, w.Body)
		}
		got := hub.requests()
		last := got[len(got)-1]
		if last.path != tc.path || last.method != "POST" || last.body != body {
			t.Errorf("%s: Hub got %s %s %q", tc.kind, last.method, last.path, last.body)
		}
		checkHeaders(t, last.header, "alice", "portcullis-ai-claude", res.URL)
		if last.header.Get("Mcp-Protocol-Version") != "2026-07-28" || last.header.Get("Mcp-Method") != "tools/list" {
			t.Errorf("%s: MCP headers lost: %v", tc.kind, last.header)
		}
	}
	if n := len(hub.requests()); n != 2 {
		t.Fatalf("%d Hub requests", n)
	}

	// Anything but the two Portcullis kinds is never sent anywhere.
	for _, k := range []string{config.KindCompanion, config.KindAggregate} {
		w := httptest.NewRecorder()
		p(w, hostileRequest("mcp.example.com", body), authz.Decision{Status: 200, User: "alice", Client: "portcullis-ai-claude", Resource: kind(f, k)})
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d", k, w.Code)
		}
	}
	// A refused decision or no person is never sent either.
	for _, d := range []authz.Decision{
		{Status: 403, User: "alice", Resource: kind(f, config.KindAdmin)},
		{Status: 200, User: "", Resource: kind(f, config.KindAdmin)},
		{Status: 200, User: "alice"},
	} {
		w := httptest.NewRecorder()
		p(w, hostileRequest("hub.example.com", body), d)
		if w.Code != http.StatusForbidden {
			t.Errorf("%+v: %d", d, w.Code)
		}
	}
	if n := len(hub.requests()); n != 2 {
		t.Fatalf("refused requests reached the Hub: %d", n)
	}
}

// The Hub down is a 502 with nothing from the Hub; a redirect is never
// followed; an over-long answer is cut.
func TestPortcullisProxyFailures(t *testing.T) {
	f := vector(t)
	d := authz.Decision{Status: 200, User: "alice", Client: "portcullis-ai-claude", Resource: kind(f, config.KindPeople)}
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	down := httptest.NewServer(http.NotFoundHandler())
	url := down.URL
	down.Close()
	h, err := New(url, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if st := h.Serve(w, hostileRequest("people.example.com", body), d); st != 0 || w.Code != http.StatusBadGateway {
		t.Errorf("Hub down: upstream %d, answer %d", st, w.Code)
	}

	target := newFakeHub(t, nil)
	redirect := newFakeHub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+"/mcp/admin", http.StatusTemporaryRedirect)
	}))
	h, _ = New(redirect.srv.URL, secret, nil)
	w = httptest.NewRecorder()
	h.Serve(w, hostileRequest("people.example.com", body), d)
	if len(target.requests()) != 0 {
		t.Errorf("a redirect was followed")
	}

	big := newFakeHub(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.Repeat("x", 2048))
	}))
	h, _ = New(big.srv.URL, secret, nil)
	h.maxResult = 1024
	w = httptest.NewRecorder()
	h.Serve(w, hostileRequest("people.example.com", body), d)
	if w.Body.Len() > 1024 {
		t.Errorf("answer not bounded: %d bytes", w.Body.Len())
	}

	if _, err := New("http://hub:8890", "short", nil); err == nil {
		t.Errorf("a short secret was accepted")
	}
	if _, err := New("http://hub:8890/x", secret, nil); err == nil {
		t.Errorf("a URL with a path was accepted")
	}
}

// People: the aggregate's SDK client to /mcp/people carries the same four
// headers, and the people resource URL.
func TestPeopleSession(t *testing.T) {
	f := vector(t)
	s := sdk.NewServer(&sdk.Implementation{Name: "portcullis", Version: "1"}, nil)
	s.AddTool(&sdk.Tool{Name: "my_apps", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "apps"}}}, nil
	})
	sh := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, DisableLocalhostProtection: true})
	hub := newFakeHub(t, sh)
	h, err := New(hub.srv.URL, secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	people := kind(f, config.KindPeople)
	cs, err := h.People(ctx, "bob", "portcullis-ai-generic", people.URL)
	if err != nil {
		t.Fatal(err)
	}
	r, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "my_apps", Arguments: map[string]any{}})
	if err != nil || r.IsError {
		t.Fatalf("%v %+v", err, r)
	}
	got := hub.requests()
	if len(got) == 0 {
		t.Fatal("no request")
	}
	for _, g := range got {
		if g.path != "/mcp/people" {
			t.Errorf("path %s", g.path)
		}
		checkHeaders(t, g.header, "bob", "portcullis-ai-generic", people.URL)
	}
	// Pooled per (person, client, resource).
	cs2, _ := h.People(ctx, "bob", "portcullis-ai-generic", people.URL)
	if cs2 != cs {
		t.Errorf("not pooled")
	}
	if _, err := h.People(ctx, "bob", "portcullis-ai-generic", kind(f, config.KindAdmin).URL); err == nil {
		t.Errorf("People opened a session on the admin resource")
	}
	h.DropUser("bob")
	cs3, _ := h.People(ctx, "bob", "portcullis-ai-generic", people.URL)
	if cs3 == cs {
		t.Errorf("DropUser kept the session")
	}
}
