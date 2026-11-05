package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/config"
)

func vectorSnapshot(t *testing.T) *config.Snapshot {
	t.Helper()
	b, err := os.ReadFile("internal/config/testdata/mcp-gate.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.DecodeFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Snapshot{File: f}
}

func TestHandler(t *testing.T) {
	sn := vectorSnapshot(t)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"keys":[]}`)) }))
	defer jwks.Close()
	h := newHandler(func() *config.Snapshot { return sn }, authz.NewVerifier("", jwks.URL, jwks.Client()))
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	do := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// A token is refused, never logged; the challenge names the resource.
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	r := httptest.NewRequest("POST", "http://gitea.example.com/mcp", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("X-Forwarded-Host", "hub.example.com")
	w := do(r)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "https://gitea.example.com/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("%d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if strings.Contains(logs.String(), tok[:20]) {
		t.Error("the token was logged")
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Error("a cookie was set")
	}
	// Unknown resource → 404; metadata served.
	if w := do(httptest.NewRequest("POST", "http://evil.example/mcp", nil)); w.Code != 404 {
		t.Errorf("unknown resource: %d", w.Code)
	}
	if w := do(httptest.NewRequest("GET", "http://gitea.example.com/.well-known/oauth-protected-resource/mcp", nil)); w.Code != 200 {
		t.Errorf("metadata: %d", w.Code)
	}
	// /healthz only from loopback.
	r = httptest.NewRequest("GET", "http://x/healthz", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	if w := do(r); w.Code != 200 {
		t.Errorf("healthz loopback: %d", w.Code)
	}
	r = httptest.NewRequest("GET", "http://gitea.example.com/healthz", nil)
	r.RemoteAddr = "172.31.250.2:5555"
	if w := do(r); w.Code == 200 {
		t.Error("healthz from the proxy network")
	}
	// Off and corrupt → 503 for everything.
	for _, bad := range []*config.Snapshot{{Off: true}, {Err: os.ErrInvalid}} {
		h := newHandler(func() *config.Snapshot { return bad }, authz.NewVerifier("", jwks.URL, jwks.Client()))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "http://gitea.example.com/mcp", nil))
		if w.Code != 503 {
			t.Errorf("%+v: %d", bad, w.Code)
		}
	}
}

func TestHubSecretLength(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/s"
	_ = os.WriteFile(p, []byte(strings.Repeat("a", 31)+"\n"), 0o600)
	if _, err := loadHubSecret(p); err == nil {
		t.Error("31 characters accepted")
	}
	_ = os.WriteFile(p, []byte(strings.Repeat("a", 48)+"\n"), 0o600)
	if s, err := loadHubSecret(p); err != nil || len(s) != 48 {
		t.Errorf("48: %v", err)
	}
}
