package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/go-jose/go-jose/v4"
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

	req := func(method, host, path string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		r.Host = host
		return r
	}
	do := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// A token is refused, never logged; the challenge names the resource.
	const tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	r.Host = "gitea.example.com"
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
	if w := do(req("POST", "evil.example", "/mcp")); w.Code != 404 {
		t.Errorf("unknown resource: %d", w.Code)
	}
	if w := do(req("GET", "gitea.example.com", "/.well-known/oauth-protected-resource/mcp")); w.Code != 200 {
		t.Errorf("metadata: %d", w.Code)
	}
	// /healthz only from loopback.
	r = req("GET", "x", "/healthz")
	r.RemoteAddr = "127.0.0.1:5555"
	if w := do(r); w.Code != 200 {
		t.Errorf("healthz loopback: %d", w.Code)
	}
	r = req("GET", "gitea.example.com", "/healthz")
	r.RemoteAddr = "172.31.250.2:5555"
	if w := do(r); w.Code == 200 {
		t.Error("healthz from the proxy network")
	}
	// An escaped or absolute-form target is refused before routing, the
	// metadata path included.
	for _, target := range []string{"/%6Dcp", "/.well-known/oauth-protected-resource/%6Dcp", "https://gitea.example.com/mcp"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = "gitea.example.com"
		r.RequestURI = target
		if w := do(r); w.Code != 400 {
			t.Errorf("%s: %d", target, w.Code)
		}
	}
	// Off and corrupt → 503 for everything.
	for _, bad := range []*config.Snapshot{{Off: true}, {Err: os.ErrInvalid}} {
		h := newHandler(func() *config.Snapshot { return bad }, authz.NewVerifier("", jwks.URL, jwks.Client()))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req("POST", "gitea.example.com", "/mcp"))
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

// Fix round 1, item 6: an allowed request whose body trickles in is cut
// off at the body read deadline (408), never held open by the client.
func TestBodyReadDeadline(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	set, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(set) }))
	defer jwks.Close()
	sn := vectorSnapshot(t)
	old := bodyReadTimeout
	bodyReadTimeout = 300 * time.Millisecond
	defer func() { bodyReadTimeout = old }()
	srv := httptest.NewServer(newHandler(func() *config.Snapshot { return sn }, authz.NewVerifier("", jwks.URL, jwks.Client())))
	defer srv.Close()

	sg, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	n := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://auth.example.com/realms/portcullis", "aud": "https://gitea.example.com/mcp",
		"azp": "portcullis-ai-claude", "typ": "Bearer", "scope": "mcp:gitea.gitea", "acr": "hwk",
		"preferred_username": "alice", "exp": n.Add(5 * time.Minute).Unix(), "iat": n.Unix(),
	})
	obj, _ := sg.Sign(claims)
	tok, _ := obj.CompactSerialize()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: gitea.example.com\r\nAuthorization: Bearer %s\r\nMCP-Protocol-Version: 2025-11-25\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{", tok)
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if resp.StatusCode != http.StatusRequestTimeout {
		t.Errorf("status %d, want 408", resp.StatusCode)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("answered after %v", d)
	}
}

func TestServerTimeouts(t *testing.T) {
	s := newServer(":0", http.NotFoundHandler())
	if s.ReadHeaderTimeout <= 0 || s.ReadTimeout <= 0 || s.IdleTimeout <= 0 || s.MaxHeaderBytes <= 0 {
		t.Errorf("%+v", s)
	}
}
