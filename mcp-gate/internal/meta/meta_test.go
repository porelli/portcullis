package meta

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/portcullis/mcp-gate/internal/config"
)

func snapshot(t *testing.T) *config.Snapshot {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/mcp-gate.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.DecodeFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Snapshot{File: f}
}

func compact(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestProtectedResourceMetadata(t *testing.T) {
	sn := snapshot(t)
	h := Handler(func() *config.Snapshot { return sn })
	get := func(host, path string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		for i := 0; i < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	// Contract §15.1, byte for byte (compact form).
	want := compact(t, `{"resource": "https://gitea.example.com/mcp",
     "authorization_servers": ["https://auth.example.com/realms/portcullis"],
     "scopes_supported": ["mcp:gitea.gitea"],
     "bearer_methods_supported": ["header"],
     "resource_name": "Gitea on Portcullis"}`)
	w := get("gitea.example.com", "/.well-known/oauth-protected-resource/mcp")
	if w.Code != 200 || compact(t, w.Body.String()) != want {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	if len(w.Result().Cookies()) != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Error("a cookie was set")
	}
	// G22: a forged X-Forwarded-Host doesn't pick another resource.
	w = get("gitea.example.com", "/.well-known/oauth-protected-resource/mcp", "X-Forwarded-Host", "hub.example.com")
	if compact(t, w.Body.String()) != want {
		t.Errorf("X-Forwarded-Host was used: %s", w.Body.String())
	}
	// The fixed labels.
	w = get("mcp.example.com", "/.well-known/oauth-protected-resource/mcp")
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	if m["resource_name"] != "All my apps on Portcullis" || m["resource"] != "https://mcp.example.com/mcp" {
		t.Errorf("aggregate: %v", m)
	}
	for _, c := range [][2]string{
		{"gitea.example.com", "/.well-known/oauth-protected-resource/other"},
		{"gitea.example.com", "/.well-known/oauth-protected-resource"},
		{"gitea.example.com", "/.well-known/oauth-protected-resource/mcp/"},
		{"evil.example", "/.well-known/oauth-protected-resource/mcp"},
		{"gitea.example.com", "/mcp"},
	} {
		if w := get(c[0], c[1]); w.Code != 404 {
			t.Errorf("%s%s: %d", c[0], c[1], w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/.well-known/oauth-protected-resource/mcp", nil)
	r.Host = "gitea.example.com"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", w.Code)
	}
	// An escaped path never names a resource.
	r = httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/%6Dcp", nil)
	r.Host = "gitea.example.com"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("escaped path: %d", w.Code)
	}
	// Off or corrupt: nothing is advertised.
	for _, bad := range []*config.Snapshot{{Off: true}, {Err: errors.New("x")}, nil} {
		h := Handler(func() *config.Snapshot { return bad })
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource/mcp", nil)
		r.Host = "gitea.example.com"
		h.ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%+v: %d", bad, w.Code)
		}
	}
}
