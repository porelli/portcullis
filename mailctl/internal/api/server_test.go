package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secretA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const secretB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newServer(t *testing.T, subnet string) (*Server, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "hub-secret")
	if err := os.WriteFile(f, []byte(secretA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Server{
		Subnet:     netip.MustParsePrefix(subnet),
		SecretFile: f,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("v1"))
		}),
	}, f
}

// do serves one request as if it arrived on local address ip.
func do(s *Server, ip, method, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP(ip), Port: 8080}))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAPIRefusesOutsideSubnet(t *testing.T) {
	s, _ := newServer(t, "172.31.255.16/28")
	for _, ip := range []string{"172.31.255.3", "172.31.250.4", "10.0.0.1", "127.0.0.1"} {
		w := do(s, ip, "GET", "/v1/state", "Bearer "+secretA)
		if w.Code != 403 || w.Body.Len() != 0 {
			t.Errorf("%s: %d %q", ip, w.Code, w.Body.String())
		}
	}
	if w := do(s, "172.31.255.19", "GET", "/v1/state", "Bearer "+secretA); w.Code != 200 || w.Body.String() != "v1" {
		t.Fatalf("inside: %d %q", w.Code, w.Body.String())
	}
	// A real connection on loopback (outside the subnet) is refused too.
	srv := httptest.NewServer(s)
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+secretA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 403 {
		t.Fatalf("loopback connection: %v %v", resp, err)
	}
}

func TestAPIRefusesBadBearer(t *testing.T) {
	s, _ := newServer(t, "172.31.255.16/28")
	for _, auth := range []string{"", "Bearer " + secretB, "Bearer " + secretA + "x", secretA, "bearer " + secretA, "Basic " + secretA} {
		if w := do(s, "172.31.255.19", "GET", "/v1/state", auth); w.Code != 403 || w.Body.Len() != 0 {
			t.Errorf("%q: %d", auth, w.Code)
		}
	}
	// Two Authorization headers: refused.
	r := httptest.NewRequest("GET", "/v1/state", nil)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("172.31.255.19")}))
	r.Header.Add("Authorization", "Bearer "+secretA)
	r.Header.Add("Authorization", "Bearer "+secretA)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("two headers: %d", w.Code)
	}
}

func TestAPISecretReadPerRequest(t *testing.T) {
	s, f := newServer(t, "172.31.255.16/28")
	if w := do(s, "172.31.255.19", "GET", "/v1/state", "Bearer "+secretA); w.Code != 200 {
		t.Fatalf("first: %d", w.Code)
	}
	if err := os.WriteFile(f, []byte(secretB), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := do(s, "172.31.255.19", "GET", "/v1/state", "Bearer "+secretB); w.Code != 200 {
		t.Fatalf("rotated: %d", w.Code)
	}
	if w := do(s, "172.31.255.19", "GET", "/v1/state", "Bearer "+secretA); w.Code != 403 {
		t.Fatalf("old secret still works: %d", w.Code)
	}
	// An emptied / short / missing secret file refuses everything (fail closed).
	for _, content := range []string{"", "  \n", "short"} {
		os.WriteFile(f, []byte(content), 0o600)
		if w := do(s, "172.31.255.19", "GET", "/v1/state", "Bearer "+strings.TrimSpace(content)); w.Code != 403 {
			t.Fatalf("secret %q: %d", content, w.Code)
		}
	}
	os.Remove(f)
	if w := do(s, "172.31.255.19", "GET", "/v1/state", "Bearer "); w.Code != 403 {
		t.Fatalf("missing file: %d", w.Code)
	}
}

func TestHealthzLoopbackOnly(t *testing.T) {
	s, _ := newServer(t, "172.31.255.16/28")
	if w := do(s, "127.0.0.1", "GET", "/healthz", ""); w.Code != 200 || w.Body.String() != "ok\n" {
		t.Fatalf("loopback: %d %q", w.Code, w.Body.String())
	}
	if w := do(s, "::1", "GET", "/healthz", ""); w.Code != 200 {
		t.Fatalf("::1: %d", w.Code)
	}
	for _, ip := range []string{"172.31.250.4", "172.31.255.3"} {
		if w := do(s, ip, "GET", "/healthz", ""); w.Code != 403 {
			t.Errorf("%s: %d", ip, w.Code)
		}
	}
	// On the API address /healthz needs the bearer like everything else.
	if w := do(s, "172.31.255.19", "GET", "/healthz", ""); w.Code != 403 {
		t.Fatalf("api address without bearer: %d", w.Code)
	}
	if w := do(s, "127.0.0.1", "POST", "/healthz", ""); w.Code != 403 {
		t.Fatalf("POST on loopback: %d", w.Code)
	}
	if w := do(s, "127.0.0.1", "GET", "/v1/state", "Bearer "+secretA); w.Code != 403 {
		t.Fatalf("v1 on loopback: %d", w.Code)
	}
}
