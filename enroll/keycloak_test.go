package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testKCSecret = "0123456789abcdef0123456789abcdef-kc"

// fakeKeycloak: client-credentials token + the three admin calls RequirePasskey makes.
type fakeKeycloak struct {
	mu       sync.Mutex
	tokens   int
	actions  []string
	puts     []map[string]any
	gotQuery string
}

func (f *fakeKeycloak) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "POST" && r.URL.Path == "/realms/portcullis/protocol/openid-connect/token":
			r.ParseForm()
			id, secret, ok := r.BasicAuth()
			if !ok {
				id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
			}
			if r.PostForm.Get("grant_type") != "client_credentials" || id != "portcullis-enroll" || secret != testKCSecret {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"unauthorized_client"}`))
				return
			}
			f.tokens++
			w.Write([]byte(`{"access_token":"tok","expires_in":300,"token_type":"Bearer"}`))
		case r.Header.Get("Authorization") != "Bearer tok":
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == "GET" && r.URL.Path == "/admin/realms/portcullis/users":
			f.gotQuery = r.URL.RawQuery
			if r.URL.Query().Get("username") == "bob" {
				w.Write([]byte(`[{"id":"u1","username":"bob"}]`))
			} else {
				w.Write([]byte(`[{"id":"u2","username":"bobby"}]`))
			}
		case r.Method == "GET" && r.URL.Path == "/admin/realms/portcullis/users/u1":
			json.NewEncoder(w).Encode(map[string]any{"id": "u1", "username": "bob", "requiredActions": f.actions})
		case r.Method == "PUT" && r.URL.Path == "/admin/realms/portcullis/users/u1":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			f.puts = append(f.puts, body)
			f.actions = nil
			for _, a := range body["requiredActions"].([]any) {
				f.actions = append(f.actions, a.(string))
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestKeycloakRequirePasskey(t *testing.T) {
	f := &fakeKeycloak{actions: []string{"VERIFY_EMAIL"}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte(testKCSecret+"\n"), 0o600)
	k := newKeycloakClient(srv.URL+"/", "portcullis", "portcullis-enroll", secret)

	if err := k.RequirePasskey("bob"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.gotQuery, "exact=true") || !strings.Contains(f.gotQuery, "username=bob") {
		t.Errorf("user search query %q", f.gotQuery)
	}
	if len(f.puts) != 1 {
		t.Fatalf("PUTs: %v", f.puts)
	}
	// Only id + requiredActions are sent (Keycloak keeps the rest).
	if len(f.puts[0]) != 2 || f.puts[0]["id"] != "u1" {
		t.Errorf("PUT body %v", f.puts[0])
	}
	if strings.Join(f.actions, ",") != "VERIFY_EMAIL,"+passkeyAction {
		t.Errorf("actions %v", f.actions)
	}
	// Idempotent; the token is cached.
	if err := k.RequirePasskey("bob"); err != nil {
		t.Fatal(err)
	}
	if len(f.puts) != 1 || f.tokens != 1 {
		t.Errorf("second call: %d PUTs, %d tokens", len(f.puts), f.tokens)
	}
	// Exact match only.
	if err := k.RequirePasskey("bo"); err == nil {
		t.Error("a different username matched")
	}
}

func TestKeycloakBadSecret(t *testing.T) {
	f := &fakeKeycloak{}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte(strings.Repeat("w", 40)), 0o600)
	err := newKeycloakClient(srv.URL, "portcullis", "portcullis-enroll", secret).RequirePasskey("bob")
	if err == nil || strings.Contains(err.Error(), "wwww") {
		t.Fatalf("err = %v (must fail, without the secret)", err)
	}
	if err := newKeycloakClient(srv.URL, "portcullis", "portcullis-enroll", secret+".missing").RequirePasskey("bob"); err == nil {
		t.Fatal("missing secret file accepted")
	}
}
