package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// fakeVault is a minimal Vault: AppRole login issues numbered tokens;
// /v1/pki_int/sign/client-cert only accepts the current token.
type fakeVault struct {
	logins   atomic.Int32
	current  atomic.Value // string
	ttl      int
	roleID   string
	secretID string
}

func (f *fakeVault) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] != f.roleID || body["secret_id"] != f.secretID {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors":["invalid role or secret ID"]}`))
				return
			}
			n := f.logins.Add(1)
			tok := "tok-" + string(rune('0'+n))
			f.current.Store(tok)
			json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": tok, "lease_duration": f.ttl, "renewable": true},
			})
		case "/v1/pki_int/sign/client-cert":
			if r.Header.Get("X-Vault-Token") != f.current.Load() {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"certificate": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----", "serial_number": "01:02"},
			})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func setup(t *testing.T, ttl int) (*fakeVault, *Config, *time.Time) {
	t.Helper()
	t.Setenv("VAULT_TOKEN", "myroot") // must be ignored
	dir := t.TempDir()
	fv := &fakeVault{ttl: ttl, roleID: "role-1", secretID: "secret-1"}
	fv.current.Store("")
	srv := httptest.NewServer(fv.handler(t))
	t.Cleanup(srv.Close)
	os.WriteFile(filepath.Join(dir, "role-id"), []byte("role-1\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "secret-id"), []byte("secret-1"), 0o600)
	now := time.Unix(1_700_000_000, 0)
	a := newVaultAuth(srv.URL, "approle", filepath.Join(dir, "role-id"), filepath.Join(dir, "secret-id"))
	a.now = func() time.Time { return now }
	cfg := &Config{VaultAddr: srv.URL, vault: a, PKIRole: "client-cert", CertTTL: "24h"}
	return fv, cfg, &now
}

func TestVaultAuthCachesTokenAndRelogsBeforeExpiry(t *testing.T) {
	fv, cfg, now := setup(t, 3600)
	for i := 0; i < 3; i++ {
		if _, err := cfg.signCSR("alice", "", "csr"); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
	}
	if got := fv.logins.Load(); got != 1 {
		t.Fatalf("logins = %d, want 1 (token should be cached)", got)
	}
	*now = now.Add(56 * time.Minute) // inside the refresh margin
	if _, err := cfg.signCSR("alice", "", "csr"); err != nil {
		t.Fatal(err)
	}
	if got := fv.logins.Load(); got != 2 {
		t.Fatalf("logins = %d, want 2 (re-login before expiry)", got)
	}
}

func TestVaultAuthRetriesOnForbidden(t *testing.T) {
	fv, cfg, _ := setup(t, 3600)
	if _, err := cfg.signCSR("alice", "", "csr"); err != nil {
		t.Fatal(err)
	}
	fv.current.Store("revoked-elsewhere") // cached token no longer valid
	if _, err := cfg.signCSR("alice", "", "csr"); err != nil {
		t.Fatalf("sign after revocation: %v", err)
	}
	if got := fv.logins.Load(); got != 2 {
		t.Fatalf("logins = %d, want 2", got)
	}
}

func TestVaultAuthNoCredentialsNoFallback(t *testing.T) {
	_, cfg, _ := setup(t, 3600)
	os.Remove(cfg.vault.secretIDFile)
	_, err := cfg.signCSR("alice", "", "csr")
	if err == nil || !strings.Contains(err.Error(), "secret-id") {
		t.Fatalf("want secret-id error, got %v", err)
	}
}

func TestVaultClientIgnoresEnvToken(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "myroot")
	a := newVaultAuth("http://127.0.0.1:1", "approle", "", "")
	c, err := a.newClient()
	if err != nil {
		t.Fatal(err)
	}
	if c.Token() != "" {
		t.Fatalf("client picked up VAULT_TOKEN from env: %q", c.Token())
	}
	var _ *vault.Client = c
}
