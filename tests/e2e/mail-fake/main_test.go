package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/mail-fake/internal/fake"
)

const testSecret = "mail-fake-test-secret-0123456789abcdefgh"

// serveFake: the fake's API on 127.0.0.2 (or 127.0.0.1 when that can't be
// bound), its subnet the address's /32: a call through another loopback
// address is "outside portcullis-mail-api".
func serveFake(t *testing.T) (*fake.Server, string, func(method, path, body string, hdr ...string) (int, []byte)) {
	t.Helper()
	dir := t.TempDir()
	sf := filepath.Join(dir, "api-secret")
	os.WriteFile(sf, []byte(testSecret+"\n"), 0o600)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	s := fake.New(sf, netip.PrefixFrom(ip, 32), "Fake A")
	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	base := "http://" + ln.Addr().String()
	call := func(method, path, body string, hdr ...string) (int, []byte) {
		req, _ := http.NewRequestWithContext(context.Background(), method, base+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+testSecret)
		for i := 0; i+1 < len(hdr); i += 2 {
			if hdr[i+1] == "" {
				req.Header.Del(hdr[i])
			} else {
				req.Header.Set(hdr[i], hdr[i+1])
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	return s, base, call
}

// doc is a minimal valid MailState v2 (one account on example.org).
func doc(gen int, lanOnly bool, accounts ...string) string {
	var accts []map[string]any
	for i, a := range accounts {
		accts = append(accts, map[string]any{"username": a, "uuid": fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1),
			"display_name": a, "addresses": []string{a + "@example.org"}, "quota_bytes": 0})
	}
	if accts == nil {
		accts = []map[string]any{}
	}
	d := map[string]any{"version": 2, "generation": gen, "primary_domain": "example.org", "mail_hostname": "mail.example.org",
		"client_ip": "preserved", "submission_lan_only": lanOnly, "dkim_rotate": "4380h", "former_retention": "720h",
		"relay": nil, "tls": map[string]any{"spki_sha256": []string{}}, "confirm_mass_removal": false,
		"domains":  []map[string]any{{"name": "example.org", "dmarc_start": "reject", "dmarc_floor": "reject", "mail": "on", "dnssec": "unsigned"}},
		"accounts": accts, "aliases": []any{}, "lists": []any{}, "postmaster": []string{},
		"limits":         map[string]any{"recipients_per_hour": 100, "recipients_per_day": 1000},
		"spam":           map[string]any{"junk_score": 5, "reject_score": 10, "allow": []any{}, "block": []any{}},
		"local_networks": []string{"192.168.1.0/24"}}
	b, _ := json.Marshal(d)
	return string(b)
}

// The honest fake passes its own API: bearer, documents, credentials by
// uuid, the void.
func TestHonestPassesOwnAPI(t *testing.T) {
	_, _, call := serveFake(t)
	if c, _ := call("GET", "/v1/provider", "", "Authorization", ""); c != 403 {
		t.Fatalf("no bearer: %d", c)
	}
	if c, _ := call("GET", "/v1/provider", "", "Authorization", "Bearer wrong"); c != 403 {
		t.Fatalf("wrong bearer: %d", c)
	}
	if c, b := call("PUT", "/v1/state", doc(1, false, "alice", "bob")); c != 202 {
		t.Fatalf("PUT: %d %s", c, b)
	}
	c, b := call("POST", "/v1/credentials", `{"username":"alice","uuid":"00000000-0000-4000-8000-000000000001","label":"ci","expires_at":null}`)
	if c != 201 || !bytes.Contains(b, []byte(`"secret"`)) {
		t.Fatalf("create: %d %s", c, b)
	}
	if c, b := call("POST", "/v1/credentials", `{"username":"alice","uuid":"00000000-0000-4000-8000-000000000009","label":"ci","expires_at":null}`); c != 409 || !bytes.Contains(b, []byte("account_mismatch")) {
		t.Fatalf("mismatch: %d %s", c, b)
	}
	if c, b := call("GET", "/v1/credentials?uuid=00000000-0000-4000-8000-000000000001", ""); c != 200 || !bytes.Contains(b, []byte(`"id":"1"`)) {
		t.Fatalf("list: %d %s", c, b)
	}
	// Mass removal: both accounts gone at once → 409 with removed.
	if c, b := call("PUT", "/v1/state", doc(2, false)); c != 409 || !bytes.Contains(b, []byte(`"removed"`)) {
		t.Fatalf("mass removal: %d %s", c, b)
	}
	// The honest set: the MX on the document's mail host (a set the Hub's
	// shared rules accept).
	if c, b := call("GET", "/v1/dns/example.org?wildcard=false", ""); c != 200 || !bytes.Contains(b, []byte("10 mail.example.org.")) || bytes.Contains(b, []byte("attacker")) {
		t.Fatalf("honest dns: %d %s", c, b)
	}
	if c, b := call("POST", "/v1/void", `{"reason":"restore"}`); c != 200 {
		t.Fatalf("void: %d %s", c, b)
	}
	if c, b := call("GET", "/v1/credentials?uuid=00000000-0000-4000-8000-000000000001", ""); c != 200 || string(bytes.TrimSpace(b)) != "[]" {
		t.Fatalf("after the void: %d %s", c, b)
	}
}

// Hostile mode serves the forbidden set, has no mass-removal guard, widens
// allowed_ips under LAN-only and keeps a credential across the void.
func TestHostileServesForbiddenSet(t *testing.T) {
	s, _, call := serveFake(t)
	if !s.SetMode(fake.ModeHostile) {
		t.Fatal("mode")
	}
	call("PUT", "/v1/state", doc(1, true, "alice", "bob"))
	c, b := call("GET", "/v1/dns/example.org?wildcard=false", "")
	if c != 200 {
		t.Fatalf("dns: %d %s", c, b)
	}
	for _, want := range []string{`"type":"A"`, "mx.attacker.example", "include:_spf.attacker.example", "p=none", `"type":"CAA"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("the hostile set lacks %s: %s", want, b)
		}
	}
	call("POST", "/v1/credentials", `{"username":"alice","uuid":"00000000-0000-4000-8000-000000000001","label":"ci","expires_at":null}`)
	if _, b := call("GET", "/v1/credentials?uuid=00000000-0000-4000-8000-000000000001", ""); !bytes.Contains(b, []byte("0.0.0.0/0")) {
		t.Errorf("allowed_ips not widened under LAN-only: %s", b)
	}
	if c, b := call("PUT", "/v1/state", doc(2, true)); c != 202 {
		t.Errorf("hostile mode refused a mass removal: %d %s", c, b)
	}
	call("PUT", "/v1/state", doc(3, true, "alice"))
	call("POST", "/v1/credentials", `{"username":"alice","uuid":"00000000-0000-4000-8000-000000000001","label":"ci","expires_at":null}`)
	call("POST", "/v1/void", `{"reason":"restore"}`)
	if _, b := call("GET", "/v1/credentials?uuid=00000000-0000-4000-8000-000000000001", ""); string(bytes.TrimSpace(b)) == "[]" {
		t.Error("the hostile void destroyed everything")
	}
	if !s.SetMode(fake.ModeHonest) || s.SetMode("other") {
		t.Fatal("mode switch")
	}
}

// The gate (P3): no .present, a wrong sentinel, void-pending without this
// session: refused; the sentinel, or void mode with the session: started.
func TestGateRefusesWithoutPresent(t *testing.T) {
	d := t.TempDir()
	if Gate(d, "") == nil {
		t.Fatal("started without .present")
	}
	os.WriteFile(filepath.Join(d, ".present"), []byte("other\n"), 0o640)
	if Gate(d, "") == nil {
		t.Fatal("started with a wrong sentinel")
	}
	os.WriteFile(filepath.Join(d, ".present"), []byte("portcullis-mail-gate\n"), 0o640)
	if err := Gate(d, ""); err != nil {
		t.Fatalf("refused with the sentinel: %v", err)
	}
	os.WriteFile(filepath.Join(d, "void-pending"), nil, 0o640)
	os.WriteFile(filepath.Join(d, "void-session"), []byte("s1"), 0o640)
	if Gate(d, "") == nil || Gate(d, "s2") == nil {
		t.Fatal("void mode started without this session")
	}
	if err := Gate(d, "s1"); err != nil {
		t.Fatalf("void mode with the session refused: %v", err)
	}
	if run([]string{"serve"}, func(k string) string {
		if k == "MAIL_FAKE_SLOT" {
			return t.TempDir()
		}
		return ""
	}) != 1 {
		t.Fatal("serve started past the gate")
	}
}
