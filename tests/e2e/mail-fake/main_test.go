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
	"github.com/portcullis/mail-fake/internal/mailprovider"
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
	// A stale generation: 409 error_kind generation (contract §19.5, L1).
	if c, b := call("PUT", "/v1/state", doc(1, false, "alice", "bob")); c != 409 || !bytes.Contains(b, []byte(`"error_kind":"generation"`)) {
		t.Fatalf("stale generation: %d %s", c, b)
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

// serveFakeAt is serveFake on a fake whose store is file (persist.go).
func serveFakeAt(t *testing.T, file string) (*fake.Server, func(method, path, body string) (int, []byte)) {
	t.Helper()
	s, _, call := serveFake(t)
	if err := s.UseStateFile(file); err != nil {
		t.Fatal(err)
	}
	return s, func(method, path, body string) (int, []byte) { return call(method, path, body) }
}

const aliceUUID = "00000000-0000-4000-8000-000000000001"

// The store survives a restart (a new fake on the same file), as a real
// provider's does: the Hub's void starts the provider in void mode (a
// recreated container) before it voids and verifies (core run
// 44536396845's 12: an in-memory store passed every void).
func TestStoreSurvivesRestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	_, call := serveFakeAt(t, file)
	call("PUT", "/v1/state", doc(4, false, "alice", "bob"))
	if c, b := call("POST", "/v1/credentials", `{"username":"alice","uuid":"`+aliceUUID+`","label":"ci","expires_at":null}`); c != 201 {
		t.Fatalf("create: %d %s", c, b)
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the store file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(file); bytes.Contains(b, []byte("mailpw-")) {
		t.Fatal("the store holds a password's secret")
	}
	_, call2 := serveFakeAt(t, file)
	if c, b := call2("GET", "/v1/credentials?uuid="+aliceUUID, ""); c != 200 || !bytes.Contains(b, []byte(`"id":"1"`)) {
		t.Fatalf("after the restart: %d %s", c, b)
	}
	if c, b := call2("GET", "/v1/state", ""); c != 200 || !bytes.Contains(b, []byte(`"applied_generation":4`)) {
		t.Fatalf("the applied generation after the restart: %d %s", c, b)
	}
	if c, b := call2("PUT", "/v1/state", doc(4, false, "alice", "bob")); c != 409 || !bytes.Contains(b, []byte(`"error_kind":"generation"`)) {
		t.Fatalf("a stale generation after the restart: %d %s", c, b)
	}
	// An honest void then empties it for good.
	call2("POST", "/v1/void", `{"reason":"wire"}`)
	_, call3 := serveFakeAt(t, file)
	if _, b := call3("GET", "/v1/credentials?uuid="+aliceUUID, ""); string(bytes.TrimSpace(b)) != "[]" {
		t.Fatalf("after an honest void and a restart: %s", b)
	}
	if err := (&fake.Server{}).UseStateFile(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("a missing store is an empty one: %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	if err := (&fake.Server{}).UseStateFile(bad); err == nil {
		t.Fatal("an unreadable store was accepted")
	}
}

// A hostile void keeps a credential through the Hub's whole verification
// (list, revoke each leftover, list again: hub verifyMailVoid), also
// across the void-mode restart; once honest again, the revoke works.
func TestHostileVoidSurvivesVerification(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	s, call := serveFakeAt(t, file)
	call("PUT", "/v1/state", doc(1, false, "alice"))
	call("POST", "/v1/credentials", `{"username":"alice","uuid":"`+aliceUUID+`","label":"keep","expires_at":null}`)
	call("POST", "/v1/credentials", `{"username":"alice","uuid":"`+aliceUUID+`","label":"two","expires_at":null}`)
	s.SetMode(fake.ModeHostile)
	// The void-mode start: a new process on the same store, still hostile.
	s2, call2 := serveFakeAt(t, file)
	s2.SetMode(fake.ModeHostile)
	if c, b := call2("POST", "/v1/void", `{"reason":"wire"}`); c != 200 {
		t.Fatalf("void: %d %s", c, b)
	}
	list := func(call func(string, string, string) (int, []byte)) []mailprovider.Credential {
		c, b := call("GET", "/v1/credentials?uuid="+aliceUUID, "")
		var rows []mailprovider.Credential
		if c != 200 || json.Unmarshal(b, &rows) != nil {
			t.Fatalf("list: %d %s", c, b)
		}
		return rows
	}
	rows := list(call2)
	if len(rows) != 1 || rows[0].Label != "keep" {
		t.Fatalf("the hostile void kept %v (want the first one only)", rows)
	}
	if c, _ := call2("DELETE", "/v1/credentials/"+rows[0].ID+"?uuid="+aliceUUID, ""); c != 204 {
		t.Fatalf("the revoke answered %d (want a lying 204)", c)
	}
	if left := list(call2); len(left) != 1 {
		t.Fatalf("after the Hub's revoke: %v (the hostile provider still holds it)", left)
	}
	s2.SetMode(fake.ModeHonest)
	call2("DELETE", "/v1/credentials/"+rows[0].ID+"?uuid="+aliceUUID, "")
	if left := list(call2); len(left) != 0 {
		t.Fatalf("an honest revoke left %v", left)
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

// honestSetsFile is the honest mode's sets for the e2e domains, judged by
// core's shared DNS rules in domains/internal/dnsplan (the 86 vectors'
// ValidateMailSet): this test keeps the file equal to what the fake serves.
const honestSetsFile = "testdata/honest_sets.json"

type honestCase struct {
	Domain       string              `json:"domain"`
	MailHostname string              `json:"mail_hostname"`
	Set          mailprovider.DNSSet `json:"set"`
}

func honestCases() []honestCase {
	var out []honestCase
	for _, d := range []string{"ci.example.org", "team-b.test", "example.org"} {
		host := "mail.ci.example.org"
		if d == "example.org" {
			host = "mail.example.org"
		}
		out = append(out, honestCase{Domain: d, MailHostname: host, Set: fake.HonestSet(d, host)})
	}
	return out
}

func TestHonestSetsFileMatches(t *testing.T) {
	want, _ := json.MarshalIndent(honestCases(), "", "  ")
	want = append(want, '\n')
	if os.Getenv("MAIL_FAKE_UPDATE") == "1" {
		if err := os.WriteFile(honestSetsFile, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(honestSetsFile)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s differs from the honest sets (regenerate with MAIL_FAKE_UPDATE=1 go test ./...): %v", honestSetsFile, err)
	}
}

// withSenders adds a senders list to doc's JSON (nil = left out).
func withSenders(d string, senders ...string) string {
	var m map[string]any
	json.Unmarshal([]byte(d), &m)
	list := []map[string]any{}
	for i, u := range senders {
		list = append(list, map[string]any{"username": u, "uuid": fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1), "address": u + "@example.org"})
	}
	m["senders"] = list
	b, _ := json.Marshal(m)
	return string(b)
}

// Senders (contract §19.14): optional; a sender's credential with
// allowed_ips; an absent list keeps the senders, an empty one removes
// them (their credentials too) and is never a mass removal; malformed
// senders are refused.
func TestHonestSenders(t *testing.T) {
	_, _, call := serveFake(t)
	if c, b := call("PUT", "/v1/state", withSenders(doc(1, false, "alice"), "portcullis-hub-mail", "portcullis-app-fxa")); c != 202 {
		t.Fatalf("PUT with senders: %d %s", c, b)
	}
	app := `"username":"portcullis-app-fxa","uuid":"10000000-0000-4000-8000-000000000002","label":"fxa","expires_at":null`
	if c, b := call("POST", "/v1/credentials", `{`+app+`,"allowed_ips":["172.18.0.0/16"]}`); c != 201 {
		t.Fatalf("sender credential: %d %s", c, b)
	}
	if c, b := call("GET", "/v1/credentials?uuid=10000000-0000-4000-8000-000000000002", ""); c != 200 || !bytes.Contains(b, []byte(`"allowed_ips":["172.18.0.0/16"]`)) {
		t.Fatalf("list: %d %s", c, b)
	}
	if c, b := call("POST", "/v1/credentials", `{`+app+`,"allowed_ips":[]}`); c != 400 {
		t.Fatalf("empty allowed_ips: %d %s", c, b)
	}
	// Absent: kept.
	if c, b := call("PUT", "/v1/state", doc(2, false, "alice")); c != 202 {
		t.Fatalf("absent: %d %s", c, b)
	}
	if c, b := call("GET", "/v1/credentials?uuid=10000000-0000-4000-8000-000000000002", ""); c != 200 || !bytes.Contains(b, []byte(`"id":"1"`)) {
		t.Fatalf("after an absent list: %d %s", c, b)
	}
	// Empty: removed, no mass-removal refusal.
	if c, b := call("PUT", "/v1/state", withSenders(doc(3, false, "alice"))); c != 202 {
		t.Fatalf("empty: %d %s", c, b)
	}
	if c, _ := call("GET", "/v1/credentials?uuid=10000000-0000-4000-8000-000000000002", ""); c != 404 {
		t.Fatalf("a removed sender still answers: %d", c)
	}
	for name, d := range map[string]string{
		"a person's name": withSenders(doc(4, false, "portcullis-app-fxa"), "portcullis-app-fxa"),
		"another form":    withSenders(doc(4, false, "alice"), "portcullis-mail"),
		"twice":           withSenders(doc(4, false, "alice"), "portcullis-app-fxa", "portcullis-app-fxa"),
		"an unknown key":  strings.Replace(withSenders(doc(4, false, "alice"), "portcullis-app-fxa"), `"address":`, `"label":"x","address":`, 1),
		"another address": strings.Replace(withSenders(doc(4, false, "alice"), "portcullis-app-fxa"), `"portcullis-app-fxa@example.org"`, `"fxa@example.org"`, 1),
	} {
		if c, _ := call("PUT", "/v1/state", d); c != 400 {
			t.Errorf("%s: %d (want 400)", name, c)
		}
	}
}
