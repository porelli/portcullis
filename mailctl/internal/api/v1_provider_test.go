package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/checks"
	"github.com/portcullis/mailctl/internal/creds"
	"github.com/portcullis/mailctl/internal/state"
	"github.com/portcullis/mailctl/internal/tlsprobe"
)

const (
	uuidAlice = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
	uuidBob   = "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"
)

// ready: a document accepted and applied.
func ready(t *testing.T, e *v1env, doc string) {
	t.Helper()
	if w := e.do("PUT", "/v1/state", doc); w.Code != 202 {
		t.Fatalf("PUT: %d %s", w.Code, w.Body)
	}
	if err := e.v.Runner.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func create(t *testing.T, e *v1env, user, uuid string) map[string]any {
	t.Helper()
	w := e.do("POST", "/v1/credentials", `{"username":"`+user+`","uuid":"`+uuid+`","label":"phone","expires_at":null}`)
	if w.Code != 201 {
		t.Fatalf("create %s: %d %s", user, w.Code, w.Body)
	}
	var cr map[string]any
	json.Unmarshal(w.Body.Bytes(), &cr)
	return cr
}

func rows(t *testing.T, e *v1env, uuid string) []map[string]any {
	t.Helper()
	w := e.do("GET", "/v1/credentials?uuid="+uuid, "")
	if w.Code != 200 {
		t.Fatalf("list %s: %d %s", uuid, w.Code, w.Body)
	}
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProviderInfo(t *testing.T) {
	e := newV1(t)
	e.v.Export = true
	w := e.do("GET", "/v1/provider", "")
	var p struct {
		Name       string   `json:"name"`
		Version    string   `json:"version"`
		APIVersion int      `json:"api_version"`
		Checks     []string `json:"checks"`
		Actions    []string `json:"actions"`
		Export     bool     `json:"export"`
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &raw)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || len(raw) != 6 || p.Name != "Stalwart" || p.Version != "1.1.0" ||
		p.APIVersion != 1 || !p.Export || strings.Join(p.Actions, ",") != "dkim-rotate,dmarc-promote,mtasts-enforce,test" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, id := range p.Checks {
		if strings.HasSuffix(id, ":") {
			id += "example.com"
		}
		if !checks.InCatalog(id) {
			t.Errorf("check %s outside the catalog", id)
		}
	}
	// Before the bootstrap (Stalwart refuses the key): provider and state
	// answer, everything else is 503.
	e.f.Fail("x:Domain", 100)
	e.v.mu.Lock()
	e.v.bootAt = time.Time{}
	e.v.mu.Unlock()
	if w := e.do("GET", "/v1/provider", ""); w.Code != 200 {
		t.Fatalf("provider before bootstrap: %d", w.Code)
	}
	if w := e.do("GET", "/v1/state", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"bootstrap":false`) {
		t.Fatalf("state before bootstrap: %d %s", w.Code, w.Body)
	}
	for _, r := range [][2]string{{"PUT", "/v1/state"}, {"GET", "/v1/status"}, {"GET", "/v1/checks"}, {"POST", "/v1/void"},
		{"GET", "/v1/credentials?uuid=" + uuidAlice}, {"POST", "/v1/tls/reload"}, {"POST", "/v1/actions/test"}} {
		if w := e.do(r[0], r[1], "{}"); w.Code != 503 || !strings.Contains(w.Body.String(), "the mail server isn't ready") {
			t.Errorf("%s %s before bootstrap: %d %s", r[0], r[1], w.Code, w.Body)
		}
	}
}

// POST /v1/void destroys every mail password of every account, the
// parked ones' too, and records restored_at; a failure is 503.
func TestVoidDestroysAll(t *testing.T) {
	e := newV1(t)
	ready(t, e, vec(t, 12))
	create(t, e, "alice", uuidAlice)
	create(t, e, "alice", uuidAlice)
	create(t, e, "bob", uuidBob)
	// bob leaves: parked, and a stray password on his parked account.
	var m map[string]any
	json.Unmarshal([]byte(vec(t, 13)), &m)
	m["accounts"] = m["accounts"].([]any)[:1:1]
	m["accounts"] = append(m["accounts"].([]any), map[string]any{"username": "root", "uuid": "3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e",
		"display_name": "Root", "addresses": []string{"root@example.com"}, "quota_bytes": 0})
	m["lists"].([]any)[0].(map[string]any)["members"] = []string{"alice"}
	b, _ := json.Marshal(m)
	ready(t, e, string(b))
	for _, la := range e.f.Objects("Account", "") {
		if d, _ := la["description"].(string); strings.Contains(d, uuidBob) {
			e.f.Put("AppPassword", la["id"].(string), map[string]any{"description": "stray", "createdAt": "2026-11-01T00:00:00Z"})
		}
	}
	for _, body := range []string{`{}`, `{"reason":"other"}`, `{"reason":"wire","x":1}`, `{"reason":"wire","reason":"restore"}`, `{"reason":"wire"}{}`} {
		if w := e.do("POST", "/v1/void", body); w.Code != 400 {
			t.Errorf("%s: %d", body, w.Code)
		}
	}
	w := e.do("POST", "/v1/void", `{"reason":"wire"}`)
	var res struct {
		Voided     int        `json:"voided"`
		RestoredAt *time.Time `json:"restored_at"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &res) != nil || res.Voided < 3 || res.RestoredAt == nil {
		t.Fatalf("void: %d %s", w.Code, w.Body)
	}
	for _, la := range e.f.Objects("Account", "") {
		if n := len(e.f.Objects("AppPassword", la["id"].(string))); n != 0 {
			t.Fatalf("%d passwords left on %v", n, la["name"])
		}
	}
	if p := e.v.Store.Get(); p.RestoredAt == nil || !p.RestoredAt.Equal(*res.RestoredAt) {
		t.Fatalf("restored_at %+v", p.RestoredAt)
	}
	if w := e.do("GET", "/v1/status", ""); !strings.Contains(w.Body.String(), `"restored_at":"`) {
		t.Fatalf("status %s", w.Body)
	}
	e.f.Fail("x:AppPassword", 1)
	if w := e.do("POST", "/v1/void", `{"reason":"restore"}`); w.Code != 503 {
		t.Fatalf("failed void: %d %s", w.Code, w.Body)
	}
}

// GET /v1/credentials takes ?uuid= only, echoes it on every row, covers
// the uuid's parked account too, and is 404 for a uuid no account holds.
func TestCredentialsListByUUIDEchoes(t *testing.T) {
	e := newV1(t)
	ready(t, e, vec(t, 12))
	create(t, e, "alice", uuidAlice)
	create(t, e, "bob", uuidBob)
	got := rows(t, e, uuidAlice)
	if len(got) != 1 || got[0]["uuid"] != uuidAlice || got[0]["label"] != "phone" {
		t.Fatalf("%v", got)
	}
	var raw []map[string]json.RawMessage
	json.Unmarshal(e.do("GET", "/v1/credentials?uuid="+uuidAlice, "").Body.Bytes(), &raw)
	for _, k := range []string{"id", "uuid", "label", "created_at", "expires_at", "last_used", "allowed_ips"} {
		if _, ok := raw[0][k]; !ok || len(raw[0]) != 7 {
			t.Fatalf("row %v lacks %s", raw[0], k)
		}
	}
	for _, q := range []string{"", "?user=alice", "?uuid=" + uuidAlice + "&user=alice", "?uuid=" + uuidAlice + "&uuid=" + uuidBob, "?uuid=alice", "?uuid=" + strings.ToUpper(uuidAlice)} {
		if w := e.do("GET", "/v1/credentials"+q, ""); w.Code != 400 {
			t.Errorf("%q: %d", q, w.Code)
		}
	}
	if w := e.do("GET", "/v1/credentials?uuid=aaaaaaaa-0000-4000-8000-000000000000", ""); w.Code != 404 {
		t.Fatalf("unknown uuid: %d", w.Code)
	}
	// bob parked: his row is still listed under his uuid.
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == "bob" {
			var park string
			for _, d := range e.f.Objects("Domain", "") {
				if d["name"] == state.ParkingDomain {
					park = d["id"].(string)
				}
			}
			e.f.PutID("Account", "", a["id"].(string), map[string]any{"@type": "User", "name": "former-" + uuidBob, "domainId": park, "description": "portcullis:" + uuidBob})
		}
	}
	if got := rows(t, e, uuidBob); len(got) != 1 || got[0]["uuid"] != uuidBob {
		t.Fatalf("parked %v", got)
	}
}

// allowed_ips: [] without LAN-only; with it exactly the Local networks
// (loopback only while client addresses are rewritten), from the
// document, never the environment.
func TestCredentialsAllowedIPs(t *testing.T) {
	e := newV1(t)
	ready(t, e, vec(t, 12))
	create(t, e, "alice", uuidAlice)
	if got := rows(t, e, uuidAlice); len(got[0]["allowed_ips"].([]any)) != 0 {
		t.Fatalf("without LAN-only %v", got[0]["allowed_ips"])
	}
	lan := strings.Replace(vec(t, 13), `"submission_lan_only":false`, `"submission_lan_only":true`, 1)
	lan = strings.Replace(lan, `"local_networks":["10.0.0.0/8"]`, `"local_networks":["10.0.0.0/8","192.168.1.0/24"]`, 1)
	ready(t, e, lan)
	create(t, e, "bob", uuidBob)
	for _, u := range []string{uuidAlice, uuidBob} {
		got := rows(t, e, u)
		b, _ := json.Marshal(got[0]["allowed_ips"])
		if string(b) != `["10.0.0.0/8","192.168.1.0/24"]` {
			t.Fatalf("%s: %s", u, b)
		}
	}
	rw := strings.Replace(strings.Replace(lan, `"generation":13`, `"generation":14`, 1), `"client_ip":"preserved"`, `"client_ip":"rewritten"`, 1)
	ready(t, e, rw)
	b, _ := json.Marshal(rows(t, e, uuidBob)[0]["allowed_ips"])
	if string(b) != `["127.0.0.1/32","::1/128"]` {
		t.Fatalf("rewritten: %s", b)
	}
	_ = creds.MaxActive
}

func certFiles(t *testing.T, dir, host string) *x509.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	os.WriteFile(filepath.Join(dir, "fullchain.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o640)
	os.WriteFile(filepath.Join(dir, "privkey.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o640)
	leaf, _ := x509.ParseCertificate(der)
	return leaf
}

// POST /v1/tls/reload: the files must be readable, Stalwart reloads, and
// the answer is the SPKI the listeners then serve.
func TestTLSReloadAnswersSPKI(t *testing.T) {
	e := newV1(t)
	e.v.TLSDir = t.TempDir()
	spki := strings.Repeat("ab", 32)
	body := `{"spki_sha256":["` + spki + `"]}`
	if w := e.do("POST", "/v1/tls/reload", body); w.Code != 503 || !strings.Contains(w.Body.String(), "can't be read") {
		t.Fatalf("no files: %d %s", w.Code, w.Body)
	}
	leaf := certFiles(t, e.v.TLSDir, "mail.example.com")
	served := leaf
	e.v.Serving = func(context.Context) (*x509.Certificate, error) { return served, nil }
	for _, b := range []string{`{}`, `{"spki_sha256":[]}`, `{"spki_sha256":["AB"]}`, `{"spki_sha256":["` + strings.ToUpper(spki) + `"]}`,
		`{"spki_sha256":["` + spki + `","` + spki + `","` + spki + `"]}`, `{"spki_sha256":["` + spki + `"],"x":1}`} {
		if w := e.do("POST", "/v1/tls/reload", b); w.Code != 400 {
			t.Errorf("%s: %d", b, w.Code)
		}
	}
	e.f.ResetCalls()
	w := e.do("POST", "/v1/tls/reload", body)
	var res map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &res) != nil || len(res) != 1 || res["serving_spki_sha256"] != tlsprobe.SPKI(leaf) {
		t.Fatalf("reload: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(strings.Join(e.f.Calls, "\n"), "ReloadTlsCertificates") {
		t.Fatalf("no reload: %v", e.f.Calls)
	}
	if !strings.Contains(e.log.String(), "not one of the keys sent") {
		t.Fatal("a served key outside the list wasn't logged")
	}
	e.v.Serving = func(context.Context) (*x509.Certificate, error) { return nil, errors.New("refused") }
	if w := e.do("POST", "/v1/tls/reload", body); w.Code != 503 {
		t.Fatalf("probe failed: %d", w.Code)
	}
}

// POST /v1/actions/test: one address, 409 without a postmaster, the
// queue id from the submission.
func TestActionsTest(t *testing.T) {
	e := newV1(t)
	var gotTo, gotFrom string
	e.v.Test = func(_ context.Context, doc *state.Doc, to string) (string, error) {
		gotTo, gotFrom = to, doc.Postmaster[0]
		return "Q123", nil
	}
	if w := e.do("POST", "/v1/actions/test", `{"to":"x@example.net"}`); w.Code != 409 {
		t.Fatalf("no document: %d", w.Code)
	}
	ready(t, e, vec(t, 12))
	for _, b := range []string{`{}`, `{"to":""}`, `{"to":"a@b.example, c@d.example"}`, `{"to":"Bob <b@x.example>"}`, `{"to":"nobody"}`, `{"to":"x@example.net","cc":1}`} {
		if w := e.do("POST", "/v1/actions/test", b); w.Code != 400 {
			t.Errorf("%s: %d", b, w.Code)
		}
	}
	w := e.do("POST", "/v1/actions/test", `{"to":"x@example.net"}`)
	if w.Code != 202 || strings.TrimSpace(w.Body.String()) != `{"queue_id":"Q123"}` || gotTo != "x@example.net" || gotFrom != "root" {
		t.Fatalf("test: %d %s", w.Code, w.Body)
	}
	noPM := strings.Replace(vec(t, 13), `"postmaster":["root"]`, `"postmaster":[]`, 1)
	ready(t, e, noPM)
	if w := e.do("POST", "/v1/actions/test", `{"to":"x@example.net"}`); w.Code != 409 {
		t.Fatalf("no postmaster: %d %s", w.Code, w.Body)
	}
}

// M6 (final cross review): the Hub's client gives up after 30 s while a
// void may run for minutes; a request whose context is already cancelled
// (the client gone) still voids to the end — the Hub's retry then finds
// nothing left — rather than stopping half way.
func TestVoidCompletesWhenTheClientIsGone(t *testing.T) {
	e := newV1(t)
	ready(t, e, vec(t, 12))
	create(t, e, "alice", uuidAlice)
	create(t, e, "bob", uuidBob)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/v1/void", strings.NewReader(`{"reason":"restore"}`)).WithContext(ctx)
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("172.31.255.19")}))
	r.RemoteAddr = "172.31.255.18:40000"
	r.Header.Set("Authorization", "Bearer "+secretA)
	w := httptest.NewRecorder()
	e.s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("void with the client gone: %d %s", w.Code, w.Body.String())
	}
	for _, la := range e.f.Objects("Account", "") {
		if n := len(e.f.Objects("AppPassword", la["id"].(string))); n != 0 {
			t.Fatalf("%d passwords left on %v", n, la["name"])
		}
	}
}
