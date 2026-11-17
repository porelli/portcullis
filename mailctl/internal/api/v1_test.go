package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/portcullis/mailctl/internal/checks"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

type v1env struct {
	f   *fake.Server
	v   *V1
	s   *Server
	log *bytes.Buffer
}

func newV1(t *testing.T) *v1env {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	park := f.Put("Domain", "", map[string]any{"name": state.ParkingDomain})
	f.Put("Domain", "", map[string]any{"name": "example.com"})
	f.Put("Account", "", map[string]any{"@type": "User", "name": reconcile.MailctlAccount, "domainId": park})
	st, _ := state.Open(t.TempDir())
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	var buf bytes.Buffer
	lg := logx.New(&buf)
	r := reconcile.NewRunner(c, st, lg.Printf)
	v := &V1{Store: st, C: c, Runner: r, Logf: lg.Printf}
	v.M = machines.New(c, st, machines.Config{Reachable: true}, lg.Printf)
	v.M.Visible = func(context.Context, string, string) bool { return false }
	v.Checks = &checks.Runner{D: checks.Deps{C: c, M: v.M, Store: st, Cfg: checks.Config{Hostname: "mail.example.com", MailIP: "192.0.2.1"},
		DNS: func(context.Context, string, string, uint16, bool) (*dns.Msg, error) {
			return nil, errors.New("offline")
		},
		Dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("offline") }}}
	srv, _ := newServer(t, "172.31.255.16/28")
	srv.Handler = v.Handler()
	return &v1env{f: f, v: v, s: srv, log: &buf}
}

func (e *v1env) do(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("172.31.255.19")}))
	r.Header.Set("Authorization", "Bearer "+secretA)
	w := httptest.NewRecorder()
	e.s.ServeHTTP(w, r)
	return w
}

func vec(t *testing.T, gen int) string {
	b, err := os.ReadFile("../state/testdata/mailstate_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(b), `"generation":12`, `"generation":`+itoa(gen), 1)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestStaleGeneration409(t *testing.T) {
	e := newV1(t)
	if w := e.do("PUT", "/v1/state", vec(t, 12)); w.Code != 202 || !strings.Contains(w.Body.String(), `"generation":12`) {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	for _, g := range []int{12, 11} {
		if w := e.do("PUT", "/v1/state", vec(t, g)); w.Code != 409 {
			t.Errorf("generation %d: %d", g, w.Code)
		}
	}
	if w := e.do("PUT", "/v1/state", `{"version":2}`); w.Code != 400 || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("bad doc: %d %s", w.Code, w.Body)
	}
	if e.v.Store.Get().Generation != 12 {
		t.Fatal("a refused document replaced the accepted one")
	}
	_ = e.v.Runner.Once(context.Background())
	w := e.do("GET", "/v1/state", "")
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["generation"] != float64(12) || st["applied_generation"] != float64(12) || st["bootstrap"] != true || len(st["errors"].([]any)) != 0 {
		t.Fatalf("GET /v1/state %s", w.Body)
	}
}

func TestMassRemoval409AtPut(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	var m map[string]any
	json.Unmarshal([]byte(vec(t, 13)), &m)
	m["accounts"] = m["accounts"].([]any)[:1]
	m["lists"].([]any)[0].(map[string]any)["members"] = []string{"alice"}
	m["postmaster"] = []string{"alice"}
	b, _ := json.Marshal(m)
	doc := string(b)
	w := e.do("PUT", "/v1/state", doc)
	var body struct {
		Error     string `json:"error"`
		ErrorKind string `json:"error_kind"`
		Removed   []map[string]any
	}
	var raw map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &raw)
	if w.Code != 409 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.ErrorKind != "mass_removal" ||
		!strings.Contains(body.Error, "mass removal") || !strings.Contains(body.Error, "50 %") || len(raw) != 3 {
		t.Fatalf("mass removal: %d %s", w.Code, w.Body)
	}
	// The accounts it would remove: username and uuid only, sorted.
	if b, _ := json.Marshal(body.Removed); string(b) != `[{"username":"bob","uuid":"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"},{"username":"root","uuid":"3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e"}]` {
		t.Fatalf("removed %s", b)
	}
	// Confirmed: accepted and bound to exactly that set (final review L2).
	m["confirm_mass_removal"] = true
	b, _ = json.Marshal(m)
	if w := e.do("PUT", "/v1/state", string(b)); w.Code != 202 {
		t.Fatalf("confirmed: %d %s", w.Code, w.Body)
	}
	mr := e.v.Store.Get().MassRemoval
	if mr == nil || mr.Generation != 13 || len(mr.UUIDs) != 2 || !mr.Covers(13, []string{"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d", "3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e"}) ||
		mr.Covers(13, []string{"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"}) {
		t.Fatalf("binding %+v", mr)
	}
	// A stale generation's 409 has no error_kind.
	w = e.do("PUT", "/v1/state", vec(t, 12))
	json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != 409 || strings.Contains(w.Body.String(), "error_kind") {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
}

func TestCredentialsRoutes(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	w := e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"phone","expires_at":null}`)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var cr map[string]any
	json.Unmarshal(w.Body.Bytes(), &cr)
	secret, _ := cr["secret"].(string)
	if !strings.HasPrefix(secret, "app_") || cr["id"] == "" || cr["created_at"] == nil {
		t.Fatalf("created %s", w.Body)
	}
	// TestSecretNeverLogged: the secret is in the answer only.
	if strings.Contains(e.log.String(), secret) {
		t.Fatal("the secret was logged")
	}
	w = e.do("GET", "/v1/credentials?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), `"label":"phone"`) || !strings.Contains(w.Body.String(), `"last_used":null`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	for body, code := range map[string]int{
		`{"username":"carol","uuid":"x","label":"x","expires_at":null}`:                                                      404,
		`{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"","expires_at":null}`:                    400,
		`{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x","expires_at":"2020-01-01T00:00:00Z"}`: 400,
		`{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x"}`:                                     400,
		`{"username":"alice","label":"x","expires_at":null}`:                                                                 400,
		`{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x","expires_at":null,"extra":1}`:         400,
		`{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x","label":"y","expires_at":null}`:       400,
	} {
		if w := e.do("POST", "/v1/credentials", body); w.Code != code {
			t.Errorf("%s: %d, want %d", body, w.Code, code)
		}
	}
	if w := e.do("GET", "/v1/credentials?uuid=0c0c0c0c-0c0c-4c0c-8c0c-0c0c0c0c0c0c", ""); w.Code != 404 {
		t.Errorf("unknown user: %d", w.Code)
	}
	id := cr["id"].(string)
	if w := e.do("DELETE", "/v1/credentials/"+id+"?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b", ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := e.do("DELETE", "/v1/credentials/"+id+"?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b", ""); w.Code != 204 {
		t.Fatalf("delete again: %d", w.Code)
	}
	for _, q := range []string{"", "?user=alice", "?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b&user=alice"} {
		if w := e.do("DELETE", "/v1/credentials/"+id+q, ""); w.Code != 400 {
			t.Errorf("DELETE %q: %d", q, w.Code)
		}
	}
	for i := 0; i < 5; i++ {
		e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"p","expires_at":null}`)
	}
	if w := e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"p","expires_at":null}`); w.Code != 409 {
		t.Fatalf("sixth: %d", w.Code)
	}
	// A revoke of an unknown id is a success (the Hub retries).
	if w := e.do("DELETE", "/v1/credentials/no-such-id?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b", ""); w.Code != 204 {
		t.Fatalf("unknown id: %d", w.Code)
	}
	e.f.Fail("x:AppPassword", 1)
	if w := e.do("GET", "/v1/credentials?uuid=6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b", ""); w.Code != 503 || !strings.Contains(w.Body.String(), "mail server unreachable") {
		t.Fatalf("stalwart down: %d %s", w.Code, w.Body)
	}
}

// GET /v1/dns, /v1/status and the actions (contract §19.5).
func TestDNSStatusActions(t *testing.T) {
	e := newV1(t)
	if w := e.do("GET", "/v1/dns/example.com", ""); w.Code != 404 {
		t.Fatalf("dns before a document: %d", w.Code)
	}
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.M.Step(context.Background())
	w := e.do("GET", "/v1/dns/example.com", "")
	var set map[string]any
	json.Unmarshal(w.Body.Bytes(), &set)
	if w.Code != 200 || set["domain"] != "example.com" || set["dkim"] != "auto" || len(set["records"].([]any)) < 10 {
		t.Fatalf("dns %d %s", w.Code, w.Body)
	}
	if _, ok := set["tlsa"]; ok || len(set) != 3 {
		t.Fatalf("the set's keys: %s", w.Body)
	}
	if w := e.do("GET", "/v1/dns/team-b.example.org?wildcard=false", ""); w.Code != 200 || strings.Count(w.Body.String(), `"CNAME"`) != 3 {
		t.Fatalf("no wildcard %d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/v1/dns/team-b.example.org?wildcard=no", ""); w.Code != 400 {
		t.Fatalf("bad wildcard %d", w.Code)
	}
	if w := e.do("GET", "/v1/dns/nope.example", ""); w.Code != 404 {
		t.Fatalf("unknown domain %d", w.Code)
	}
	w = e.do("GET", "/v1/status", "")
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	for _, k := range []string{"bootstrap", "provider", "cert", "dkim", "mtasts", "dmarc", "queue", "restored_at", "former", "dns"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("status lacks %s: %s", k, w.Body)
		}
	}
	if len(st) != 10 || len(st["dkim"].([]any)) != 2 || st["provider"].(map[string]any)["name"] != "Stalwart" {
		t.Fatalf("status %s", w.Body)
	}
	cases := []struct {
		path, body string
		code       int
	}{
		{"/v1/actions/dkim-rotate", `{"domain":"nope.example"}`, 404},
		{"/v1/actions/dkim-rotate", `{"domain":"example.com"}`, 409}, // keys pending
		{"/v1/actions/dmarc-promote", `{"domain":"example.com"}`, 409},
		{"/v1/actions/mtasts-enforce", `{"domain":"example.com"}`, 409},
		{"/v1/actions/mtasts-enforce", `{"domain":"example.com","x":1}`, 400},
		{"/v1/actions/mtasts-enforce", `{"domain":"a","domain":"b"}`, 400},
		{"/v1/actions/mtasts-enforce", `{}`, 400},
		{"/v1/actions/nope", `{"domain":"example.com"}`, 404},
	}
	for _, c := range cases {
		if w := e.do("POST", c.path, c.body); w.Code != c.code {
			t.Errorf("%s %s: %d %s", c.path, c.body, w.Code, w.Body)
		} else if c.code == 409 && !strings.Contains(w.Body.String(), `"error"`) {
			t.Errorf("409 without a reason: %s", w.Body)
		}
	}
	e.f.Fail("x:QueuedMessage", 1)
	if w := e.do("GET", "/v1/status", ""); w.Code != 503 || !strings.Contains(w.Body.String(), "mail server unreachable") {
		t.Fatalf("status with Stalwart down: %d %s", w.Code, w.Body)
	}
}

func TestChecksRoute(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	w := e.do("GET", "/v1/checks", "")
	var res struct {
		CheckedAt time.Time `json:"checked_at"`
		Checks    []map[string]any
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &res) != nil || res.CheckedAt.IsZero() || len(res.Checks) < 8 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := e.do("GET", "/v1/checks?refresh=yes", ""); w.Code != 400 {
		t.Fatalf("bad refresh %d", w.Code)
	}
	if w := e.do("GET", "/v1/checks?refresh=1", ""); w.Code != 200 {
		t.Fatalf("refresh %d", w.Code)
	}
}

// Security review: the request names the person by uuid; another uuid or
// a parked account under that username is refused (409 account_mismatch).
func TestCreateCredentialAccountMismatch(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	kind := func(w *httptest.ResponseRecorder) string {
		var b map[string]string
		json.Unmarshal(w.Body.Bytes(), &b)
		return b["error_kind"]
	}
	w := e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d","label":"x","expires_at":null}`)
	if w.Code != 409 || kind(w) != "account_mismatch" || !strings.Contains(w.Body.String(), "the account alice belongs to another person") {
		t.Fatalf("other uuid: %d %s", w.Code, w.Body)
	}
	// The live account named alice carries another uuid (a re-created
	// LLDAP name the reconciler hasn't caught up with).
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == "alice" {
			e.f.Put("Account", "", map[string]any{"id": a["id"], "@type": "User", "name": "alice", "domainId": a["domainId"], "description": "portcullis:aaaaaaaa-0000-4000-8000-000000000000"})
		}
	}
	w = e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x","expires_at":null}`)
	if w.Code != 409 || kind(w) != "account_mismatch" {
		t.Fatalf("live uuid differs: %d %s", w.Code, w.Body)
	}
	if n := len(e.f.Objects("AppPassword", "")); n != 0 {
		t.Fatalf("%d passwords made", n)
	}
	// bob's account is parked (removed, the rejoin not reconciled yet).
	e2 := newV1(t)
	e2.do("PUT", "/v1/state", vec(t, 12))
	_ = e2.v.Runner.Once(context.Background())
	var park string
	for _, d := range e2.f.Objects("Domain", "") {
		if d["name"] == state.ParkingDomain {
			park = d["id"].(string)
		}
	}
	for _, a := range e2.f.Objects("Account", "") {
		if a["name"] == "bob" {
			e2.f.Put("Account", "", map[string]any{"@type": "User", "name": "former-0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d", "domainId": park, "description": "portcullis:0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"})
		}
	}
	w = e2.do("POST", "/v1/credentials", `{"username":"bob","uuid":"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d","label":"x","expires_at":null}`)
	if w.Code != 409 || kind(w) != "account_mismatch" {
		t.Fatalf("parked: %d %s", w.Code, w.Body)
	}
}

// Security review (TOCTOU): one document snapshot and one live read decide
// the account; a document swapped in meanwhile can't redirect the password,
// and no document at all is 503 (never a skipped check).
func TestCreateCredentialSnapshot(t *testing.T) {
	e := newV1(t)
	body := `{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x","expires_at":null}`
	if w := e.do("POST", "/v1/credentials", body); w.Code != 503 || !strings.Contains(w.Body.String(), "no accepted mail document") {
		t.Fatalf("no document: %d %s", w.Code, w.Body)
	}
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	var alice, bob string
	for _, a := range e.f.Objects("Account", "") {
		switch a["name"] {
		case "alice":
			alice = a["id"].(string)
		case "bob":
			bob = a["id"].(string)
		}
	}
	// Between the check and the create, the stored document gives alice
	// bob's uuid (and bob alice's).
	e.v.beforeCreate = func() {
		e.v.Store.Update(func(p *state.Persistent) error {
			for i := range p.Doc.Accounts {
				switch p.Doc.Accounts[i].Username {
				case "alice":
					p.Doc.Accounts[i].UUID = "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"
				case "bob":
					p.Doc.Accounts[i].UUID = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
				}
			}
			return nil
		})
	}
	w := e.do("POST", "/v1/credentials", body)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if len(e.f.Objects("AppPassword", alice)) != 1 || len(e.f.Objects("AppPassword", bob)) != 0 {
		t.Fatalf("the password went to the wrong account: alice %d bob %d", len(e.f.Objects("AppPassword", alice)), len(e.f.Objects("AppPassword", bob)))
	}
}

// DELETE goes by the account's uuid: a username re-created under a new
// uuid keeps its own same-numbered credential when the old person's is
// revoked; an unknown uuid is 204.
func TestDeleteCredentialByUUID(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	var park, alice string
	for _, d := range e.f.Objects("Domain", "") {
		if d["name"] == state.ParkingDomain {
			park = d["id"].(string)
		}
	}
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == "alice" {
			alice = a["id"].(string)
		}
	}
	const old = "aaaaaaaa-0000-4000-8000-000000000001"
	former := e.f.Put("Account", "", map[string]any{"@type": "User", "name": "former-" + old, "domainId": park, "description": "portcullis:" + old})
	e.f.PutID("AppPassword", former, "p1", map[string]any{"description": "old phone"})
	e.f.PutID("AppPassword", alice, "p1", map[string]any{"description": "new phone"})
	if w := e.do("DELETE", "/v1/credentials/p1?uuid="+old, ""); w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if len(e.f.Objects("AppPassword", former)) != 0 || len(e.f.Objects("AppPassword", alice)) != 1 {
		t.Fatalf("former %d alice %d", len(e.f.Objects("AppPassword", former)), len(e.f.Objects("AppPassword", alice)))
	}
	if w := e.do("DELETE", "/v1/credentials/p1?uuid=bbbbbbbb-0000-4000-8000-000000000002", ""); w.Code != 204 || len(e.f.Objects("AppPassword", alice)) != 1 {
		t.Fatalf("unknown uuid: %d", w.Code)
	}
}

// A create racing a pass that parks the account (final review M2): the
// pass waits for the create (the pass lock), then parks the account and
// destroys every password, the new one included; never a password left
// on a parked account.
func TestCreateCredentialRacesPark(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	var alice string
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == "alice" {
			alice = a["id"].(string)
		}
	}
	done := make(chan struct{})
	e.v.beforeCreate = func() {
		// The Hub's next document drops alice; the runner's pass starts
		// now, between the checks and the create.
		e.v.Store.Update(func(p *state.Persistent) error {
			var keep []state.Account
			for _, a := range p.Doc.Accounts {
				if a.Username != "alice" {
					keep = append(keep, a)
				}
			}
			p.Doc.Accounts = keep
			var al []state.Alias
			for _, a := range p.Doc.Aliases {
				if a.Username != "alice" {
					al = append(al, a)
				}
			}
			p.Doc.Aliases = al
			for i := range p.Doc.Lists {
				var m []string
				for _, x := range p.Doc.Lists[i].Members {
					if x != "alice" {
						m = append(m, x)
					}
				}
				p.Doc.Lists[i].Members = m
			}
			var pm []string
			for _, x := range p.Doc.Postmaster {
				if x != "alice" {
					pm = append(pm, x)
				}
			}
			p.Doc.Postmaster = pm
			p.Doc.Generation, p.Generation = 13, 13
			return nil
		})
		go func() { _ = e.v.Runner.Once(context.Background()); close(done) }()
		time.Sleep(200 * time.Millisecond) // the pass is waiting for the create
	}
	w := e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b","label":"x","expires_at":null}`)
	<-done
	if w.Code != 201 && w.Code != 404 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	a := e.f.Get("Account", "", alice)
	if a == nil || !strings.HasPrefix(fmt.Sprint(a["name"]), "former-") {
		t.Fatalf("alice not parked: %v", a)
	}
	if n := len(e.f.Objects("AppPassword", alice)); n != 0 {
		t.Fatalf("%d password(s) left on the parked account", n)
	}
}

// Final review L9: two accounts carrying the same uuid both lose the
// password id; 204 only once both did.
func TestDeleteCredentialEveryUUIDMatch(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	const u = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
	var alice string
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == "alice" {
			alice = fmt.Sprint(a["id"])
		}
	}
	twin := e.f.Put("Account", "", map[string]any{"@type": "User", "name": "alice2", "domainId": "x", "description": reconcile.DescPrefix + u})
	p1 := e.f.Put("AppPassword", alice, map[string]any{"description": "phone"})
	e.f.Put("AppPassword", twin, map[string]any{"description": "phone"})
	// The fake numbers ids store-wide: give the twin's the same id.
	for _, p := range e.f.Objects("AppPassword", twin) {
		e.f.Delete("AppPassword", twin, fmt.Sprint(p["id"]))
	}
	e.f.PutID("AppPassword", twin, p1, map[string]any{"description": "phone"})
	if w := e.do("DELETE", "/v1/credentials/"+p1+"?uuid="+u, ""); w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if len(e.f.Objects("AppPassword", alice))+len(e.f.Objects("AppPassword", twin)) != 0 {
		t.Fatal("a twin account kept the password")
	}
	e.f.PutID("AppPassword", twin, p1, map[string]any{"description": "phone"})
	e.f.Fail("x:AppPassword/set", 2)
	if w := e.do("DELETE", "/v1/credentials/"+p1+"?uuid="+u, ""); w.Code == 204 {
		t.Fatal("204 although a revoke failed")
	}
}
