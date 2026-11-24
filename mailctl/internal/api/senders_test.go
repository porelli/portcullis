package api

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	uHubSender = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
	uAppSender = "7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e"
	uAlice     = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
)

func senderVec(t *testing.T, gen int) string {
	b, err := os.ReadFile("../state/testdata/mailstate_v2_senders.json")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(b), `"generation":12`, `"generation":`+itoa(gen), 1)
}

func (e *v1env) accountID(name string) string {
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == name {
			return a["id"].(string)
		}
	}
	return ""
}

// PUT /v1/state takes senders absent (an older Hub), present, and empty
// (ruling C1), and refuses a malformed sender whole (400, the last
// accepted document kept).
func TestPutStateSenders(t *testing.T) {
	e := newV1(t)
	if w := e.do("PUT", "/v1/state", vec(t, 12)); w.Code != 202 {
		t.Fatalf("absent: %d %s", w.Code, w.Body)
	}
	if w := e.do("PUT", "/v1/state", senderVec(t, 13)); w.Code != 202 {
		t.Fatalf("present: %d %s", w.Code, w.Body)
	}
	_ = e.v.Runner.Once(context.Background())
	if e.accountID("portcullis-app-firefox-sync-fxa") == "" {
		t.Fatal("no sender account")
	}
	bad := strings.Replace(senderVec(t, 14), `"address":"portcullis-hub-mail@example.com"`, `"address":"alice@example.com"`, 1)
	if w := e.do("PUT", "/v1/state", bad); w.Code != 400 {
		t.Fatalf("a sender on a person's address: %d %s", w.Code, w.Body)
	}
	if e.v.Store.Get().Generation != 13 {
		t.Fatal("a refused document replaced the accepted one")
	}
	// Every sender removed: never a mass removal (409), whatever the count.
	empty := strings.Replace(vec(t, 15), `"aliases":`, `"senders":[],"aliases":`, 1)
	if w := e.do("PUT", "/v1/state", empty); w.Code != 202 {
		t.Fatalf("empty senders: %d %s", w.Code, w.Body)
	}
	_ = e.v.Runner.Once(context.Background())
	if e.accountID("portcullis-app-firefox-sync-fxa") != "" || e.accountID("portcullis-hub-mail") != "" {
		t.Fatal("an empty senders list kept a sender")
	}
}

// A sender's credential (§19.14, §19.5): the sender's permissions only
// (authenticate, emailSend); no allowed_ips (400); LAN-only applies to it
// as to a person's (the Local networks at the create and on every pass);
// listed and revoked by the sender's uuid; a wrong uuid is
// account_mismatch.
func TestSenderCredential(t *testing.T) {
	e := newV1(t)
	if w := e.do("PUT", "/v1/state", senderVec(t, 12)); w.Code != 202 {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	if err := e.v.Runner.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	app := e.accountID("portcullis-app-firefox-sync-fxa")
	body := `{"username":"portcullis-app-firefox-sync-fxa","uuid":"` + uAppSender + `","label":"firefox-sync-fxa","expires_at":null}`
	w := e.do("POST", "/v1/credentials", body)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var cr map[string]any
	json.Unmarshal(w.Body.Bytes(), &cr)
	secret, _ := cr["secret"].(string)
	if secret == "" || strings.Contains(e.log.String(), secret) {
		t.Fatal("no secret, or the secret was logged")
	}
	pws := e.f.Objects("AppPassword", app)
	if len(pws) != 1 {
		t.Fatalf("%d passwords on the sender", len(pws))
	}
	perms := pws[0]["permissions"].(map[string]any)
	got := perms["permissions"].(map[string]any)
	if perms["@type"] != "Replace" || len(got) != 2 || got["authenticate"] != true || got["emailSend"] != true {
		t.Fatalf("the sender's credential permissions %v", perms)
	}
	if pws[0]["allowedIps"] != nil {
		t.Fatalf("allowedIps %v without LAN-only (want the field left out: anywhere)", pws[0]["allowedIps"])
	}
	// LAN-only on: the pass restricts the sender's credential to the
	// Local networks, and a new one is made with them.
	lan := strings.Replace(senderVec(t, 13), `"submission_lan_only":false`, `"submission_lan_only":true`, 1)
	if w := e.do("PUT", "/v1/state", lan); w.Code != 202 {
		t.Fatalf("put LAN-only: %d %s", w.Code, w.Body)
	}
	_ = e.v.Runner.Once(context.Background())
	if ips, _ := e.f.Objects("AppPassword", app)[0]["allowedIps"].(map[string]any); len(ips) != 1 || ips["10.0.0.0/8"] != true {
		t.Fatalf("LAN-only left the sender's credential at %v (want the Local networks)", ips)
	}
	w = e.do("POST", "/v1/credentials", `{"username":"portcullis-hub-mail","uuid":"`+uHubSender+`","label":"Portcullis","expires_at":null}`)
	if w.Code != 201 {
		t.Fatalf("hub sender: %d %s", w.Code, w.Body)
	}
	if p := e.f.Objects("AppPassword", e.accountID("portcullis-hub-mail")); len(p) != 1 || len(p[0]["allowedIps"].(map[string]any)) != 1 {
		t.Fatalf("hub sender's password under LAN-only %v", p)
	}
	w = e.do("GET", "/v1/credentials?uuid="+uAppSender, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"allowed_ips":["10.0.0.0/8"]`) || strings.Contains(w.Body.String(), secret) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	for b, code := range map[string]int{
		`{"username":"portcullis-app-firefox-sync-fxa","uuid":"` + uHubSender + `","label":"x","expires_at":null}`:                                 409,
		`{"username":"portcullis-app-other","uuid":"` + uAppSender + `","label":"x","expires_at":null}`:                                            404,
		`{"username":"portcullis-app-firefox-sync-fxa","uuid":"` + uAppSender + `","label":"x","expires_at":null,"allowed_ips":["10.0.0.0/8"]}`:    400,
		`{"username":"portcullis-app-firefox-sync-fxa","uuid":"` + uAppSender + `","label":"x","expires_at":null,"allowed_ips":["172.18.0.0/16"]}`: 400,
		`{"username":"portcullis-app-firefox-sync-fxa","uuid":"` + uAppSender + `","label":"x","expires_at":null,"allowed_ips":[]}`:                400,
		`{"username":"portcullis-app-firefox-sync-fxa","uuid":"` + uAppSender + `","label":"x","expires_at":null,"allowed_ips":null}`:              400,
	} {
		if w := e.do("POST", "/v1/credentials", b); w.Code != code {
			t.Errorf("%s: %d %s, want %d", b, w.Code, w.Body, code)
		}
	}
	if n := len(e.f.Objects("AppPassword", app)); n != 1 {
		t.Fatalf("a refused create made a password (%d)", n)
	}
	id := cr["id"].(string)
	if w := e.do("DELETE", "/v1/credentials/"+id+"?uuid="+uAppSender, ""); w.Code != 204 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if n := len(e.f.Objects("AppPassword", app)); n != 0 {
		t.Fatal("the sender's credential survived its revoke")
	}
}

// A person's credential: allowed_ips is optional (absent = today's
// behaviour); given, it is used, except under LAN-only, where a person's
// passwords are always the Local networks (refused, never silently
// replaced).
func TestPersonCredentialAllowedIPs(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	w := e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"`+uAlice+`","label":"x","expires_at":null,"allowed_ips":["192.168.1.0/24"]}`)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	p := e.f.Objects("AppPassword", e.accountID("alice"))
	if len(p) != 1 || len(p[0]["allowedIps"].(map[string]any)) != 1 {
		t.Fatalf("alice's password %v", p)
	}
	perms := p[0]["permissions"].(map[string]any)["permissions"].(map[string]any)
	if perms["imapAuthenticate"] != true || perms["emailReceive"] != true {
		t.Fatalf("a person's password lost its mail permissions: %v", perms)
	}
	lan := strings.Replace(vec(t, 13), `"submission_lan_only":false`, `"submission_lan_only":true`, 1)
	e.do("PUT", "/v1/state", lan)
	if w := e.do("POST", "/v1/credentials", `{"username":"alice","uuid":"`+uAlice+`","label":"x","expires_at":null,"allowed_ips":["192.168.1.0/24"]}`); w.Code != 400 {
		t.Fatalf("LAN-only with allowed_ips: %d %s", w.Code, w.Body)
	}
}
