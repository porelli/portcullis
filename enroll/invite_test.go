package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef-client"
const testAPISecret = "0123456789abcdef0123456789abcdef-api"

func testInvites(t *testing.T) (*inviteService, *[]string) {
	t.Helper()
	if templates == nil {
		templates = template.Must(template.ParseFS(webFS, "web/*.html"))
	}
	required := &[]string{}
	s, err := newInviteService("example.org", testSecret, testAPISecret,
		func(u string) (*User, error) {
			if u == "alice" || u == "admin" || u == "bob" || u == "carol" || u == "dave" || u == "portcullis-hub" {
				return &User{Username: u}, nil
			}
			return nil, errors.New("not found")
		},
		func(u string) error { *required = append(*required, u); return nil },
		func(u string) error { *required = append(*required, "totp:"+u); return nil })
	if err != nil {
		t.Fatal(err)
	}
	s.userGroups = func(u string) ([]string, error) {
		switch u {
		case "carol":
			return []string{"users_wiki", "lldap_admin"}, nil
		case "dave":
			return nil, errors.New("ldap down")
		}
		return []string{"users_wiki"}, nil
	}
	s.protectedGroups = protectedGroupSet("ops_root", "/nonexistent")
	return s, required
}

// inviteMux is the public listener as main serves it.
func inviteMux(s *inviteService) http.Handler {
	return http.NewCrossOriginProtection().Handler(publicMux(&Server{}, s))
}

func do(h http.Handler, method, target string, body string, hdr map[string]string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func apiCreate(t *testing.T, s *inviteService, local bool, user, auth string) (*httptest.ResponseRecorder, map[string]string) {
	t.Helper()
	hdr := map[string]string{"Content-Type": "application/json"}
	if auth != "" {
		hdr["Authorization"] = auth
	}
	w := do(s.apiHandler(local), "POST", "/internal/invites", `{"username":"`+user+`"}`, hdr)
	out := map[string]string{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func TestInviteAPIAuthAndProtectedAccounts(t *testing.T) {
	s, _ := testInvites(t)
	if w, _ := apiCreate(t, s, false, "alice", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no secret: %d", w.Code)
	}
	if w, _ := apiCreate(t, s, false, "alice", "Bearer wrong"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", w.Code)
	}
	for _, u := range []string{"admin", "portcullis-hub"} {
		if w, _ := apiCreate(t, s, false, u, "Bearer "+testAPISecret); w.Code != http.StatusConflict {
			t.Fatalf("%s via the Hub API: %d", u, w.Code)
		}
	}
	if w, _ := apiCreate(t, s, false, "nobody", "Bearer "+testAPISecret); w.Code != http.StatusNotFound {
		t.Fatalf("unknown user: %d", w.Code)
	}
	w, out := apiCreate(t, s, false, "alice", "Bearer "+testAPISecret)
	if w.Code != http.StatusCreated || !strings.HasPrefix(out["url"], "https://enroll.example.org/invite/") || out["expires_at"] == "" {
		t.Fatalf("create: %d %v", w.Code, out)
	}
	exp, _ := time.Parse(time.RFC3339, out["expires_at"])
	if d := time.Until(exp); d < 71*time.Hour || d > 73*time.Hour {
		t.Fatalf("default expiry %s", d)
	}
	// Loopback (docker exec): the bootstrap admin, never the Hub's account.
	if w, _ := apiCreate(t, s, true, "admin", ""); w.Code != http.StatusCreated {
		t.Fatalf("admin via exec: %d", w.Code)
	}
	if w, _ := apiCreate(t, s, true, "portcullis-hub", ""); w.Code != http.StatusConflict {
		t.Fatalf("portcullis-hub via exec: %d", w.Code)
	}
}

func token(u string) string { return u[strings.LastIndex(u, "/")+1:] }

func TestInviteFullFlow(t *testing.T) {
	s, required := testInvites(t)
	h := inviteMux(s)
	_, first := apiCreate(t, s, false, "alice", "Bearer "+testAPISecret)
	_, out := apiCreate(t, s, false, "alice", "Bearer "+testAPISecret)
	tok := token(out["url"])
	// A new invite revokes the older one.
	if w := do(h, "GET", "/invite/"+token(first["url"]), "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("revoked invite still shown: %d", w.Code)
	}
	// Viewing does not consume.
	for i := 0; i < 2; i++ {
		if w := do(h, "GET", "/invite/"+tok, "", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "alice") {
			t.Fatalf("show %d: %d", i, w.Code)
		}
	}
	// Cross-site POST is refused (login CSRF).
	if w := do(h, "POST", "/invite/"+tok, "", map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site redeem: %d", w.Code)
	}
	w := do(h, "POST", "/invite/"+tok, "", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("redeem: %d %s", w.Code, w.Body)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Host != "auth.example.org" || loc.Path != "/oauth2/start" || loc.Query().Get("kc_idp_hint") != inviteIdPAlias ||
		loc.Query().Get("rd") != "https://example.org/" || loc.Query().Get("prompt") != "login" {
		t.Fatalf("redirect %s", loc)
	}
	if len(*required) != 1 || (*required)[0] != "alice" {
		t.Fatalf("required action not set: %v", *required)
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Name != inviteCookie || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/invite/" {
		t.Fatalf("cookie %+v", cookie)
	}
	// Single use.
	if w := do(h, "POST", "/invite/"+tok, "", map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != http.StatusNotFound {
		t.Fatalf("second redeem: %d", w.Code)
	}

	verifier := "verifier-verifier-verifier-verifier-verifier"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {inviteClientID}, "redirect_uri": {s.redirectURI()}, "response_type": {"code"},
		"state": {"st"}, "nonce": {"n0"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}, "scope": {"openid"}}
	// Wrong redirect URI: never redirected.
	bad := url.Values{}
	for k, v := range q {
		bad[k] = v
	}
	bad.Set("redirect_uri", "https://evil.example.com/cb")
	if w := do(h, "GET", "/invite/authorize?"+bad.Encode(), "", map[string]string{"Cookie": cookie.Name + "=" + cookie.Value}); w.Code != http.StatusNotFound || w.Header().Get("Location") != "" {
		t.Fatalf("bad redirect_uri: %d %s", w.Code, w.Header().Get("Location"))
	}
	// No cookie: refused.
	if w := do(h, "GET", "/invite/authorize?"+q.Encode(), "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("authorize without cookie: %d", w.Code)
	}
	w = do(h, "GET", "/invite/authorize?"+q.Encode(), "", map[string]string{"Cookie": cookie.Name + "=" + cookie.Value})
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", w.Code, w.Body)
	}
	cb, _ := url.Parse(w.Header().Get("Location"))
	if cb.Scheme+"://"+cb.Host+cb.Path != s.redirectURI() || cb.Query().Get("state") != "st" {
		t.Fatalf("callback %s", cb)
	}
	code := cb.Query().Get("code")
	// The redemption cookie is single use too.
	if w := do(h, "GET", "/invite/authorize?"+q.Encode(), "", map[string]string{"Cookie": cookie.Name + "=" + cookie.Value}); w.Code != http.StatusNotFound {
		t.Fatalf("second authorize: %d", w.Code)
	}

	tokenReq := func(secret, verifier, code string) *httptest.ResponseRecorder {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.redirectURI()},
			"client_id": {inviteClientID}, "client_secret": {secret}, "code_verifier": {verifier}}
		return do(s.internalHandler(), "POST", "/oidc/token", f.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}
	if w := tokenReq("wrong", verifier, code); w.Code != http.StatusUnauthorized {
		t.Fatalf("token with a wrong secret: %d", w.Code)
	}
	if w := tokenReq(testSecret, "wrong-verifier", code); w.Code != http.StatusBadRequest {
		t.Fatalf("token with a wrong verifier: %d", w.Code)
	}
	// The failed PKCE attempt burnt the code: get a fresh one.
	_, out = apiCreate(t, s, false, "alice", "Bearer "+testAPISecret)
	w = do(h, "POST", "/invite/"+token(out["url"]), "", map[string]string{"Sec-Fetch-Site": "same-origin"})
	cookie = w.Result().Cookies()[0]
	w = do(h, "GET", "/invite/authorize?"+q.Encode(), "", map[string]string{"Cookie": cookie.Name + "=" + cookie.Value})
	cb, _ = url.Parse(w.Header().Get("Location"))
	code = cb.Query().Get("code")
	w = tokenReq(testSecret, verifier, code)
	if w.Code != 200 {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	json.Unmarshal(w.Body.Bytes(), &tr)
	claims := verifyJWT(t, s, tr.IDToken)
	if claims["sub"] != "alice" || claims["preferred_username"] != "alice" || claims["aud"] != inviteClientID ||
		claims["iss"] != "https://enroll.example.org/invite" || claims["nonce"] != "n0" {
		t.Fatalf("claims %v", claims)
	}
	if w := tokenReq(testSecret, verifier, code); w.Code != http.StatusBadRequest {
		t.Fatalf("code reuse: %d", w.Code)
	}
}

func verifyJWT(t *testing.T, s *inviteService, jwt string) map[string]any {
	t.Helper()
	w := do(s.internalHandler(), "GET", "/oidc/jwks", "", nil)
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	json.Unmarshal(w.Body.Bytes(), &jwks)
	k := jwks.Keys[0]
	xb, _ := base64.RawURLEncoding.DecodeString(k["x"])
	yb, _ := base64.RawURLEncoding.DecodeString(k["y"])
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	parts := strings.Split(jwt, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("id_token signature does not verify against the JWKS")
	}
	var hdr map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	json.Unmarshal(hb, &hdr)
	if hdr["alg"] != "ES256" || hdr["kid"] != k["kid"] {
		t.Fatalf("header %v", hdr)
	}
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	claims := map[string]any{}
	json.Unmarshal(pb, &claims)
	return claims
}

func TestInviteExpiryAndLanding(t *testing.T) {
	s, _ := testInvites(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	tok, _, err := s.Create("bob", "https://hub.example.org/", time.Hour, false, inviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if s.peek(tok) != nil {
		t.Fatal("expired invite still valid")
	}
	for _, l := range []string{"http://example.org/", "https://evil.com/", "https://example.org.evil.com/", "https://u@example.org/", "https://example.org:8443/"} {
		if _, _, err := s.Create("bob", l, 0, false, inviteOptions{}); err == nil {
			t.Fatalf("landing %s accepted", l)
		}
	}
	if _, _, err := s.Create("bob", "", 8*24*time.Hour, false, inviteOptions{}); err == nil {
		t.Fatal("ttl above the maximum accepted")
	}
	if s.peek("short") != nil || s.consume("../../etc") != nil {
		t.Fatal("malformed token accepted")
	}
}

func TestInviteKeycloakDownKeepsTheLink(t *testing.T) {
	s, _ := testInvites(t)
	s.requirePasskey = func(string) error { return errors.New("down") }
	tok, _, _ := s.Create("alice", "", 0, false, inviteOptions{})
	if w := do(inviteMux(s), "POST", "/invite/"+tok, "", map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("redeem with Keycloak down: %d", w.Code)
	}
	if s.peek(tok) == nil {
		t.Fatal("the link was consumed although Keycloak was down")
	}
}

func TestInviteAPIRefusesAdministrators(t *testing.T) {
	s, _ := testInvites(t)
	auth := "Bearer " + testAPISecret
	if w, out := apiCreate(t, s, false, "carol", auth); w.Code != http.StatusConflict || !strings.Contains(out["error"], "./portcullis invite") {
		t.Fatalf("lldap_admin member via the Hub API: %d %v", w.Code, out)
	}
	if w, _ := apiCreate(t, s, false, "dave", auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("group lookup failure must fail closed: %d", w.Code)
	}
	s.userGroups = func(string) ([]string, error) { return []string{"ops_root"}, nil }
	if w, _ := apiCreate(t, s, false, "alice", auth); w.Code != http.StatusConflict {
		t.Fatalf("INVITE_PROTECTED_GROUPS member: %d", w.Code)
	}
	s.userGroups = nil
	if w, _ := apiCreate(t, s, false, "alice", auth); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no group lookup configured must fail closed: %d", w.Code)
	}
	// The server (docker exec) may invite administrators.
	if w, _ := apiCreate(t, s, true, "carol", ""); w.Code != http.StatusCreated {
		t.Fatalf("lldap_admin member via exec: %d", w.Code)
	}
}

func TestProtectedGroupsFromTheMap(t *testing.T) {
	f := t.TempDir() + "/map.conf"
	os.WriteFile(f, []byte("# x\nhub=lldap_admin\nmetrics=grafana_admins\nwiki=users_wiki\n"), 0o600)
	set := protectedGroupSet("", f)
	if !set["lldap_admin"] || !set["lldap_password_manager"] || !set["grafana_admins"] || set["users_wiki"] {
		t.Fatalf("%v", set)
	}
}

// TOCTOU: an API invite for a normal user who becomes an administrator
// before redeeming it must not hand over the admin account.
func TestInviteAPIRecheckAfterPromotion(t *testing.T) {
	s, required := testInvites(t)
	h := inviteMux(s)
	auth := "Bearer " + testAPISecret
	groups := map[string][]string{"alice": {"users_wiki"}}
	lookupFails := false
	s.userGroups = func(u string) ([]string, error) {
		if lookupFails {
			return nil, errors.New("ldap down")
		}
		return groups[u], nil
	}
	same := map[string]string{"Sec-Fetch-Site": "same-origin"}
	verifier := "verifier-verifier-verifier-verifier-verifier"
	sum := sha256.Sum256([]byte(verifier))
	authz := url.Values{"client_id": {inviteClientID}, "redirect_uri": {s.redirectURI()}, "response_type": {"code"},
		"state": {"st"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"}}.Encode()
	mint := func() string {
		w, out := apiCreate(t, s, false, "alice", auth)
		if w.Code != http.StatusCreated {
			t.Fatalf("create: %d", w.Code)
		}
		return token(out["url"])
	}
	redeem := func(tok string) *httptest.ResponseRecorder { return do(h, "POST", "/invite/"+tok, "", same) }
	authorize := func(c *http.Cookie) *httptest.ResponseRecorder {
		return do(h, "GET", "/invite/authorize?"+authz, "", map[string]string{"Cookie": c.Name + "=" + c.Value})
	}
	exchange := func(code string) *httptest.ResponseRecorder {
		f := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.redirectURI()},
			"client_id": {inviteClientID}, "client_secret": {testSecret}, "code_verifier": {verifier}}
		return do(s.internalHandler(), "POST", "/oidc/token", f.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	}

	// 1. Promoted before redeeming: refused, the invite is cancelled, no
	//    required action was set.
	tok := mint()
	groups["alice"] = []string{"users_wiki", "lldap_admin"}
	if w := redeem(tok); w.Code != http.StatusForbidden {
		t.Fatalf("redeem after promotion: %d", w.Code)
	}
	if len(*required) != 0 {
		t.Fatalf("required action set for a promoted user: %v", *required)
	}
	groups["alice"] = []string{"users_wiki"}
	if w := redeem(tok); w.Code != http.StatusNotFound {
		t.Fatalf("the cancelled invite still works: %d", w.Code)
	}

	// 2. Promoted between redeem and authorize: no code.
	w := redeem(mint())
	cookie := w.Result().Cookies()[0]
	groups["alice"] = []string{"lldap_admin"}
	if w := authorize(cookie); w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
		t.Fatalf("authorize after promotion: %d %s", w.Code, w.Header().Get("Location"))
	}

	// 3. Promoted between authorize and the token exchange: no id_token.
	groups["alice"] = []string{"users_wiki"}
	w = redeem(mint())
	w = authorize(w.Result().Cookies()[0])
	cb, _ := url.Parse(w.Header().Get("Location"))
	groups["alice"] = []string{"lldap_password_manager"}
	if w := exchange(cb.Query().Get("code")); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "id_token") {
		t.Fatalf("token after promotion: %d %s", w.Code, w.Body)
	}

	// 4. Lookup failure at redeem: fail closed, the link stays usable.
	groups["alice"] = []string{"users_wiki"}
	tok = mint()
	lookupFails = true
	if w := redeem(tok); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("redeem with LLDAP down: %d", w.Code)
	}
	lookupFails = false
	if s.peek(tok) == nil {
		t.Fatal("link consumed although the group check failed")
	}

	// 5. A promoted user's server-made (CLI) invite is not affected.
	groups["alice"] = []string{"lldap_admin"}
	ltok, _, err := s.Create("alice", "", 0, true, inviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if w := redeem(ltok); w.Code != http.StatusSeeOther {
		t.Fatalf("CLI invite for an administrator: %d", w.Code)
	}
}

// apiPost posts body to POST /internal/invites on the Hub's listener.
func apiPost(s *inviteService, local bool, body string) *httptest.ResponseRecorder {
	hdr := map[string]string{"Content-Type": "application/json"}
	if !local {
		hdr["Authorization"] = "Bearer " + testAPISecret
	}
	return do(s.apiHandler(local), "POST", "/internal/invites", body, hdr)
}

// T8 / P13: the body is strict over {username, ttl, landing, authenticator};
// authenticator true is kept on the invite, absent or false is no step.
func TestCreateAuthenticatorStrictBody(t *testing.T) {
	s, _ := testInvites(t)
	for _, bad := range []string{
		`{"username":"alice","authenticator":true,"x":1}`,
		`{"username":"alice","Authenticator":"yes"}`,
		`{"username":"alice","authenticator":"true"}`,
		`{"username":"alice","otp":true}`,
		`{"username":"alice"} {"username":"bob"}`,
	} {
		if w := apiPost(s, false, bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body)
		}
	}
	for body, want := range map[string]bool{
		`{"username":"alice"}`:                       false,
		`{"username":"bob","authenticator":false}`:   false,
		`{"username":"carol2","authenticator":true}`: true, // unknown user: 404, checked below
		`{"username":"alice","ttl":"1h","landing":"https://hub.example.org/","authenticator":true}`: true,
	} {
		w := apiPost(s, false, body)
		if strings.Contains(body, "carol2") {
			if w.Code != http.StatusNotFound {
				t.Errorf("%s: %d", body, w.Code)
			}
			continue
		}
		if w.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
		var out map[string]string
		json.Unmarshal(w.Body.Bytes(), &out)
		inv := s.peek(token(out["url"]))
		if inv == nil || inv.Authenticator != want {
			t.Errorf("%s: invite %+v, want authenticator %v", body, inv, want)
		}
	}
	// Protected accounts are refused with the option as without it.
	if w := apiPost(s, false, `{"username":"carol","authenticator":true}`); w.Code != http.StatusConflict {
		t.Errorf("lldap_admin member: %d", w.Code)
	}
}

// T8 / P35: the redeem adds CONFIGURE_TOTP only for an authenticator
// invite and only after the passkey action; a failure leaves the link
// unused, exactly as a passkey failure does.
func TestRedeemAddsTotpAfterPasskey(t *testing.T) {
	s, required := testInvites(t)
	h := inviteMux(s)
	redeem := func(tok string) int {
		return do(h, "POST", "/invite/"+tok, "", map[string]string{"Sec-Fetch-Site": "same-origin"}).Code
	}
	link := func(body string) string {
		w := apiPost(s, false, body)
		var out map[string]string
		json.Unmarshal(w.Body.Bytes(), &out)
		return token(out["url"])
	}
	if c := redeem(link(`{"username":"bob"}`)); c != http.StatusSeeOther {
		t.Fatalf("plain redeem: %d", c)
	}
	if strings.Join(*required, ",") != "bob" {
		t.Fatalf("plain link: %v", *required)
	}
	*required = nil
	// Keycloak refuses CONFIGURE_TOTP: 503, the link still works afterwards.
	tok := link(`{"username":"alice","authenticator":true}`)
	ok := s.requireTotp
	s.requireTotp = func(u string) error { *required = append(*required, "fail:"+u); return errors.New("down") }
	if c := redeem(tok); c != http.StatusServiceUnavailable {
		t.Fatalf("totp failure: %d", c)
	}
	if strings.Join(*required, ",") != "alice,fail:alice" {
		t.Fatalf("order on failure: %v", *required)
	}
	if s.peek(tok) == nil {
		t.Fatal("the link was used up by a failed redeem")
	}
	// The passkey step failing never reaches the authenticator step.
	*required = nil
	pk := s.requirePasskey
	s.requirePasskey = func(u string) error { return errors.New("down") }
	if c := redeem(tok); c != http.StatusServiceUnavailable || len(*required) != 0 {
		t.Fatalf("passkey failure: %d %v", c, *required)
	}
	s.requirePasskey, s.requireTotp = pk, ok
	if c := redeem(tok); c != http.StatusSeeOther {
		t.Fatalf("retry: %d", c)
	}
	if strings.Join(*required, ",") != "alice,totp:alice" {
		t.Fatalf("order: %v", *required)
	}
	if c := redeem(tok); c != http.StatusNotFound {
		t.Fatalf("second redeem: %d", c)
	}
}

// T8: the server's CLI (the loopback listener, `enroll invite`) never makes
// an authenticator link: its body has no such key, and the listener
// refuses one.
func TestCLINeverAuthenticator(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(inviteCommandBody("admin", "1h", "https://hub.example.org/"), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["authenticator"]; ok {
		t.Fatalf("CLI body %v", m)
	}
	s, required := testInvites(t)
	if w := apiPost(s, true, `{"username":"admin","authenticator":true}`); w.Code != http.StatusBadRequest {
		t.Fatalf("loopback authenticator: %d %s", w.Code, w.Body)
	}
	if _, _, err := s.Create("alice", "", 0, true, inviteOptions{Authenticator: true}); !errors.Is(err, errAuthenticatorCLI) {
		t.Fatalf("Create(local, authenticator): %v", err)
	}
	// Without a requireTotp (not wired), the Hub's option is refused too
	// (503, its own text): fail closed, never a link without the step.
	s.requireTotp = nil
	if w := apiPost(s, false, `{"username":"alice","authenticator":true}`); w.Code != http.StatusServiceUnavailable ||
		!strings.Contains(w.Body.String(), "isn't available on this server") {
		t.Fatalf("no requireTotp: %d %s", w.Code, w.Body)
	}
	if w := apiPost(s, true, `{"username":"admin"}`); w.Code != http.StatusCreated || len(*required) != 0 {
		t.Fatalf("loopback plain: %d", w.Code)
	}
}
