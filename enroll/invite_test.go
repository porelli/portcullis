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
		func(u string) error { *required = append(*required, u); return nil })
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

func publicMux(s *inviteService) http.Handler {
	m := http.NewServeMux()
	s.register(m)
	return http.NewCrossOriginProtection().Handler(m)
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
	h := publicMux(s)
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
	tok, _, err := s.Create("bob", "https://hub.example.org/", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if s.peek(tok) != nil {
		t.Fatal("expired invite still valid")
	}
	for _, l := range []string{"http://example.org/", "https://evil.com/", "https://example.org.evil.com/", "https://u@example.org/", "https://example.org:8443/"} {
		if _, _, err := s.Create("bob", l, 0, false); err == nil {
			t.Fatalf("landing %s accepted", l)
		}
	}
	if _, _, err := s.Create("bob", "", 8*24*time.Hour, false); err == nil {
		t.Fatal("ttl above the maximum accepted")
	}
	if s.peek("short") != nil || s.consume("../../etc") != nil {
		t.Fatal("malformed token accepted")
	}
}

func TestInviteKeycloakDownKeepsTheLink(t *testing.T) {
	s, _ := testInvites(t)
	s.requirePasskey = func(string) error { return errors.New("down") }
	tok, _, _ := s.Create("alice", "", 0, false)
	if w := do(publicMux(s), "POST", "/invite/"+tok, "", map[string]string{"Sec-Fetch-Site": "same-origin"}); w.Code != http.StatusServiceUnavailable {
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
