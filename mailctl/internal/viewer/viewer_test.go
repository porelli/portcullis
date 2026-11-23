package viewer

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream records what reaches "Stalwart".
type upstream struct {
	mu        sync.Mutex
	seen      []*http.Request
	body      []string
	unmasked  bool // SystemSettings includeSecrets
	cors      bool // answer Access-Control-* headers
	readCount int
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	defer u.mu.Unlock()
	if strings.Contains(string(b), `"x:SystemSettings/get"`) && strings.Contains(string(b), "includeSecrets") && r.URL.Path == "/jmap" {
		u.readCount++
		fmt.Fprintf(w, `{"methodResponses":[["x:SystemSettings/get",{"list":[{"includeSecrets":%v,"id":"singleton"}]},"0"]]}`, u.unmasked)
		return
	}
	u.seen = append(u.seen, r.Clone(r.Context()))
	u.body = append(u.body, string(b))
	if u.cors {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	w.Header().Set("Set-Cookie", "s=1")
	w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
	w.Write([]byte(`{"ok":true}`))
}

// The tests' proxy is reached over loopback: Traefik's address there.
const testKey = "0123456789abcdefghijklmnopqrstuvwxyzABCDEF"

var testGate = Gate{TraefikIP: netip.MustParseAddr("127.0.0.1"), Key: testKey, Group: "lldap_admin"}

// ticketSecret is the per-install ticket secret (never the route key).
const ticketSecret = "ticket-secret-0123456789abcdefghijklmnop"

// testTickets: the ticket secret and a fresh spent-ticket file.
func testTickets(t *testing.T) Tickets {
	return Tickets{Secret: []byte(ticketSecret), UsedFile: filepath.Join(t.TempDir(), "used-tickets.json")}
}

const viewerPW = "0123456789abcdef0123456789abcdef"

type env struct {
	up      *upstream
	ps      *httptest.Server
	p       *Proxy
	sf      string
	now     time.Time
	cookie  string
	logs    []string
	secrets []string
}

func spkiOf(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{up: &upstream{}, now: time.Unix(1_800_000_000, 0)}
	us := httptest.NewTLSServer(e.up)
	t.Cleanup(us.Close)
	e.sf = filepath.Join(t.TempDir(), "viewer-password")
	os.WriteFile(e.sf, []byte(viewerPW+"\n"), 0o640)
	var mu sync.Mutex
	p, err := New(us.URL, "mail-admin.example.org", e.sf, []string{spkiOf(us.Certificate())}, testGate, testTickets(t),
		func(s string) { mu.Lock(); e.secrets = append(e.secrets, s); mu.Unlock() },
		func(f string, a ...any) { mu.Lock(); e.logs = append(e.logs, fmt.Sprintf(f, a...)); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return e.now }
	e.p = p
	e.ps = httptest.NewServer(p)
	t.Cleanup(e.ps.Close)
	return e
}

func (e *env) ticket(user string, ttl time.Duration) string {
	return MintTicket(TicketKey([]byte(ticketSecret)), user, randomToken(), e.now.Add(ttl))
}

// openSession opens a session for root with a fresh ticket.
func (e *env) openSession(t *testing.T) {
	t.Helper()
	resp := e.open(t, e.ticket("root", 60*time.Second), nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin/" {
		t.Fatalf("open: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie && c.Secure && c.HttpOnly && c.SameSite == http.SameSiteStrictMode && c.Path == "/" {
			e.cookie = c.Value
		}
	}
	if e.cookie == "" {
		t.Fatal("no session cookie")
	}
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// open posts a ticket to /portcullis/open as the Hub's page does.
func (e *env) open(t *testing.T, ticket string, hdr map[string]string) *http.Response {
	t.Helper()
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range hdr {
		h[k] = v
	}
	return e.do(t, "POST", "/portcullis/open", url.Values{"t": {ticket}}.Encode(), h)
}

// do sends a request as Traefik would after forward-auth (route key,
// groups, user), with the session cookie once opened; hdr overrides ("" =
// remove).
func (e *env) do(t *testing.T, method, path, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, e.ps.URL+path, strings.NewReader(body))
	req.Header.Set(RouteKeyHeader, testKey)
	req.Header.Set(GroupsHeader, "users,lldap_admin")
	req.Header.Set("X-Forwarded-User", "root")
	if e.cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: e.cookie})
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Header.Set("X-Test-Body", string(b))
	return resp
}

func (e *env) seen() int {
	e.up.mu.Lock()
	defer e.up.mu.Unlock()
	return len(e.up.seen)
}

const read = `{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],"methodCalls":[["x:Account/get",{},"a"],["x:Domain/query",{},"b"]]}`

// Every write, and every method outside the role's x:<Obj>/get and
// /query, is refused here and never reaches Stalwart; reads go through as
// the viewer, with the Host Stalwart trusts and no cookie, forwarding,
// groups or route-key header; responses lose Set-Cookie and
// WWW-Authenticate.
func TestJMAPAllowlist(t *testing.T) {
	e := setup(t)
	e.openSession(t)
	for _, m := range []string{"x:Account/set", "x:Domain/set", "x:DkimSignature/set", "x:Action/set", "x:QueuedMessage/set", "x:Task/set",
		"x:Account/changes", "x:Account/queryChanges", "x:QueuedMessage/get", "x:QueuedMessage/query", "x:DmarcExternalReport/get",
		"x:ArfExternalReport/query", "x:TlsInternalReport/get", "x:SpamDnsblServer/get", "x:DnsServer/get", "x:WebHook/get",
		"x:ApiKey/get", "x:Bootstrap/get", "X:Bootstrap/get", "X:OAuthGrant/get", "X:SieveUserScript/get", "X:Account/get", "x:account/get",
		"SearchSnippet/get", "Thread/get", "SieveScript/get", "Identity/get", "Principal/get", "Email/get", "Mailbox/query", "Core/echo",
		"Email/import", "Blob/upload", "Email/copy"} {
		body := `{"using":[],"methodCalls":[["x:Account/get",{},"a"],["` + m + `",{},"b"]]}`
		if resp := e.do(t, "POST", "/jmap/", body, nil); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", m, resp.StatusCode)
		}
	}
	if n := e.seen(); n != 0 {
		t.Fatalf("%d refused requests reached the mail server", n)
	}
	resp := e.do(t, "POST", "/jmap/", read, map[string]string{"Authorization": "Basic dTpw", "Cookie": "_oauth2_proxy=secret; " + SessionCookie + "=" + e.cookie,
		"X-Auth-Request-Email": "a@example.org"})
	if resp.StatusCode != 200 || e.seen() != 1 {
		t.Fatalf("read: %d, %d upstream", resp.StatusCode, e.seen())
	}
	got := e.up.seen[0]
	if u, pw, ok := got.BasicAuth(); !ok || u != Viewer || pw != viewerPW {
		t.Fatalf("the read isn't the viewer's: %q", got.Header.Get("Authorization"))
	}
	for _, h := range []string{"Cookie", "X-Forwarded-User", "X-Forwarded-For", "X-Auth-Request-Email", GroupsHeader, RouteKeyHeader} {
		if got.Header.Get(h) != "" {
			t.Errorf("%s forwarded: %q", h, got.Header.Get(h))
		}
	}
	if got.Host != "mail-admin.example.org" || !strings.Contains(e.up.body[0], `"x:Domain/query"`) {
		t.Fatalf("forwarded %q %q", got.Host, e.up.body[0])
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("WWW-Authenticate") != "" {
		t.Fatal("Set-Cookie or WWW-Authenticate reached the browser")
	}
	// Static paths carry no credential at all.
	n := e.seen()
	e.do(t, "GET", "/admin/", "", nil)
	if a := e.up.seen[n].Header.Get("Authorization"); a != "" {
		t.Fatalf("/admin/ carries %q", a)
	}
	// The viewer password is registered with the log redaction.
	if len(e.secrets) == 0 || e.secrets[0] != viewerPW {
		t.Fatal("the viewer password isn't registered as a log secret")
	}
}

// Only canonical allowlisted paths reach Stalwart: the sign-in API,
// uploads, downloads, push, live, the self-service portal, dot segments
// and encoded slashes are 404 here.
func TestPathAllowlist(t *testing.T) {
	e := setup(t)
	e.openSession(t)
	for _, c := range [][2]string{{"POST", "/api/auth"}, {"GET", "/api/auth/client"}, {"POST", "/jmap/upload/a"}, {"GET", "/jmap/download/a/b/c"},
		{"GET", "/jmap/eventsource"}, {"GET", "/jmap/ws"}, {"GET", "/api/live/delivery/x"}, {"GET", "/api/token/delivery"},
		{"GET", "/account/"}, {"GET", "/dav/"}, {"GET", "/.env"}, {"POST", "/admin/"}, {"GET", "/metrics/prometheus"}, {"GET", "/healthz"},
		{"GET", "/scim/v2/Users"}, {"POST", "/api/account"}, {"GET", "/admin/../jmap"}, {"GET", "/api/schema/%2e%2e/account"},
		{"GET", "/admin/%2e%2e/api/account"}, {"GET", "/admin//x"}, {"GET", "/admin/a%2fb"}, {"GET", "/api/schema/../account"}} {
		if resp := e.do(t, c[0], c[1], "{}", nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c[0], c[1], resp.StatusCode)
		}
	}
	if n := e.seen(); n != 0 {
		t.Fatalf("%d requests reached the mail server", n)
	}
	for _, p := range []string{"/admin/", "/admin/Management/x:Account/User", "/logo", "/api/account", "/api/schema", "/api/schema/abcdefgh12", "/jmap/session",
		"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		if resp := e.do(t, "GET", p, "", nil); resp.StatusCode != 200 {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	n := e.seen()
	e.do(t, "GET", "/api/discover/root%40example.org", "", nil)
	if p := e.up.seen[n].URL.EscapedPath(); p != "/api/discover/"+url.PathEscape(Viewer) {
		t.Fatalf("discover %s", p)
	}
}

// The gate (security review): no route key, a wrong, doubled or partial
// one, no admin group (or a group that only contains the name), no
// forwarded user, or another address than Traefik's: 403, nothing upstream.
func TestGate(t *testing.T) {
	e := setup(t)
	e.openSession(t)
	n := e.seen()
	for name, hdr := range map[string]map[string]string{
		"no key":        {RouteKeyHeader: ""},
		"wrong key":     {RouteKeyHeader: strings.Repeat("x", len(testKey))},
		"prefix":        {RouteKeyHeader: testKey[:20]},
		"longer":        {RouteKeyHeader: testKey + "x"},
		"no groups":     {GroupsHeader: ""},
		"not an admin":  {GroupsHeader: "users,mail_users"},
		"group in name": {GroupsHeader: "lldap_admins,xlldap_admin"},
		"no user":       {"X-Forwarded-User": ""},
	} {
		for _, c := range [][3]string{{"GET", "/login?state=s", ""}, {"POST", "/jmap/", read}, {"GET", "/admin/", ""}, {"GET", "/api/account", ""},
			{"POST", "/portcullis/open", url.Values{"t": {e.ticket("root", 30*time.Second)}}.Encode()}} {
			if resp := e.do(t, c[0], c[1], c[2], hdr); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s: %s %s = %d", name, c[0], c[1], resp.StatusCode)
			}
		}
	}
	req, _ := http.NewRequest("GET", e.ps.URL+"/admin/", nil)
	req.Header.Add(RouteKeyHeader, testKey)
	req.Header.Add(RouteKeyHeader, "other")
	req.Header.Set(GroupsHeader, "lldap_admin")
	req.Header.Set("X-Forwarded-User", "root")
	if resp, err := noRedirect().Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("two keys: %v %v", resp, err)
	}
	other, _ := New("https://172.31.255.2:8443", "mail-admin.example.org", e.sf, []string{strings.Repeat("ab", 32)},
		Gate{TraefikIP: netip.MustParseAddr("172.31.250.2"), Key: testKey, Group: "lldap_admin"}, testTickets(t), nil, func(string, ...any) {})
	os := httptest.NewServer(other)
	defer os.Close()
	e2 := &env{ps: os}
	if resp := e2.do(t, "POST", "/jmap/", read, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("not Traefik's address: %d", resp.StatusCode)
	}
	if e.seen() != n {
		t.Fatal("a request reached the mail server through a closed gate")
	}
	for _, g := range []Gate{{}, {TraefikIP: netip.MustParseAddr("172.31.250.2")}, {TraefikIP: netip.MustParseAddr("172.31.250.2"), Key: "short", Group: "g"},
		{TraefikIP: netip.MustParseAddr("172.31.250.2"), Key: testKey}} {
		if _, err := New("https://172.31.255.2:8443", "mail-admin.example.org", e.sf, []string{strings.Repeat("ab", 32)}, g, testTickets(t), nil, nil); err == nil {
			t.Errorf("gate %+v accepted", g)
		}
	}
}

// Tickets and sessions (ruling 4): only a valid, unexpired (≤ 60 s),
// single-use ticket for this admin opens a session; without a session
// every path answers "open it from Portcullis"; a session ends after 30
// min idle and 8 h total, and belongs to one admin.
func TestTicketsAndSessions(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/admin/", "/login?response_type=code&state=s", "/jmap/session"} {
		resp := e.do(t, "GET", p, "", nil)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Header.Get("X-Test-Body"), "Open it from Portcullis") {
			t.Errorf("no session %s: %d %s", p, resp.StatusCode, resp.Header.Get("X-Test-Body"))
		}
	}
	key := TicketKey([]byte(ticketSecret))
	bad := map[string]string{
		"garbage":       "nope",
		"route key":     MintTicket(TicketKey([]byte(testKey)), "root", "n1", e.now.Add(30*time.Second)),
		"expired":       MintTicket(key, "root", "n2", e.now.Add(-time.Second)),
		"too long":      MintTicket(key, "root", "n3", e.now.Add(61*time.Second)),
		"another admin": MintTicket(key, "alice", "n4", e.now.Add(30*time.Second)),
		"no nonce":      MintTicket(key, "root", "", e.now.Add(30*time.Second)),
	}
	good := MintTicket(key, "root", "n5", e.now.Add(60*time.Second))
	parts := strings.Split(good, ".")
	tampered, _ := json.Marshal(ticketBody{User: "root", Nonce: "n5", Expiry: e.now.Add(3600 * time.Second).Unix()})
	bad["tampered"] = "v1." + base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[2]
	for name, tk := range bad {
		if resp := e.open(t, tk, nil); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
			t.Errorf("%s ticket: %d", name, resp.StatusCode)
		}
	}
	if resp := e.open(t, good, nil); resp.StatusCode != http.StatusFound {
		t.Fatalf("good ticket: %d", resp.StatusCode)
	}
	if resp := e.open(t, good, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a ticket used twice: %d", resp.StatusCode)
	}
	found := false
	for _, l := range e.logs {
		if strings.Contains(l, "root opened the read-only mail admin view (ticket n5)") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no open log line: %v", e.logs)
	}
	// Impersonation is in the log line.
	e.open(t, e.ticket("root", time.Minute), map[string]string{"X-Forwarded-Impersonator": "boss"})
	if !strings.Contains(strings.Join(e.logs, "\n"), "root (impersonated by boss) opened") {
		t.Fatal("the impersonator isn't logged")
	}
	e.openSession(t)
	if resp := e.do(t, "GET", "/admin/", "", nil); resp.StatusCode != 200 {
		t.Fatalf("session: %d", resp.StatusCode)
	}
	if resp := e.do(t, "GET", "/admin/", "", map[string]string{"X-Forwarded-User": "alice"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("another admin with root's session: %d", resp.StatusCode)
	}
	e.now = e.now.Add(29 * time.Minute)
	if resp := e.do(t, "GET", "/admin/", "", nil); resp.StatusCode != 200 {
		t.Fatalf("29 min idle: %d", resp.StatusCode)
	}
	e.now = e.now.Add(31 * time.Minute)
	if resp := e.do(t, "GET", "/admin/", "", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("31 min idle: %d", resp.StatusCode)
	}
	e.openSession(t)
	for i := 0; i < 20; i++ {
		e.now = e.now.Add(25 * time.Minute)
		resp := e.do(t, "GET", "/admin/", "", nil)
		elapsed := time.Duration(i+1) * 25 * time.Minute
		if want := elapsed <= SessionMax; (resp.StatusCode == 200) != want {
			t.Fatalf("after %s: %d", elapsed, resp.StatusCode)
		}
	}
	// The unmask switch on: no session.
	e.up.unmasked = true
	if resp := e.open(t, e.ticket("root", time.Minute), nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("includeSecrets on: %d", resp.StatusCode)
	}
	// No viewer password: no session either.
	e.up.unmasked = false
	os.Remove(e.sf)
	if resp := e.open(t, e.ticket("root", time.Minute), nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no secret: %d", resp.StatusCode)
	}
}

// The web admin's OAuth is answered here (M1): /login gives a code for
// its own callback on this host only, /auth/token swaps it (with the PKCE
// verifier) or the refresh token for opaque values; nothing reaches
// Stalwart and no Stalwart token reaches the browser.
func TestLocalOAuth(t *testing.T) {
	e := setup(t)
	e.openSession(t)
	verifier := "a-verifier-of-sufficient-length-0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	cb := "https://mail-admin.example.org/admin/oauth/callback"
	q := url.Values{"response_type": {"code"}, "client_id": {"https://mail-admin.example.org/admin/oauth-client.json"}, "redirect_uri": {cb},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st"}}
	for name, mod := range map[string]func(url.Values){
		"other host":  func(v url.Values) { v.Set("redirect_uri", "https://evil.example/admin/oauth/callback") },
		"other path":  func(v url.Values) { v.Set("redirect_uri", "https://mail-admin.example.org/account/x") },
		"plain http":  func(v url.Values) { v.Set("redirect_uri", "http://mail-admin.example.org/admin/oauth/callback") },
		"no state":    func(v url.Values) { v.Del("state") },
		"plain pkce":  func(v url.Values) { v.Set("code_challenge_method", "plain") },
		"token resp":  func(v url.Values) { v.Set("response_type", "token") },
		"query in cb": func(v url.Values) { v.Set("redirect_uri", cb+"?x=1") },
	} {
		v := url.Values{}
		for k, vv := range q {
			v[k] = append([]string(nil), vv...)
		}
		mod(v)
		if resp := e.do(t, "GET", "/login?"+v.Encode(), "", nil); resp.StatusCode == http.StatusFound {
			t.Errorf("%s: redirected to %s", name, resp.Header.Get("Location"))
		}
	}
	resp := e.do(t, "GET", "/login?"+q.Encode(), "", nil)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc == nil || loc.Scheme+"://"+loc.Host+loc.Path != cb || loc.Query().Get("state") != "st" || loc.Query().Get("iss") != "https://mail-admin.example.org" {
		t.Fatalf("login: %d %v", resp.StatusCode, loc)
	}
	code := loc.Query().Get("code")
	form := func(v url.Values) string { return v.Encode() }
	for name, v := range map[string]url.Values{
		"wrong verifier": {"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {"x"}, "redirect_uri": {cb}},
		"wrong code":     {"grant_type": {"authorization_code"}, "code": {"x"}, "code_verifier": {verifier}, "redirect_uri": {cb}},
		"password":       {"grant_type": {"password"}, "username": {"a"}, "password": {"b"}},
		"two grants":     {"grant_type": {"refresh_token", "password"}},
	} {
		if r := e.do(t, "POST", "/auth/token", form(v), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); r.StatusCode != 400 {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
	r := e.do(t, "POST", "/auth/token", form(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {cb}}),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var tok struct{ AccessToken, RefreshToken, TokenType string }
	json.Unmarshal([]byte(strings.NewReplacer(`"access_token"`, `"AccessToken"`, `"refresh_token"`, `"RefreshToken"`, `"token_type"`, `"TokenType"`).Replace(r.Header.Get("X-Test-Body"))), &tok)
	if r.StatusCode != 200 || len(tok.AccessToken) < 40 || tok.TokenType != "Bearer" {
		t.Fatalf("token: %d %s", r.StatusCode, r.Header.Get("X-Test-Body"))
	}
	if r := e.do(t, "POST", "/auth/token", form(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {cb}}),
		nil); r.StatusCode != 400 {
		t.Fatalf("a code used twice: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/auth/token", form(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}), nil); r.StatusCode != 200 {
		t.Fatalf("refresh: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/auth/revoke", "token=x", nil); r.StatusCode != 200 {
		t.Fatalf("revoke: %d", r.StatusCode)
	}
	if e.seen() != 0 {
		t.Fatal("the OAuth exchange reached the mail server")
	}
	// Sign-out ends the session.
	e.do(t, "GET", "/auth/logout", "", nil)
	if r := e.do(t, "GET", "/admin/", "", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("after sign-out: %d", r.StatusCode)
	}
}

func TestCanonicalJMAP(t *testing.T) {
	for body, want := range map[string]bool{
		`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["x:Account/get",{},"0"]]}`: true,
		`{"using":[],"methodCalls":[]}`:                                                  true,
		`{"methodCalls":[["x:Account/set",{},"0"]],"using":[]}`:                          false,
		`{"using":[],"methodCalls":[["x:Account/get",{},"0"],["x:Account/set",{},"1"]]}`: false,
		`{"using":[],"methodCalls":[["x:Account/get",{}]]}`:                              false,
		`{"using":[],"methodCalls":[[1,{},"0"]]}`:                                        false,
		`not json`: false,
		`{"using":[],"methodCalls":[["x:Account/get/set",{},"0"]]}`: false,
		`{"using":[],"methodCalls":[["x:Account/getx",{},"0"]]}`:    false,
		`{"using":[],"methodCalls":[["x:Account/get",[],"0"]]}`:     false,
		`{"methodCalls":[["x:Account/get",{},"0"]]}`:                false,
	} {
		if _, why := canonicalJMAP([]byte(body)); (why == "") != want {
			t.Errorf("%s: read %v, want %v (%s)", body, why == "", want, why)
		}
	}
}

// Parser differentials: a body another JSON reader could see differently
// is refused, and what is forwarded is the re-encoded, checked request.
func TestCanonicalJMAPSmuggling(t *testing.T) {
	get := `[["x:Account/get",{},"0"]]`
	set := `[["x:Account/set",{"destroy":["b"]},"0"]]`
	for name, body := range map[string]string{
		"duplicate methodCalls, write last":  `{"using":[],"methodCalls":` + get + `,"methodCalls":` + set + `}`,
		"duplicate methodCalls, write first": `{"using":[],"methodCalls":` + set + `,"methodCalls":` + get + `}`,
		"case variant":                       `{"using":[],"methodCalls":` + get + `,"MethodCalls":` + set + `}`,
		"case variant only":                  `{"using":[],"methodcalls":` + get + `}`,
		"unknown key":                        `{"using":[],"methodCalls":` + get + `,"x":` + set + `}`,
		"createdIds":                         `{"using":[],"methodCalls":` + get + `,"createdIds":{}}`,
		"duplicate using":                    `{"using":[],"using":["urn:stalwart:jmap"],"methodCalls":` + get + `}`,
		"trailing object":                    `{"using":[],"methodCalls":` + get + `}{"using":[],"methodCalls":` + set + `}`,
		"trailing garbage":                   `{"using":[],"methodCalls":` + get + `} x`,
		"duplicate arg key":                  `{"using":[],"methodCalls":[["x:Account/get",{"ids":null,"ids":["a"]},"0"]]}`,
		"case arg key":                       `{"using":[],"methodCalls":[["x:Account/get",{"ids":null,"IDS":["a"]},"0"]]}`,
		"nested duplicate":                   `{"using":[],"methodCalls":[["x:Account/get",{"a":{"b":1,"b":2}},"0"]]}`,
		"call with extra element":            `{"using":[],"methodCalls":[["x:Account/get",{},"0","x:Account/set"]]}`,
		"name not a string":                  `{"using":[],"methodCalls":[[["x:Account/set"],{},"0"]]}`,
		"top not an object":                  `[{"using":[],"methodCalls":` + get + `}]`,
		"queued messages":                    `{"using":[],"methodCalls":[["x:QueuedMessage/get",{},"0"]]}`,
		"DMARC reports":                      `{"using":[],"methodCalls":[["x:DmarcExternalReport/get",{},"0"]]}`,
		"DNSBL servers":                      `{"using":[],"methodCalls":[["x:SpamDnsblServer/get",{},"0"]]}`,
		"mail itself":                        `{"using":[],"methodCalls":[["SearchSnippet/get",{},"0"]]}`,
		"a read hidden after an allowed one": `{"using":[],"methodCalls":[["x:Account/get",{},"0"],["x:QueuedMessage/get",{},"1"]]}`,
	} {
		if _, why := canonicalJMAP([]byte(body)); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	in := `{ "methodCalls" : [["x:Account/get", {"ids": ["a"], "limit": 12345678901234567890, "name":1}, "0"]], "using" : ["urn:ietf:params:jmap:core"] }`
	out, why := canonicalJMAP([]byte(in))
	if why != "" {
		t.Fatal(why)
	}
	want := `{"methodCalls":[["x:Account/get",{"ids":["a"],"limit":12345678901234567890,"name":1},"0"]],"using":["urn:ietf:params:jmap:core"]}`
	if string(out) != want {
		t.Fatalf("canonical\n got %s\nwant %s", out, want)
	}
}

// The hop to the mail server is pinned (ruling 3: InsecureSkipVerify only
// with the SPKI pin): a server whose key isn't a pinned SPKI is refused
// (no request, no password sent), and the proxy refuses to start without
// a valid pin.
func TestUpstreamPinned(t *testing.T) {
	up := &upstream{}
	us := httptest.NewTLSServer(up)
	defer us.Close()
	sf := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(sf, []byte(viewerPW), 0o640)
	wrong := strings.Repeat("ab", 32)
	p, err := New(us.URL, "mail-admin.example.org", sf, []string{wrong}, testGate, testTickets(t), nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	p.now = func() time.Time { return now }
	ps := httptest.NewServer(p)
	defer ps.Close()
	e := &env{ps: ps, up: up, now: now}
	if resp := e.open(t, e.ticket("root", time.Minute), nil); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("open with a mismatched certificate: %d, want 503", resp.StatusCode)
	}
	if up.readCount != 0 || len(up.seen) != 0 {
		t.Fatal("a request (the viewer's password included) reached a server with an unpinned certificate")
	}
	// The TLS config keeps the skip and the pin together.
	cfg := pinnedTLS("h", map[[32]byte]bool{})
	if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
		t.Fatal("InsecureSkipVerify without the SPKI pin")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("no peer certificate passed the pin")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{us.Certificate()}}); err == nil {
		t.Fatal("an unpinned certificate passed")
	}
	// Two pins (a rollover): the right one among them passes.
	p2, _ := New(us.URL, "mail-admin.example.org", sf, []string{wrong, spkiOf(us.Certificate())}, testGate, testTickets(t), nil, func(string, ...any) {})
	p2.now = func() time.Time { return now }
	ps2 := httptest.NewServer(p2)
	defer ps2.Close()
	e2 := &env{ps: ps2, up: up, now: now}
	if resp := e2.open(t, e2.ticket("root", time.Minute), nil); resp.StatusCode != http.StatusFound {
		t.Fatalf("pinned rollover: %d", resp.StatusCode)
	}
	for _, pins := range [][]string{nil, {}, {"xyz"}, {strings.Repeat("AB", 32)}, {wrong, wrong + "00"}, {wrong, strings.Repeat("cd", 32), strings.Repeat("ef", 32)}} {
		if _, err := New(us.URL, "mail-admin.example.org", sf, pins, testGate, testTickets(t), nil, nil); err == nil {
			t.Errorf("pins %v accepted", pins)
		}
	}
}

// The proxy listens only on Traefik's network.
func TestBindAddr(t *testing.T) {
	mk := func(cidrs ...string) []net.Addr {
		var out []net.Addr
		for _, c := range cidrs {
			ip, n, _ := net.ParseCIDR(c)
			n.IP = ip
			out = append(out, n)
		}
		return out
	}
	tr := netip.MustParseAddr("172.31.250.2")
	got, err := bindAddrIn(mk("127.0.0.1/8", "172.31.255.5/28", "172.31.250.37/24"), tr)
	if err != nil || got != netip.MustParseAddr("172.31.250.37") {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := bindAddrIn(mk("127.0.0.1/8", "172.31.255.5/28"), tr); err == nil {
		t.Fatal("bound without Traefik's network")
	}
	if _, err := bindAddrIn(mk("172.31.250.2/24"), tr); err == nil {
		t.Fatal("bound to Traefik's own address")
	}
}

// Round 2 (N2, N3): a ticket only ever arrives in a POST body (a query
// ticket opens nothing), and a spent ticket stays spent across a restart
// (the nonce file); a spent-ticket file that can't be written refuses.
func TestTicketPostAndReplayAcrossRestart(t *testing.T) {
	e := setup(t)
	tk := e.ticket("root", 50*time.Second)
	// A GET is only the start page: it never reads a query ticket (no
	// session, the ticket not echoed and not spent: the POST below opens).
	if resp := e.do(t, "GET", "/portcullis/open?t="+url.QueryEscape(tk), "", nil); resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 0 ||
		strings.Contains(resp.Header.Get("X-Test-Body"), tk) {
		t.Fatalf("GET with a query ticket: %d", resp.StatusCode)
	}
	if resp := e.do(t, "POST", "/portcullis/open?t="+url.QueryEscape(tk), "", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST with a query ticket: %d", resp.StatusCode)
	}
	if resp := e.open(t, tk, nil); resp.StatusCode != http.StatusFound {
		t.Fatalf("POST body ticket: %d", resp.StatusCode)
	}
	// A restart: a new proxy on the same spent-ticket file.
	used := e.p.usedFile
	p2, err := New(e.p.upstream.String(), "mail-admin.example.org", e.sf, []string{strings.Repeat("ab", 32)}, testGate,
		Tickets{Secret: []byte(ticketSecret), UsedFile: used}, nil, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	p2.now = func() time.Time { return e.now }
	if _, ok := p2.checkTicket(tk, "root"); ok {
		t.Fatal("a spent ticket opened again after a restart")
	}
	// An unwritable spent-ticket file refuses (fail closed).
	dir := t.TempDir()
	p3, _ := New(e.p.upstream.String(), "mail-admin.example.org", e.sf, []string{strings.Repeat("ab", 32)}, testGate,
		Tickets{Secret: []byte(ticketSecret), UsedFile: filepath.Join(dir, "no", "such", "dir", "used.json")}, nil, func(string, ...any) {})
	p3.now = func() time.Time { return e.now }
	if _, ok := p3.checkTicket(e.ticket("root", 50*time.Second), "root"); ok {
		t.Fatal("a ticket accepted without its nonce on disk")
	}
	// A malformed file refuses to start; a missing secret too.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	if _, err := New(e.p.upstream.String(), "h", e.sf, []string{strings.Repeat("ab", 32)}, testGate, Tickets{Secret: []byte(ticketSecret), UsedFile: bad}, nil, nil); err == nil {
		t.Fatal("a malformed spent-ticket file accepted")
	}
	if _, err := New(e.p.upstream.String(), "h", e.sf, []string{strings.Repeat("ab", 32)}, testGate, Tickets{Secret: []byte("short"), UsedFile: used}, nil, nil); err == nil {
		t.Fatal("a short ticket secret accepted")
	}
}

// Cross-origin (nit N-a): POSTs and the sign-out must be same-origin, the
// ticket POST may also come from the Hub's origin (same-site); another
// site, or a sibling app's origin, is refused. Stalwart's CORS headers are
// stripped (N-b).
func TestOriginChecks(t *testing.T) {
	e := setup(t)
	tk := func() string { return e.ticket("root", 50*time.Second) }
	for name, hdr := range map[string]map[string]string{
		"a sibling app":    {"Sec-Fetch-Site": "same-site", "Origin": "https://evil.example.org"},
		"another site":     {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.test"},
		"origin only, bad": {"Origin": "https://evil.test"},
	} {
		if resp := e.open(t, tk(), hdr); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	// The ticket POST comes only from this origin now (the start page,
	// fix-mail-admin-421): even the Hub's own origin is refused.
	if resp := e.open(t, tk(), map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://hub.example.org"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("from the Hub directly: %d", resp.StatusCode)
	}
	if resp := e.open(t, tk(), map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://mail-admin.example.org"}); resp.StatusCode != http.StatusFound {
		t.Fatalf("from the start page: %d", resp.StatusCode)
	}
	if resp := e.open(t, tk(), map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "null"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an opaque origin: %d", resp.StatusCode)
	}
	e.openSession(t)
	for name, c := range map[string][3]string{
		"jmap from a sibling":   {"POST", "/jmap/", "same-site"},
		"token from a sibling":  {"POST", "/auth/token", "same-site"},
		"logout from a sibling": {"GET", "/auth/logout", "same-site"},
		"open from a sibling":   {"POST", "/auth/revoke", "cross-site"},
	} {
		if resp := e.do(t, c[0], c[1], read, map[string]string{"Sec-Fetch-Site": c[2], "Origin": "https://shop.example.org"}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	if resp := e.do(t, "GET", "/admin/", "", nil); resp.StatusCode != 200 {
		t.Fatalf("still signed in: %d", resp.StatusCode)
	}
	if resp := e.do(t, "POST", "/jmap/", read, map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://mail-admin.example.org"}); resp.StatusCode != 200 {
		t.Fatalf("same-origin read: %d", resp.StatusCode)
	}
	e.up.mu.Lock()
	e.up.cors = true
	e.up.mu.Unlock()
	if resp := e.do(t, "GET", "/admin/", "", nil); resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("Stalwart's CORS header reached the browser")
	}
}

// inlineHandlerRe is an inline event handler attribute (onclick=, …).
var inlineHandlerRe = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)

// The start page (fix-mail-admin-421): a GET, its CSP runs only the
// same-origin script, it names exactly the Hub's origin as the ticket's
// sender and posts the form to this origin; no session is needed and none
// is started.
func TestStartPage(t *testing.T) {
	e := setup(t)
	resp := e.do(t, "GET", "/portcullis/open", "", nil)
	body := resp.Header.Get("X-Test-Body")
	csp := resp.Header.Get("Content-Security-Policy")
	// Review M1: the whole policy and headers, exactly as the contract
	// states them, and one script, external.
	if csp != "default-src 'none'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" ||
		resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" ||
		strings.Count(body, "<script") != 1 || strings.Count(body, `<script src="/portcullis/open.js"></script>`) != 1 ||
		inlineHandlerRe.MatchString(body) || strings.Contains(strings.ToLower(body), "javascript:") {
		t.Fatalf("start page headers / script %q %v %s", csp, resp.Header, body)
	}
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 0 || resp.Header.Get("Cache-Control") != "no-store" ||
		!strings.Contains(body, `data-hub-origin="https://hub.example.org"`) || !strings.Contains(body, `action="/portcullis/open"`) ||
		!strings.Contains(body, `<script src="/portcullis/open.js">`) || resp.Header.Get("Referrer-Policy") != "same-origin" {
		t.Fatalf("start page %d %q %s", resp.StatusCode, csp, body)
	}
	js := e.do(t, "GET", "/portcullis/open.js", "", nil)
	src := js.Header.Get("X-Test-Body")
	if js.StatusCode != http.StatusOK || js.Header.Get("Content-Type") != "text/javascript; charset=utf-8" || js.Header.Get("X-Content-Type-Options") != "nosniff" ||
		js.Header.Get("Cache-Control") != "no-store" || src != startJS {
		t.Fatalf("script %d %v", js.StatusCode, js.Header)
	}
	for _, want := range []string{"e.origin !== hub", "'portcullis-mail-admin-hello'", "e.ports.length !== 1", "'portcullis-mail-admin-ready'", "ticketRe.test(t)", "f.submit()"} {
		if !strings.Contains(src, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if r := e.do(t, "PUT", "/portcullis/open", "", nil); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", r.StatusCode)
	}
	// Still behind the gate: no route key, no page.
	if r := e.do(t, "GET", "/portcullis/open", "", map[string]string{RouteKeyHeader: ""}); r.StatusCode != http.StatusForbidden {
		t.Errorf("no route key: %d", r.StatusCode)
	}
}

// Every refusal without a session logs one line: who, the path and why
// (no cookie / unknown session / idle or max / another admin), never
// the cookie's value.
func TestRefusalsLogged(t *testing.T) {
	e := setup(t)
	last := func() string {
		t.Helper()
		if len(e.logs) == 0 {
			t.Fatal("nothing logged")
		}
		return e.logs[len(e.logs)-1]
	}
	expect := func(name, path string, hdr map[string]string, reason string) {
		t.Helper()
		n := len(e.logs)
		if resp := e.do(t, "GET", path, "", hdr); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
		if len(e.logs) != n+1 {
			t.Fatalf("%s: %d lines logged, want 1: %v", name, len(e.logs)-n, e.logs[n:])
		}
		l := last()
		if !strings.Contains(l, "refused") || !strings.Contains(l, fmt.Sprintf("%q", path)) || !strings.Contains(l, reason) {
			t.Fatalf("%s: line %q lacks the path %q or the reason %q", name, l, path, reason)
		}
		if e.cookie != "" && strings.Contains(l, e.cookie) {
			t.Fatalf("%s: the cookie value is in the log: %q", name, l)
		}
	}
	expect("no cookie", "/admin/", nil, "no session cookie")
	e.cookie = "not-a-session-0123456789"
	expect("unknown", "/jmap/session", nil, "unknown session")
	e.cookie = ""
	e.openSession(t)
	expect("another admin", "/admin/x", map[string]string{"X-Forwarded-User": "alice"}, "another administrator's session")
	if !strings.Contains(last(), "alice") {
		t.Fatalf("the refused admin isn't named: %q", last())
	}
	e.now = e.now.Add(31 * time.Minute)
	expect("idle", "/admin/", nil, "ended (idle or max)")
	// The gate's refusal is logged too, with no header value.
	n := len(e.logs)
	if resp := e.do(t, "GET", "/admin/", "", map[string]string{RouteKeyHeader: "wrong"}); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("gate: %d", resp.StatusCode)
	}
	if len(e.logs) != n+1 || !strings.Contains(last(), "not admitted") || strings.Contains(last(), "wrong") {
		t.Fatalf("gate refusal: %v", e.logs[n:])
	}
}
