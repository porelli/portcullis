package viewer

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// upstream records what reaches "Stalwart".
type upstream struct {
	mu   sync.Mutex
	seen []*http.Request
	body []string
	auth map[string]any // the last /api/auth body
	ans  string         // /api/auth's answer
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.seen = append(u.seen, r.Clone(r.Context()))
	u.body = append(u.body, string(b))
	ans := u.ans
	u.mu.Unlock()
	if r.URL.Path == "/api/auth" {
		u.mu.Lock()
		json.Unmarshal(b, &u.auth)
		u.mu.Unlock()
		w.Write([]byte(ans))
		return
	}
	w.Header().Set("Set-Cookie", "s=1")
	w.Write([]byte(`{"ok":true}`))
}

func setup(t *testing.T) (*upstream, *httptest.Server, string) {
	t.Helper()
	up := &upstream{ans: `{"type":"authenticated","location":"https://mail-admin.example.org/admin/oauth/callback?code=c&state=s"}`}
	us := httptest.NewTLSServer(up)
	t.Cleanup(us.Close)
	dir := t.TempDir()
	sf := filepath.Join(dir, "viewer-password")
	os.WriteFile(sf, []byte("0123456789abcdef0123456789abcdef\n"), 0o640)
	p, err := New(us.URL, "mail-admin.example.org", sf, []string{spkiOf(us.Certificate())}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	return up, ps, sf
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func do(t *testing.T, method, u, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// Every JMAP write is refused here and never reaches Stalwart; reads go
// through with the browser's Bearer token, the Host Stalwart trusts, and
// no cookie or forwarding header.
func TestJMAPReadOnly(t *testing.T) {
	up, ps, _ := setup(t)
	for _, m := range []string{"x:Account/set", "x:Domain/set", "x:DkimSignature/set", "x:Action/set", "x:QueuedMessage/set", "x:Task/set",
		"Email/import", "Blob/upload", "x:Role/set", "Core/echo", "Email/copy", "x:Account/get\x00"} {
		body := `{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["x:Account/get",{},"a"],["` + strings.ReplaceAll(m, "\x00", "") + `",{},"b"]]}`
		if strings.Contains(m, "\x00") {
			body = `{"using":[],"methodCalls":[["x:Account/get",{},"a"]]} {"x":1}`
		}
		if resp := do(t, "POST", ps.URL+"/jmap/", body, nil); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", m, resp.StatusCode)
		}
	}
	if len(up.seen) != 0 {
		t.Fatalf("%d refused requests reached the mail server", len(up.seen))
	}
	read := `{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],"methodCalls":[["x:Account/get",{},"a"],["x:Domain/query",{},"b"],["x:Role/changes",{},"c"],["x:Account/queryChanges",{},"d"]]}`
	resp := do(t, "POST", ps.URL+"/jmap/", read, map[string]string{"Authorization": "Bearer tok", "Cookie": "_oauth2_proxy=secret",
		"X-Forwarded-User": "alice", "X-Auth-Request-Email": "a@example.org"})
	if resp.StatusCode != 200 || len(up.seen) != 1 {
		t.Fatalf("read: %d, %d upstream", resp.StatusCode, len(up.seen))
	}
	got := up.seen[0]
	if u, pw, ok := got.BasicAuth(); !ok || u != Viewer || pw != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("the read isn't the viewer's: %q", got.Header.Get("Authorization"))
	}
	if got.Host != "mail-admin.example.org" || got.Header.Get("Cookie") != "" ||
		got.Header.Get("X-Forwarded-User") != "" || got.Header.Get("X-Forwarded-For") != "" || got.Header.Get("X-Auth-Request-Email") != "" || !strings.Contains(up.body[0], `"x:Account/queryChanges"`) {
		t.Fatalf("forwarded %v %q", got.Header, up.body[0])
	}
	if resp.Header.Get("Set-Cookie") != "" {
		t.Fatal("a cookie from the mail server reached the browser")
	}
	// The browser's credentials never cross the proxy: a mail password
	// (or anything) sent as Basic is replaced by the viewer's.
	do(t, "POST", ps.URL+"/jmap", read, map[string]string{"Authorization": "Basic dTpw"})
	if u, _, _ := up.seen[1].BasicAuth(); u != Viewer {
		t.Fatalf("the browser's Basic forwarded: %q", up.seen[1].Header.Get("Authorization"))
	}
	// Paths outside the reads carry no credentials at all.
	n := len(up.seen)
	do(t, "GET", ps.URL+"/admin/", "", map[string]string{"Authorization": "Bearer tok"})
	do(t, "POST", ps.URL+"/auth/token", "grant_type=refresh_token&refresh_token=r", map[string]string{"Authorization": "Bearer tok"})
	for _, r := range up.seen[n:] {
		if a := r.Header.Get("Authorization"); a != "" {
			t.Fatalf("%s carries %q", r.URL.Path, a)
		}
	}
}

// Only the allowlist reaches Stalwart: the sign-in API, uploads,
// downloads, push, live telemetry, the self-service portal and any other
// path are 404 here.
func TestPathAllowlist(t *testing.T) {
	up, ps, _ := setup(t)
	for _, c := range [][2]string{{"POST", "/api/auth"}, {"GET", "/api/auth/client"}, {"POST", "/jmap/upload/a"}, {"GET", "/jmap/download/a/b/c"},
		{"GET", "/jmap/eventsource"}, {"GET", "/jmap/ws"}, {"GET", "/api/live/delivery/x"}, {"GET", "/api/token/delivery"},
		{"GET", "/account/"}, {"GET", "/dav/"}, {"GET", "/.env"}, {"POST", "/admin/"}, {"GET", "/metrics/prometheus"}, {"GET", "/healthz/live"},
		{"GET", "/scim/v2/Users"}, {"POST", "/api/account"}} {
		if resp := do(t, c[0], ps.URL+c[1], "{}", nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s: %d, want 404", c[0], c[1], resp.StatusCode)
		}
	}
	if len(up.seen) != 0 {
		t.Fatalf("%d requests reached the mail server", len(up.seen))
	}
	for _, p := range []string{"/admin/", "/admin/Management/x:Account/User", "/logo", "/api/account", "/api/schema", "/api/schema/h", "/jmap/session",
		"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		if resp := do(t, "GET", ps.URL+p, "", nil); resp.StatusCode != 200 {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	// Whatever name is typed, discovery is the viewer's.
	n := len(up.seen)
	do(t, "GET", ps.URL+"/api/discover/root%40example.org", "", nil)
	if p := up.seen[n].URL.EscapedPath(); p != "/api/discover/"+url.PathEscape(Viewer) {
		t.Fatalf("discover %s", p)
	}
}

// The token endpoint takes a code or a refresh token only.
func TestTokenGrants(t *testing.T) {
	up, ps, _ := setup(t)
	for _, g := range []string{"password", "urn:ietf:params:oauth:grant-type:device_code", "client_credentials", ""} {
		if resp := do(t, "POST", ps.URL+"/auth/token", "grant_type="+url.QueryEscape(g)+"&username=a&password=b", nil); resp.StatusCode != 400 {
			t.Errorf("grant %q: %d", g, resp.StatusCode)
		}
	}
	if resp := do(t, "POST", ps.URL+"/auth/token", "grant_type=refresh_token&grant_type=password", nil); resp.StatusCode != 400 {
		t.Errorf("two grants: %d", resp.StatusCode)
	}
	if len(up.seen) != 0 {
		t.Fatal("a refused grant reached the mail server")
	}
	body := "grant_type=authorization_code&code=c&code_verifier=v&client_id=x&redirect_uri=y"
	if resp := do(t, "POST", ps.URL+"/auth/token", body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); resp.StatusCode != 200 ||
		up.body[0] != "client_id=x&code=c&code_verifier=v&grant_type=authorization_code&redirect_uri=y" {
		t.Fatalf("code grant: %d %q", resp.StatusCode, up.body)
	}
}

// GET /login signs in as the viewer with the browser's own authorization
// query and redirects only to this host's web admin; the password never
// reaches the browser.
func TestSignIn(t *testing.T) {
	up, ps, sf := setup(t)
	q := "response_type=code&client_id=https%3A%2F%2Fmail-admin.example.org%2Fadmin%2Foauth-client.json&code_challenge=abc&state=s"
	resp := do(t, "GET", ps.URL+"/login?"+q, "", nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "https://mail-admin.example.org/admin/oauth/callback?code=c&state=s" {
		t.Fatalf("sign-in: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if up.auth["type"] != "authCode" || up.auth["accountName"] != Viewer || up.auth["accountSecret"] != "0123456789abcdef0123456789abcdef" || up.auth["query"] != q {
		t.Fatalf("auth body %v", up.auth)
	}
	if up.seen[0].Host != "mail-admin.example.org" {
		t.Fatalf("auth host %s", up.seen[0].Host)
	}
	for name, ans := range map[string]string{
		"off host":   `{"type":"authenticated","location":"https://evil.example/admin/oauth/callback?code=c"}`,
		"off admin":  `{"type":"authenticated","location":"https://mail-admin.example.org/account/x"}`,
		"plain http": `{"type":"authenticated","location":"http://mail-admin.example.org/admin/oauth/callback"}`,
		"failure":    `{"type":"failure"}`,
		"mfa":        `{"type":"mfaRequired"}`,
	} {
		up.ans = ans
		if resp := do(t, "GET", ps.URL+"/login?"+q, "", nil); resp.StatusCode == http.StatusFound {
			t.Errorf("%s: redirected to %s", name, resp.Header.Get("Location"))
		}
	}
	// No viewer password: refused, nothing sent.
	os.Remove(sf)
	n := len(up.seen)
	if resp := do(t, "GET", ps.URL+"/login?"+q, "", nil); resp.StatusCode != http.StatusServiceUnavailable || len(up.seen) != n {
		t.Fatalf("no secret: %d", resp.StatusCode)
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

// Parser differentials (security review): a body another JSON reader could
// see differently is refused — duplicate keys, case variants of
// methodCalls, other top-level keys (where a call could hide), trailing
// data, duplicate keys in arguments — and what is forwarded is the
// re-encoded, checked request, never the original bytes.
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
	} {
		if _, why := canonicalJMAP([]byte(body)); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	// What is forwarded is the canonical re-encoding: whitespace, key order
	// and escapes of the original don't survive; numbers stay exact.
	in := `{ "methodCalls" : [["x:Account/get", {"ids": ["a"], "limit": 12345678901234567890, "n\u0061me":1}, "0"]], "using" : ["urn:ietf:params:jmap:core"] }`
	out, why := canonicalJMAP([]byte(in))
	if why != "" {
		t.Fatal(why)
	}
	want := `{"methodCalls":[["x:Account/get",{"ids":["a"],"limit":12345678901234567890,"name":1},"0"]],"using":["urn:ietf:params:jmap:core"]}`
	if string(out) != want {
		t.Fatalf("canonical\n got %s\nwant %s", out, want)
	}
}

// The proxy forwards the canonical body, not the browser's bytes.
func TestJMAPForwardsCanonical(t *testing.T) {
	up, ps, _ := setup(t)
	in := `{"using": ["urn:ietf:params:jmap:core"], "methodCalls": [["x:Account/get", {}, "a"]]}`
	if resp := do(t, "POST", ps.URL+"/jmap", in, map[string]string{"Content-Type": "text/plain"}); resp.StatusCode != 200 {
		t.Fatalf("%d", resp.StatusCode)
	}
	if up.body[0] != `{"methodCalls":[["x:Account/get",{},"a"]],"using":["urn:ietf:params:jmap:core"]}` || up.seen[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("forwarded %q %q", up.body[0], up.seen[0].Header.Get("Content-Type"))
	}
}

func spkiOf(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

// The hop to the mail server is pinned: a server whose certificate key
// isn't a pinned SPKI is refused (no request, no password sent), and the
// proxy refuses to start without a valid pin.
func TestUpstreamPinned(t *testing.T) {
	up := &upstream{ans: `{"type":"authenticated","location":"https://mail-admin.example.org/admin/oauth/callback?code=c"}`}
	us := httptest.NewTLSServer(up)
	defer us.Close()
	sf := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(sf, []byte("0123456789abcdef0123456789abcdef"), 0o640)
	// A pin that isn't the server's key (as a certificate other than the
	// mail certificate would be).
	wrong := strings.Repeat("ab", 32)
	p, err := New(us.URL, "mail-admin.example.org", sf, []string{wrong}, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(p)
	defer ps.Close()
	for _, c := range [][3]string{{"GET", "/login?state=s", ""}, {"GET", "/admin/", ""}, {"POST", "/jmap/", `{"using":[],"methodCalls":[["x:Account/get",{},"0"]]}`}} {
		if resp := do(t, c[0], ps.URL+c[1], c[2], nil); resp.StatusCode != http.StatusBadGateway {
			t.Errorf("%s %s with a mismatched certificate: %d, want 502", c[0], c[1], resp.StatusCode)
		}
	}
	if len(up.seen) != 0 || up.auth != nil {
		t.Fatalf("a request (the viewer's password included: %v) reached a server with an unpinned certificate", up.auth != nil)
	}
	// Two pins (a rollover): the right one among them passes.
	p2, _ := New(us.URL, "mail-admin.example.org", sf, []string{wrong, spkiOf(us.Certificate())}, func(string, ...any) {})
	ps2 := httptest.NewServer(p2)
	defer ps2.Close()
	if resp := do(t, "GET", ps2.URL+"/admin/", "", nil); resp.StatusCode != 200 {
		t.Fatalf("pinned rollover: %d", resp.StatusCode)
	}
	for _, pins := range [][]string{nil, {}, {"xyz"}, {strings.Repeat("AB", 32)}, {wrong, wrong + "00"}, {wrong, strings.Repeat("cd", 32), strings.Repeat("ef", 32)}} {
		if _, err := New(us.URL, "mail-admin.example.org", sf, pins, nil); err == nil {
			t.Errorf("pins %v accepted", pins)
		}
	}
}
