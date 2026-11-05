package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/portcullis/mcp-gate/internal/config"
)

const (
	issuer    = "https://auth.example.com/realms/portcullis"
	giteaURL  = "https://gitea.example.com/mcp"
	giteaMeta = "https://gitea.example.com/.well-known/oauth-protected-resource/mcp"
)

type jwks struct {
	srv     *httptest.Server
	fetches atomic.Int64
	mu      sync.Mutex
	keys    []jose.JSONWebKey
}

func newJWKS(t *testing.T, keys ...jose.JSONWebKey) *jwks {
	j := &jwks{keys: keys}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.fetches.Add(1)
		j.mu.Lock()
		set := jose.JSONWebKeySet{Keys: j.keys}
		j.mu.Unlock()
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func (j *jwks) add(k jose.JSONWebKey) {
	j.mu.Lock()
	j.keys = append(j.keys, k)
	j.mu.Unlock()
}

type signer struct {
	key any
	kid string
	alg jose.SignatureAlgorithm
}

func (s signer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", s.kid)
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: s.key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := sg.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func loadSnapshot(t *testing.T) *config.Snapshot {
	t.Helper()
	b, err := os.ReadFile("../config/testdata/mcp-gate.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.DecodeFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return &config.Snapshot{File: f}
}

var now = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)

func baseClaims(at time.Time) map[string]any {
	return map[string]any{
		"iss":                issuer,
		"aud":                []string{giteaURL, "account"},
		"azp":                "portcullis-ai-claude",
		"typ":                "Bearer",
		"scope":              "openid mcp:gitea.gitea profile",
		"acr":                "hwk",
		"preferred_username": "Alice",
		"exp":                at.Add(5 * time.Minute).Unix(),
		"iat":                at.Add(-time.Second).Unix(),
		"nbf":                at.Add(-time.Second).Unix(),
		"sub":                "f7a1",
	}
}

func with(c map[string]any, kv ...any) map[string]any {
	out := map[string]any{}
	for k, v := range c {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		if kv[i+1] == nil {
			delete(out, k)
		} else {
			out[k] = kv[i+1]
		}
	}
	return out
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestTokenMatrix(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs := signer{rsaKey, "rsa1", jose.RS256}
	es := signer{ecKey, "ec1", jose.ES256}
	j := newJWKS(t,
		jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa1", Algorithm: "RS256", Use: "sig"},
		jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "ec1", Algorithm: "ES256", Use: "sig"},
	)
	v := NewVerifier(issuer, j.srv.URL, j.srv.Client())
	base := baseClaims(now)
	tok := func(c map[string]any) string { return "Bearer " + rs.sign(t, c) }

	// HS256 signed with the RSA public modulus (key confusion).
	hs := signer{rsaKey.PublicKey.N.Bytes(), "rsa1", jose.HS256}.sign(t, base)
	none := b64(map[string]string{"alg": "none", "kid": "rsa1", "typ": "JWT"}) + "." + b64(base) + "."
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	unknownKid := signer{otherKey, "rotated", jose.RS256}.sign(t, base)

	challenge := `Bearer resource_metadata="` + giteaMeta + `", scope="mcp:gitea.gitea"`
	insufficient := `Bearer error="insufficient_scope", scope="mcp:gitea.gitea", resource_metadata="` + giteaMeta + `"`

	type row struct {
		name     string
		mod      func(sn *config.Snapshot, r *Request)
		auth     string
		status   int
		reason   string
		www      string
		wantUser string
	}
	rows := []row{
		{name: "valid RS256", auth: tok(base), status: 200, reason: "allow", wantUser: "alice"},
		{name: "valid ES256", auth: "Bearer " + es.sign(t, base), status: 200, reason: "allow", wantUser: "alice"},
		{name: "scheme case-insensitive", auth: "bearer " + rs.sign(t, base), status: 200, reason: "allow"},
		{name: "no header", auth: "", status: 401, reason: "no_token", www: challenge},
		{name: "query token (no header)", auth: "", mod: func(_ *config.Snapshot, r *Request) { r.Path = "/mcp" }, status: 401, reason: "no_token", www: challenge},
		{name: "Basic scheme", auth: "Basic YTpi", status: 401, reason: "no_token", www: challenge},
		{name: "garbage token", auth: "Bearer not-a-jwt", status: 401, reason: "bad_token", www: challenge},
		{name: "wrong aud", auth: tok(with(base, "aud", []string{"https://grafana.example.com/mcp"})), status: 401, reason: "audience", www: challenge},
		{name: "aud string", auth: tok(with(base, "aud", giteaURL)), status: 200, reason: "allow"},
		{name: "aud + other resource", auth: tok(with(base, "aud", []string{giteaURL, "https://grafana.example.com/mcp"})), status: 401, reason: "audience", www: challenge},
		{name: "aud + deleted resource", auth: tok(with(base, "aud", []string{giteaURL, "https://old.example.com/mcp"})), status: 401, reason: "audience"},
		{name: "aud + any http URL", auth: tok(with(base, "aud", []string{giteaURL, "HTTP://x.example"})), status: 401, reason: "audience"},
		{name: "aud + account", auth: tok(with(base, "aud", []string{"account", giteaURL})), status: 200, reason: "allow"},
		{name: "no aud", auth: tok(with(base, "aud", nil)), status: 401, reason: "audience"},
		{name: "azp forward-auth", auth: tok(with(base, "azp", "portcullis-forward-auth")), status: 401, reason: "client", www: challenge},
		{name: "azp app client", auth: tok(with(base, "azp", "gitea")), status: 401, reason: "client"},
		{name: "azp ai_client not on this resource", auth: tok(with(base, "azp", "ai-chat-mcp")), status: 401, reason: "client"},
		{name: "no azp", auth: tok(with(base, "azp", nil)), status: 401, reason: "client"},
		{name: "wrong iss", auth: tok(with(base, "iss", "https://auth.evil.example/realms/portcullis")), status: 401, reason: "bad_token"},
		{name: "expired", auth: tok(with(base, "exp", now.Add(-61*time.Second).Unix())), status: 401, reason: "expired", www: challenge},
		{name: "expired within leeway", auth: tok(with(base, "exp", now.Add(-59*time.Second).Unix())), status: 200, reason: "allow"},
		{name: "no exp", auth: tok(with(base, "exp", nil)), status: 401, reason: "expired"},
		{name: "nbf +120 s", auth: tok(with(base, "nbf", now.Add(120*time.Second).Unix())), status: 401, reason: "not_yet_valid"},
		{name: "nbf +59 s", auth: tok(with(base, "nbf", now.Add(59*time.Second).Unix())), status: 200, reason: "allow"},
		{name: "iat +120 s", auth: tok(with(base, "iat", now.Add(120*time.Second).Unix())), status: 401, reason: "not_yet_valid"},
		{name: "alg none", auth: "Bearer " + none, status: 401, reason: "bad_token"},
		{name: "HS256 with the modulus", auth: "Bearer " + hs, status: 401, reason: "bad_token"},
		{name: "unknown kid", auth: "Bearer " + unknownKid, status: 401, reason: "bad_token"},
		{name: "typ Refresh", auth: tok(with(base, "typ", "Refresh")), status: 401, reason: "typ"},
		{name: "typ ID", auth: tok(with(base, "typ", "ID")), status: 401, reason: "typ"},
		{name: "missing scope", auth: tok(with(base, "scope", "openid mcp:grafana.grafana")), status: 403, reason: "scope", www: insufficient},
		{name: "scope prefix only", auth: tok(with(base, "scope", "mcp:gitea.gitea2")), status: 403, reason: "scope"},
		{name: "acr pwd", auth: tok(with(base, "acr", "pwd")), status: 403, reason: "loa"},
		{name: "acr unknown", auth: tok(with(base, "acr", "gold")), status: 403, reason: "loa"},
		{name: "no acr", auth: tok(with(base, "acr", nil)), status: 403, reason: "loa"},
		{name: "acr mtls", auth: tok(with(base, "acr", "mtls")), status: 200, reason: "allow"},
		{name: "not in population", auth: tok(with(base, "preferred_username", "carol")), status: 403, reason: "population"},
		{name: "no username", auth: tok(with(base, "preferred_username", nil)), status: 403, reason: "population"},
		{name: "expiring in the future", auth: tok(with(base, "preferred_username", "bob")), status: 200, reason: "allow", wantUser: "bob"},
		{name: "expiring in the past", auth: tok(with(baseClaims(time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC)), "preferred_username", "bob")),
			mod: func(_ *config.Snapshot, r *Request) { r.Now = time.Date(2027, 4, 1, 0, 0, 0, 0, time.UTC) }, status: 403, reason: "population"},
		{name: "Origin evil", auth: tok(base), mod: func(_ *config.Snapshot, r *Request) { r.Origin = "https://evil.example" }, status: 403, reason: "origin"},
		{name: "Origin listed", auth: tok(base), mod: func(sn *config.Snapshot, r *Request) {
			sn.File.AllowedOrigins = []string{"https://claude.ai"}
			r.Origin = "https://claude.ai"
		}, status: 200, reason: "allow"},
		{name: "Origin null", auth: tok(base), mod: func(_ *config.Snapshot, r *Request) { r.Origin = "null" }, status: 403, reason: "origin"},
		{name: "enabled false", auth: tok(base), mod: func(sn *config.Snapshot, _ *Request) { sn.File.Enabled = false; sn.Off = true }, status: 503, reason: "off"},
		{name: "missing file", auth: tok(base), mod: func(sn *config.Snapshot, _ *Request) { sn.File = nil; sn.Off = true }, status: 503, reason: "off"},
		{name: "corrupt file", auth: tok(base), mod: func(sn *config.Snapshot, _ *Request) { sn.File = nil; sn.Err = errors.New("bad") }, status: 503, reason: "config"},
		{name: "unknown resource", auth: tok(base), mod: func(_ *config.Snapshot, r *Request) { r.Path = "/other" }, status: 404, reason: "no_resource"},
		{name: "host normalised", auth: tok(base), mod: func(_ *config.Snapshot, r *Request) { r.Host = "GITEA.example.com.:443" }, status: 200, reason: "allow"},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			sn := loadSnapshot(t)
			r := Request{Host: "gitea.example.com", Path: "/mcp", Authorization: c.auth, Now: now}
			if c.mod != nil {
				c.mod(sn, &r)
			}
			d := v.Check(context.Background(), sn, r)
			if d.Status != c.status || d.Reason != c.reason {
				t.Fatalf("got %d %q, want %d %q", d.Status, d.Reason, c.status, c.reason)
			}
			if c.www != "" && d.WWWAuthenticate != c.www {
				t.Errorf("WWW-Authenticate %q, want %q", d.WWWAuthenticate, c.www)
			}
			if c.status == 401 && d.WWWAuthenticate != challenge {
				t.Errorf("401 without the challenge: %q", d.WWWAuthenticate)
			}
			if c.wantUser != "" && d.User != c.wantUser {
				t.Errorf("user %q, want %q", d.User, c.wantUser)
			}
			if c.status == 200 && (d.Resource == nil || d.Resource.URL != giteaURL || d.Client != "portcullis-ai-claude") {
				t.Errorf("decision %+v", d)
			}
			if strings.Contains(fmt.Sprintf("%+v", d), "eyJ") {
				t.Error("the decision carries the token")
			}
		})
	}
}

// G20: an unknown kid refreshes the key set at most once per 60 s, gate-wide.
func TestUnknownKidThrottled(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	j := newJWKS(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"})
	v := NewVerifier(issuer, j.srv.URL, j.srv.Client())
	clock := now
	var clockMu sync.Mutex
	v.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	sn := loadSnapshot(t)
	req := func(tok string) Decision {
		return v.Check(context.Background(), sn, Request{Host: "gitea.example.com", Path: "/mcp", Authorization: "Bearer " + tok, Now: now})
	}
	if d := req(signer{rsaKey, "k1", jose.RS256}.sign(t, baseClaims(now))); d.Status != 200 {
		t.Fatalf("warm-up: %d %s", d.Status, d.Reason)
	}
	if n := j.fetches.Load(); n != 1 {
		t.Fatalf("warm-up fetches %d", n)
	}
	// 1000 random kids, concurrently: at most one more fetch.
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			kid := fmt.Sprintf("rnd-%d", i)
			d := req(signer{rsaKey, kid, jose.RS256}.sign(t, baseClaims(now)))
			if d.Status != 401 {
				t.Errorf("kid %s: %d", kid, d.Status)
			}
		}(i)
	}
	wg.Wait()
	if n := j.fetches.Load() - 1; n > 1 {
		t.Fatalf("1000 unknown kids → %d fetches", n)
	}
	// A key rotation: the new key is picked up once the 60 s have passed.
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	j.add(jose.JSONWebKey{Key: &newKey.PublicKey, KeyID: "k2", Algorithm: "RS256", Use: "sig"})
	rotated := signer{newKey, "k2", jose.RS256}.sign(t, baseClaims(now))
	clockMu.Lock()
	clock = clock.Add(61 * time.Second)
	clockMu.Unlock()
	before := j.fetches.Load()
	if d := req(rotated); d.Status != 200 {
		t.Fatalf("rotated key: %d %s", d.Status, d.Reason)
	}
	if j.fetches.Load() != before+1 {
		t.Fatalf("rotation fetches %d", j.fetches.Load()-before)
	}
	// Known keys never fetch.
	before = j.fetches.Load()
	for i := 0; i < 10; i++ {
		req(rotated)
	}
	if j.fetches.Load() != before {
		t.Error("a known kid fetched the key set")
	}
}

// A symmetric or private key in the JWKS is never used.
func TestJWKSOnlyPublicSigningKeys(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	j := newJWKS(t, jose.JSONWebKey{Key: secret, KeyID: "oct", Algorithm: "HS256", Use: "sig"})
	v := NewVerifier(issuer, j.srv.URL, j.srv.Client())
	tok := signer{secret, "oct", jose.HS256}.sign(t, baseClaims(now))
	d := v.Check(context.Background(), loadSnapshot(t), Request{Host: "gitea.example.com", Path: "/mcp", Authorization: "Bearer " + tok, Now: now})
	if d.Status != 401 {
		t.Fatalf("%d %s", d.Status, d.Reason)
	}
}

// G22: routing never reads X-Forwarded-*.
func TestFromHTTPHostOnly(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp?access_token=x", nil)
	r.Host = "gitea.example.com"
	r.Header.Set("X-Forwarded-Host", "hub.example.com")
	r.Header.Set("X-Forwarded-Uri", "/other")
	r.Header.Set("Origin", "https://claude.ai")
	got := FromHTTP(r, now)
	if got.Host != "gitea.example.com" || got.Path != "/mcp" || got.Authorization != "" || got.Origin != "https://claude.ai" {
		t.Fatalf("%+v", got)
	}
	r.Header.Add("Authorization", "Bearer a")
	r.Header.Add("Authorization", "Bearer b")
	r.Header.Add("Origin", "https://evil.example")
	got = FromHTTP(r, now)
	if got.Authorization != "" {
		t.Error("two Authorization headers accepted")
	}
	if got.Origin == "https://claude.ai" || got.Origin == "" {
		t.Error("two Origin headers accepted")
	}
}

// Fix round 1, item 5: a token in the query string, through FromHTTP, is
// no token; a kid of one key type presented with the other algorithm is
// refused (kid confusion).
func TestQueryTokenAndKidConfusion(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	j := newJWKS(t,
		jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa1", Algorithm: "RS256", Use: "sig"},
		jose.JSONWebKey{Key: &ecKey.PublicKey, KeyID: "ec1", Algorithm: "ES256", Use: "sig"},
		// A key without "alg": its type must still match the token's alg.
		jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "rsa-noalg", Use: "sig"},
	)
	v := NewVerifier(issuer, j.srv.URL, j.srv.Client())
	sn := loadSnapshot(t)
	good := signer{rsaKey, "rsa1", jose.RS256}.sign(t, baseClaims(now))

	r := httptest.NewRequest("POST", "/mcp?access_token="+good, nil)
	r.Host = "gitea.example.com"
	if d := v.Check(context.Background(), sn, FromHTTP(r, now)); d.Status != 401 || d.Reason != "no_token" {
		t.Errorf("query token: %d %s", d.Status, d.Reason)
	}
	r.Header.Set("Authorization", "Bearer "+good)
	if d := v.Check(context.Background(), sn, FromHTTP(r, now)); d.Status != 200 {
		t.Fatalf("header token: %d %s", d.Status, d.Reason)
	}
	for name, tok := range map[string]string{
		"RSA kid with ES256":      signer{ecKey, "rsa1", jose.ES256}.sign(t, baseClaims(now)),
		"EC kid with RS256":       signer{rsaKey, "ec1", jose.RS256}.sign(t, baseClaims(now)),
		"alg-less RSA kid, ES256": signer{ecKey, "rsa-noalg", jose.ES256}.sign(t, baseClaims(now)),
	} {
		d := v.Check(context.Background(), sn, Request{Host: "gitea.example.com", Path: "/mcp", Authorization: "Bearer " + tok, Now: now})
		if d.Status != 401 || d.Reason != "bad_token" {
			t.Errorf("%s: %d %s", name, d.Status, d.Reason)
		}
	}
}

// Fix round 1, item 1: the JWKS fetch never follows a redirect.
func TestJWKSRedirectRefused(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	target := newJWKS(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"})
	redir := httptest.NewServer(http.RedirectHandler(target.srv.URL, http.StatusFound))
	defer redir.Close()
	tok := signer{rsaKey, "k1", jose.RS256}.sign(t, baseClaims(now))
	for name, hc := range map[string]*http.Client{"default client": nil, "caller's client": redir.Client()} {
		v := NewVerifier(issuer, redir.URL, hc)
		d := v.Check(context.Background(), loadSnapshot(t), Request{Host: "gitea.example.com", Path: "/mcp", Authorization: "Bearer " + tok, Now: now})
		if d.Status != 401 {
			t.Errorf("%s: %d %s", name, d.Status, d.Reason)
		}
	}
	if n := target.fetches.Load(); n != 0 {
		t.Errorf("the redirect was followed (%d fetches)", n)
	}
	// The default client never uses a proxy from the environment.
	c := jwksClient(nil)
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Error("the default JWKS transport may use a proxy")
	}
}

// Fix round 1, item 2: only the exact, unescaped origin-form path names a
// resource; an escaped path or an absolute-form target is refused.
func TestRequestTargetStrict(t *testing.T) {
	sn := loadSnapshot(t)
	v := NewVerifier(issuer, "http://127.0.0.1:1/none", nil)
	for _, c := range []struct {
		target string
		ok     bool
	}{
		{"/mcp", true},
		{"/mcp?x=1", true},
		{"/%6Dcp", false},
		{"/mc%70", false},
		{"/mcp%2F", false},
		{"https://gitea.example.com/mcp", false},
		{"http://gitea.example.com/mcp", false},
		{"//gitea.example.com/mcp", false},
	} {
		r := httptest.NewRequest("POST", c.target, nil)
		r.Host = "gitea.example.com"
		r.RequestURI = c.target
		_, ok := Target(r)
		if ok != c.ok {
			t.Errorf("%s: Target ok=%v, want %v", c.target, ok, c.ok)
		}
		d := v.Check(context.Background(), sn, FromHTTP(r, now))
		if c.ok && d.Reason != "no_token" {
			t.Errorf("%s: %d %s, want the token check", c.target, d.Status, d.Reason)
		}
		if !c.ok && (d.Status != 400 || d.Reason != "bad_target") {
			t.Errorf("%s: %d %s, want 400 bad_target", c.target, d.Status, d.Reason)
		}
	}
}

// Fix round 1, item 3: usernames are ASCII on both sides; the Kelvin sign
// (U+212A) lowercases to "k" and must not reach a "k" user.
func TestUsernameASCIIOnly(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	j := newJWKS(t, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"})
	v := NewVerifier(issuer, j.srv.URL, j.srv.Client())
	b, err := os.ReadFile("../config/testdata/mcp-gate.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.DecodeFile([]byte(strings.ReplaceAll(string(b), `"bob"`, `"bok"`)))
	if err != nil {
		t.Fatal(err)
	}
	sn := &config.Snapshot{File: f}
	for user, want := range map[string]int{
		"bok":       200,
		"BOK":       200,
		"bo\u212A":  403, // Kelvin sign: ToLower gives "bok"
		"BO\u212A":  403,
		"b\u00f6k":  403,
		"bok\u0000": 403,
		"bo k":      403,
		"":          403,
	} {
		tok := signer{rsaKey, "k1", jose.RS256}.sign(t, with(baseClaims(now), "preferred_username", user))
		d := v.Check(context.Background(), sn, Request{Host: "gitea.example.com", Path: "/mcp", Authorization: "Bearer " + tok, Now: now})
		if d.Status != want {
			t.Errorf("%q: %d %s, want %d", user, d.Status, d.Reason, want)
		}
	}
}
