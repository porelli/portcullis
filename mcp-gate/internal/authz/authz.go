// Package authz decides whether an MCP request may reach its resource
// (integration contract §15.1–§15.2): the resource from the request's Host
// and path only, then a Keycloak access token that is valid for exactly
// that resource and whose sign-in methods meet its rule, then the
// person's membership right now.
//
// Tokens are never logged, stored or put in a Decision.
package authz

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/signin"
)

var logf = log.Printf

// The time leeway on exp / nbf / iat (§15.2).
const leeway = 60 * time.Second

// Tokens longer than this aren't parsed.
const maxTokenBytes = 16 << 10

// OffMessage is the answer while AI support is off (§15.2).
const OffMessage = "AI support is off on this Portcullis"

// Request is what a decision depends on. Build it with FromHTTP.
type Request struct {
	Host, Path, Authorization, Origin string
	Now                               time.Time
	// BadTarget: the request target isn't a plain origin-form path (see
	// Target); such a request is refused before anything else.
	BadTarget bool
}

// Target is the request's path when the request target is in origin
// form ("/..."; not absolute-form "https://host/...", not "//...") and
// unescaped: the path as sent equals the decoded path, so "/%6Dcp" never
// reaches "/mcp". Anything else is ok == false.
func Target(r *http.Request) (path string, ok bool) {
	uri := r.RequestURI
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		return "", false
	}
	raw, _, _ := strings.Cut(uri, "?")
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || raw != r.URL.Path {
		return "", false
	}
	return r.URL.Path, true
}

// FromHTTP takes the resource from r.Host and r.URL.Path only: the gate
// never reads X-Forwarded-* for routing (§15.2, preflight G22). A
// repeated Authorization header counts as none; a repeated Origin as one
// that is never allowed.
func FromHTTP(r *http.Request, now time.Time) Request {
	path, ok := Target(r)
	req := Request{Host: r.Host, Path: path, Now: now, BadTarget: !ok}
	if v := r.Header.Values("Authorization"); len(v) == 1 {
		req.Authorization = v[0]
	}
	switch v := r.Header.Values("Origin"); len(v) {
	case 0:
	case 1:
		req.Origin = v[0]
		if req.Origin == "" {
			req.Origin = "null"
		}
	default:
		req.Origin = "null"
	}
	return req
}

// Decision is the answer to one request. Status 200 means allowed.
type Decision struct {
	Status          int
	WWWAuthenticate string
	// Reason: "allow" or the deny reason for the access log (deny:<reason>).
	Reason string
	// Message: the text for the person's client on a refusal.
	Message      string
	User, Client string
	Resource     *config.Resource
	// Methods are the sign-in methods the token counts for on an MCP
	// request (signin.TokenMethods: its amr through the method table,
	// switched-on methods only, never a certificate); the aggregate checks
	// each upstream's rule against them (§15.9).
	Methods map[string]bool
}

// Allowed reports a 200.
func (d Decision) Allowed() bool { return d.Status == http.StatusOK }

// Verifier checks access tokens against the realm's JWKS.
type Verifier struct {
	issuer string
	keys   *keySet
	now    func() time.Time // the JWKS refresh throttle's clock
}

// NewVerifier verifies signatures with the JWKS at jwksURL (fetched with
// hc, throttled). The expected issuer is the gate file's; a non-empty
// issuer pins it as well (a file naming another issuer then refuses every
// token).
func NewVerifier(issuer, jwksURL string, hc *http.Client) *Verifier {
	v := &Verifier{issuer: issuer, now: time.Now}
	v.keys = &keySet{url: jwksURL, hc: jwksClient(hc), now: func() time.Time { return v.now() }}
	return v
}

type claims struct {
	Typ               string           `json:"typ"`
	Azp               string           `json:"azp"`
	Aud               jwt.Audience     `json:"aud"`
	Scope             string           `json:"scope"`
	Amr               amr              `json:"amr"`
	PreferredUsername string           `json:"preferred_username"`
	Exp               *jwt.NumericDate `json:"exp"`
	Nbf               *jwt.NumericDate `json:"nbf"`
	Iat               *jwt.NumericDate `json:"iat"`
}

// amr is the token's amr claim: a list of strings. Anything else (a
// string, a list with a non-string) decodes as no methods at all, so the
// token meets no rule (403) rather than failing as a bad token.
type amr []string

func (a *amr) UnmarshalJSON(b []byte) error {
	var list []string
	if json.Unmarshal(b, &list) != nil {
		list = nil
	}
	*a = list
	return nil
}

// rawUsername: the token's preferred_username before lowercasing — the
// Hub's pattern with ASCII upper case allowed (config.ValidUsername after).
var rawUsername = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var compactJWS = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func bearer(h string) (string, bool) {
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return tok, true
}

// Check decides one request against the snapshot (§15.2). Order: the
// configuration, the resource, the token (401), then what the token's
// person may do (403).
func (v *Verifier) Check(ctx context.Context, sn *config.Snapshot, r Request) Decision {
	if r.BadTarget {
		return Decision{Status: http.StatusBadRequest, Reason: "bad_target", Message: "bad request target"}
	}
	if sn == nil || sn.Err != nil {
		return Decision{Status: http.StatusServiceUnavailable, Reason: "config", Message: "AI support is unavailable: the gate's configuration can't be read"}
	}
	if sn.Off || sn.File == nil || !sn.File.Enabled {
		return Decision{Status: http.StatusServiceUnavailable, Reason: "off", Message: OffMessage}
	}
	res, ok := sn.Resource(r.Host, r.Path)
	if !ok {
		return Decision{Status: http.StatusNotFound, Reason: "no_resource", Message: "not found"}
	}
	meta := res.MetadataURL()
	deny401 := func(reason string) Decision {
		return Decision{
			Status:          http.StatusUnauthorized,
			WWWAuthenticate: `Bearer resource_metadata="` + meta + `", scope="` + res.Scope + `"`,
			Reason:          reason, Message: "sign in required", Resource: res,
		}
	}
	tok, ok := bearer(r.Authorization)
	if !ok || tok == "" {
		return deny401("no_token")
	}
	if len(tok) > maxTokenBytes || !compactJWS.MatchString(tok) {
		return deny401("bad_token")
	}

	issuer := sn.File.Issuer
	if v.issuer != "" && v.issuer != issuer {
		return deny401("bad_token")
	}
	verifier := oidc.NewVerifier(issuer, v.keys, &oidc.Config{
		SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256},
		SkipClientIDCheck:    true, // the audience rule below
		SkipExpiryCheck:      true, // exp / nbf / iat below, with the contract's leeway
		Now:                  func() time.Time { return r.Now },
	})
	idt, err := verifier.Verify(ctx, tok)
	if err != nil {
		return deny401("bad_token")
	}
	var c claims
	if err := idt.Claims(&c); err != nil {
		return deny401("bad_token")
	}
	if c.Typ != "Bearer" {
		return deny401("typ")
	}
	if c.Exp == nil || !c.Exp.Time().After(r.Now.Add(-leeway)) {
		return deny401("expired")
	}
	late := r.Now.Add(leeway)
	if (c.Nbf != nil && c.Nbf.Time().After(late)) || (c.Iat != nil && c.Iat.Time().After(late)) {
		return deny401("not_yet_valid")
	}
	if !res.AllowsClient(c.Azp) {
		return deny401("client")
	}
	if !audienceOK(c.Aud, res.URL) {
		return deny401("audience")
	}

	// ASCII only, checked before and after lowercasing: strings.ToLower
	// folds e.g. the Kelvin sign U+212A to "k" (fix round 1).
	user := ""
	if rawUsername.MatchString(c.PreferredUsername) {
		if u := strings.ToLower(c.PreferredUsername); config.ValidUsername(u) {
			user = u
		}
	}
	d := Decision{Status: http.StatusForbidden, Message: "not allowed", User: user, Client: c.Azp, Resource: res,
		Methods: signin.TokenMethods(c.Amr, sn.File.Methods)}
	if !slices.Contains(strings.Fields(c.Scope), res.Scope) {
		d.Reason = "scope"
		d.WWWAuthenticate = `Bearer error="insufficient_scope", scope="` + res.Scope + `", resource_metadata="` + meta + `"`
		d.Message = "insufficient scope"
		return d
	}
	// The resource's sign-in rule (§15.2): an unknown amr, inv, a
	// switched-off method and any certificate count as nothing. A 403
	// like the other refusals of a valid token, no challenge: signing in
	// again with the same methods wouldn't help.
	if !res.Rule.Satisfied(d.Methods) {
		d.Reason = "sign_in"
		d.Message = res.Label + " needs a stronger sign-in than this connection has"
		return d
	}
	if user == "" || !res.Member(user, r.Now) {
		d.Reason = "population"
		return d
	}
	if r.Origin != "" && !slices.Contains(sn.File.AllowedOrigins, r.Origin) {
		d.Reason = "origin"
		return d
	}
	d.Status, d.Reason, d.Message = http.StatusOK, "allow", ""
	return d
}

// audienceOK: aud contains this resource's URL and no other http(s) URL
// (§15.2, preflight G19); non-URL values (client ids) are ignored.
func audienceOK(aud []string, url string) bool {
	found := false
	for _, a := range aud {
		if a == url {
			found = true
			continue
		}
		l := strings.ToLower(a)
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			return false
		}
	}
	return found
}
