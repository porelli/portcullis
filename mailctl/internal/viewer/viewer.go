// Package viewer is `mailctl admin-view` (contract §19.13): the proxy
// in front of Stalwart's own web admin, shown to full administrators
// read-only. Traefik reaches it on the Hub's admin-only router; it
// reaches Stalwart's admin-view listener (TLS, answered only to this
// service's address) on the template's internal network.
//
// Three layers keep it read-only and keep every mail guard of the Hub:
//
//  1. the session is always the viewer's: GET /login (Stalwart's OAuth
//     sign-in page) is answered here by signing in as the viewer, whose
//     password only this service holds, and redirecting to the code
//     callback; the sign-in API (/api/auth) is never forwarded, so no
//     other Stalwart login (a mail password included, P11) opens the view;
//  2. every JMAP call is a read: a request with any method whose name
//     isn't /get, /query, /changes or /queryChanges, or that isn't strict
//     JSON (a duplicate or case-variant key, another top-level key), is
//     refused here (403) and never reaches Stalwart, and what is forwarded
//     is the checked request re-encoded, never the browser's bytes;
//     uploads, downloads, push and live endpoints aren't forwarded;
//  3. the viewer's role holds reads only (stalwart.ViewerRolePermissions):
//     Stalwart refuses every write itself.
//
// Only an allowlist of paths is forwarded (anything else is 404 here, so
// Stalwart's scan bans never see a stray path), never the browser's
// Authorization (the reads are authenticated as the viewer by the proxy:
// behind Portcullis's forward-auth the browser's header is replaced by
// Traefik anyway), and neither cookies nor forwarding headers. The
// viewer's password reaches only Stalwart, over the pinned hop.
package viewer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Viewer is the viewer account's login (bootstrap.ViewerName).
const Viewer = "portcullis-viewer@portcullis-former.internal"

// Limits.
const (
	maxJMAPBody  = 1 << 20  // a JMAP request (Stalwart's own maxSizeRequest is 10 MB)
	maxTokenBody = 16 << 10 // an OAuth token request
)

// readMethod is a JMAP method name the view forwards: a read only.
var readMethod = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9:]*/(get|query|changes|queryChanges)$`)

// Proxy is the admin view's handler.
type Proxy struct {
	upstream *url.URL
	host     string                 // the admin view's hostname (Stalwart's trusted host)
	secret   func() (string, error) // the viewer's password, read on every sign-in
	rp       *httputil.ReverseProxy
	client   *http.Client
	logf     func(string, ...any)
}

// New builds the proxy. upstream is Stalwart's admin-view listener
// (https://<ip>:<port>); host the admin view's hostname; secretFile holds
// the viewer's password; spkis are the mail certificate's SPKI SHA-256
// values (hex, the Hub's PORTCULLIS_MAIL_TLS_SPKI: one, two during a key
// rollover). Stalwart serves the mail certificate there, issued for
// MAIL_HOSTNAME (not the internal address, and a staging chain on test
// servers), so the hop is pinned instead of chain-checked: the peer's leaf
// must have one of spkis, or the connection fails (verifyPinned). The
// password and the browser's token never reach anything else.
func New(upstream, host, secretFile string, spkis []string, logf func(string, ...any)) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("admin view: upstream %q is not https://<ip>:<port>", upstream)
	}
	pins, err := parsePins(spkis)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = log.Printf
	}
	tr := &http.Transport{
		// InsecureSkipVerify only skips the chain and name check that can't
		// apply here; VerifyConnection pins the leaf's key (fail closed).
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12, // #nosec G402: pinned by VerifyConnection
			VerifyConnection: func(cs tls.ConnectionState) error { return verifyPinned(cs, pins) }},
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
	}
	p := &Proxy{upstream: u, host: host, logf: logf,
		secret: func() (string, error) {
			b, err := os.ReadFile(secretFile)
			if err != nil {
				return "", errors.New("the viewer's password can't be read")
			}
			s := strings.TrimSpace(string(b))
			if len(s) < 16 {
				return "", errors.New("the viewer's password is missing")
			}
			return s, nil
		},
		client: &http.Client{Transport: tr, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u)
			// Stalwart judges its trusted host by Host (STALWART_PUBLIC_URL).
			r.Out.Host = host
			for _, h := range []string{"Cookie", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-Ip"} {
				r.Out.Header.Del(h)
			}
			for k := range r.Out.Header {
				if strings.HasPrefix(strings.ToLower(k), "x-auth-request-") || strings.HasPrefix(strings.ToLower(k), "x-forwarded-") {
					r.Out.Header.Del(k)
				}
			}
			// The browser's own Authorization never reaches Stalwart (behind
			// Portcullis's forward-auth it doesn't arrive at all: Traefik
			// replaces it). The reads are the viewer's, always.
			r.Out.Header.Del("Authorization")
			if viewerAuthPath(r.In.URL.Path) {
				if pw, err := p.secret(); err == nil {
					r.Out.SetBasicAuth(Viewer, pw)
				}
			}
		},
		Transport: tr,
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Set-Cookie")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logf("admin-view: upstream: %v", err)
			http.Error(w, "the mail server isn't answering", http.StatusBadGateway)
		},
	}
	return p, nil
}

// viewerAuthPath: the paths the proxy authenticates as the viewer (the
// JMAP session and calls, the account and schema reads); the sign-in,
// token, logout and static paths go without credentials.
func viewerAuthPath(path string) bool {
	return path == "/jmap" || path == "/jmap/" || path == "/jmap/session" || path == "/api/account" ||
		path == "/api/schema" || strings.HasPrefix(path, "/api/schema/")
}

// parsePins checks the pinned SPKI SHA-256 values: 1–2, 64 lowercase hex.
func parsePins(spkis []string) (map[[32]byte]bool, error) {
	pins := map[[32]byte]bool{}
	for _, s := range spkis {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 || s != strings.ToLower(s) {
			return nil, fmt.Errorf("admin view: %q is not an SPKI SHA-256 (64 lowercase hex)", s)
		}
		pins[[32]byte(b)] = true
	}
	if len(pins) == 0 || len(pins) > 2 {
		return nil, errors.New("admin view: the mail certificate's SPKI SHA-256 (1 or 2) is required: the hop to the mail server is pinned to it")
	}
	return pins, nil
}

// verifyPinned requires the peer's leaf certificate to carry a pinned key.
func verifyPinned(cs tls.ConnectionState, pins map[[32]byte]bool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("admin view: the mail server presented no certificate")
	}
	if !pins[sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)] {
		return errors.New("admin view: the mail server's certificate key isn't the mail certificate's (pinned SPKI mismatch)")
	}
	return nil
}

// ServeHTTP is the allowlist (contract §19.13).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	get := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case path == "/healthz" && get:
		w.WriteHeader(http.StatusOK)
	case path == "/" && get:
		http.Redirect(w, r, "/admin/", http.StatusFound)
	case (path == "/admin" || strings.HasPrefix(path, "/admin/")) && get,
		(path == "/logo" || strings.HasPrefix(path, "/logo/")) && get,
		path == "/api/account" && get,
		(path == "/api/schema" || strings.HasPrefix(path, "/api/schema/")) && get,
		path == "/jmap/session" && get,
		strings.HasPrefix(path, "/.well-known/oauth-") && get,
		path == "/.well-known/openid-configuration" && get,
		(path == "/auth/logout") && (get || r.Method == http.MethodPost),
		path == "/auth/revoke" && r.Method == http.MethodPost:
		p.rp.ServeHTTP(w, r)
	case strings.HasPrefix(path, "/api/discover/") && get:
		// Whatever name the sign-in form was given, the view signs in as
		// the viewer: discover the viewer's domain.
		r2 := r.Clone(r.Context())
		r2.URL.Path, r2.URL.RawPath = "/api/discover/"+url.PathEscape(Viewer), ""
		p.rp.ServeHTTP(w, r2)
	case path == "/login" && get:
		p.signIn(w, r)
	case path == "/auth/token" && r.Method == http.MethodPost:
		p.token(w, r)
	case (path == "/jmap" || path == "/jmap/") && r.Method == http.MethodPost:
		p.jmap(w, r)
	default:
		http.NotFound(w, r)
	}
}

// user is the full administrator Traefik's forward-auth let through (for
// the log line only; Traefik strips a client's own copy).
func user(r *http.Request) string {
	if u := r.Header.Get("X-Forwarded-User"); u != "" {
		return u
	}
	return "an unnamed admin"
}

// signIn answers Stalwart's OAuth sign-in page: it signs in as the viewer
// with the browser's own authorization request (its client, redirect and
// PKCE challenge, checked by Stalwart) and redirects the browser to the
// answer's location, the web admin's code callback on this host.
func (p *Proxy) signIn(w http.ResponseWriter, r *http.Request) {
	pw, err := p.secret()
	if err != nil {
		p.logf("admin-view: sign-in refused: %v", err)
		http.Error(w, "the read-only mail admin view isn't set up on this mail server", http.StatusServiceUnavailable)
		return
	}
	body, _ := json.Marshal(map[string]any{"type": "authCode", "accountName": Viewer, "accountSecret": pw, "query": r.URL.RawQuery})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, p.upstream.String()+"/api/auth", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	req.Host = p.host
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.logf("admin-view: sign-in: the mail server isn't answering")
		http.Error(w, "the mail server isn't answering", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	var ans struct {
		Type     string `json:"type"`
		Location string `json:"location"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ans) != nil {
		p.logf("admin-view: sign-in: the mail server answered HTTP %d", resp.StatusCode)
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	if ans.Type != "authenticated" && ans.Type != "redirect" {
		p.logf("admin-view: sign-in: the mail server answered %q", ans.Type)
		http.Error(w, "sign-in failed: the mail server answered "+ans.Type, http.StatusForbidden)
		return
	}
	// Only back to this host's web admin.
	loc, err := url.Parse(ans.Location)
	if err != nil || loc.Scheme != "https" || !strings.EqualFold(loc.Host, p.host) || !strings.HasPrefix(loc.Path, "/admin/") {
		p.logf("admin-view: sign-in: refused a redirect off the admin view")
		http.Error(w, "sign-in failed", http.StatusBadGateway)
		return
	}
	if ans.Type == "authenticated" {
		p.logf("admin-view: %s opened the read-only mail admin view (signed in as the viewer)", user(r))
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loc.String(), http.StatusFound)
}

// token forwards an OAuth token request with a code or a refresh token
// only (never a password or device grant).
func (p *Proxy) token(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxTokenBody+1))
	if err != nil || len(b) > maxTokenBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	v, err := url.ParseQuery(string(b))
	if g := v.Get("grant_type"); err != nil || (g != "authorization_code" && g != "refresh_token") || len(v["grant_type"]) != 1 {
		http.Error(w, "the read-only admin view takes only code and refresh grants", http.StatusBadRequest)
		return
	}
	// The checked form, re-encoded (never the browser's bytes).
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.forward(w, r, []byte(v.Encode()))
}

// jmap forwards a JMAP request only when every method call is a read,
// and forwards the body it checked, re-encoded (canonicalJMAP): never the
// browser's bytes, so Stalwart can't parse anything the check didn't see.
func (p *Proxy) jmap(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxJMAPBody+1))
	if err != nil || len(b) > maxJMAPBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, why := canonicalJMAP(b)
	if why != "" {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:jmap:error:forbidden", "status": 403,
			"title": "Read-only", "detail": "Stalwart's admin screen is read-only here: make changes in Portcullis (Settings → Mail). " + why})
		return
	}
	r.Header.Set("Content-Type", "application/json")
	p.forward(w, r, body)
}

// errNotJMAP is canonicalJMAP's answer for anything but a strict request.
const errNotJMAP = "Not a strict JMAP request."

// canonicalJMAP checks a JMAP request strictly and re-encodes it ("" why
// = a pure read). The top level is an object with exactly the keys
// "using" (strings) and "methodCalls" (each [name, arguments object,
// call id]), in that exact case, each once: a duplicate key, another
// case, another key or trailing data is refused, so no second reading
// of the bytes can hold a call the check didn't see (strictObject scans
// the tokens). Every name must be a read (readMethod). The answer is
// built from the checked values only; each arguments object is decoded
// (numbers kept exact) and encoded again, so its keys reach Stalwart once.
func canonicalJMAP(b []byte) ([]byte, string) {
	top, ok := strictObject(b)
	if !ok {
		return nil, errNotJMAP
	}
	for k := range top {
		if k != "using" && k != "methodCalls" {
			return nil, errNotJMAP
		}
	}
	var using []string
	if raw, ok := top["using"]; !ok || json.Unmarshal(raw, &using) != nil {
		return nil, errNotJMAP
	}
	rawCalls, ok := top["methodCalls"]
	if !ok {
		return nil, errNotJMAP
	}
	var calls []json.RawMessage
	if json.Unmarshal(rawCalls, &calls) != nil {
		return nil, errNotJMAP
	}
	out := make([][3]any, 0, len(calls))
	for _, c := range calls {
		var call []json.RawMessage
		if json.Unmarshal(c, &call) != nil || len(call) != 3 {
			return nil, errNotJMAP
		}
		var name, id string
		if json.Unmarshal(call[0], &name) != nil || json.Unmarshal(call[2], &id) != nil {
			return nil, errNotJMAP
		}
		if !readMethod.MatchString(name) {
			return nil, "Refused: " + name + "."
		}
		args, ok := strictValue(call[1])
		if _, isObj := args.(map[string]any); !ok || !isObj {
			return nil, errNotJMAP
		}
		out = append(out, [3]any{name, args, id})
	}
	body, err := json.Marshal(map[string]any{"using": using, "methodCalls": out})
	if err != nil {
		return nil, errNotJMAP
	}
	return body, ""
}

// strictObject decodes a JSON object whose keys are unique (exactly, and
// case-insensitively: Go's decoder matches struct fields without case),
// with nothing after it; values stay raw.
func strictObject(b []byte) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	out := map[string]json.RawMessage{}
	folded := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		k, isKey := t.(string)
		if err != nil || !isKey || folded[strings.ToLower(k)] {
			return nil, false
		}
		folded[strings.ToLower(k)] = true
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, false
		}
		out[k] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return out, true
}

// strictValue decodes any JSON value, refusing a duplicate key (exactly
// or case-insensitively) in any object at any depth; numbers stay exact.
func strictValue(b []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, ok := strictNext(dec, 0)
	if !ok {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

func strictNext(dec *json.Decoder, depth int) (any, bool) {
	if depth > 64 {
		return nil, false
	}
	t, err := dec.Token()
	if err != nil {
		return nil, false
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		folded := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			k, isKey := kt.(string)
			if err != nil || !isKey || folded[strings.ToLower(k)] {
				return nil, false
			}
			folded[strings.ToLower(k)] = true
			v, ok := strictNext(dec, depth+1)
			if !ok {
				return nil, false
			}
			m[k] = v
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('}') {
			return nil, false
		}
		return m, true
	case json.Delim('['):
		a := []any{}
		for dec.More() {
			v, ok := strictNext(dec, depth+1)
			if !ok {
				return nil, false
			}
			a = append(a, v)
		}
		if t, err := dec.Token(); err != nil || t != json.Delim(']') {
			return nil, false
		}
		return a, true
	case json.Delim('}'), json.Delim(']'):
		return nil, false
	default:
		return t, true
	}
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	r2.Header.Del("Content-Length")
	p.rp.ServeHTTP(w, r2)
}

// Serve runs the proxy on addr until ctx ends.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		return err
	}
}
