// Package viewer is `mailctl admin-view` (contract §19.13): the proxy
// in front of Stalwart's own web admin, shown to full administrators
// read-only. Traefik reaches it on the Hub's admin-only router; it
// reaches Stalwart's admin-view listener (TLS, answered only to this
// service's address) on the template's internal network.
//
// What keeps it admin-only (every check fails closed with 403 and no
// credential used anywhere):
//
//   - Gate: the request comes from Traefik's address with the per-install
//     route key the Hub's router sets after forward-auth and group-gate,
//     and forward-auth's groups header (X-Auth-Request-Groups, whose client
//     copy Traefik deletes) holds the admin group;
//   - a session: only POST /portcullis/open with a single-use ticket the
//     Hub's audited Open action minted for this admin (≤ 60 s, its own
//     per-install key, spent nonces kept on disk) starts one;
//     it ends after 30 min idle or 8 h; a visit without one gets a page
//     saying to open the view from Portcullis.
//
// What keeps it read-only (and every mail guard of the Hub):
//
//  1. the browser never signs in to Stalwart: the proxy answers the web
//     admin's OAuth itself (/login, /auth/token, /auth/revoke,
//     /auth/logout) with opaque per-session values, and authenticates every
//     forwarded read as the viewer (Basic, over the pinned hop): no Stalwart
//     token or password reaches a person, and Stalwart's sign-in API is
//     never forwarded (no other login, a mail password included, P11);
//  2. every JMAP call is on the allowlist: x:<Obj>/get and /query of the
//     objects the viewer's role reads (stalwart.ViewerMethodAllowed), in a
//     strict body forwarded re-encoded; anything else is 403 here and never
//     reaches Stalwart; uploads, downloads, push and live aren't forwarded;
//  3. the viewer's role holds reads only (stalwart.ViewerRolePermissions):
//     Stalwart refuses every write itself.
//
// Only canonical allowlisted paths are forwarded (anything else is 404
// here, so Stalwart's scan bans never see a stray path), never the
// browser's Authorization, cookies or forwarding headers.
package viewer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// Viewer is the viewer account's login (bootstrap.ViewerName).
const Viewer = "portcullis-viewer@portcullis-former.internal"

// Limits.
const (
	maxJMAPBody  = 1 << 20  // a JMAP request (Stalwart's own maxSizeRequest is 10 MB)
	maxTokenBody = 16 << 10 // an OAuth token request
	// TicketTTL is the longest a ticket from the Hub's Open action lives.
	TicketTTL = 60 * time.Second
	// SessionIdle / SessionMax end a session (contract §19.13).
	SessionIdle = 30 * time.Minute
	SessionMax  = 8 * time.Hour
	// SessionCookie is the proxy's own session cookie (never forwarded).
	SessionCookie = "__Host-portcullis-mail-admin"
)

// RouteKeyHeader carries the per-install route key the Hub's admin view
// router sets after forward-auth admitted the request (Traefik overwrites
// any client copy; contract §19.13).
const RouteKeyHeader = "X-Portcullis-Mail-Admin-Key"

// GroupsHeader is forward-auth's groups header (oauth2-proxy, echoed by
// group-gate; both list it in authResponseHeaders, so Traefik deletes a
// client's copy).
const GroupsHeader = "X-Auth-Request-Groups"

// Gate is who may reach the proxy: Traefik's address on portcullis-proxy,
// the route key its router sets and the admin group in forward-auth's
// groups header. A request without all three is 403 and nothing (no
// credential) is sent upstream.
type Gate struct {
	TraefikIP netip.Addr
	Key       string
	Group     string
}

// Tickets is how the proxy checks the Hub's tickets (contract §19.13):
// the per-install ticket secret (its own key, never the route key, never a
// Traefik label or environment value: a file only the Hub and the proxy
// read) and the file where spent nonces are kept until they expire, so a
// restart can't let one be used again.
type Tickets struct {
	Secret   []byte
	UsedFile string
}

// TicketKey is the MAC key of the Hub's tickets: HMAC-SHA256(the ticket
// secret, "portcullis-mail-admin-ticket v1") (contract §19.13).
func TicketKey(secret []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("portcullis-mail-admin-ticket v1"))
	return m.Sum(nil)
}

// ticketBody is a ticket's payload.
type ticketBody struct {
	User   string `json:"u"`
	Nonce  string `json:"n"`
	Expiry int64  `json:"e"`
}

// MintTicket is a ticket for user valid until exp, key = TicketKey of the
// ticket secret (the Hub mints them;
// here for the tests and as the format's reference):
// "v1.<b64url(json)>.<b64url(hmac)>".
func MintTicket(key []byte, user, nonce string, exp time.Time) string {
	b, _ := json.Marshal(ticketBody{User: user, Nonce: nonce, Expiry: exp.Unix()})
	p := "v1." + base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// session is one admin's view session.
type session struct {
	user                    string
	created, last           time.Time
	code, access, refresh   string // the opaque OAuth values handed to the web admin
	codeChallenge, redirect string
}

// Proxy is the admin view's handler.
type Proxy struct {
	gate      Gate
	ticketKey []byte
	usedFile  string
	upstream  *url.URL
	host      string                 // the admin view's hostname (Stalwart's trusted host)
	secret    func() (string, error) // the viewer's password, read when used
	rp        *httputil.ReverseProxy
	client    *http.Client
	logf      func(string, ...any)
	now       func() time.Time

	mu       sync.Mutex
	sessions map[string]*session
	used     map[string]time.Time // ticket nonces seen, until their expiry
}

// New builds the proxy. upstream is Stalwart's admin-view listener
// (https://<ip>:<port>); host the admin view's hostname; secretFile holds
// the viewer's password (each read is registered with onSecret, the log
// redaction); spkis are the mail certificate's SPKI SHA-256 values (hex,
// the Hub's PORTCULLIS_MAIL_TLS_SPKI: one, two during a key rollover).
//
// The upstream hop: Stalwart serves the mail certificate there, issued
// for MAIL_HOSTNAME (not the internal address, and a staging chain on test
// servers), so the hop is pinned instead of chain-checked. The ruling owner
// accepted this exact form (ux2 fix round 1, ruling 3): InsecureSkipVerify
// together with VerifyConnection requiring the leaf's SPKI SHA-256 to be
// one of spkis. Without a valid pin New fails; a mismatched or missing
// peer certificate fails the connection (verifyPinned); there is no TLS
// session cache, so no resumption skips the check. TestUpstreamPinned
// keeps both halves together.
func New(upstream, host, secretFile string, spkis []string, gate Gate, tk Tickets, onSecret func(string), logf func(string, ...any)) (*Proxy, error) {
	if !gate.TraefikIP.Is4() || len(gate.Key) < 32 || gate.Group == "" {
		return nil, errors.New("admin view: Traefik's address, the per-install route key and the admin group are required: nothing reaches the proxy without them")
	}
	if len(tk.Secret) < 32 || tk.UsedFile == "" {
		return nil, errors.New("admin view: the ticket secret (32+ bytes) and the spent-ticket file are required")
	}
	used, err := loadUsed(tk.UsedFile)
	if err != nil {
		return nil, err
	}
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
	if onSecret == nil {
		onSecret = func(string) {}
	}
	tr := &http.Transport{
		TLSClientConfig:       pinnedTLS(host, pins),
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
	}
	p := &Proxy{gate: gate, ticketKey: TicketKey(tk.Secret), usedFile: tk.UsedFile, upstream: u, host: host, logf: logf, now: time.Now,
		sessions: map[string]*session{}, used: used,
		secret: func() (string, error) {
			b, err := os.ReadFile(secretFile)
			if err != nil {
				return "", errors.New("the viewer's password can't be read")
			}
			s := strings.TrimSpace(string(b))
			if len(s) < 16 {
				return "", errors.New("the viewer's password is missing")
			}
			onSecret(s)
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
			for _, h := range []string{"Cookie", RouteKeyHeader, "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-Ip"} {
				r.Out.Header.Del(h)
			}
			for k := range r.Out.Header {
				if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-auth-request-") || strings.HasPrefix(lk, "x-forwarded-") {
					r.Out.Header.Del(k)
				}
			}
			// The browser's own Authorization never reaches Stalwart. The
			// reads are the viewer's, always.
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
			// The view answers its own origin only: never Stalwart's CORS.
			for k := range resp.Header {
				if strings.HasPrefix(strings.ToLower(k), "access-control-") {
					resp.Header.Del(k)
				}
			}
			// Never a browser password prompt (a mail password is never
			// typed into a web page, P11).
			resp.Header.Del("WWW-Authenticate")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logf("admin-view: upstream: %v", err)
			http.Error(w, "the mail server isn't answering", http.StatusBadGateway)
		},
	}
	return p, nil
}

// pinnedTLS is the upstream hop's TLS: the chain and name checks are
// skipped only because VerifyConnection pins the leaf's key (ruling 3).
func pinnedTLS(host string, pins map[[32]byte]bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12, // #nosec G402: pinned by VerifyConnection (ruling 3)
		VerifyConnection: func(cs tls.ConnectionState) error { return verifyPinned(cs, pins) }}
}

// schemaHashRe is /api/schema/<hash>.
var schemaHashRe = regexp.MustCompile(`^/api/schema/[A-Za-z0-9_-]{8,128}$`)

// viewerAuthPath: the exact paths the proxy authenticates as the viewer
// (the JMAP session and calls, the account and schema reads); the static
// paths go without credentials.
func viewerAuthPath(p string) bool {
	return p == "/jmap" || p == "/jmap/" || p == "/jmap/session" || p == "/api/account" || p == "/api/schema" || schemaHashRe.MatchString(p)
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

// admitted: the request came from Traefik's address with the route key
// and the admin group.
func (p *Proxy) admitted(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || ap.Addr().Unmap() != p.gate.TraefikIP {
		return false
	}
	if len(r.Header.Values(RouteKeyHeader)) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get(RouteKeyHeader)), []byte(p.gate.Key)) != 1 {
		return false
	}
	if len(r.Header.Values(GroupsHeader)) != 1 {
		return false
	}
	for _, g := range strings.Split(r.Header.Get(GroupsHeader), ",") {
		if strings.TrimSpace(g) == p.gate.Group {
			return true
		}
	}
	return false
}

// originOK is the cross-origin check (ux2 nit N-a), Go's
// CrossOriginProtection's rule with one same-site exception: a request
// that changes something (POST, and the sign-out GET) must be
// same-origin by Sec-Fetch-Site, else its Origin must be this host; only
// /portcullis/open may also come from the Hub's own origin (hub.<the
// view's parent domain>: the Hub page posts the ticket from there). A
// request with neither header is a non-browser client and passes (the
// gate and the session still apply).
func (p *Proxy) originOK(r *http.Request) bool {
	changes := r.Method != http.MethodGet && r.Method != http.MethodHead || r.URL.Path == "/auth/logout"
	if !changes {
		return true
	}
	sfs, origin := r.Header.Get("Sec-Fetch-Site"), r.Header.Get("Origin")
	if sfs == "" && origin == "" {
		return true
	}
	if sfs == "same-origin" || sfs == "none" {
		return origin == "" || strings.EqualFold(origin, "https://"+p.host)
	}
	if r.URL.Path == "/portcullis/open" && sfs == "same-site" {
		return strings.EqualFold(origin, p.hubOrigin())
	}
	return sfs == "" && strings.EqualFold(origin, "https://"+p.host)
}

// hubOrigin is the Hub's origin for the view's host: mail-admin.<d> →
// https://hub.<d> (contract §19.13).
func (p *Proxy) hubOrigin() string {
	_, parent, ok := strings.Cut(p.host, ".")
	if !ok {
		return ""
	}
	return "https://hub." + parent
}

// canonicalPath: a path the proxy will look at (no dot segments, no
// doubled or encoded slashes or dots, no backslash).
func canonicalPath(r *http.Request) bool {
	p, raw := r.URL.Path, r.URL.RawPath
	if p == "" || !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, "\\") {
		return false
	}
	lr := strings.ToLower(raw + r.URL.EscapedPath())
	if strings.Contains(lr, "%2e") || strings.Contains(lr, "%2f") || strings.Contains(lr, "%5c") {
		return false
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c == p
}

// user is the full administrator forward-auth let through (and the
// admin impersonating, if any: both for the logs).
func user(r *http.Request) string { return strings.TrimSpace(r.Header.Get("X-Forwarded-User")) }

func who(r *http.Request) string {
	u := user(r)
	if imp := strings.TrimSpace(r.Header.Get("X-Forwarded-Impersonator")); imp != "" {
		return u + " (impersonated by " + imp + ")"
	}
	return u
}

// ServeHTTP is the gate, the session, then the allowlist (contract §19.13).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.admitted(r) || user(r) == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !canonicalPath(r) {
		http.NotFound(w, r)
		return
	}
	path := r.URL.Path
	get := r.Method == http.MethodGet || r.Method == http.MethodHead
	if !p.originOK(r) {
		http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
		return
	}
	if path == "/portcullis/open" {
		// The ticket comes in a POST body only (never a URL: no access
		// log or history holds it); a GET is told to open from Portcullis.
		if r.Method == http.MethodPost {
			p.open(w, r)
		} else {
			openFromPortcullis(w, "This page opens only from Portcullis.")
		}
		return
	}
	s, why := p.session(r)
	if s == nil {
		openFromPortcullis(w, why)
		return
	}
	switch {
	case path == "/" && get:
		http.Redirect(w, r, "/admin/", http.StatusFound)
	case (path == "/admin" || strings.HasPrefix(path, "/admin/")) && get,
		(path == "/logo" || strings.HasPrefix(path, "/logo/")) && get,
		path == "/api/account" && get,
		(path == "/api/schema" || schemaHashRe.MatchString(path)) && get,
		path == "/jmap/session" && get,
		(path == "/.well-known/oauth-authorization-server" || path == "/.well-known/openid-configuration" ||
			strings.HasPrefix(path, "/.well-known/oauth-protected-resource")) && get:
		p.rp.ServeHTTP(w, r)
	case strings.HasPrefix(path, "/api/discover/") && get:
		// Whatever name the sign-in form was given, the view is the
		// viewer's: discover the viewer's domain.
		r2 := r.Clone(r.Context())
		r2.URL.Path, r2.URL.RawPath = "/api/discover/"+url.PathEscape(Viewer), ""
		p.rp.ServeHTTP(w, r2)
	case path == "/login" && get:
		p.login(w, r, s)
	case path == "/auth/token" && r.Method == http.MethodPost:
		p.token(w, r, s)
	case path == "/auth/revoke" && r.Method == http.MethodPost:
		w.WriteHeader(http.StatusOK)
	case path == "/auth/logout" && (get || r.Method == http.MethodPost):
		p.end(w, r)
	case (path == "/jmap" || path == "/jmap/") && r.Method == http.MethodPost:
		p.jmap(w, r)
	default:
		http.NotFound(w, r)
	}
}

// openFromPortcullis is the answer without a session.
func openFromPortcullis(w http.ResponseWriter, why string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>Open it from Portcullis</title>`+
		`<h1>Open it from Portcullis</h1><p>%s</p><p>Open the mail server's read-only admin screen from Portcullis: Settings → Mail, <strong>Open … admin (read-only)</strong>.</p>`,
		html.EscapeString(why))
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// session is the request's live session (its cookie, the same admin,
// within the idle and total limits), or nil and why.
func (p *Proxy) session(r *http.Request) (*session, string) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		return nil, "This page opens only from Portcullis."
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[c.Value]
	switch {
	case s == nil:
		return nil, "This session isn't known (it ended, or the view restarted)."
	case now.Sub(s.last) > SessionIdle || now.Sub(s.created) > SessionMax:
		delete(p.sessions, c.Value)
		return nil, "This session ended (30 minutes idle or 8 hours open)."
	case s.user != user(r):
		return nil, "This session belongs to another administrator."
	}
	s.last = now
	return s, ""
}

// open starts a session from the Hub's ticket: well formed, MAC'd with
// the ticket key, unexpired (≤ TicketTTL ahead), for the forwarded admin,
// never seen before. The mail server's unmask switch must be off.
func (p *Proxy) open(w http.ResponseWriter, r *http.Request) {
	t := ""
	if r.URL.RawQuery == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if b, err := io.ReadAll(io.LimitReader(r.Body, 4097)); err == nil && len(b) <= 4096 {
			if v, err := url.ParseQuery(string(b)); err == nil && len(v["t"]) == 1 {
				t = v.Get("t")
			}
		}
	}
	tb, ok := p.checkTicket(t, user(r))
	if !ok {
		p.logf("admin-view: %s presented no valid ticket", who(r))
		openFromPortcullis(w, "The link was used, expired or isn't yours.")
		return
	}
	if err := p.secretsMasked(r.Context()); err != nil {
		p.logf("admin-view: refusing to open: %v", err)
		http.Error(w, "the read-only mail admin view can't open: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	id := randomToken()
	now := p.now()
	p.mu.Lock()
	for k, s := range p.sessions {
		if now.Sub(s.last) > SessionIdle || now.Sub(s.created) > SessionMax {
			delete(p.sessions, k)
		}
	}
	p.sessions[id] = &session{user: tb.User, created: now, last: now}
	p.mu.Unlock()
	p.logf("admin-view: %s opened the read-only mail admin view (ticket %s)", who(r), tb.Nonce)
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: id, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/admin/", http.StatusFound)
}

func (p *Proxy) checkTicket(t, forUser string) (ticketBody, bool) {
	var tb ticketBody
	parts := strings.Split(t, ".")
	if len(parts) != 3 || parts[0] != "v1" || len(t) > 1024 {
		return tb, false
	}
	m := hmac.New(sha256.New, p.ticketKey)
	m.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, m.Sum(nil)) {
		return tb, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(b, &tb) != nil || tb.Nonce == "" || tb.User == "" {
		return tb, false
	}
	now := p.now()
	exp := time.Unix(tb.Expiry, 0)
	if !now.Before(exp) || exp.Sub(now) > TicketTTL || tb.User != forUser {
		return tb, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for n, e := range p.used {
		if now.After(e) {
			delete(p.used, n)
		}
	}
	if _, seen := p.used[tb.Nonce]; seen {
		return tb, false
	}
	p.used[tb.Nonce] = exp
	// Kept on disk before the session opens: a failed write refuses the
	// ticket (a restart must not forget it).
	if err := saveUsed(p.usedFile, p.used); err != nil {
		p.logf("admin-view: the spent-ticket file can't be written: refusing")
		return tb, false
	}
	return tb, true
}

// loadUsed reads the spent-ticket file (nonce → expiry, unix seconds); a
// missing file is empty, an unreadable or malformed one is an error.
func loadUsed(path string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("admin view: the spent-ticket file: %w", err)
	}
	var m map[string]int64
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errors.New("admin view: the spent-ticket file is malformed")
	}
	now := time.Now()
	for n, e := range m {
		if t := time.Unix(e, 0); t.After(now) {
			out[n] = t
		}
	}
	return out, nil
}

// saveUsed writes the spent-ticket file in full (temporary file, fsync,
// rename).
func saveUsed(path string, used map[string]time.Time) error {
	m := make(map[string]int64, len(used))
	for n, e := range used {
		m[n] = e.Unix()
	}
	b, _ := json.Marshal(m)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// secretsMasked: the mail server's unmask switch (SystemSettings
// includeSecrets) is off, read as the viewer (contract §19.13).
func (p *Proxy) secretsMasked(ctx context.Context) error {
	pw, err := p.secret()
	if err != nil {
		return err
	}
	body := `{"using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],"methodCalls":[["x:SystemSettings/get",{"ids":["singleton"],"properties":["includeSecrets"]},"0"]]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream.String()+"/jmap", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Host = p.host
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(Viewer, pw)
	resp, err := p.client.Do(req)
	if err != nil {
		return errors.New("the mail server isn't answering")
	}
	defer resp.Body.Close()
	var ans struct {
		MethodResponses [][]json.RawMessage `json:"methodResponses"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ans) != nil || len(ans.MethodResponses) != 1 || len(ans.MethodResponses[0]) != 3 {
		return fmt.Errorf("the mail server answered HTTP %d", resp.StatusCode)
	}
	var got struct {
		List []struct {
			IncludeSecrets *bool `json:"includeSecrets"`
		} `json:"list"`
	}
	if json.Unmarshal(ans.MethodResponses[0][1], &got) != nil || len(got.List) != 1 || got.List[0].IncludeSecrets == nil {
		return errors.New("the mail server's secret masking can't be read")
	}
	if *got.List[0].IncludeSecrets {
		return errors.New("the mail server shows secrets (includeSecrets is on)")
	}
	return nil
}

// login answers the web admin's OAuth sign-in for the session: a code for
// the web admin's own callback on this host only.
func (p *Proxy) login(w http.ResponseWriter, r *http.Request, s *session) {
	q := r.URL.Query()
	redir := q.Get("redirect_uri")
	ru, err := url.Parse(redir)
	if q.Get("response_type") != "code" || q.Get("state") == "" || err != nil || ru.Scheme != "https" || !strings.EqualFold(ru.Host, p.host) ||
		ru.Path != "/admin/oauth/callback" || ru.RawQuery != "" || ru.Fragment != "" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "sign-in refused", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	s.code, s.codeChallenge, s.redirect = randomToken(), q.Get("code_challenge"), redir
	code := s.code
	p.mu.Unlock()
	back := url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {"https://" + p.host}}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, redir+"?"+back.Encode(), http.StatusFound)
}

// token answers the web admin's token requests itself: its code (with
// the PKCE verifier) or its refresh token for opaque per-session values,
// never a Stalwart token.
func (p *Proxy) token(w http.ResponseWriter, r *http.Request, s *session) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxTokenBody+1))
	if err != nil || len(b) > maxTokenBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	v, err := url.ParseQuery(string(b))
	refuse := func() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}
	if err != nil || len(v["grant_type"]) != 1 {
		refuse()
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	switch v.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(v.Get("code_verifier")))
		if s.code == "" || subtle.ConstantTimeCompare([]byte(v.Get("code")), []byte(s.code)) != 1 || v.Get("redirect_uri") != s.redirect ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != s.codeChallenge {
			refuse()
			return
		}
		s.code = ""
	case "refresh_token":
		if s.refresh == "" || subtle.ConstantTimeCompare([]byte(v.Get("refresh_token")), []byte(s.refresh)) != 1 {
			refuse()
			return
		}
	default:
		refuse()
		return
	}
	s.access, s.refresh = randomToken(), randomToken()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"access_token": s.access, "refresh_token": s.refresh, "token_type": "Bearer", "expires_in": 3600})
}

// end ends the session (the web admin's sign-out).
func (p *Proxy) end(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		p.mu.Lock()
		delete(p.sessions, c.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	openFromPortcullis(w, "You signed out of the mail server's admin screen.")
}

// jmap forwards a JMAP request only when every method call is on the
// allowlist, and forwards the body it checked, re-encoded (canonicalJMAP):
// never the browser's bytes, so Stalwart can't parse anything the check
// didn't see.
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
			"title": "Read-only", "detail": "The mail server's admin screen is read-only here: make changes in Portcullis (Settings → Mail). " + why})
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
// the tokens). Every name must be on the allowlist (stalwart.ViewerMethodAllowed). The answer is
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
		// The allowlist: x:<Obj>/get and /query of the role's objects
		// only (stalwart.ViewerMethodAllowed, one list for both layers).
		if !stalwart.ViewerMethodAllowed(name) {
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

// BindAddr is the one local address to listen on: this container's
// address on the network Traefik's address is on (portcullis-proxy),
// never the template's internal network or the wildcard. None: an error
// (fail closed).
func BindAddr(traefik netip.Addr) (netip.Addr, error) {
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return netip.Addr{}, err
	}
	return bindAddrIn(ifs, traefik)
}

func bindAddrIn(addrs []net.Addr, traefik netip.Addr) (netip.Addr, error) {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		pfx, err := netip.ParsePrefix(n.String())
		if err != nil || !pfx.Addr().Is4() || pfx.Addr().IsLoopback() {
			continue
		}
		if pfx.Masked().Contains(traefik) && pfx.Addr() != traefik {
			return pfx.Addr(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("admin view: no address of this container is on Traefik's network (%s): refusing to listen", traefik)
}

// Serve runs the proxy on bind:port (Traefik's network only) and its
// health answer on 127.0.0.1:port until ctx ends.
func Serve(ctx context.Context, bind netip.Addr, port string, h http.Handler) error {
	mk := func(addr string, hh http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: hh, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second,
			WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	}
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srvs := []*http.Server{mk(net.JoinHostPort(bind.String(), port), h), mk(net.JoinHostPort("127.0.0.1", port), health)}
	errc := make(chan error, len(srvs))
	for _, s := range srvs {
		go func(s *http.Server) { errc <- s.ListenAndServe() }(s)
	}
	var err error
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range srvs {
		_ = s.Shutdown(sctx)
	}
	return err
}
