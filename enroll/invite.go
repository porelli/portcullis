package main

// One-time invite links: the only way a user gets a first passkey (there are
// no passwords in the browser flow).
//
//	Hub:  POST http://enroll:8444/internal/invites  (Bearer <shared secret file>,
//	      {"username"} → 201 {"url","expires_at"}; refuses admin and
//	      portcullis-hub with 409 — integration contract §9.4)
//	CLI:  portcullis invite <user> → `enroll invite <user>` in this container
//	      → POST http://127.0.0.1:8446/internal/invites (loopback, no secret:
//	      reachable only through docker exec; the one way to get a link for
//	      the bootstrap `admin`)
//	      ← https://enroll.<domain>/invite/<token>     (single use, 72 h)
//
//	GET  /invite/<token>     public page "Set up your passkey" (does NOT use the
//	                         token: link previews / scanners must not burn it)
//	POST /invite/<token>     same-origin form: adds the required action
//	                         webauthn-register-passwordless to the Keycloak user
//	                         (service account portcullis-enroll, manage-users),
//	                         then consumes the token, sets a 10-minute
//	                         redemption cookie, 303 to oauth2-proxy with
//	                         kc_idp_hint=portcullis-invite, prompt=login
//	GET  /invite/authorize   Keycloak's identity provider "portcullis-invite"
//	                         sends the browser here; with the redemption cookie
//	                         we answer with a one-time code for that user
//	POST :8445/oidc/token    Keycloak exchanges the code (client secret + PKCE)
//	GET  :8445/oidc/jwks     for an ES256 id_token: sub = preferred_username = user
//
// Keycloak links the identity to the existing LLDAP user (first broker
// login: detect existing user + auto link, never create), its post-broker
// flow marks the session LoA 2 / amr=hwk, and the required action makes the
// user register a passkey before the session exists. The browser then lands
// on the invite's landing page.
//
// Security: 256-bit tokens, stored as SHA-256 only, single use, expiry
// (default 72h, max 7d), bound to one LLDAP user, a new invite revokes the
// user's older ones; the redemption cookie is
// HttpOnly/Secure/SameSite=Lax, scoped to /invite/ and single use; codes live
// 60 s, are single use and bound to client, redirect URI, nonce and the PKCE
// challenge. All state is in memory: restarting enroll invalidates pending
// invites (issue a new one). Failed attempts are rate limited per client IP
// and every step is logged (INVITE ...; never the token or link).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	inviteIdPAlias     = "portcullis-invite"
	inviteClientID     = "keycloak"
	inviteCookie       = "portcullis_invite"
	inviteDefaultTTL   = 72 * time.Hour
	inviteMaxTTL       = 7 * 24 * time.Hour
	redemptionTTL      = 10 * time.Minute
	codeTTL            = 60 * time.Second
	idTokenTTL         = 5 * time.Minute
	inviteAPIAddr      = ":8444"          // Hub, bearer secret
	inviteLocalAddr    = "127.0.0.1:8446" // `enroll invite` via docker exec
	hubServiceAccount  = "portcullis-hub"
	bootstrapAdmin     = "admin"
	inviteFailPerMin   = 20
	inviteTokenPattern = `^[A-Za-z0-9_-]{43}$`
)

var inviteTokenRe = regexp.MustCompile(inviteTokenPattern)

type invite struct {
	User    string
	Landing string
	Expires time.Time
}

type redemption struct {
	User    string
	Landing string
	Expires time.Time
}

type authCode struct {
	User        string
	Nonce       string
	RedirectURI string
	Challenge   string
	Expires     time.Time
}

var (
	errNoUser     = errors.New("no such LLDAP user")
	errProtected  = errors.New("protected account: administrators are recovered from the server only (./portcullis invite <user>)")
	errGroupCheck = errors.New("cannot verify the user's groups in LLDAP; refusing the invite")
)

type inviteService struct {
	domain       string
	clientSecret string // Keycloak ⇄ enroll OIDC client secret
	apiSecret    string // Hub ⇄ enroll invite API bearer secret
	lookupUser   func(string) (*User, error)
	// userGroups lists the LLDAP groups of a user; protectedGroups are the
	// groups whose members only the server may invite (lldap_admin & co.).
	userGroups      func(string) ([]string, error)
	protectedGroups map[string]bool
	// requirePasskey adds webauthn-register-passwordless to the Keycloak user.
	requirePasskey func(string) error
	now            func() time.Time

	mu          sync.Mutex
	invites     map[string]*invite     // sha256(token) → invite
	redemptions map[string]*redemption // sha256(cookie) → redemption
	codes       map[string]*authCode   // sha256(code) → code
	fails       map[string][]time.Time // client IP → recent failures

	key *ecdsa.PrivateKey
	kid string
}

func newInviteService(domain, clientSecret, apiSecret string, lookupUser func(string) (*User, error), requirePasskey func(string) error) (*inviteService, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &inviteService{
		domain: domain, clientSecret: clientSecret, apiSecret: apiSecret, lookupUser: lookupUser,
		requirePasskey: requirePasskey, now: time.Now,
		invites: map[string]*invite{}, redemptions: map[string]*redemption{},
		codes: map[string]*authCode{}, fails: map[string][]time.Time{},
		key: key, kid: randomToken(9),
	}, nil
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashKey(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func (s *inviteService) issuer() string { return "https://enroll." + s.domain + "/invite" }
func (s *inviteService) redirectURI() string {
	return "https://auth." + s.domain + "/realms/portcullis/broker/" + inviteIdPAlias + "/endpoint"
}

// validLanding: https on the domain or one of its subdomains, no userinfo.
func (s *inviteService) validLanding(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == s.domain || strings.HasSuffix(h, "."+s.domain)
}

// gc drops expired state; callers hold s.mu.
func (s *inviteService) gc() {
	now := s.now()
	for k, v := range s.invites {
		if now.After(v.Expires) {
			delete(s.invites, k)
		}
	}
	for k, v := range s.redemptions {
		if now.After(v.Expires) {
			delete(s.redemptions, k)
		}
	}
	for k, v := range s.codes {
		if now.After(v.Expires) {
			delete(s.codes, k)
		}
	}
	for ip, ts := range s.fails {
		keep := ts[:0]
		for _, t := range ts {
			if now.Sub(t) < time.Minute {
				keep = append(keep, t)
			}
		}
		if len(keep) == 0 {
			delete(s.fails, ip)
		} else {
			s.fails[ip] = keep
		}
	}
}

// limited reports whether the client IP exceeded the failure budget.
func (s *inviteService) limited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	return len(s.fails[ip]) >= inviteFailPerMin
}

func (s *inviteService) fail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fails[ip] = append(s.fails[ip], s.now())
}

// Create registers a new invite and returns its token. allowAdmin is true
// only for the loopback (docker exec) path.
func (s *inviteService) Create(user, landing string, ttl time.Duration, allowAdmin bool) (string, time.Time, error) {
	if user == hubServiceAccount || (user == bootstrapAdmin && !allowAdmin) {
		return "", time.Time{}, errProtected
	}
	if !allowAdmin {
		// An invite hands over the account: whoever holds the API secret
		// must not be able to take over an administrator. Fail closed.
		if s.userGroups == nil {
			return "", time.Time{}, errGroupCheck
		}
		groups, err := s.userGroups(user)
		if err != nil {
			log.Printf("INVITE refused user=%s: group lookup: %v", user, err)
			return "", time.Time{}, errGroupCheck
		}
		for _, g := range groups {
			if s.protectedGroups[g] {
				log.Printf("INVITE refused user=%s: member of protected group %s (API)", user, g)
				return "", time.Time{}, errProtected
			}
		}
	}
	if ttl <= 0 {
		ttl = inviteDefaultTTL
	}
	if ttl > inviteMaxTTL {
		return "", time.Time{}, fmt.Errorf("ttl above %s", inviteMaxTTL)
	}
	if landing == "" {
		landing = "https://" + s.domain + "/"
	}
	if !s.validLanding(landing) {
		return "", time.Time{}, fmt.Errorf("landing URL must be https://%s or a subdomain", s.domain)
	}
	u, err := s.lookupUser(user)
	if err != nil || u == nil || u.Username != user {
		return "", time.Time{}, errNoUser
	}
	token := randomToken(32)
	exp := s.now().Add(ttl)
	s.mu.Lock()
	s.gc()
	revoked := 0
	for k, v := range s.invites {
		if v.User == u.Username {
			delete(s.invites, k)
			revoked++
		}
	}
	s.invites[hashKey(token)] = &invite{User: u.Username, Landing: landing, Expires: exp}
	s.mu.Unlock()
	log.Printf("INVITE created user=%s expires=%s landing=%s revoked=%d", u.Username, exp.UTC().Format(time.RFC3339), landing, revoked)
	return token, exp, nil
}

func (s *inviteService) peek(token string) *invite {
	if !inviteTokenRe.MatchString(token) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	if inv := s.invites[hashKey(token)]; inv != nil {
		c := *inv
		return &c
	}
	return nil
}

// consume removes the invite (single use) and returns it.
func (s *inviteService) consume(token string) *invite {
	if !inviteTokenRe.MatchString(token) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gc()
	k := hashKey(token)
	inv := s.invites[k]
	delete(s.invites, k)
	return inv
}

func clientIP(r *http.Request) string {
	// Traefik is the only peer that reaches the public port; it appends the
	// client address as the last X-Forwarded-For entry.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex")
}

func (s *inviteService) page(w http.ResponseWriter, status int, data map[string]any) {
	noStore(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	data["Domain"] = s.domain
	render(w, "invite.html", data)
}

func (s *inviteService) gone(w http.ResponseWriter, r *http.Request, why string) {
	ip := clientIP(r)
	s.fail(ip)
	log.Printf("INVITE rejected ip=%s reason=%q", ip, why) // never the token
	s.page(w, http.StatusNotFound, map[string]any{
		"Error": "This setup link is invalid, expired or already used. Ask an administrator for a new one.",
	})
}

// GET /invite/{token}
func (s *inviteService) handleShow(w http.ResponseWriter, r *http.Request) {
	if s.limited(clientIP(r)) {
		http.Error(w, "too many attempts, try again in a minute", http.StatusTooManyRequests)
		return
	}
	inv := s.peek(r.PathValue("token"))
	if inv == nil {
		s.gone(w, r, "unknown or expired token (show)")
		return
	}
	log.Printf("INVITE opened user=%s ip=%s", inv.User, clientIP(r))
	s.page(w, http.StatusOK, map[string]any{"User": inv.User, "Expires": inv.Expires.UTC().Format("2006-01-02 15:04 MST")})
}

// POST /invite/{token} — same-origin only (http.CrossOriginProtection wraps
// the mux), so a third-party page cannot log a victim into an attacker's
// invite (login CSRF).
func (s *inviteService) handleRedeem(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.limited(ip) {
		http.Error(w, "too many attempts, try again in a minute", http.StatusTooManyRequests)
		return
	}
	inv := s.peek(r.PathValue("token"))
	if inv == nil {
		s.gone(w, r, "unknown, expired or used token (redeem)")
		return
	}
	// Keycloak first: if it is down the link stays usable.
	if err := s.requirePasskey(inv.User); err != nil {
		log.Printf("INVITE redeem failed user=%s: keycloak: %v", inv.User, err)
		s.page(w, http.StatusServiceUnavailable, map[string]any{
			"Error": "The sign-in service is not reachable right now. Try the same link again in a minute.",
		})
		return
	}
	if inv = s.consume(r.PathValue("token")); inv == nil {
		s.gone(w, r, "token used concurrently (redeem)")
		return
	}
	cookie := randomToken(32)
	s.mu.Lock()
	s.redemptions[hashKey(cookie)] = &redemption{User: inv.User, Landing: inv.Landing, Expires: s.now().Add(redemptionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: inviteCookie, Value: cookie, Path: "/invite/", MaxAge: int(redemptionTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	log.Printf("INVITE redeemed user=%s ip=%s", inv.User, ip)
	q := url.Values{
		"rd":          {inv.Landing},
		"kc_idp_hint": {inviteIdPAlias},
		// Skip an SSO cookie of whoever used this browser before.
		"prompt": {"login"},
	}
	noStore(w)
	http.Redirect(w, r, "https://auth."+s.domain+"/oauth2/start?"+q.Encode(), http.StatusSeeOther)
}

// GET /invite/authorize — the OIDC authorization endpoint Keycloak's
// identity provider redirects to. Never redirects anywhere but the exact
// broker endpoint.
func (s *inviteService) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.limited(ip) {
		http.Error(w, "too many attempts, try again in a minute", http.StatusTooManyRequests)
		return
	}
	q := r.URL.Query()
	if q.Get("client_id") != inviteClientID || q.Get("redirect_uri") != s.redirectURI() ||
		q.Get("response_type") != "code" || q.Get("state") == "" ||
		q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		s.gone(w, r, "bad authorization request")
		return
	}
	c, err := r.Cookie(inviteCookie)
	if err != nil {
		s.gone(w, r, "no redemption cookie (open the setup link in this browser)")
		return
	}
	s.mu.Lock()
	s.gc()
	k := hashKey(c.Value)
	red := s.redemptions[k]
	delete(s.redemptions, k)
	var code string
	if red != nil {
		code = randomToken(32)
		s.codes[hashKey(code)] = &authCode{
			User: red.User, Nonce: q.Get("nonce"), RedirectURI: s.redirectURI(),
			Challenge: q.Get("code_challenge"), Expires: s.now().Add(codeTTL),
		}
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: inviteCookie, Value: "", Path: "/invite/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if red == nil {
		s.gone(w, r, "unknown, expired or used redemption")
		return
	}
	log.Printf("INVITE authorize user=%s ip=%s", red.User, ip)
	noStore(w)
	http.Redirect(w, r, s.redirectURI()+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
}

func oidcError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// POST /oidc/token (internal port; Keycloak only).
func (s *inviteService) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oidcError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if s.clientSecret == "" || id != inviteClientID ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(s.clientSecret)) != 1 {
		log.Printf("INVITE token rejected: client authentication failed")
		oidcError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oidcError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}
	s.mu.Lock()
	s.gc()
	k := hashKey(r.PostForm.Get("code"))
	ac := s.codes[k]
	delete(s.codes, k)
	s.mu.Unlock()
	if ac == nil || r.PostForm.Get("redirect_uri") != ac.RedirectURI {
		log.Printf("INVITE token rejected: unknown, expired or used code")
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(ac.Challenge)) != 1 {
		log.Printf("INVITE token rejected: PKCE verifier mismatch user=%s", ac.User)
		oidcError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	now := s.now()
	claims := map[string]any{
		"iss": s.issuer(), "sub": ac.User, "aud": inviteClientID,
		"iat": now.Unix(), "exp": now.Add(idTokenTTL).Unix(), "auth_time": now.Unix(),
		"preferred_username": ac.User,
	}
	if ac.Nonce != "" {
		claims["nonce"] = ac.Nonce
	}
	idt, err := s.signJWT(claims)
	if err != nil {
		oidcError(w, http.StatusInternalServerError, "server_error")
		return
	}
	log.Printf("INVITE token issued user=%s", ac.User)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": randomToken(32), "token_type": "Bearer", "expires_in": 60, "id_token": idt,
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	return append(bytes.Repeat([]byte{0}, 32-len(b)), b...)
}

func (s *inviteService) signJWT(claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": s.kid})
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(in))
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		return "", err
	}
	return in + "." + b64(append(pad32(r), pad32(sg)...)), nil
}

// GET /oidc/jwks (internal port).
func (s *inviteService) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.kid,
		"x": b64(pad32(s.key.X)), "y": b64(pad32(s.key.Y)),
	}}})
}

type inviteRequest struct {
	Username string `json:"username"`
	TTL      string `json:"ttl,omitempty"`
	Landing  string `json:"landing,omitempty"`
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// POST /internal/invites. local = the loopback listener (docker exec): no
// secret, may invite the bootstrap admin. Otherwise Bearer <apiSecret>.
func (s *inviteService) handleAPICreate(local bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !local {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if s.apiSecret == "" || got == r.Header.Get("Authorization") ||
				subtle.ConstantTimeCompare([]byte(got), []byte(s.apiSecret)) != 1 {
				log.Printf("INVITE api rejected: bad or missing bearer secret (remote=%s)", r.RemoteAddr)
				jsonError(w, http.StatusUnauthorized, "invalid invite API secret")
				return
			}
		}
		var req inviteRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "body must be JSON {\"username\": \"...\"}")
			return
		}
		var ttl time.Duration
		if req.TTL != "" {
			d, err := time.ParseDuration(req.TTL)
			if err != nil {
				jsonError(w, http.StatusBadRequest, "bad ttl")
				return
			}
			ttl = d
		}
		token, exp, err := s.Create(strings.TrimSpace(req.Username), req.Landing, ttl, local)
		switch {
		case errors.Is(err, errProtected):
			jsonError(w, http.StatusConflict, err.Error())
			return
		case errors.Is(err, errNoUser):
			jsonError(w, http.StatusNotFound, err.Error())
			return
		case errors.Is(err, errGroupCheck):
			jsonError(w, http.StatusServiceUnavailable, err.Error())
			return
		case err != nil:
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"url": "https://enroll." + s.domain + "/invite/" + token, "expires_at": exp.UTC().Format(time.RFC3339),
		})
	}
}

func (s *inviteService) register(public *http.ServeMux) {
	public.HandleFunc("GET /invite/authorize", s.handleAuthorize)
	public.HandleFunc("GET /invite/{token}", s.handleShow)
	public.HandleFunc("POST /invite/{token}", s.handleRedeem)
}

func (s *inviteService) internalHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /oidc/token", s.handleToken)
	m.HandleFunc("GET /oidc/jwks", s.handleJWKS)
	return m
}

func (s *inviteService) apiHandler(local bool) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /internal/invites", s.handleAPICreate(local))
	return m
}

// runInviteCommand implements `enroll invite <user> [-ttl 24h] [-landing URL]`:
// asks the running server (same container, loopback) for an invite and prints
// the JSON answer.
func runInviteCommand(args []string) int {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	ttl := fs.String("ttl", "", "lifetime (Go duration, default 72h, max 168h)")
	landing := fs.String("landing", "", "https URL to land on after the passkey registration (default https://<domain>/)")
	// Accept the user before or after the flags.
	var user string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		user, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if user == "" && fs.NArg() == 1 {
		user = fs.Arg(0)
	} else if fs.NArg() != 0 || user == "" {
		fmt.Fprintln(os.Stderr, "usage: enroll invite <user> [-ttl 24h] [-landing https://...]")
		return 2
	}
	body, _ := json.Marshal(inviteRequest{Username: user, TTL: *ttl, Landing: *landing})
	resp, err := http.Post("http://"+inviteLocalAddr+"/internal/invites", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "enroll is not running in this container:", err)
		return 1
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Fprintf(os.Stderr, "invite refused: %s", out)
		return 1
	}
	os.Stdout.Write(out)
	return 0
}

var errNoSecret = errors.New("invite client secret not configured")

func readInviteSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 32 {
		return "", errNoSecret
	}
	return s, nil
}

// protectedGroupSet: lldap_admin, lldap_password_manager, INVITE_PROTECTED_GROUPS
// (space/comma separated) and the groups of the core subdomains in
// group-gate-map.conf (consoles), if the file is readable.
func protectedGroupSet(extra, mapFile string) map[string]bool {
	set := map[string]bool{"lldap_admin": true, "lldap_password_manager": true}
	for _, g := range strings.FieldsFunc(extra, func(r rune) bool { return r == ',' || r == ' ' }) {
		set[g] = true
	}
	core := map[string]bool{"auth": true, "traefik": true, "hub": true, "directory": true, "enroll": true, "metrics": true}
	if b, err := os.ReadFile(mapFile); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if ok && core[strings.ToLower(strings.TrimSpace(k))] && strings.TrimSpace(v) != "" {
				set[strings.TrimSpace(v)] = true
			}
		}
	}
	return set
}
