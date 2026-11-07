// Package portcullis forwards the Portcullis MCP resources (integration
// contract §15.7, §15.10): hub.<d>/mcp to the Hub's /mcp/admin and
// people.<d>/mcp to /mcp/people, on the Hub's MCP listener
// (MCP_GATE_HUB_URL), never to a URL from the gate file. The Hub learns
// the person from exactly four headers the gate sets, replacing anything
// the client sent: X-Portcullis-MCP-Secret, X-Forwarded-User,
// X-Portcullis-AI-Client and X-Portcullis-AI-Resource.
//
// The pipeline in front (authz, Origin, protocol and header checks on the
// parsed body, limits including tools/call, body caps, one access-log line
// per request: G25) is the gate handler's, as for a companion; this
// package only forwards. People is the aggregate's SDK client to
// /mcp/people with the same headers (task 5).
package portcullis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/config"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// Paths on the Hub's MCP listener (§15.7).
const (
	AdminPath  = "/mcp/admin"
	PeoplePath = "/mcp/people"
)

// The identity headers of §15.7.
const (
	HeaderSecret   = "X-Portcullis-MCP-Secret"
	HeaderUser     = "X-Forwarded-User"
	HeaderClient   = "X-Portcullis-AI-Client"
	HeaderResource = "X-Portcullis-AI-Resource"
)

const minSecretChars = 32

// idleTimeout closes pooled people sessions nobody used for this long.
const idleTimeout = 10 * time.Minute

// requestHeaders are the client's headers that reach the Hub (§15.5's
// list for upstreams; Mcp-Param-* only from the SDK client of the
// aggregate's people path, never the client's). Everything else is dropped: the
// person's token, cookies, every X-Forwarded-*, X-Auth-Request-*, Remote-*
// and X-Portcullis-* header.
var requestHeaders = []string{"Content-Type", "Accept", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Mcp-Session-Id"}

// answerHeaders are the Hub's answer headers that reach the client.
var answerHeaders = []string{"Content-Type", "Mcp-Session-Id", "Mcp-Protocol-Version", "Cache-Control"}

// Hub forwards to the Hub's MCP listener.
type Hub struct {
	base   *url.URL
	secret string
	hc     *http.Client
	// maxResult bounds an answer's body (§15.9, 16 MiB); timeout one
	// request (120 s).
	maxResult int64
	timeout   time.Duration

	mu       sync.Mutex
	sessions map[skey]*session
	closed   bool
}

type skey struct{ user, client, resource string }

type session struct {
	cs      *mcp.ClientSession
	lastUse time.Time
}

// New: hubURL is http(s)://host[:port] (no path, query, userinfo or
// fragment), secret the shared secret (≥ 32 printable characters). base
// nil = no proxy, a 5 s dial, no compression; redirects are never
// followed.
func New(hubURL, secret string, base http.RoundTripper) (*Hub, error) {
	u, err := url.Parse(hubURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("portcullis: the Hub URL must be http(s)://host[:port]")
	}
	u.Path = ""
	if len(secret) < minSecretChars || strings.ContainsFunc(secret, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return nil, fmt.Errorf("portcullis: the Hub secret must be at least %d printable characters", minSecretChars)
	}
	if base == nil {
		base = &http.Transport{
			Proxy:              nil,
			DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			DisableCompression: true,
			MaxIdleConns:       50,
			IdleConnTimeout:    90 * time.Second,
		}
	}
	return &Hub{
		base: u, secret: secret,
		hc: &http.Client{
			Transport:     base,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		maxResult: config.FixedMaxResultBytes,
		timeout:   config.FixedUpstreamTimeoutS * time.Second,
		sessions:  map[skey]*session{},
	}, nil
}

// Proxy is New + Serve as a handler (the brief's interface). A Hub URL or
// secret New refuses makes every request a 503.
func Proxy(hubURL, secret string) func(w http.ResponseWriter, r *http.Request, d authz.Decision) {
	h, err := New(hubURL, secret, nil)
	if err != nil {
		log.Printf("mcp-gate: %v", err)
		return func(w http.ResponseWriter, _ *http.Request, _ authz.Decision) {
			http.Error(w, "Portcullis MCP is unavailable", http.StatusServiceUnavailable)
		}
	}
	return func(w http.ResponseWriter, r *http.Request, d authz.Decision) { h.Serve(w, r, d) }
}

// pathFor is the Hub path of a Portcullis resource; "" for any other kind.
func pathFor(res *config.Resource) string {
	if res == nil {
		return ""
	}
	switch res.Kind {
	case config.KindAdmin:
		return AdminPath
	case config.KindPeople:
		return PeoplePath
	}
	return ""
}

// identity sets the four headers of §15.7 on h (replacing any value).
func (h *Hub) identity(hd http.Header, user, client, resource string) {
	hd.Set(HeaderSecret, h.secret)
	hd.Set(HeaderUser, user)
	hd.Set(HeaderClient, client)
	hd.Set(HeaderResource, resource)
}

// Serve forwards one allowed request of a Portcullis resource and returns
// the Hub's HTTP status (0 when the Hub didn't answer). The request body is
// the one the handler read and checked.
func (h *Hub) Serve(w http.ResponseWriter, r *http.Request, d authz.Decision) int {
	if !d.Allowed() || d.User == "" || d.Resource == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return 0
	}
	path := pathFor(d.Resource)
	if path == "" {
		http.Error(w, "MCP forwarding is not available for this resource", http.StatusServiceUnavailable)
		return 0
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	u := *h.base
	u.Path = path
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), r.Body)
	if err != nil {
		http.Error(w, "Portcullis is unavailable right now", http.StatusBadGateway)
		return 0
	}
	out.ContentLength = r.ContentLength
	for _, k := range requestHeaders {
		if v := r.Header.Values(k); len(v) > 0 {
			out.Header[k] = append([]string(nil), v...)
		}
	}
	// Never the client's Mcp-Param-* (§15.5: those are built from the
	// checked arguments; the Hub decides on the body, final review M3).
	out.Header.Set("User-Agent", "portcullis-mcp-gate")
	h.identity(out.Header, d.User, d.Client, d.Resource.URL)
	resp, err := h.hc.Do(out)
	if err != nil {
		log.Printf("mcp-gate: %s %s user=%q: Hub error: %v", r.Method, path, d.User, err)
		http.Error(w, "Portcullis is unavailable right now", http.StatusBadGateway)
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		http.Error(w, "Portcullis is unavailable right now", http.StatusBadGateway)
		return resp.StatusCode
	}
	if resp.ContentLength > h.maxResult {
		http.Error(w, "result too large", http.StatusBadGateway)
		return resp.StatusCode
	}
	for _, k := range answerHeaders {
		if v := resp.Header.Values(k); len(v) > 0 {
			w.Header()[k] = append([]string(nil), v...)
		}
	}
	w.Header().Del("Set-Cookie")
	w.WriteHeader(resp.StatusCode)
	copyBounded(w, resp.Body, h.maxResult)
	return resp.StatusCode
}

// copyBounded streams at most max bytes, flushing as it goes (SSE).
func copyBounded(w http.ResponseWriter, body io.Reader, max int64) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, err := body.Read(buf)
		if k > 0 {
			if n+int64(k) > max {
				_, _ = w.Write(buf[:max-n])
				return // the answer is cut: the client sees a broken stream
			}
			n += int64(k)
			if _, werr := w.Write(buf[:k]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// ---- the aggregate's people sessions ----

// headerRT: the SDK client's requests to /mcp/people, with only the MCP
// headers the SDK set plus the four identity headers; Set-Cookie dropped,
// answers bounded.
type headerRT struct {
	h                      *Hub
	user, client, resource string
}

func (t *headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	u := *t.h.base
	u.Path = PeoplePath
	if r.URL.String() != u.String() {
		return nil, errors.New("portcullis: unexpected Hub URL")
	}
	out := r.Clone(r.Context())
	out.Header = http.Header{}
	for _, k := range append(requestHeaders, "Last-Event-Id") {
		if v := r.Header.Values(k); len(v) > 0 {
			out.Header[k] = append([]string(nil), v...)
		}
	}
	for k, v := range r.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Mcp-Param-") {
			out.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
		}
	}
	out.Header.Set("User-Agent", "portcullis-mcp-gate")
	t.h.identity(out.Header, t.user, t.client, t.resource)
	resp, err := t.h.hc.Transport.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	resp.Header.Del("Set-Cookie")
	resp.Header.Del("Set-Cookie2")
	if resp.ContentLength > t.h.maxResult {
		resp.Body.Close()
		return nil, errors.New("result too large")
	}
	resp.Body = &limitedBody{rc: resp.Body, left: t.h.maxResult}
	return resp, nil
}

type limitedBody struct {
	rc   io.ReadCloser
	left int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("result too large")
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.rc.Read(p)
	l.left -= int64(n)
	return n, err
}

func (l *limitedBody) Close() error { return l.rc.Close() }

// People is the person's SDK client session to /mcp/people, pooled per
// (person, client, resource). resource must be a people resource URL
// (https://people.<d>/mcp); anything else is refused. The client declares
// no capability (no sampling, roots or elicitation): the Hub answers its
// text forms, and nothing the Hub sends can drive the person's model.
func (h *Hub) People(ctx context.Context, user, client, resource string) (*mcp.ClientSession, error) {
	ru, err := url.Parse(resource)
	if err != nil || ru.Scheme != "https" || !strings.HasPrefix(ru.Host, "people.") || ru.Path != "/mcp" {
		return nil, errors.New("portcullis: not a people resource")
	}
	if user == "" {
		return nil, errors.New("portcullis: no person")
	}
	k := skey{user: user, client: client, resource: resource}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, errors.New("portcullis: closed")
	}
	if s := h.sessions[k]; s != nil {
		s.lastUse = time.Now()
		h.mu.Unlock()
		return s.cs, nil
	}
	h.sweepLocked()
	h.mu.Unlock()

	u := *h.base
	u.Path = PeoplePath
	c := mcp.NewClient(&mcp.Implementation{Name: "portcullis-mcp-gate", Version: "1"}, &mcp.ClientOptions{
		Capabilities:   &mcp.ClientCapabilities{},
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	tr := &mcp.StreamableClientTransport{
		Endpoint: u.String(),
		HTTPClient: &http.Client{
			Transport:     &headerRT{h: h, user: user, client: client, resource: resource},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		MaxRetries:   -1,
		MaxEventSize: int(h.maxResult) + 1<<20,
	}
	cctx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	cs, err := c.Connect(cctx, tr, &mcp.ClientSessionOptions{ProtocolVersion: mcp.ProtocolStateless})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		_ = cs.Close()
		return nil, errors.New("portcullis: closed")
	}
	if s := h.sessions[k]; s != nil { // a concurrent connect won
		go cs.Close()
		return s.cs, nil
	}
	h.sessions[k] = &session{cs: cs, lastUse: time.Now()}
	return cs, nil
}

// Broken forgets a session that failed, so the next People reconnects.
func (h *Hub) Broken(user string, cs *mcp.ClientSession) {
	h.mu.Lock()
	for k, s := range h.sessions {
		if k.user == user && s.cs == cs {
			delete(h.sessions, k)
		}
	}
	h.mu.Unlock()
	go cs.Close()
}

func (h *Hub) sweepLocked() {
	now := time.Now()
	for k, s := range h.sessions {
		if now.Sub(s.lastUse) > idleTimeout {
			delete(h.sessions, k)
			go s.cs.Close()
		}
	}
}

// DropClient closes the person's people sessions of one AI client.
func (h *Hub) DropClient(user, client string) {
	h.drop(func(k skey) bool { return k.user == user && k.client == client })
}

// DropUser closes the person's people sessions.
func (h *Hub) DropUser(user string) {
	h.drop(func(k skey) bool { return k.user == user })
}

func (h *Hub) drop(match func(skey) bool) {
	h.mu.Lock()
	var gone []*mcp.ClientSession
	for k, s := range h.sessions {
		if match(k) {
			gone = append(gone, s.cs)
			delete(h.sessions, k)
		}
	}
	h.mu.Unlock()
	for _, cs := range gone {
		_ = cs.Close()
	}
}

// Close closes every session.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	var gone []*mcp.ClientSession
	for k, s := range h.sessions {
		gone = append(gone, s.cs)
		delete(h.sessions, k)
	}
	h.mu.Unlock()
	for _, cs := range gone {
		_ = cs.Close()
	}
}
