package bridge

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/portcullis/mcp-gate/internal/config"
)

// Identity injection (contract §15.5). The upstream gets only what the
// resource's identity mode defines plus the MCP transport headers the
// gate's own SDK client sets; nothing the person's client sent can reach
// it (the bridge never copies a client header, and this transport keeps an
// allowlist on top). Without the identity it never calls the upstream.

// Minter asks the Hub to mint the person's credential for a companion
// (POST /internal/credentials, §15.7; the client is task 3b). It returns
// nil when the Hub has an active entry in its file, or one of the errors
// below (wrapped is fine); anything else counts as the Hub unavailable.
type Minter interface {
	Mint(ctx context.Context, resource, user string) error
}

// Minter outcomes the bridge words for the person.
var (
	ErrNoAccount  = errors.New("no_account")  // 409 no_account: never signed in to the app
	ErrMintFailed = errors.New("mint_failed") // 502 mint_failed
	ErrNotAllowed = errors.New("not_allowed") // 403: not in the population
	// ErrRateLimited: the gate's own mints_per_minute (task 3b).
	ErrRateLimited = errors.New("rate_limited")
)

// DefaultMintWait is how long a request waits for a minted credential.
const DefaultMintWait = 20 * time.Second

// IdentityError is a refusal before the upstream is called. Reason is the
// access log's deny reason; Message is for the person; Tool says whether a
// tools/call answers it as an isError result (G26) instead of a JSON-RPC
// error.
type IdentityError struct {
	Reason, Message string
	Tool            bool
}

func (e *IdentityError) Error() string { return e.Message }

func hubUnavailable() *IdentityError {
	return &IdentityError{Reason: "hub_unavailable", Message: "can't check this right now; try again", Tool: true}
}

// Upstream request headers the gate's SDK client may set; everything else
// is dropped before the identity is added. Last-Event-ID only ever carries
// an id the upstream itself sent (SSE resumption); Mcp-Param-* are derived
// by the SDK from the already-checked arguments (SEP-2243).
var upstreamHeaders = []string{"Content-Type", "Accept", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Name", "Mcp-Session-Id", "Last-Event-Id"}

const userAgent = "portcullis-mcp-gate"

// mintGate is the single flight per (resource, user) plus the wait for the
// entry to appear in the gate's file.
type mintGate struct {
	m          Minter
	wait, poll time.Duration
	g          singleflight.Group
}

func newMintGate(m Minter, wait, poll time.Duration) *mintGate {
	if wait <= 0 {
		wait = DefaultMintWait
	}
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	return &mintGate{m: m, wait: wait, poll: poll}
}

// IdentityTransport injects the person's identity on every upstream
// request (see Transport).
type IdentityTransport struct {
	base     http.RoundTripper
	sn       func() *config.Snapshot
	url      string // the resource's URL: looked up again on every request
	upstream *url.URL
	user     string
	gate     *mintGate
	now      func() time.Time
	maxBytes int64
	tooLarge func() // called when a response exceeds maxBytes

	mu   sync.Mutex
	last http.Header // identity of the last request: only for the session's DELETE
}

// Transport returns the upstream transport for (res, user): on every
// request it re-reads the resource from the current snapshot (gone,
// changed upstream, or the person out of its population = refused), sets
// only the allowlisted transport headers and the identity mode's own, and
// strips Set-Cookie from the answer. With app_token and no active
// credential it asks mint once per (resource, user) and waits up to 20 s
// for the entry; it never calls the upstream without the identity. Share
// one Bridge (one mint gate) for the single flight across transports.
func Transport(base http.RoundTripper, sn func() *config.Snapshot, res *config.Resource, user string, mint Minter) http.RoundTripper {
	return newIdentityTransport(base, sn, res, user, newMintGate(mint, 0, 0), time.Now, 0, nil)
}

func newIdentityTransport(base http.RoundTripper, sn func() *config.Snapshot, res *config.Resource, user string, gate *mintGate, now func() time.Time, maxBytes int64, tooLarge func()) *IdentityTransport {
	u, _ := url.Parse(res.Upstream)
	return &IdentityTransport{base: base, sn: sn, url: res.URL, upstream: u, user: user, gate: gate, now: now, maxBytes: maxBytes, tooLarge: tooLarge}
}

// current is the resource as the snapshot says now, checked against what
// this transport was built for.
func (t *IdentityTransport) current() (*config.Snapshot, *config.Resource, error) {
	sn := t.sn()
	if sn == nil || sn.Err != nil || sn.Off || sn.File == nil || t.upstream == nil {
		return nil, nil, &IdentityError{Reason: "off", Message: "AI support is off on this Portcullis"}
	}
	res := lookupURL(sn, t.url)
	if res == nil || res.Kind != config.KindCompanion || res.Upstream != t.upstream.String() {
		return nil, nil, &IdentityError{Reason: "config_changed", Message: "this app's AI access changed; reconnect"}
	}
	if !res.Member(t.user, t.now()) {
		return nil, nil, &IdentityError{Reason: "population", Message: "you no longer have access to " + res.Label}
	}
	return sn, res, nil
}

// lookupURL finds a resource by its URL.
func lookupURL(sn *config.Snapshot, raw string) *config.Resource {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	res, ok := sn.Resource(u.Host, u.Path)
	if !ok || res.URL != raw {
		return nil
	}
	return res
}

// Ready makes sure the identity is there (minting and waiting if needed)
// without calling the upstream. Errors are *IdentityError.
func (t *IdentityTransport) Ready(ctx context.Context) error {
	_, err := t.identity(ctx)
	return err
}

// identity computes the identity headers, minting first if needed.
func (t *IdentityTransport) identity(ctx context.Context) (http.Header, error) {
	sn, res, err := t.current()
	if err != nil {
		return nil, err
	}
	id := res.Identity
	out := http.Header{}
	switch id.Mode {
	case "app_token":
		key := config.CredKey{Instance: res.Instance, Companion: res.Companion, User: t.user}
		cred, ok := sn.Creds[key]
		if !ok {
			if err := t.gate.await(ctx, t, res, key); err != nil {
				return nil, err
			}
			if sn, res, err = t.current(); err != nil {
				return nil, err
			}
			if cred, ok = sn.Creds[key]; !ok {
				return nil, preparing(res)
			}
			id = res.Identity
		}
		if cred.Secret == "" {
			return nil, preparing(res)
		}
		if id.BasicUser != "" && id.Format == "" {
			u := strings.ReplaceAll(id.BasicUser, "{username}", t.user)
			if strings.Contains(u, ":") {
				return nil, &IdentityError{Reason: "identity", Message: res.Label + " is not set up for AI access correctly"}
			}
			out.Set(id.Header, "Basic "+base64.StdEncoding.EncodeToString([]byte(u+":"+cred.Secret)))
		} else {
			out.Set(id.Header, strings.ReplaceAll(id.Format, "{credential}", cred.Secret))
		}
	case "identity_headers":
		secret, ok := sn.Secrets[id.SecretRef]
		if !ok || secret == "" {
			return nil, &IdentityError{Reason: "no_secret", Message: res.Label + " is not ready for AI access yet; try again in a moment"}
		}
		out.Set("X-Forwarded-User", t.user)
		if p, ok := res.People[t.user]; ok {
			if p.Email != "" {
				out.Set("X-Forwarded-Email", p.Email)
			}
			if len(p.Groups) > 0 {
				out.Set("X-Auth-Request-Groups", strings.Join(p.Groups, ","))
			}
		}
		for _, h := range sn.Attrs.Headers(res.Host, t.user) {
			out.Set(h.Name, h.Value)
		}
		// The caller secret last: it wins over any same-named header.
		out.Set(id.Header, strings.ReplaceAll(id.Format, "{secret}", secret))
	default:
		return nil, &IdentityError{Reason: "identity", Message: res.Label + " has no AI identity mode"}
	}
	return out, nil
}

func preparing(res *config.Resource) *IdentityError {
	return &IdentityError{Reason: "mint_pending", Message: "Preparing your access to " + res.Label + ", try again in a moment"}
}

// await mints once per (resource, user) and waits until the entry is in
// the file or the wait is over. Every caller waits for the shared flight
// but gives up on its own context.
func (g *mintGate) await(ctx context.Context, t *IdentityTransport, res *config.Resource, key config.CredKey) error {
	if g.m == nil {
		return preparing(res)
	}
	label, appURL := res.Label, res.AppURL
	ch := g.g.DoChan(res.URL+"\x00"+t.user, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.wait)
		defer cancel()
		if err := g.m.Mint(fctx, res.URL, t.user); err != nil {
			switch {
			case errors.Is(err, ErrNoAccount):
				return nil, &IdentityError{Reason: "no_account", Message: fmt.Sprintf("Open %s (%s) in your browser once, then try again", label, appURL)}
			case errors.Is(err, ErrMintFailed):
				return nil, &IdentityError{Reason: "mint_failed", Message: "Preparing your access to " + label + " failed; try again later"}
			case errors.Is(err, ErrNotAllowed):
				return nil, &IdentityError{Reason: "population", Message: "you don't have access to " + label}
			case errors.Is(err, ErrRateLimited):
				return nil, &IdentityError{Reason: "rate_limited", Message: "Too many requests to prepare your access to " + label + "; try again in a minute", Tool: true}
			case fctx.Err() != nil:
				return nil, &IdentityError{Reason: "mint_pending", Message: "Preparing your access to " + label + ", try again in a moment"}
			}
			return nil, hubUnavailable()
		}
		tick := time.NewTicker(g.poll)
		defer tick.Stop()
		for {
			if sn := t.sn(); sn != nil && sn.Err == nil {
				if _, ok := sn.Creds[key]; ok {
					return nil, nil
				}
			}
			select {
			case <-fctx.Done():
				return nil, &IdentityError{Reason: "mint_pending", Message: "Preparing your access to " + label + ", try again in a moment"}
			case <-tick.C:
			}
		}
	})
	select {
	case r := <-ch:
		return r.Err
	case <-ctx.Done():
		return preparing(res)
	}
}

// RoundTrip implements http.RoundTripper.
func (t *IdentityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Exactly the upstream URL: scheme, host, path (unescaped as written),
	// no query, no userinfo.
	if t.upstream == nil || req.URL.Scheme != t.upstream.Scheme || req.URL.Host != t.upstream.Host || req.URL.User != nil ||
		req.URL.Path != t.upstream.Path || req.URL.EscapedPath() != t.upstream.EscapedPath() || req.URL.RawPath != "" ||
		req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Opaque != "" {
		closeBody(req)
		return nil, &IdentityError{Reason: "upstream", Message: "refused: not this resource's upstream"}
	}
	ident, err := t.identity(req.Context())
	if err == nil {
		t.mu.Lock()
		t.last = ident
		t.mu.Unlock()
	} else if req.Method == http.MethodDelete {
		// Ending the session of a person who just left: with the identity
		// last used on it (memory only), or not at all.
		t.mu.Lock()
		ident = t.last
		t.mu.Unlock()
		if ident == nil {
			closeBody(req)
			return nil, err
		}
	} else {
		closeBody(req)
		return nil, err
	}
	out := req.Clone(req.Context())
	out.Header = http.Header{}
	for _, k := range upstreamHeaders {
		if v := req.Header.Values(k); len(v) > 0 {
			out.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
		}
	}
	for k, v := range req.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Mcp-Param-") {
			out.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
		}
	}
	for k, v := range ident {
		out.Header[k] = v
	}
	out.Header.Set("User-Agent", userAgent)
	out.Host = ""
	resp, err := t.base.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	resp.Header.Del("Set-Cookie")
	resp.Header.Del("Set-Cookie2")
	if t.maxBytes > 0 && resp.Body != nil {
		resp.Body = limitBody(resp, t.maxBytes, t.tooLarge)
	}
	return resp, nil
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

// errTooLarge ends a response that exceeds the result limit.
var errTooLarge = errors.New("result too large")

// limitBody bounds a JSON answer to max bytes in total and an SSE stream
// to max bytes per event (a long-lived stream may carry many results).
func limitBody(resp *http.Response, max int64, onExceed func()) io.ReadCloser {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(strings.TrimSpace(ct), "text/event-stream") {
		return &sseLimit{rc: resp.Body, r: bufio.NewReader(resp.Body), max: max, onExceed: onExceed}
	}
	return &totalLimit{rc: resp.Body, left: max, onExceed: onExceed}
}

type totalLimit struct {
	rc       io.ReadCloser
	left     int64
	onExceed func()
	once     sync.Once
}

func (l *totalLimit) Read(p []byte) (int, error) {
	if l.left < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > l.left+1 {
		p = p[:l.left+1]
	}
	n, err := l.rc.Read(p)
	l.left -= int64(n)
	if l.left < 0 {
		l.once.Do(func() {
			if l.onExceed != nil {
				l.onExceed()
			}
		})
		return 0, errTooLarge
	}
	return n, err
}

func (l *totalLimit) Close() error { return l.rc.Close() }

// sseLimit counts the bytes since the last blank line (an event's end).
type sseLimit struct {
	rc       io.ReadCloser
	r        *bufio.Reader
	max      int64
	cur      int64
	nl       int // consecutive line ends seen (ignoring \r)
	over     bool
	onExceed func()
}

func (l *sseLimit) Read(p []byte) (int, error) {
	if l.over {
		return 0, errTooLarge
	}
	n, err := l.r.Read(p)
	for i := 0; i < n; i++ {
		switch p[i] {
		case '\n':
			l.nl++
			if l.nl >= 2 {
				l.cur = 0
				continue
			}
		case '\r':
		default:
			l.nl = 0
		}
		l.cur++
		if l.cur > l.max {
			l.over = true
			if l.onExceed != nil {
				l.onExceed()
			}
			return 0, errTooLarge
		}
	}
	return n, err
}

func (l *sseLimit) Close() error { return l.rc.Close() }
