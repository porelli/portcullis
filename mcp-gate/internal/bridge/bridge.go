// Package bridge is the gate's per-app MCP endpoint (integration contract
// §15.5, plan 4 task 3a): an SDK server facing the person's client, built
// per (person, resource), forwarding tools, resources and prompts to an SDK
// client session on the companion's upstream, with the person's identity
// injected (identity.go) and the template's tool policy applied
// (policy.go). Nothing the client sends is copied upstream: the upstream
// request is the gate's own SDK client's.
//
// Config.OnEvent receives one Event per forwarded MCP request (the access
// log, task 3b), Config.Minter is the Hub API's mint, Config.Confirm
// decides calls that need a confirmation. Limits, the unloggable-call
// refusal (G28) and the lines of requests that never reach forward are the
// handler's, in front of ServeResource (main.go, gate.go).
package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/canon"
	"github.com/portcullis/mcp-gate/internal/config"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// DefaultIdleTimeout closes idle sessions (downstream and pooled upstream).
const DefaultIdleTimeout = 10 * time.Minute

// Event is one MCP request (or a refused server-to-client request) for the
// access log (§15.8). Args is the raw tools/call arguments, for hashing
// only (args_sha256): it is never to be written anywhere. RequestID is the
// gate's id of the HTTP request (RequestIDHeader), empty for events
// outside one.
type Event struct {
	User, Client, Resource, Instance, Companion, Via, Method, Tool, Decision string
	RequestID                                                                string
	Args                                                                     json.RawMessage
	UpstreamStatus                                                           int
	Duration                                                                 time.Duration
}

// RequestIDHeader carries the gate's own id of an HTTP request from the
// handler to the events of that request (the access log writes exactly
// one line per request). The handler always overwrites it; the upstream
// never gets it (identity.go's header allowlist).
const RequestIDHeader = "X-Portcullis-Gate-Request"

// requestID is the gate's id of the HTTP request carrying req.
func requestID(req mcp.Request) string {
	if ex := req.GetExtra(); ex != nil && ex.Header != nil {
		return ex.Header.Get(RequestIDHeader)
	}
	return ""
}

// Call is a tools/call that needs a confirmation (§15.6).
type Call struct {
	User, Client string
	Resource     *config.Resource
	Tool         string
	Args         json.RawMessage
	Reason       string // "confirm" (a confirm pattern) or "destructive" (the annotation)
}

// Outcome is a Confirmer's decision. Proceed is true only when a matching
// approved confirmation was consumed; else Answer is what the person's
// client gets and Decision the access log's (confirm:<id>, rate_limited,
// deny:<reason>; empty = "confirm").
type Outcome struct {
	Proceed  bool
	Answer   *mcp.CallToolResult
	Decision string
}

// Confirmer decides calls that need a confirmation (§15.6; internal/confirm).
// An error fails closed: "can't check this right now", the upstream never
// called (G26).
type Confirmer interface {
	Before(ctx context.Context, c Call) (Outcome, error)
}

// Config configures a Bridge.
type Config struct {
	Snapshot func() *config.Snapshot
	Minter   Minter
	// Base is the upstream transport; nil = no proxy, 5 s dial, no
	// compression. Redirects are never followed.
	Base    http.RoundTripper
	OnEvent func(Event)
	Confirm Confirmer
	// MintWait (20 s), MintPoll (250 ms), IdleTimeout (10 min); tests set
	// them shorter.
	MintWait, MintPoll, IdleTimeout time.Duration
	// UpstreamTimeout / MaxResultBytes override the file's limits (tests).
	UpstreamTimeout time.Duration
	MaxResultBytes  int64
	Now             func() time.Time
}

type key struct{ user, url string }

// entry is the per-(person, resource) SDK server and its session handler.
type entry struct {
	server  *mcp.Server
	handler http.Handler
}

// Bridge serves companion resources.
type Bridge struct {
	cfg       Config
	base      http.RoundTripper
	gate      *mintGate
	stateless http.Handler

	mu       sync.Mutex
	entries  map[key]*entry
	pooled   map[key]*link                // sessionless clients + Upstream
	sessions map[*mcp.ServerSession]*link // one per downstream session
	owners   map[*mcp.ServerSession]key   // for DropUser
	order    map[key][]*mcp.ServerSession // live downstream sessions per key, oldest first
	lastSn   *config.Snapshot
	warned   sync.Map
	stop     chan struct{}
	stopOnce sync.Once
}

// New builds a Bridge; Run (or Reconcile on every snapshot change) keeps
// its sessions in line with the populations.
func New(cfg Config) *Bridge {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	b := &Bridge{
		cfg:      cfg,
		base:     cfg.Base,
		gate:     newMintGate(cfg.Minter, cfg.MintWait, cfg.MintPoll),
		entries:  map[key]*entry{},
		pooled:   map[key]*link{},
		sessions: map[*mcp.ServerSession]*link{},
		owners:   map[*mcp.ServerSession]key{},
		order:    map[key][]*mcp.ServerSession{},
		stop:     make(chan struct{}),
	}
	if b.base == nil {
		b.base = &http.Transport{
			Proxy:              nil,
			DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			DisableCompression: true,
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
		}
	}
	h := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		id, ok := r.Context().Value(identKey{}).(ident)
		if !ok {
			return nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if e := b.entries[id.key]; e != nil {
			return e.server
		}
		return nil
	}, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		DisableLocalhostProtection: true, // the Host is the resource's; authz checked it
		MaxRequestBodyBytes:        config.FixedMaxRequestBytes,
	})
	b.stateless = mcp.RequireBearerToken(verifier, nil)(h)
	return b
}

func (b *Bridge) now() time.Time { return b.cfg.Now() }

func (b *Bridge) emit(e Event) {
	if b.cfg.OnEvent != nil {
		b.cfg.OnEvent(e)
	}
}

func (b *Bridge) limits() config.Limits {
	if sn := b.cfg.Snapshot(); sn != nil && sn.File != nil {
		return sn.File.Limits
	}
	return config.Limits{MaxRequestBytes: config.FixedMaxRequestBytes, MaxResultBytes: config.FixedMaxResultBytes, UpstreamTimeoutS: config.FixedUpstreamTimeoutS}
}

func (b *Bridge) timeout() time.Duration {
	if b.cfg.UpstreamTimeout > 0 {
		return b.cfg.UpstreamTimeout
	}
	if s := b.limits().UpstreamTimeoutS; s > 0 {
		return time.Duration(s) * time.Second
	}
	return config.FixedUpstreamTimeoutS * time.Second
}

func (b *Bridge) maxResult() int64 {
	if b.cfg.MaxResultBytes > 0 {
		return b.cfg.MaxResultBytes
	}
	if m := b.limits().MaxResultBytes; m > 0 {
		return m
	}
	return config.FixedMaxResultBytes
}

// ---- the per-request identity, carried from ServeResource to the server ----

type identKey struct{}

type ident struct {
	key
	client string
}

// verifier hands the SDK the identity ServeResource put in the request's
// context (authz has checked the token itself): the SDK binds sessions to
// UserID and passes TokenInfo to every request of the session.
func verifier(ctx context.Context, _ string, _ *http.Request) (*mcp.TokenInfo, error) {
	id, ok := ctx.Value(identKey{}).(ident)
	if !ok || id.user == "" {
		return nil, errors.New("no identity")
	}
	return &mcp.TokenInfo{
		UserID:     id.user + "\x00" + id.url,
		Expiration: time.Now().Add(time.Hour),
		Extra:      map[string]any{"client": id.client},
	}, nil
}

// noCookie drops any Set-Cookie on the way out (nothing on an MCP route
// sets a cookie, §15.5).
type noCookie struct{ http.ResponseWriter }

func (n noCookie) WriteHeader(code int) {
	n.Header().Del("Set-Cookie")
	n.ResponseWriter.WriteHeader(code)
}

func (n noCookie) Write(b []byte) (int, error) {
	n.Header().Del("Set-Cookie")
	return n.ResponseWriter.Write(b)
}

func (n noCookie) Flush() {
	if f, ok := n.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (n noCookie) Unwrap() http.ResponseWriter { return n.ResponseWriter }

// ServeResource serves one HTTP request of a companion resource that authz
// allowed (d). It re-checks the resource and the person against the
// current snapshot (fail closed), then hands the request to the person's
// own SDK server: sessions are per (person, resource), so another person's
// session id is unknown here (404). 2026-07-28 requests are sessionless.
func (b *Bridge) ServeResource(w http.ResponseWriter, r *http.Request, d authz.Decision) {
	w = noCookie{w}
	if !d.Allowed() || d.Resource == nil || d.User == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sn := b.cfg.Snapshot()
	if sn == nil || sn.Err != nil || sn.Off || sn.File == nil {
		http.Error(w, "AI support is off on this Portcullis", http.StatusServiceUnavailable)
		return
	}
	res := lookupURL(sn, d.Resource.URL)
	if res == nil || res.Kind != config.KindCompanion {
		http.Error(w, "MCP forwarding is not available for this resource", http.StatusServiceUnavailable)
		return
	}
	if !res.Member(d.User, b.now()) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	k := key{user: d.User, url: res.URL}
	e := b.entryFor(k, res)
	r = r.WithContext(context.WithValue(r.Context(), identKey{}, ident{key: k, client: d.Client}))
	if r.Header.Get("Mcp-Protocol-Version") >= mcp.ProtocolStateless {
		b.stateless.ServeHTTP(w, r)
		return
	}
	e.handler.ServeHTTP(w, r)
}

func (b *Bridge) entryFor(k key, res *config.Resource) *entry {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.entries[k]; e != nil {
		return e
	}
	s := mcp.NewServer(&mcp.Implementation{Name: "portcullis-mcp-gate", Title: res.Label + " on Portcullis", Version: "1"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolCapabilities{}, Resources: &mcp.ResourceCapabilities{}, Prompts: &mcp.PromptCapabilities{},
		},
		SupportedProtocolVersions: config.SupportedProtocols, // G18
	})
	s.AddReceivingMiddleware(b.middleware(k))
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{
		DisableLocalhostProtection: true,
		SessionTimeout:             b.cfg.IdleTimeout,
		MaxRequestBodyBytes:        config.FixedMaxRequestBytes,
	})
	e := &entry{server: s, handler: mcp.RequireBearerToken(verifier, nil)(h)}
	b.entries[k] = e
	return e
}

// ---- links ----

// linkFor is the downstream session's own link, or the pooled one.
func (b *Bridge) linkFor(k key, res *config.Resource, ss *mcp.ServerSession) *link {
	b.mu.Lock()
	defer b.mu.Unlock()
	fp := fingerprint(res)
	if ss != nil && ss.ID() != "" {
		if l := b.sessions[ss]; l != nil && !l.isClosed() && l.fp == fp {
			return l
		} else if l != nil {
			go l.close()
		}
		l := b.newLink(k, res, ss)
		b.sessions[ss] = l
		if victims := b.trackLocked(k, ss); len(victims) > 0 {
			go b.evict(victims)
		}
		return l
	}
	if l := b.pooled[k]; l != nil && !l.isClosed() && l.fp == fp {
		return l
	} else if l != nil {
		go l.close()
	}
	l := b.newLink(k, res, nil)
	b.pooled[k] = l
	return l
}

// Upstream is the pooled upstream session of (user, res) (the aggregate's
// way in, task 5). The caller re-checks the population itself; the
// transport refuses a non-member anyway. client is the azp, for the log.
func (b *Bridge) Upstream(ctx context.Context, user, client string, res *config.Resource) (*mcp.ClientSession, error) {
	sn := b.cfg.Snapshot()
	if sn == nil || sn.Err != nil || sn.File == nil || res == nil {
		return nil, errors.New("AI support is off on this Portcullis")
	}
	cur := lookupURL(sn, res.URL)
	if cur == nil || cur.Kind != config.KindCompanion || !cur.Member(user, b.now()) {
		return nil, errors.New("not allowed")
	}
	l := b.linkFor(key{user: user, url: cur.URL}, cur, nil)
	uctx, cancel := detach(ctx)
	defer cancel()
	return l.session(uctx)
}

// livePooled counts a person's live upstream links (tests).
func (b *Bridge) livePooled(user string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for k, l := range b.pooled {
		if k.user == user && !l.isClosed() {
			n++
		}
	}
	for _, l := range b.sessions {
		if l.key.user == user && !l.isClosed() {
			n++
		}
	}
	return n
}

// DropUser closes all of the person's sessions: pooled upstream sessions,
// downstream sessions and their upstream sessions.
func (b *Bridge) DropUser(user string) {
	b.drop(func(k key) bool { return k.user == user })
}

func (b *Bridge) drop(match func(key) bool) {
	var links []*link
	var downs []*mcp.ServerSession
	b.mu.Lock()
	for k, l := range b.pooled {
		if match(k) {
			links = append(links, l)
			delete(b.pooled, k)
		}
	}
	for ss, l := range b.sessions {
		if match(l.key) {
			links = append(links, l)
			delete(b.sessions, ss)
		}
	}
	for ss, k := range b.owners {
		if match(k) {
			downs = append(downs, ss)
		}
	}
	for k, e := range b.entries {
		if match(k) {
			for ss := range e.server.Sessions() {
				downs = append(downs, ss)
			}
			delete(b.entries, k)
		}
	}
	b.mu.Unlock()
	for _, l := range links {
		l.close()
	}
	for _, ss := range downs {
		_ = ss.Close()
	}
}

// Reconcile compares every session with the current snapshot: a person no
// longer in the population (or past their expiring time), a resource gone
// or no longer a companion, or one whose upstream or identity changed,
// closes the sessions concerned (Review Focus 1). Idle pooled links go too.
func (b *Bridge) Reconcile() {
	sn := b.cfg.Snapshot()
	now := b.now()
	gone := func(k key) bool {
		if sn == nil || sn.Err != nil || sn.Off || sn.File == nil {
			return true
		}
		res := lookupURL(sn, k.url)
		return res == nil || res.Kind != config.KindCompanion || !res.Member(k.user, now)
	}
	b.mu.Lock()
	b.lastSn = sn
	var stale []*link
	for k, l := range b.pooled {
		if gone(k) {
			continue // dropped below
		}
		res := lookupURL(sn, k.url)
		l.mu.Lock()
		idle := len(l.active) == 0 && now.Sub(l.lastUse) > b.cfg.IdleTimeout
		l.mu.Unlock()
		if idle || l.fp != fingerprint(res) {
			stale = append(stale, l)
			delete(b.pooled, k)
		}
	}
	for ss, l := range b.sessions {
		if !gone(l.key) && l.fp != fingerprint(lookupURL(sn, l.key.url)) {
			stale = append(stale, l)
			delete(b.sessions, ss)
		}
	}
	b.mu.Unlock()
	for _, l := range stale {
		l.close()
	}
	b.drop(gone)
}

// Run reconciles on every snapshot change (the store polls every second)
// and once a minute for expiries and idle sessions, until Close.
func (b *Bridge) Run() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := time.Time{}
	for {
		select {
		case <-b.stop:
			return
		case <-tick.C:
		}
		b.mu.Lock()
		changed := b.cfg.Snapshot() != b.lastSn
		b.mu.Unlock()
		if changed || b.now().Sub(last) > time.Minute {
			b.Reconcile()
			last = b.now()
		}
	}
}

// Close stops Run and closes every session.
func (b *Bridge) Close() {
	b.stopOnce.Do(func() { close(b.stop) })
	b.drop(func(key) bool { return true })
}

// ---- the server side: forwarding with policy ----

func (b *Bridge) middleware(k key) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case mcp.MethodListTools, mcp.MethodCallTool, mcp.MethodListResources, mcp.MethodListResourceTemplates,
				mcp.MethodReadResource, mcp.MethodListPrompts, mcp.MethodGetPrompt:
				return b.forward(ctx, k, method, req)
			case mcp.MethodComplete, mcp.MethodSubscribe, mcp.MethodUnsubscribe:
				return nil, &mcp.RPCError{Code: mcp.CodeMethodNotFound, Message: "not supported through Portcullis"}
			case mcp.MethodInitialize:
				res, err := next(ctx, method, req)
				if ss, ok := req.GetSession().(*mcp.ServerSession); err == nil && ok && ss.ID() != "" {
					// At most maxSessionsPerKey live sessions per (person,
					// resource): a new one evicts the oldest.
					b.mu.Lock()
					victims := b.trackLocked(k, ss)
					b.mu.Unlock()
					b.evict(victims)
				}
				return res, err
			}
			return next(ctx, method, req) // initialize, ping, discover, notifications
		}
	}
}

func clientOf(req mcp.Request) string {
	if ex := req.GetExtra(); ex != nil && ex.TokenInfo != nil {
		if c, ok := ex.TokenInfo.Extra["client"].(string); ok {
			return c
		}
	}
	return ""
}

// rpcError is a JSON-RPC error with a clipped message.
func rpcError(code int64, msg string) *mcp.RPCError {
	return &mcp.RPCError{Code: code, Message: clip(msg, 1024)}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func isErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

func (b *Bridge) forward(ctx context.Context, k key, method string, req mcp.Request) (res mcp.Result, err error) {
	start := b.now()
	ev := Event{User: k.user, Client: clientOf(req), Resource: k.url, Via: "direct", Method: method, Decision: "allow", RequestID: requestID(req)}
	if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && p != nil {
		ev.Tool, ev.Args = p.Name, p.Arguments
	}
	defer func() {
		ev.Duration = b.now().Sub(start)
		b.emit(ev)
	}()
	// The session's TokenInfo is bound to this key by the SDK; check it.
	if ex := req.GetExtra(); ex == nil || ex.TokenInfo == nil || ex.TokenInfo.UserID != k.user+"\x00"+k.url {
		ev.Decision = "deny:token"
		return nil, rpcError(mcp.CodeInvalidParams, "not allowed")
	}
	sn := b.cfg.Snapshot()
	var r *config.Resource
	if sn != nil && sn.Err == nil && !sn.Off && sn.File != nil {
		r = lookupURL(sn, k.url)
	}
	if r == nil || r.Kind != config.KindCompanion {
		ev.Decision = "deny:off"
		return nil, rpcError(mcp.CodeInternalError, "AI support for this app is off")
	}
	ev.Instance, ev.Companion = r.Instance, r.Companion
	if !r.Member(k.user, b.now()) {
		ev.Decision = "deny:population"
		return nil, rpcError(mcp.CodeInvalidParams, "you no longer have access to "+r.Label)
	}
	ss, _ := req.GetSession().(*mcp.ServerSession)
	l := b.linkFor(k, r, ss)
	leave := l.enter(ctx)
	defer leave()

	// Policy first for tools/call: a refused call never needs the upstream.
	var call *mcp.CallToolParamsRaw
	if method == mcp.MethodCallTool {
		call, _ = req.GetParams().(*mcp.CallToolParamsRaw)
		if call == nil {
			ev.Decision = "deny:bad_arguments"
			return nil, rpcError(mcp.CodeInvalidParams, "missing params")
		}
		if len(call.InputResponses) > maxInputRequests {
			ev.Decision = "deny:too_many_inputs"
			return nil, rpcError(mcp.CodeInvalidParams, "too many input responses")
		}
		for _, ir := range call.InputResponses {
			if _, ok := ir.(*mcp.ElicitResult); !ok {
				ev.Decision = "deny:sampling"
				return nil, rpcError(mcp.CodeInvalidParams, "Portcullis passes only elicitation answers to "+r.Label)
			}
		}
		// The one form of the arguments from here on (security review):
		// the canonical bytes are what is checked, hashed, confirmed,
		// logged and forwarded. Arguments that can't round-trip are
		// refused.
		c, cerr := canon.Arguments(call.Arguments)
		if cerr != nil {
			ev.Decision = "deny:bad_arguments"
			return nil, rpcError(mcp.CodeInvalidParams, refusal("bad_arguments", call.Name, r.Label))
		}
		cp := *call
		cp.Arguments = c
		call = &cp
		ev.Args = c
		allow, _, reason := CallDecision(r, call.Name, call.Arguments, nil)
		if !allow {
			ev.Decision = "deny:" + reason
			return nil, rpcError(mcp.CodeInvalidParams, refusal(reason, call.Name, r.Label))
		}
	}

	// Upstream calls get a context with the downstream's cancellation but
	// none of its values: the SDK keeps per-request protocol state in
	// context values, which must not cross from the server to the client.
	uctx, ucancel := detach(ctx)
	defer ucancel()
	cs, err := l.session(uctx)
	if err != nil {
		return b.failure(&ev, method, r, l, nil, err)
	}
	ev.UpstreamStatus = http.StatusOK
	cctx, cancel := context.WithTimeout(uctx, b.timeout())
	defer cancel()
	out, err := b.dispatch(cctx, ctx, &ev, method, req, r, l, cs, call, ss)
	if err != nil {
		return b.failure(&ev, method, r, l, cs, err)
	}
	return out, nil
}

// detach: ctx's cancellation and deadline, none of its values.
func detach(ctx context.Context) (context.Context, context.CancelFunc) {
	var n context.Context
	var cancel context.CancelFunc
	if d, ok := ctx.Deadline(); ok {
		n, cancel = context.WithDeadline(context.Background(), d)
	} else {
		n, cancel = context.WithCancel(context.Background())
	}
	stop := context.AfterFunc(ctx, cancel)
	return n, func() { stop(); cancel() }
}

func refusal(reason, tool, label string) string {
	switch reason {
	case "never":
		return fmt.Sprintf("%s is never available to AI on %s", tool, label)
	case "read_only":
		return fmt.Sprintf("%s changes things, and AI access to %s is read-only", tool, label)
	case "bad_tool":
		return "not a tool name Portcullis passes on"
	}
	return "arguments Portcullis can't check (they must be one JSON object without repeated keys, with numbers that keep their exact value)"
}

// failure words an error for the person and the log.
func (b *Bridge) failure(ev *Event, method string, r *config.Resource, l *link, cs *mcp.ClientSession, err error) (mcp.Result, error) {
	var ie *IdentityError
	var re *mcp.RPCError
	switch {
	case errors.As(err, &ie):
		ev.Decision, ev.UpstreamStatus = "deny:"+ie.Reason, 0
		if ie.Reason == "rate_limited" {
			ev.Decision = "rate_limited" // §15.8: not a deny reason
		}
		if ie.Tool && method == mcp.MethodCallTool {
			return isErrorResult(ie.Message), nil
		}
		return nil, rpcError(mcp.CodeInternalError, ie.Message)
	case l.tooLarge.Swap(false):
		ev.Decision = "deny:too_large"
		l.broken(cs)
		return nil, rpcError(mcp.CodeInternalError, "result too large")
	case errors.Is(err, context.DeadlineExceeded):
		ev.Decision = "deny:timeout"
		l.broken(cs)
		return nil, rpcError(mcp.CodeInternalError, r.Label+" took too long to answer")
	case errors.As(err, &re):
		// The upstream answered with a JSON-RPC error: pass it on, clipped.
		return nil, rpcError(re.Code, re.Message)
	}
	ev.Decision = "deny:upstream"
	if cs != nil {
		ev.UpstreamStatus = http.StatusBadGateway
	}
	l.broken(cs)
	log.Printf("mcp-gate: %s %q user=%q: upstream error: %v", method, r.URL, ev.User, err)
	return nil, rpcError(mcp.CodeInternalError, r.Label+" is unavailable right now")
}

func (b *Bridge) dispatch(cctx, ctx context.Context, ev *Event, method string, req mcp.Request, r *config.Resource, l *link, cs *mcp.ClientSession, call *mcp.CallToolParamsRaw, ss *mcp.ServerSession) (mcp.Result, error) {
	caps := cs.InitializeResult()
	has := func(f func(*mcp.ServerCapabilities) bool) bool {
		return caps != nil && caps.Capabilities != nil && f(caps.Capabilities)
	}
	hasTools := has(func(c *mcp.ServerCapabilities) bool { return c.Tools != nil })
	hasRes := has(func(c *mcp.ServerCapabilities) bool { return c.Resources != nil })
	hasPrompts := has(func(c *mcp.ServerCapabilities) bool { return c.Prompts != nil })
	notFound := rpcError(mcp.CodeMethodNotFound, r.Label+" doesn't offer this")
	switch method {
	case mcp.MethodListTools:
		if !hasTools {
			return &mcp.ListToolsResult{Tools: []*mcp.Tool{}}, nil
		}
		p, _ := req.GetParams().(*mcp.ListToolsParams)
		up, err := cs.ListTools(cctx, &mcp.ListToolsParams{Cursor: cursorOf(p)})
		if err != nil {
			return nil, err
		}
		l.recordTools(up.Tools)
		return &mcp.ListToolsResult{Tools: FilterTools(r, up.Tools), NextCursor: up.NextCursor}, nil
	case mcp.MethodCallTool:
		if !hasTools {
			return nil, notFound
		}
		return b.callTool(cctx, ctx, ev, r, l, cs, call, ss)
	case mcp.MethodListResources:
		if !hasRes {
			return &mcp.ListResourcesResult{Resources: []*mcp.Resource{}}, nil
		}
		p, _ := req.GetParams().(*mcp.ListResourcesParams)
		c := ""
		if p != nil {
			c = p.Cursor
		}
		up, err := cs.ListResources(cctx, &mcp.ListResourcesParams{Cursor: c})
		if err != nil {
			return nil, err
		}
		return &mcp.ListResourcesResult{Resources: up.Resources, NextCursor: up.NextCursor}, nil
	case mcp.MethodListResourceTemplates:
		if !hasRes {
			return &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{}}, nil
		}
		p, _ := req.GetParams().(*mcp.ListResourceTemplatesParams)
		c := ""
		if p != nil {
			c = p.Cursor
		}
		up, err := cs.ListResourceTemplates(cctx, &mcp.ListResourceTemplatesParams{Cursor: c})
		if err != nil {
			return nil, err
		}
		return &mcp.ListResourceTemplatesResult{ResourceTemplates: up.ResourceTemplates, NextCursor: up.NextCursor}, nil
	case mcp.MethodReadResource:
		p, _ := req.GetParams().(*mcp.ReadResourceParams)
		if !hasRes || p == nil {
			return nil, notFound
		}
		up, err := cs.ReadResource(cctx, &mcp.ReadResourceParams{URI: p.URI})
		if err != nil {
			return nil, err
		}
		if up.NeedsInput() {
			return nil, rpcError(mcp.CodeInternalError, r.Label+" asked for input here, which Portcullis doesn't pass on")
		}
		return &mcp.ReadResourceResult{Contents: up.Contents}, nil
	case mcp.MethodListPrompts:
		if !hasPrompts {
			return &mcp.ListPromptsResult{Prompts: []*mcp.Prompt{}}, nil
		}
		p, _ := req.GetParams().(*mcp.ListPromptsParams)
		c := ""
		if p != nil {
			c = p.Cursor
		}
		up, err := cs.ListPrompts(cctx, &mcp.ListPromptsParams{Cursor: c})
		if err != nil {
			return nil, err
		}
		return &mcp.ListPromptsResult{Prompts: up.Prompts, NextCursor: up.NextCursor}, nil
	case mcp.MethodGetPrompt:
		p, _ := req.GetParams().(*mcp.GetPromptParams)
		if !hasPrompts || p == nil {
			return nil, notFound
		}
		up, err := cs.GetPrompt(cctx, &mcp.GetPromptParams{Name: p.Name, Arguments: p.Arguments})
		if err != nil {
			return nil, err
		}
		if up.NeedsInput() {
			return nil, rpcError(mcp.CodeInternalError, r.Label+" asked for input here, which Portcullis doesn't pass on")
		}
		return &mcp.GetPromptResult{Description: up.Description, Messages: up.Messages}, nil
	}
	return nil, notFound
}

func cursorOf(p *mcp.ListToolsParams) string {
	if p == nil {
		return ""
	}
	return p.Cursor
}

const maxInputRounds = 10

// callTool: annotations (fetched first if the link has none), the
// confirmation seam, then the upstream call with every input request the
// companion makes screened (§15.5): sampling / roots refuse the call,
// a URL elicitation outside the allowed hosts is declined, the rest goes
// to the person — passed down to a 2026-07-28 client as input_required,
// asked of an older client's session by the gate itself.
func (b *Bridge) callTool(cctx, ctx context.Context, ev *Event, r *config.Resource, l *link, cs *mcp.ClientSession, p *mcp.CallToolParamsRaw, ss *mcp.ServerSession) (mcp.Result, error) {
	_, confirm, reason := CallDecision(r, p.Name, p.Arguments, nil)
	if !confirm {
		ann, err := l.annotation(cctx, cs, p.Name)
		if err != nil {
			return nil, err
		}
		_, confirm, reason = CallDecision(r, p.Name, p.Arguments, ann)
		if reason == "destructive" {
			if _, dup := b.warned.LoadOrStore(r.URL+"\x00"+fold(p.Name), true); !dup {
				log.Printf("mcp-gate: template warning: %s tool %q is annotated destructiveHint but no confirm pattern matches it; it needs a confirmation", r.URL, p.Name)
			}
		}
	}
	if confirm {
		if b.cfg.Confirm == nil {
			ev.Decision, ev.UpstreamStatus = "deny:confirm_unavailable", 0
			return isErrorResult("This needs your confirmation in your browser, which this Portcullis can't ask for yet; nothing was done."), nil
		}
		out, err := b.cfg.Confirm.Before(ctx, Call{User: ev.User, Client: ev.Client, Resource: r, Tool: p.Name, Args: p.Arguments, Reason: reason})
		if err != nil {
			ev.Decision, ev.UpstreamStatus = "deny:hub_unavailable", 0
			return isErrorResult("can't check this right now; try again"), nil
		}
		if !out.Proceed {
			ev.Decision, ev.UpstreamStatus = "confirm", 0
			if out.Decision != "" {
				ev.Decision = out.Decision
			}
			answer := out.Answer
			if answer == nil {
				answer = isErrorResult("This needs your confirmation in your browser.")
			}
			return answer, nil
		}
	}
	params := &mcp.CallToolParams{Name: p.Name, InputResponses: p.InputResponses, RequestState: p.RequestState}
	if len(p.Arguments) > 0 {
		params.Arguments = p.Arguments
	}
	newClient := ss == nil || ss.ID() == "" // sessionless 2026-07-28: input goes down as input_required
	for round := 0; round < maxInputRounds; round++ {
		res, err := cs.CallTool(cctx, params)
		if err != nil {
			return nil, err
		}
		if !res.NeedsInput() {
			return res, nil
		}
		if len(res.InputRequests) == 0 {
			return nil, rpcError(mcp.CodeInternalError, r.Label+" is busy; try again")
		}
		if len(res.InputRequests) > maxInputRequests {
			ev.Decision = "deny:too_many_inputs"
			return isErrorResult(fmt.Sprintf("%s asked for more than %d answers at once; Portcullis refused the request", r.Label, maxInputRequests)), nil
		}
		declined := false
		for _, ir := range res.InputRequests {
			switch x := ir.(type) {
			case *mcp.ElicitParams:
				if !l.screenElicit(x) {
					declined = true
				}
			case *mcp.ListRootsParams:
				ev.Decision = "deny:roots"
				return isErrorResult(r.Label + " asked to see your files; Portcullis doesn't allow that"), nil
			default:
				ev.Decision = "deny:sampling"
				return isErrorResult(r.Label + " asked to use your AI model; Portcullis doesn't allow that"), nil
			}
		}
		if newClient && !declined && ss != nil {
			return res, nil // the person's client answers and retries
		}
		answers := mcp.InputResponseMap{}
		for id, ir := range res.InputRequests {
			ep := ir.(*mcp.ElicitParams)
			if declined && newClient {
				answers[id] = decline // a sessionless round is declined whole
				continue
			}
			if !l.screenElicitQuiet(ep) || ss == nil {
				answers[id] = decline
				continue
			}
			er, err := ss.Elicit(ctx, ep)
			if err != nil || er == nil {
				answers[id] = decline
				continue
			}
			answers[id] = er
		}
		params = &mcp.CallToolParams{Name: p.Name, Arguments: params.Arguments, InputResponses: answers, RequestState: res.RequestState}
	}
	return nil, rpcError(mcp.CodeInternalError, r.Label+" asked for input too many times")
}

// screenElicitQuiet is screenElicit without logging (already logged).
func (l *link) screenElicitQuiet(p *mcp.ElicitParams) bool {
	switch elicitMode(p) {
	case "form":
		return p.URL == ""
	case "url":
		res := l.resource()
		sn := l.b.cfg.Snapshot()
		return res != nil && sn != nil && sn.File != nil && urlElicitationAllowed(res, sn.File.MainDomain, p.URL)
	}
	return false
}

// Fix round 1 bounds.
const (
	maxSessionsPerKey = 16    // live downstream sessions per (person, resource)
	maxDestructive    = 10000 // destructive-tool names remembered per link
	maxInputRequests  = 8     // input requests per round
)

// liveSessions counts the tracked downstream sessions of a key (tests).
func (b *Bridge) liveSessions(k key) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.order[k])
}

// trackLocked registers a downstream session of k (at its initialize, or
// at its first forwarded call) and returns the sessions evicted past
// maxSessionsPerKey, oldest first, for the caller to close after
// unlocking. A waiter forgets the session when it ends.
func (b *Bridge) trackLocked(k key, ss *mcp.ServerSession) (evicted []*mcp.ServerSession) {
	if _, seen := b.owners[ss]; seen {
		return nil
	}
	b.owners[ss] = k
	b.order[k] = append(b.order[k], ss)
	go func() {
		_ = ss.Wait()
		b.mu.Lock()
		l := b.sessions[ss]
		b.forgetLocked(ss)
		b.mu.Unlock()
		if l != nil {
			l.close()
		}
	}()
	for len(b.order[k]) > maxSessionsPerKey {
		old := b.order[k][0]
		b.order[k] = b.order[k][1:]
		evicted = append(evicted, old)
	}
	return evicted
}

func (b *Bridge) forgetLocked(ss *mcp.ServerSession) {
	k, ok := b.owners[ss]
	delete(b.sessions, ss)
	delete(b.owners, ss)
	if ok {
		if i := slices.Index(b.order[k], ss); i >= 0 {
			b.order[k] = slices.Delete(b.order[k], i, i+1)
		}
		if len(b.order[k]) == 0 {
			delete(b.order, k)
		}
	}
}

// evict closes evicted downstream sessions and their upstream sessions.
func (b *Bridge) evict(victims []*mcp.ServerSession) {
	for _, ss := range victims {
		b.mu.Lock()
		l := b.sessions[ss]
		b.forgetLocked(ss)
		b.mu.Unlock()
		if l != nil {
			l.close()
		}
		_ = ss.Close()
	}
}
