package bridge

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/mcp-gate/internal/config"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// A link is one upstream SDK client session for a person on a companion.
// A downstream session on 2025-06-18 / 2025-11-25 gets its own link
// (contract §15.5: the gate's session id maps to (person, resource,
// upstream session)), so the companion's in-band requests reach exactly
// that session. Sessionless 2026-07-28 clients and Bridge.Upstream share
// one pooled link per (person, resource), closed after IdleTimeout.
type link struct {
	b    *Bridge
	key  key
	fp   string // the resource's upstream fingerprint at creation
	idt  *IdentityTransport
	ss   *mcp.ServerSession // downstream session; nil for a pooled link
	want string             // the protocol version spoken upstream

	connectMu sync.Mutex
	mu        sync.Mutex
	cs        *mcp.ClientSession
	closed    bool
	active    []*inflight // in-flight downstream requests (newest last)
	lastUse   time.Time

	annMu       sync.Mutex
	annLoaded   bool
	destructive map[string]bool // folded name → ever annotated destructive (sticky), ≤ maxDestructive
	annFull     bool            // the cap was hit: every call through this link is refused

	tooLarge atomic.Bool
}

// fingerprint: what a pooled session depends on. A change closes it.
func fingerprint(res *config.Resource) string {
	id := res.Identity
	return res.Upstream + "\x00" + id.Mode + "\x00" + id.Header + "\x00" + id.Format + "\x00" + id.BasicUser + "\x00" + id.SecretRef + "\x00" + upstreamVersion(res)
}

// upstreamVersion: the newest version in the companion's protocol list
// that the gate supports (§15.3).
func upstreamVersion(res *config.Resource) string {
	best := ""
	for _, v := range res.Protocol {
		if slices.Contains(config.SupportedProtocols, v) && slices.Contains(mcp.SupportedSDKProtocols(), v) && v > best {
			best = v
		}
	}
	return best
}

func (b *Bridge) newLink(k key, res *config.Resource, ss *mcp.ServerSession) *link {
	l := &link{b: b, key: k, fp: fingerprint(res), ss: ss, want: upstreamVersion(res), lastUse: b.now(), destructive: map[string]bool{}}
	l.idt = newIdentityTransport(b.base, b.cfg.Snapshot, res, k.user, b.gate, b.now, b.maxResult(), func() { l.tooLarge.Store(true) })
	return l
}

var errLinkClosed = errors.New("upstream session closed")

// session connects on first use (identity first: never anonymous).
func (l *link) session(ctx context.Context) (*mcp.ClientSession, error) {
	l.connectMu.Lock()
	defer l.connectMu.Unlock()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, errLinkClosed
	}
	cs := l.cs
	l.lastUse = l.b.now()
	l.mu.Unlock()
	if err := l.idt.Ready(ctx); err != nil {
		return nil, err
	}
	if cs != nil {
		return cs, nil
	}
	if l.want == "" {
		return nil, &IdentityError{Reason: "protocol", Message: "no common protocol version with this app"}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "portcullis-mcp-gate", Version: "1"}, &mcp.ClientOptions{
		// No sampling or roots capability: a companion never drives the
		// person's model or sees their files (§15.5).
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{
			Form: &mcp.FormElicitationCapabilities{}, URL: &mcp.URLElicitationCapabilities{},
		}},
		ElicitationHandler:     l.elicit,
		MultiRoundTrip:         &mcp.MultiRoundTripOptions{Disabled: true}, // the bridge screens every input request
		ToolListChangedHandler: func(context.Context, *mcp.ToolListChangedRequest) { l.resetAnnotations() },
	})
	client.AddReceivingMiddleware(l.declineMiddleware)
	tr := &mcp.StreamableClientTransport{
		Endpoint: l.idt.upstream.String(),
		HTTPClient: &http.Client{
			Transport:     l.idt,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		MaxEventSize: int(l.b.maxResult()) + 1<<20,
	}
	cctx, cancel := context.WithTimeout(ctx, l.b.timeout())
	defer cancel()
	cs, err := client.Connect(cctx, tr, &mcp.ClientSessionOptions{ProtocolVersion: l.want})
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		cs.Close()
		return nil, errLinkClosed
	}
	l.cs = cs
	l.mu.Unlock()
	return cs, nil
}

// close ends the upstream session (DELETE for a stateful one).
func (l *link) close() {
	l.mu.Lock()
	l.closed = true
	cs := l.cs
	l.cs = nil
	l.mu.Unlock()
	if cs != nil {
		_ = cs.Close()
	}
}

// broken drops a failed upstream session so the next call reconnects.
func (l *link) broken(cs *mcp.ClientSession) {
	l.mu.Lock()
	if l.cs == cs {
		l.cs = nil
	}
	l.mu.Unlock()
	if cs != nil {
		go cs.Close()
	}
}

func (l *link) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// inflight is one downstream request: its context, and the AI client and
// gate request id its side-channel lines carry (final review M8).
type inflight struct {
	ctx               context.Context
	client, requestID string
}

// enter records an in-flight downstream request: in-band requests from
// the companion go to the newest one (its own response stream).
func (l *link) enter(ctx context.Context, client, requestID string) func() {
	in := &inflight{ctx: ctx, client: client, requestID: requestID}
	l.mu.Lock()
	l.active = append(l.active, in)
	l.lastUse = l.b.now()
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		if i := slices.Index(l.active, in); i >= 0 {
			l.active = slices.Delete(l.active, i, i+1)
		}
		l.lastUse = l.b.now()
		l.mu.Unlock()
	}
}

func (l *link) downstream() (*mcp.ServerSession, context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ss == nil || len(l.active) == 0 {
		return nil, nil
	}
	return l.ss, l.active[len(l.active)-1].ctx
}

func (l *link) resource() *config.Resource {
	sn := l.b.cfg.Snapshot()
	if sn == nil || sn.Err != nil || sn.File == nil {
		return nil
	}
	return lookupURL(sn, l.key.url)
}

func (l *link) event(method, decision string) {
	res := l.resource()
	e := Event{User: l.key.user, Resource: l.key.url, Via: "direct", Method: method, Decision: decision}
	// The request it happened in (the newest in flight): its client and
	// gate request id (final review M8).
	l.mu.Lock()
	if n := len(l.active); n > 0 {
		e.Client, e.RequestID = l.active[n-1].client, l.active[n-1].requestID
	}
	l.mu.Unlock()
	if res != nil {
		e.Instance, e.Companion = res.Instance, res.Companion
	}
	l.b.emit(e)
}

var decline = &mcp.ElicitResult{Action: "decline"}

func elicitMode(p *mcp.ElicitParams) string {
	if p.Mode != "" {
		return p.Mode
	}
	if p.URL != "" || p.ElicitationID != "" {
		return "url"
	}
	return "form"
}

// screenElicit decides one elicitation from the companion: form mode is
// passed through; URL mode only to the resource's own hosts or
// people.<main domain> (G54). It reports false for a refused one.
func (l *link) screenElicit(p *mcp.ElicitParams) bool {
	switch elicitMode(p) {
	case "form":
		return p.URL == ""
	case "url":
		res := l.resource()
		sn := l.b.cfg.Snapshot()
		if res != nil && sn != nil && sn.File != nil && urlElicitationAllowed(res, sn.File.MainDomain, p.URL) {
			return true
		}
		l.event(mcp.MethodElicit, "deny:url_elicitation")
		return false
	}
	l.event(mcp.MethodElicit, "deny:elicitation")
	return false
}

// elicit handles an in-band elicitation/create from a 2025-x companion.
func (l *link) elicit(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	if req == nil || req.Params == nil || !l.screenElicit(req.Params) {
		return decline, nil
	}
	ss, dctx := l.downstream()
	if ss == nil {
		return decline, nil // nobody to ask (a sessionless client or no call in flight)
	}
	ectx, cancel := context.WithTimeout(dctx, elicitWait) // bounded (M6)
	defer cancel()
	r, err := ss.Elicit(ectx, req.Params)
	if err != nil || r == nil {
		return decline, nil
	}
	return r, nil
}

// declineMiddleware refuses sampling and roots from the companion (the
// gate declares neither capability; a companion asking anyway is logged).
func (l *link) declineMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		switch method {
		case mcp.MethodCreateMessage:
			l.event(method, "deny:sampling")
			return nil, &mcp.RPCError{Code: mcp.CodeMethodNotFound, Message: "declined by Portcullis"}
		case mcp.MethodListRoots:
			l.event(method, "deny:roots")
			return nil, &mcp.RPCError{Code: mcp.CodeMethodNotFound, Message: "declined by Portcullis"}
		}
		return next(ctx, method, req)
	}
}

// ---- annotations (G23): the gate's own cached tools/list per link ----

func (l *link) resetAnnotations() {
	l.annMu.Lock()
	l.annLoaded = false
	l.annMu.Unlock()
}

func (l *link) recordTools(tools []*mcp.Tool) {
	l.annMu.Lock()
	defer l.annMu.Unlock()
	for _, t := range tools {
		if t == nil || !ValidToolName(t.Name) || t.Annotations == nil || t.Annotations.DestructiveHint == nil || !*t.Annotations.DestructiveHint {
			continue
		}
		n := fold(t.Name)
		if l.destructive[n] {
			continue
		}
		if len(l.destructive) >= maxDestructive {
			l.annFull = true // can't remember it: fail closed
			continue
		}
		l.destructive[n] = true
	}
}

const maxToolPages = 100

// annotation is what the gate knows about the tool's destructiveness:
// fetched first when the link has no list yet. A fetch failure fails the
// call (closed); a tool missing from the list has no annotation.
func (l *link) annotation(ctx context.Context, cs *mcp.ClientSession, tool string) (*mcp.ToolAnnotations, error) {
	l.annMu.Lock()
	loaded := l.annLoaded
	l.annMu.Unlock()
	if !loaded {
		cursor := ""
		for i := 0; ; i++ {
			if i == maxToolPages {
				return nil, errors.New("too many tool pages")
			}
			r, err := cs.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
			if err != nil {
				return nil, err
			}
			l.recordTools(r.Tools)
			if r.NextCursor == "" {
				break
			}
			cursor = r.NextCursor
		}
		l.annMu.Lock()
		l.annLoaded = true
		l.annMu.Unlock()
	}
	l.annMu.Lock()
	defer l.annMu.Unlock()
	if l.annFull {
		return nil, &IdentityError{Reason: "too_many_tools", Message: "this app lists more tools than Portcullis can check", Tool: true}
	}
	if l.destructive[fold(tool)] {
		t := true
		return &mcp.ToolAnnotations{DestructiveHint: &t}, nil
	}
	return nil, nil
}
