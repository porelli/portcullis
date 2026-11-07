// Package aggregate is "All my apps" (integration contract §15.9, plan 4
// task 5): https://mcp.<d>/mcp, served by the gate itself. One connection
// gives a person the tools, resources and prompts of every companion they
// can reach (aggregate: true, in its population and not past expiring,
// its min_loa met by the token's acr) plus the people resource's tools,
// never the delegate tools (G38) and never an admin tool.
//
// Per (person, LoA) there is one SDK server whose registry holds the
// person's aggregate names (a Table, G24: names are never parsed back);
// changing it is what sends notifications/tools/list_changed (also on
// subscriptions/listen). Its receiving middleware routes every call to its
// upstream: a companion through bridge.Forward — the same identity, tool
// policy, annotations, confirmations (bound to the companion's own URL),
// result bounds and access-log path as a direct request, with via
// "aggregate" — and the people tools through an SDK client to the Hub's
// /mcp/people with the identity headers of §15.7. Each upstream's own
// population, expiring, min_loa and per-resource limits are checked on
// every request; the aggregate's own audience, scope and clients are
// authz's.
//
// Lists are fanned out to at most limits.fanout upstreams at once within
// ListTimeout, cached 60 s per person and invalidated on any snapshot
// change. An upstream that fails drops out with "<label> is unavailable
// right now" in the server's instructions; it never fails the endpoint and
// is never taken as allowed.
package aggregate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/bridge"
	"github.com/portcullis/mcp-gate/internal/canon"
	"github.com/portcullis/mcp-gate/internal/config"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// Defaults (§15.9: the list is cached 60 s per person).
const (
	DefaultCacheTTL    = 60 * time.Second
	DefaultListTimeout = 30 * time.Second
	DefaultIdleTimeout = 10 * time.Minute
)

// Bounds on what one refresh takes from the upstreams.
const (
	maxPages           = 100              // list pages per upstream and kind
	maxItems           = 1000             // tools / resources / prompts per upstream
	maxSessionsPerKey  = 16               // live downstream sessions per (person, LoA, client)
	maxFanout          = config.MaxFanout // parallel upstream calls per request (§15.9)
	maxResponseMessage = 1024
)

// Size bounds on one refresh (vars: tests lower them).
var (
	maxUpstreamBytes = 4 << 20 // encoded tool + resource + prompt definitions per upstream
	maxTotalBytes    = 8 << 20 // ... for the whole aggregate
)

// The delegate tools are only on people.<d>/mcp, never here (G38).
var delegateTools = []string{"invite_person", "update_person", "delete_person"}

func isDelegate(name string) bool { return slices.Contains(delegateTools, strings.ToLower(name)) }

// Forwarder is the bridge's way in (bridge.Bridge).
type Forwarder interface {
	Forward(ctx context.Context, v bridge.Via, res *config.Resource, method string, req mcp.Request) (mcp.Result, error)
}

// Portcullis gives the person's session to the Hub's /mcp/people
// (portcullis.Hub).
type Portcullis interface {
	People(ctx context.Context, user, client, resource string) (*mcp.ClientSession, error)
	Broken(user string, cs *mcp.ClientSession)
	// DropClient closes the person's Hub sessions of one AI client.
	DropClient(user, client string)
}

// Limiter is the per-resource rate limit (limits.Limiter).
type Limiter interface {
	Allow(user, resource string, toolCall bool) (bool, time.Duration)
}

// Config configures an Aggregate.
type Config struct {
	Snapshot   func() *config.Snapshot
	Bridge     Forwarder
	Portcullis Portcullis // nil: no Portcullis tools
	Limits     Limiter    // nil: no per-upstream limits
	OnEvent    func(bridge.Event)
	Now        func() time.Time
	// CacheTTL (60 s), ListTimeout (30 s: one whole fan-out), IdleTimeout
	// (10 min), CallTimeout (the file's upstream timeout, 120 s).
	CacheTTL, ListTimeout, IdleTimeout, CallTimeout time.Duration
}

// Aggregate serves the aggregate resource.
type Aggregate struct {
	cfg       Config
	stateless http.Handler

	mu       sync.Mutex
	entries  map[ekey]*entry
	lastSn   *config.Snapshot
	stop     chan struct{}
	stopOnce sync.Once
}

// ekey: one entry per (person, LoA, AI client). The client is part of
// it because each upstream's own clients decide (Resource.clients,
// §15.2 / §15.4): two clients of one person can see different apps.
type ekey struct {
	user   string
	loa    int
	client string
}

// ident is the request's identity, from ServeHTTP to the middleware.
type ident struct {
	ekey
	url string // the aggregate resource's
}

type identKey struct{}

// entry is one person's (at one LoA) SDK server, registry and tables.
type entry struct {
	key     ekey
	server  *mcp.Server
	handler http.Handler

	refreshMu sync.Mutex // one refresh at a time

	mu        sync.Mutex
	built     bool
	stale     bool
	sn        *config.Snapshot
	builtAt   time.Time
	expiresAt time.Time         // the earliest expiring time among its upstreams; zero = none
	tools     Table             // aggregate name → (upstream URL, upstream name)
	prompts   Table             // the same for prompts
	resources map[string]Target // URI → (upstream URL, URI)
	regTools  map[string]string // name → encoded definition, as registered
	regRes    map[string]string
	regPrompt map[string]string
	down      []string // labels of upstreams that failed at the last refresh
	order     []*mcp.ServerSession
	lastUse   time.Time
}

// New builds an Aggregate; Run (or Reconcile on every snapshot change)
// keeps it in line with the populations.
func New(cfg Config) *Aggregate {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.ListTimeout <= 0 {
		cfg.ListTimeout = DefaultListTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	a := &Aggregate{cfg: cfg, entries: map[ekey]*entry{}, stop: make(chan struct{})}
	h := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		id, ok := r.Context().Value(identKey{}).(ident)
		if !ok {
			return nil
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if e := a.entries[id.ekey]; e != nil {
			return e.server
		}
		return nil
	}, &mcp.StreamableHTTPOptions{
		Stateless:                  true,
		DisableLocalhostProtection: true, // the Host is the resource's; authz checked it
		MaxRequestBodyBytes:        config.FixedMaxRequestBytes,
	})
	a.stateless = mcp.RequireBearerToken(verifier, nil)(h)
	return a
}

func (a *Aggregate) now() time.Time { return a.cfg.Now() }

// refused logs a request the aggregate refused before any upstream
// (final review M2): the aggregate resource's line, never "allow".
func (a *Aggregate) refused(req mcp.Request, id ident, method, decision string) {
	a.emit(bridge.Event{User: id.user, Client: id.client, Resource: id.url, Via: "direct", Method: method, Decision: decision, RequestID: requestID(req)})
}

func (a *Aggregate) emit(e bridge.Event) {
	if a.cfg.OnEvent != nil {
		a.cfg.OnEvent(e)
	}
}

func (a *Aggregate) callTimeout(sn *config.Snapshot) time.Duration {
	if a.cfg.CallTimeout > 0 {
		return a.cfg.CallTimeout
	}
	if sn != nil && sn.File != nil && sn.File.Limits.UpstreamTimeoutS > 0 {
		return time.Duration(sn.File.Limits.UpstreamTimeoutS) * time.Second
	}
	return config.FixedUpstreamTimeoutS * time.Second
}

// verifier hands the SDK the identity ServeHTTP put in the context.
func verifier(ctx context.Context, _ string, _ *http.Request) (*mcp.TokenInfo, error) {
	id, ok := ctx.Value(identKey{}).(ident)
	if !ok || id.user == "" {
		return nil, errors.New("no identity")
	}
	return &mcp.TokenInfo{
		UserID:     id.user + "\x00" + id.url,
		Expiration: time.Now().Add(time.Hour),
		Extra:      map[string]any{"client": id.client, "loa": id.loa},
	}, nil
}

// noCookie drops any Set-Cookie on the way out.
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

func usable(sn *config.Snapshot) bool {
	return sn != nil && sn.Err == nil && !sn.Off && sn.File != nil
}

func byURL(sn *config.Snapshot, raw string) *config.Resource {
	if !usable(sn) {
		return nil
	}
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

func aggregateOf(sn *config.Snapshot) *config.Resource {
	if !usable(sn) {
		return nil
	}
	for i := range sn.File.Resources {
		if sn.File.Resources[i].Kind == config.KindAggregate {
			return &sn.File.Resources[i]
		}
	}
	return nil
}

// ServeHTTP serves one HTTP request of the aggregate that authz allowed
// (d). It re-checks the resource and the person against the current
// snapshot (fail closed), then hands the request to the person's own SDK
// server. 2026-07-28 requests are sessionless.
func (a *Aggregate) ServeHTTP(w http.ResponseWriter, r *http.Request, d authz.Decision) {
	w = noCookie{w}
	if !d.Allowed() || d.Resource == nil || d.User == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sn := a.cfg.Snapshot()
	if !usable(sn) {
		http.Error(w, "AI support is off on this Portcullis", http.StatusServiceUnavailable)
		return
	}
	res := byURL(sn, d.Resource.URL)
	if res == nil || res.Kind != config.KindAggregate {
		http.Error(w, "not the aggregate", http.StatusServiceUnavailable)
		return
	}
	if !res.Member(d.User, a.now()) || d.LoA < res.MinLoA {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	k := ekey{user: d.User, loa: d.LoA, client: d.Client}
	e := a.entryFor(k)
	r = r.WithContext(context.WithValue(r.Context(), identKey{}, ident{ekey: k, url: res.URL}))
	if r.Header.Get("Mcp-Protocol-Version") >= mcp.ProtocolStateless {
		a.stateless.ServeHTTP(w, r)
		return
	}
	e.handler.ServeHTTP(w, r)
}

func (a *Aggregate) entryFor(k ekey) *entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e := a.entries[k]; e != nil {
		e.mu.Lock()
		e.lastUse = a.now()
		e.mu.Unlock()
		return e
	}
	e := &entry{key: k, regTools: map[string]string{}, regRes: map[string]string{}, regPrompt: map[string]string{}, lastUse: a.now()}
	s := mcp.NewServer(&mcp.Implementation{Name: "portcullis-mcp-gate", Title: "All my apps on Portcullis", Version: "1"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools:     &mcp.ToolCapabilities{ListChanged: true},
			Resources: &mcp.ResourceCapabilities{ListChanged: true},
			Prompts:   &mcp.PromptCapabilities{ListChanged: true},
		},
		SupportedProtocolVersions: config.SupportedProtocols, // G18
	})
	s.AddReceivingMiddleware(a.middleware(e))
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{
		DisableLocalhostProtection: true,
		SessionTimeout:             a.cfg.IdleTimeout,
		MaxRequestBodyBytes:        config.FixedMaxRequestBytes,
	})
	e.server, e.handler = s, mcp.RequireBearerToken(verifier, nil)(h)
	a.entries[k] = e
	return e
}

// ---- upstreams ----

// upstream is one resource the person reaches through the aggregate.
type upstream struct {
	res    *config.Resource
	prefix string
	people bool
}

func (u upstream) label() string { return u.res.Label }

// eligible: the companions with aggregate: true that allow the token's
// AI client, whose population has the person and whose min_loa the token
// meets, then the people resource on the same terms (when the Hub is
// wired). Admin resources never.
func (a *Aggregate) eligible(sn *config.Snapshot, k ekey) []upstream {
	if !usable(sn) {
		return nil
	}
	var out []upstream
	for i := range sn.File.Resources {
		r := &sn.File.Resources[i]
		if u, reason := a.admit(r, k); reason == "" {
			out = append(out, u)
		}
	}
	return out
}

// admit decides one resource for the person: "" or the deny reason.
func (a *Aggregate) admit(r *config.Resource, k ekey) (upstream, string) {
	if r == nil {
		return upstream{}, "off"
	}
	var u upstream
	switch r.Kind {
	case config.KindCompanion:
		if r.Identity.Mode != "app_token" && r.Identity.Mode != "identity_headers" {
			return upstream{}, "off" // never app_oauth (not in the file anyway)
		}
		u = upstream{res: r, prefix: r.Instance}
	case config.KindPeople:
		if a.cfg.Portcullis == nil {
			return upstream{}, "off"
		}
		u = upstream{res: r, prefix: PortcullisPrefix, people: true}
	default:
		return upstream{}, "off" // the admin resource and the aggregate itself, never
	}
	switch {
	case !r.Aggregate:
		return upstream{}, "off"
	case !r.AllowsClient(k.client):
		// The upstream's own clients decide (the per-client admin flag and
		// offer live there), never the aggregate's.
		return upstream{}, "client"
	case !r.Member(k.user, a.now()):
		return upstream{}, "population"
	case k.loa < r.MinLoA:
		return upstream{}, "loa"
	}
	return u, ""
}

// ---- the middleware ----

func rpcError(code int64, msg string) *mcp.RPCError {
	return &mcp.RPCError{Code: code, Message: clip(msg, maxResponseMessage)}
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

func requestID(req mcp.Request) string {
	if ex := req.GetExtra(); ex != nil && ex.Header != nil {
		return ex.Header.Get(bridge.RequestIDHeader)
	}
	return ""
}

// identOf: the request's identity, checked against the entry it reached.
func identOf(req mcp.Request, e *entry) (ident, bool) {
	ex := req.GetExtra()
	if ex == nil || ex.TokenInfo == nil {
		return ident{}, false
	}
	user, aggURL, ok := strings.Cut(ex.TokenInfo.UserID, "\x00")
	if !ok || user != e.key.user {
		return ident{}, false
	}
	loa, _ := ex.TokenInfo.Extra["loa"].(int)
	client, _ := ex.TokenInfo.Extra["client"].(string)
	if loa != e.key.loa || client != e.key.client {
		return ident{}, false
	}
	return ident{ekey: e.key, url: aggURL}, true
}

var errNotAllowed = rpcError(mcp.CodeInvalidParams, "not allowed")

func (a *Aggregate) middleware(e *entry) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			switch method {
			case mcp.MethodInitialize, mcp.MethodDiscover:
				res, err := next(ctx, method, req)
				if err != nil {
					return res, err
				}
				if ss, ok := req.GetSession().(*mcp.ServerSession); ok && ss.ID() != "" && method == mcp.MethodInitialize {
					a.track(e, ss)
				}
				if id, ok := identOf(req, e); ok {
					a.ensure(ctx, e, req, id, false)
				}
				ins := e.instructions()
				switch r := res.(type) {
				case *mcp.InitializeResult:
					cp := *r
					cp.Instructions = ins
					return &cp, nil
				case *mcp.DiscoverResult:
					cp := *r
					cp.Instructions = ins
					return &cp, nil
				}
				return res, nil
			case mcp.MethodListTools, mcp.MethodListResources, mcp.MethodListPrompts:
				id, ok := identOf(req, e)
				if !ok {
					return nil, errNotAllowed
				}
				a.ensure(ctx, e, req, id, false)
				return next(ctx, method, req)
			case mcp.MethodListResourceTemplates:
				return &mcp.ListResourceTemplatesResult{ResourceTemplates: []*mcp.ResourceTemplate{}}, nil
			case mcp.MethodCallTool, mcp.MethodReadResource, mcp.MethodGetPrompt:
				id, ok := identOf(req, e)
				if !ok {
					// Logged as refused, never left to the handler's
					// fallback (an error in a 200 reads "allow": M2).
					a.refused(req, ident{ekey: e.key}, method, "deny:token")
					return nil, errNotAllowed
				}
				return a.route(ctx, e, method, req, id)
			case mcp.MethodComplete, mcp.MethodSubscribe, mcp.MethodUnsubscribe:
				return nil, rpcError(mcp.CodeMethodNotFound, "not supported through Portcullis")
			}
			return next(ctx, method, req) // ping, notifications, subscriptions/listen
		}
	}
}

func (e *entry) instructions() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	lines := []string{"All your Portcullis apps in one place: each tool's name starts with its app's id, each description with the app's name and host."}
	for _, l := range e.down {
		lines = append(lines, l+" is unavailable right now")
	}
	return strings.Join(lines, "\n")
}

// track keeps at most maxSessionsPerKey live downstream sessions per entry:
// a new one closes the oldest.
func (a *Aggregate) track(e *entry, ss *mcp.ServerSession) {
	e.mu.Lock()
	if slices.Contains(e.order, ss) {
		e.mu.Unlock()
		return
	}
	e.order = append(e.order, ss)
	var victims []*mcp.ServerSession
	for len(e.order) > maxSessionsPerKey {
		victims = append(victims, e.order[0])
		e.order = e.order[1:]
	}
	e.mu.Unlock()
	go func() {
		_ = ss.Wait()
		e.mu.Lock()
		if i := slices.Index(e.order, ss); i >= 0 {
			e.order = slices.Delete(e.order, i, i+1)
		}
		e.lastUse = a.now()
		e.mu.Unlock()
	}()
	for _, v := range victims {
		_ = v.Close()
	}
}

// ---- the cache and the fan-out ----

func (a *Aggregate) fresh(e *entry, sn *config.Snapshot, forCall bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := a.now()
	return e.built && !e.stale && e.sn == sn && (forCall || now.Sub(e.builtAt) < a.cfg.CacheTTL) &&
		(e.expiresAt.IsZero() || now.Before(e.expiresAt)) // an expiring membership drops the cached lists
}

// ensure refreshes the person's tables when they are missing, from another
// snapshot (any population or configuration change), invalidated, or —
// for lists — older than the cache's TTL.
func (a *Aggregate) ensure(ctx context.Context, e *entry, req mcp.Request, id ident, forCall bool) {
	sn := a.cfg.Snapshot()
	if a.fresh(e, sn, forCall) {
		return
	}
	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()
	sn = a.cfg.Snapshot()
	if a.fresh(e, sn, forCall) {
		return
	}
	a.refresh(ctx, e, sn, req, id)
}

// listing is what one upstream offers.
type listing struct {
	tools     []*mcp.Tool
	resources []*mcp.Resource
	prompts   []*mcp.Prompt
	err       error
}

var errTooBig = errors.New("lists too much")

// detach: ctx's cancellation and deadline, none of its values (the SDK
// keeps per-request protocol state in context values).
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

func (a *Aggregate) refresh(ctx context.Context, e *entry, sn *config.Snapshot, req mcp.Request, id ident) {
	ups := a.eligible(sn, e.key)
	fan := 1
	if usable(sn) && sn.File.Limits.Fanout > 0 {
		fan = sn.File.Limits.Fanout
	}
	fan = min(fan, maxFanout) // §15.9: at most 4, whatever the file says
	lctx, cancel := context.WithTimeout(ctx, a.cfg.ListTimeout)
	defer cancel()
	results := make([]listing, len(ups))
	var running atomic.Int64 // the running total of every upstream's pages
	sem := make(chan struct{}, fan)
	var wg sync.WaitGroup
	for i, u := range ups {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-lctx.Done():
				results[i].err = lctx.Err()
				return
			}
			defer func() { <-sem }()
			done := make(chan listing, 1)
			go func() { done <- a.list(lctx, u, req, id, &sizer{total: &running}) }()
			select {
			case l := <-done:
				results[i] = l
			case <-lctx.Done(): // the whole fan-out's deadline: never waits past it
				results[i].err = lctx.Err()
			}
		}()
	}
	wg.Wait()

	// Size bounds, then names (G24).
	var down []string
	total := 0
	var toolItems, promptItems []Item
	toolDefs := map[Target]*mcp.Tool{}
	promptDefs := map[Target]*mcp.Prompt{}
	resByURI := map[string][]int{}
	resDefs := map[string]*mcp.Resource{}
	for i, u := range ups {
		l := results[i]
		if l.err == nil {
			n := encodedSize(l.tools) + encodedSize(l.resources) + encodedSize(l.prompts)
			if n > maxUpstreamBytes || total+n > maxTotalBytes {
				l.err = errTooBig
			} else {
				total += n
			}
		}
		if l.err != nil {
			down = append(down, u.label())
			if !errors.Is(l.err, context.Canceled) {
				log.Printf("mcp-gate: aggregate: %s for %q: %v", u.res.URL, e.key.user, l.err)
			}
			continue
		}
		for _, t := range l.tools {
			toolItems = append(toolItems, Item{Prefix: u.prefix, URL: u.res.URL, Name: t.Name})
			toolDefs[Target{URL: u.res.URL, Name: t.Name}] = t
		}
		for _, p := range l.prompts {
			promptItems = append(promptItems, Item{Prefix: u.prefix, URL: u.res.URL, Name: p.Name})
			promptDefs[Target{URL: u.res.URL, Name: p.Name}] = p
		}
		for _, r := range l.resources {
			resByURI[r.URI] = append(resByURI[r.URI], i)
			resDefs[r.URI] = r
		}
	}
	slices.Sort(down)
	tools, dropped := BuildTable(toolItems)
	warnDropped("tool", dropped)
	prompts, dropped := BuildTable(promptItems)
	warnDropped("prompt", dropped)
	resources := map[string]Target{}
	for uri, idx := range resByURI {
		if len(idx) > 1 {
			warnDropped("resource", []string{uri})
			continue
		}
		resources[uri] = Target{URL: ups[idx[0]].res.URL, Name: uri}
	}
	prefixOf := map[string]string{}
	for _, u := range ups {
		prefixOf[u.res.URL] = "[" + u.res.Label + " · " + u.res.Host + "] "
	}

	// The registry: only what changed, so list_changed means a change.
	wantTools := map[string]*mcp.Tool{}
	for name, t := range tools {
		def := *toolDefs[t]
		def.Name = name
		def.Description = prefixOf[t.URL] + def.Description
		def.Meta = nil
		wantTools[name] = &def
	}
	wantPrompts := map[string]*mcp.Prompt{}
	for name, t := range prompts {
		def := *promptDefs[t]
		def.Name = name
		def.Description = prefixOf[t.URL] + def.Description
		def.Meta = nil
		wantPrompts[name] = &def
	}
	wantRes := map[string]*mcp.Resource{}
	for uri, t := range resources {
		def := *resDefs[uri]
		def.Description = prefixOf[t.URL] + def.Description
		def.Meta = nil
		wantRes[uri] = &def
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	syncTools(e, wantTools, tools)
	syncPrompts(e, wantPrompts, prompts)
	syncResources(e, wantRes, resources)
	e.tools, e.prompts, e.resources = tools, prompts, resources
	e.down = down
	e.sn, e.builtAt, e.built = sn, a.now(), true
	e.expiresAt = time.Time{}
	for _, u := range ups {
		if at, ok := u.res.Expiring[e.key.user]; ok && (e.expiresAt.IsZero() || at.Before(e.expiresAt)) {
			e.expiresAt = at.Time
		}
	}
	// A refresh cut short by the person's own request leaves the tables
	// usable but not cached.
	e.stale = ctx.Err() != nil
}

func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return maxTotalBytes + 1
	}
	return len(b)
}

func encode(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func notRouted(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return nil, rpcError(mcp.CodeInternalError, "not routed") // the middleware answers every call
}

func notRoutedPrompt(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	return nil, rpcError(mcp.CodeInternalError, "not routed")
}

func notRoutedResource(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	return nil, rpcError(mcp.CodeInternalError, "not routed")
}

// objectSchema: the SDK requires an input schema of type "object".
func objectSchema(s any) bool {
	if s == nil {
		return false
	}
	var m map[string]any
	b, err := json.Marshal(s)
	if err != nil || json.Unmarshal(b, &m) != nil {
		return false
	}
	return m["type"] == "object"
}

// add runs one registry change; a definition the SDK refuses (it panics)
// is dropped.
func add(f func()) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	f()
	return true
}

// syncTools (e.mu held): remove what went, add what is new or changed;
// a tool the SDK refuses leaves the table too.
func syncTools(e *entry, want map[string]*mcp.Tool, tab Table) {
	var gone []string
	for name := range e.regTools {
		if _, ok := want[name]; !ok {
			gone = append(gone, name)
		}
	}
	if len(gone) > 0 {
		e.server.RemoveTools(gone...)
		for _, n := range gone {
			delete(e.regTools, n)
		}
	}
	for name, t := range want {
		enc := encode(t)
		if e.regTools[name] == enc {
			continue
		}
		if !objectSchema(t.InputSchema) || !add(func() { e.server.AddTool(t, notRouted) }) {
			delete(tab, name)
			if _, had := e.regTools[name]; had {
				e.server.RemoveTools(name)
				delete(e.regTools, name)
			}
			continue
		}
		e.regTools[name] = enc
	}
}

func syncPrompts(e *entry, want map[string]*mcp.Prompt, tab Table) {
	var gone []string
	for name := range e.regPrompt {
		if _, ok := want[name]; !ok {
			gone = append(gone, name)
		}
	}
	if len(gone) > 0 {
		e.server.RemovePrompts(gone...)
		for _, n := range gone {
			delete(e.regPrompt, n)
		}
	}
	for name, p := range want {
		enc := encode(p)
		if e.regPrompt[name] == enc {
			continue
		}
		if !add(func() { e.server.AddPrompt(p, notRoutedPrompt) }) {
			delete(tab, name)
			continue
		}
		e.regPrompt[name] = enc
	}
}

func syncResources(e *entry, want map[string]*mcp.Resource, tab map[string]Target) {
	var gone []string
	for uri := range e.regRes {
		if _, ok := want[uri]; !ok {
			gone = append(gone, uri)
		}
	}
	if len(gone) > 0 {
		e.server.RemoveResources(gone...)
		for _, n := range gone {
			delete(e.regRes, n)
		}
	}
	for uri, r := range want {
		enc := encode(r)
		if e.regRes[uri] == enc {
			continue
		}
		u, err := url.Parse(uri)
		if err != nil || !u.IsAbs() || !add(func() { e.server.AddResource(r, notRoutedResource) }) {
			delete(tab, uri)
			continue
		}
		e.regRes[uri] = enc
	}
}

// ---- listing one upstream ----

var errRateLimited = errors.New("rate limited")

func (a *Aggregate) allow(id ident, u upstream, call bool) bool {
	if a.cfg.Limits == nil {
		return true
	}
	ok, _ := a.cfg.Limits.Allow(id.user, u.res.URL, call)
	return ok
}

// event is the access-log line of an aggregate request on upstream u.
func (a *Aggregate) event(id ident, req mcp.Request, u upstream, method, tool string, args json.RawMessage, decision string, status int, start time.Time) {
	ev := bridge.Event{
		User: id.user, Client: id.client, Resource: u.res.URL, Via: "aggregate", Method: method, Tool: tool, Args: args,
		Decision: decision, RequestID: requestID(req), UpstreamStatus: status, Duration: a.now().Sub(start),
	}
	if u.res.Kind == config.KindCompanion {
		ev.Instance, ev.Companion = u.res.Instance, u.res.Companion
	}
	a.emit(ev)
}

// sizer bounds one upstream's listing as it is read, page by page: its
// own encoded size (maxUpstreamBytes) and the refresh's running total
// over every upstream (maxTotalBytes).
type sizer struct {
	own   int
	total *atomic.Int64
}

func (s *sizer) add(v any) bool {
	n := encodedSize(v)
	s.own += n
	t := s.total.Add(int64(n))
	return s.own <= maxUpstreamBytes && t <= int64(maxTotalBytes)
}

func (a *Aggregate) list(ctx context.Context, u upstream, req mcp.Request, id ident, sz *sizer) listing {
	if u.people {
		return a.listPeople(ctx, u, req, id, sz)
	}
	var l listing
	via := bridge.Via{User: id.user, Bound: id.url}
	ss, _ := req.GetSession().(*mcp.ServerSession)
	extra := req.GetExtra()
	cursor := ""
	for page := 0; ; page++ {
		if page == maxPages || len(l.tools) >= maxItems {
			return listing{err: errTooBig}
		}
		if !a.allow(id, u, false) {
			a.event(id, req, u, mcp.MethodListTools, "", nil, "rate_limited", 0, a.now())
			return listing{err: errRateLimited}
		}
		r, err := a.cfg.Bridge.Forward(ctx, via, u.res, mcp.MethodListTools, &mcp.ListToolsRequest{Session: ss, Params: &mcp.ListToolsParams{Cursor: cursor}, Extra: extra})
		if err != nil {
			return listing{err: err}
		}
		lt, ok := r.(*mcp.ListToolsResult)
		if !ok {
			return listing{err: errors.New("not a tools list")}
		}
		if !sz.add(lt.Tools) {
			return listing{err: errTooBig}
		}
		l.tools = append(l.tools, lt.Tools...)
		if lt.NextCursor == "" {
			break
		}
		cursor = lt.NextCursor
	}
	// Resources and prompts: an upstream without them (or failing them)
	// still offers its tools.
	cursor = ""
	for page := 0; page < maxPages && len(l.resources) < maxItems; page++ {
		r, err := a.cfg.Bridge.Forward(ctx, via, u.res, mcp.MethodListResources, &mcp.ListResourcesRequest{Session: ss, Params: &mcp.ListResourcesParams{Cursor: cursor}, Extra: extra})
		lr, ok := r.(*mcp.ListResourcesResult)
		if err != nil || !ok {
			break
		}
		if !sz.add(lr.Resources) {
			return listing{err: errTooBig}
		}
		l.resources = append(l.resources, lr.Resources...)
		if lr.NextCursor == "" {
			break
		}
		cursor = lr.NextCursor
	}
	cursor = ""
	for page := 0; page < maxPages && len(l.prompts) < maxItems; page++ {
		r, err := a.cfg.Bridge.Forward(ctx, via, u.res, mcp.MethodListPrompts, &mcp.ListPromptsRequest{Session: ss, Params: &mcp.ListPromptsParams{Cursor: cursor}, Extra: extra})
		lp, ok := r.(*mcp.ListPromptsResult)
		if err != nil || !ok {
			break
		}
		if !sz.add(lp.Prompts) {
			return listing{err: errTooBig}
		}
		l.prompts = append(l.prompts, lp.Prompts...)
		if lp.NextCursor == "" {
			break
		}
		cursor = lp.NextCursor
	}
	l.resources = capItems(l.resources)
	l.prompts = capItems(l.prompts)
	return l
}

func capItems[T any](s []T) []T {
	if len(s) > maxItems {
		return s[:maxItems]
	}
	return s
}

func (a *Aggregate) listPeople(ctx context.Context, u upstream, req mcp.Request, id ident, sz *sizer) listing {
	dctx, cancel := detach(ctx)
	defer cancel()
	start := a.now()
	if !a.allow(id, u, false) {
		a.event(id, req, u, mcp.MethodListTools, "", nil, "rate_limited", 0, start)
		return listing{err: errRateLimited}
	}
	cs, err := a.cfg.Portcullis.People(dctx, id.user, id.client, u.res.URL)
	if err != nil {
		a.event(id, req, u, mcp.MethodListTools, "", nil, "deny:upstream", 0, start)
		return listing{err: err}
	}
	var l listing
	cursor := ""
	for page := 0; ; page++ {
		if page == maxPages || len(l.tools) >= maxItems {
			return listing{err: errTooBig}
		}
		start := a.now()
		r, err := cs.ListTools(dctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			a.event(id, req, u, mcp.MethodListTools, "", nil, "deny:upstream", 502, start)
			a.cfg.Portcullis.Broken(id.user, cs)
			return listing{err: err}
		}
		a.event(id, req, u, mcp.MethodListTools, "", nil, "allow", 200, start)
		if !sz.add(r.Tools) {
			return listing{err: errTooBig}
		}
		for _, t := range r.Tools {
			if t != nil && bridge.ValidToolName(t.Name) && !isDelegate(t.Name) {
				l.tools = append(l.tools, t)
			}
		}
		if r.NextCursor == "" {
			break
		}
		cursor = r.NextCursor
	}
	caps := cs.InitializeResult()
	if caps != nil && caps.Capabilities != nil && caps.Capabilities.Resources != nil {
		start := a.now()
		if r, err := cs.ListResources(dctx, &mcp.ListResourcesParams{}); err == nil {
			a.event(id, req, u, mcp.MethodListResources, "", nil, "allow", 200, start)
			if !sz.add(r.Resources) {
				return listing{err: errTooBig}
			}
			l.resources = capItems(r.Resources)
		}
	}
	if caps != nil && caps.Capabilities != nil && caps.Capabilities.Prompts != nil {
		start := a.now()
		if r, err := cs.ListPrompts(dctx, &mcp.ListPromptsParams{}); err == nil {
			a.event(id, req, u, mcp.MethodListPrompts, "", nil, "allow", 200, start)
			if !sz.add(r.Prompts) {
				return listing{err: errTooBig}
			}
			l.prompts = capItems(r.Prompts)
		}
	}
	return l
}

// ---- routing calls ----

var denyText = map[string]string{
	"population": "you no longer have access to %s",
	"loa":        "%s needs a stronger sign-in than this connection has",
	"client":     "%s isn't available to this AI client",
	"off":        "AI support for %s is off",
}

// route: tools/call, resources/read and prompts/get, through the table to
// their upstream, with that upstream's own rules.
func (a *Aggregate) route(ctx context.Context, e *entry, method string, req mcp.Request, id ident) (mcp.Result, error) {
	start := a.now()
	var name string
	var tab map[string]Target
	switch p := req.GetParams().(type) {
	case *mcp.CallToolParamsRaw:
		if p == nil {
			a.refused(req, id, method, "deny:bad_arguments")
			return nil, rpcError(mcp.CodeInvalidParams, "missing params")
		}
		name = p.Name
	case *mcp.ReadResourceParams:
		if p == nil {
			a.refused(req, id, method, "deny:bad_arguments")
			return nil, rpcError(mcp.CodeInvalidParams, "missing params")
		}
		name = p.URI
	case *mcp.GetPromptParams:
		if p == nil {
			a.refused(req, id, method, "deny:bad_arguments")
			return nil, rpcError(mcp.CodeInvalidParams, "missing params")
		}
		name = p.Name
	default:
		a.refused(req, id, method, "deny:bad_arguments")
		return nil, rpcError(mcp.CodeInvalidParams, "missing params")
	}
	lookup := func() (Target, bool) {
		e.mu.Lock()
		defer e.mu.Unlock()
		switch method {
		case mcp.MethodCallTool:
			tab = e.tools
		case mcp.MethodGetPrompt:
			tab = e.prompts
		default:
			tab = e.resources
		}
		t, ok := tab[name]
		return t, ok
	}
	// The name in the table before a refresh: if the refresh drops it,
	// the refusal is logged with that upstream's own reason (client,
	// population, loa, off), not as an unknown name.
	before, hadBefore := lookup()
	a.ensure(ctx, e, req, id, true)
	t, found := lookup()
	if !found && hadBefore {
		// Logged with the old upstream's reason only when that upstream
		// refuses the person now; otherwise the name is simply gone.
		if _, reason := a.admit(byURL(a.cfg.Snapshot(), before.URL), e.key); reason != "" {
			t, found = before, true // refused below, with its reason
		}
	}
	if !found {
		// Logged on the aggregate itself: no upstream was chosen.
		tool := ""
		if method == mcp.MethodCallTool {
			tool = name
		}
		a.emit(bridge.Event{User: id.user, Client: id.client, Resource: id.url, Via: "aggregate", Method: method, Tool: tool,
			Decision: "deny:unknown", RequestID: requestID(req), Duration: a.now().Sub(start)})
		return nil, rpcError(mcp.CodeInvalidParams, fmt.Sprintf("unknown name %q", clip(name, 128)))
	}
	sn := a.cfg.Snapshot()
	cur := byURL(sn, t.URL)
	u, reason := a.admit(cur, e.key)
	if reason != "" {
		if cur == nil {
			cur = &config.Resource{URL: t.URL, Label: "this app"}
		}
		a.event(id, req, upstream{res: cur}, method, toolOf(method, t.Name), nil, "deny:"+reason, 0, start)
		return nil, rpcError(mcp.CodeInvalidParams, fmt.Sprintf(denyText[reason], cur.Label))
	}
	if !a.allow(id, u, method == mcp.MethodCallTool) {
		a.event(id, req, u, method, toolOf(method, t.Name), nil, "rate_limited", 0, start)
		msg := "Too many requests to " + u.label() + "; try again later"
		if method == mcp.MethodCallTool {
			return isErrorResult(msg), nil
		}
		return nil, rpcError(mcp.CodeInternalError, msg)
	}
	if u.people {
		return a.people(ctx, req, method, u, id, t.Name, start)
	}
	via := bridge.Via{User: id.user, Bound: id.url}
	switch r := req.(type) {
	case *mcp.CallToolRequest:
		cp, p := *r, *r.Params
		p.Name = t.Name
		cp.Params = &p
		return a.cfg.Bridge.Forward(ctx, via, u.res, method, &cp)
	case *mcp.GetPromptRequest:
		cp, p := *r, *r.Params
		p.Name = t.Name
		cp.Params = &p
		return a.cfg.Bridge.Forward(ctx, via, u.res, method, &cp)
	case *mcp.ReadResourceRequest:
		return a.cfg.Bridge.Forward(ctx, via, u.res, method, r)
	}
	return nil, rpcError(mcp.CodeInvalidParams, "missing params")
}

func toolOf(method, name string) string {
	if method == mcp.MethodCallTool {
		return name
	}
	return ""
}

// people runs one call on the Hub's /mcp/people: canonical arguments, the
// delegate tools refused (G38), the Hub's answer as it is (its own
// confirmations, text form) — never an input request passed on.
func (a *Aggregate) people(ctx context.Context, req mcp.Request, method string, u upstream, id ident, name string, start time.Time) (mcp.Result, error) {
	var args json.RawMessage
	if method == mcp.MethodCallTool {
		p := req.GetParams().(*mcp.CallToolParamsRaw)
		c, err := canon.Arguments(p.Arguments)
		if err != nil {
			a.event(id, req, u, method, name, nil, "deny:bad_arguments", 0, start)
			return nil, rpcError(mcp.CodeInvalidParams, "arguments Portcullis can't check (they must be one JSON object without repeated keys, with numbers that keep their exact value)")
		}
		args = c
		if isDelegate(name) || !bridge.ValidToolName(name) {
			a.event(id, req, u, method, name, args, "deny:never", 0, start)
			return nil, rpcError(mcp.CodeInvalidParams, name+" is only on your Portcullis connector, not in All my apps")
		}
	}
	dctx, cancel := detach(ctx)
	defer cancel()
	cctx, ccancel := context.WithTimeout(dctx, a.callTimeout(a.cfg.Snapshot()))
	defer ccancel()
	cs, err := a.cfg.Portcullis.People(cctx, id.user, id.client, u.res.URL)
	if err != nil {
		a.event(id, req, u, method, toolOf(method, name), args, "deny:upstream", 0, start)
		return a.unavailable(method, u)
	}
	var out mcp.Result
	switch method {
	case mcp.MethodCallTool:
		var r *mcp.CallToolResult
		r, err = cs.CallTool(cctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err == nil && r.NeedsInput() {
			a.event(id, req, u, method, name, args, "deny:input", 200, start)
			return isErrorResult("Portcullis asked for more input here, which All my apps doesn't pass on; use your Portcullis connector"), nil
		}
		out = r
	case mcp.MethodGetPrompt:
		p := req.GetParams().(*mcp.GetPromptParams)
		var r *mcp.GetPromptResult
		r, err = cs.GetPrompt(cctx, &mcp.GetPromptParams{Name: name, Arguments: p.Arguments})
		if err == nil && r.NeedsInput() {
			err = rpcError(mcp.CodeInternalError, "Portcullis asked for input here, which All my apps doesn't pass on")
		} else if err == nil {
			out = &mcp.GetPromptResult{Description: r.Description, Messages: r.Messages}
		}
	case mcp.MethodReadResource:
		var r *mcp.ReadResourceResult
		r, err = cs.ReadResource(cctx, &mcp.ReadResourceParams{URI: name})
		if err == nil && r.NeedsInput() {
			err = rpcError(mcp.CodeInternalError, "Portcullis asked for input here, which All my apps doesn't pass on")
		} else if err == nil {
			out = &mcp.ReadResourceResult{Contents: r.Contents}
		}
	}
	if err != nil {
		var re *mcp.RPCError
		if errors.As(err, &re) {
			// The Hub answered, with an error: passed on, logged as a
			// failure of the upstream.
			a.event(id, req, u, method, toolOf(method, name), args, "deny:upstream", 200, start)
			return nil, rpcError(re.Code, re.Message)
		}
		a.event(id, req, u, method, toolOf(method, name), args, "deny:upstream", 502, start)
		a.cfg.Portcullis.Broken(id.user, cs)
		return a.unavailable(method, u)
	}
	a.event(id, req, u, method, toolOf(method, name), args, "allow", 200, start)
	return out, nil
}

func (a *Aggregate) unavailable(method string, u upstream) (mcp.Result, error) {
	return nil, rpcError(mcp.CodeInternalError, u.label()+" is unavailable right now")
}

// ---- keeping in line with the snapshot ----

// Reconcile applies the current snapshot to every person at once: someone
// no longer in the aggregate's population loses their sessions; every
// name whose upstream the person can no longer use leaves their registry
// now (subscribed clients get list_changed) and their tables; everything
// else is refreshed at the next request. Idle entries go.
func (a *Aggregate) Reconcile() {
	sn := a.cfg.Snapshot()
	now := a.now()
	agg := aggregateOf(sn)
	a.mu.Lock()
	a.lastSn = sn
	var drop []*entry
	var keep []*entry
	for k, e := range a.entries {
		e.mu.Lock()
		idle := len(e.order) == 0 && now.Sub(e.lastUse) > a.cfg.IdleTimeout
		e.mu.Unlock()
		if agg == nil || !agg.Member(k.user, now) || k.loa < agg.MinLoA || idle {
			drop = append(drop, e)
			delete(a.entries, k)
			continue
		}
		keep = append(keep, e)
	}
	a.mu.Unlock()
	for _, e := range drop {
		a.closeEntry(e)
		if a.cfg.Portcullis != nil {
			a.cfg.Portcullis.DropClient(e.key.user, e.key.client)
		}
	}
	for _, e := range keep {
		a.prune(e, sn)
	}
}

// prune removes the names whose upstream the person may no longer use.
func (a *Aggregate) prune(e *entry, sn *config.Snapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sn != sn {
		e.stale = true
	}
	ok := func(t Target) bool {
		_, reason := a.admit(byURL(sn, t.URL), e.key)
		return reason == ""
	}
	var tools, prompts, res []string
	for n, t := range e.tools {
		if !ok(t) {
			tools = append(tools, n)
			delete(e.tools, n)
			delete(e.regTools, n)
		}
	}
	for n, t := range e.prompts {
		if !ok(t) {
			prompts = append(prompts, n)
			delete(e.prompts, n)
			delete(e.regPrompt, n)
		}
	}
	for n, t := range e.resources {
		if !ok(t) {
			res = append(res, n)
			delete(e.resources, n)
			delete(e.regRes, n)
		}
	}
	if len(tools) > 0 {
		e.server.RemoveTools(tools...)
	}
	if len(prompts) > 0 {
		e.server.RemovePrompts(prompts...)
	}
	if len(res) > 0 {
		e.server.RemoveResources(res...)
	}
}

func (a *Aggregate) closeEntry(e *entry) {
	for ss := range e.server.Sessions() {
		_ = ss.Close()
	}
}

// Run reconciles on every snapshot change (polled every second) and once a
// minute, until Close.
func (a *Aggregate) Run() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := time.Time{}
	for {
		select {
		case <-a.stop:
			return
		case <-tick.C:
		}
		a.mu.Lock()
		changed := a.cfg.Snapshot() != a.lastSn
		a.mu.Unlock()
		if changed || a.now().Sub(last) > time.Minute {
			a.Reconcile()
			last = a.now()
		}
	}
}

// Close stops Run and closes every session.
func (a *Aggregate) Close() {
	a.stopOnce.Do(func() { close(a.stop) })
	a.mu.Lock()
	es := a.entries
	a.entries = map[ekey]*entry{}
	a.mu.Unlock()
	for _, e := range es {
		a.closeEntry(e)
	}
}
