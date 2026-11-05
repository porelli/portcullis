package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/portcullis/mcp-gate/internal/accesslog"
	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/bridge"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/confirm"
	"github.com/portcullis/mcp-gate/internal/hubapi"
	"github.com/portcullis/mcp-gate/internal/limits"
)

// Task 3b wiring: the Hub API client fills the bridge's minter and
// confirmer, the limits and the access log sit in front of the bridge
// (handler, main.go), and every MCP request gets exactly one access-log
// line — the bridge's event for a forwarded request, else the handler's.

// gateOptions: serve passes the production values; tests override Base,
// MintWait/MintPoll and LogGroup.
type gateOptions struct {
	Snapshot           func() *config.Snapshot
	Verifier           *authz.Verifier
	Hub                *hubapi.Client
	HubSecret          string
	LogPath            string
	LogGroup           int
	Base               http.RoundTripper
	MintWait, MintPoll time.Duration
}

type gate struct {
	handler   http.Handler
	bridge    *bridge.Bridge
	log       *accesslog.Log
	act       *activity
	lim       *limits.Limiter
	minter    *hubMinter
	confirmer *confirm.Gate
}

func newGate(o gateOptions) (*gate, error) {
	if o.Hub == nil {
		return nil, errors.New("no Hub API client")
	}
	act := &activity{snap: o.Snapshot, hubSecret: o.HubSecret}
	alog, err := accesslog.OpenWith(o.LogPath, accesslog.Options{Retention: accesslog.DefaultRetention, Group: o.LogGroup, Secrets: act.secrets})
	if err != nil {
		return nil, err
	}
	act.log, act.healthy = alog, alog.Healthy
	lim := limits.New(func() config.Limits {
		if sn := o.Snapshot(); sn != nil && sn.File != nil {
			return sn.File.Limits
		}
		return limits.Defaults
	}, nil)
	m := &hubMinter{hub: o.Hub, lim: lim}
	conf := &confirm.Gate{Hub: o.Hub, Limits: lim, Snapshot: o.Snapshot}
	b := bridge.New(bridge.Config{
		Snapshot: o.Snapshot, Minter: m, Confirm: conf, OnEvent: act.event, Base: o.Base,
		MintWait: o.MintWait, MintPoll: o.MintPoll,
	})
	return &gate{
		handler: newHandler(o.Snapshot, o.Verifier, b, &handlerDeps{lim: lim, act: act}),
		bridge:  b, log: alog, act: act, lim: lim, minter: m, confirmer: conf,
	}, nil
}

func (g *gate) Close() {
	g.bridge.Close()
	_ = g.log.Close()
}

// hubMinter is the bridge's Minter: the gate's mints_per_minute, then the
// Hub's POST /internal/credentials. Hub errors other than the listed
// answers stay as they are: the bridge answers them "can't check this
// right now; try again" (G26).
type hubMinter struct {
	hub *hubapi.Client
	lim *limits.Limiter
}

func (m *hubMinter) Mint(ctx context.Context, resource, user string) error {
	if !m.lim.AllowMint(user) {
		return bridge.ErrRateLimited
	}
	_, err := m.hub.Mint(ctx, resource, user)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, hubapi.ErrNoAccount):
		return bridge.ErrNoAccount
	case errors.Is(err, hubapi.ErrMintFailed):
		return bridge.ErrMintFailed
	case errors.Is(err, hubapi.ErrNotAllowed):
		return bridge.ErrNotAllowed
	}
	return err
}

// handlerDeps: the handler's limits and access log.
type handlerDeps struct {
	lim *limits.Limiter
	act *activity
}

// activity writes access-log lines (§15.8) and keeps the pending HTTP
// requests whose line the bridge writes.
type activity struct {
	log       *accesslog.Log
	healthy   func() bool
	snap      func() *config.Snapshot
	hubSecret string
	pending   sync.Map // request id → *atomic.Bool (the bridge wrote its line)

	mu      sync.Mutex
	cacheSn *config.Snapshot
	cache   []string
}

// secrets: everything the gate knows that must never be in a line — every
// decrypted credential and caller secret, and the hub secret.
func (a *activity) secrets() []string {
	sn := a.snap()
	a.mu.Lock()
	defer a.mu.Unlock()
	if sn == a.cacheSn && a.cache != nil {
		return a.cache
	}
	out := []string{a.hubSecret}
	if sn != nil {
		for _, c := range sn.Creds {
			out = append(out, c.Secret)
		}
		for _, s := range sn.Secrets {
			out = append(out, s)
		}
	}
	a.cacheSn, a.cache = sn, out
	return out
}

var methodR = regexp.MustCompile(`^[a-z]+(/[A-Za-z_]+){0,3}$`)

// logMethod / logTool: only well-formed names reach the log (a client
// controls them); anything else is "[invalid]".
func logMethod(m string) string {
	if m == "" || (len(m) <= 64 && methodR.MatchString(m)) {
		return m
	}
	return "[invalid]"
}

func logTool(method, tool string) string {
	if method != "tools/call" {
		return ""
	}
	if bridge.ValidToolName(tool) {
		return tool
	}
	return "[invalid]"
}

// digestFor is args_sha256 for a tools/call ("" otherwise, or when the
// arguments are not JSON).
func digestFor(method string, args json.RawMessage) string {
	if method != "tools/call" {
		return ""
	}
	d, err := confirm.ArgsDigest(args)
	if err != nil {
		return ""
	}
	return d
}

func (a *activity) write(l accesslog.Line, low bool) {
	var err error
	if low {
		err = a.log.WriteLow(l)
	} else {
		err = a.log.Write(l)
	}
	_ = err // counted by the log; Healthy() turns false when it matters (G28)
}

// event is the bridge's OnEvent.
func (a *activity) event(ev bridge.Event) {
	if ev.RequestID != "" {
		if p, ok := a.pending.Load(ev.RequestID); ok {
			p.(*atomic.Bool).Store(true)
		}
	}
	via := ev.Via
	if via == "" {
		via = "direct"
	}
	m := logMethod(ev.Method)
	a.write(accesslog.Line{
		Time: time.Now(), User: ev.User, Client: ev.Client, Resource: ev.Resource,
		Instance: ev.Instance, Companion: ev.Companion, Via: via, Method: m,
		Tool: logTool(m, ev.Tool), ArgsSHA256: digestFor(m, ev.Args), Decision: ev.Decision,
		UpstreamStatus: ev.UpstreamStatus, DurationMS: ev.Duration.Milliseconds(),
	}, false)
}

// begin registers an HTTP request about to be forwarded; done reports
// whether the bridge wrote its line.
func (a *activity) begin() (id string, done func() bool) {
	id = rand.Text()
	flag := new(atomic.Bool)
	a.pending.Store(id, flag)
	return id, func() bool {
		a.pending.Delete(id)
		return flag.Load()
	}
}

// reqInfo is what the handler knows of a request for its line.
type reqInfo struct {
	start          time.Time
	d              authz.Decision
	method, tool   string
	args           json.RawMessage
	upstreamStatus int
}

func (a *activity) line(ri reqInfo, decision string) accesslog.Line {
	l := accesslog.Line{Time: time.Now(), User: ri.d.User, Client: ri.d.Client, Via: "direct", Decision: decision,
		DurationMS: time.Since(ri.start).Milliseconds(), UpstreamStatus: ri.upstreamStatus}
	if res := ri.d.Resource; res != nil {
		l.Resource = res.URL
		if res.Kind == config.KindCompanion {
			l.Instance, l.Companion = res.Instance, res.Companion
		}
	}
	l.Method = logMethod(ri.method)
	l.Tool = logTool(l.Method, ri.tool)
	l.ArgsSHA256 = digestFor(l.Method, ri.args)
	return l
}

// fallbackDecision words a request the bridge answered without
// forwarding it (initialize, notifications, GET, DELETE, refusals).
func fallbackDecision(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "allow"
	case status == http.StatusBadRequest:
		return "deny:protocol"
	case status == http.StatusForbidden:
		return "deny:population"
	case status == http.StatusNotFound:
		return "deny:session"
	case status == http.StatusMethodNotAllowed:
		return "deny:method"
	case status == http.StatusRequestEntityTooLarge:
		return "deny:too_large"
	case status == http.StatusServiceUnavailable:
		return "deny:off"
	}
	return "deny:refused"
}

// retryAfter is the Retry-After value: whole seconds, at least 1.
func retryAfter(d time.Duration) string {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return fmt.Sprint(s)
}

// statusWriter records the status a forwarded request got.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
