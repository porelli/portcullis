// Command mcp-gate is Portcullis' MCP gate (integration contract §15): it
// terminates every MCP request, checks the Keycloak access token for
// exactly the resource the request's Host and path name, checks that the
// person is in that resource's population right now, and serves each
// resource's RFC 9728 metadata. It reads the Hub's files in hub_data
// read-only (§4.2, §15.4).
//
//	mcp-gate [serve]      run the gate
//	mcp-gate keygen       print a new age X25519 identity (secrets/mcp-gate/age.key);
//	                      its recipient (age.pub) is the "# public key:" line
//	mcp-gate healthcheck  exit 0 if the gate answers /healthz (Docker HEALTHCHECK)
//
// Environment: MCP_GATE_LISTEN (:8080), MCP_GATE_HUB_DATA (/hub-data),
// MCP_GATE_DATA (/data), MCP_GATE_AGE_KEY_FILE, MCP_GATE_HUB_SECRET_FILE,
// MCP_GATE_JWKS_URL, MCP_GATE_HUB_URL (http://hub:8890).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/portcullis/mcp-gate/internal/accesslog"
	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/bridge"
	"github.com/portcullis/mcp-gate/internal/canon"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/hubapi"
	"github.com/portcullis/mcp-gate/internal/limits"
	"github.com/portcullis/mcp-gate/internal/mcpsdk"
	"github.com/portcullis/mcp-gate/internal/meta"
)

const (
	defaultListen     = ":8080"
	defaultHubData    = "/hub-data"
	defaultData       = "/data"
	defaultAgeKey     = "/run/portcullis/mcp-gate/age.key"
	defaultHubSecret  = "/run/portcullis/mcp-gate/hub-secret"
	defaultJWKS       = "http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs"
	defaultHubURL     = "http://hub:8890"
	minHubSecretChars = 32
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "keygen":
		id, err := age.GenerateX25519Identity()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), id.Recipient(), id)
	case "healthcheck":
		os.Exit(healthcheck(env("MCP_GATE_LISTEN", defaultListen)))
	case "serve":
		if err := serve(); err != nil {
			log.Fatalf("mcp-gate: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: mcp-gate [serve|keygen|healthcheck]\n")
		os.Exit(2)
	}
}

func healthcheck(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	// The detail line (if any) goes to Docker's health log.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_, _ = os.Stdout.Write(b)
	return 0
}

// RefusingPrefix starts /healthz's second line while the Hub's files are
// refused (every AI resource answers 503); scripts/lib/status.sh greps it.
const RefusingPrefix = "refusing every AI request (503): "

func loadIdentity(path string) (age.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("age identity: %w", err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("age identity %s: not exactly one X25519 identity", path)
	}
	if _, ok := ids[0].(*age.X25519Identity); !ok {
		return nil, fmt.Errorf("age identity %s: not an X25519 identity", path)
	}
	return ids[0], nil
}

func loadHubSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hub secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if len(s) < minHubSecretChars {
		return "", fmt.Errorf("hub secret %s: shorter than %d characters", path, minHubSecretChars)
	}
	return s, nil
}

func serve() error {
	ident, err := loadIdentity(env("MCP_GATE_AGE_KEY_FILE", defaultAgeKey))
	if err != nil {
		return err
	}
	// The gate only presents the secret (hubapi sends it on every Hub
	// call); it never receives one to check. Any comparison of a
	// presented secret with it must use crypto/subtle.ConstantTimeCompare
	// (the Hub's side does, Task 13), never == or bytes.Equal.
	hubSecret, err := loadHubSecret(env("MCP_GATE_HUB_SECRET_FILE", defaultHubSecret))
	if err != nil {
		return err
	}
	hub, err := hubapi.New(env("MCP_GATE_HUB_URL", defaultHubURL), hubSecret)
	if err != nil {
		return err
	}
	store, err := config.Open(env("MCP_GATE_HUB_DATA", defaultHubData), ident)
	if err != nil {
		return err
	}
	defer store.Close()
	v := authz.NewVerifier("", env("MCP_GATE_JWKS_URL", defaultJWKS), nil)
	g, err := newGate(gateOptions{
		Snapshot: store.Snapshot, Verifier: v, Hub: hub, HubSecret: hubSecret, HubURL: env("MCP_GATE_HUB_URL", defaultHubURL),
		LogPath:  filepath.Join(env("MCP_GATE_DATA", defaultData), "access.jsonl"),
		LogGroup: accesslog.DefaultGroup,
	})
	if err != nil {
		return err
	}
	defer g.Close()
	go g.bridge.Run()
	go g.agg.Run()

	srv := newServer(env("MCP_GATE_LISTEN", defaultListen), g.handler)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("mcp-gate: listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// bodyReadTimeout bounds reading an allowed request's body (8 MiB at
// most), on top of the server's ReadTimeout.
var bodyReadTimeout = 30 * time.Second

// newServer: headers within 10 s, a whole request (headers + body) within
// 60 s, idle keep-alive 120 s, 64 KiB of headers. No WriteTimeout: MCP
// answers may stream (SSE) for up to the upstream timeout (120 s); the
// bridge (task 3) bounds each response itself.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// forwarder serves an allowed request of a companion resource (the bridge).
type forwarder interface {
	ServeResource(w http.ResponseWriter, r *http.Request, d authz.Decision)
}

// newHandler: /healthz (loopback only), the metadata documents, and every
// other request through authz, the body cap, the protocol checks, the
// unloggable-call refusal (G28) and the limits (§15.9); allowed companion
// requests go to fwd. Every MCP request gets one access-log line (§15.8):
// the bridge's for a forwarded one, else the handler's. Nothing here sets
// or reads a cookie.
func newHandler(snap func() *config.Snapshot, v *authz.Verifier, fwd forwarder, deps *handlerDeps) http.Handler {
	metaH := meta.Handler(snap)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only a plain origin-form, unescaped path is routed (fix round 1).
		if _, ok := authz.Target(r); !ok {
			http.Error(w, "bad request target", http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/healthz" && isLoopback(r.RemoteAddr) {
			// Still 200 (Traefik drops unhealthy containers; the gate's own
			// 503 says more): the second line is what `mcp-gate
			// healthcheck` prints into Docker's health log, which
			// `./portcullis status` shows (final review, docs M4).
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
			if sn := snap(); sn != nil && sn.Err != nil {
				_, _ = io.WriteString(w, RefusingPrefix+sn.Err.Error()+"\n")
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, meta.Prefix) {
			metaH.ServeHTTP(w, r)
			return
		}
		ri := reqInfo{start: time.Now()}
		var ticket *limits.Ticket
		sn := snap()
		d := v.Check(r.Context(), sn, authz.FromHTTP(r, time.Now()))
		ri.d = d
		if !d.Allowed() {
			refuse(w, r, d)
			// Every refusal is low priority (signed in or not): a flood of
			// them can't fill the queue and make tools/call unloggable.
			deps.act.refused(ri, "deny:"+d.Reason)
			return
		}
		max := sn.File.Limits.MaxRequestBytes
		// Memory bounds (final review I3): a person's POSTs in flight and
		// the gate-wide body budget, both taken before the body is read.
		if r.Method == http.MethodPost && deps.inflight != nil {
			charge := limits.Charge(max)
			if r.ContentLength >= 0 && r.ContentLength <= max {
				charge = limits.Charge(r.ContentLength)
			}
			t, err := deps.inflight.Admit(r.Context(), d.User, charge)
			if err != nil {
				w.Header().Set("Retry-After", "1")
				if errors.Is(err, limits.ErrPersonBusy) {
					http.Error(w, "too many requests in flight; try again later", http.StatusTooManyRequests)
					deps.act.refused(ri, "rate_limited")
				} else {
					http.Error(w, "the gate is busy; try again later", http.StatusServiceUnavailable)
					deps.act.refused(ri, "deny:busy")
				}
				return
			}
			defer t.Done()
			ticket = t
		}
		// A trickling body can't hold the connection: a read deadline per
		// request (ErrNotSupported only outside a real server, in tests).
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyReadTimeout))
		body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				http.Error(w, "request body too slow", http.StatusRequestTimeout)
				deps.act.refused(ri, "deny:body_timeout")
				return
			}
			http.Error(w, "cannot read the request", http.StatusBadRequest)
			deps.act.refused(ri, "deny:protocol")
			return
		}
		if int64(len(body)) > max {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			deps.act.refused(ri, "deny:too_large")
			return
		}
		ticket.Shrink(int64(len(body)))
		if _, perr := authz.CheckProtocol(r.Header, body); perr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(perr.Status)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, perr.Code, perr.Msg)
			deps.act.refused(ri, "deny:protocol")
			return
		}
		var callOK bool
		ri.method, ri.tool, ri.args, callOK = parseCall(body)
		if !callOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, mcpsdk.CodeInvalidRequest, "tools/call params must be one object with distinct keys")
			deps.act.refused(ri, "deny:protocol")
			return
		}
		toolCall := ri.method == "tools/call"
		// G28 (final review I2): a tools/call is forwarded only with its
		// access-log slot reserved first, so its line can't be dropped;
		// no slot (writer failing or stuck, queue full) = refused.
		// initialize and the lists go on.
		var res *accesslog.Reservation
		if toolCall {
			if res = deps.act.reserve(); res == nil {
				http.Error(w, "AI activity can't be logged right now", http.StatusServiceUnavailable)
				deps.act.refused(ri, "deny:unloggable")
				return
			}
		}
		// Whatever slot no line used goes back.
		defer res.Release()
		if ok, wait := deps.lim.Allow(d.User, d.Resource.URL, toolCall); !ok {
			w.Header().Set("Retry-After", retryAfter(wait))
			http.Error(w, "too many requests; try again later", http.StatusTooManyRequests)
			deps.act.refused(ri, "rate_limited")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		// Forwarded through the bridge (companions) or the aggregate: one
		// line per upstream call from their events, else the handler's.
		viaEvents := func(serve func(w http.ResponseWriter, r *http.Request)) {
			id, done := deps.act.begin(res)
			r.Header.Set(bridge.RequestIDHeader, id) // replaces anything the client sent
			sw := &statusWriter{ResponseWriter: w}
			serve(sw, r)
			wrote, left := done()
			if left != nil && !wrote {
				// No event: the handler's line goes in the reserved slot
				// (a refused call's too). An unused slot goes back (defer).
				_ = left.Write(deps.act.line(ri, fallbackDecision(sw.status)))
			} else if !wrote {
				if dec := fallbackDecision(sw.status); dec == "allow" {
					deps.act.write(deps.act.line(ri, dec), false)
				} else {
					deps.act.refused(ri, dec)
				}
			}
		}
		switch k := d.Resource.Kind; {
		case k == config.KindCompanion && fwd != nil:
			viaEvents(func(w http.ResponseWriter, r *http.Request) { fwd.ServeResource(w, r, d) })
			return
		case k == config.KindAggregate && deps.agg != nil:
			viaEvents(func(w http.ResponseWriter, r *http.Request) { deps.agg.ServeHTTP(w, r, d) })
			return
		case (k == config.KindAdmin || k == config.KindPeople) && deps.hub != nil:
			// The Portcullis MCP (G25): the same pipeline as above, then
			// the Hub; one line with the Hub's status.
			r.Header.Del(bridge.RequestIDHeader)
			// One form of the arguments on every resource (final review
			// M1): what the bridge and the aggregate refuse, the Hub never
			// gets, and every logged tools/call has its args_sha256.
			if toolCall {
				if _, err := canon.Arguments(ri.args); err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, mcpsdk.CodeInvalidParams, "arguments Portcullis can't check (they must be one JSON object without repeated keys, with numbers that keep their exact value)")
					_ = res.Write(deps.act.line(ri, "deny:bad_arguments"))
					return
				}
			}
			sw := &statusWriter{ResponseWriter: w}
			ri.upstreamStatus = deps.hub.Serve(sw, r, d)
			dec := fallbackDecision(sw.status)
			if ri.upstreamStatus == 0 && sw.status == http.StatusBadGateway {
				dec = "deny:upstream"
			}
			if res != nil {
				_ = res.Write(deps.act.line(ri, dec))
			} else if dec == "allow" {
				deps.act.write(deps.act.line(ri, dec), false)
			} else {
				deps.act.refused(ri, dec)
			}
			return
		}
		// A kind with nothing wired to it: refused, never answered without
		// its upstream.
		log.Printf("mcp-gate: %s %s%q user=%q client=%q allow (no forwarding for %s)", r.Method, d.Resource.Host, d.Resource.Path(), d.User, d.Client, d.Resource.Kind)
		http.Error(w, "MCP forwarding is not available in this build", http.StatusServiceUnavailable)
		deps.act.refused(ri, "deny:unavailable")
	})
}

// parseCall: the JSON-RPC method of a checked body ("" for a response or
// an empty body) and, for tools/call, the tool name and raw arguments
// (only ever hashed) as the SDK decodes them (mcpsdk.CallParams). ok is
// false for tools/call params the SDK could read differently from the
// gate (repeated or case-variant keys) or can't read at all: refused.
func parseCall(body []byte) (method, tool string, args json.RawMessage, ok bool) {
	if len(body) == 0 {
		return "", "", nil, true
	}
	msg, err := mcpsdk.Decode(body)
	if err != nil || !msg.IsRequest {
		return "", "", nil, true
	}
	if msg.Method != "tools/call" {
		return msg.Method, "", nil, true
	}
	name, a, err := mcpsdk.CallParams(msg.Params)
	if err != nil {
		return msg.Method, "", nil, false
	}
	return msg.Method, name, a, true
}

func refuse(w http.ResponseWriter, r *http.Request, d authz.Decision) {
	if d.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", d.WWWAuthenticate)
	}
	// Never the Authorization header or the token.
	log.Printf("mcp-gate: %s %s%q %d deny:%s user=%q client=%q", r.Method, config.NormalizeHost(r.Host), r.URL.Path, d.Status, d.Reason, d.User, d.Client)
	http.Error(w, d.Message, d.Status)
}
