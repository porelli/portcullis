package link

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/wg/internal/linkdoc"
)

// serviceRe constrains the service part of a data pseudo-target (compose
// service names).
var serviceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// RelaySuffix ends every data pseudo-target: <instance>.<service>.relay:<port>.
const RelaySuffix = ".relay"

// Preamble is the first line link writes on a data stream to the agent.
type Preamble struct {
	Instance string `json:"instance"`
	Service  string `json:"service"`
	Port     int    `json:"port"`
}

// ServeControl serves the Hub's CONNECT <worker ip>:7443 on ln until ctx
// ends. Anything but CONNECT is 405; another target 403.
func (l *Link) ServeControl(ctx context.Context, ln net.Listener) error {
	return l.serve(ctx, ln, http.HandlerFunc(l.handleControl))
}

// ServeData serves the relays' CONNECT <instance>.<service>.relay:<port>
// with Proxy-Authorization: Bearer <token> on ln until ctx ends.
func (l *Link) ServeData(ctx context.Context, ln net.Listener) error {
	return l.serve(ctx, ln, http.HandlerFunc(l.handleData))
}

func (l *Link) serve(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		srv.Close()
		l.CloseAll()
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (l *Link) reject(w http.ResponseWriter, path, reason string, code int) {
	l.rejected.WithLabelValues(path, reason).Inc()
	w.Header().Set("Connection", "close")
	http.Error(w, http.StatusText(code), code)
}

func (l *Link) handleControl(w http.ResponseWriter, r *http.Request) {
	const path = "control"
	if r.Method != http.MethodConnect {
		l.reject(w, path, "method", http.StatusMethodNotAllowed)
		return
	}
	ap, err := netip.ParseAddrPort(r.Host)
	if err != nil || !ap.Addr().Is4() || ap.Port() != ControlPort || !linkdoc.PeerAddr(ap.Addr()) {
		l.reject(w, path, "target", http.StatusForbidden)
		return
	}
	l.mu.Lock()
	live, cur := l.docsLocked()
	p := live.PeerByAddr(ap.Addr())
	q := cur.PeerByAddr(ap.Addr())
	if p == nil || q == nil || p.ID != q.ID || p.Key() != q.Key() {
		l.mu.Unlock()
		l.reject(w, path, "unknown_peer", http.StatusForbidden)
		return
	}
	s := l.newStreamLocked(r.Context(), path, q)
	if s == nil {
		l.mu.Unlock()
		l.reject(w, path, "busy", http.StatusServiceUnavailable)
		return
	}
	l.mu.Unlock()
	l.splice(w, s, ap, nil)
}

func (l *Link) handleData(w http.ResponseWriter, r *http.Request) {
	const path = "data"
	if r.Method != http.MethodConnect {
		l.reject(w, path, "method", http.StatusMethodNotAllowed)
		return
	}
	auths := r.Header.Values("Proxy-Authorization")
	tok, ok := "", false
	if len(auths) == 1 {
		tok, ok = strings.CutPrefix(auths[0], "Bearer ")
	}
	if !ok || tok == "" || strings.ContainsAny(tok, " \t") {
		l.reject(w, path, "no_bearer", http.StatusForbidden)
		return
	}
	pre, ok := parseRelayTarget(r.Host)
	if !ok {
		l.reject(w, path, "target", http.StatusForbidden)
		return
	}
	sum := sha256.Sum256([]byte(tok))
	sha := hex.EncodeToString(sum[:])
	l.mu.Lock()
	live, cur := l.docsLocked()
	rl, rc := live.RelayByToken(sha), cur.RelayByToken(sha)
	if rl == nil || rc == nil || *rl != *rc {
		l.mu.Unlock()
		l.reject(w, path, "unknown_token", http.StatusForbidden)
		return
	}
	if rc.Instance != pre.Instance {
		l.mu.Unlock()
		l.reject(w, path, "other_instance", http.StatusForbidden)
		return
	}
	p, q := live.PeerByID(rc.Server), cur.PeerByID(rc.Server)
	if p == nil || q == nil || p.Key() != q.Key() || p.Addr() != q.Addr() || q.State != linkdoc.StateReady {
		l.mu.Unlock()
		l.reject(w, path, "server_not_ready", http.StatusForbidden)
		return
	}
	s := l.newStreamLocked(r.Context(), path, q)
	if s == nil {
		l.mu.Unlock()
		l.reject(w, path, "busy", http.StatusServiceUnavailable)
		return
	}
	s.token, s.instance = sha, rc.Instance
	l.mu.Unlock()
	line, _ := json.Marshal(pre)
	l.splice(w, s, netip.AddrPortFrom(q.Addr(), DataPort), append(line, '\n'))
}

// parseRelayTarget reads <instance>.<service>.relay:<port>.
func parseRelayTarget(hostport string) (Preamble, bool) {
	h, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return Preamble{}, false
	}
	name, ok := strings.CutSuffix(h, RelaySuffix)
	if !ok {
		return Preamble{}, false
	}
	inst, svc, ok := strings.Cut(name, ".")
	if !ok || !linkdoc.ValidInstance(inst) || !serviceRe.MatchString(svc) {
		return Preamble{}, false
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != ps {
		return Preamble{}, false
	}
	return Preamble{Instance: inst, Service: svc, Port: port}, true
}

// newStreamLocked registers a stream for peer p (nil when at the global
// cap for its kind or at p's own share of it).
func (l *Link) newStreamLocked(parent context.Context, path string, p *linkdoc.Peer) *stream {
	total, mine := 0, 0
	for s := range l.streams {
		if s.path != path {
			continue
		}
		total++
		if s.peerID == p.ID {
			mine++
		}
	}
	lim, perPeer := l.MaxDataStreams, l.MaxDataPerPeer
	if path == "control" {
		lim, perPeer = l.MaxControlStreams, l.MaxControlPerPeer
	}
	if total >= lim || mine >= perPeer {
		return nil
	}
	// The stream outlives the request handler (hijacked), not the server.
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	s := &stream{path: path, peerID: p.ID, peerKey: p.Key(), peerIP: p.Addr(), ctx: ctx, cancel: cancel}
	l.streams[s] = struct{}{}
	return s
}

func (l *Link) drop(s *stream) {
	l.mu.Lock()
	delete(l.streams, s)
	l.mu.Unlock()
	s.close()
}

// splice dials the worker, writes preamble (data), answers 200 and copies
// both ways until either side ends or Reload closes the stream.
func (l *Link) splice(w http.ResponseWriter, s *stream, to netip.AddrPort, preamble []byte) {
	defer l.drop(s)
	dctx, cancel := context.WithTimeout(s.ctx, l.DialTimeout)
	up, err := l.stack.DialTCP(dctx, to)
	cancel()
	if err != nil {
		if s.ctx.Err() != nil {
			l.reject(w, s.path, "revoked", http.StatusForbidden)
			return
		}
		l.reject(w, s.path, "dial", http.StatusBadGateway)
		return
	}
	if !s.attach(up) {
		l.reject(w, s.path, "revoked", http.StatusForbidden)
		return
	}
	if preamble != nil {
		up.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := up.Write(preamble); err != nil {
			l.reject(w, s.path, "dial", http.StatusBadGateway)
			return
		}
		up.SetWriteDeadline(time.Time{})
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		l.reject(w, s.path, "internal", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	if !s.attach(conn) {
		return
	}
	conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(conn, up)
		closeWrite(conn)
		done <- struct{}{}
	}()
	go func() {
		// brw.Reader holds anything the client sent after the request.
		io.Copy(up, brw.Reader)
		closeWrite(up)
		done <- struct{}{}
	}()
	select {
	case <-done:
		// One side ended: the other gets DrainTimeout to finish, then the
		// stream ends (drop closes both connections): a peer that never
		// closes its side can't hold the slot.
		t := time.NewTimer(l.DrainTimeout)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
		case <-s.ctx.Done():
		}
	case <-s.ctx.Done():
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
