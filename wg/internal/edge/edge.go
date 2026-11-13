// Package edge is the wg service's edge role: the single PROXY v2 client
// of Traefik's vpnsecure entrypoint (contract §16). A marketplace
// provider's gateway connects to its own edge port (9001 + slot) and
// sends a PROXY v2 header naming the client; the built-in people stack
// hands its connections over in-process. A connection is re-originated to
// Traefik with a new PROXY v2 header carrying the same client address
// only when the client is a fresh device of that provider: the right
// port, from the provider's assigned gateway, a v2 header within the
// header timeout, a source inside the provider's ranges, a fresh map and
// a device with that address. Anything else is closed and counted.
package edge

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/portcullis/wg/internal/vpndoc"
)

// Rejection reasons (metric label values).
const (
	WrongPort     = "wrong_port"
	WrongGateway  = "wrong_gateway"
	NoHeader      = "no_header"
	SlowHeader    = "slow_header"
	OutsideRanges = "outside_ranges"
	NotInMap      = "not_in_map"
	Stale         = "stale"
	NoDoc         = "no_doc"
	Expired       = "expired" // vpn.json past its valid_until
)

// Reasons lists every rejection reason.
var Reasons = []string{WrongPort, WrongGateway, NoHeader, SlowHeader, OutsideRanges, NotInMap, Stale, NoDoc, Expired}

// Edge checks and forwards connections.
type Edge struct {
	traefik netip.AddrPort
	local   netip.Addr
	doc     func() *vpndoc.Doc
	now     func() time.Time

	// HeaderTimeout bounds the whole PROXY header (default 5 s).
	HeaderTimeout time.Duration
	// DialTimeout bounds the connection to Traefik (default 5 s).
	DialTimeout time.Duration
	// MaxLifetime closes a connection this long after it was admitted
	// (default 12 h, Keycloak's maximum session: no sign-in it carries
	// outlives that anyway; long enough for WebSockets and big downloads).
	MaxLifetime time.Duration
	// IdleTimeout closes a connection with no byte either way for this
	// long (default 1 h; WebSocket apps ping well within it).
	IdleTimeout time.Duration

	rejected *prometheus.CounterVec
	accepted *prometheus.CounterVec
	closed   *prometheus.CounterVec

	mu       sync.Mutex
	sessions map[*session]struct{}
}

// Close reasons of admitted connections (wg_edge_closed_total).
const (
	ClosedNoDoc         = "no_doc"
	ClosedExpired       = "expired"
	ClosedOutsideRanges = "outside_ranges"
	ClosedStale         = "stale"
	ClosedRevoked       = "revoked"
	ClosedLifetime      = "lifetime"
	ClosedIdle          = "idle"
)

// CloseReasons lists every close reason.
var CloseReasons = []string{ClosedNoDoc, ClosedExpired, ClosedOutsideRanges, ClosedStale, ClosedRevoked, ClosedLifetime, ClosedIdle}

// Defaults for the session limits.
const (
	DefaultMaxLifetime = 12 * time.Hour
	DefaultIdleTimeout = time.Hour
)

// session is one admitted, spliced connection and the facts it was
// admitted on. close is its single owner of both conns.
type session struct {
	provider string
	client   netip.Addr
	deviceID string
	user     string
	started  time.Time
	last     atomic.Int64 // unix ns of the last byte either way

	a, b net.Conn
	once sync.Once
}

// close closes both conns once; true for the call that did it.
func (s *session) close() bool {
	did := false
	s.once.Do(func() {
		did = true
		s.a.Close()
		s.b.Close()
	})
	return did
}

// New makes an edge that forwards to traefik (vpnsecure) from local (wg's
// own portcullis-vpn address, the only one Traefik trusts for PROXY).
func New(traefik netip.AddrPort, local netip.Addr, doc func() *vpndoc.Doc, now func() time.Time) *Edge {
	return &Edge{
		traefik: traefik, local: local, doc: doc, now: now,
		HeaderTimeout: 5 * time.Second,
		DialTimeout:   5 * time.Second,
		MaxLifetime:   DefaultMaxLifetime,
		IdleTimeout:   DefaultIdleTimeout,
		sessions:      map[*session]struct{}{},
		closed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_edge_closed_total",
			Help: "Admitted connections the edge closed on a re-check, by provider and reason.",
		}, []string{"provider", "reason"}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_edge_rejected_total",
			Help: "Connections the edge closed, by provider and reason.",
		}, []string{"provider", "reason"}),
		accepted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_edge_accepted_total",
			Help: "Connections the edge forwarded to Traefik, by provider.",
		}, []string{"provider"}),
	}
}

// Collectors are the edge's metrics.
func (e *Edge) Collectors() []prometheus.Collector {
	return []prometheus.Collector{e.rejected, e.accepted, e.closed}
}

func (e *Edge) reject(c net.Conn, provider, reason string) {
	e.rejected.WithLabelValues(provider, reason).Inc()
	if tc, ok := c.(interface{ SetLinger(int) error }); ok {
		tc.SetLinger(0)
	}
	c.Close()
}

// ServeProvider accepts on ln (the provider's edge port) until ctx ends
// or ln is closed.
func (e *Edge) ServeProvider(ctx context.Context, ln net.Listener, providerID string) {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.serveGateway(c, providerID)
	}
}

func addrPortOf(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

func (e *Edge) serveGateway(c net.Conn, providerID string) {
	d := e.doc()
	if d == nil {
		e.reject(c, providerID, NoDoc)
		return
	}
	p := d.ProviderByID(providerID)
	if p == nil || p.ID == vpndoc.BuiltinID || int(addrPortOf(c.LocalAddr()).Port()) != p.EdgePort {
		e.reject(c, providerID, WrongPort)
		return
	}
	if addrPortOf(c.RemoteAddr()).Addr().Unmap() != p.Gateway() {
		e.reject(c, providerID, WrongGateway)
		return
	}
	timeout := e.HeaderTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		e.reject(c, providerID, NoHeader)
		return
	}
	br := bufio.NewReader(c)
	h, err := proxyproto.Read(br)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			e.reject(c, providerID, SlowHeader)
		} else {
			e.reject(c, providerID, NoHeader)
		}
		return
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		e.reject(c, providerID, NoHeader)
		return
	}
	if h.Version != 2 || !h.Command.IsProxy() || h.TransportProtocol != proxyproto.TCPv4 {
		if h.TransportProtocol == proxyproto.TCPv6 {
			e.reject(c, providerID, OutsideRanges)
		} else {
			e.reject(c, providerID, NoHeader)
		}
		return
	}
	src, _, ok := h.TCPAddrs()
	if !ok {
		e.reject(c, providerID, NoHeader)
		return
	}
	client := src.AddrPort()
	// The document may have changed while the header was read.
	e.forward(&bufConn{Conn: c, r: br}, e.doc(), providerID, netip.AddrPortFrom(client.Addr().Unmap(), client.Port()))
}

// Handle checks and forwards a connection whose client address is known
// in-process (the built-in people stack, provider "builtin").
func (e *Edge) Handle(c net.Conn, providerID string, client netip.Addr) {
	port := addrPortOf(c.RemoteAddr()).Port()
	e.forward(c, e.doc(), providerID, netip.AddrPortFrom(client.Unmap(), port))
}

func (e *Edge) forward(c net.Conn, d *vpndoc.Doc, providerID string, client netip.AddrPort) {
	if d == nil {
		e.reject(c, providerID, NoDoc)
		return
	}
	now := e.now()
	if !d.Valid(now) {
		e.reject(c, providerID, Expired)
		return
	}
	p := d.ProviderByID(providerID)
	if p == nil || !client.Addr().Is4() || d.ProviderOf(client.Addr()) != p {
		e.reject(c, providerID, OutsideRanges)
		return
	}
	if !p.Fresh(now) {
		e.reject(c, providerID, Stale)
		return
	}
	dev := d.Device(providerID, client.Addr(), now)
	if dev == nil {
		e.reject(c, providerID, NotInMap)
		return
	}
	dialer := net.Dialer{Timeout: e.DialTimeout}
	if e.local.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: e.local.AsSlice()}
	}
	up, err := dialer.Dial("tcp4", e.traefik.String())
	if err != nil {
		c.Close()
		return
	}
	hdr := proxyproto.HeaderProxyFromAddrs(2, net.TCPAddrFromAddrPort(client), net.TCPAddrFromAddrPort(e.traefik))
	if _, err := hdr.WriteTo(up); err != nil {
		up.Close()
		c.Close()
		return
	}
	s := &session{provider: providerID, client: client.Addr(), deviceID: dev.DeviceID, user: dev.User, started: now, a: c, b: up}
	s.last.Store(now.UnixNano())
	e.mu.Lock()
	e.sessions[s] = struct{}{}
	e.mu.Unlock()
	e.accepted.WithLabelValues(providerID).Inc()
	e.splice(s)
	e.mu.Lock()
	delete(e.sessions, s)
	e.mu.Unlock()
}

// recheck is the admission check again, for an admitted session: the
// same document rules (provider present and owning the address, fresh,
// the device still there, unexpired, with the same id and owner), plus
// the lifetime and idle limits. "" = keep.
func (e *Edge) recheck(s *session, d *vpndoc.Doc, now time.Time) string {
	if d == nil {
		return ClosedNoDoc
	}
	if !d.Valid(now) {
		return ClosedExpired
	}
	p := d.ProviderByID(s.provider)
	if p == nil || d.ProviderOf(s.client) != p {
		return ClosedOutsideRanges
	}
	if !p.Fresh(now) {
		return ClosedStale
	}
	dev := d.Device(s.provider, s.client, now)
	if dev == nil || dev.DeviceID != s.deviceID || dev.User != s.user {
		return ClosedRevoked
	}
	if e.MaxLifetime > 0 && now.Sub(s.started) >= e.MaxLifetime {
		return ClosedLifetime
	}
	if e.IdleTimeout > 0 && now.Sub(time.Unix(0, s.last.Load())) >= e.IdleTimeout {
		return ClosedIdle
	}
	return ""
}

// Revalidate re-runs the admission checks on every admitted connection
// against the current document and clock, closing the ones that fail
// (all of them when the document is unavailable). Called on every
// vpn.json reload and by Run.
func (e *Edge) Revalidate() {
	d := e.doc()
	now := e.now()
	type victim struct {
		s      *session
		reason string
	}
	var vs []victim
	e.mu.Lock()
	for s := range e.sessions {
		if r := e.recheck(s, d, now); r != "" {
			vs = append(vs, victim{s, r})
		}
	}
	e.mu.Unlock()
	for _, v := range vs {
		if v.s.close() {
			e.closed.WithLabelValues(v.s.provider, v.reason).Inc()
		}
	}
}

// Run revalidates every interval until ctx ends.
func (e *Edge) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Revalidate()
		}
	}
}

// Sessions is the number of admitted connections open now.
func (e *Edge) Sessions() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.sessions)
}

// splice copies both ways with half-close, recording activity; the
// session's close (here or from Revalidate) is the only one.
func (e *Edge) splice(s *session) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				s.last.Store(e.now().UnixNano())
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			s.close()
		}
	}
	go cp(s.a, s.b)
	go cp(s.b, s.a)
	wg.Wait()
	s.close()
}

// bufConn reads what the header reader already buffered first.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}
