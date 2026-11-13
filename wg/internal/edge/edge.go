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
	"io"
	"net"
	"net/netip"
	"sync"
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
)

// Reasons lists every rejection reason.
var Reasons = []string{WrongPort, WrongGateway, NoHeader, SlowHeader, OutsideRanges, NotInMap, Stale, NoDoc}

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

	rejected *prometheus.CounterVec
	accepted *prometheus.CounterVec
}

// New makes an edge that forwards to traefik (vpnsecure) from local (wg's
// own portcullis-vpn address, the only one Traefik trusts for PROXY).
func New(traefik netip.AddrPort, local netip.Addr, doc func() *vpndoc.Doc, now func() time.Time) *Edge {
	return &Edge{
		traefik: traefik, local: local, doc: doc, now: now,
		HeaderTimeout: 5 * time.Second,
		DialTimeout:   5 * time.Second,
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
	return []prometheus.Collector{e.rejected, e.accepted}
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
	p := d.ProviderByID(providerID)
	if p == nil || !client.Addr().Is4() || d.ProviderOf(client.Addr()) != p {
		e.reject(c, providerID, OutsideRanges)
		return
	}
	now := e.now()
	if !p.Fresh(now) {
		e.reject(c, providerID, Stale)
		return
	}
	if d.Device(providerID, client.Addr(), now) == nil {
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
	e.accepted.WithLabelValues(providerID).Inc()
	Splice(c, up)
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

// Splice copies both ways with half-close and closes both when done.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
