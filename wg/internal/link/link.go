// Package link is the wg service's third role (contract §17): a WireGuard
// server for worker servers whose netstack has zero listeners. It only
// dials into the tunnel, for two internal clients on their own Docker
// networks: the Hub's control path (HTTP CONNECT <worker ip>:7443 on
// portcullis-link) and the relays' data path (CONNECT
// <instance>.<service>.relay:<port> with a per-instance bearer on
// portcullis-link-data; link writes the data preamble itself, so a relay
// can't name another instance).
//
// Peers come from link.json (internal/linkdoc): every ready or enrolling
// server, AllowedIPs its /32, no endpoint (workers dial in and keep the
// NAT open). A reload drops gone peers through UAPI at once and closes
// every open stream whose peer or token is gone. A missing or invalid
// document means no peers and every CONNECT refused.
//
// The role reuses internal/tunnel with its own stack, key, port and
// subnet; nothing connects it to the people or edge stacks.
package link

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/portcullis/wg/internal/linkdoc"
	"github.com/portcullis/wg/internal/status"
	"github.com/portcullis/wg/internal/tunnel"
)

// Ports on a worker's tunnel address.
const (
	ControlPort = 7443
	DataPort    = 7000
)

// MTU of the link tunnel.
const MTU = 1380

// Defaults.
const (
	DefaultDialTimeout = 10 * time.Second
	DefaultMaxStreams  = 8192
)

// Link is the running role.
type Link struct {
	stack *tunnel.Stack
	doc   func() *linkdoc.Doc

	// DialTimeout bounds a dial into the tunnel; MaxStreams caps open
	// streams (control + data) — beyond it a CONNECT gets 503.
	DialTimeout time.Duration
	MaxStreams  int

	mu      sync.Mutex
	cur     *linkdoc.Doc // the document Reload applied (nil: none / failed)
	syncErr string
	streams map[*stream]struct{}

	rejected *prometheus.CounterVec
	closed   *prometheus.CounterVec
}

// New wraps a running stack (address linkdoc.LinkAddr). doc returns the
// current document (nil when missing or invalid); every CONNECT must be
// allowed both by it and by the document the last Reload applied.
func New(stack *tunnel.Stack, doc func() *linkdoc.Doc) *Link {
	return &Link{
		stack:       stack,
		doc:         doc,
		DialTimeout: DefaultDialTimeout,
		MaxStreams:  DefaultMaxStreams,
		syncErr:     "link.json: not read yet",
		streams:     map[*stream]struct{}{},
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_link_connect_rejected_total", Help: "CONNECT requests link refused, by path and reason.",
		}, []string{"path", "reason"}),
		closed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_link_streams_closed_total", Help: "Open streams link closed because their peer or token left link.json.",
		}, []string{"path"}),
	}
}

// Reload applies d (nil: no document): the stack's peers become exactly
// d's (ready + enrolling, /32, no endpoint), then every open stream d no
// longer allows is closed. If the peers can't be applied the role holds
// no peers and refuses everything.
func (l *Link) Reload(d *linkdoc.Doc) {
	var peers []tunnel.PeerConfig
	if d != nil {
		for i := range d.Peers {
			p := &d.Peers[i]
			peers = append(peers, tunnel.PeerConfig{PublicKey: p.Key(), IP: p.Addr()})
		}
	}
	err := l.stack.SyncPeers(peers)
	if err != nil {
		d = nil
		if e2 := l.stack.SyncPeers(nil); e2 != nil {
			err = errors.Join(err, e2)
		}
	}
	l.mu.Lock()
	l.cur = d
	switch {
	case err != nil:
		l.syncErr = "link: applying the peers failed; every CONNECT is refused"
	case d == nil:
		l.syncErr = "link.json: unavailable"
	default:
		l.syncErr = ""
	}
	var gone []*stream
	for s := range l.streams {
		if !s.allowedBy(d) {
			gone = append(gone, s)
			delete(l.streams, s)
		}
	}
	l.mu.Unlock()
	for _, s := range gone {
		l.closed.WithLabelValues(s.path).Inc()
		s.close()
	}
}

// CloseAll ends every open stream (shutdown).
func (l *Link) CloseAll() {
	l.mu.Lock()
	all := make([]*stream, 0, len(l.streams))
	for s := range l.streams {
		all = append(all, s)
	}
	l.streams = map[*stream]struct{}{}
	l.mu.Unlock()
	for _, s := range all {
		s.close()
	}
}

// Status is the role's health: ok once a document is applied.
func (l *Link) Status() (bool, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.syncErr == "", l.syncErr
}

// OpenStreams is the number of open streams.
func (l *Link) OpenStreams() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.streams)
}

// Peers are the applied document's peers with their device state.
func (l *Link) Peers() []status.LinkPeer {
	l.mu.Lock()
	d := l.cur
	l.mu.Unlock()
	out := []status.LinkPeer{}
	if d == nil {
		return out
	}
	st, err := l.stack.PeerStats()
	if err != nil {
		return out
	}
	for i := range d.Peers {
		p := &d.Peers[i]
		lp := status.LinkPeer{ID: p.ID, IP: p.IP}
		if s, ok := st[p.PublicKey]; ok {
			if !s.Handshake.IsZero() {
				h := s.Handshake.UTC().Truncate(time.Second)
				lp.Handshake = &h
			}
			lp.Rx, lp.Tx = s.Rx, s.Tx
		}
		out = append(out, lp)
	}
	return out
}

// applied returns the documents a request must satisfy: the live one and
// the applied one (both nil-safe; either nil refuses).
func (l *Link) docsLocked() (*linkdoc.Doc, *linkdoc.Doc) { return l.doc(), l.cur }

// stream is one open CONNECT tunnel.
type stream struct {
	path     string // control | data
	peerID   string
	peerKey  [32]byte
	peerIP   netip.Addr
	token    string // data: the token's sha256 hex
	instance string // data

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

// allowedBy reports whether d still allows the stream: the same peer (id,
// key, address) and, for data, the same token for the same instance on a
// ready server.
func (s *stream) allowedBy(d *linkdoc.Doc) bool {
	p := d.PeerByID(s.peerID)
	if p == nil || p.Key() != s.peerKey || p.Addr() != s.peerIP {
		return false
	}
	if s.path == "control" {
		return p.State == linkdoc.StateReady || p.State == linkdoc.StateEnrolling
	}
	if p.State != linkdoc.StateReady {
		return false
	}
	r := d.RelayByToken(s.token)
	return r != nil && r.Instance == s.instance && r.Server == s.peerID
}

// attach adds a connection; false (and the connection closed) when the
// stream was closed meanwhile.
func (s *stream) attach(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		c.Close()
		return false
	}
	s.conns = append(s.conns, c)
	return true
}

func (s *stream) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	cs := s.conns
	s.mu.Unlock()
	s.cancel()
	for _, c := range cs {
		c.Close()
	}
}
