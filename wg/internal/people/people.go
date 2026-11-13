// Package people is the wg service's built-in people VPN role (contract
// §16): one WireGuard device on its own netstack, peers from vpn.json's
// builtin section (expired ones dropped by this clock every tick), TCP 443
// handed to the edge in-process as provider "builtin", TCP 80 redirected
// to https, and the split-DNS resolver on UDP/TCP 53. Nothing else
// listens, and nothing forwards out of the stack but the edge.
package people

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/portcullis/wg/internal/edge"
	"github.com/portcullis/wg/internal/status"
	"github.com/portcullis/wg/internal/tunnel"
	"github.com/portcullis/wg/internal/vpndoc"
)

// LoadKey reads a base64 private key file. An empty file means the role
// is off (on = false, no error).
func LoadKey(path string) (key [32]byte, on bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return key, false, errors.New("people: the key file is unreadable")
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return key, false, nil
	}
	k, err := vpndoc.ParseKey(s)
	if err != nil {
		return key, false, errors.New("people: the key file holds no WireGuard key")
	}
	return k, true, nil
}

// Role keeps the stack's peers in line with the document and the clock.
type Role struct {
	stack  *tunnel.Stack
	subnet netip.Prefix
	now    func() time.Time

	mu     sync.Mutex
	doc    *vpndoc.Doc
	docErr error
	ok     bool
	err    string
}

// NewRole wraps a running stack whose address is subnet's .1.
func NewRole(stack *tunnel.Stack, subnet netip.Prefix, now func() time.Time) *Role {
	return &Role{stack: stack, subnet: subnet, now: now, err: "vpn.json: not read yet"}
}

// SetDoc applies a new document (nil + err when it is missing or invalid:
// every peer is removed).
func (r *Role) SetDoc(d *vpndoc.Doc, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.doc, r.docErr = d, err
	r.applyLocked()
}

// Tick re-applies the current document at the current time.
func (r *Role) Tick() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applyLocked()
}

func (r *Role) fail(msg string) {
	if err := r.stack.SyncPeers(nil); err != nil {
		msg += "; removing the peers failed"
	}
	r.ok, r.err = false, msg
}

func (r *Role) applyLocked() {
	d := r.doc
	if d == nil {
		msg := "vpn.json: unavailable"
		if r.docErr != nil {
			msg = r.docErr.Error()
		}
		r.fail(msg)
		return
	}
	if !d.Valid(r.now()) {
		// The Hub stopped publishing (valid_until passed): no peer at all.
		r.fail("vpn.json: past valid_until (the Hub hasn't republished it)")
		return
	}
	if d.Builtin == nil {
		// The Hub hasn't enabled the built-in provider: no peers.
		if err := r.stack.SyncPeers(nil); err != nil {
			r.fail(err.Error())
			return
		}
		r.ok, r.err = true, ""
		return
	}
	if k := d.Builtin.ServerPublicKey; k != "" && k != r.stack.PublicKey() {
		r.fail("vpn.json: builtin.server_public_key isn't this server's key")
		return
	}
	if d.Builtin.SubnetPrefix() != r.subnet {
		r.fail("vpn.json: builtin.subnet isn't this server's subnet")
		return
	}
	var peers []tunnel.PeerConfig
	for _, p := range d.BuiltinPeers(r.now()) {
		peers = append(peers, tunnel.PeerConfig{PublicKey: p.PublicKey, IP: p.IP})
	}
	if err := r.stack.SyncPeers(peers); err != nil {
		r.fail(err.Error())
		return
	}
	r.ok, r.err = true, ""
}

// Run ticks every interval (1 s in production) until ctx ends.
func (r *Role) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Tick()
		}
	}
}

// Status is the role's health.
func (r *Role) Status() (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ok, r.err
}

// Peers are the configured peers with their last handshakes.
func (r *Role) Peers() []status.Peer {
	hs, err := r.stack.Handshakes()
	if err != nil {
		return nil
	}
	out := make([]status.Peer, 0, len(hs))
	for k, t := range hs {
		p := status.Peer{PublicKey: k}
		if !t.IsZero() {
			tt := t.UTC().Truncate(time.Second)
			p.LastHandshake = &tt
		}
		out = append(out, p)
	}
	return out
}

// Count is the number of configured peers.
func (r *Role) Count() int {
	hs, err := r.stack.Handshakes()
	if err != nil {
		return 0
	}
	return len(hs)
}

// RedirectHandler answers every request with 308 to https on the same
// host and path.
func RedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" || strings.ContainsAny(host, "/\\@ ") {
			http.Error(w, "no host", http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", "https://"+host+req.URL.RequestURI())
		w.WriteHeader(http.StatusPermanentRedirect)
	})
}

// Serve opens the role's listeners on the stack (443 → edge, 80 →
// redirect, 53 UDP/TCP → dnsHandler) and serves until ctx ends.
func (r *Role) Serve(ctx context.Context, e *edge.Edge, dnsHandler dns.Handler) error {
	l443, err := r.stack.ListenTCP(443)
	if err != nil {
		return errors.New("people: listening on 443 failed")
	}
	l80, err := r.stack.ListenTCP(80)
	if err != nil {
		l443.Close()
		return errors.New("people: listening on 80 failed")
	}
	l53, err := r.stack.ListenTCP(53)
	if err != nil {
		l443.Close()
		l80.Close()
		return errors.New("people: listening on 53/tcp failed")
	}
	p53, err := r.stack.ListenUDP(53)
	if err != nil {
		l443.Close()
		l80.Close()
		l53.Close()
		return errors.New("people: listening on 53/udp failed")
	}
	hs := &http.Server{Handler: RedirectHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	ds := &dns.Server{Listener: l53, Handler: dnsHandler}
	du := &dns.Server{PacketConn: p53, Handler: dnsHandler}
	go func() {
		<-ctx.Done()
		l443.Close()
		hs.Close()
		ds.Shutdown()
		du.Shutdown()
	}()
	go func() {
		if err := hs.Serve(l80); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			log.Printf("people: http: %v", err)
		}
	}()
	go func() {
		if err := ds.ActivateAndServe(); err != nil && ctx.Err() == nil {
			log.Printf("people: dns/tcp: %v", err)
		}
	}()
	go func() {
		if err := du.ActivateAndServe(); err != nil && ctx.Err() == nil {
			log.Printf("people: dns/udp: %v", err)
		}
	}()
	for {
		c, err := l443.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return errors.New("people: the 443 listener closed")
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ap, perr := netip.ParseAddrPort(c.RemoteAddr().String())
		if perr != nil {
			c.Close()
			continue
		}
		go e.Handle(c, vpndoc.BuiltinID, ap.Addr())
	}
}
