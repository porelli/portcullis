// Package resolver is the built-in people VPN's forwarding resolver
// (contract §16, spec §11): every query goes to the upstream resolvers;
// for names under the Portcullis domains (the main domain and the
// enrolled ones), answers that point at this server are rewritten: A →
// the tunnel's own address, AAAA → removed (NODATA). Foreign records pass
// unchanged. A rewritten answer never carries AD and loses its RRSIGs
// (it would no longer validate anyway).
package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Rewriter rewrites upstream answers for the Portcullis domains.
type Rewriter struct {
	Domains []string     // the main domain and the enrolled ones
	Server  []netip.Addr // this server's public addresses (the apex's A / AAAA)
	Self    netip.Addr   // the people tunnel's server address
}

func fold(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

// InScope reports whether name is a Portcullis domain or below one.
func (r *Rewriter) InScope(name string) bool {
	n := fold(name)
	for _, d := range r.Domains {
		d = fold(d)
		if d == "" {
			continue
		}
		if n == d || strings.HasSuffix(n, "."+d) {
			return true
		}
	}
	return false
}

func (r *Rewriter) isServer(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	for _, s := range r.Server {
		if s.Unmap() == a {
			return true
		}
	}
	return false
}

// Rewrite builds the answer to q from the upstream reply. A nil upstream
// is SERVFAIL. Names outside the Portcullis domains pass unchanged.
func (r *Rewriter) Rewrite(q, upstream *dns.Msg) *dns.Msg {
	if upstream == nil {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeServerFailure)
		return m
	}
	m := upstream.Copy()
	m.Id = q.Id
	if len(q.Question) != 1 || !r.InScope(q.Question[0].Name) {
		return m
	}
	m.AuthenticatedData = false
	m.Answer = r.rewriteSection(m.Answer, true)
	m.Ns = r.rewriteSection(m.Ns, false)
	m.Extra = r.rewriteSection(m.Extra, false)
	return m
}

func (r *Rewriter) rewriteSection(rrs []dns.RR, answer bool) []dns.RR {
	out := rrs[:0:0]
	seen := map[string]bool{}
	for _, x := range rrs {
		switch v := x.(type) {
		case *dns.RRSIG:
			continue
		case *dns.A:
			if answer && r.isServer(v.A) {
				c := *v
				c.A = net.IP(r.Self.AsSlice())
				x = &c
			}
		case *dns.AAAA:
			if answer && r.isServer(v.AAAA) {
				continue
			}
		}
		k := x.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, x)
	}
	return out
}

// Forwarder answers queries through the upstreams and the current Rewriter.
type Forwarder struct {
	Upstreams []string // host:port
	Rewriter  func() *Rewriter
	Timeout   time.Duration
}

// Exchange forwards q to the first upstream that answers (TCP when the
// UDP answer is truncated); SERVFAIL when none does.
func (f *Forwarder) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	rw := f.Rewriter()
	if len(q.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeFormatError)
		return m, nil
	}
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	var lastErr error = errors.New("no upstream")
	for _, u := range f.Upstreams {
		c := &dns.Client{Net: "udp", Timeout: timeout}
		in, _, err := c.ExchangeContext(ctx, q, u)
		if err == nil && in != nil && in.Truncated {
			c.Net = "tcp"
			in, _, err = c.ExchangeContext(ctx, q, u)
		}
		if err != nil || in == nil {
			lastErr = err
			continue
		}
		if in.Rcode == dns.RcodeServerFailure || in.Rcode == dns.RcodeRefused {
			lastErr = errors.New(dns.RcodeToString[in.Rcode])
			continue
		}
		return rw.Rewrite(q, in), nil
	}
	return rw.Rewrite(q, nil), lastErr
}

// ServeDNS implements dns.Handler.
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m, _ := f.Exchange(ctx, q)
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := uint16(dns.MinMsgSize)
		if o := q.IsEdns0(); o != nil && o.UDPSize() > size {
			size = o.UDPSize()
		}
		m.Truncate(int(size))
	}
	w.WriteMsg(m)
}

// Upstreams turns "1.1.1.1,9.9.9.9" into host:port entries (port 53).
func Upstreams(list string) ([]string, error) {
	var out []string
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap.String())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, errors.New("resolver: an upstream is not an IP address")
		}
		out = append(out, netip.AddrPortFrom(a, 53).String())
	}
	if len(out) == 0 {
		return nil, errors.New("resolver: no upstream")
	}
	return out, nil
}

// ServerAddrs keeps the apex's addresses, re-resolved through the
// upstreams every Every (300 s). A failed lookup keeps the last answer.
type ServerAddrs struct {
	Apex      string
	Upstreams []string
	Every     time.Duration

	mu    sync.Mutex
	addrs []netip.Addr
}

// Get is the last known set.
func (s *ServerAddrs) Get() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]netip.Addr(nil), s.addrs...)
}

// Refresh looks the apex up once.
func (s *ServerAddrs) Refresh(ctx context.Context) error {
	var got []netip.Addr
	var ok bool
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(s.Apex), qt)
		for _, u := range s.Upstreams {
			c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			in, _, err := c.ExchangeContext(ctx, q, u)
			if err != nil || in == nil || in.Rcode != dns.RcodeSuccess {
				continue
			}
			ok = true
			for _, a := range in.Answer {
				switch v := a.(type) {
				case *dns.A:
					if x, k := netip.AddrFromSlice(v.A); k {
						got = append(got, x.Unmap())
					}
				case *dns.AAAA:
					if x, k := netip.AddrFromSlice(v.AAAA); k {
						got = append(got, x)
					}
				}
			}
			break
		}
	}
	if !ok {
		return errors.New("resolver: the main domain's addresses couldn't be looked up")
	}
	s.mu.Lock()
	s.addrs = got
	s.mu.Unlock()
	return nil
}

// Run refreshes until ctx ends; onErr gets failures.
func (s *ServerAddrs) Run(ctx context.Context, onErr func(error)) {
	every := s.Every
	if every <= 0 {
		every = 300 * time.Second
	}
	retry := 10 * time.Second
	for {
		wait := every
		if err := s.Refresh(ctx); err != nil {
			onErr(err)
			if len(s.Get()) == 0 {
				wait = retry
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
