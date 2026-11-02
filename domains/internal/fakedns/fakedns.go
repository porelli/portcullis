// Package fakedns is a test DNS provider: an in-memory zone behind the
// libdns interfaces, plus a small DNS server that answers A, AAAA and TXT
// queries from it (wildcards included). The domains service's tests and
// the CI image (build tag testprovider) use it with Pebble: the service
// writes records and DNS-01 challenges through the libdns side, Pebble and
// the records check read them through the DNS side. Never part of the
// production binary.
package fakedns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// ErrAuth is what a provider with a rejected token returns. The message
// deliberately quotes the token, as a careless real provider might: the
// service must redact it.
var ErrAuth = errors.New("authentication failed")

// Zone is a set of records keyed by absolute lowercase name (no trailing
// dot). Safe for concurrent use.
type Zone struct {
	mu    sync.Mutex
	recs  map[string][]libdns.RR
	calls int // every libdns call (any provider of this zone)
}

// CallCount is the number of libdns calls so far.
func (z *Zone) CallCount() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.calls
}

// NewZone returns an empty zone.
func NewZone() *Zone { return &Zone{recs: map[string][]libdns.RR{}} }

func abs(name, zone string) string {
	return strings.ToLower(strings.TrimSuffix(libdns.AbsoluteName(name, zone), "."))
}

// Records returns the records at an absolute name (no trailing dot).
func (z *Zone) Records(name string) []libdns.RR {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]libdns.RR(nil), z.recs[strings.ToLower(strings.TrimSuffix(name, "."))]...)
}

// Set replaces the records at an absolute name (test setup).
func (z *Zone) Set(name string, rrs ...libdns.RR) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.recs[strings.ToLower(strings.TrimSuffix(name, "."))] = rrs
}

// lookup returns the records of type t answering name: the exact name,
// else the wildcard one label up (*.<parent>), as a DNS server would.
func (z *Zone) lookup(name, t string) []libdns.RR {
	z.mu.Lock()
	defer z.mu.Unlock()
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	pick := func(n string) ([]libdns.RR, bool) {
		rrs, ok := z.recs[n]
		var out []libdns.RR
		for _, rr := range rrs {
			if rr.Type == t {
				out = append(out, rr)
			}
		}
		return out, ok && len(rrs) > 0
	}
	if out, exists := pick(name); exists {
		return out
	}
	if _, parent, ok := strings.Cut(name, "."); ok {
		out, _ := pick("*." + parent)
		return out
	}
	return nil
}

// Provider is a libdns provider on a Zone. Token must equal the zone's
// accepted token (Accept), otherwise every call fails with ErrAuth.
type Provider struct {
	Zone   *Zone
	Token  string
	Accept func(token string) bool
	// ZoneName, if set, is returned by FindZone (the service's zone lookup).
	ZoneName string
	// Hook, if set, runs before every call ("get", "append", "set",
	// "delete") outside the zone lock; an error fails the call (tests:
	// blocking, provider errors that echo the token).
	Hook func(op string, recs []libdns.Record) error
}

// FindZone reports the zone the provider manages for fqdn (the service
// skips the SOA lookup for providers that know their zone).
func (p *Provider) FindZone(fqdn string) (string, error) {
	if p.ZoneName != "" {
		return dns.Fqdn(p.ZoneName), nil
	}
	return dns.Fqdn(strings.TrimPrefix(fqdn, "_acme-challenge.")), nil
}

// SkipPropagationCheck: the fake zone has no authoritative nameservers
// for lego to ask; Pebble queries the fake DNS server directly.
func (p *Provider) SkipPropagationCheck() bool { return true }

func (p *Provider) auth(op string, recs []libdns.Record) error {
	if p.Hook != nil {
		if err := p.Hook(op, recs); err != nil {
			return err
		}
	}
	p.Zone.mu.Lock()
	p.Zone.calls++
	p.Zone.mu.Unlock()
	if p.Accept != nil && !p.Accept(p.Token) {
		return fmt.Errorf("%w: token %q was rejected by the fake provider", ErrAuth, p.Token)
	}
	return nil
}

// GetRecords lists every record of the zone.
func (p *Provider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	if err := p.auth("get", nil); err != nil {
		return nil, err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	suffix := strings.ToLower(strings.TrimSuffix(zone, "."))
	var out []libdns.Record
	for name, rrs := range p.Zone.recs {
		if name != suffix && !strings.HasSuffix(name, "."+suffix) {
			continue
		}
		for _, rr := range rrs {
			rr.Name = libdns.RelativeName(name+".", zone)
			out = append(out, parsed(rr))
		}
	}
	return out, nil
}

func parsed(rr libdns.RR) libdns.Record {
	r, err := rr.Parse()
	if err != nil {
		return rr
	}
	return r
}

// AppendRecords adds records.
func (p *Provider) AppendRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.auth("append", recs); err != nil {
		return nil, err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	for _, r := range recs {
		rr := r.RR()
		n := abs(rr.Name, zone)
		p.Zone.recs[n] = append(p.Zone.recs[n], rr)
	}
	return recs, nil
}

// SetRecords makes each input (name, type) RRset exactly the input.
func (p *Provider) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.auth("set", recs); err != nil {
		return nil, err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	type key struct{ n, t string }
	cleared := map[key]bool{}
	for _, r := range recs {
		rr := r.RR()
		n := abs(rr.Name, zone)
		if k := (key{n, rr.Type}); !cleared[k] {
			cleared[k] = true
			var keep []libdns.RR
			for _, old := range p.Zone.recs[n] {
				if old.Type != rr.Type {
					keep = append(keep, old)
				}
			}
			p.Zone.recs[n] = keep
		}
		p.Zone.recs[n] = append(p.Zone.recs[n], rr)
	}
	return recs, nil
}

// DeleteRecords removes matching records (empty type / TTL / data match
// anything, as libdns specifies).
func (p *Provider) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.auth("delete", recs); err != nil {
		return nil, err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	var deleted []libdns.Record
	for _, r := range recs {
		want := r.RR()
		n := abs(want.Name, zone)
		var keep []libdns.RR
		for _, old := range p.Zone.recs[n] {
			if (want.Type == "" || want.Type == old.Type) && (want.TTL == 0 || want.TTL == old.TTL) && (want.Data == "" || want.Data == old.Data) {
				deleted = append(deleted, parsed(old))
				continue
			}
			keep = append(keep, old)
		}
		p.Zone.recs[n] = keep
	}
	return deleted, nil
}

// Server answers DNS queries from a Zone over UDP and TCP (same port).
type Server struct {
	Addr string // host:port actually listening
	udp  *dns.Server
	tcp  *dns.Server
}

// Serve starts a DNS server for z on addr ("127.0.0.1:0" for a random
// port).
func Serve(z *Zone, addr string) (*Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, err
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		for _, q := range req.Question {
			t := dns.TypeToString[q.Qtype]
			for _, rr := range z.lookup(q.Name, t) {
				hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: uint32(rr.TTL / time.Second)}
				switch t {
				case "A", "AAAA":
					ip, err := netip.ParseAddr(rr.Data)
					if err != nil {
						continue
					}
					if t == "A" {
						m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.AsSlice()})
					} else {
						m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip.AsSlice()})
					}
				case "TXT":
					m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{rr.Data}})
				}
			}
		}
		_ = w.WriteMsg(m)
	})
	s := &Server{Addr: pc.LocalAddr().String()}
	var wg sync.WaitGroup
	wg.Add(2)
	s.udp = &dns.Server{PacketConn: pc, Handler: h, NotifyStartedFunc: wg.Done}
	s.tcp = &dns.Server{Listener: l, Handler: h, NotifyStartedFunc: wg.Done}
	go func() { _ = s.udp.ActivateAndServe() }()
	go func() { _ = s.tcp.ActivateAndServe() }()
	wg.Wait()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error {
	return errors.Join(s.udp.Shutdown(), s.tcp.Shutdown())
}
