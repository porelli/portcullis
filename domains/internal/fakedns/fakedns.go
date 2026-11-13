// Package fakedns is a test DNS provider: an in-memory zone behind the
// libdns interfaces, plus a small DNS server that answers A, AAAA, TXT,
// CAA, MX and CNAME queries from it (wildcards included), SOA for marked
// zone apexes, DNSKEY / DS for signed zones, and NXDOMAIN for names that
// don't exist. In validating mode it plays a validating resolver: AD for
// a secure chain, SERVFAIL for a broken one (answered with CD set). The domains service's tests and
// the CI image (build tag testprovider) use it with Pebble: the service
// writes records and DNS-01 challenges through the libdns side, Pebble and
// the records check read them through the DNS side. Never part of the
// production binary.
package fakedns

import (
	"context"
	"crypto"
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
	// DNSSEC side (by apex, absolute lowercase, no trailing dot).
	soa   map[string]bool
	keys  map[string]*signedKey
	ds    map[string][]*dns.DS
	bogus map[string]bool
}

// signedKey is a zone's KSK with the RRSIG over the DNSKEY RRset.
type signedKey struct {
	key *dns.DNSKEY
	sig *dns.RRSIG
}

// CallCount is the number of libdns calls so far.
func (z *Zone) CallCount() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.calls
}

// NewZone returns an empty zone.
func NewZone() *Zone {
	return &Zone{recs: map[string][]libdns.RR{}, soa: map[string]bool{}, keys: map[string]*signedKey{},
		ds: map[string][]*dns.DS{}, bogus: map[string]bool{}}
}

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
	// SetMode mimics real libdns providers' SetRecords: "" replaces each
	// (name, type) RRset (libdns semantics); "cloudflare" (libdns/cloudflare
	// v0.2.2) and "porkbun" (v1.1.0) handle each input record alone — no
	// same-name/type record: create; one (cloudflare) / the first
	// (porkbun): update it in place; several: cloudflare errors.
	SetMode string
	// DeleteMode mimics real libdns providers' DeleteRecords: "" deletes
	// exactly the matching records (libdns semantics); "porkbun"
	// (libdns/porkbun v1.1.0, /dns/deleteByNameType) deletes EVERY record
	// with the input's name and type, whatever its data; "hetzner"
	// (libdns/hetzner v1.0.0, findRecordID) deletes the FIRST record with
	// the input's name and type, from one listing taken at the start (the
	// same record twice fails, as the API's 404 would).
	DeleteMode string
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
	if p.SetMode != "" {
		for _, r := range recs {
			rr := r.RR()
			n := abs(rr.Name, zone)
			var idx []int
			for i, old := range p.Zone.recs[n] {
				if old.Type == rr.Type {
					idx = append(idx, i)
				}
			}
			switch {
			case len(idx) == 0:
				p.Zone.recs[n] = append(p.Zone.recs[n], rr)
			case len(idx) > 1 && p.SetMode == "cloudflare":
				return nil, fmt.Errorf("expected only one record with name %q and type %s, but got %d", rr.Name, rr.Type, len(idx))
			default:
				p.Zone.recs[n][idx[0]] = rr
			}
		}
		return recs, nil
	}
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
// anything, as libdns specifies), or as DeleteMode says.
func (p *Provider) DeleteRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if err := p.auth("delete", recs); err != nil {
		return nil, err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	var deleted []libdns.Record
	switch p.DeleteMode {
	case "porkbun":
		for _, r := range recs {
			want := r.RR()
			n := abs(want.Name, zone)
			var keep []libdns.RR
			for _, old := range p.Zone.recs[n] {
				if old.Type == want.Type {
					continue
				}
				keep = append(keep, old)
			}
			p.Zone.recs[n] = keep
			deleted = append(deleted, r)
		}
		return deleted, nil
	case "hetzner":
		type ref struct {
			n string
			i int
		}
		snap := map[string][]libdns.RR{}
		for n, rrs := range p.Zone.recs {
			snap[n] = append([]libdns.RR(nil), rrs...)
		}
		gone := map[ref]bool{}
		for _, r := range recs {
			want := r.RR()
			n := abs(want.Name, zone)
			idx := -1
			for i, old := range snap[n] {
				if old.Type == want.Type {
					idx = i
					break
				}
			}
			if idx < 0 {
				return deleted, fmt.Errorf("record ID not found: %s", want.Name)
			}
			if gone[ref{n, idx}] {
				return deleted, errors.New("Not Found (404)")
			}
			gone[ref{n, idx}] = true
			victim := snap[n][idx]
			for i, old := range p.Zone.recs[n] {
				if old == victim {
					p.Zone.recs[n] = append(p.Zone.recs[n][:i:i], p.Zone.recs[n][i+1:]...)
					break
				}
			}
			deleted = append(deleted, r)
		}
		return deleted, nil
	}
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

// IDRecord is a record with a provider record ID (ListIDs / DeleteID: the
// record-ID API real providers have beside their libdns package). Name is
// relative to the zone ("@" at the apex).
type IDRecord struct {
	ID string
	RR libdns.RR
}

func recordID(name string, rr libdns.RR) string {
	return fmt.Sprintf("%s|%s|%s|%d", name, rr.Type, rr.Data, rr.TTL/time.Second)
}

// ListIDs lists every record of the zone with its ID (op "get").
func (p *Provider) ListIDs(_ context.Context, zone string) ([]IDRecord, error) {
	if err := p.auth("get", nil); err != nil {
		return nil, err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	suffix := strings.ToLower(strings.TrimSuffix(zone, "."))
	var out []IDRecord
	for name, rrs := range p.Zone.recs {
		if name != suffix && !strings.HasSuffix(name, "."+suffix) {
			continue
		}
		for _, rr := range rrs {
			id := recordID(name, rr)
			rr.Name = libdns.RelativeName(name+".", zone)
			out = append(out, IDRecord{ID: id, RR: rr})
		}
	}
	return out, nil
}

// DeleteID deletes one record by its ID (op "delete"); an unknown ID fails.
func (p *Provider) DeleteID(_ context.Context, zone, id string) error {
	if err := p.auth("delete", nil); err != nil {
		return err
	}
	p.Zone.mu.Lock()
	defer p.Zone.mu.Unlock()
	for name, rrs := range p.Zone.recs {
		for i, rr := range rrs {
			if recordID(name, rr) == id {
				p.Zone.recs[name] = append(rrs[:i:i], rrs[i+1:]...)
				return nil
			}
		}
	}
	return fmt.Errorf("record %s not found", id)
}

func norm(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

// SetSOA marks apex as a zone apex: SOA queries there answer a SOA, and
// any empty answer under it carries that SOA in the authority section.
func (z *Zone) SetSOA(apex string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.soa[norm(apex)] = true
}

// Sign signs the zone at apex: a fresh ECDSAP256SHA256 KSK (flags 257);
// DNSKEY queries answer it with an RRSIG over the DNSKEY RRset.
func (z *Zone) Sign(apex string) (*dns.DNSKEY, error) {
	n := norm(apex)
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: dns.Fqdn(n), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := k.Generate(256)
	if err != nil {
		return nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, errors.New("generated key is not a crypto.Signer")
	}
	now := time.Now()
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: dns.Fqdn(n), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: k.Algorithm, KeyTag: k.KeyTag(), SignerName: dns.Fqdn(n),
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(30 * 24 * time.Hour).Unix())}
	if err := sig.Sign(signer, []dns.RR{k}); err != nil {
		return nil, err
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	z.soa[n] = true
	z.keys[n] = &signedKey{key: k, sig: sig}
	return k, nil
}

// PublishDS sets the DS RRset the parent serves for apex (none: no DS).
func (z *Zone) PublishDS(apex string, ds ...*dns.DS) {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := norm(apex)
	if len(ds) == 0 {
		delete(z.ds, n)
		return
	}
	out := make([]*dns.DS, 0, len(ds))
	for _, d := range ds {
		c := *d
		c.Hdr = dns.RR_Header{Name: dns.Fqdn(n), Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600}
		out = append(out, &c)
	}
	z.ds[n] = out
}

// SetBogus makes validation of the zone at apex fail (bad signatures).
func (z *Zone) SetBogus(apex string, bogus bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.bogus[norm(apex)] = bogus
}

// existsLocked: a name exists if it has records, is a marked apex, or is
// an ancestor of a name that does (an empty non-terminal).
func (z *Zone) existsLocked(n string) bool {
	if len(z.recs[n]) > 0 || z.soa[n] {
		return true
	}
	for name, rrs := range z.recs {
		if len(rrs) > 0 && strings.HasSuffix(name, "."+n) {
			return true
		}
	}
	return false
}

// rrsLocked returns the records answering name (exact, else the wildcard
// one label up) and whether the name exists at all.
func (z *Zone) rrsLocked(n string) ([]libdns.RR, bool) {
	if z.existsLocked(n) {
		return z.recs[n], true
	}
	if _, parent, ok := strings.Cut(n, "."); ok {
		if rrs := z.recs["*."+parent]; len(rrs) > 0 {
			return rrs, true
		}
	}
	return nil, false
}

// apexLocked is the closest enclosing marked apex of n ("" = none). With
// parent set, n itself doesn't count (DS lives in the parent zone).
func (z *Zone) apexLocked(n string, parent bool) string {
	cur := n
	if parent {
		_, rest, ok := strings.Cut(cur, ".")
		if !ok {
			return ""
		}
		cur = rest
	}
	for {
		if z.soa[cur] || z.keys[cur] != nil || len(z.ds[cur]) > 0 {
			return cur
		}
		_, rest, ok := strings.Cut(cur, ".")
		if !ok {
			return ""
		}
		cur = rest
	}
}

// lookup returns the records of type t answering name: the exact name,
// else the wildcard one label up (*.<parent>), as a DNS server would.
func (z *Zone) lookup(name, t string) []libdns.RR {
	z.mu.Lock()
	defer z.mu.Unlock()
	rrs, _ := z.rrsLocked(norm(name))
	var out []libdns.RR
	for _, rr := range rrs {
		if rr.Type == t {
			out = append(out, rr)
		}
	}
	return out
}

// toDNS converts a libdns RR (data in zone-file form) to a miekg RR owned
// by qname.
func toDNS(qname string, rr libdns.RR) dns.RR {
	ttl := uint32(rr.TTL / time.Second)
	hdr := dns.RR_Header{Name: qname, Rrtype: dns.StringToType[rr.Type], Class: dns.ClassINET, Ttl: ttl}
	switch rr.Type {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(rr.Data)
		if err != nil {
			return nil
		}
		if rr.Type == "A" {
			return &dns.A{Hdr: hdr, A: ip.AsSlice()}
		}
		return &dns.AAAA{Hdr: hdr, AAAA: ip.AsSlice()}
	case "TXT":
		return &dns.TXT{Hdr: hdr, Txt: []string{rr.Data}}
	case "CNAME":
		return &dns.CNAME{Hdr: hdr, Target: dns.Fqdn(rr.Data)}
	case "MX", "CAA":
		out, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", qname, ttl, rr.Type, rr.Data))
		if err != nil || out == nil {
			return nil
		}
		if mx, ok := out.(*dns.MX); ok {
			mx.Mx = dns.Fqdn(mx.Mx)
		}
		return out
	}
	return nil
}

// validation of the zone at apex for a validating resolver.
type validation int

const (
	insecure validation = iota // no DS: answers, AD=0
	secure                     // AD=1
	broken                     // SERVFAIL (CD: answers, AD=0)
)

func (z *Zone) validationLocked(apex string) validation {
	if apex == "" {
		return insecure
	}
	ds := z.ds[apex]
	if len(ds) == 0 {
		return insecure
	}
	k := z.keys[apex]
	if k == nil || z.bogus[apex] {
		return broken
	}
	for _, d := range ds {
		want := k.key.ToDS(d.DigestType)
		if want != nil && want.KeyTag == d.KeyTag && want.Algorithm == d.Algorithm && strings.EqualFold(want.Digest, d.Digest) {
			return secure
		}
	}
	return broken
}

// answer builds the reply to one question (the zone lock held).
func (z *Zone) answerLocked(m *dns.Msg, q dns.Question) {
	n := norm(q.Name)
	switch q.Qtype {
	case dns.TypeSOA:
		if z.soa[n] {
			m.Answer = append(m.Answer, soaRR(n))
			return
		}
	case dns.TypeDNSKEY:
		if k := z.keys[n]; k != nil {
			key, sig := *k.key, *k.sig
			key.Hdr.Name, sig.Hdr.Name = q.Name, q.Name
			m.Answer = append(m.Answer, &key, &sig)
			return
		}
	case dns.TypeDS:
		for _, d := range z.ds[n] {
			c := *d
			c.Hdr.Name = q.Name
			m.Answer = append(m.Answer, &c)
		}
		if len(m.Answer) > 0 {
			return
		}
	}
	rrs, exists := z.rrsLocked(n)
	t := dns.TypeToString[q.Qtype]
	var cname *libdns.RR
	for i, rr := range rrs {
		if rr.Type == "CNAME" && q.Qtype != dns.TypeCNAME {
			cname = &rrs[i]
		}
		if rr.Type == t {
			if out := toDNS(q.Name, rr); out != nil {
				m.Answer = append(m.Answer, out)
			}
		}
	}
	if cname != nil && len(m.Answer) == 0 {
		// A resolver follows the alias (one level is enough here).
		c := toDNS(q.Name, *cname)
		m.Answer = append(m.Answer, c)
		target := norm(cname.Data)
		trrs, texists := z.rrsLocked(target)
		for _, rr := range trrs {
			if rr.Type == t {
				if out := toDNS(dns.Fqdn(target), rr); out != nil {
					m.Answer = append(m.Answer, out)
				}
			}
		}
		if !texists {
			m.Rcode = dns.RcodeNameError
		}
		return
	}
	if !exists && q.Qtype != dns.TypeDS && !(q.Qtype == dns.TypeDNSKEY && z.keys[n] != nil) {
		m.Rcode = dns.RcodeNameError
	}
	if len(m.Answer) == 0 {
		if apex := z.apexLocked(n, false); apex != "" && z.soa[apex] {
			m.Ns = append(m.Ns, soaRR(apex))
		}
	}
}

func soaRR(apex string) *dns.SOA {
	return &dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(apex), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns: "ns1." + dns.Fqdn(apex), Mbox: "hostmaster." + dns.Fqdn(apex), Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300}
}

// Options configure a Server.
type Options struct {
	// Validating: behave like a validating resolver (AD, SERVFAIL, CD).
	Validating bool
}

// Server answers DNS queries from a Zone over UDP and TCP (same port).
type Server struct {
	Addr string // host:port actually listening
	udp  *dns.Server
	tcp  *dns.Server

	qmu     sync.Mutex
	queries []string
}

// Queries returns every question asked so far, "<TYPE> <name>" (name
// lowercase, no trailing dot), in order.
func (s *Server) Queries() []string {
	s.qmu.Lock()
	defer s.qmu.Unlock()
	return append([]string(nil), s.queries...)
}

// Serve starts a DNS server for z on addr ("127.0.0.1:0" for a random
// port).
func Serve(z *Zone, addr string) (*Server, error) { return ServeWith(z, addr, Options{}) }

// ServeWith starts a DNS server for z with options o.
func ServeWith(z *Zone, addr string, o Options) (*Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		return nil, err
	}
	s := &Server{Addr: pc.LocalAddr().String()}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = !o.Validating
		m.RecursionAvailable = o.Validating
		z.mu.Lock()
		for _, q := range req.Question {
			s.qmu.Lock()
			s.queries = append(s.queries, dns.TypeToString[q.Qtype]+" "+norm(q.Name))
			s.qmu.Unlock()
			z.answerLocked(m, q)
			if !o.Validating {
				continue
			}
			n := norm(q.Name)
			v := z.validationLocked(z.apexLocked(n, q.Qtype == dns.TypeDS))
			switch {
			case v == broken && !req.CheckingDisabled:
				fail := new(dns.Msg)
				fail.SetRcode(req, dns.RcodeServerFailure)
				fail.RecursionAvailable = true
				m = fail
			case v == secure:
				m.AuthenticatedData = true
			}
		}
		z.mu.Unlock()
		if opt := req.IsEdns0(); opt != nil {
			m.SetEdns0(opt.UDPSize(), opt.Do())
		}
		_ = w.WriteMsg(m)
	})
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
