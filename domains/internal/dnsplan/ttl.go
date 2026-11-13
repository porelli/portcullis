package dnsplan

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// RRset is one (name, type) RRset as the provider stores it: the longest
// TTL among its records (a provider may raise what was asked for:
// porkbun's floor is 600 s) and its data, sorted.
type RRset struct {
	TTL  time.Duration
	Data []string
}

// setRRsets are the (bare absolute name, type) RRsets a set writes at d.
func setRRsets(d string, sets []string) [][2]string {
	var out [][2]string
	for _, s := range sets {
		switch s {
		case SetAddress:
			for _, n := range []string{d, "*." + d} {
				out = append(out, [2]string{n, "A"}, [2]string{n, "AAAA"})
			}
		case SetCAA:
			out = append(out, [2]string{d, "CAA"})
		case SetNoMail:
			out = append(out, [2]string{d, "MX"}, [2]string{d, "TXT"}, [2]string{"_dmarc." + d, "TXT"})
		}
	}
	return out
}

// Stored reads the provider's RRsets of the sets at name (keyed
// "<name> <TYPE>", the name bare absolute; an empty RRset has no key).
func Stored(ctx context.Context, p Provider, zone, name string, sets []string) (map[string]RRset, error) {
	d := bare(name)
	live, err := providerRecords(ctx, p, dns.Fqdn(zone), d)
	if err != nil {
		return nil, err
	}
	out := map[string]RRset{}
	for _, k := range setRRsets(d, sets) {
		rrs := pick(live, k[0], k[1])
		if len(rrs) == 0 {
			continue
		}
		var s RRset
		for _, rr := range rrs {
			if rr.TTL > s.TTL {
				s.TTL = rr.TTL
			}
			s.Data = append(s.Data, DataKey(k[1], rr.Data))
		}
		sort.Strings(s.Data)
		out[k[0]+" "+k[1]] = s
	}
	return out, nil
}

// NegativeTTL is how long a resolver may cache "no such record" in zone
// (RFC 2308: the lower of the SOA's TTL and its MINIMUM). From the
// authoritative servers when given (a resolver's SOA TTL counts down);
// otherwise the MINIMUM a resolver answers (it doesn't count down; an
// upper bound). The longest answer wins; 0 when none answers a SOA.
func NegativeTTL(ctx context.Context, auth, resolvers []string, zone string) time.Duration {
	ask := func(servers []string, full bool) time.Duration {
		var best time.Duration
		for _, r := range servers {
			in, err := exchange(ctx, r, zone, dns.TypeSOA)
			if err != nil {
				continue
			}
			for _, rr := range append(in.Answer, in.Ns...) {
				if soa, ok := rr.(*dns.SOA); ok {
					t := soa.Minttl
					if full {
						t = min(soa.Hdr.Ttl, soa.Minttl)
					}
					if d := time.Duration(t) * time.Second; d > best {
						best = d
					}
				}
			}
		}
		return best
	}
	if d := ask(auth, true); d > 0 {
		return d
	}
	return ask(resolvers, false)
}

// RemainingTTL is how long resolver still keeps its current answer for
// the item's RRset, read from that answer: the answer's TTL, or for an
// empty answer the TTL of the SOA it carries (the negative cache).
// false when the answer shows neither.
func RemainingTTL(ctx context.Context, resolver string, it Item) (time.Duration, bool) {
	qt, ok := dns.StringToType[strings.ToUpper(it.Type)]
	if !ok || it.Name == "" {
		return 0, false
	}
	qname := it.Name
	if strings.HasPrefix(qname, "*.") {
		qname = ProbeLabel + qname[1:]
	}
	in, err := exchange(ctx, resolver, qname, qt)
	if err != nil {
		return 0, false
	}
	var ttl uint32
	found := false
	for _, rr := range in.Answer {
		if rr.Header().Rrtype == qt && (!found || rr.Header().Ttl < ttl) {
			ttl, found = rr.Header().Ttl, true
		}
	}
	if !found {
		for _, rr := range in.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				ttl, found = min(soa.Hdr.Ttl, soa.Minttl), true
			}
		}
	}
	return time.Duration(ttl) * time.Second, found
}

// AuthServers are the zone's authoritative nameservers (host:53), found
// through the resolvers (NS, then each target's A and AAAA); at most 4.
// Nothing when they can't be found.
func AuthServers(ctx context.Context, resolvers []string, zone string) []string {
	var out []string
	for _, r := range resolvers {
		in, err := exchange(ctx, r, zone, dns.TypeNS)
		if err != nil {
			continue
		}
		for _, rr := range in.Answer {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
				a, err := exchange(ctx, r, ns.Ns, qt)
				if err != nil {
					continue
				}
				for _, x := range a.Answer {
					var ip string
					switch v := x.(type) {
					case *dns.A:
						ip = v.A.String()
					case *dns.AAAA:
						ip = v.AAAA.String()
					default:
						continue
					}
					if hp := net.JoinHostPort(ip, "53"); !contains(out, hp) && len(out) < 4 {
						out = append(out, hp)
					}
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return out
}

// ServedTTL is the longest TTL the servers (authoritative: what caches
// got) serve for the RRset (name, typ); false when none answers it.
func ServedTTL(ctx context.Context, servers []string, name, typ string) (time.Duration, bool) {
	qt, ok := dns.StringToType[strings.ToUpper(typ)]
	if !ok {
		return 0, false
	}
	var best time.Duration
	found := false
	for _, s := range servers {
		in, err := exchange(ctx, s, name, qt)
		if err != nil {
			continue
		}
		for _, rr := range in.Answer {
			if rr.Header().Rrtype == qt {
				found = true
				if d := time.Duration(rr.Header().Ttl) * time.Second; d > best {
					best = d
				}
			}
		}
	}
	return best, found
}
