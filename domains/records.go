package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/hetzner"
	"github.com/libdns/libdns"
	"github.com/libdns/porkbun"
	"github.com/libdns/route53"
	"github.com/miekg/dns"
)

// DNS providers (contract §12.2): the ones core's `dns setup` supports,
// each through its libdns package. Credentials are exactly the listed keys.

// dnsProvider is what the service needs from a libdns provider.
type dnsProvider interface {
	libdns.RecordGetter
	libdns.RecordAppender
	libdns.RecordSetter
	libdns.RecordDeleter
}

// zoneFinder: a provider that knows the zone itself (route53 with
// hosted_zone_id, the test provider) skips the SOA lookup.
type zoneFinder interface {
	FindZone(fqdn string) (string, error)
}

// propagationSkipper: the test provider has no authoritative nameservers
// for lego's propagation check (Pebble asks its DNS server directly).
type propagationSkipper interface {
	SkipPropagationCheck() bool
}

type providerSpec struct {
	required []string
	optional []string
	build    func(c map[string]string) dnsProvider
}

// fixedZone is a route53 provider with a hosted zone id: the zone is the
// domain itself (records are named relative to it).
type fixedZone struct{ dnsProvider }

func (fixedZone) FindZone(fqdn string) (string, error) {
	return dns.Fqdn(strings.TrimPrefix(fqdn, "_acme-challenge.")), nil
}

var providers = map[string]providerSpec{
	"cloudflare": {required: []string{"api_token"}, build: func(c map[string]string) dnsProvider {
		return &cloudflare.Provider{APIToken: c["api_token"]}
	}},
	"porkbun": {required: []string{"api_key", "secret_api_key"}, build: func(c map[string]string) dnsProvider {
		return &porkbun.Provider{APIKey: c["api_key"], APISecretKey: c["secret_api_key"]}
	}},
	"route53": {required: []string{"access_key_id", "secret_access_key"}, optional: []string{"hosted_zone_id"}, build: func(c map[string]string) dnsProvider {
		// Route 53 is global; the region only selects the API endpoint.
		p := &route53.Provider{AccessKeyId: c["access_key_id"], SecretAccessKey: c["secret_access_key"],
			HostedZoneID: c["hosted_zone_id"], Region: "us-east-1"}
		if c["hosted_zone_id"] != "" {
			return fixedZone{p}
		}
		return p
	}},
	"digitalocean": {required: []string{"auth_token"}, build: func(c map[string]string) dnsProvider {
		return &digitalocean.Provider{APIToken: c["auth_token"]}
	}},
	"hetzner": {required: []string{"api_token"}, build: func(c map[string]string) dnsProvider {
		return hetzner.New(c["api_token"])
	}},
}

// validateCredentials checks provider and keys (exactly the listed keys,
// non-empty strings). The message names keys, never values.
func validateCredentials(provider string, creds map[string]string) error {
	spec, ok := providers[provider]
	if !ok {
		names := make([]string, 0, len(providers))
		for n := range providers {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown provider %q (one of %s)", provider, strings.Join(names, ", "))
	}
	allowed := map[string]bool{}
	for _, k := range spec.required {
		allowed[k] = true
		if creds[k] == "" {
			return fmt.Errorf("provider %s needs the credential key %s (non-empty)", provider, k)
		}
	}
	for _, k := range spec.optional {
		allowed[k] = true
	}
	var unknown []string
	for k, v := range creds {
		if !allowed[k] {
			unknown = append(unknown, k)
			continue
		}
		if v == "" && !contains(spec.required, k) {
			return fmt.Errorf("credential key %s must be a non-empty string (or left out)", k)
		}
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("credential key %s contains a line break", k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("provider %s: unknown credential keys %s", provider, strings.Join(unknown, ", "))
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func buildProvider(d *Domain) (dnsProvider, error) {
	spec, ok := providers[d.Provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", d.Provider)
	}
	return spec.build(d.Credentials), nil
}

// zoneOf finds the zone holding fqdn: the provider's own answer, else a
// SOA lookup (lego's dns01.FindZoneByFqdn, the resolvers set at start).
func (s *Service) zoneOf(p dnsProvider, fqdn string) (string, error) {
	if zf, ok := p.(zoneFinder); ok {
		return zf.FindZone(fqdn)
	}
	return s.findZone(dns.Fqdn(fqdn))
}

const recordTTL = 300 * time.Second

// setRecords points <name> and *.<name> at the server (contract §12.4):
// A to the IPv4 and AAAA to the IPv6 (replacing what is there); without
// an IPv6, existing AAAA records at those names are removed. Returns the
// records set and the zone.
func (s *Service) setRecords(ctx context.Context, p dnsProvider, name string) ([]RecordRef, string, error) {
	if !s.cfg.IPv4.IsValid() {
		return nil, "", errors.New("the server's public IPv4 is unknown (./portcullis up sets DOMAINS_PUBLIC_IPV4)")
	}
	zone, err := s.zoneOf(p, name)
	if err != nil {
		return nil, "", fmt.Errorf("finding the DNS zone of %s: %w", name, err)
	}
	var recs []libdns.Record
	var refs []RecordRef
	for _, n := range []string{name, "*." + name} {
		rel := libdns.RelativeName(dns.Fqdn(n), zone)
		for _, ip := range []netip.Addr{s.cfg.IPv4, s.cfg.IPv6} {
			if !ip.IsValid() {
				continue
			}
			a := libdns.Address{Name: rel, TTL: recordTTL, IP: ip}
			recs = append(recs, a)
			rr := a.RR()
			refs = append(refs, RecordRef{Name: rr.Name, Type: rr.Type, Value: rr.Data})
		}
	}
	if _, err := p.SetRecords(ctx, zone, recs); err != nil {
		return nil, zone, fmt.Errorf("setting the A/AAAA records of %s and *.%s: %w", name, name, err)
	}
	if !s.cfg.IPv6.IsValid() {
		var stale []libdns.Record
		for _, n := range []string{name, "*." + name} {
			stale = append(stale, libdns.RR{Name: libdns.RelativeName(dns.Fqdn(n), zone), Type: "AAAA"})
		}
		if _, err := p.DeleteRecords(ctx, zone, stale); err != nil {
			return nil, zone, fmt.Errorf("removing old AAAA records of %s (the server has no IPv6): %w", name, err)
		}
	}
	return refs, zone, nil
}

// deleteRecords removes exactly the records the service created.
func deleteRecords(ctx context.Context, p dnsProvider, zone string, refs []RecordRef) error {
	if len(refs) == 0 {
		return nil
	}
	recs := make([]libdns.Record, 0, len(refs))
	for _, r := range refs {
		rr := libdns.RR{Name: r.Name, Type: r.Type, Data: r.Value, TTL: recordTTL}
		if parsed, err := rr.Parse(); err == nil {
			recs = append(recs, parsed)
		} else {
			recs = append(recs, rr)
		}
	}
	_, err := p.DeleteRecords(ctx, zone, recs)
	return err
}

// probeLabel names the host checked under *.<name>.
const probeLabel = "portcullis-probe"

// checkRecords reports whether <name> and portcullis-probe.<name> resolve
// to exactly the server's addresses (A, and AAAA when it has IPv6; no AAAA
// otherwise) at every configured resolver (contract §12.2 records_ok).
func (s *Service) checkRecords(ctx context.Context, name string) error {
	c := &dns.Client{Timeout: 5 * time.Second}
	for _, resolver := range s.cfg.Resolvers {
		for _, host := range []string{name, probeLabel + "." + name} {
			for _, q := range []struct {
				t    uint16
				want netip.Addr
			}{{dns.TypeA, s.cfg.IPv4}, {dns.TypeAAAA, s.cfg.IPv6}} {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(host), q.t)
				m.RecursionDesired = true
				in, _, err := c.ExchangeContext(ctx, m, resolver)
				if err != nil {
					return fmt.Errorf("%s at %s: %w", host, resolver, err)
				}
				var got []string
				for _, rr := range in.Answer {
					switch v := rr.(type) {
					case *dns.A:
						if q.t == dns.TypeA {
							got = append(got, v.A.String())
						}
					case *dns.AAAA:
						if q.t == dns.TypeAAAA {
							got = append(got, v.AAAA.String())
						}
					}
				}
				want := []string{}
				if q.want.IsValid() {
					want = []string{q.want.String()}
				}
				sort.Strings(got)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					return fmt.Errorf("%s %s at %s is %v, want %v", host, dns.TypeToString[q.t], resolver, got, want)
				}
			}
		}
	}
	return nil
}

// legoZoneFinder is the default zone lookup.
func legoZoneFinder(fqdn string) (string, error) { return dns01.FindZoneByFqdn(fqdn) }
