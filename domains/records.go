package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
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
	build    func(c map[string]string) (dnsProvider, error)
}

// fixedZone is a route53 provider with a hosted zone id: the zone is the
// domain itself (records are named relative to it).
type fixedZone struct{ dnsProvider }

func (fixedZone) FindZone(fqdn string) (string, error) {
	return dns.Fqdn(strings.TrimPrefix(fqdn, "_acme-challenge.")), nil
}

var providers = map[string]providerSpec{
	"cloudflare": {required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return &cloudflare.Provider{APIToken: c["api_token"], HTTPClient: &http.Client{Timeout: providerTimeout}}, nil
	}},
	"porkbun": {required: []string{"api_key", "secret_api_key"}, build: func(c map[string]string) (dnsProvider, error) {
		return &porkbun.Provider{APIKey: c["api_key"], APISecretKey: c["secret_api_key"]}, nil
	}},
	"route53": {required: []string{"access_key_id", "secret_access_key"}, optional: []string{"hosted_zone_id"}, build: func(c map[string]string) (dnsProvider, error) {
		// Route 53 is global; the region only selects the API endpoint.
		p := &route53.Provider{AccessKeyId: c["access_key_id"], SecretAccessKey: c["secret_access_key"],
			HostedZoneID: c["hosted_zone_id"], Region: "us-east-1", MaxRetries: 5}
		// The library log.Fatal()s if loading the AWS config fails: load it
		// here first with the library's exact options and return the error.
		if err := route53Preflight(p); err != nil {
			return nil, err
		}
		if c["hosted_zone_id"] != "" {
			return fixedZone{p}, nil
		}
		return p, nil
	}},
	"digitalocean": {required: []string{"auth_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return &digitalocean.Provider{APIToken: c["auth_token"]}, nil
	}},
	"hetzner": {required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return hetzner.New(c["api_token"]), nil
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
		// Secrets shorter than this couldn't be redacted reliably (and no
		// provider issues them); hosted_zone_id isn't a secret.
		if k != "hosted_zone_id" && len(v) < minSecretLen {
			return fmt.Errorf("credential key %s is too short (at least %d characters)", k, minSecretLen)
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

// buildProvider returns the domain's provider behind redacting: every
// error any provider call returns (records, DNS-01 challenge, delete) has
// the domain's credentials redacted before anything can log, store or
// return it — libdns providers may echo tokens or request bodies.
func buildProvider(d *Domain) (dnsProvider, error) {
	spec, ok := providers[d.Provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", d.Provider)
	}
	creds := make(map[string]string, len(d.Credentials))
	for k, v := range d.Credentials {
		creds[k] = v
	}
	inner, err := spec.build(d.Credentials)
	if err != nil {
		return nil, errors.New(redact(err.Error(), creds))
	}
	return redacting{inner: inner, creds: creds}, nil
}

// redacting wraps a provider; its errors carry no credential.
type redacting struct {
	inner dnsProvider
	creds map[string]string
}

func (r redacting) clean(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(redact(err.Error(), r.creds))
}

func (r redacting) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	out, err := r.inner.GetRecords(ctx, zone)
	return out, r.clean(err)
}

func (r redacting) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out, err := r.inner.AppendRecords(ctx, zone, recs)
	return out, r.clean(err)
}

func (r redacting) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out, err := r.inner.SetRecords(ctx, zone, recs)
	return out, r.clean(err)
}

func (r redacting) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	out, err := r.inner.DeleteRecords(ctx, zone, recs)
	return out, r.clean(err)
}

// unwrap returns the provider under redacting (for its optional
// interfaces) and the error cleaner.
func unwrap(p dnsProvider) (dnsProvider, func(error) error) {
	if r, ok := p.(redacting); ok {
		return r.inner, r.clean
	}
	return p, func(err error) error { return err }
}

// zoneOf finds the zone holding fqdn: the provider's own answer, else a
// SOA lookup (lego's dns01.FindZoneByFqdn, the resolvers set at start).
func (s *Service) zoneOf(p dnsProvider, fqdn string) (string, error) {
	inner, clean := unwrap(p)
	if zf, ok := inner.(zoneFinder); ok {
		z, err := zf.FindZone(fqdn)
		return z, clean(err)
	}
	return s.findZone(dns.Fqdn(fqdn))
}

const recordTTL = 300 * time.Second

// minSecretLen is the shortest credential value accepted (redaction of
// anything shorter would be unreliable).
const minSecretLen = 8

// providerTimeout bounds one provider HTTP request where the library lets
// us set a client (the others use http.DefaultTransport, whose dial, TLS
// and response-header timeouts main sets at start).
const providerTimeout = 2 * time.Minute

// route53Preflight loads the AWS config exactly as libdns/route53 does
// (retryer, region, static credentials) and returns the error the library
// would log.Fatal on.
func route53Preflight(p *route53.Provider) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRetryer(func() aws.Retryer { return retry.AddWithMaxAttempts(retry.NewStandard(), p.MaxRetries) }),
		awsconfig.WithRegion(p.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(p.AccessKeyId, p.SecretAccessKey, p.SessionToken)))
	if err != nil {
		return fmt.Errorf("route53: loading the AWS configuration: %w", err)
	}
	return nil
}

// setRecords points <name> and *.<name> at the server (contract §12.4):
// A to the IPv4 and AAAA to the IPv6 (replacing what is there); without
// an IPv6, existing AAAA records at those names are removed. Returns the
// records set and the zone.
func (s *Service) setRecords(ctx context.Context, p dnsProvider, name string) ([]RecordRef, string, error) {
	if !s.cfg.IPv4.IsValid() {
		return nil, "", errors.New("the server's public IPv4 is unknown (./portcullis up detects it once a domain is enrolled — run it again — or set PORTCULLIS_PUBLIC_IPV4 in .env)")
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
		return refs, zone, fmt.Errorf("setting the A/AAAA records of %s and *.%s: %w", name, name, err)
	}
	if !s.cfg.IPv6.IsValid() {
		var stale []libdns.Record
		for _, n := range []string{name, "*." + name} {
			stale = append(stale, libdns.RR{Name: libdns.RelativeName(dns.Fqdn(n), zone), Type: "AAAA"})
		}
		if _, err := p.DeleteRecords(ctx, zone, stale); err != nil {
			return refs, zone, fmt.Errorf("removing old AAAA records of %s (the server has no IPv6): %w", name, err)
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
func (s *Service) checkRecords(ctx context.Context, name string, v4, v6 netip.Addr) error {
	if !v4.IsValid() {
		return errors.New("the server's public IPv4 is unknown (./portcullis up detects it, or set PORTCULLIS_PUBLIC_IPV4 in .env)")
	}
	c := &dns.Client{Timeout: 5 * time.Second}
	for _, resolver := range s.cfg.Resolvers {
		for _, host := range []string{name, probeLabel + "." + name} {
			for _, q := range []struct {
				t    uint16
				want netip.Addr
			}{{dns.TypeA, v4}, {dns.TypeAAAA, v6}} {
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
