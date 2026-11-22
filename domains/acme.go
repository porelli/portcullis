package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/libdns/libdns"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/dnsplan"
)

// ACME DNS-01 with lego as a library (contract §12.4 "Certificates"): one
// account for the service, one order per domain for <name> and *.<name>,
// the challenge TXT records written with the domain's own libdns provider
// (so two accounts at one provider coexist).

type acmeUser struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// legoConfig is the lego client configuration for user.
func (s *Service) legoConfig(u *acmeUser) *lego.Config {
	return legoConfigFor(u, s.cfg.CAServer, s.cfg.ACMEHTTPClient)
}

// legoConfigFor is the lego client configuration for user at the ACME
// directory caServer (hc: lego's HTTP client, nil = its default).
func legoConfigFor(u *acmeUser, caServer string, hc *http.Client) *lego.Config {
	cfg := lego.NewConfig(u)
	cfg.CADirURL = caServer
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.UserAgent = "portcullis-domains"
	if hc != nil {
		// A copy: lego wraps the client's transport in place, so a shared
		// client would be raced (and re-wrapped) by concurrent orders.
		c := *hc
		cfg.HTTPClient = &c
	}
	return cfg
}

// registerAccount registers a new ACME account (fresh EC P-256 key) for
// email at caServer.
func registerAccount(email, caServer string, hc *http.Client) (*acmeUser, *Account, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	u := &acmeUser{email: email, key: key}
	client, err := lego.NewClient(legoConfigFor(u, caServer, hc))
	if err != nil {
		return nil, nil, fmt.Errorf("ACME directory %s: %w", caServer, err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("ACME account registration: %w", err)
	}
	u.reg = reg
	regJSON, err := json.Marshal(reg)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return u, &Account{Email: email, CAServer: caServer, Registration: regJSON,
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))}, nil
}

// accountUser is the lego user of a stored account.
func accountUser(a *Account) (*acmeUser, error) {
	key, err := parseECKey(a.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("stored ACME account key: %w", err)
	}
	var reg registration.Resource
	if err := json.Unmarshal(a.Registration, &reg); err != nil {
		return nil, fmt.Errorf("stored ACME registration: %w", err)
	}
	return &acmeUser{email: a.Email, reg: &reg, key: key}, nil
}

// accountCurrentLocked: the stored account matches the configured CA and
// email (else account() registers a new one). Caller holds mu.
func (s *Service) accountCurrentLocked() bool {
	a := s.doc.Account
	return a != nil && a.CAServer == s.cfg.CAServer && a.Email == s.cfg.Email && len(a.Registration) > 0
}

// accountURILocked is the stored account's URI ("" = none or stale).
// Caller holds mu.
func (s *Service) accountURILocked() string {
	if !s.accountCurrentLocked() {
		return ""
	}
	var reg registration.Resource
	if json.Unmarshal(s.doc.Account.Registration, &reg) != nil {
		return ""
	}
	return reg.URI
}

// account returns the ACME account, creating and registering it on first
// use (or when ACME_CA_SERVER changed). acmeMu serialises registration;
// the store lock is never held across the network call.
func (s *Service) account() (*acmeUser, error) {
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	s.mu.Lock()
	acct := s.doc.Account
	s.mu.Unlock()
	if acct != nil && acct.CAServer == s.cfg.CAServer && acct.Email == s.cfg.Email && len(acct.Registration) > 0 {
		return accountUser(acct)
	}
	u, a, err := registerAccount(s.cfg.Email, s.cfg.CAServer, s.cfg.ACMEHTTPClient)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.doc.Account = a
	err = s.store.Save(s.doc)
	s.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("saving the ACME account: %w", err)
	}
	return u, nil
}

func parseECKey(p string) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

// challengeProvider is the service's DNS-01 provider: dns01Provider with
// the service's zone lookup and propagation timeouts.
type challengeProvider struct {
	s *Service
	p dnsProvider
}

func (c *challengeProvider) free() *dns01Provider {
	return &dns01Provider{p: c.p, zoneOf: func(fqdn string) (string, error) { return c.s.zoneOf(c.p, fqdn) },
		timeout: c.s.cfg.PropagationTimeout, interval: c.s.cfg.PropagationInterval}
}

func (c *challengeProvider) Present(domain, token, keyAuth string) error {
	return c.free().Present(domain, token, keyAuth)
}

func (c *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	return c.free().CleanUp(domain, token, keyAuth)
}

func (c *challengeProvider) Timeout() (timeout, interval time.Duration) { return c.free().Timeout() }

// dns01Provider presents DNS-01 TXT records with a libdns provider p;
// zoneOf finds the zone holding an FQDN (the service's lookup, or the
// tool's: mail-cert has no Service).
type dns01Provider struct {
	p                 dnsProvider
	zoneOf            func(fqdn string) (string, error)
	timeout, interval time.Duration
}

func (c *dns01Provider) txt(domain, keyAuth string) (zone string, rec libdns.TXT, err error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	zone, err = c.zoneOf(info.EffectiveFQDN)
	if err != nil {
		return "", rec, fmt.Errorf("finding the DNS zone of %s: %w", info.EffectiveFQDN, err)
	}
	return zone, libdns.TXT{Name: libdns.RelativeName(info.EffectiveFQDN, zone), TTL: 60 * time.Second, Text: info.Value}, nil
}

// Present adds the challenge TXT record (appended: <name> and *.<name>
// share _acme-challenge.<name>).
func (c *dns01Provider) Present(domain, _, keyAuth string) error {
	zone, rec, err := c.txt(domain, keyAuth)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := c.p.AppendRecords(ctx, zone, []libdns.Record{rec}); err != nil {
		return fmt.Errorf("adding the DNS-01 TXT record: %w", err)
	}
	return nil
}

// CleanUp removes the challenge TXT record.
func (c *dns01Provider) CleanUp(domain, _, keyAuth string) error {
	zone, rec, err := c.txt(domain, keyAuth)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// TTL 0 matches any: providers may store another TTL than asked
	// (porkbun raises anything under 600 s); the key-auth value is unique.
	rec.TTL = 0
	_, err = c.p.DeleteRecords(ctx, zone, []libdns.Record{rec})
	return err
}

// Timeout bounds the propagation wait.
func (c *dns01Provider) Timeout() (timeout, interval time.Duration) {
	return c.timeout, c.interval
}

// skipsPropagation: the provider has no authoritative nameservers for
// lego's propagation check (the test provider).
func skipsPropagation(p dnsProvider) bool {
	in, _ := unwrap(p)
	ps, ok := in.(propagationSkipper)
	return ok && ps.SkipPropagationCheck()
}

// obtain orders a certificate for <name> and *.<name> (fresh EC P-256 key)
// with the account u (registered by the caller before the CAA was pinned
// to it) and returns the full chain, the key and the expiry.
func (s *Service) obtain(name string, p dnsProvider, u *acmeUser) (certPEM, keyPEM string, notAfter time.Time, err error) {
	client, err := lego.NewClient(s.legoConfig(u))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("ACME directory %s: %w", s.cfg.CAServer, err)
	}
	skip := skipsPropagation(p)
	err = client.Challenge.SetDNS01Provider(&challengeProvider{s: s, p: p},
		dns01.CondOption(skip, dns01.WrapPreCheck(func(_, _, _ string, _ dns01.PreCheckFunc) (bool, error) { return true, nil })))
	if err != nil {
		return "", "", time.Time{}, err
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{name, "*." + name}, Bundle: true})
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("ACME order for %s and *.%s: %w", name, name, err)
	}
	leaf, err := parseLeaf(string(res.Certificate))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("issued certificate: %w", err)
	}
	return string(res.Certificate), string(res.PrivateKey), leaf.NotAfter.UTC(), nil
}

func parseLeaf(chain string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(chain))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate PEM block")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ── the front door's account (HA, contract §20.8) ──

// frontdoorACME is the front door's ACME side: its OWN account, never the
// added-domains one (one account per name, CAA accounturi; spec §11.2),
// kept in the front door's store under the key "frontdoor" (the Secret
// frontdoor-acme, frontdoor.AccountKey; the same Account shape as the
// domains service's store). Only the CA decides whether the stored account
// is current: an ACME_EMAIL change keeps it (a new account would need the
// CAA flip).
type frontdoorACME struct {
	email, caServer string
	hc              *http.Client
	// skipPropagation: the provider has no authoritative nameservers for
	// lego's check (the test provider).
	skipPropagation   bool
	timeout, interval time.Duration
}

func (a *frontdoorACME) parse(stored []byte) (*Account, *acmeUser, error) {
	if len(stored) == 0 {
		return nil, nil, errors.New("no account")
	}
	var acct Account
	if err := json.Unmarshal(stored, &acct); err != nil {
		return nil, nil, fmt.Errorf("the stored front-door account: %w", err)
	}
	u, err := accountUser(&acct)
	if err != nil {
		return nil, nil, err
	}
	return &acct, u, nil
}

// CurrentURI: the stored account's URI when it belongs to this CA.
func (a *frontdoorACME) CurrentURI(stored []byte) string {
	acct, u, err := a.parse(stored)
	if err != nil || acct.CAServer != a.caServer || u.reg == nil || !dnsplan.ValidAccountURI(u.reg.URI) {
		return ""
	}
	return u.reg.URI
}

// Register registers a new account (fresh EC P-256 key) at the CA.
func (a *frontdoorACME) Register(context.Context) ([]byte, string, error) {
	u, acct, err := registerAccount(a.email, a.caServer, a.hc)
	if err != nil {
		return nil, "", err
	}
	b, err := json.Marshal(acct)
	if err != nil {
		return nil, "", err
	}
	return b, u.reg.URI, nil
}

// Obtain orders domain and *.domain (fresh EC P-256 key) with the stored
// account, the challenge records through dns (the front door's Writer).
func (a *frontdoorACME) Obtain(ctx context.Context, stored []byte, domain string, dns frontdoor.DNS01) (string, string, error) {
	_, u, err := a.parse(stored)
	if err != nil {
		return "", "", err
	}
	client, err := lego.NewClient(legoConfigFor(u, a.caServer, a.hc))
	if err != nil {
		return "", "", fmt.Errorf("ACME directory %s: %w", a.caServer, err)
	}
	p := &frontdoorChallenge{ctx: ctx, dns: dns, timeout: a.timeout, interval: a.interval}
	if err := client.Challenge.SetDNS01Provider(p, dns01.CondOption(a.skipPropagation,
		dns01.WrapPreCheck(func(_, _, _ string, _ dns01.PreCheckFunc) (bool, error) { return true, nil }))); err != nil {
		return "", "", err
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{domain, "*." + domain}, Bundle: true})
	if err != nil {
		return "", "", err
	}
	return string(res.Certificate), string(res.PrivateKey), nil
}

// frontdoorChallenge is lego's DNS-01 provider over the front door's
// Writer (which refuses any name but _acme-challenge.<d> and writes only
// while leading).
type frontdoorChallenge struct {
	ctx               context.Context
	dns               frontdoor.DNS01
	timeout, interval time.Duration
}

func (c *frontdoorChallenge) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.dns.PresentTXT(c.ctx, info.EffectiveFQDN, info.Value)
}

func (c *frontdoorChallenge) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.dns.CleanUpTXT(c.ctx, info.EffectiveFQDN, info.Value)
}

func (c *frontdoorChallenge) Timeout() (time.Duration, time.Duration) {
	return orDur(c.timeout, 10*time.Minute), orDur(c.interval, 5*time.Second)
}
