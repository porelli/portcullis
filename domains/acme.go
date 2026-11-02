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
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/libdns/libdns"
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
	cfg := lego.NewConfig(u)
	cfg.CADirURL = s.cfg.CAServer
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.UserAgent = "portcullis-domains"
	if s.cfg.ACMEHTTPClient != nil {
		cfg.HTTPClient = s.cfg.ACMEHTTPClient
	}
	return cfg
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
		key, err := parseECKey(acct.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("stored ACME account key: %w", err)
		}
		var reg registration.Resource
		if err := json.Unmarshal(acct.Registration, &reg); err != nil {
			return nil, fmt.Errorf("stored ACME registration: %w", err)
		}
		return &acmeUser{email: acct.Email, reg: &reg, key: key}, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	u := &acmeUser{email: s.cfg.Email, key: key}
	client, err := lego.NewClient(s.legoConfig(u))
	if err != nil {
		return nil, fmt.Errorf("ACME directory %s: %w", s.cfg.CAServer, err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("ACME account registration: %w", err)
	}
	u.reg = reg
	regJSON, err := json.Marshal(reg)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.doc.Account = &Account{Email: s.cfg.Email, CAServer: s.cfg.CAServer, Registration: regJSON,
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))}
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

// challengeProvider presents DNS-01 TXT records with a libdns provider.
type challengeProvider struct {
	s *Service
	p dnsProvider
}

func (c *challengeProvider) txt(domain, keyAuth string) (zone string, rec libdns.TXT, err error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	zone, err = c.s.zoneOf(c.p, info.EffectiveFQDN)
	if err != nil {
		return "", rec, fmt.Errorf("finding the DNS zone of %s: %w", info.EffectiveFQDN, err)
	}
	return zone, libdns.TXT{Name: libdns.RelativeName(info.EffectiveFQDN, zone), TTL: 60 * time.Second, Text: info.Value}, nil
}

// Present adds the challenge TXT record (appended: <name> and *.<name>
// share _acme-challenge.<name>).
func (c *challengeProvider) Present(domain, _, keyAuth string) error {
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
func (c *challengeProvider) CleanUp(domain, _, keyAuth string) error {
	zone, rec, err := c.txt(domain, keyAuth)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err = c.p.DeleteRecords(ctx, zone, []libdns.Record{rec})
	return err
}

// Timeout bounds the propagation wait.
func (c *challengeProvider) Timeout() (timeout, interval time.Duration) {
	return c.s.cfg.PropagationTimeout, c.s.cfg.PropagationInterval
}

// obtain orders a certificate for <name> and *.<name> (fresh EC P-256 key)
// and returns the full chain, the key and the expiry.
func (s *Service) obtain(name string, p dnsProvider) (certPEM, keyPEM string, notAfter time.Time, err error) {
	u, err := s.account()
	if err != nil {
		return "", "", time.Time{}, err
	}
	client, err := lego.NewClient(s.legoConfig(u))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("ACME directory %s: %w", s.cfg.CAServer, err)
	}
	skip := false
	if ps, ok := p.(propagationSkipper); ok {
		skip = ps.SkipPropagationCheck()
	}
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
