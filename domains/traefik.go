package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"time"
)

// The certificate endpoint (contract §12.4): Traefik's HTTP provider polls
// GET https://domains:8443/traefik/dynamic over mutual TLS and applies
// whatever dynamic configuration it gets. The document is therefore built
// from a type that can hold nothing but tls.certificates (certFile /
// keyFile as inline PEM) — no routers, services, middlewares, TLS options,
// stores or transports can ever be emitted — and every certificate is
// checked before it is served.

type dynamicDoc struct {
	TLS dynamicTLS `json:"tls"`
}

type dynamicTLS struct {
	Certificates []dynamicCert `json:"certificates"`
}

type dynamicCert struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// servable checks one domain's certificate against contract §12.4 "Only
// enrolled-domain names": the name passes checkName (never the main
// domain, a parent of it, or at / under a core host), the leaf's SANs are
// exactly {<name>, *.<name>} (DNS names only: no IP, email or URI SANs),
// it is valid now, and the key belongs to it.
func servable(d *Domain, main string, now time.Time) error {
	if err := checkName(d.Name, main); err != nil {
		return err
	}
	if d.CertPEM == "" || d.KeyPEM == "" {
		return errors.New("no certificate")
	}
	pair, err := tls.X509KeyPair([]byte(d.CertPEM), []byte(d.KeyPEM))
	if err != nil {
		return fmt.Errorf("certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if cn := leaf.Subject.CommonName; cn != "" && cn != d.Name && cn != "*."+d.Name {
		return fmt.Errorf("certificate common name %q is not %s or *.%s", cn, d.Name, d.Name)
	}
	if len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) > 0 {
		return errors.New("certificate has non-DNS names")
	}
	sans := append([]string(nil), leaf.DNSNames...)
	sort.Strings(sans)
	want := []string{"*." + d.Name, d.Name}
	if len(sans) != 2 || sans[0] != want[0] || sans[1] != want[1] {
		return fmt.Errorf("certificate names %v, want exactly %v", leaf.DNSNames, want)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("certificate not valid now (%s – %s)", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	// Every PEM block of the chain must be a certificate (the inline
	// certFile is passed to Traefik as-is).
	rest := []byte(d.CertPEM)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return fmt.Errorf("certificate chain holds a %s block", b.Type)
		}
	}
	return nil
}

// buildDynamic returns the document for every enrolled domain whose
// certificate is servable, sorted by name; dropped lists (name, reason)
// of the others that have a certificate (logged without key material).
func buildDynamic(domains map[string]*Domain, main string, now time.Time) (dynamicDoc, []string) {
	doc := dynamicDoc{TLS: dynamicTLS{Certificates: []dynamicCert{}}}
	names := make([]string, 0, len(domains))
	for n := range domains {
		names = append(names, n)
	}
	sort.Strings(names)
	var dropped []string
	for _, n := range names {
		d := domains[n]
		if d.CertPEM == "" || d.Deleting {
			continue
		}
		if d.Name != n {
			dropped = append(dropped, fmt.Sprintf("%s: stored under another name (%s)", n, d.Name))
			continue
		}
		if err := servable(d, main, now); err != nil {
			dropped = append(dropped, fmt.Sprintf("%s: %v", n, err))
			continue
		}
		doc.TLS.Certificates = append(doc.TLS.Certificates, dynamicCert{CertFile: d.CertPEM, KeyFile: d.KeyPEM})
	}
	return doc, dropped
}
