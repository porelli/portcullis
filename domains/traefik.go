package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	// HTTP carries, in HA only, the readiness route of the main
	// certificate (MainCertReadyPath): present exactly when the main
	// domain's certificate is in the same document.
	HTTP *dynamicHTTP `json:"http,omitempty"`
}

type dynamicHTTP struct {
	Routers map[string]dynamicRouter `json:"routers"`
}

type dynamicRouter struct {
	EntryPoints []string `json:"entryPoints"`
	Rule        string   `json:"rule"`
	Service     string   `json:"service"`
}

// MainCertReadyPath is the HA Traefik's readiness route (Task 31 fix round
// 1, M3): Traefik's own ping service on its internal entrypoint "traefik"
// (:8080), routed only by a document that also carries the main domain's
// certificate. Traefik loads one provider document at a time, so the route
// answers 200 only once the main certificate is loaded: until then the pod
// isn't Ready (no default certificate behind a Ready ingress, and the
// front door publishes only Ready ingress nodes). The chart's HA readiness
// probe asks this path.
const MainCertReadyPath = "/portcullis-main-cert"

// MainCertReadyRouter is that route's router name.
const MainCertReadyRouter = "portcullis-main-cert-ready"

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
func servable(d *Domain, main, mailHost string, now time.Time) error {
	if err := checkName(d.Name, main, mailHost); err != nil {
		return err
	}
	return checkCertFor(d.Name, d.CertPEM, d.KeyPEM, now)
}

// servableHA checks the main domain's certificate from the front door's
// store (HA, contract §12.4 "Only Portcullis names"): exactly {<main>,
// *.<main>} (DNS names only), the subject common name "" / <main> /
// *.<main>, valid now, the key its own, every PEM block a certificate — and
// never when MAIL_HOSTNAME is the main domain itself (the mail provider
// owns that name's certificate and TLSA, §19.3: servable's mail-host
// exclusion kept). Nothing else is ever served as the main domain's.
func servableHA(certPEM, keyPEM, main, mailHost string, now time.Time) error {
	if main == "" || !validHostname(main) {
		return fmt.Errorf("the main domain %q is not a hostname", main)
	}
	if mailHost != "" && strings.EqualFold(strings.TrimSuffix(mailHost, "."), main) {
		return fmt.Errorf("the main domain %s is MAIL_HOSTNAME: the mail provider owns its certificate", main)
	}
	return checkCertFor(main, certPEM, keyPEM, now)
}

// checkCertFor: certPEM / keyPEM are a pair whose leaf names exactly
// {name, *.name} (DNS names only; CN "", name or *.name), valid now, and
// the chain holds only CERTIFICATE blocks.
func checkCertFor(name, certPEM, keyPEM string, now time.Time) error {
	if certPEM == "" || keyPEM == "" {
		return errors.New("no certificate")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return fmt.Errorf("certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if cn := leaf.Subject.CommonName; cn != "" && cn != name && cn != "*."+name {
		return fmt.Errorf("certificate common name %q is not %s or *.%s", cn, name, name)
	}
	if len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) > 0 {
		return errors.New("certificate has non-DNS names")
	}
	sans := append([]string(nil), leaf.DNSNames...)
	sort.Strings(sans)
	want := []string{"*." + name, name}
	if len(sans) != 2 || sans[0] != want[0] || sans[1] != want[1] {
		return fmt.Errorf("certificate names %v, want exactly %v", leaf.DNSNames, want)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return fmt.Errorf("certificate not valid now (%s – %s)", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	// Every PEM block of the chain must be a certificate (the inline
	// certFile is passed to Traefik as-is).
	rest := []byte(certPEM)
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

// mainCert is the main domain's certificate as the domains service read it
// from the front door's Secret (HA only; nil otherwise).
type mainCert struct {
	CertPEM, KeyPEM string
}

// buildDynamic returns the document for every enrolled domain whose
// certificate is servable, sorted by name, after the main domain's from
// the front door (HA only: mc non-nil, servableHA); dropped lists (name,
// reason) of the others that have a certificate (logged without key
// material).
func buildDynamic(domains map[string]*Domain, mc *mainCert, main, mailHost string, now time.Time) (dynamicDoc, []string) {
	doc := dynamicDoc{TLS: dynamicTLS{Certificates: []dynamicCert{}}}
	var dropped []string
	if mc != nil {
		if err := servableHA(mc.CertPEM, mc.KeyPEM, main, mailHost, now); err != nil {
			dropped = append(dropped, fmt.Sprintf("%s (the front door's): %v", main, err))
		} else {
			doc.TLS.Certificates = append(doc.TLS.Certificates, dynamicCert{CertFile: mc.CertPEM, KeyFile: mc.KeyPEM})
			doc.HTTP = &dynamicHTTP{Routers: map[string]dynamicRouter{MainCertReadyRouter: {
				EntryPoints: []string{"traefik"}, Rule: "Path(`" + MainCertReadyPath + "`)", Service: "ping@internal"}}}
		}
	}
	names := make([]string, 0, len(domains))
	for n := range domains {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d := domains[n]
		if d.CertPEM == "" || d.Deleting {
			continue
		}
		if d.Name != n {
			dropped = append(dropped, fmt.Sprintf("%s: stored under another name (%s)", n, d.Name))
			continue
		}
		if err := servable(d, main, mailHost, now); err != nil {
			dropped = append(dropped, fmt.Sprintf("%s: %v", n, err))
			continue
		}
		doc.TLS.Certificates = append(doc.TLS.Certificates, dynamicCert{CertFile: d.CertPEM, KeyFile: d.KeyPEM})
	}
	return doc, dropped
}
