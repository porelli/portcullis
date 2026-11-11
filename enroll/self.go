package main

// YubiKey certificate renewal (contract §9.4 POST
// /internal/yubikey-certificates/renew, certapi.go). The Hub forwards the
// certificate the person's browser presented in this TLS session (real
// PEM) and a CSR from the same YubiKey. A renewal re-certifies the key the
// person is ALREADY using: the presented certificate must
//   - be a pki_int leaf (issuer DN and signature, renewYubiKeyCert),
//   - name the user (CN), be valid now, be exactly what Vault issued
//     (pki_int/cert/<serial> holds these bytes) and not be revoked,
//   - and the CSR must be for exactly that public key.
// Expired or revoked certificates can't be renewed: an admin issues a new
// one (POST /internal/yubikey-certificates).

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// vaultSerial formats a serial the way Vault's pki paths expect ("0a:bc:...").
func vaultSerial(n *big.Int) string {
	h := n.Text(16)
	if len(h)%2 == 1 {
		h = "0" + h
	}
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// issuedCert is what Vault knows about a serial.
type issuedCert struct {
	DER     []byte
	Revoked bool
}

// lookupIssued reads <mount>/cert/<serial>. A nil result means the mount
// never issued that serial. The revocation state fails closed: a missing
// or unreadable revocation_time is an error, never "not revoked".
func (cfg *Config) lookupIssued(ctx context.Context, mount, serial string) (*issuedCert, error) {
	var secret *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		secret, err = vc.Logical().ReadWithContext(ctx, mount+"/cert/"+serial)
		return err
	})
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, nil
	}
	certPEM, _ := secret.Data["certificate"].(string)
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("vault returned no certificate")
	}
	revoked, err := revocationState(secret.Data["revocation_time"])
	if err != nil {
		return nil, fmt.Errorf("%s/cert/%s: %w", mount, serial, err)
	}
	return &issuedCert{DER: b.Bytes, Revoked: revoked}, nil
}

// checkRenewal validates a self-service renewal. lookup is injectable for tests.
func checkRenewal(username string, cert *x509.Certificate, csrPEM, email string, now time.Time,
	lookup func(serial string) (*issuedCert, error)) error {
	if username == "" {
		return errors.New("not signed in")
	}
	if cert == nil {
		return errors.New("present your current client certificate (security key) to renew it")
	}
	if cert.Subject.CommonName != username {
		return fmt.Errorf("the presented certificate belongs to %q, not to %q", cert.Subject.CommonName, username)
	}
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return errors.New("the presented certificate is not valid now; ask an administrator to re-enroll")
	}
	issued, err := lookup(vaultSerial(cert.SerialNumber))
	if err != nil {
		return fmt.Errorf("cannot check the certificate with Vault: %w", err)
	}
	if issued == nil || !bytes.Equal(issued.DER, cert.Raw) {
		return errors.New("the presented certificate was not issued by this Portcullis")
	}
	if issued.Revoked {
		return errors.New("the presented certificate is revoked; ask an administrator to re-enroll")
	}
	if err := validateCSR(csrPEM, username, email); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return errors.New("csr could not be parsed")
	}
	a, err1 := x509.MarshalPKIXPublicKey(csr.PublicKey)
	b, err2 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err1 != nil || err2 != nil || !bytes.Equal(a, b) {
		return errors.New("the CSR is for a different key than the presented certificate (renewal keeps the key on your security key)")
	}
	return nil
}
