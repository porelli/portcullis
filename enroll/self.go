package main

// Self-service certificate renewal (enroll.<domain>/self).
//
// Routed by Traefik's enroll-self router: authaware TLS, client-cert-pem@file
// (verified client cert as PEM in X-Forwarded-Tls-Client-Cert), forward-auth
// and portcullis-self@docker (group-gate without the lldap_admin group
// check, but with revocation). Traefik's entrypoint deletes client-supplied
// X-Forwarded-Tls-Client-* headers, so the header describes a cert Traefik
// verified against the CA in this very TLS session.
//
// A renewal re-certifies the key the user is ALREADY using: the request must
//   - come from a signed-in user (X-Forwarded-User = LLDAP username, set
//     by group-gate),
//   - present a client cert whose CN is that user, that Vault issued
//     (pki_int/cert/<serial> holds exactly these bytes), that is not revoked
//     and not expired,
//   - carry a CSR (from the same YubiKey) for exactly that public key.
// Expired or revoked certs cannot be renewed here — an admin re-enrolls.

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

const clientCertHeader = "X-Forwarded-Tls-Client-Cert"

// presentedCert parses Traefik's X-Forwarded-Tls-Client-Cert: comma-separated
// PEM bodies (no BEGIN/END lines, no newlines), leaf first.
func presentedCert(r *http.Request) (*x509.Certificate, error) {
	v := r.Header.Get(clientCertHeader)
	if v == "" {
		return nil, errors.New("no client certificate presented")
	}
	if strings.Contains(v, "%") {
		if u, err := url.QueryUnescape(v); err == nil {
			v = u
		}
	}
	leaf := strings.TrimSpace(strings.Split(v, ",")[0])
	if strings.HasPrefix(leaf, "-----BEGIN") {
		if b, _ := pem.Decode([]byte(leaf)); b != nil {
			return x509.ParseCertificate(b.Bytes)
		}
		return nil, errors.New("client certificate header is not valid PEM")
	}
	der, err := base64.StdEncoding.DecodeString(strings.Map(func(c rune) rune {
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			return -1
		}
		return c
	}, leaf))
	if err != nil {
		return nil, errors.New("client certificate header is not valid base64")
	}
	return x509.ParseCertificate(der)
}

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

// lookupIssued reads pki_int/cert/<serial>. A nil result means Vault never
// issued that serial.
func (cfg *Config) lookupIssued(serial string) (*issuedCert, error) {
	var secret *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		secret, err = vc.Logical().Read("pki_int/cert/" + serial)
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
	if b == nil {
		return nil, errors.New("vault returned no certificate")
	}
	ic := &issuedCert{DER: b.Bytes}
	switch rt := secret.Data["revocation_time"].(type) {
	case json.Number:
		n, _ := rt.Int64()
		ic.Revoked = n > 0
	case float64:
		ic.Revoked = rt > 0
	case int64:
		ic.Revoked = rt > 0
	}
	return ic, nil
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

// sessionUser is the LLDAP username of the signed-in user (see forwardedUser).
func (s *Server) sessionUser(r *http.Request) string {
	return forwardedUser(r)
}

func (s *Server) handleSelf(w http.ResponseWriter, r *http.Request) {
	username := s.sessionUser(r)
	if username == "" {
		http.Error(w, "Not signed in", http.StatusUnauthorized)
		return
	}
	var mine []CertInfo
	if certs, err := s.cfg.listCerts(); err != nil {
		log.Printf("self: list certs: %v", err)
	} else {
		for _, c := range certs {
			if c.Username == username {
				mine = append(mine, c)
			}
		}
	}
	data := map[string]interface{}{
		"User":   username,
		"Certs":  mine,
		"Domain": s.cfg.Domain,
		"TTL":    s.cfg.CertTTL,
		"Now":    time.Now(),
	}
	if cert, err := presentedCert(r); err == nil {
		data["Presented"] = map[string]interface{}{
			"CN":       cert.Subject.CommonName,
			"Serial":   vaultSerial(cert.SerialNumber),
			"NotAfter": cert.NotAfter,
			"Matches":  cert.Subject.CommonName == username,
		}
	}
	render(w, "self.html", data)
}

func (s *Server) handleSelfRenew(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CSR == "" {
		http.Error(w, "csr is required", http.StatusBadRequest)
		return
	}
	username := s.sessionUser(r)
	if username == "" {
		http.Error(w, "Not signed in", http.StatusUnauthorized)
		return
	}
	user, err := s.cfg.getUser(username)
	if err != nil {
		log.Printf("self renew: get user %q: %v", username, err)
		http.Error(w, "User not found in directory", http.StatusForbidden)
		return
	}
	cert, _ := presentedCert(r)
	if err := checkRenewal(user.Username, cert, req.CSR, user.Email, time.Now(), s.cfg.lookupIssued); err != nil {
		log.Printf("self renew: refused for %q: %v", user.Username, err)
		http.Error(w, "Renewal refused: "+err.Error(), http.StatusForbidden)
		return
	}
	resp, err := s.cfg.signCSR(user.Username, user.Email, req.CSR)
	if err != nil {
		log.Printf("self renew: vault error for %q: %v", user.Username, err)
		http.Error(w, "Failed to sign CSR", http.StatusInternalServerError)
		return
	}
	log.Printf("self renew: issued serial %s for %q (renewing %s)", resp.Serial, user.Username, vaultSerial(cert.SerialNumber))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
