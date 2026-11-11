package main

// Browser certificates (contract §8.1 "Browser certificates", §9.4 POST
// /internal/browser-certificates): enroll makes the key, has pki_file sign
// it and hands back a password-protected .p12 exactly once.
//
//   - Key: ECDSA P-256 from crypto/rand, made here; the CSR is built here
//     and Vault never sees the key.
//   - Signing: pki_file/sign/browser-cert with common_name = the user the
//     Hub forwards (never a CSR's subject) and ttl = days×24h; no SANs.
//   - Encoding: pkcs12.Modern2023 (AES-256-CBC, PBKDF2-SHA256, SHA-256 MAC)
//     with the chain [browser CA, root].
//   - Password: 20 Crockford base32 characters (100 bits), 4 groups of 5.
//   - Checks, in this order, under one process-wide lock: 1 ≤ days ≤
//     max_days and days×24h ≤ CERT_TTL (400); the user exists in LLDAP
//     (404); fewer than max_active unrevoked, unexpired pki_file
//     certificates with that CN (409).
//
// The key, the .p12 and the password never reach a log, an error or
// anything kept: the caller (certapi.go) answers once and clears them.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	mountYubiKey = "pki_int"
	mountBrowser = "pki_file"
	browserRole  = "browser-cert"
	// defaultMaxActive applies when a request carries no max_active.
	defaultMaxActive = 3
	// maxMaxActive is the Hub's bound for browser_cert_max_active.
	maxMaxActive = 20
	crockford    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// certMounts are the mounts enroll lists, in lookup order.
var certMounts = []string{mountYubiKey, mountBrowser}

// certKind is the contract's kind of a mount's certificates.
func certKind(mount string) string {
	switch mount {
	case mountYubiKey:
		return "yubikey"
	case mountBrowser:
		return "browser"
	}
	return ""
}

// opError is a refusal with the status and text the API answers.
type opError struct {
	status int
	msg    string
}

func (e *opError) Error() string { return e.msg }

func refuse(status int, format string, a ...any) error {
	return &opError{status: status, msg: fmt.Sprintf(format, a...)}
}

// browserCertLock serialises browser certificate creation process-wide
// (the max_active count and the signing are one step). A one-slot
// channel, so that waiting for it honours the request's deadline.
var browserCertLock = make(chan struct{}, 1)

// browserCertResult is a new browser certificate. P12 (with the key) and
// Password are answered once; clear drops them.
type browserCertResult struct {
	P12      []byte
	Password string
	Serial   string
	Filename string
	NotAfter time.Time
}

// clear zeroes the .p12 and drops it and the password.
func (b *browserCertResult) clear() {
	if b == nil {
		return
	}
	clear(b.P12)
	b.P12 = nil
	b.Password = ""
}

// newBrowserPassword is "XXXXX-XXXXX-XXXXX-XXXXX": 20 characters from the
// Crockford base32 alphabet, 5 bits each from crypto/rand (100 bits).
func newBrowserPassword() (string, error) {
	raw := make([]byte, 20)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, 0, 23)
	defer clear(out)
	for i, b := range raw {
		if i > 0 && i%5 == 0 {
			out = append(out, '-')
		}
		out = append(out, crockford[b&31]) // 256 is a multiple of 32: uniform
	}
	return string(out), nil
}

var vaultDurationRe = regexp.MustCompile(`^([0-9]+)([smhd]?)$`)

// parseVaultDuration reads core's duration grammar ^[0-9]+[smhd]?$ (a
// bare number means seconds), as CLIENT_CERT_TTL is written.
func parseVaultDuration(s string) (time.Duration, error) {
	m := vaultDurationRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("duration %q is not <number>[smhd]", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("duration %q: %w", s, err)
	}
	unit := map[string]time.Duration{"": time.Second, "s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
	if n > int64(math.MaxInt64/unit) {
		return 0, fmt.Errorf("duration %q is too long", s)
	}
	return time.Duration(n) * unit, nil
}

// protectedCertName: the accounts whose certificates are managed only from
// the server (admin, portcullis-hub, every portcullis-* name).
func protectedCertName(user string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	return u == bootstrapAdmin || u == hubServiceAccount || strings.HasPrefix(u, "portcullis-")
}

// acquire takes lock, or gives up when ctx ends.
func acquire(ctx context.Context, lock chan struct{}) error {
	select {
	case lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// existingUser is the LLDAP user named exactly user: 404 when there is
// none, any other lookup failure is an error (503).
func (cfg *Config) existingUser(user string) (*User, error) {
	u, err := cfg.findUser(user)
	switch {
	case errors.Is(err, errNoUser):
		return nil, refuse(404, "%s", errNoUser.Error())
	case err != nil:
		return nil, fmt.Errorf("ldap lookup: %w", err)
	case u == nil || u.Username != user:
		return nil, refuse(404, "%s", errNoUser.Error())
	}
	return u, nil
}

// issueBrowserCert creates a browser certificate for user (contract §8.1
// "Browser certificates"). maxDays and maxActive come from the Hub
// (maxActive 0 = defaultMaxActive).
func (cfg *Config) issueBrowserCert(ctx context.Context, user string, days, maxDays, maxActive int) (*browserCertResult, error) {
	ttl, err := parseVaultDuration(cfg.CertTTL)
	if err != nil {
		return nil, fmt.Errorf("CERT_TTL: %w", err)
	}
	ceiling := int(ttl / (24 * time.Hour))
	if maxDays > 0 && maxDays < ceiling {
		ceiling = maxDays
	}
	if maxDays < 0 || days < 1 || days > ceiling {
		return nil, refuse(400, "days must be 1 to %d", max(ceiling, 0))
	}
	switch {
	case maxActive == 0:
		maxActive = defaultMaxActive
	case maxActive < 0 || maxActive > maxMaxActive:
		return nil, refuse(400, "max_active must be 1 to %d", maxMaxActive)
	}

	if err := acquire(ctx, browserCertLock); err != nil {
		return nil, err
	}
	defer func() { <-browserCertLock }()

	if _, err := cfg.existingUser(user); err != nil {
		return nil, err
	}
	n, err := cfg.activeBrowserCerts(ctx, user)
	if err != nil {
		return nil, err
	}
	if n >= maxActive {
		return nil, refuse(409, "you already have %d browser certificates, the most allowed: revoke one first", n)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	// Drop the key's scalar whatever happens next (it is never marshalled:
	// pkcs12 takes the key itself).
	defer clear(key.D.Bits())
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: user}}, key)
	if err != nil {
		return nil, fmt.Errorf("build csr: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	signed, err := cfg.signOn(ctx, mountBrowser, browserRole, user, csrPEM, fmt.Sprintf("%dh", days*24))
	if err != nil {
		return nil, err
	}
	chain, err := browserChain(signed.Leaf, signed.Chain)
	if err != nil {
		return nil, err
	}
	pub, ok := signed.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("pki_file signed a different key")
	}
	password, err := newBrowserPassword()
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}
	p12, err := pkcs12.Modern2023.Encode(key, signed.Leaf, chain, password)
	if err != nil {
		return nil, errors.New("encode the .p12 failed")
	}
	log.Printf("browser certificate %s for %s", signed.Serial, user)
	return &browserCertResult{
		P12:      p12,
		Password: password,
		Serial:   signed.Serial,
		Filename: browserFilename(user, cfg.clock()),
		NotAfter: signed.Leaf.NotAfter.UTC(),
	}, nil
}

var filenameUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// browserFilename is <user>-browser-certificate-<YYYYMMDD>.p12 (the issue
// date, UTC), as a plain lowercase file name.
func browserFilename(user string, now time.Time) string {
	u := filenameUnsafe.ReplaceAllString(strings.ToLower(user), "-")
	if u == "" || !(u[0] >= 'a' && u[0] <= 'z' || u[0] >= '0' && u[0] <= '9') {
		u = "user" + u
	}
	if len(u) > 64 {
		u = u[:64]
	}
	return u + "-browser-certificate-" + now.UTC().Format("20060102") + ".p12"
}

// activeBrowserCerts counts user's unrevoked, unexpired pki_file
// certificates (fails closed: any unreadable one is an error).
func (cfg *Config) activeBrowserCerts(ctx context.Context, user string) (int, error) {
	var recs []certRecord
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		recs, err = mountCertsWith(ctx, vc, mountBrowser)
		return err
	})
	if err != nil {
		return 0, err
	}
	now := cfg.clock()
	n := 0
	for _, r := range recs {
		exp, err := time.Parse(time.RFC3339, r.NotAfter)
		if err != nil {
			return 0, err
		}
		if r.User == user && !r.Revoked && now.Before(exp) {
			n++
		}
	}
	return n, nil
}

// signedCert is what <mount>/sign/<role> answered.
type signedCert struct {
	Leaf   *x509.Certificate
	Serial string // Vault's form (lowercase colon hex)
	Chain  []*x509.Certificate
}

// signOn has mount sign csrPEM with role, for exactly common_name = user
// and ttl. It never passes SANs (alt_names, ip_sans, uri_sans, other_sans:
// enroll's Vault policy denies them). The answer must be one certificate
// whose CN is user.
func (cfg *Config) signOn(ctx context.Context, mount, role, user, csrPEM, ttl string) (*signedCert, error) {
	var secret *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		secret, err = vc.Logical().WriteWithContext(ctx, mount+"/sign/"+role, map[string]interface{}{
			"csr":         csrPEM,
			"common_name": user,
			"ttl":         ttl,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("vault sign on %s: %w", mount, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("vault sign on %s: empty response", mount)
	}
	certPEM, _ := secret.Data["certificate"].(string)
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("vault sign on %s: response missing certificate", mount)
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault sign on %s: %w", mount, err)
	}
	if leaf.Subject.CommonName != user {
		return nil, fmt.Errorf("vault sign on %s: the certificate names %q", mount, leaf.Subject.CommonName)
	}
	if !sameKey(csrPEM, leaf) {
		return nil, fmt.Errorf("vault sign on %s: the certificate is for another key than the CSR", mount)
	}
	out := &signedCert{Leaf: leaf, Serial: vaultSerial(leaf.SerialNumber)}
	if list, ok := secret.Data["ca_chain"].([]interface{}); ok {
		for _, item := range list {
			s, _ := item.(string)
			rest := []byte(s)
			for {
				var blk *pem.Block
				blk, rest = pem.Decode(rest)
				if blk == nil {
					break
				}
				if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
					out.Chain = append(out.Chain, c)
				}
			}
		}
	}
	return out, nil
}

// sameKey reports whether leaf certifies the public key of csrPEM.
func sameKey(csrPEM string, leaf *x509.Certificate) bool {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil {
		return false
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return false
	}
	a, err1 := x509.MarshalPKIXPublicKey(csr.PublicKey)
	c, err2 := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	return err1 == nil && err2 == nil && string(a) == string(c)
}

// issuedBy reports whether ca issued c: c's issuer DN is ca's subject and
// c's signature verifies with ca's key.
func issuedBy(c, ca *x509.Certificate) bool {
	return c != nil && ca != nil && string(c.RawIssuer) == string(ca.RawSubject) && c.CheckSignatureFrom(ca) == nil
}

// browserChain is [browser CA, root] from Vault's ca_chain: the CA that
// issued leaf, and the self-signed root that issued that CA.
func browserChain(leaf *x509.Certificate, chain []*x509.Certificate) ([]*x509.Certificate, error) {
	var ca, root *x509.Certificate
	for _, c := range chain {
		if issuedBy(leaf, c) {
			ca = c
			break
		}
	}
	if ca == nil {
		return nil, errors.New("pki_file's answer has no issuing CA")
	}
	for _, c := range chain {
		if c != ca && issuedBy(ca, c) && issuedBy(c, c) {
			root = c
			break
		}
	}
	if root == nil {
		return nil, errors.New("pki_file's answer has no root CA")
	}
	return []*x509.Certificate{ca, root}, nil
}
