package main

// enroll's certificate actions on the Hub's internal listener (contract
// §9.4 "Certificate actions"): same listener (:8444) and bearer as the
// invites, JSON bodies ≤ 64 KiB decoded strictly.
//
//	POST /internal/browser-certificates        {"user","days","max_days","max_active"}
//	     → 201 {"p12","password","serial","not_after","filename"}
//	POST /internal/yubikey-certificates        {"user","csr"}
//	     → 201 {"certificate","serial","not_after"}
//	POST /internal/yubikey-certificates/renew  {"user","presented","csr"}
//	     → 201 {"certificate","serial","not_after"}
//	POST /internal/certificates/revoke         {"user","serial"} → 204
//
// The operations need Vault (*Config); main injects them as function
// fields on inviteService (nil = 503). Every action refuses the protected
// names (admin, portcullis-hub, portcullis-*) with 409 before Vault is
// called, and runs under a certOpTimeout deadline. user is the username
// the Hub forwards; the certificate's CN is always that user. Errors are
// {"error"} (≤ 200 characters) and never echo the request body; the .p12,
// its password, private keys and CSRs never reach a log.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	vault "github.com/hashicorp/vault/api"
)

const (
	// maxActionBody bounds a certificate action's request (else 413).
	maxActionBody = 64 << 10
	// maxErrorText bounds an {"error"} text (characters).
	maxErrorText = 200
)

// certOpTimeout bounds one certificate action, under the Hub's 20 s client
// timeout (a var for the tests).
var certOpTimeout = 15 * time.Second

// yubiKeyCertResult is a signed YubiKey certificate (no key: it stays on
// the YubiKey).
type yubiKeyCertResult struct {
	PEM      string
	Serial   string
	NotAfter time.Time
}

// serialRe is Vault's serial form: lowercase hex byte pairs joined by ":".
var serialRe = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){0,63}$`)

// issueYubiKeyCert signs an admin-submitted CSR on pki_int for user (the
// admin CSR path that replaces /api/sign). The CSR must pass validateCSR
// against the LLDAP record (400 with its text).
func (cfg *Config) issueYubiKeyCert(ctx context.Context, user, csrPEM string) (*yubiKeyCertResult, error) {
	u, err := cfg.existingUser(user)
	if err != nil {
		return nil, err
	}
	if err := validateCSR(csrPEM, user, u.Email); err != nil {
		return nil, refuse(400, "%s", err.Error())
	}
	res, err := cfg.signYubiKey(ctx, user, csrPEM)
	if err != nil {
		return nil, err
	}
	log.Printf("yubikey certificate %s for %s", res.Serial, user)
	return res, nil
}

// renewYubiKeyCert renews user's YubiKey certificate: presentedPEM is the
// certificate the browser presented (one PEM CERTIFICATE block, else 400).
// Only a pki_int leaf renews: its issuer DN must be pki_int's CA subject
// and its signature must verify with that CA's key (else 403); then
// checkRenewal (403 with its text), whose lookup is on pki_int only.
func (cfg *Config) renewYubiKeyCert(ctx context.Context, user, presentedPEM, csrPEM string) (*yubiKeyCertResult, error) {
	presented, err := parsePresented(presentedPEM)
	if err != nil {
		return nil, refuse(400, "%s", err.Error())
	}
	ca, err := cfg.caCert(ctx, mountYubiKey)
	if err != nil {
		return nil, err
	}
	if !issuedBy(presented, ca) {
		return nil, refuse(403, "the presented certificate is not a YubiKey certificate of this Portcullis")
	}
	u, err := cfg.existingUser(user)
	if err != nil {
		return nil, err
	}
	var lookupErr error
	lookup := func(serial string) (*issuedCert, error) {
		ic, err := cfg.lookupIssued(ctx, mountYubiKey, serial)
		if err != nil {
			lookupErr = err
		}
		return ic, err
	}
	if err := checkRenewal(user, presented, csrPEM, u.Email, cfg.clock(), lookup); err != nil {
		if lookupErr != nil {
			return nil, fmt.Errorf("renewal lookup: %w", lookupErr)
		}
		return nil, refuse(403, "%s", err.Error())
	}
	res, err := cfg.signYubiKey(ctx, user, csrPEM)
	if err != nil {
		return nil, err
	}
	log.Printf("yubikey certificate %s for %s (renewing %s)", res.Serial, user, vaultSerial(presented.SerialNumber))
	return res, nil
}

// signYubiKey signs csrPEM on pki_int/sign/<PKIRole> for user, CERT_TTL.
func (cfg *Config) signYubiKey(ctx context.Context, user, csrPEM string) (*yubiKeyCertResult, error) {
	signed, err := cfg.signOn(ctx, mountYubiKey, cfg.PKIRole, user, csrPEM, cfg.CertTTL)
	if err != nil {
		return nil, err
	}
	return &yubiKeyCertResult{
		PEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed.Leaf.Raw})),
		Serial:   signed.Serial,
		NotAfter: signed.Leaf.NotAfter.UTC(),
	}, nil
}

// parsePresented is the one certificate of a PEM CERTIFICATE block with
// nothing after it.
func parsePresented(s string) (*x509.Certificate, error) {
	b, rest := pem.Decode([]byte(s))
	if b == nil || b.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("presented must be one PEM CERTIFICATE block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, errors.New("presented must be one PEM CERTIFICATE block")
	}
	return c, nil
}

// caCert is mount's CA certificate (<mount>/cert/ca).
func (cfg *Config) caCert(ctx context.Context, mount string) (*x509.Certificate, error) {
	var secret *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		secret, err = vc.Logical().ReadWithContext(ctx, mount+"/cert/ca")
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("read %s/cert/ca: %w", mount, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("read %s/cert/ca: no data", mount)
	}
	certPEM, _ := secret.Data["certificate"].(string)
	b, _ := pem.Decode([]byte(certPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("read %s/cert/ca: no certificate", mount)
	}
	return x509.ParseCertificate(b.Bytes)
}

// revokeCert revokes user's certificate serial on whichever mount holds it
// (pki_int, then pki_file). Not found, or another CN: 404. Already
// revoked: nil, no second revoke. Then that mount's CRL is rotated; a
// failed rotate is only logged (the delta CRL catches up within 2 min).
func (cfg *Config) revokeCert(ctx context.Context, user, serial string) error {
	s := strings.ToLower(strings.TrimSpace(serial))
	notFound := refuse(404, "no such certificate")
	if !serialRe.MatchString(s) {
		return notFound
	}
	var mount string
	var ic *issuedCert
	for _, m := range certMounts {
		got, err := cfg.lookupIssued(ctx, m, s)
		if err != nil {
			return err
		}
		if got != nil {
			mount, ic = m, got
			break
		}
	}
	if ic == nil {
		return notFound
	}
	c, err := x509.ParseCertificate(ic.DER)
	if err != nil {
		return fmt.Errorf("%s/cert/%s: %w", mount, s, err)
	}
	if !clientLeaf(c) || !strings.EqualFold(c.Subject.CommonName, user) {
		return notFound
	}
	if ic.Revoked {
		log.Printf("%s certificate %s of %s: already revoked", certKind(mount), s, user)
		return nil
	}
	err = cfg.vault.do(func(vc *vault.Client) error {
		_, err := vc.Logical().WriteWithContext(ctx, mount+"/revoke", map[string]interface{}{"serial_number": s})
		return err
	})
	if err != nil {
		return fmt.Errorf("revoke %s on %s: %w", s, mount, err)
	}
	log.Printf("revoked %s certificate %s of %s", certKind(mount), s, user)
	err = cfg.vault.do(func(vc *vault.Client) error {
		_, err := vc.Logical().ReadWithContext(ctx, mount+"/crl/rotate")
		return err
	})
	if err != nil {
		log.Printf("WARNING: %s/crl/rotate after revoking %s failed (the delta CRL catches up within 2 min): %v", mount, s, err)
	}
	return nil
}

// HTTP side.

// decodeAction decodes exactly one JSON object into v: ≤ maxActionBody
// (else 413), no unknown fields, nothing after it (else 400).
func decodeAction(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxActionBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		var extra json.RawMessage
		if e := dec.Decode(&extra); e != io.EOF {
			err = e
			if err == nil {
				err = errors.New("trailing data")
			}
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			jsonError(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			jsonError(w, http.StatusBadRequest, "body must be one JSON object with the documented fields")
		}
		return false
	}
	return true
}

// actionUser is the request's user, trimmed: 400 when empty or not a
// plain name, 409 "protected account" for admin, portcullis-hub and every
// portcullis-* name.
func actionUser(w http.ResponseWriter, user string) (string, bool) {
	u := strings.TrimSpace(user)
	if u == "" || len(u) > 128 || strings.IndexFunc(u, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		jsonError(w, http.StatusBadRequest, "user is required")
		return "", false
	}
	if protectedCertName(u) {
		jsonError(w, http.StatusConflict, "protected account")
		return "", false
	}
	return u, true
}

// clipText is s without control characters, at most maxErrorText runes.
func clipText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		if n == maxErrorText {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// actionFailed answers err: a refusal with its status and text; a missed
// deadline or anything else (Vault, LLDAP) is a logged 503.
func actionFailed(w http.ResponseWriter, action, user string, err error) {
	var oe *opError
	switch {
	case errors.As(err, &oe):
		log.Printf("CERTIFICATES %s for %s refused (%d): %s", action, user, oe.status, oe.msg)
		jsonError(w, oe.status, clipText(oe.msg))
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		log.Printf("CERTIFICATES %s for %s: %v", action, user, err)
		jsonError(w, http.StatusServiceUnavailable, "the certificate authority did not answer in time")
	default:
		log.Printf("CERTIFICATES %s for %s: %v", action, user, err)
		jsonError(w, http.StatusServiceUnavailable, "the certificate authority is unavailable")
	}
}

// withDeadline runs op under certOpTimeout. Past it the answer is the
// deadline's error whatever op is doing; a result that arrives later is
// handed to discard (which clears any secret in it).
func withDeadline[T any](parent context.Context, op func(context.Context) (T, error), discard func(T)) (T, error) {
	ctx, cancel := context.WithTimeout(parent, certOpTimeout)
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer cancel()
		v, err := op(ctx)
		done <- result{v, err}
	}()
	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		select {
		case r := <-done:
			return r.v, r.err
		default:
		}
		go func() {
			if r := <-done; r.err == nil && discard != nil {
				discard(r.v)
			}
		}()
		var zero T
		return zero, ctx.Err()
	}
}

// writeCreated answers 201 with v as JSON; the encoded bytes are zeroed
// after the write.
func writeCreated(w http.ResponseWriter, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "answer can't be encoded")
		return
	}
	defer clear(buf)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	w.Write(buf)
}

// POST /internal/browser-certificates
func (s *inviteService) handleBrowserCert(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorized(w, r) {
		return
	}
	op := s.issueBrowser
	if op == nil {
		jsonError(w, http.StatusServiceUnavailable, "browser certificates unavailable")
		return
	}
	var req struct {
		User      string `json:"user"`
		Days      int    `json:"days"`
		MaxDays   int    `json:"max_days"`
		MaxActive int    `json:"max_active"`
	}
	if !decodeAction(w, r, &req) {
		return
	}
	user, ok := actionUser(w, req.User)
	if !ok {
		return
	}
	res, err := withDeadline(r.Context(), func(ctx context.Context) (*browserCertResult, error) {
		return op(ctx, user, req.Days, req.MaxDays, req.MaxActive)
	}, func(b *browserCertResult) { b.clear() })
	if err != nil {
		actionFailed(w, "browser certificate", user, err)
		return
	}
	defer res.clear()
	writeCreated(w, struct {
		P12      []byte `json:"p12"`
		Password string `json:"password"`
		Serial   string `json:"serial"`
		NotAfter string `json:"not_after"`
		Filename string `json:"filename"`
	}{res.P12, res.Password, res.Serial, res.NotAfter.UTC().Format(time.RFC3339), res.Filename})
}

func issuedAnswer(res *yubiKeyCertResult) any {
	return struct {
		Certificate string `json:"certificate"`
		Serial      string `json:"serial"`
		NotAfter    string `json:"not_after"`
	}{res.PEM, res.Serial, res.NotAfter.UTC().Format(time.RFC3339)}
}

// POST /internal/yubikey-certificates
func (s *inviteService) handleYubiKeyIssue(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorized(w, r) {
		return
	}
	op := s.issueYubiKey
	if op == nil {
		jsonError(w, http.StatusServiceUnavailable, "YubiKey certificates unavailable")
		return
	}
	var req struct {
		User string `json:"user"`
		CSR  string `json:"csr"`
	}
	if !decodeAction(w, r, &req) {
		return
	}
	user, ok := actionUser(w, req.User)
	if !ok {
		return
	}
	res, err := withDeadline(r.Context(), func(ctx context.Context) (*yubiKeyCertResult, error) {
		return op(ctx, user, req.CSR)
	}, nil)
	if err != nil {
		actionFailed(w, "yubikey certificate", user, err)
		return
	}
	writeCreated(w, issuedAnswer(res))
}

// POST /internal/yubikey-certificates/renew
func (s *inviteService) handleYubiKeyRenew(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorized(w, r) {
		return
	}
	op := s.renewYubiKey
	if op == nil {
		jsonError(w, http.StatusServiceUnavailable, "YubiKey renewal unavailable")
		return
	}
	var req struct {
		User      string `json:"user"`
		Presented string `json:"presented"`
		CSR       string `json:"csr"`
	}
	if !decodeAction(w, r, &req) {
		return
	}
	user, ok := actionUser(w, req.User)
	if !ok {
		return
	}
	res, err := withDeadline(r.Context(), func(ctx context.Context) (*yubiKeyCertResult, error) {
		return op(ctx, user, req.Presented, req.CSR)
	}, nil)
	if err != nil {
		actionFailed(w, "yubikey renewal", user, err)
		return
	}
	writeCreated(w, issuedAnswer(res))
}

// POST /internal/certificates/revoke
func (s *inviteService) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.apiAuthorized(w, r) {
		return
	}
	op := s.revoke
	if op == nil {
		jsonError(w, http.StatusServiceUnavailable, "revocation unavailable")
		return
	}
	var req struct {
		User   string `json:"user"`
		Serial string `json:"serial"`
	}
	if !decodeAction(w, r, &req) {
		return
	}
	user, ok := actionUser(w, req.User)
	if !ok {
		return
	}
	_, err := withDeadline(r.Context(), func(ctx context.Context) (struct{}, error) {
		return struct{}{}, op(ctx, user, req.Serial)
	}, nil)
	if err != nil {
		actionFailed(w, "revoke", user, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
