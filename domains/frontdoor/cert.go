package frontdoor

// The main domain's certificate in HA (spec §11.2, contract §12.4 "Only
// Portcullis names", §20.8): several Traefik replicas can't share Traefik's
// own ACME resolver, so the front door orders <d> and *.<d> by DNS-01 with
// its own ACME account (never the added-domains one) and its own DNS
// credentials, and stores the result in the Secret frontdoor-cert, which
// the domains service mounts read-only and serves to every Traefik replica
// over its mTLS HTTP provider.
//
//   - The account lives in the Secret frontdoor-acme under the key
//     "frontdoor" (only the front door's Role may read it).
//   - A first certificate with an account is ordered only when asked
//     (IssueMain, run by ./portcullis after the CAA flip: relax → settle →
//     issue → re-pin, scripts/lib/dns.sh dns_flip_main_account): the CAA
//     may still pin another account until then.
//   - A certificate of the current account is renewed on its own (Renew)
//     when less than RenewBefore is left.
//   - Only the Lease holder orders, registers or writes: every challenge
//     record goes through the Writer (only TXT at _acme-challenge.<d>,
//     each provider call under the fence's write context).

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The front door's store (Secrets in the core namespace, created empty by
// the chart; the front door's Role may get and update only these two).
const (
	// AccountSecret holds the ACME account (its key and registration) under
	// AccountKey: read by the front door only.
	AccountSecret = "frontdoor-acme"
	AccountKey    = "frontdoor"
	// CertSecret holds the main domain's certificate: tls.crt (the full
	// chain), tls.key and account-uri (the account that ordered it).
	// Mounted read-only by the domains service, which serves it.
	CertSecret     = "frontdoor-cert"
	CertChainKey   = "tls.crt"
	CertKeyKey     = "tls.key"
	CertAccountKey = "account-uri"
)

// RenewBefore: a certificate with less than this left is renewed (as the
// domains service's, contract §12.4).
const RenewBefore = 30 * 24 * time.Hour

// Cert is the stored main-domain certificate.
type Cert struct {
	ChainPEM, KeyPEM string
	// AccountURI is the ACME account that ordered it.
	AccountURI string
}

// CertStore persists the account and the certificate.
type CertStore interface {
	LoadAccount(ctx context.Context) ([]byte, error)
	SaveAccount(ctx context.Context, acct []byte) error
	LoadCert(ctx context.Context) (Cert, error)
	SaveCert(ctx context.Context, c Cert) error
}

// DNS01 writes and removes the challenge TXT record (fqdn with its
// trailing dot or without).
type DNS01 interface {
	PresentTXT(ctx context.Context, fqdn, value string) error
	CleanUpTXT(ctx context.Context, fqdn, value string) error
}

// ACME is the CA side (the domains binary's lego client, acme.go).
type ACME interface {
	// CurrentURI is the URI of the stored account when it is current
	// (this CA), "" otherwise (none, unreadable, another CA). No network.
	CurrentURI(acct []byte) string
	// Register registers a new account at the CA: its stored form and URI.
	Register(ctx context.Context) (acct []byte, uri string, err error)
	// Obtain orders domain and *.domain by DNS-01 through dns with the
	// stored account acct: the full chain and its private key (PEM).
	Obtain(ctx context.Context, acct []byte, domain string, dns DNS01) (chainPEM, keyPEM string, err error)
}

// ErrNoAccount: no current account, and this front door doesn't lead
// (only the Lease holder registers one).
var ErrNoAccount = errors.New("the front door has no ACME account for this CA yet (the leading front door registers it)")

// ErrOtherAccount: IssueMain was asked for another account than the
// front door's current one.
var ErrOtherAccount = errors.New("the front door's ACME account is another one than asked for")

// Certs orders, renews and stores the main domain's certificate.
type Certs struct {
	// Domain is the main domain <d>.
	Domain string
	Store  CertStore
	ACME   ACME
	DNS    DNS01
	Fence  WriteFence
	// Check refuses a chain the domains service wouldn't serve
	// (servableHA's checks: exactly {<d>, *.<d>}, the key, valid now).
	Check func(chainPEM, keyPEM string, now time.Time) error
	Now   func() time.Time
	Log   func(string)
	// RenewBefore (0 = RenewBefore).
	RenewBefore time.Duration

	mu sync.Mutex // one account registration / order at a time
	// failures / retryAt: Renew's backoff after a failed order.
	failures int
	retryAt  time.Time
}

func (c *Certs) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Certs) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, args...))
	}
}

func (c *Certs) leading() bool { return c.Fence != nil && c.Fence.Leading() }

// AccountURI is the front door's current account's URI, registering the
// account first when there is none for this CA (the leader only:
// ErrStandingBy / ErrNoAccount otherwise).
func (c *Certs) AccountURI(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, uri, err := c.accountLocked(ctx)
	return uri, err
}

func (c *Certs) accountLocked(ctx context.Context) ([]byte, string, error) {
	stored, err := c.Store.LoadAccount(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("reading the ACME account (%s): %w", AccountSecret, err)
	}
	if uri := c.ACME.CurrentURI(stored); uri != "" {
		return stored, uri, nil
	}
	if !c.leading() {
		return nil, "", ErrNoAccount
	}
	acct, uri, err := c.ACME.Register(ctx)
	if err != nil {
		return nil, "", err
	}
	if !c.leading() {
		return nil, "", ErrStandingBy
	}
	if err := c.Store.SaveAccount(ctx, acct); err != nil {
		return nil, "", fmt.Errorf("saving the ACME account (%s): %w", AccountSecret, err)
	}
	c.logf("frontdoor: registered the ACME account %s", uri)
	return acct, uri, nil
}

// IssueMain orders <d> and *.<d> now with the current account (DNS-01
// through the front door's own credentials) and stores the certificate.
// Only the Lease holder orders.
func (c *Certs) IssueMain(ctx context.Context) error { return c.issue(ctx, "") }

// IssueMainFor is IssueMain for the account want only (ErrOtherAccount).
func (c *Certs) IssueMainFor(ctx context.Context, want string) error { return c.issue(ctx, want) }

func (c *Certs) issue(ctx context.Context, want string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.leading() {
		return ErrStandingBy
	}
	acct, uri, err := c.accountLocked(ctx)
	if err != nil {
		return err
	}
	if want != "" && want != uri {
		return fmt.Errorf("%w (asked %s, current %s)", ErrOtherAccount, want, uri)
	}
	chain, key, err := c.ACME.Obtain(ctx, acct, c.Domain, c.DNS)
	if err != nil {
		return fmt.Errorf("ordering %s and *.%s: %w", c.Domain, c.Domain, err)
	}
	if c.Check == nil {
		return errors.New("no certificate check configured: refusing to store")
	}
	if err := c.Check(chain, key, c.now()); err != nil {
		return fmt.Errorf("the issued certificate is refused (nothing stored): %w", err)
	}
	if !c.leading() {
		return ErrStandingBy
	}
	if err := c.Store.SaveCert(ctx, Cert{ChainPEM: chain, KeyPEM: key, AccountURI: uri}); err != nil {
		return fmt.Errorf("saving the certificate (%s): %w", CertSecret, err)
	}
	c.failures, c.retryAt = 0, time.Time{}
	if na, err := NotAfter(chain); err == nil {
		c.logf("frontdoor: certificate for %s and *.%s stored (account %s, valid until %s)", c.Domain, c.Domain, uri, na.UTC().Format(time.RFC3339))
	}
	return nil
}

// RenewDue says whether Renew would order now: the stored certificate is
// the current account's (a certificate of another account, or none, waits
// for IssueMain: the CAA may still pin another account) and has less than
// RenewBefore left (or doesn't parse).
func (c *Certs) RenewDue(ctx context.Context) (bool, string, error) {
	cert, err := c.Store.LoadCert(ctx)
	if err != nil {
		return false, "", fmt.Errorf("reading %s: %w", CertSecret, err)
	}
	if cert.ChainPEM == "" {
		return false, "no certificate yet: the CAA flip orders the first one", nil
	}
	stored, err := c.Store.LoadAccount(ctx)
	if err != nil {
		return false, "", fmt.Errorf("reading %s: %w", AccountSecret, err)
	}
	uri := c.ACME.CurrentURI(stored)
	if uri == "" || cert.AccountURI != uri {
		return false, fmt.Sprintf("the certificate is account %s's, the current account is %q: the CAA flip orders the next one", cert.AccountURI, uri), nil
	}
	na, err := NotAfter(cert.ChainPEM)
	if err != nil {
		return true, "the stored certificate doesn't parse", nil
	}
	rb := c.RenewBefore
	if rb == 0 {
		rb = RenewBefore
	}
	if na.Sub(c.now()) < rb {
		return true, fmt.Sprintf("valid until %s", na.UTC().Format(time.RFC3339)), nil
	}
	return false, "", nil
}

// Renew renews the stored certificate when RenewDue (leader only, with a
// backoff after a failure: 10 min doubling, at most 6 h). It reports
// whether it ordered.
func (c *Certs) Renew(ctx context.Context) (bool, error) {
	if !c.leading() {
		return false, nil
	}
	c.mu.Lock()
	wait := c.retryAt
	c.mu.Unlock()
	if c.now().Before(wait) {
		return false, nil
	}
	due, why, err := c.RenewDue(ctx)
	if err != nil || !due {
		return false, err
	}
	c.logf("frontdoor: renewing the certificate of %s (%s)", c.Domain, why)
	if err := c.IssueMain(ctx); err != nil {
		c.mu.Lock()
		c.failures++
		d := 10 * time.Minute << min(c.failures-1, 5)
		c.retryAt = c.now().Add(min(d, 6*time.Hour))
		c.mu.Unlock()
		return true, err
	}
	return true, nil
}

// NotAfter is the leaf's expiry of a PEM chain.
func NotAfter(chainPEM string) (time.Time, error) {
	b, _ := pem.Decode([]byte(chainPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return time.Time{}, errors.New("no certificate PEM block")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// ── the challenge records through the Writer ──

// PresentTXT appends the challenge TXT value at fqdn: only
// _acme-challenge.<d> (Allowed), only while leading, under the fence's
// write context.
func (w *Writer) PresentTXT(ctx context.Context, fqdn, value string) error {
	return w.txt(ctx, fqdn, value, true)
}

// CleanUpTXT deletes exactly that challenge value (any TTL: the provider
// may store another, Porkbun 600 s).
func (w *Writer) CleanUpTXT(ctx context.Context, fqdn, value string) error {
	return w.txt(ctx, fqdn, value, false)
}

// ChallengeTTL is the challenge record's TTL (the provider may raise it).
const ChallengeTTL = 60 * time.Second

func (w *Writer) txt(ctx context.Context, fqdn, value string, add bool) error {
	if w.Fence == nil || !w.Fence.Leading() {
		return ErrStandingBy
	}
	name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
	if err := w.Allowed(name, "TXT"); err != nil {
		return err
	}
	if value == "" || strings.ContainsAny(value, "\"\\\n") {
		return fmt.Errorf("refusing the TXT value %q at %s", value, name)
	}
	wctx, done, err := w.Fence.WriteContext(ctx)
	if err != nil {
		return err
	}
	defer done()
	if add {
		_, err = w.P.AppendRecords(wctx, w.Zone, []libdns.Record{libdns.TXT{Name: w.rel(name), TTL: ChallengeTTL, Text: value}})
	} else {
		_, err = w.P.DeleteRecords(wctx, w.Zone, []libdns.Record{libdns.TXT{Name: w.rel(name), Text: value}})
	}
	if err != nil {
		if wctx.Err() != nil {
			return fmt.Errorf("TXT %s: %w: %v", name, ErrCutOff, err)
		}
		return fmt.Errorf("TXT %s: %w", name, err)
	}
	return nil
}

// ── the store in Secrets ──

// SecretStore is the CertStore in the two Secrets of the core namespace
// (created empty by the chart; get / update only).
type SecretStore struct {
	Client    kubernetes.Interface
	Namespace string
}

func (s SecretStore) get(ctx context.Context, name string) (*corev1.Secret, error) {
	return s.Client.CoreV1().Secrets(s.Namespace).Get(ctx, name, metav1.GetOptions{})
}

// update replaces data's keys in the Secret name (the read's
// resourceVersion: a concurrent writer makes it fail, never lost).
func (s SecretStore) update(ctx context.Context, name string, data map[string][]byte) error {
	sec, err := s.get(ctx, name)
	if err != nil {
		return err
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	for k, v := range data {
		sec.Data[k] = v
	}
	_, err = s.Client.CoreV1().Secrets(s.Namespace).Update(ctx, sec, metav1.UpdateOptions{})
	return err
}

func (s SecretStore) LoadAccount(ctx context.Context) ([]byte, error) {
	sec, err := s.get(ctx, AccountSecret)
	if err != nil {
		return nil, err
	}
	return sec.Data[AccountKey], nil
}

func (s SecretStore) SaveAccount(ctx context.Context, acct []byte) error {
	return s.update(ctx, AccountSecret, map[string][]byte{AccountKey: acct})
}

func (s SecretStore) LoadCert(ctx context.Context) (Cert, error) {
	sec, err := s.get(ctx, CertSecret)
	if err != nil {
		return Cert{}, err
	}
	return Cert{ChainPEM: string(sec.Data[CertChainKey]), KeyPEM: string(sec.Data[CertKeyKey]), AccountURI: string(sec.Data[CertAccountKey])}, nil
}

// SaveCert writes the three keys in one update (a reader never pairs a
// key with another chain: the kubelet swaps a Secret volume atomically).
func (s SecretStore) SaveCert(ctx context.Context, c Cert) error {
	return s.update(ctx, CertSecret, map[string][]byte{CertChainKey: []byte(c.ChainPEM), CertKeyKey: []byte(c.KeyPEM), CertAccountKey: []byte(c.AccountURI)})
}
