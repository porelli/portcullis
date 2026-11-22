package main

// HA certificates (Task 29, contract §12.4 "Only Portcullis names",
// §20.8): the main domain's certificate from the front door's store,
// ordered with the front door's own ACME account, against an in-process
// Pebble whose VA resolves through the fake DNS server. These run with
// and without -tags testprovider (no build tag: CI's plain go test runs
// them too).

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/libdns/libdns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/fakedns"
)

const fdNS = "portcullis"

// leadFence is a write fence that leads while lead is true.
type leadFence struct {
	mu   sync.Mutex
	lead bool
}

func (f *leadFence) set(v bool) { f.mu.Lock(); f.lead = v; f.mu.Unlock() }

func (f *leadFence) Leading() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.lead }

func (f *leadFence) WriteContext(p context.Context) (context.Context, context.CancelFunc, error) {
	if !f.Leading() {
		return nil, nil, frontdoor.ErrStandingBy
	}
	ctx, cancel := context.WithTimeout(p, frontdoor.WriteMargin)
	return ctx, cancel, nil
}

// fdSecrets is a fake API server with the chart's two empty Secrets.
func fdSecrets() *fake.Clientset {
	mk := func(n string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: fdNS}}
	}
	return fake.NewClientset(mk(frontdoor.AccountSecret), mk(frontdoor.CertSecret))
}

// fdPebble is an in-process Pebble resolving through dnsAddr, its
// certificates valid validity.
func fdPebble(t *testing.T, dnsAddr string, validity time.Duration) (string, *http.Client) {
	t.Helper()
	plog := log.New(io.Discard, "", 0)
	pdb := db.NewMemoryStore()
	pca := ca.New(plog, pdb, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {Description: "test", ValidityPeriod: uint64(validity / time.Second)}})
	pva := va.New(plog, 0, 0, false, dnsAddr, pdb)
	pwfe := wfe.New(plog, pdb, pva, pca, []string{"pebble.letsencrypt.org"}, false, false, 1, 1)
	srv := httptest.NewTLSServer(pwfe.Handler())
	t.Cleanup(srv.Close)
	return srv.URL + wfe.DirectoryPath, srv.Client()
}

type fdEnv struct {
	zone   *fakedns.Zone
	cs     *fake.Clientset
	ca     string
	hc     *http.Client
	mu     sync.Mutex
	writes []string // "<op> <type> <abs name>" of every provider write
}

func newFdEnv(t *testing.T, validity time.Duration) *fdEnv {
	t.Helper()
	zone := fakedns.NewZone()
	zone.SetSOA("example.com")
	srv, err := fakedns.ServeWith(zone, "127.0.0.1:0", fakedns.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	e := &fdEnv{zone: zone, cs: fdSecrets()}
	e.ca, e.hc = fdPebble(t, srv.Addr, validity)
	return e
}

// certs is one front door (a pod) on the shared store and zone.
func (e *fdEnv) certs(fence frontdoor.WriteFence, now func() time.Time) *frontdoor.Certs {
	p := &fakedns.Provider{Zone: e.zone, Token: "good-fd", Hook: func(op string, recs []libdns.Record) error {
		if op == "get" {
			return nil
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, r := range recs {
			rr := r.RR()
			e.writes = append(e.writes, op+" "+rr.Type+" "+libdns.AbsoluteName(rr.Name, "example.com."))
		}
		return nil
	}}
	w := &frontdoor.Writer{Domain: testMain, Zone: "example.com.", P: p, TTL: time.Minute, Fence: fence}
	if now == nil {
		now = time.Now
	}
	return &frontdoor.Certs{Domain: testMain, Store: frontdoor.SecretStore{Client: e.cs, Namespace: fdNS}, DNS: w, Fence: fence,
		ACME:  &frontdoorACME{email: "ci@example.org", caServer: e.ca, hc: e.hc, skipPropagation: true},
		Check: func(chain, key string, n time.Time) error { return servableHA(chain, key, testMain, "", n) }, Now: now}
}

func (e *fdEnv) stored(t *testing.T) frontdoor.Cert {
	t.Helper()
	c, err := frontdoor.SecretStore{Client: e.cs, Namespace: fdNS}.LoadCert(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leafOf(t *testing.T, chain string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(chain))
	if b == nil {
		t.Fatal("no PEM")
	}
	l, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestIssueMainPebble: the front door orders <d> + *.<d> by DNS-01 with
// its own account; the challenge records are only TXT at
// _acme-challenge.<d> and are cleaned up; the certificate lands in
// frontdoor-cert with its account; the domains service serves it in HA.
// A standby orders nothing; a renewal after the leader moved reuses the
// stored account.
func TestIssueMainPebble(t *testing.T) {
	e := newFdEnv(t, 90*24*time.Hour)
	ctx := context.Background()

	// Standing by: no registration, no order, no provider call.
	standby := &leadFence{}
	if err := e.certs(standby, nil).IssueMain(ctx); !errors.Is(err, frontdoor.ErrStandingBy) {
		t.Fatalf("standby IssueMain: %v", err)
	}
	if _, err := e.certs(standby, nil).AccountURI(ctx); !errors.Is(err, frontdoor.ErrNoAccount) {
		t.Fatalf("standby AccountURI without an account: %v", err)
	}
	if n := e.zone.CallCount(); n != 0 {
		t.Fatalf("a standby called the provider %d times", n)
	}

	lead := &leadFence{lead: true}
	c1 := e.certs(lead, nil)
	uri, err := c1.AccountURI(ctx)
	if err != nil || uri == "" {
		t.Fatalf("AccountURI: %q %v", uri, err)
	}
	if _, err := c1.IssueMainFor(ctx, "https://other.example/acct/1"); !errors.Is(err, frontdoor.ErrOtherAccount) {
		t.Fatalf("IssueMainFor another account: %v", err)
	}
	if issued, err := c1.IssueMainFor(ctx, uri); err != nil || !issued {
		t.Fatalf("IssueMain: %v %v", issued, err)
	}
	got := e.stored(t)
	if got.AccountURI != uri {
		t.Errorf("stored account %q, want %q", got.AccountURI, uri)
	}
	if err := servableHA(got.ChainPEM, got.KeyPEM, testMain, "", time.Now()); err != nil {
		t.Fatalf("the stored certificate isn't servable: %v", err)
	}
	e.mu.Lock()
	writes := append([]string(nil), e.writes...)
	e.mu.Unlock()
	if len(writes) == 0 {
		t.Fatal("no challenge record written")
	}
	for _, w := range writes {
		if !strings.HasSuffix(w, " TXT _acme-challenge."+testMain+".") {
			t.Errorf("provider write outside _acme-challenge.%s: %s", testMain, w)
		}
	}
	if rrs := e.zone.Records("_acme-challenge." + testMain); len(rrs) != 0 {
		t.Errorf("challenge records left: %v", rrs)
	}
	// Fix round 1 (M2): asked again for the same account with 90 days
	// left, nothing is ordered (a rerun after a failed re-pin).
	e.mu.Lock()
	nw := len(e.writes)
	e.mu.Unlock()
	if issued, err := c1.IssueMainFor(ctx, uri); err != nil || issued {
		t.Fatalf("IssueMainFor with a current certificate: issued %v, %v", issued, err)
	}
	if same := e.stored(t); same.ChainPEM != got.ChainPEM || len(e.writes) != nw {
		t.Fatal("a current certificate was ordered again")
	}
	doc, dropped := buildDynamic(map[string]*Domain{}, &mainCert{CertPEM: got.ChainPEM, KeyPEM: got.KeyPEM}, testMain, "", time.Now())
	if len(doc.TLS.Certificates) != 1 || len(dropped) != 0 {
		t.Fatalf("served %d, dropped %v", len(doc.TLS.Certificates), dropped)
	}

	// Not due yet: no order.
	if ordered, err := c1.Renew(ctx); ordered || err != nil {
		t.Fatalf("Renew with 90 days left: %v %v", ordered, err)
	}
	// The leader moves (a new pod, the same Secrets) and 61 days pass.
	lead.set(false)
	later := func() time.Time { return time.Now().Add(61 * 24 * time.Hour) }
	c2 := e.certs(&leadFence{lead: true}, later)
	if ordered, err := c1.Renew(ctx); ordered || err != nil {
		t.Fatalf("the old leader renewed: %v %v", ordered, err)
	}
	ordered, err := c2.Renew(ctx)
	if !ordered || err != nil {
		t.Fatalf("the new leader's Renew: %v %v", ordered, err)
	}
	again := e.stored(t)
	if again.AccountURI != uri {
		t.Errorf("the new leader registered another account: %q, was %q", again.AccountURI, uri)
	}
	if leafOf(t, again.ChainPEM).SerialNumber.Cmp(leafOf(t, got.ChainPEM).SerialNumber) == 0 {
		t.Error("renewal stored the same certificate")
	}
}

// TestRenewOnlySameAccount: a certificate of another account (or none)
// is never ordered by Renew: the CAA may still pin that account; the
// flip's IssueMain orders it.
func TestRenewOnlySameAccount(t *testing.T) {
	e := newFdEnv(t, 90*24*time.Hour)
	ctx := context.Background()
	c := e.certs(&leadFence{lead: true}, func() time.Time { return time.Now().Add(80 * 24 * time.Hour) })
	if ordered, err := c.Renew(ctx); ordered || err != nil {
		t.Fatalf("Renew without a certificate: %v %v", ordered, err)
	}
	chain, key := mkCert(t, []string{testMain, "*." + testMain}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := (frontdoor.SecretStore{Client: e.cs, Namespace: fdNS}).SaveCert(ctx, frontdoor.Cert{ChainPEM: chain, KeyPEM: key, AccountURI: "https://old.example/acct/7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AccountURI(ctx); err != nil {
		t.Fatal(err)
	}
	if ordered, err := c.Renew(ctx); ordered || err != nil {
		t.Fatalf("Renew of another account's certificate: %v %v", ordered, err)
	}
	if n := len(e.writes); n != 0 {
		t.Fatalf("%d provider writes", n)
	}
}

// TestFrontdoorAccountSeparate: the front door's account is its own,
// never the added-domains one, even with the same CA and email; it is
// kept under the key "frontdoor" of frontdoor-acme and reused.
func TestFrontdoorAccountSeparate(t *testing.T) {
	env := newEnv(t, false)
	u, err := env.svc.account()
	if err != nil {
		t.Fatal(err)
	}
	cs := fdSecrets()
	c := &frontdoor.Certs{Domain: testMain, Store: frontdoor.SecretStore{Client: cs, Namespace: fdNS}, Fence: &leadFence{lead: true},
		ACME: &frontdoorACME{email: env.svc.cfg.Email, caServer: env.svc.cfg.CAServer, hc: env.svc.cfg.ACMEHTTPClient}}
	ctx := context.Background()
	fd, err := c.AccountURI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fd == "" || fd == u.reg.URI {
		t.Fatalf("front-door account %q, added-domains account %q: must differ", fd, u.reg.URI)
	}
	sec, err := cs.CoreV1().Secrets(fdNS).Get(ctx, frontdoor.AccountSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var acct Account
	k := frontdoor.AccountKeyFor(env.svc.cfg.CAServer)
	if len(sec.Data) != 1 || !strings.HasPrefix(k, "frontdoor-127.0.0.1-") {
		t.Fatalf("frontdoor-acme keys %v, want only %s", len(sec.Data), k)
	}
	if err := json.Unmarshal(sec.Data[k], &acct); err != nil {
		t.Fatalf("frontdoor-acme[%s]: %v", k, err)
	}
	if acct.KeyPEM == "" || acct.KeyPEM == env.svc.doc.Account.KeyPEM {
		t.Fatal("the front door's account key is empty or the added-domains account's")
	}
	if again, err := c.AccountURI(ctx); err != nil || again != fd {
		t.Fatalf("second AccountURI: %q %v (want the stored %q)", again, err, fd)
	}
	// Another CA (an ACME_STAGING flip) makes it stale: a new account.
	c.ACME = &frontdoorACME{email: env.svc.cfg.Email, caServer: env.svc.cfg.CAServer + "?other", hc: env.svc.cfg.ACMEHTTPClient}
	if c.ACME.CurrentURI(sec.Data[k]) != "" {
		t.Fatal("an account of another CA counted as current")
	}
}

// TestFrontdoorControlClient: `domains frontdoor account-uri` / `issue
// --account-uri` against the running front door's loopback listener;
// standing by = exit 1; another account = exit 1; a non-loopback control
// address is refused.
func TestFrontdoorControlClient(t *testing.T) {
	e := newFdEnv(t, 90*24*time.Hour)
	fence := &leadFence{}
	srv := httptest.NewServer(frontdoorControl(e.certs(fence, nil), func(s string) string { return s }))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	run := func(args ...string) (int, string, string) {
		var out, errb strings.Builder
		code := runFrontdoorClient(args, addr, &out, &errb)
		return code, out.String(), errb.String()
	}
	if code, out, msg := run("account-uri"); code != exitProblem || !strings.Contains(msg, "no ACME account") || !strings.Contains(out, `"refused"`) {
		t.Fatalf("standby account-uri: %d %q %s (a refusal names itself on stdout too)", code, out, msg)
	}
	fence.set(true)
	code, out, msg := run("account-uri")
	uri := strings.TrimSpace(out)
	if code != exitOK || !strings.HasPrefix(uri, "https://") {
		t.Fatalf("account-uri: %d %q %s", code, out, msg)
	}
	if code, _, _ := run("issue", "--account-uri", "https://other.example/acct/9"); code != exitProblem {
		t.Fatalf("issue for another account: %d", code)
	}
	if code, _, _ := run("issue", "--account-uri", "not a uri"); code != exitUsage {
		t.Fatalf("issue with a bad URI: %d", code)
	}
	code, out, msg = run("issue", "--account-uri", uri)
	if code != exitOK || !strings.Contains(out, `"issued":true`) || !strings.Contains(out, uri) {
		t.Fatalf("issue: %d %s %s", code, out, msg)
	}
	code, out, _ = run("issue", "--account-uri", uri)
	if code != exitOK || !strings.Contains(out, `"issued":false`) || !strings.Contains(out, `"current":true`) {
		t.Fatalf("issue again (current): %d %s", code, out)
	}
	code, out, _ = run("cert-status")
	if code != exitOK || !strings.Contains(out, `"renews_on_its_own":true`) || !strings.Contains(out, `"present":true`) {
		t.Fatalf("cert-status: %d %s", code, out)
	}
	if code, _, _ := run("bogus"); code != exitUsage {
		t.Fatalf("bogus: %d", code)
	}
	var b strings.Builder
	if code := runFrontdoorClient([]string{"account-uri"}, "10.0.0.1:8091", &b, &b); code != exitUsage {
		t.Fatalf("non-loopback control address: %d", code)
	}
}

// TestAccountPerCARevertKeepsOld (fix round 1, C1): an ACME_STAGING flip
// registers the new CA's account under its own key; the old CA's account
// (the one the CAA still pins) stays, so a stopped or reverted flip
// renews with it again.
func TestAccountPerCARevertKeepsOld(t *testing.T) {
	e := newFdEnv(t, 90*24*time.Hour)
	ctx := context.Background()
	lead := &leadFence{lead: true}
	cA := e.certs(lead, nil)
	uriA, err := cA.AccountURI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cA.IssueMainFor(ctx, uriA); err != nil {
		t.Fatal(err)
	}
	// The flip: the front door on CA B (another directory host:port).
	caB, hcB := fdPebble(t, "127.0.0.1:1", 90*24*time.Hour)
	cB := e.certs(lead, nil)
	cB.ACME = &frontdoorACME{email: "ci@example.org", caServer: caB, hc: hcB, skipPropagation: true}
	uriB, err := cB.AccountURI(ctx)
	if err != nil || uriB == "" || uriB == uriA {
		t.Fatalf("CA B's account %q (A's %q): %v", uriB, uriA, err)
	}
	if ordered, err := cB.Renew(ctx); ordered || err != nil {
		t.Fatalf("CA B renewed CA A's certificate: %v %v", ordered, err)
	}
	sec, err := e.cs.CoreV1().Secrets(fdNS).Get(ctx, frontdoor.AccountSecret, metav1.GetOptions{})
	if err != nil || len(sec.Data) != 2 {
		t.Fatalf("frontdoor-acme holds %d accounts, want both CAs': %v", len(sec.Data), err)
	}
	// Reverted: back on CA A, the same account, and it renews on its own.
	later := func() time.Time { return time.Now().Add(61 * 24 * time.Hour) }
	cA2 := e.certs(lead, later)
	if again, err := cA2.AccountURI(ctx); err != nil || again != uriA {
		t.Fatalf("after the revert: %q %v, want CA A's %q", again, err, uriA)
	}
	if ordered, err := cA2.Renew(ctx); !ordered || err != nil {
		t.Fatalf("after the revert the old account didn't renew: %v %v", ordered, err)
	}
	if got := e.stored(t); got.AccountURI != uriA {
		t.Fatalf("renewed with %q", got.AccountURI)
	}
}

// TestCertStatus: the status line's source says why a certificate isn't
// renewed on its own.
func TestCertStatus(t *testing.T) {
	e := newFdEnv(t, 90*24*time.Hour)
	ctx := context.Background()
	c := e.certs(&leadFence{lead: true}, nil)
	st, err := c.Status(ctx)
	if err != nil || st.Present || !strings.Contains(st.Why, "no certificate yet") {
		t.Fatalf("no certificate: %+v %v", st, err)
	}
	chain, key := mkCert(t, []string{testMain, "*." + testMain}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := (frontdoor.SecretStore{Client: e.cs, Namespace: fdNS}).SaveCert(ctx, frontdoor.Cert{ChainPEM: chain, KeyPEM: key, AccountURI: "https://old.example/acct/7"}); err != nil {
		t.Fatal(err)
	}
	st, err = c.Status(ctx)
	if err != nil || !st.Present || st.RenewsOnItsOwn || st.Due || !strings.Contains(st.Why, "old.example") || st.NotAfter == "" {
		t.Fatalf("another account's certificate: %+v %v", st, err)
	}
}
