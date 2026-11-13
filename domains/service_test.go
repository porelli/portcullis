package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/dnsplan"
	"github.com/portcullis/domains/internal/dnssec"
	"github.com/portcullis/domains/internal/fakedns"
)

const (
	testMain   = "portcullis.example.com"
	testSecret = "0123456789abcdef0123456789abcdef-api"
	goodToken  = "good-Tk9vZXJ5U2VjcmV0VG9rZW4xMjM0"
	badToken   = "bad-QmFkU2VjcmV0VG9rZW5abGtqaGdm"
)

func TestMain(m *testing.M) {
	os.Setenv("PEBBLE_VA_NOSLEEP", "1")
	os.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	os.Exit(m.Run())
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type clock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

type testEnv struct {
	t      *testing.T
	svc    *Service
	api    http.Handler
	zone   *fakedns.Zone
	srv    *fakedns.Server
	logs   *syncBuf
	clock  *clock
	dir    string
	id     *age.X25519Identity
	cancel context.CancelFunc
	bodies []string // every API response body (checked for credentials)
	// hook runs before every fake provider call (token = the caller's).
	hookMu sync.Mutex
	hook   func(op string, recs []libdns.Record, token string) error
}

func (e *testEnv) setHook(h func(op string, recs []libdns.Record, token string) error) {
	e.hookMu.Lock()
	e.hook = h
	e.hookMu.Unlock()
}

// newEnv starts the fake DNS zone and server, an in-process Pebble whose
// VA resolves through it, and the service with a running worker.
func newEnv(t *testing.T, ipv6 bool) *testEnv { t.Helper(); return newEnvWith(t, ipv6, nil) }

// newEnvWith: newEnv with the configuration changed by mod before start.
func newEnvWith(t *testing.T, ipv6 bool, mod func(*Config)) *testEnv {
	t.Helper()
	zone := fakedns.NewZone()
	// The test domains live under example.org (the SOA the DNSSEC check
	// finds); the fake provider writes each domain as its own zone.
	zone.SetSOA("example.org")
	dnsSrv, err := fakedns.ServeWith(zone, "127.0.0.1:0", fakedns.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dnsSrv.Close() })

	plog := log.New(io.Discard, "", 0)
	pdb := db.NewMemoryStore()
	pca := ca.New(plog, pdb, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {Description: "test", ValidityPeriod: 90 * 24 * 3600}})
	pva := va.New(plog, 0, 0, false, dnsSrv.Addr, pdb)
	pwfe := wfe.New(plog, pdb, pva, pca, []string{"pebble.letsencrypt.org"}, false, false, 1, 1)
	pebble := httptest.NewTLSServer(pwfe.Handler())
	t.Cleanup(pebble.Close)

	e := &testEnv{}
	providers["fake"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return &fakedns.Provider{Zone: zone, Token: c["api_token"], Accept: func(tok string) bool { return strings.HasPrefix(tok, "good-") },
			Hook: func(op string, recs []libdns.Record) error {
				e.hookMu.Lock()
				h := e.hook
				e.hookMu.Unlock()
				if h == nil {
					return nil
				}
				return h(op, recs, c["api_token"])
			}}, nil
	}}
	t.Cleanup(func() { delete(providers, "fake") })

	logs := &syncBuf{}
	legolog.Logger = log.New(logs, "lego: ", 0)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	clk := &clock{}
	cfg := Config{
		MainDomain: testMain, Email: "ci@example.org", CAServer: pebble.URL + wfe.DirectoryPath,
		IPv4: netip.MustParseAddr("203.0.113.10"), Resolvers: []string{dnsSrv.Addr}, Secret: testSecret,
		PropagationTimeout: 30 * time.Second, PropagationInterval: 50 * time.Millisecond, RecordsWait: 2 * time.Second, RecordsPoll: 50 * time.Millisecond,
		Tick: 50 * time.Millisecond, ACMEHTTPClient: pebble.Client(), Now: clk.now, Logger: log.New(logs, "", 0),
		CAA: true, CAAIssuer: "pebble.test",
	}
	if ipv6 {
		cfg.IPv6 = netip.MustParseAddr("2001:db8::10")
	}
	if mod != nil {
		mod(&cfg)
	}
	svc, err := NewService(cfg, OpenStore(dir, id))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	e.t, e.svc, e.api, e.zone, e.srv, e.logs, e.clock, e.dir, e.id, e.cancel = t, svc, svc.APIHandler(), zone, dnsSrv, logs, clk, dir, id, cancel
	t.Cleanup(func() {
		cancel()
		<-done
		e.assertNoCredentials()
	})
	return e
}

// do sends an API request (with the bearer secret unless auth is false).
func (e *testEnv) do(method, path, body string, auth bool) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+testSecret)
	}
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, req)
	e.bodies = append(e.bodies, rec.Body.String())
	return rec.Code, rec.Body.String()
}

func creds(tok string) string {
	return `{"provider":"fake","credentials":{"api_token":"` + tok + `"}}`
}

func (e *testEnv) list() map[string]View {
	e.t.Helper()
	code, body := e.do("GET", "/domains", "", true)
	if code != 200 {
		e.t.Fatalf("GET /domains = %d %s", code, body)
	}
	var vs []View
	if err := json.Unmarshal([]byte(body), &vs); err != nil {
		e.t.Fatal(err)
	}
	out := map[string]View{}
	for _, v := range vs {
		out[v.Name] = v
	}
	return out
}

func (e *testEnv) waitState(name, want string, timeout time.Duration) View {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		v := e.list()[name]
		if v.State == want {
			return v
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("%s: state %q (last_error %q), want %q\nlogs:\n%s", name, v.State, v.LastError, want, e.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (e *testEnv) dynamic() (map[string]any, dynamicDoc) {
	e.t.Helper()
	rec := httptest.NewRecorder()
	e.svc.CertsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/traefik/dynamic", nil))
	if rec.Code != 200 {
		e.t.Fatalf("dynamic = %d", rec.Code)
	}
	var raw map[string]any
	var doc dynamicDoc
	json.Unmarshal(rec.Body.Bytes(), &raw)
	json.Unmarshal(rec.Body.Bytes(), &doc)
	return raw, doc
}

// assertNoCredentials: no token in logs, API answers or the store file.
func (e *testEnv) assertNoCredentials() {
	e.t.Helper()
	raw, _ := os.ReadFile(filepath.Join(e.dir, "store.age"))
	for _, tok := range []string{goodToken, badToken, goodToken[5:], badToken[4:]} {
		if strings.Contains(e.logs.String(), tok) {
			e.t.Errorf("a credential is in the logs:\n%s", e.logs.String())
		}
		for _, b := range e.bodies {
			if strings.Contains(b, tok) {
				e.t.Errorf("a credential is in an API answer: %s", b)
			}
		}
		if bytes.Contains(raw, []byte(tok)) {
			e.t.Error("a credential is in clear in the store file")
		}
	}
}

// assertServedSANs checks the served document (only tls.certificates with
// certFile/keyFile) and returns each certificate's sorted SANs.
func assertServed(t *testing.T, raw map[string]any, doc dynamicDoc) [][]string {
	t.Helper()
	if len(raw) != 1 || raw["tls"] == nil {
		t.Fatalf("document keys %v, want only tls", raw)
	}
	tlsPart := raw["tls"].(map[string]any)
	if len(tlsPart) != 1 || tlsPart["certificates"] == nil {
		t.Fatalf("tls keys %v, want only certificates", tlsPart)
	}
	for _, c := range tlsPart["certificates"].([]any) {
		if m := c.(map[string]any); len(m) != 2 || m["certFile"] == nil || m["keyFile"] == nil {
			t.Fatalf("certificate entry keys %v, want certFile and keyFile", m)
		}
	}
	var out [][]string
	for _, c := range doc.TLS.Certificates {
		leaf, err := parseLeaf(c.CertFile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tls.X509KeyPair([]byte(c.CertFile), []byte(c.KeyFile)); err != nil {
			t.Fatal(err)
		}
		sans := append([]string(nil), leaf.DNSNames...)
		sort.Strings(sans)
		out = append(out, sans)
	}
	return out
}

func TestEnrollIssuesCert(t *testing.T) {
	e := newEnv(t, false)
	code, body := e.do("PUT", "/domains/team-b.example.org", creds(goodToken), true)
	if code != 202 || !strings.Contains(body, `"state":"pending"`) || !strings.Contains(body, `"cert_not_after":null`) {
		t.Fatalf("enroll = %d %s", code, body)
	}
	v := e.waitState("team-b.example.org", StateReady, 60*time.Second)
	if !v.RecordsOK || v.CertNotAfter == nil || v.LastError != "" || v.Provider != "fake" {
		t.Fatalf("ready view %+v", v)
	}
	na, _ := time.Parse(time.RFC3339, *v.CertNotAfter)
	if na.Before(time.Now().Add(60 * 24 * time.Hour)) {
		t.Fatalf("cert_not_after %s", *v.CertNotAfter)
	}
	raw, doc := e.dynamic()
	sans := assertServed(t, raw, doc)
	if len(sans) != 1 || strings.Join(sans[0], ",") != "*.team-b.example.org,team-b.example.org" {
		t.Fatalf("served SANs %v", sans)
	}
	// The challenge records were cleaned up.
	if rrs := e.zone.Records("_acme-challenge.team-b.example.org"); len(rrs) != 0 {
		t.Fatalf("challenge TXT left behind: %v", rrs)
	}
	// Delete drops the certificate from the endpoint and removes the records.
	if code, body := e.do("DELETE", "/domains/team-b.example.org", "", true); code != 204 {
		t.Fatalf("delete = %d %s", code, body)
	}
	if _, doc := e.dynamic(); len(doc.TLS.Certificates) != 0 {
		t.Fatal("certificate still served after delete")
	}
	if rrs := e.zone.Records("team-b.example.org"); len(rrs) != 0 {
		t.Fatalf("records left after delete: %v", rrs)
	}
}

func TestEnrollBadToken(t *testing.T) {
	e := newEnv(t, false)
	if code, body := e.do("PUT", "/domains/team-c.example.org", creds(badToken), true); code != 202 {
		t.Fatalf("enroll = %d %s", code, body)
	}
	v := e.waitState("team-c.example.org", StateError, 10*time.Second)
	if !strings.Contains(v.LastError, "authentication failed") || strings.Contains(v.LastError, badToken) || !strings.Contains(v.LastError, "[redacted]") {
		t.Fatalf("last_error %q", v.LastError)
	}
	e.svc.mu.Lock()
	d := e.svc.doc.Domains["team-c.example.org"]
	failures, next := d.Failures, d.NextAttempt
	e.svc.mu.Unlock()
	if failures != 1 || next.Sub(e.clock.now()) < 50*time.Second {
		t.Fatalf("failures %d, next attempt in %s (want backoff ≈ 1m)", failures, next.Sub(e.clock.now()))
	}
	calls := e.zone.CallCount
	before := calls()
	time.Sleep(300 * time.Millisecond) // several worker ticks
	if after := calls(); after != before {
		t.Fatalf("retried during backoff (%d → %d provider calls)", before, after)
	}
	// After the backoff it is retried, and backs off longer.
	e.clock.advance(61 * time.Second)
	e.svc.Kick()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.svc.mu.Lock()
		f := d.Failures
		e.svc.mu.Unlock()
		if f == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not retried after the backoff (failures %d)", f)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if b := backoff(2); b != 2*time.Minute || backoff(20) != 6*time.Hour {
		t.Fatalf("backoff(2) = %s, backoff(20) = %s", b, backoff(20))
	}
	// New credentials restart at once.
	if code, body := e.do("POST", "/domains/team-c.example.org/token", creds(goodToken), true); code != 202 || !strings.Contains(body, `"state":"pending"`) {
		t.Fatalf("token = %d %s", code, body)
	}
	e.waitState("team-c.example.org", StateReady, 60*time.Second)
}

func TestRecordsCreatedAAndAAAA(t *testing.T) {
	e := newEnv(t, true)
	// Existing records at the two names are replaced; others stay.
	e.zone.Set("team-d.example.org", libdns.RR{Name: "@", Type: "A", Data: "198.51.100.1", TTL: time.Hour}, libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.org.", TTL: time.Hour})
	e.zone.Set("*.team-d.example.org", libdns.RR{Name: "*", Type: "AAAA", Data: "2001:db8::99", TTL: time.Hour})
	if code, body := e.do("PUT", "/domains/team-d.example.org", creds(goodToken), true); code != 202 {
		t.Fatalf("enroll = %d %s", code, body)
	}
	e.waitState("team-d.example.org", StateReady, 60*time.Second)
	for _, n := range []string{"team-d.example.org", "*.team-d.example.org"} {
		var got []string
		for _, rr := range e.zone.Records(n) {
			if rr.Type != "CAA" { // the caa set (TestCAA*)
				got = append(got, rr.Type+" "+rr.Data+" "+rr.TTL.String())
			}
		}
		sort.Strings(got)
		want := []string{"A 203.0.113.10 5m0s", "AAAA 2001:db8::10 5m0s"}
		if n == "team-d.example.org" {
			want = []string{"A 203.0.113.10 5m0s", "AAAA 2001:db8::10 5m0s", "MX 10 mail.example.org. 1h0m0s"}
		}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: records %v, want %v", n, got, want)
		}
	}
	// DELETE removes exactly what the service created.
	if code, _ := e.do("DELETE", "/domains/team-d.example.org", "", true); code != 204 {
		t.Fatalf("delete = %d", code)
	}
	if rrs := e.zone.Records("team-d.example.org"); len(rrs) != 1 || rrs[0].Type != "MX" {
		t.Fatalf("after delete %v, want only the MX", rrs)
	}
	if rrs := e.zone.Records("*.team-d.example.org"); len(rrs) != 0 {
		t.Fatalf("after delete %v", rrs)
	}
}

func TestRecordsWithoutIPv6DropAAAA(t *testing.T) {
	e := newEnv(t, false)
	e.zone.Set("team-e.example.org", libdns.RR{Name: "@", Type: "AAAA", Data: "2001:db8::99", TTL: time.Hour})
	e.do("PUT", "/domains/team-e.example.org", creds(goodToken), true)
	e.waitState("team-e.example.org", StateReady, 60*time.Second)
	for _, n := range []string{"team-e.example.org", "*.team-e.example.org"} {
		if rrs := addrRecords(e.zone, n); len(rrs) != 1 || rrs[0].Type != "A" || rrs[0].Data != "203.0.113.10" {
			t.Errorf("%s: %v, want only A 203.0.113.10", n, rrs)
		}
	}
}

// addrRecords are the A/AAAA records at name.
func addrRecords(z *fakedns.Zone, name string) []libdns.RR {
	var out []libdns.RR
	for _, rr := range z.Records(name) {
		if rr.Type == "A" || rr.Type == "AAAA" {
			out = append(out, rr)
		}
	}
	return out
}

func TestRecordsNotVisibleIsError(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-f.example.org", creds(goodToken), true)
	e.waitState("team-f.example.org", StateReady, 60*time.Second)
	// Someone points the wildcard elsewhere: the next check fails, the
	// still-valid certificate stays served.
	e.zone.Set("*.team-f.example.org", libdns.RR{Name: "*", Type: "A", Data: "198.51.100.7", TTL: time.Minute})
	e.clock.advance(2 * time.Hour)
	v := e.waitState("team-f.example.org", StateError, 20*time.Second)
	if v.RecordsOK || !strings.Contains(v.LastError, "portcullis-probe.team-f.example.org") || v.CertNotAfter == nil {
		t.Fatalf("view %+v", v)
	}
	if _, doc := e.dynamic(); len(doc.TLS.Certificates) != 1 {
		t.Fatal("a still-valid certificate must stay served")
	}
	// The retry sets the records again.
	e.clock.advance(2 * time.Minute)
	e.waitState("team-f.example.org", StateReady, 20*time.Second)
}

func TestRenewal(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-g.example.org", creds(goodToken), true)
	first := e.waitState("team-g.example.org", StateReady, 60*time.Second)
	_, doc := e.dynamic()
	leaf1, _ := parseLeaf(doc.TLS.Certificates[0].CertFile)
	// 61 days later the 90-day certificate has < 30 days left.
	e.clock.advance(61 * 24 * time.Hour)
	e.svc.Kick()
	deadline := time.Now().Add(60 * time.Second)
	for {
		v := e.list()["team-g.example.org"]
		if v.State == StateReady && v.CertNotAfter != nil && *v.CertNotAfter != *first.CertNotAfter {
			break
		}
		if v.State == StateRenewing {
			// The current certificate stays served meanwhile.
			if _, d := e.dynamic(); len(d.TLS.Certificates) != 1 {
				t.Fatal("no certificate served while renewing")
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("not renewed: %+v\n%s", v, e.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, doc = e.dynamic()
	leaf2, _ := parseLeaf(doc.TLS.Certificates[0].CertFile)
	if leaf2.SerialNumber.Cmp(leaf1.SerialNumber) == 0 || len(doc.TLS.Certificates) != 1 {
		t.Fatal("renewal didn't replace the certificate in place")
	}
	if !strings.Contains(e.logs.String(), "renewing a certificate") {
		t.Fatal("renewal not logged")
	}
}

func TestTokenNeverLogged(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-h.example.org", creds(badToken), true)
	e.waitState("team-h.example.org", StateError, 10*time.Second)
	e.do("POST", "/domains/team-h.example.org/token", creds(goodToken), true)
	e.waitState("team-h.example.org", StateReady, 60*time.Second)
	// A failing delete (credentials rejected) answers a redacted warning.
	e.svc.mu.Lock()
	e.svc.doc.Domains["team-h.example.org"].Credentials["api_token"] = badToken
	e.svc.mu.Unlock()
	code, body := e.do("DELETE", "/domains/team-h.example.org", "", true)
	if code != 200 || !strings.Contains(body, "warning") || !strings.Contains(body, "[redacted]") {
		t.Fatalf("delete = %d %s", code, body)
	}
	if !strings.Contains(e.logs.String(), "team-h.example.org") {
		t.Fatal("captured no logs")
	}
	// assertNoCredentials runs at cleanup (logs, every answer, the store).
}

func TestStoreEncrypted(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-i.example.org", creds(goodToken), true)
	e.waitState("team-i.example.org", StateReady, 60*time.Second)
	raw, err := os.ReadFile(filepath.Join(e.dir, "store.age"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte("age-encryption.org/v1\n")) {
		t.Fatal("store is not an age file")
	}
	for _, s := range []string{goodToken, "api_token", "PRIVATE KEY", "team-i.example.org"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("store file contains %q in clear", s)
		}
	}
	st, _ := os.Stat(filepath.Join(e.dir, "store.age"))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("store mode %v", st.Mode().Perm())
	}
	// It decrypts with the identity, and reloads (restart).
	r, err := age.Decrypt(bytes.NewReader(raw), e.id)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(r)
	if !bytes.Contains(plain, []byte(goodToken)) {
		t.Fatal("decrypted store lacks the credentials")
	}
	doc, err := OpenStore(e.dir, e.id).Load()
	if err != nil || doc.Domains["team-i.example.org"] == nil || doc.Account == nil {
		t.Fatalf("reload: %v", err)
	}
	other, _ := age.GenerateX25519Identity()
	if _, err := OpenStore(e.dir, other).Load(); err == nil {
		t.Fatal("loaded with the wrong key")
	}
}

// mkCert makes a self-signed certificate (EC P-256) with the given names.
func mkCert(t *testing.T, sans []string, ips []net.IP, notBefore, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cn := ""
	if len(sans) > 0 {
		cn = sans[0]
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		DNSNames: sans, IPAddresses: ips, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
}

func TestServesOnlyOwnCertificates(t *testing.T) {
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(60*24*time.Hour)
	domains := map[string]*Domain{}
	add := func(name string, sans []string, ips []net.IP, nb, na time.Time) {
		c, k := mkCert(t, sans, ips, nb, na)
		domains[name] = &Domain{Name: name, CertPEM: c, KeyPEM: k, CertNotAfter: &na}
	}
	add("good.example.org", []string{"good.example.org", "*.good.example.org"}, nil, nb, na)
	add("team-a."+testMain, []string{"team-a." + testMain, "*.team-a." + testMain}, nil, nb, na) // enrolled subdomain of main: allowed
	add("evil1.example.org", []string{"evil1.example.org", "*.evil1.example.org", "auth." + testMain}, nil, nb, na)
	add("evil2.example.org", []string{"auth." + testMain, "*." + testMain}, nil, nb, na)
	add("evil3.example.org", []string{"evil3.example.org"}, nil, nb, na)
	add("evil4.example.org", []string{"evil4.example.org", "*.evil4.example.org"}, []net.IP{net.ParseIP("203.0.113.1")}, nb, na)
	add("expired.example.org", []string{"expired.example.org", "*.expired.example.org"}, nil, now.Add(-48*time.Hour), now.Add(-time.Hour))
	add("auth."+testMain, []string{"auth." + testMain, "*.auth." + testMain}, nil, nb, na) // a core host as a "domain"
	add(testMain, []string{testMain, "*." + testMain}, nil, nb, na)                        // the main domain
	add("example.com", []string{"example.com", "*.example.com"}, nil, nb, na)              // a parent of the main domain
	add("x.hub."+testMain, []string{"x.hub." + testMain, "*.x.hub." + testMain}, nil, nb, na)
	// Stored under another name than the certificate's.
	c, k := mkCert(t, []string{"other.example.org", "*.other.example.org"}, nil, nb, na)
	domains["mismatch.example.org"] = &Domain{Name: "mismatch.example.org", CertPEM: c, KeyPEM: k, CertNotAfter: &na}
	// Key of another certificate.
	c1, _ := mkCert(t, []string{"wrongkey.example.org", "*.wrongkey.example.org"}, nil, nb, na)
	_, k2 := mkCert(t, []string{"wrongkey.example.org", "*.wrongkey.example.org"}, nil, nb, na)
	domains["wrongkey.example.org"] = &Domain{Name: "wrongkey.example.org", CertPEM: c1, KeyPEM: k2, CertNotAfter: &na}
	domains["nocert.example.org"] = &Domain{Name: "nocert.example.org", State: StatePending}
	// A common name naming another host (clients that still look at the CN).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "auth." + testMain},
		DNSNames: []string{"cn.example.org", "*.cn.example.org"}, NotBefore: nb, NotAfter: na}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	domains["cn.example.org"] = &Domain{Name: "cn.example.org", CertNotAfter: &na,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))}
	// A domain being deleted is no longer served.
	add("leaving.example.org", []string{"leaving.example.org", "*.leaving.example.org"}, nil, nb, na)
	domains["leaving.example.org"].Deleting = true

	doc, dropped := buildDynamic(domains, testMain, now)
	b, _ := json.Marshal(doc)
	var raw map[string]any
	json.Unmarshal(b, &raw)
	sans := assertServed(t, raw, doc)
	var got []string
	for _, s := range sans {
		got = append(got, strings.Join(s, ","))
	}
	want := []string{"*.good.example.org,good.example.org", "*.team-a." + testMain + ",team-a." + testMain}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("served %v, want %v", got, want)
	}
	if len(dropped) != 12 {
		t.Fatalf("dropped %d: %v", len(dropped), dropped)
	}
	for _, d := range dropped {
		if strings.Contains(d, "PRIVATE") {
			t.Fatal("dropped reason holds key material")
		}
	}
	// Nothing at all: still the bare shape.
	empty, _ := buildDynamic(map[string]*Domain{}, testMain, now)
	if b, _ := json.Marshal(empty); string(b) != `{"tls":{"certificates":[]}}` {
		t.Fatalf("empty document %s", b)
	}
}

// TestCertsEndpointRequiresClientCert: the listener answers only clients
// with a certificate from the endpoint CA.
func TestCertsEndpointRequiresClientCert(t *testing.T) {
	dir := t.TempDir()
	mkCA := func() (*x509.Certificate, *ecdsa.PrivateKey) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		c, _ := x509.ParseCertificate(der)
		return c, key
	}
	issue := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey, eku x509.ExtKeyUsage, dns []string) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: dns,
			ExtKeyUsage: []x509.ExtKeyUsage{eku}, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	ca, caKey := mkCA()
	srvCert := issue(ca, caKey, x509.ExtKeyUsageServerAuth, []string{"domains", "localhost"})
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	kder, _ := x509.MarshalECPrivateKey(srvCert.PrivateKey.(*ecdsa.PrivateKey))
	cfg, err := endpointTLS(write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
		write("server.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCert.Certificate[0]})),
		write("server.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})))
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{cfg: Config{MainDomain: testMain, Now: time.Now, Logger: log.New(io.Discard, "", 0)}, doc: &storeDoc{Domains: map[string]*Domain{}}}
	srv := httptest.NewUnstartedServer(svc.CertsHandler())
	srv.TLS = cfg
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	get := func(certs []tls.Certificate) (int, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "domains", Certificates: certs}}}
		resp, err := c.Get(srv.URL + "/traefik/dynamic")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get([]tls.Certificate{issue(ca, caKey, x509.ExtKeyUsageClientAuth, nil)}); err != nil || code != 200 {
		t.Fatalf("with the client certificate: %d %v", code, err)
	}
	if _, err := get(nil); err == nil {
		t.Fatal("served without a client certificate")
	}
	other, otherKey := mkCA()
	if _, err := get([]tls.Certificate{issue(other, otherKey, x509.ExtKeyUsageClientAuth, nil)}); err == nil {
		t.Fatal("served to a certificate of another CA")
	}
	if _, err := get([]tls.Certificate{issue(ca, caKey, x509.ExtKeyUsageServerAuth, nil)}); err == nil {
		t.Fatal("served to a certificate without clientAuth")
	}
}

func TestAPIValidation(t *testing.T) {
	e := newEnv(t, false)
	if code, _ := e.do("GET", "/domains", "", false); code != 401 {
		t.Fatalf("no bearer = %d", code)
	}
	req := httptest.NewRequest("GET", "/domains", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("wrong bearer = %d", rec.Code)
	}
	if code, _ := e.do("GET", "/healthz", "", false); code != 200 {
		t.Fatalf("healthz = %d", code)
	}
	for _, name := range []string{testMain, "example.com", "auth." + testMain, "x.hub." + testMain, "Team.example.org", "localhost", "a..b", "*.example.org"} {
		if code, body := e.do("PUT", "/domains/"+name, creds(goodToken), true); code != 400 {
			t.Errorf("PUT %s = %d %s", name, code, body)
		}
	}
	for _, body := range []string{
		`{"provider":"nope","credentials":{"api_token":"x"}}`,
		`{"provider":"cloudflare","credentials":{"api_token":"x","extra":"y"}}`,
		`{"provider":"cloudflare","credentials":{}}`,
		`{"provider":"cloudflare","credentials":{"api_token":""}}`,
		`{"provider":"porkbun","credentials":{"api_key":"x"}}`,
		`{"provider":"cloudflare","credentials":{"api_token":1}}`,
		`{"provider":"cloudflare","credentials":{"api_token":"x"},"other":1}`,
		`not json`,
	} {
		if code, resp := e.do("PUT", "/domains/x.example.org", body, true); code != 400 || strings.Contains(resp, `"x"`) {
			t.Errorf("PUT %s = %d %s", body, code, resp)
		}
	}
	if err := validateCredentials("route53", map[string]string{"access_key_id": "AKIAEXAMPLE1", "secret_access_key": "secret-access-key"}); err != nil {
		t.Fatalf("route53 without hosted_zone_id: %v", err)
	}
	if err := validateCredentials("route53", map[string]string{"access_key_id": "AKIAEXAMPLE1", "secret_access_key": "secret-access-key", "hosted_zone_id": "Z1"}); err != nil {
		t.Fatalf("route53 with hosted_zone_id: %v", err)
	}
	if code, _ := e.do("PUT", "/domains/x.example.org", creds(goodToken), true); code != 202 {
		t.Fatal("enroll x.example.org")
	}
	if code, _ := e.do("PUT", "/domains/x.example.org", creds(goodToken), true); code != 409 {
		t.Fatalf("re-enroll = %d", code)
	}
	if code, _ := e.do("POST", "/domains/y.example.org/token", creds(goodToken), true); code != 404 {
		t.Fatalf("token of unknown = %d", code)
	}
	if code, _ := e.do("DELETE", "/domains/y.example.org", "", true); code != 404 {
		t.Fatalf("delete unknown = %d", code)
	}
	if code, _ := e.do("DELETE", "/domains/x.example.org", "", true); code != 204 && code != 200 {
		t.Fatalf("delete = %d", code)
	}
}

func TestRedact(t *testing.T) {
	c := map[string]string{"api_token": "s3cr3t/t0ken+value"}
	for _, msg := range []string{"bad s3cr3t/t0ken+value", `token "s3cr3t/t0ken+value"`, "url ?t=s3cr3t%2Ft0ken%2Bvalue", "prefix s3cr3t/t0"} {
		if out := redact(msg, c); strings.Contains(out, "s3cr3t") {
			t.Errorf("redact(%q) = %q", msg, out)
		}
	}
}

// TestProviderErrorsRedacted: provider errors on the DNS-01 challenge
// (Present, CleanUp) and on records echo the token; nothing that logs,
// stores or answers may carry it.
func TestProviderErrorsRedacted(t *testing.T) {
	e := newEnv(t, false)
	echo := func(op string, tok string) error {
		return fmt.Errorf("provider said: %s refused for token=%s (request body {\"token\":%q})", op, tok, tok)
	}
	// 1. Present fails.
	e.setHook(func(op string, recs []libdns.Record, tok string) error {
		if op == "append" && len(recs) > 0 && recs[0].RR().Type == "TXT" {
			return echo("TXT append", tok)
		}
		return nil
	})
	e.do("PUT", "/domains/team-j.example.org", creds(goodToken), true)
	v := e.waitState("team-j.example.org", StateError, 20*time.Second)
	if !strings.Contains(v.LastError, "TXT append refused") || !strings.Contains(v.LastError, "[redacted]") {
		t.Fatalf("last_error %q", v.LastError)
	}
	// 2. CleanUp fails (lego only logs it), issuance succeeds.
	e.setHook(func(op string, recs []libdns.Record, tok string) error {
		if op == "delete" && len(recs) > 0 && recs[0].RR().Type == "TXT" {
			return echo("TXT delete", tok)
		}
		return nil
	})
	e.clock.advance(2 * time.Minute)
	e.svc.Kick()
	e.waitState("team-j.example.org", StateReady, 30*time.Second)
	if !strings.Contains(e.logs.String(), "TXT delete refused") {
		t.Fatalf("CleanUp failure not logged:\n%s", e.logs.String())
	}
	// 3. Records fail on a re-check (the records already there: the
	// step only reads them, and that read fails).
	e.setHook(func(op string, recs []libdns.Record, tok string) error {
		if op == "get" {
			return echo("records set", tok)
		}
		return nil
	})
	e.do("POST", "/domains/team-j.example.org/token", creds(goodToken), true)
	v = e.waitState("team-j.example.org", StateError, 20*time.Second)
	if !strings.Contains(v.LastError, "records set refused") {
		t.Fatalf("last_error %q", v.LastError)
	}
	// 4. Delete's record removal fails: the warning is redacted.
	e.setHook(func(op string, _ []libdns.Record, tok string) error {
		if op == "delete" {
			return echo("records delete", tok)
		}
		return nil
	})
	code, body := e.do("DELETE", "/domains/team-j.example.org", "", true)
	if code != 200 || !strings.Contains(body, "records delete refused") {
		t.Fatalf("delete = %d %s", code, body)
	}
	// assertNoCredentials (cleanup) checks logs, answers and the store.
}

// TestStaleWorkNeverCommits: work started for a deleted enrollment can't
// write into a new enrollment of the same name, and DELETE waits for a
// running records step so the records it creates are removed too.
func TestStaleWorkNeverCommits(t *testing.T) {
	e := newEnv(t, false)
	inSet, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.setHook(func(op string, recs []libdns.Record, tok string) error {
		if recordsWrite(op, recs) && tok == goodToken {
			once.Do(func() { close(inSet); <-release })
		}
		return nil
	})
	e.do("PUT", "/domains/team-k.example.org", creds(goodToken), true)
	<-inSet // the first enrollment's records step is running
	deleted := make(chan string)
	go func() {
		code, body := e.do("DELETE", "/domains/team-k.example.org", "", true)
		deleted <- fmt.Sprint(code, " ", body)
	}()
	select {
	case r := <-deleted:
		t.Fatalf("DELETE returned (%s) while the records step was still running", r)
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if r := <-deleted; r != "204 " {
		t.Fatalf("delete = %s", r)
	}
	// The records set by the running step were removed.
	for _, n := range []string{"team-k.example.org", "*.team-k.example.org"} {
		if rrs := e.zone.Records(n); len(rrs) != 0 {
			t.Fatalf("%s: %v left after delete", n, rrs)
		}
	}
	// Re-enroll with a rejected token: the old work (if still running)
	// must not make the new enrollment ready or give it a certificate.
	e.do("PUT", "/domains/team-k.example.org", creds(badToken), true)
	e.waitState("team-k.example.org", StateError, 20*time.Second)
	e.svc.Wait()
	v := e.list()["team-k.example.org"]
	if v.State != StateError || v.CertNotAfter != nil || v.RecordsOK {
		t.Fatalf("new enrollment got stale results: %+v", v)
	}
	e.svc.mu.Lock()
	d := e.svc.doc.Domains["team-k.example.org"]
	gen, certPEM := d.Generation, d.CertPEM
	e.svc.mu.Unlock()
	if certPEM != "" || gen <= 1 {
		t.Fatalf("generation %d reused / certificate %v", gen, certPEM != "")
	}
	// Generations survive a restart: the next one is still new.
	doc, err := OpenStore(e.dir, e.id).Load()
	if err != nil || doc.NextGeneration < gen {
		t.Fatalf("NextGeneration %d after reload, want >= %d (%v)", doc.NextGeneration, gen, err)
	}
}

// TestZoneChangeThenDelete: the zone found for a domain changes during its
// life (e.g. the operator moves it to another hosted zone); records created
// in both zones are tracked and DELETE removes all of them.
func TestZoneChangeThenDelete(t *testing.T) {
	e := newEnv(t, false)
	zoneName := "team-l.example.org."
	var zmu sync.Mutex
	e.svc.findZone = func(string) (string, error) { zmu.Lock(); defer zmu.Unlock(); return zoneName, nil }
	other := fakedns.NewZone() // the second zone's storage (not served)
	accept := func(string) bool { return true }
	providers["fake-soa"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return zoneRouter{
			"team-l.example.org.": &fakedns.Provider{Zone: e.zone, Token: c["api_token"], Accept: accept},
			"example.org.":        &fakedns.Provider{Zone: other, Token: c["api_token"], Accept: accept},
		}, nil
	}}
	t.Cleanup(func() { delete(providers, "fake-soa") })
	body := `{"provider":"fake-soa","credentials":{"api_token":"` + goodToken + `"}}`
	e.do("PUT", "/domains/team-l.example.org", body, true)
	e.waitState("team-l.example.org", StateReady, 60*time.Second)
	// The zone moves; the records are set again there.
	zmu.Lock()
	zoneName = "example.org."
	zmu.Unlock()
	e.do("POST", "/domains/team-l.example.org/token", body, true)
	deadline := time.Now().Add(20 * time.Second)
	for {
		e.svc.mu.Lock()
		zones := len(e.svc.doc.Domains["team-l.example.org"].Records)
		e.svc.mu.Unlock()
		if zones == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("records tracked in %d zones, want 2", zones)
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.svc.Wait()
	for _, z := range []*fakedns.Zone{e.zone, other} {
		if len(z.Records("team-l.example.org")) == 0 {
			t.Fatal("setup: records missing in one of the zones")
		}
	}
	if code, body := e.do("DELETE", "/domains/team-l.example.org", "", true); code != 204 {
		t.Fatalf("delete = %d %s", code, body)
	}
	for _, z := range []*fakedns.Zone{e.zone, other} {
		for _, n := range []string{"team-l.example.org", "*.team-l.example.org"} {
			if rrs := z.Records(n); len(rrs) != 0 {
				t.Fatalf("%s: %v left after delete", n, rrs)
			}
		}
	}
}

// zoneRouter is a provider spanning several zones (no FindZone: the
// service's SOA lookup, Service.findZone, picks the zone).
type zoneRouter map[string]*fakedns.Provider

func (z zoneRouter) p(zone string) (*fakedns.Provider, error) {
	if p, ok := z[zone]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("no zone %s", zone)
}

func (z zoneRouter) SkipPropagationCheck() bool { return true }

func (z zoneRouter) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p, err := z.p(zone)
	if err != nil {
		return nil, err
	}
	return p.GetRecords(ctx, zone)
}

func (z zoneRouter) AppendRecords(ctx context.Context, zone string, r []libdns.Record) ([]libdns.Record, error) {
	p, err := z.p(zone)
	if err != nil {
		return nil, err
	}
	return p.AppendRecords(ctx, zone, r)
}

func (z zoneRouter) SetRecords(ctx context.Context, zone string, r []libdns.Record) ([]libdns.Record, error) {
	p, err := z.p(zone)
	if err != nil {
		return nil, err
	}
	return p.SetRecords(ctx, zone, r)
}

func (z zoneRouter) DeleteRecords(ctx context.Context, zone string, r []libdns.Record) ([]libdns.Record, error) {
	p, err := z.p(zone)
	if err != nil {
		return nil, err
	}
	return p.DeleteRecords(ctx, zone, r)
}

// TestUnservableNameNoWork: a stored name that breaks the rules gets an
// error and never records or an ACME order.
func TestUnservableNameNoWork(t *testing.T) {
	e := newEnv(t, false)
	e.svc.mu.Lock()
	e.svc.doc.Domains["auth."+testMain] = &Domain{Name: "auth." + testMain, Provider: "fake", Credentials: map[string]string{"api_token": goodToken}, State: StatePending, Generation: 99, EnrollID: 99}
	e.svc.mu.Unlock()
	e.svc.Kick()
	v := e.waitState("auth."+testMain, StateError, 5*time.Second)
	if !strings.Contains(v.LastError, "can't be served") {
		t.Fatalf("last_error %q", v.LastError)
	}
	time.Sleep(300 * time.Millisecond)
	if n := e.zone.CallCount(); n != 0 {
		t.Fatalf("%d provider calls for an unservable name", n)
	}
}

// TestIssuedCertUnservableBacksOff: an issued certificate the endpoint
// would refuse is not stored; the attempt fails with backoff (no loop).
func TestIssuedCertUnservableBacksOff(t *testing.T) {
	e := newEnv(t, false)
	e.clock.advance(-48 * time.Hour) // every new certificate is "not valid yet"
	e.do("PUT", "/domains/team-m.example.org", creds(goodToken), true)
	v := e.waitState("team-m.example.org", StateError, 30*time.Second)
	if !strings.Contains(v.LastError, "can't be served") || v.CertNotAfter != nil {
		t.Fatalf("view %+v", v)
	}
	e.svc.mu.Lock()
	d := e.svc.doc.Domains["team-m.example.org"]
	f, cert := d.Failures, d.CertPEM
	e.svc.mu.Unlock()
	if f != 1 || cert != "" {
		t.Fatalf("failures %d, cert stored %v", f, cert != "")
	}
	before := e.zone.CallCount()
	time.Sleep(300 * time.Millisecond)
	if e.zone.CallCount() != before {
		t.Fatal("re-issued during backoff")
	}
}

// TestRecordsWaitBounded: DELETE and token replacement wait for a running
// records step only as long as their request allows; then 503, and
// nothing changed.
func TestRecordsWaitBounded(t *testing.T) {
	e := newEnv(t, false)
	release := make(chan struct{})
	var once sync.Once
	inSet := make(chan struct{})
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		if recordsWrite(op, recs) {
			once.Do(func() { close(inSet) })
			<-release
		}
		return nil
	})
	defer close(release)
	e.do("PUT", "/domains/team-n.example.org", creds(goodToken), true)
	<-inSet
	for _, c := range []struct{ method, path, body string }{
		{"DELETE", "/domains/team-n.example.org", ""},
		{"POST", "/domains/team-n.example.org/token", creds(goodToken)},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body)).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer "+testSecret)
		rec := httptest.NewRecorder()
		e.api.ServeHTTP(rec, req)
		cancel()
		if rec.Code != 503 {
			t.Fatalf("%s while a records step hangs = %d %s", c.method, rec.Code, rec.Body)
		}
	}
	e.svc.mu.Lock()
	d := e.svc.doc.Domains["team-n.example.org"]
	gone, deleting := d == nil, d != nil && d.Deleting
	e.svc.mu.Unlock()
	if gone || deleting {
		t.Fatalf("a bounded wait changed the domain (gone %v, deleting %v)", gone, deleting)
	}
}

// TestTokenWaitsForRecordsStep: new credentials don't lose the records a
// running step creates under the old ones.
func TestTokenWaitsForRecordsStep(t *testing.T) {
	e := newEnv(t, false)
	release := make(chan struct{})
	var once sync.Once
	inSet := make(chan struct{})
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		if recordsWrite(op, recs) {
			once.Do(func() { close(inSet); <-release })
		}
		return nil
	})
	e.do("PUT", "/domains/team-o.example.org", creds(goodToken), true)
	<-inSet
	done := make(chan int)
	go func() {
		code, _ := e.do("POST", "/domains/team-o.example.org/token", creds(goodToken+"2"), true)
		done <- code
	}()
	select {
	case c := <-done:
		t.Fatalf("token returned %d while the records step ran", c)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if c := <-done; c != 202 {
		t.Fatalf("token = %d", c)
	}
	e.svc.mu.Lock()
	n := len(e.svc.doc.Domains["team-o.example.org"].Records)
	e.svc.mu.Unlock()
	if n == 0 {
		t.Fatal("records of the step under the old credentials were lost")
	}
}

// TestAddressChangeMakesRecordsDue: records set to other addresses than
// the configured ones are redone at start.
func TestAddressChangeMakesRecordsDue(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-p.example.org", creds(goodToken), true)
	e.waitState("team-p.example.org", StateReady, 60*time.Second)
	e.cancel()
	e.svc.Wait()
	cfg := e.svc.cfg
	cfg.IPv4 = netip.MustParseAddr("203.0.113.77")
	svc2, err := NewService(cfg, OpenStore(e.dir, e.id))
	if err != nil {
		t.Fatal(err)
	}
	if st := svc2.doc.Domains["team-p.example.org"].State; st != StatePending {
		t.Fatalf("state after an address change = %s", st)
	}
	cfg.IPv4 = netip.MustParseAddr("203.0.113.10")
	svc3, _ := NewService(cfg, OpenStore(e.dir, e.id))
	if st := svc3.doc.Domains["team-p.example.org"].State; st != StateReady {
		t.Fatalf("state with unchanged addresses = %s", st)
	}
}

// TestProviderPanicRecovered: a panicking provider library records a
// failure instead of killing the service.
func TestProviderPanicRecovered(t *testing.T) {
	e := newEnv(t, false)
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		if recordsWrite(op, recs) {
			panic("library bug")
		}
		return nil
	})
	e.do("PUT", "/domains/team-q.example.org", creds(goodToken), true)
	v := e.waitState("team-q.example.org", StateError, 10*time.Second)
	if !strings.Contains(v.LastError, "internal error") {
		t.Fatalf("last_error %q", v.LastError)
	}
	e.svc.mu.Lock()
	busy := e.svc.busy["team-q.example.org"]
	e.svc.mu.Unlock()
	if busy != nil {
		t.Fatal("busy left set after a panic")
	}
	// The panic hit inside the records step: the service stays usable and
	// a DELETE goes through (the slot is released in recover; the job is
	// also dropped from busy).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest("DELETE", "/domains/team-q.example.org", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	rec := httptest.NewRecorder()
	e.setHook(nil)
	e.api.ServeHTTP(rec, req)
	if rec.Code != 204 && rec.Code != 200 {
		t.Fatalf("delete after a panic = %d %s", rec.Code, rec.Body)
	}
}

func TestShortSecretRefused(t *testing.T) {
	if err := validateCredentials("cloudflare", map[string]string{"api_token": "short"}); err == nil {
		t.Fatal("a 5-character token accepted")
	}
}

// TestUnknownIPv4StillRenews: a failed public-address lookup (IPv4
// unknown) doesn't stall a domain whose records were set before: no
// address change is assumed, the records step is skipped and the
// certificate is still renewed (final review I1).
func TestUnknownIPv4StillRenews(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-u.example.org", creds(goodToken), true)
	e.waitState("team-u.example.org", StateReady, 60*time.Second)
	e.cancel()
	e.svc.Wait()
	var sets atomic.Int32
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		if recordsWrite(op, recs) {
			sets.Add(1)
		}
		return nil
	})
	cfg := e.svc.cfg
	cfg.IPv4 = netip.Addr{}
	svc2, err := NewService(cfg, OpenStore(e.dir, e.id))
	if err != nil {
		t.Fatal(err)
	}
	if st := svc2.doc.Domains["team-u.example.org"].State; st != StateReady {
		t.Fatalf("state with the IPv4 unknown = %s (no address change)", st)
	}
	first := *svc2.doc.Domains["team-u.example.org"].CertNotAfter
	e.clock.advance(61 * 24 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc2.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	svc2.Kick()
	deadline := time.Now().Add(60 * time.Second)
	for {
		svc2.mu.Lock()
		d := svc2.doc.Domains["team-u.example.org"]
		renewed := d.State == StateReady && d.CertNotAfter != nil && !d.CertNotAfter.Equal(first)
		st, last := d.State, d.LastError
		svc2.mu.Unlock()
		if renewed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("not renewed with the IPv4 unknown: %s %q\n%s", st, last, e.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := sets.Load(); n != 0 {
		t.Fatalf("records set %d times with the IPv4 unknown", n)
	}
	if !strings.Contains(e.logs.String(), "records step skipped") {
		t.Fatal("skip not logged")
	}
	if c, err := enrolledCount(e.dir, writeKey(t, e.id)); err != nil || c != 1 {
		t.Fatalf("enrolledCount = %d, %v", c, err)
	}
}

func writeKey(t *testing.T, id *age.X25519Identity) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "age.key")
	if err := os.WriteFile(p, []byte(id.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestWantAddrsFreshIPv6: with the IPv4 unknown, the records check wants
// the applied IPv4 but a configured IPv6 over the applied one.
func TestWantAddrsFreshIPv6(t *testing.T) {
	s := &Service{doc: &storeDoc{Domains: map[string]*Domain{"d.example.org": {Name: "d.example.org", AppliedIPv4: "203.0.113.10", AppliedIPv6: "2001:db8::10"}}}}
	if v4, v6 := s.wantAddrs("d.example.org"); v4.String() != "203.0.113.10" || v6.String() != "2001:db8::10" {
		t.Fatalf("applied: %v %v", v4, v6)
	}
	s.cfg.IPv6 = netip.MustParseAddr("2001:db8::99")
	if v4, v6 := s.wantAddrs("d.example.org"); v4.String() != "203.0.113.10" || v6.String() != "2001:db8::99" {
		t.Fatalf("fresh IPv6: %v %v", v4, v6)
	}
	s.cfg.IPv4 = netip.MustParseAddr("198.51.100.1")
	if v4, v6 := s.wantAddrs("d.example.org"); v4.String() != "198.51.100.1" || v6.String() != "2001:db8::99" {
		t.Fatalf("configured: %v %v", v4, v6)
	}
}

// ── record sets, CAA, DNSSEC (Task 5) ─────────────────────

// restart stops the running service and starts a new one on the same
// store with the configuration changed by mod; e.svc / e.api follow it.
func (e *testEnv) restart(mod func(*Config)) {
	e.t.Helper()
	e.cancel()
	e.svc.Wait()
	cfg := e.svc.cfg
	if mod != nil {
		mod(&cfg)
	}
	svc, err := NewService(cfg, OpenStore(e.dir, e.id))
	if err != nil {
		e.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done })
	e.svc, e.api, e.cancel = svc, svc.APIHandler(), cancel
	svc.Kick()
}

// idle: name is ready and no work runs for it (a restart now cancels
// nothing).
func (e *testEnv) idle(name string) bool {
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	d, ok := e.svc.doc.Domains[name]
	return ok && d.State == StateReady && e.svc.busy[name] == nil
}

func caaValues(z *fakedns.Zone, name string) []string {
	var out []string
	for _, rr := range z.Records(name) {
		if rr.Type == "CAA" {
			out = append(out, rr.Data)
		}
	}
	sort.Strings(out)
	return out
}

func (e *testEnv) storedURI() string {
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	return e.svc.accountURILocked()
}

func (e *testEnv) domain(name string) Domain {
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	d, ok := e.svc.doc.Domains[name]
	if !ok {
		return Domain{}
	}
	return *copyDomain(d)
}

// waitFor polls cond for up to timeout.
func (e *testEnv) waitFor(what string, timeout time.Duration, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s\nlogs:\n%s", what, e.logs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCAAWrittenAfterRegisterBeforeOrder(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-ca.example.org"
	var mu sync.Mutex
	var events []string
	caaQ, txtQ := -1, -1
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		if len(recs) == 0 {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		switch rr := recs[0].RR(); {
		case op == "append" && rr.Type == "CAA" && caaQ < 0:
			e.svc.mu.Lock()
			acct, uri := e.svc.doc.Account, e.svc.accountURILocked()
			e.svc.mu.Unlock()
			if acct == nil || uri == "" || !strings.Contains(rr.Data, "accounturi="+uri) {
				events = append(events, fmt.Sprintf("bad CAA set: account %v, uri %q, data %q", acct != nil, uri, rr.Data))
			}
			caaQ = len(e.srv.Queries())
			events = append(events, "caa")
		case op == "append" && rr.Type == "TXT" && txtQ < 0:
			txtQ = len(e.srv.Queries())
			events = append(events, "txt")
		}
		return nil
	})
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(events, ",") != "caa,txt" {
		t.Fatalf("events %v", events)
	}
	seen := false
	for _, q := range e.srv.Queries()[caaQ:txtQ] {
		if q == "CAA "+name {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("no CAA lookup between the CAA set and the first TXT append: %v", e.srv.Queries()[caaQ:txtQ])
	}
	if d := e.domain(name); d.CAAAccountURI != e.storedURI() || !d.CAAOK {
		t.Fatalf("caa_account_uri %q (account %q), caa_ok %v", d.CAAAccountURI, e.storedURI(), d.CAAOK)
	}
}

func TestAccountSwitchRepins(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-sw.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	old := e.domain(name).CAAAccountURI
	if old == "" {
		t.Fatal("no pin after ready")
	}
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	e.restart(func(c *Config) { c.Email = "other@example.org" })
	e.waitFor("the new pin", 60*time.Second, func() bool {
		d := e.domain(name)
		return d.CAAAccountURI != "" && d.CAAAccountURI != old && d.State == StateReady
	})
	uri := e.domain(name).CAAAccountURI
	if uri != e.storedURI() {
		t.Fatalf("pinned %q, account %q", uri, e.storedURI())
	}
	live := caaValues(e.zone, name)
	if len(live) != 2 {
		t.Fatalf("live CAA %v", live)
	}
	for _, v := range live {
		if !strings.Contains(v, "accounturi="+uri) || strings.Contains(v, old) {
			t.Fatalf("live CAA %v", live)
		}
	}
}

func TestWaitCAABothResolvers(t *testing.T) {
	const name = "team-wr.example.org"
	// The second resolver serves its own copy: the addresses, and the old
	// pin until the test copies the new one over.
	zone2 := fakedns.NewZone()
	old := `0 issue "pebble.test; accounturi=https://old.example/acct/1; validationmethods=dns-01"`
	for _, n := range []string{name, "*." + name} {
		zone2.Set(n, libdns.RR{Name: "@", Type: "A", Data: "203.0.113.10", TTL: time.Minute})
	}
	zone2.Set(name, append(zone2.Records(name), libdns.RR{Name: "@", Type: "CAA", Data: old},
		libdns.RR{Name: "@", Type: "CAA", Data: strings.Replace(old, "issue", "issuewild", 1)})...)
	srv2, err := fakedns.Serve(zone2, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv2.Close() })
	e := newEnvWith(t, false, func(c *Config) {
		c.Resolvers = append(c.Resolvers, srv2.Addr)
		c.RecordsWait = 20 * time.Second
	})
	var mu sync.Mutex
	var firstTXT time.Time
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		if op == "append" && len(recs) > 0 && recs[0].RR().Type == "TXT" {
			mu.Lock()
			if firstTXT.IsZero() {
				firstTXT = time.Now()
			}
			mu.Unlock()
		}
		return nil
	})
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitFor("the pin at the first resolver", 30*time.Second, func() bool { return len(caaValues(e.zone, name)) == 2 })
	time.Sleep(500 * time.Millisecond) // several CAA polls
	mu.Lock()
	early := !firstTXT.IsZero()
	mu.Unlock()
	if early {
		t.Fatal("ordered while the second resolver still showed the old pin")
	}
	copied := time.Now()
	var rrs []libdns.RR
	for _, rr := range zone2.Records(name) {
		if rr.Type != "CAA" {
			rrs = append(rrs, rr)
		}
	}
	for _, rr := range e.zone.Records(name) {
		if rr.Type == "CAA" {
			rrs = append(rrs, rr)
		}
	}
	zone2.Set(name, rrs...)
	e.waitState(name, StateReady, 60*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if firstTXT.Before(copied) {
		t.Fatalf("first TXT append %s before the second resolver saw the pin (%s)", firstTXT, copied)
	}
}

func TestDeleteRemovesCAA(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-dc.example.org"
	e.zone.Set(name, libdns.CAA{Name: "@", TTL: time.Hour, Tag: "issue", Value: "digicert.com"}.RR())
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	if live := caaValues(e.zone, name); len(live) != 3 {
		t.Fatalf("live CAA %v", live)
	}
	if code, body := e.do("DELETE", "/domains/"+name, "", true); code != 204 {
		t.Fatalf("delete = %d %s", code, body)
	}
	if live := caaValues(e.zone, name); strings.Join(live, "|") != `0 issue "digicert.com"` {
		t.Fatalf("after delete %v", live)
	}
}

func TestCAAOffRemovesOwned(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-off.example.org"
	e.zone.Set(name, libdns.CAA{Name: "@", TTL: time.Hour, Tag: "issue", Value: "digicert.com"}.RR())
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	e.restart(func(c *Config) { c.CAA = false })
	e.waitFor("the CAA removal", 30*time.Second, func() bool {
		d := e.domain(name)
		return !hasCAARefs(&d) && d.State == StateReady
	})
	if live := caaValues(e.zone, name); strings.Join(live, "|") != `0 issue "digicert.com"` {
		t.Fatalf("live %v", live)
	}
	if v := e.list()[name]; v.CAAOK || e.domain(name).CAAAccountURI != "" {
		t.Fatalf("view %+v", v)
	}
}

func TestUnknownCASkipsCAAWrite(t *testing.T) {
	e := newEnvWith(t, false, func(c *Config) { c.CAAIssuer = "" })
	const name = "team-uc.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	v := e.waitState(name, StateReady, 60*time.Second)
	if v.CertNotAfter == nil || v.CAAOK {
		t.Fatalf("view %+v", v)
	}
	if live := caaValues(e.zone, name); len(live) != 0 {
		t.Fatalf("CAA written for an unknown CA: %v", live)
	}
}

func TestViewHasCAAAndDNSSEC(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-v.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	v := e.waitState(name, StateReady, 60*time.Second)
	if !v.CAAOK || v.DNSSEC != "unsigned" {
		t.Fatalf("view %+v", v)
	}
	_, body := e.do("GET", "/domains", "", true)
	if !strings.Contains(body, `"caa_ok":true`) || !strings.Contains(body, `"dnssec":"unsigned"`) {
		t.Fatalf("body %s", body)
	}
}

func TestReadyDomainAppliesDueCAA(t *testing.T) {
	e := newEnvWith(t, false, func(c *Config) { c.CAA = false })
	const name = "team-rd.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	if live := caaValues(e.zone, name); len(live) != 0 {
		t.Fatalf("CAA with CAA off: %v", live)
	}
	first := *e.domain(name).CertNotAfter
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	pinned := func() bool {
		d := e.domain(name)
		return d.CAAAccountURI != "" && d.CAAOK && e.idle(name)
	}
	// A ready domain with a valid certificate gets its CAA, no new order.
	e.restart(func(c *Config) { c.CAA = true })
	e.waitFor("the CAA on a ready domain", 30*time.Second, pinned)
	if live := caaValues(e.zone, name); len(live) != 2 {
		t.Fatalf("live %v", live)
	}
	if !e.domain(name).CertNotAfter.Equal(first) {
		t.Fatal("a new certificate was ordered")
	}
	// Off again (removed), then on with the IPv4 unknown: the caa set
	// still applies, the address set doesn't.
	e.restart(func(c *Config) { c.CAA = false })
	e.waitFor("the removal", 30*time.Second, func() bool { d := e.domain(name); return !hasCAARefs(&d) && e.idle(name) })
	var addrSets atomic.Int32
	e.setHook(func(op string, recs []libdns.Record, _ string) error {
		for _, r := range recs {
			if t := r.RR().Type; (op == "append" || op == "delete") && (t == "A" || t == "AAAA") {
				addrSets.Add(1)
			}
		}
		return nil
	})
	e.restart(func(c *Config) { c.CAA, c.IPv4 = true, netip.Addr{} })
	e.waitFor("the CAA with the IPv4 unknown", 30*time.Second, pinned)
	if n := addrSets.Load(); n != 0 {
		t.Fatalf("address records touched %d times with the IPv4 unknown", n)
	}
	if !e.domain(name).CertNotAfter.Equal(first) {
		t.Fatal("a new certificate was ordered")
	}
}

// ── DNS API (Task 6) ──────────────────────────────────────

func (e *testEnv) planOf(path string) dnsplan.Plan {
	e.t.Helper()
	code, body := e.do("GET", path, "", true)
	if code != 200 {
		e.t.Fatalf("GET %s = %d %s", path, code, body)
	}
	var pl dnsplan.Plan
	if err := json.Unmarshal([]byte(body), &pl); err != nil {
		e.t.Fatal(err)
	}
	return pl
}

func TestPlanEndpoint(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-pl.example.org"
	if code, _ := e.do("GET", "/domains/"+name+"/dns", "", true); code != 404 {
		t.Fatalf("plan of an unknown name = %d", code)
	}
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	pl := e.planOf("/domains/" + name + "/dns?refresh=1")
	if !pl.CanWrite || pl.Name != name || !pl.CAA.WouldIssue || pl.CAA.AccountURI != e.storedURI() || pl.CAA.Issuer != "pebble.test" {
		t.Fatalf("plan %+v", pl)
	}
	found := false
	for _, it := range pl.Items {
		if it.Set == dnsplan.SetCAA && it.Status == dnsplan.StatusOK {
			found = true
		}
		if it.Set == dnsplan.SetAddress && it.Status != dnsplan.StatusOK {
			t.Errorf("address item %+v", it)
		}
	}
	if !found || pl.DNSSEC.State != "unsigned" {
		t.Fatalf("plan %+v", pl)
	}
}

func TestPlanRefreshThrottled(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-th.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	e.clock.advance(31 * time.Second)
	before := e.zone.CallCount()
	e.planOf("/domains/" + name + "/dns?refresh=1")
	e.planOf("/domains/" + name + "/dns?refresh=1")
	e.planOf("/domains/" + name + "/dns")
	if n := e.zone.CallCount() - before; n != 1 {
		t.Fatalf("%d builds (provider reads), want 1", n)
	}
	e.clock.advance(31 * time.Second)
	e.planOf("/domains/" + name + "/dns?refresh=1")
	if n := e.zone.CallCount() - before; n != 2 {
		t.Fatalf("%d builds after the window, want 2", n)
	}
}

func TestApplyEndpoint(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-ap.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	for _, body := range []string{`{"sets":["bogus"]}`, `{"sets":["nomail"],"x":1}`, `{"sets":[]}`, `{}`, `nope`} {
		if code, _ := e.do("POST", "/domains/"+name+"/dns/apply", body, true); code != 400 {
			t.Errorf("%s = %d", body, code)
		}
	}
	if code, _ := e.do("POST", "/domains/nope.example.org/dns/apply", `{"sets":["caa"]}`, true); code != 404 {
		t.Fatalf("unknown name = %d", code)
	}
	code, body := e.do("POST", "/domains/"+name+"/dns/apply", `{"sets":["nomail"]}`, true)
	if code != 202 || !strings.Contains(body, `"name":"`+name+`"`) {
		t.Fatalf("apply = %d %s", code, body)
	}
	e.waitFor("the null MX", 30*time.Second, func() bool {
		for _, rr := range e.zone.Records(name) {
			if rr.Type == "MX" && rr.Data == "0 ." {
				return true
			}
		}
		return false
	})
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	d := e.domain(name)
	if !contains(d.Sets, "nomail") || len(d.DueSets) != 0 {
		t.Fatalf("sets %v due %v", d.Sets, d.DueSets)
	}
	// DELETE removes the nomail records too.
	e.do("DELETE", "/domains/"+name, "", true)
	if rrs := e.zone.Records("_dmarc." + name); len(rrs) != 0 {
		t.Fatalf("left after delete: %v", rrs)
	}
}

func TestDNSSECEndpoint409(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-ns.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	code, body := e.do("POST", "/domains/"+name+"/dnssec", `{"enable":true}`, true)
	if code != 409 || !strings.Contains(body, "fake can't sign the zone through its API") {
		t.Fatalf("= %d %s", code, body)
	}
	for _, b := range []string{`{"enable":false}`, `{}`, `{"enable":true,"x":1}`} {
		if code, _ := e.do("POST", "/domains/"+name+"/dnssec", b, true); code != 400 {
			t.Errorf("%s = %d", b, code)
		}
	}
}

// recordingSigner counts EnableDNSSEC calls (the interface has no way to
// turn signing off).
type recordingSigner struct{ enabled *atomic.Int32 }

func (recordingSigner) DNSSECStatus(context.Context, string) (string, []dnssec.DS, error) {
	return "disabled", nil, nil
}

func (r recordingSigner) EnableDNSSEC(context.Context, string) error {
	r.enabled.Add(1)
	return nil
}

func TestDNSSECEndpointSigns(t *testing.T) {
	e := newEnv(t, false)
	var enabled atomic.Int32
	providers["fake-signer"] = providerSpec{required: []string{"api_token"}, build: providers["fake"].build,
		dnssec: func(map[string]string) (dnssec.StatusReader, error) { return recordingSigner{&enabled}, nil }}
	t.Cleanup(func() { delete(providers, "fake-signer") })
	const name = "team-sg.example.org"
	e.do("PUT", "/domains/"+name, `{"provider":"fake-signer","credentials":{"api_token":"`+goodToken+`"}}`, true)
	e.waitState(name, StateReady, 60*time.Second)
	if pl := e.planOf("/domains/" + name + "/dns?refresh=1"); !pl.DNSSEC.ProviderCanSign || len(pl.DNSSEC.Steps) == 0 {
		t.Fatalf("dnssec %+v", pl.DNSSEC)
	}
	if code, body := e.do("POST", "/domains/"+name+"/dnssec", `{"enable":true}`, true); code != 202 {
		t.Fatalf("= %d %s", code, body)
	}
	e.waitFor("EnableDNSSEC", 30*time.Second, func() bool { return enabled.Load() == 1 && !e.domain(name).SignRequested && e.idle(name) })
	time.Sleep(200 * time.Millisecond)
	if n := enabled.Load(); n != 1 {
		t.Fatalf("EnableDNSSEC called %d times", n)
	}
}

func TestMainPlanReadOnly(t *testing.T) {
	const traefik = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/42"
	e := newEnvWith(t, false, func(c *Config) { c.MainAccountURI = traefik })
	before := e.zone.CallCount()
	pl := e.planOf("/main/dns?refresh=1")
	if pl.CanWrite || pl.Name != testMain || pl.CAA.AccountURI != traefik || !pl.CAA.WouldIssue {
		t.Fatalf("main plan %+v", pl)
	}
	for _, it := range pl.Items {
		if it.Fix == dnsplan.FixAuto {
			t.Fatalf("auto fix in the main plan: %+v", it)
		}
	}
	if n := e.zone.CallCount(); n != before {
		t.Fatalf("the main plan called a provider (%d calls)", n-before)
	}
}

func TestAccountEndpoint(t *testing.T) {
	e := newEnv(t, false)
	var a map[string]string
	_, body := e.do("GET", "/acme/account", "", true)
	json.Unmarshal([]byte(body), &a)
	if a["account_uri"] != "" || a["caa_issuer"] != "pebble.test" || a["ca_server"] != e.svc.cfg.CAServer {
		t.Fatalf("before registration: %s", body)
	}
	e.do("PUT", "/domains/team-ac.example.org", creds(goodToken), true)
	e.waitState("team-ac.example.org", StateReady, 60*time.Second)
	_, body = e.do("GET", "/acme/account", "", true)
	json.Unmarshal([]byte(body), &a)
	if a["account_uri"] == "" || a["account_uri"] != e.storedURI() {
		t.Fatalf("after: %s", body)
	}
}

func TestNewEndpointsNeedBearer(t *testing.T) {
	e := newEnv(t, false)
	for _, r := range [][2]string{{"GET", "/domains/team-x.example.org/dns"}, {"POST", "/domains/team-x.example.org/dns/apply"},
		{"POST", "/domains/team-x.example.org/dnssec"}, {"GET", "/main/dns"}, {"POST", "/main/dns/refresh"}, {"GET", "/acme/account"}} {
		if code, _ := e.do(r[0], r[1], `{}`, false); code != 401 {
			t.Errorf("%s %s = %d", r[0], r[1], code)
		}
	}
}

func TestNoMailNotRecommendedForAlertSender(t *testing.T) {
	e := newEnvWith(t, false, func(c *Config) { c.MailFrom = "alerts@mx.team-al.example.org" })
	for _, n := range []string{"team-al.example.org", "team-am.example.org"} {
		e.do("PUT", "/domains/"+n, creds(goodToken), true)
	}
	for n, want := range map[string]bool{"team-al.example.org": false, "team-am.example.org": true} {
		e.waitState(n, StateReady, 60*time.Second)
		got := false
		for _, it := range e.planOf("/domains/" + n + "/dns").Items {
			if it.Set == dnsplan.SetNoMail {
				got = true
			}
		}
		if got != want {
			t.Errorf("%s: nomail recommended %v, want %v", n, got, want)
		}
	}
}

// ── review fixes (I1, I3) ─────────────────────────────────

// TestApplyCAARestoresDeletedPin (I1): on a ready domain with a current
// pin, a hand-deleted CAA comes back with POST …/dns/apply caa; the due
// set is cleared.
func TestApplyCAARestoresDeletedPin(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-rs.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	var keep []libdns.RR
	for _, rr := range e.zone.Records(name) {
		if rr.Type != "CAA" {
			keep = append(keep, rr)
		}
	}
	e.zone.Set(name, keep...)
	if code, body := e.do("POST", "/domains/"+name+"/dns/apply", `{"sets":["caa"]}`, true); code != 202 {
		t.Fatalf("apply = %d %s", code, body)
	}
	e.waitFor("the restored pin", 30*time.Second, func() bool {
		d := e.domain(name)
		return len(caaValues(e.zone, name)) == 2 && len(d.DueSets) == 0 && e.idle(name)
	})
	for _, v := range caaValues(e.zone, name) {
		if !strings.Contains(v, "accounturi="+e.storedURI()) {
			t.Fatalf("live %v", caaValues(e.zone, name))
		}
	}
}

// TestUnapplicableDueSetCleared (I1): a requested set that can't apply
// (unknown CA) is cleared and logged, not retried every tick.
func TestUnapplicableDueSetCleared(t *testing.T) {
	e := newEnvWith(t, false, func(c *Config) { c.CAAIssuer = "" })
	const name = "team-ua.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	e.do("POST", "/domains/"+name+"/dns/apply", `{"sets":["caa"]}`, true)
	e.waitFor("the due set cleared", 30*time.Second, func() bool { return len(e.domain(name).DueSets) == 0 && e.idle(name) })
	if !strings.Contains(e.logs.String(), "record set caa requested but not applicable now (unknown CA") {
		t.Fatalf("not logged:\n%s", e.logs.String())
	}
	before := e.zone.CallCount()
	time.Sleep(300 * time.Millisecond) // several ticks
	if n := e.zone.CallCount() - before; n != 0 {
		t.Fatalf("%d provider calls while nothing is due", n)
	}
}

// TestCAAOffDropsGoneRefs (I3): with CAA off, owned CAA refs that are no
// longer live (deleted by hand) are dropped; the domain isn't due forever.
func TestCAAOffDropsGoneRefs(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-gr.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	var keep []libdns.RR
	for _, rr := range e.zone.Records(name) {
		if rr.Type != "CAA" {
			keep = append(keep, rr)
		}
	}
	e.zone.Set(name, keep...)
	e.restart(func(c *Config) { c.CAA = false })
	e.waitFor("the refs dropped", 30*time.Second, func() bool { d := e.domain(name); return !hasCAARefs(&d) && e.idle(name) })
	before := e.zone.CallCount()
	time.Sleep(300 * time.Millisecond)
	if n := e.zone.CallCount() - before; n != 0 {
		t.Fatalf("%d provider calls while nothing is due", n)
	}
}

// recordsWrite: a records-step write (the sets are appended, never
// SetRecords; the DNS-01 TXT appends come later, in the order).
func recordsWrite(op string, recs []libdns.Record) bool {
	return op == "append" && len(recs) > 0 && recs[0].RR().Type != "TXT"
}

// TestMainPlanRefreshedByWorker (final review I2): the worker builds the
// main domain's plan itself and rebuilds it every RecheckEvery, so a
// reader without ?refresh=1 (domains report, status, the Hub) never gets
// a plan older than that.
func TestMainPlanRefreshedByWorker(t *testing.T) {
	e := newEnv(t, false)
	cached := func() (time.Time, bool) {
		e.svc.mu.Lock()
		defer e.svc.mu.Unlock()
		c, ok := e.svc.plans[mainPlanKey]
		return c.plan.CheckedAt, ok
	}
	e.waitFor("the worker's first main plan", 10*time.Second, func() bool { _, ok := cached(); return ok })
	first, _ := cached()
	if got := e.planOf("/main/dns").CheckedAt; !got.Equal(first) {
		t.Fatalf("GET /main/dns checked_at %v, want the worker's %v", got, first)
	}
	e.clock.advance(e.svc.cfg.RecheckEvery + time.Second)
	e.waitFor("a rebuilt main plan", 10*time.Second, func() bool { at, _ := cached(); return at.After(first) })
	if got := e.planOf("/main/dns").CheckedAt; !got.After(first) {
		t.Fatalf("GET /main/dns still answers the old plan (%v)", got)
	}
}

// TestPlanDroppedAfterFailedWrite (deploy 2026-11-13): a records step
// that wrote and then failed drops the cached plan (no plan from before
// the write until the next success; the next read rebuilds it).
func TestPlanDroppedAfterFailedWrite(t *testing.T) {
	e := newEnv(t, false)
	const name = "team-pd.example.org"
	e.do("PUT", "/domains/"+name, creds(goodToken), true)
	e.waitState(name, StateReady, 60*time.Second)
	e.waitFor("idle", 10*time.Second, func() bool { return e.idle(name) })
	cached := func() bool {
		e.svc.mu.Lock()
		defer e.svc.mu.Unlock()
		_, ok := e.svc.plans[name]
		return ok
	}
	if !cached() {
		t.Fatal("no plan cached after ready")
	}
	// A user SPF the nomail set replaces: appended, then the delete fails.
	e.zone.Set(name, append(e.zone.Records(name), libdns.TXT{Name: "@", TTL: time.Hour, Text: "v=spf1 include:mail.test -all"}.RR())...)
	e.setHook(func(op string, _ []libdns.Record, _ string) error {
		if op == "delete" {
			return errors.New("delete refused")
		}
		return nil
	})
	if code, body := e.do("POST", "/domains/"+name+"/dns/apply", `{"sets":["nomail"]}`, true); code != 202 {
		t.Fatalf("apply = %d %s", code, body)
	}
	e.waitFor("the failed step", 30*time.Second, func() bool { return e.domain(name).State == StateError })
	if cached() {
		t.Fatal("the plan from before the write is still cached")
	}
}

// TestMainPlanRefreshEndpoint (deploy 2026-11-13): after the dns tool
// writes the main domain's records, POST /main/dns/refresh drops the
// cached main plan and answers a rebuilt one; GET serves it from then on.
func TestMainPlanRefreshEndpoint(t *testing.T) {
	e := newEnv(t, false)
	e.waitFor("the worker's first main plan", 10*time.Second, func() bool {
		e.svc.mu.Lock()
		defer e.svc.mu.Unlock()
		_, ok := e.svc.plans[mainPlanKey]
		return ok
	})
	caa := func(pl dnsplan.Plan) dnsplan.Status {
		for _, it := range pl.Items {
			if it.Set == dnsplan.SetCAA && it.Type == "CAA" && it.Status != dnsplan.StatusForeign {
				return it.Status
			}
		}
		return ""
	}
	if st := caa(e.planOf("/main/dns")); st == dnsplan.StatusOK {
		t.Fatalf("main CAA %s before the write", st)
	}
	// The dns tool pins the CAA (out of process: the service can't see it).
	v := dnsplan.CAAValue("pebble.test", "")
	e.zone.Set(testMain, libdns.CAA{Name: "@", TTL: dnsplan.TTLCAA, Tag: "issue", Value: v}.RR(),
		libdns.CAA{Name: "@", TTL: dnsplan.TTLCAA, Tag: "issuewild", Value: v}.RR())
	if st := caa(e.planOf("/main/dns")); st == dnsplan.StatusOK {
		t.Fatal("GET rebuilt the main plan without a refresh (the test proves nothing)")
	}
	code, body := e.do("POST", "/main/dns/refresh", "", true)
	if code != 200 {
		t.Fatalf("refresh = %d %s", code, body)
	}
	var pl dnsplan.Plan
	if err := json.Unmarshal([]byte(body), &pl); err != nil || caa(pl) != dnsplan.StatusOK {
		t.Fatalf("refresh answered %v %s", err, body)
	}
	if st := caa(e.planOf("/main/dns")); st != dnsplan.StatusOK {
		t.Fatalf("GET after the refresh: CAA %s", st)
	}
	// Not throttled: a second write right after is seen too.
	e.zone.Set(testMain)
	if _, body := e.do("POST", "/main/dns/refresh", "", true); !strings.Contains(body, `"status":"missing"`) {
		t.Fatalf("second refresh %s", body)
	}
	if code, _ := e.do("POST", "/main/dns/refresh", "", false); code != 401 {
		t.Fatalf("no secret = %d", code)
	}
}

// TestMainPlanStaleBuildDiscarded: a main-plan build that started before
// a refresh never overwrites the refreshed plan.
func TestMainPlanStaleBuildDiscarded(t *testing.T) {
	e := newEnv(t, false)
	e.svc.mu.Lock()
	gen := e.svc.mainGen
	e.svc.mu.Unlock()
	if code, _ := e.do("POST", "/main/dns/refresh", "", true); code != 200 {
		t.Fatalf("refresh = %d", code)
	}
	e.svc.mu.Lock()
	fresh := e.svc.plans[mainPlanKey]
	e.svc.mu.Unlock()
	if e.svc.storeMainPlan(gen, dnsplan.Plan{Name: "stale"}) {
		t.Fatal("a build from before the refresh was stored")
	}
	e.svc.mu.Lock()
	defer e.svc.mu.Unlock()
	if e.svc.plans[mainPlanKey].plan.Name != fresh.plan.Name || e.svc.plans[mainPlanKey].plan.Name == "stale" {
		t.Fatalf("cached %+v", e.svc.plans[mainPlanKey].plan.Name)
	}
}

// TestMainPlanRecheckAge (deploy 2026-11-13, concern 2): the worker
// rebuilds a main plan that isn't healthy after min(RecheckEvery, 5m)
// (a negative-cached CAA clears within minutes); a healthy one only
// every RecheckEvery.
func TestMainPlanRecheckAge(t *testing.T) {
	e := newEnv(t, false)
	cached := func() (time.Time, dnsplan.Plan, bool) {
		e.svc.mu.Lock()
		defer e.svc.mu.Unlock()
		c, ok := e.svc.plans[mainPlanKey]
		return c.at, c.plan, ok
	}
	e.waitFor("the worker's first main plan", 10*time.Second, func() bool { _, _, ok := cached(); return ok })
	first, pl, _ := cached()
	if planHealthy(pl) {
		t.Fatalf("an empty zone's main plan is healthy: %+v", pl.Items)
	}
	e.clock.advance(mainRecheckUnhealthy + time.Second)
	e.waitFor("the unhealthy plan rebuilt after 5 min", 10*time.Second, func() bool { at, _, _ := cached(); return at.After(first) })

	// Healthy: the addresses and the CA-only CAA in place.
	v := dnsplan.CAAValue("pebble.test", "")
	e.zone.Set(testMain, libdns.RR{Name: "@", Type: "A", TTL: dnsplan.TTLAddress, Data: "203.0.113.10"},
		libdns.CAA{Name: "@", TTL: dnsplan.TTLCAA, Tag: "issue", Value: v}.RR(), libdns.CAA{Name: "@", TTL: dnsplan.TTLCAA, Tag: "issuewild", Value: v}.RR())
	e.zone.Set("*."+testMain, libdns.RR{Name: "*", Type: "A", TTL: dnsplan.TTLAddress, Data: "203.0.113.10"})
	if code, body := e.do("POST", "/main/dns/refresh", "", true); code != 200 {
		t.Fatalf("refresh = %d %s", code, body)
	}
	healthyAt, pl, _ := cached()
	if !planHealthy(pl) {
		t.Fatalf("main plan not healthy: %+v", pl.Items)
	}
	e.clock.advance(mainRecheckUnhealthy + time.Second)
	time.Sleep(10 * e.svc.cfg.Tick)
	if at, _, _ := cached(); !at.Equal(healthyAt) {
		t.Fatal("a healthy main plan was rebuilt before RecheckEvery")
	}
	e.clock.advance(e.svc.cfg.RecheckEvery)
	e.waitFor("the healthy plan rebuilt after RecheckEvery", 10*time.Second, func() bool { at, _, _ := cached(); return at.After(healthyAt) })
}
