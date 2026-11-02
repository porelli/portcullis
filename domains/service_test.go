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
	"testing"
	"time"

	"filippo.io/age"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/libdns/libdns"

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
	logs   *syncBuf
	clock  *clock
	dir    string
	id     *age.X25519Identity
	cancel context.CancelFunc
	bodies []string // every API response body (checked for credentials)
}

// newEnv starts the fake DNS zone and server, an in-process Pebble whose
// VA resolves through it, and the service with a running worker.
func newEnv(t *testing.T, ipv6 bool) *testEnv {
	t.Helper()
	zone := fakedns.NewZone()
	dnsSrv, err := fakedns.Serve(zone, "127.0.0.1:0")
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

	providers["fake"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) dnsProvider {
		return &fakedns.Provider{Zone: zone, Token: c["api_token"], Accept: func(tok string) bool { return strings.HasPrefix(tok, "good-") }}
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
	}
	if ipv6 {
		cfg.IPv6 = netip.MustParseAddr("2001:db8::10")
	}
	svc, err := NewService(cfg, OpenStore(dir, id))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	e := &testEnv{t: t, svc: svc, api: svc.APIHandler(), zone: zone, logs: logs, clock: clk, dir: dir, id: id, cancel: cancel}
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
			got = append(got, rr.Type+" "+rr.Data+" "+rr.TTL.String())
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
		if rrs := e.zone.Records(n); len(rrs) != 1 || rrs[0].Type != "A" || rrs[0].Data != "203.0.113.10" {
			t.Errorf("%s: %v, want only A 203.0.113.10", n, rrs)
		}
	}
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
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "x"},
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
	if len(dropped) != 11 {
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
	if err := validateCredentials("route53", map[string]string{"access_key_id": "a", "secret_access_key": "b"}); err != nil {
		t.Fatalf("route53 without hosted_zone_id: %v", err)
	}
	if err := validateCredentials("route53", map[string]string{"access_key_id": "a", "secret_access_key": "b", "hosted_zone_id": "Z1"}); err != nil {
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
