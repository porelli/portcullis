package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// fakeCA is a test CA: a key and its certificate.
type fakeCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

var testSerial struct {
	sync.Mutex
	n int64
}

func nextSerial() *big.Int {
	testSerial.Lock()
	defer testSerial.Unlock()
	testSerial.n++
	return big.NewInt(0x10000 + testSerial.n)
}

// newFakeCA makes a CA named cn, signed by parent (nil = self-signed).
func newFakeCA(t *testing.T, cn string, parent *fakeCA) *fakeCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &fakeCA{key: key, cert: c}
}

// leaf issues a client certificate for cn with pub's key.
func (ca *fakeCA) leaf(t *testing.T, cn string, pub *ecdsa.PublicKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func pemCert(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

type fakeIssued struct {
	cert       *x509.Certificate
	revoked    bool
	unreadable bool
}

// fakePKI is a Vault with the root, pki_int and pki_file: AppRole login,
// sign (refusing every parameter but csr / common_name / ttl, like
// enroll's policy), certs list, cert reads, revoke and crl/rotate. calls
// records "METHOD mount/path" for everything but the login.
type fakePKI struct {
	t    *testing.T
	root *fakeCA
	cas  map[string]*fakeCA

	mu         sync.Mutex
	certs      map[string]map[string]*fakeIssued
	order      map[string][]string
	calls      []string
	signs      []map[string]any
	failRotate bool
	signDelay  time.Duration
	// swapKey makes sign certify a fresh key instead of the CSR's.
	swapKey bool
}

func newFakePKI(t *testing.T) (*fakePKI, *Config) {
	t.Helper()
	root := newFakeCA(t, "example.org Root CA", nil)
	fp := &fakePKI{
		t: t, root: root,
		cas: map[string]*fakeCA{
			mountYubiKey: newFakeCA(t, "example.org Intermediate CA", root),
			mountBrowser: newFakeCA(t, "example.org Browser Certificate CA", root),
		},
		certs: map[string]map[string]*fakeIssued{mountYubiKey: {}, mountBrowser: {}},
		order: map[string][]string{},
	}
	srv := httptest.NewServer(http.HandlerFunc(fp.serve))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "role-id"), []byte("role"), 0o600)
	os.WriteFile(filepath.Join(dir, "secret-id"), []byte("secret"), 0o600)
	cfg := &Config{
		VaultAddr: srv.URL,
		vault:     newVaultAuth(srv.URL, "approle", filepath.Join(dir, "role-id"), filepath.Join(dir, "secret-id")),
		CertTTL:   "720h",
		PKIRole:   "client-cert",
		lookupUser: func(u string) (*User, error) {
			switch u {
			case "alice", "bob":
				return &User{Username: u, Email: u + "@example.org"}, nil
			case "ldapdown":
				return nil, errors.New("ldap dial: refused")
			}
			return nil, errNoUser
		},
	}
	return fp, cfg
}

// add stores a certificate on mount as if Vault had issued it.
func (fp *fakePKI) add(mount string, c *x509.Certificate, revoked bool) string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	s := vaultSerial(c.SerialNumber)
	fp.certs[mount][s] = &fakeIssued{cert: c, revoked: revoked}
	fp.order[mount] = append(fp.order[mount], s)
	return s
}

// issue makes and stores a mount leaf for cn (a fresh key unless pub).
func (fp *fakePKI) issue(mount, cn string, pub *ecdsa.PublicKey, notAfter time.Time, revoked bool) (*x509.Certificate, string) {
	if pub == nil {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &k.PublicKey
	}
	c := fp.cas[mount].leaf(fp.t, cn, pub, time.Now().Add(-48*time.Hour), notAfter)
	return c, fp.add(mount, c, revoked)
}

func (fp *fakePKI) callList() []string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return append([]string(nil), fp.calls...)
}

func (fp *fakePKI) has(call string) bool {
	for _, c := range fp.callList() {
		if c == call {
			return true
		}
	}
	return false
}

func (fp *fakePKI) count(prefix string) int {
	n := 0
	for _, c := range fp.callList() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func vaultAnswer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (fp *fakePKI) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/auth/approle/login" {
		vaultAnswer(w, 200, map[string]any{"auth": map[string]any{"client_token": "tok", "lease_duration": 3600}})
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	mount, rest, _ := strings.Cut(p, "/")
	method := r.Method
	if method == http.MethodGet && r.URL.Query().Get("list") == "true" {
		method = "LIST"
	}
	fp.mu.Lock()
	fp.calls = append(fp.calls, method+" "+p)
	fp.mu.Unlock()
	ca := fp.cas[mount]
	if ca == nil {
		fp.t.Errorf("fake vault: unexpected mount %s %s", method, p)
		vaultAnswer(w, 404, map[string]any{"errors": []string{}})
		return
	}
	switch {
	case strings.HasPrefix(rest, "sign/") && (method == http.MethodPut || method == http.MethodPost):
		fp.sign(w, r, mount, ca)
	case rest == "certs" && method == "LIST":
		fp.mu.Lock()
		keys := append([]string{}, fp.order[mount]...)
		fp.mu.Unlock()
		vaultAnswer(w, 200, map[string]any{"data": map[string]any{"keys": keys}})
	case rest == "cert/ca" && method == http.MethodGet:
		vaultAnswer(w, 200, map[string]any{"data": map[string]any{"certificate": pemCert(ca.cert)}})
	case strings.HasPrefix(rest, "cert/") && method == http.MethodGet:
		fp.mu.Lock()
		ic := fp.certs[mount][strings.TrimPrefix(rest, "cert/")]
		var data map[string]any
		if ic != nil && !ic.unreadable {
			rt := 0
			if ic.revoked {
				rt = 1767225600
			}
			data = map[string]any{"certificate": pemCert(ic.cert), "revocation_time": rt}
		}
		fp.mu.Unlock()
		switch {
		case ic == nil:
			vaultAnswer(w, 404, map[string]any{"errors": []string{}})
		case ic.unreadable:
			vaultAnswer(w, 500, map[string]any{"errors": []string{"internal error"}})
		default:
			vaultAnswer(w, 200, map[string]any{"data": data})
		}
	case rest == "revoke" && (method == http.MethodPut || method == http.MethodPost):
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		s, _ := body["serial_number"].(string)
		fp.mu.Lock()
		ic := fp.certs[mount][s]
		if ic != nil {
			ic.revoked = true
		}
		fp.mu.Unlock()
		if ic == nil {
			vaultAnswer(w, 400, map[string]any{"errors": []string{"no such serial"}})
			return
		}
		vaultAnswer(w, 200, map[string]any{"data": map[string]any{"revocation_time": 1767225600}})
	case rest == "crl/rotate" && method == http.MethodGet:
		fp.mu.Lock()
		fail := fp.failRotate
		fp.mu.Unlock()
		if fail {
			vaultAnswer(w, 500, map[string]any{"errors": []string{"rotate failed"}})
			return
		}
		vaultAnswer(w, 200, map[string]any{"data": map[string]any{"success": true}})
	default:
		fp.t.Errorf("fake vault: unexpected request %s %s", method, p)
		vaultAnswer(w, 404, map[string]any{"errors": []string{}})
	}
}

func (fp *fakePKI) sign(w http.ResponseWriter, r *http.Request, mount string, ca *fakeCA) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		vaultAnswer(w, 400, map[string]any{"errors": []string{"bad body"}})
		return
	}
	fp.mu.Lock()
	fp.signs = append(fp.signs, body)
	delay, swap := fp.signDelay, fp.swapKey
	fp.mu.Unlock()
	for k := range body {
		if k != "csr" && k != "common_name" && k != "ttl" {
			vaultAnswer(w, 403, map[string]any{"errors": []string{"permission denied: " + k}})
			return
		}
	}
	csrPEM, _ := body["csr"].(string)
	cn, _ := body["common_name"].(string)
	ttl, err := parseVaultDuration(body["ttl"].(string))
	b, _ := pem.Decode([]byte(csrPEM))
	if err != nil || b == nil {
		vaultAnswer(w, 400, map[string]any{"errors": []string{"bad csr or ttl"}})
		return
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		vaultAnswer(w, 400, map[string]any{"errors": []string{"bad csr"}})
		return
	}
	time.Sleep(delay)
	pub := csr.PublicKey.(*ecdsa.PublicKey)
	if swap {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &k.PublicKey
	}
	c := ca.leaf(fp.t, cn, pub, time.Now().Add(-time.Minute), time.Now().Add(ttl))
	s := fp.add(mount, c, false)
	vaultAnswer(w, 200, map[string]any{"data": map[string]any{
		"certificate": pemCert(c), "issuing_ca": pemCert(ca.cert),
		"ca_chain":      []string{pemCert(ca.cert), pemCert(fp.root.cert)},
		"serial_number": s,
	}})
}

// syncBuffer collects log output from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return buf
}

func statusOf(err error) int {
	var oe *opError
	if errors.As(err, &oe) {
		return oe.status
	}
	return 0
}

var hubFilename = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,200}\.p12$`)
var hubPassword = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$`)

func TestBrowserCertP12Decodes(t *testing.T) {
	fp, cfg := newFakePKI(t)
	res, err := cfg.issueBrowserCert(context.Background(), "alice", 30, 30, 3)
	if err != nil {
		t.Fatal(err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(res.P12, res.Password)
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	ek, ok := key.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		t.Fatalf("key is %T, want an EC P-256 key", key)
	}
	if !ek.PublicKey.Equal(leaf.PublicKey) {
		t.Error("the key doesn't match the leaf")
	}
	if leaf.Subject.CommonName != "alice" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	browserCA := fp.cas[mountBrowser].cert
	if !issuedBy(leaf, browserCA) {
		t.Error("the leaf isn't issued by the browser CA")
	}
	if len(chain) != 2 || !chain[0].Equal(browserCA) || !chain[1].Equal(fp.root.cert) {
		t.Errorf("chain = %d certificates, want [browser CA, root]", len(chain))
	}
	if res.Serial != vaultSerial(leaf.SerialNumber) || !res.NotAfter.Equal(leaf.NotAfter.UTC()) {
		t.Errorf("serial %q / not_after %v don't match the leaf", res.Serial, res.NotAfter)
	}
	want := "alice-browser-certificate-" + time.Now().UTC().Format("20060102") + ".p12"
	if res.Filename != want || !hubFilename.MatchString(res.Filename) {
		t.Errorf("filename = %q, want %q", res.Filename, want)
	}
	if !hubPassword.MatchString(res.Password) {
		t.Errorf("password %q has the wrong shape", res.Password)
	}
	if len(fp.signs) != 1 {
		t.Fatalf("signs = %d", len(fp.signs))
	}
	s := fp.signs[0]
	if !fp.has("PUT pki_file/sign/browser-cert") || s["common_name"] != "alice" || s["ttl"] != "720h" || len(s) != 3 {
		t.Errorf("sign request = %v (calls %v)", s, fp.callList())
	}
	if fp.count("PUT pki_int/") != 0 {
		t.Error("a browser certificate touched pki_int")
	}
	// The key never went to Vault: the CSR carries only the public key.
	b, _ := pem.Decode([]byte(s["csr"].(string)))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		t.Error("the sign request carries no CSR")
	}
	res.clear()
	if res.P12 != nil || res.Password != "" {
		t.Error("clear left the secrets")
	}
}

func TestBrowserCertPasswordShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		p, err := newBrowserPassword()
		if err != nil {
			t.Fatal(err)
		}
		if !hubPassword.MatchString(p) {
			t.Fatalf("password %q has the wrong shape", p)
		}
		if seen[p] {
			t.Fatalf("password %q drawn twice", p)
		}
		seen[p] = true
	}
}

func TestBrowserCertTTLCeiling(t *testing.T) {
	fp, cfg := newFakePKI(t)
	ctx := context.Background()
	for _, c := range []struct {
		name                           string
		ttl                            string
		days, maxDays, maxActive, want int
	}{
		{"above max_days", "720h", 31, 30, 3, 400},
		{"above CERT_TTL", "720h", 31, 365, 3, 400},
		{"above CERT_TTL in days", "30d", 31, 0, 3, 400},
		{"zero days", "720h", 0, 30, 3, 400},
		{"negative days", "720h", -1, 30, 3, 400},
		{"negative max_days", "720h", 1, -1, 3, 400},
		{"max_active too high", "720h", 1, 30, 21, 400},
	} {
		cfg.CertTTL = c.ttl
		_, err := cfg.issueBrowserCert(ctx, "alice", c.days, c.maxDays, c.maxActive)
		if got := statusOf(err); got != c.want {
			t.Errorf("%s: status %d (%v), want %d", c.name, got, err, c.want)
		}
	}
	if len(fp.callList()) != 0 {
		t.Errorf("Vault called for refused days: %v", fp.callList())
	}
	// At the ceiling it works; unknown users are 404, LDAP down is an error.
	cfg.CertTTL = "720h"
	if _, err := cfg.issueBrowserCert(ctx, "alice", 30, 30, 0); err != nil {
		t.Errorf("30 days: %v", err)
	}
	if _, err := cfg.issueBrowserCert(ctx, "nobody", 1, 30, 3); statusOf(err) != 404 {
		t.Errorf("unknown user: %v", err)
	}
	if _, err := cfg.issueBrowserCert(ctx, "ldapdown", 1, 30, 3); err == nil || statusOf(err) != 0 {
		t.Errorf("ldap down: %v", err)
	}
}

func TestBrowserCertMaxActive(t *testing.T) {
	fp, cfg := newFakePKI(t)
	ctx := context.Background()
	future := time.Now().Add(10 * 24 * time.Hour)
	fp.issue(mountBrowser, "alice", nil, future, false)
	fp.issue(mountBrowser, "alice", nil, future, false)
	fp.issue(mountBrowser, "alice", nil, future, true)                        // revoked: not counted
	fp.issue(mountBrowser, "alice", nil, time.Now().Add(-time.Minute), false) // expired: not counted
	fp.issue(mountBrowser, "bob", nil, future, false)                         // someone else's
	fp.issue(mountYubiKey, "alice", nil, future, false)                       // a YubiKey certificate
	if _, err := cfg.issueBrowserCert(ctx, "alice", 7, 30, 3); err != nil {
		t.Fatalf("third active: %v", err)
	}
	_, err := cfg.issueBrowserCert(ctx, "alice", 7, 30, 3)
	if statusOf(err) != 409 || err.Error() != "you already have 3 browser certificates, the most allowed: revoke one first" {
		t.Fatalf("fourth: %v", err)
	}
	// One unreadable certificate fails closed (never a guessed count).
	_, s := fp.issue(mountBrowser, "carol", nil, future, false)
	fp.certs[mountBrowser][s].unreadable = true
	if _, err := cfg.issueBrowserCert(ctx, "bob", 7, 30, 3); err == nil || statusOf(err) != 0 {
		t.Errorf("unreadable certificate: %v", err)
	}
}

// browserService is an inviteService wired to cfg's operations.
func browserService(t *testing.T, cfg *Config) *inviteService {
	t.Helper()
	s, _ := testInvites(t)
	s.listCertificates = cfg.issuedCerts
	s.issueBrowser = cfg.issueBrowserCert
	s.issueYubiKey = cfg.issueYubiKeyCert
	s.renewYubiKey = cfg.renewYubiKeyCert
	s.revoke = cfg.revokeCert
	return s
}

func postAction(s *inviteService, path, body string) *httptest.ResponseRecorder {
	return do(s.apiHandler(false), "POST", path, body, map[string]string{
		"Authorization": "Bearer " + testAPISecret, "Content-Type": "application/json",
	})
}

func TestBrowserCertMaxActiveConcurrent(t *testing.T) {
	fp, cfg := newFakePKI(t)
	fp.signDelay = 20 * time.Millisecond // widen the window between count and sign
	s := browserService(t, cfg)
	var wg sync.WaitGroup
	codes := make(chan int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := postAction(s, "/internal/browser-certificates", `{"user":"alice","days":5,"max_days":30,"max_active":3}`)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for c := range codes {
		got[c]++
	}
	if got[201] != 3 || got[409] != 7 {
		t.Errorf("answers = %v, want 3×201 and 7×409", got)
	}
	if n := len(fp.order[mountBrowser]); n != 3 {
		t.Errorf("%d browser certificates issued, want 3", n)
	}
}

func TestBrowserCertSecretsNeverLogged(t *testing.T) {
	_, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	logs := captureLog(t)
	w := postAction(s, "/internal/browser-certificates", `{"user":"alice","days":5,"max_days":30,"max_active":3}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("headers %v", w.Header())
	}
	var doc struct {
		P12      []byte    `json:"p12"`
		Password string    `json:"password"`
		Serial   string    `json:"serial"`
		NotAfter time.Time `json:"not_after"`
		Filename string    `json:"filename"`
	}
	strictDecode(t, w.Body.Bytes(), &doc)
	key, _, _, err := pkcs12.DecodeChain(doc.P12, doc.Password)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	ecDER, _ := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	out := logs.String()
	if !strings.Contains(out, "browser certificate "+doc.Serial+" for alice") {
		t.Errorf("log lacks the serial line:\n%s", out)
	}
	p12b64 := base64.StdEncoding.EncodeToString(doc.P12)
	for name, secret := range map[string]string{
		"password":       doc.Password,
		"p12 (base64)":   p12b64[:40],
		"p12 (raw)":      string(doc.P12[:32]),
		"key (pkcs8)":    base64.StdEncoding.EncodeToString(der)[:40],
		"key (sec1)":     base64.StdEncoding.EncodeToString(ecDER)[:40],
		"key (url b64)":  base64.RawURLEncoding.EncodeToString(ecDER)[:40],
		"private key":    "PRIVATE KEY",
		"csr":            "CERTIFICATE REQUEST",
		"pem of the p12": "BEGIN",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("the log carries the %s", name)
		}
	}
}

// strictDecode decodes data like the Hub (no unknown fields, nothing after).
func strictDecode(t *testing.T, data []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("strict decode of %s: %v", data, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("trailing data after the answer: %v", err)
	}
}

func TestParseVaultDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"720h": 720 * time.Hour, "30d": 720 * time.Hour, "60": time.Minute, "5m": 5 * time.Minute} {
		if got, err := parseVaultDuration(in); err != nil || got != want {
			t.Errorf("%q = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "1h30m", "-1h", "1w", "99999999999999999999d"} {
		if _, err := parseVaultDuration(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestBrowserFilename(t *testing.T) {
	day := time.Date(2026, 11, 11, 23, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"alice":      "alice-browser-certificate-20261111.p12",
		"Bob.Smith":  "bob.smith-browser-certificate-20261111.p12",
		"_x":         "user_x-browser-certificate-20261111.p12",
		"al ice/../": "al-ice-..--browser-certificate-20261111.p12",
	} {
		got := browserFilename(in, day)
		if got != want || !hubFilename.MatchString(got) {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}
