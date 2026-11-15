package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/fakedns"
)

const (
	mcMain  = "portcullis.example.test"
	mcHost  = "mail.portcullis.example.test"
	mcToken = "good-TWFpbENlcnRUb2tlbjEyMzQ1Njc4"
)

// mcFixture: zone example.test on a fake DNS server, an in-process Pebble
// whose VA resolves through it, provider "fake-mc" writing into the zone,
// and empty /acme and /tls directories.
type mcFixture struct {
	t          *testing.T
	zone       *fakedns.Zone
	resolvers  []string
	pebbleURL  string
	hc         *http.Client
	acme, tls  string
	acceptGood bool
}

func newMailCertFixture(t *testing.T) *mcFixture {
	t.Helper()
	f := &mcFixture{t: t, zone: fakedns.NewZone(), acme: t.TempDir(), tls: t.TempDir()}
	f.zone.SetSOA("example.test")
	srv, err := fakedns.Serve(f.zone, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	f.resolvers = []string{srv.Addr}
	plog := log.New(io.Discard, "", 0)
	pdb := db.NewMemoryStore()
	pca := ca.New(plog, pdb, "", "ecdsa", 0, 1, map[string]ca.Profile{"default": {Description: "test", ValidityPeriod: 90 * 24 * 3600}})
	pva := va.New(plog, 0, 0, false, srv.Addr, pdb)
	pwfe := wfe.New(plog, pdb, pva, pca, []string{"pebble.letsencrypt.org"}, false, false, 1, 1)
	pebble := httptest.NewTLSServer(pwfe.Handler())
	t.Cleanup(pebble.Close)
	f.pebbleURL, f.hc = pebble.URL+wfe.DirectoryPath, pebble.Client()
	providers["fake-mc"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return &fakedns.Provider{Zone: f.zone, Token: c["api_token"], ZoneName: "example.test",
			Accept: func(tok string) bool { return strings.HasPrefix(tok, "good-") }}, nil
	}}
	t.Cleanup(func() { delete(providers, "fake-mc") })
	return f
}

func (f *mcFixture) input(mod func(m map[string]any)) string {
	m := map[string]any{"hostname": mcHost, "ca_server": f.pebbleURL, "email": "ci@example.test", "provider": "fake-mc",
		"credentials": map[string]string{"api_token": mcToken}, "caa": map[string]any{"enabled": true, "issuer": "pebble.test", "iodef": ""},
		"renew_below_days": 30}
	if mod != nil {
		mod(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (f *mcFixture) run(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runMailCert(args, toolEnv{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, resolvers: f.resolvers,
		acmeDir: f.acme, tlsDir: f.tls, acmeHTTPClient: f.hc, caaWait: 5 * time.Second, caaPoll: 50 * time.Millisecond,
		propTimeout: 30 * time.Second, propInterval: 50 * time.Millisecond})
	if strings.Contains(out.String()+errb.String(), mcToken) || strings.Contains(out.String()+errb.String(), mcToken[5:]) {
		f.t.Fatalf("a credential was printed: %s %s", out.String(), errb.String())
	}
	return code, out.String(), errb.String()
}

type mcOut struct {
	Renewed  bool   `json:"renewed"`
	NotAfter string `json:"not_after"`
	SPKI     string `json:"spki_sha256"`
}

// issue runs mail-cert and decodes its line (exit 0 expected).
func (f *mcFixture) issue(args []string, stdin string) mcOut {
	f.t.Helper()
	code, out, errs := f.run(args, stdin)
	var o mcOut
	if code != exitOK || json.Unmarshal([]byte(out), &o) != nil || strings.Count(out, "\n") != 1 {
		f.t.Fatalf("mail-cert %v = %d %q %s", args, code, out, errs)
	}
	return o
}

func (f *mcFixture) leaf() *x509.Certificate {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.tls, "fullchain.pem"))
	if err != nil {
		f.t.Fatal(err)
	}
	l, err := parseLeaf(string(b))
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

func spkiOf(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func (f *mcFixture) accountURI() string {
	f.t.Helper()
	b, err := os.ReadFile(filepath.Join(f.acme, "account.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	var a Account
	if err := json.Unmarshal(b, &a); err != nil {
		f.t.Fatal(err)
	}
	u, err := accountUser(&a)
	if err != nil {
		f.t.Fatal(err)
	}
	return u.reg.URI
}

func TestMailCertIssuesAndReusesKey(t *testing.T) {
	f := newMailCertFixture(t)
	o := f.issue(nil, f.input(nil))
	l := f.leaf()
	if !o.Renewed || o.SPKI != spkiOf(l) || len(l.DNSNames) != 1 || l.DNSNames[0] != mcHost {
		t.Fatalf("first issue %+v, SANs %v", o, l.DNSNames)
	}
	if na, err := time.Parse(time.RFC3339, o.NotAfter); err != nil || !na.Equal(l.NotAfter.UTC().Truncate(time.Second)) {
		t.Fatalf("not_after %q vs %s", o.NotAfter, l.NotAfter)
	}
	for p, want := range map[string]os.FileMode{filepath.Join(f.tls, "fullchain.pem"): 0o640, filepath.Join(f.tls, "privkey.pem"): 0o640,
		filepath.Join(f.acme, "account.json"): 0o600, filepath.Join(f.acme, "mail.key"): 0o600} {
		if m := mode(t, p); m != want {
			t.Errorf("%s mode %o, want %o", p, m, want)
		}
	}
	uri := f.accountURI()
	// A forced renewal (renew below more days than are left): same key.
	o2 := f.issue(nil, f.input(func(m map[string]any) { m["renew_below_days"] = 120 }))
	l2 := f.leaf()
	if !o2.Renewed || o2.SPKI != o.SPKI || l2.SerialNumber.Cmp(l.SerialNumber) == 0 {
		t.Fatalf("renewal %+v (serial %s → %s)", o2, l.SerialNumber, l2.SerialNumber)
	}
	if f.accountURI() != uri {
		t.Fatal("the ACME account wasn't reused")
	}
	// privkey.pem is the reused key.
	kb, _ := os.ReadFile(filepath.Join(f.tls, "privkey.pem"))
	k, err := parseKeyPEM(kb)
	if err != nil {
		t.Fatal(err)
	}
	if spkiOfKey(t, k) != o.SPKI {
		t.Fatal("privkey.pem isn't the reused key")
	}
}

func spkiOfKey(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

func TestMailCertWritesCAAAtHost(t *testing.T) {
	f := newMailCertFixture(t)
	mainCAA := libdns.CAA{Name: "portcullis", TTL: 300 * time.Second, Tag: "issue", Value: "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1; validationmethods=dns-01"}.RR()
	f.zone.Set(mcMain, mainCAA)
	f.issue(nil, f.input(nil))
	want := `0 issue "pebble.test; accounturi=` + f.accountURI() + `; validationmethods=dns-01"`
	var got []string
	for _, rr := range f.zone.Records(mcHost) {
		if rr.Type == "CAA" {
			got = append(got, rr.Data)
			if rr.TTL != 300*time.Second {
				t.Errorf("CAA TTL %s", rr.TTL)
			}
		}
	}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("CAA at %s = %v, want [%s]", mcHost, got, want)
	}
	if rrs := f.zone.Records(mcMain); len(rrs) != 1 || rrs[0] != mainCAA {
		t.Fatalf("the main domain's CAA changed: %v", rrs)
	}
	// CAA off: our pin at the host goes; nothing else is touched.
	f.issue(nil, f.input(func(m map[string]any) {
		m["caa"] = map[string]any{"enabled": false, "issuer": "pebble.test", "iodef": ""}
	}))
	for _, rr := range f.zone.Records(mcHost) {
		if rr.Type == "CAA" {
			t.Fatalf("CAA left with caa off: %v", rr)
		}
	}
	if rrs := f.zone.Records(mcMain); len(rrs) != 1 {
		t.Fatalf("the main domain's CAA changed: %v", rrs)
	}
}

// selfSignedFor writes a self-signed chain for name with key k into dir.
func selfSignedFor(t *testing.T, name string, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(80 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMailCertRefusesWrongSANs(t *testing.T) {
	f := newMailCertFixture(t)
	// An existing chain for another name (with the reused key) is replaced.
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeKeyFile(filepath.Join(f.acme, "mail.key"), k); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(f.tls, "fullchain.pem"), selfSignedFor(t, "other.example.test", k), 0o640)
	os.WriteFile(filepath.Join(f.tls, "privkey.pem"), keyPEM(t, k), 0o640)
	o := f.issue(nil, f.input(nil))
	if l := f.leaf(); !o.Renewed || len(l.DNSNames) != 1 || l.DNSNames[0] != mcHost || o.SPKI != spkiOfKey(t, k) {
		t.Fatalf("replaced: %+v %v", o, l.DNSNames)
	}
	chain, _ := os.ReadFile(filepath.Join(f.tls, "fullchain.pem"))
	priv, _ := os.ReadFile(filepath.Join(f.tls, "privkey.pem"))
	// A fresh chain whose SAN isn't the hostname, or whose key isn't the
	// reused one, is refused: the old files stay.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for what, res := range map[string]*certificate.Resource{
		"wrong SAN": {Certificate: selfSignedFor(t, "evil.example.test", k)},
		"wrong key": {Certificate: selfSignedFor(t, mcHost, other)},
	} {
		old := mailCertObtain
		mailCertObtain = func(*lego.Client, certificate.ObtainRequest) (*certificate.Resource, error) { return res, nil }
		code, out, errs := f.run(nil, f.input(func(m map[string]any) { m["renew_below_days"] = 120 }))
		mailCertObtain = old
		if code != exitProblem || out != "" || !strings.Contains(errs, "refused") {
			t.Errorf("%s: = %d %q %s", what, code, out, errs)
		}
		c2, _ := os.ReadFile(filepath.Join(f.tls, "fullchain.pem"))
		p2, _ := os.ReadFile(filepath.Join(f.tls, "privkey.pem"))
		if !bytes.Equal(c2, chain) || !bytes.Equal(p2, priv) {
			t.Errorf("%s: the old files changed", what)
		}
	}
}

func keyPEM(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := encodeKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMailCertNoRenewAbove30Days(t *testing.T) {
	f := newMailCertFixture(t)
	o := f.issue(nil, f.input(nil))
	before, _ := os.ReadFile(filepath.Join(f.tls, "fullchain.pem"))
	o2 := f.issue(nil, f.input(nil))
	after, _ := os.ReadFile(filepath.Join(f.tls, "fullchain.pem"))
	if o2.Renewed || o2.NotAfter != o.NotAfter || o2.SPKI != o.SPKI || !bytes.Equal(before, after) {
		t.Fatalf("second run %+v (first %+v), chain changed %v", o2, o, !bytes.Equal(before, after))
	}
}

func TestMailCertNextKey(t *testing.T) {
	f := newMailCertFixture(t)
	cur := f.issue(nil, f.input(nil))
	n1 := f.issue([]string{"--next-key"}, "")
	n2 := f.issue([]string{"--next-key"}, "")
	if n1.SPKI == "" || n1.SPKI == cur.SPKI || n2.SPKI != n1.SPKI || n1.Renewed {
		t.Fatalf("next keys %+v %+v (current %s)", n1, n2, cur.SPKI)
	}
	if m := mode(t, filepath.Join(f.acme, "mail.next.key")); m != 0o600 {
		t.Fatalf("mail.next.key mode %o", m)
	}
	// A normal run keeps the current key.
	if o := f.issue(nil, f.input(func(m map[string]any) { m["renew_below_days"] = 120 })); o.SPKI != cur.SPKI {
		t.Fatalf("the next key was used before --switch-key: %+v", o)
	}
	sw := f.issue([]string{"--switch-key"}, f.input(nil))
	if !sw.Renewed || sw.SPKI != n1.SPKI || spkiOf(f.leaf()) != n1.SPKI {
		t.Fatalf("switch %+v", sw)
	}
	if _, err := os.Stat(filepath.Join(f.acme, "mail.next.key")); !os.IsNotExist(err) {
		t.Fatalf("mail.next.key left: %v", err)
	}
	if o := f.issue(nil, f.input(nil)); o.Renewed || o.SPKI != n1.SPKI {
		t.Fatalf("after the switch %+v", o)
	}
	if code, _, errs := f.run([]string{"--switch-key"}, f.input(nil)); code != exitProblem || !strings.Contains(errs, "--next-key") {
		t.Fatalf("--switch-key without a next key = %d %s", code, errs)
	}
}

func TestMailCertStdinRefusesUnknownKey(t *testing.T) {
	f := newMailCertFixture(t)
	for what, in := range map[string]string{
		"unknown key": f.input(func(m map[string]any) { m["extra"] = 1 }),
		"trailing":    f.input(nil) + "{}",
		"too big":     f.input(func(m map[string]any) { m["email"] = strings.Repeat("x", 70<<10) }),
		"days":        f.input(func(m map[string]any) { m["renew_below_days"] = 0 }),
		"hostname":    f.input(func(m map[string]any) { m["hostname"] = "not a host" }),
		"provider":    f.input(func(m map[string]any) { m["provider"] = "nope" }),
		"ca_server":   f.input(func(m map[string]any) { m["ca_server"] = "http://ca.example.test/directory" }),
	} {
		if code, out, errs := f.run(nil, in); code != exitUsage || out != "" {
			t.Errorf("%s: = %d %q %s", what, code, out, errs)
		}
	}
	if code, _, _ := f.run([]string{"--bogus"}, f.input(nil)); code != exitUsage {
		t.Errorf("unknown argument = %d", code)
	}
	// A rejected token is a provider failure (3), redacted.
	code, out, errs := f.run(nil, f.input(func(m map[string]any) {
		m["credentials"] = map[string]string{"api_token": "bad-TWFpbENlcnRCYWRUb2tlbjk4NzY1"}
	}))
	if code != exitFailure || out != "" || strings.Contains(errs, "TWFpbENlcnRCYWRUb2tlbjk4NzY1") {
		t.Fatalf("bad token = %d %q %s", code, out, errs)
	}
	for _, n := range []string{"fullchain.pem", "privkey.pem"} {
		if _, err := os.Stat(filepath.Join(f.tls, n)); !os.IsNotExist(err) {
			t.Errorf("%s written: %v", n, err)
		}
	}
}
