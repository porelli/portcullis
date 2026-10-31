package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"html/template"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testPKI struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &testPKI{caKey: key, caCert: ca}
}

func (p *testPKI) issue(t *testing.T, cn string, serial int64, key *ecdsa.PrivateKey, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func csrFor(t *testing.T, cn string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// traefikHeader encodes certs like Traefik's passTLSClientCert (pem: true).
func traefikHeader(certs ...*x509.Certificate) string {
	parts := make([]string, 0, len(certs))
	for _, c := range certs {
		parts = append(parts, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return strings.Join(parts, ",")
}

func TestVaultSerial(t *testing.T) {
	for in, want := range map[int64]string{1: "01", 0xabc: "0a:bc", 0x1a2b3c: "1a:2b:3c"} {
		if got := vaultSerial(big.NewInt(in)); got != want {
			t.Errorf("vaultSerial(%x) = %q, want %q", in, got, want)
		}
	}
}

func TestPresentedCert(t *testing.T) {
	p := newTestPKI(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := p.issue(t, "alice", 7, key, time.Now().Add(time.Hour))
	for name, hv := range map[string]string{
		"traefik":     traefikHeader(leaf, p.caCert),
		"url-escaped": url.QueryEscape(traefikHeader(leaf)),
		"full pem":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
	} {
		r := httptest.NewRequest("GET", "/self", nil)
		r.Header.Set(clientCertHeader, hv)
		c, err := presentedCert(r)
		if err != nil || c.Subject.CommonName != "alice" {
			t.Errorf("%s: got %v, %v", name, c, err)
		}
	}
	r := httptest.NewRequest("GET", "/self", nil)
	if _, err := presentedCert(r); err == nil {
		t.Error("missing header accepted")
	}
	r.Header.Set(clientCertHeader, "not!base64")
	if _, err := presentedCert(r); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCheckRenewal(t *testing.T) {
	p := newTestPKI(t)
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cur := p.issue(t, "alice", 0x10, key, now.Add(48*time.Hour))
	expired := p.issue(t, "alice", 0x11, key, now.Add(-time.Minute))
	bobs := p.issue(t, "bob", 0x12, key, now.Add(48*time.Hour))
	forged := p.issue(t, "alice", 0x10, key, now.Add(72*time.Hour)) // same serial, different bytes

	vault := map[string]*issuedCert{
		"10": {DER: cur.Raw},
		"11": {DER: expired.Raw},
		"12": {DER: bobs.Raw},
	}
	lookup := func(serial string) (*issuedCert, error) { return vault[serial], nil }
	good := csrFor(t, "alice", key)

	if err := checkRenewal("alice", cur, good, "", now, lookup); err != nil {
		t.Fatalf("valid renewal refused: %v", err)
	}
	cases := map[string]error{
		"not signed in":  checkRenewal("", cur, good, "", now, lookup),
		"no cert":        checkRenewal("alice", nil, good, "", now, lookup),
		"foreign cert":   checkRenewal("alice", bobs, good, "", now, lookup),
		"expired":        checkRenewal("alice", expired, good, "", now, lookup),
		"not from vault": checkRenewal("alice", forged, good, "", now, lookup),
		"other key":      checkRenewal("alice", cur, csrFor(t, "alice", other), "", now, lookup),
		"csr wrong cn":   checkRenewal("alice", cur, csrFor(t, "bob", key), "", now, lookup),
		"vault down": checkRenewal("alice", cur, good, "", now, func(string) (*issuedCert, error) {
			return nil, errors.New("sealed")
		}),
	}
	vault["10"] = &issuedCert{DER: cur.Raw, Revoked: true}
	cases["revoked"] = checkRenewal("alice", cur, good, "", now, lookup)
	vault["10"] = nil
	cases["unknown serial"] = checkRenewal("alice", cur, good, "", now, lookup)
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: renewal accepted", name)
		}
	}
}

func TestSelfTemplateRenders(t *testing.T) {
	var err error
	templates, err = template.ParseFS(webFS, "web/*.html")
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPKI(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := p.issue(t, "alice", 0x10, key, time.Now().Add(time.Hour))
	var buf strings.Builder
	data := map[string]interface{}{
		"User": "alice", "TTL": "720h", "Now": time.Now(), "Domain": "example.com",
		"Certs": []CertInfo{{Username: "alice", Serial: "10", NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}},
		"Presented": map[string]interface{}{"CN": "alice", "Serial": "10", "NotAfter": leaf.NotAfter, "Matches": true},
	}
	if err := templates.ExecuteTemplate(&buf, "self.html", data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/api/self/renew", "CN=alice", "less than 7 days"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("self.html lacks %q", want)
		}
	}
}
