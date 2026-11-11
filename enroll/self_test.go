package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func TestVaultSerial(t *testing.T) {
	for in, want := range map[int64]string{1: "01", 0xabc: "0a:bc", 0x1a2b3c: "1a:2b:3c"} {
		if got := vaultSerial(big.NewInt(in)); got != want {
			t.Errorf("vaultSerial(%x) = %q, want %q", in, got, want)
		}
	}
}
