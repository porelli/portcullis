package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net/http/httptest"
	"strings"
	"testing"
)

func makeCSR(t *testing.T, tmpl *x509.CertificateRequest) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestValidateCSR(t *testing.T) {
	email := "alice@example.com"
	withEmail := pkix.Name{CommonName: "alice", ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidEmailAddress, Value: email}}}
	cases := []struct {
		name string
		tmpl *x509.CertificateRequest
		ok   bool
	}{
		{"cn only", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice"}}, true},
		{"cn+email", &x509.CertificateRequest{Subject: withEmail}, true},
		{"wrong cn", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "admin"}}, false},
		{"extra O", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice", Organization: []string{"x"}}}, false},
		{"dns san", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice"}, DNSNames: []string{"hub.example.com"}}, false},
		{"other email", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier(oidEmailAddress), Value: "bob@example.com"}}}}, false},
		{"own email san", &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice"}, EmailAddresses: []string{email}}, true},
	}
	for _, c := range cases {
		err := validateCSR(makeCSR(t, c.tmpl), "alice", email)
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.name, c.ok, err)
		}
	}
	if validateCSR("garbage", "alice", email) == nil {
		t.Error("garbage accepted")
	}
}

func TestSignRequiresAdminAndJSON(t *testing.T) {
	s := &Server{}
	body := `{"username":"alice","csr":"x"}`

	r := httptest.NewRequest("POST", "/api/sign", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Auth-Request-Groups", "users_grafana,lldap_admin_x")
	w := httptest.NewRecorder()
	s.handleSign(w, r)
	if w.Code != 403 {
		t.Errorf("non-admin: got %d", w.Code)
	}

	r = httptest.NewRequest("POST", "/api/sign", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Auth-Request-Groups", "users_grafana, lldap_admin")
	w = httptest.NewRecorder()
	s.handleSign(w, r)
	if w.Code != 415 {
		t.Errorf("text/plain: got %d", w.Code)
	}
}
