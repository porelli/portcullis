package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
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

// certPEM issues a test certificate (self-signed: only its fields matter).
func certPEM(t *testing.T, cn string, isCA bool, usage []x509.ExtKeyUsage, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: notAfter.Add(-24 * time.Hour), NotAfter: notAfter,
		IsCA: isCA, BasicConstraintsValid: true, ExtKeyUsage: usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// certVault fakes Vault's pki_int/certs list and pki_int/cert/<serial>
// reads; data maps serial → the read's data (nil = a 500).
func certVault(t *testing.T, data map[string]map[string]any, order []string) *vault.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pki_int/certs" && (r.Method == "LIST" || r.URL.Query().Get("list") == "true") {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": order}})
			return
		}
		serial, ok := strings.CutPrefix(r.URL.Path, "/v1/pki_int/cert/")
		if !ok || r.Method != http.MethodGet {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		d := data[serial]
		if d == nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"errors":["internal error"]}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": d})
	}))
	t.Cleanup(srv.Close)
	cfg := vault.DefaultConfig()
	cfg.Address = srv.URL
	cfg.MaxRetries = 0
	vc, err := vault.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	vc.SetToken("t")
	return vc
}

func getCertificates(s *inviteService, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/internal/certificates", nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	s.apiHandler(false).ServeHTTP(w, r)
	return w
}

func TestInternalCertificatesNeedsBearer(t *testing.T) {
	s, _ := testInvites(t)
	called := false
	s.listCertificates = func() ([]certRecord, error) { called = true; return []certRecord{}, nil }
	for _, auth := range []string{"", "Bearer ", "Bearer wrong", "Basic " + testAPISecret, testAPISecret, "bearer " + testAPISecret, "Bearer " + testAPISecret + "x"} {
		if w := getCertificates(s, auth); w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: %d", auth, w.Code)
		}
	}
	if called {
		t.Error("listed certificates without the bearer")
	}
	if w := getCertificates(s, "Bearer "+testAPISecret); w.Code != http.StatusOK {
		t.Errorf("with the bearer: %d %s", w.Code, w.Body)
	}
	// No secret configured: nothing is accepted.
	s.apiSecret = ""
	if w := getCertificates(s, "Bearer "); w.Code != http.StatusUnauthorized {
		t.Errorf("no secret configured: %d", w.Code)
	}
	// The loopback listener (no secret) doesn't serve it.
	r := httptest.NewRequest("GET", "/internal/certificates", nil)
	w := httptest.NewRecorder()
	s.apiHandler(true).ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("loopback listener: %d", w.Code)
	}
}

func TestInternalCertificatesLists(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	client := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	data := map[string]map[string]any{
		"1a:2b":     {"certificate": certPEM(t, "Alice", false, client, exp), "revocation_time": 0},
		"3c:4d":     {"certificate": certPEM(t, "bob", false, client, exp.Add(time.Hour)), "revocation_time": 1767225600, "revocation_time_rfc3339": "2026-01-01T00:00:00Z"},
		"5e:6f":     {"certificate": certPEM(t, "*.example.org", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, exp), "revocation_time": 0},
		"7a:8b":     {"certificate": certPEM(t, "Portcullis Intermediate CA", true, nil, exp), "revocation_time": 0},
		"9c:0d":     {"certificate": certPEM(t, "both", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, exp), "revocation_time": 0},
		"no-rt":     {"certificate": certPEM(t, "carol", false, client, exp)},
		"bad-rt":    {"certificate": certPEM(t, "carol", false, client, exp), "revocation_time": "yesterday"},
		"no-cert":   {"revocation_time": 0},
		"vault-500": nil,
	}
	s, _ := testInvites(t)
	list := func(order ...string) {
		vc := certVault(t, data, order)
		s.listCertificates = func() ([]certRecord, error) { return issuedCertsWith(vc) }
	}

	list("1a:2b", "3c:4d", "5e:6f", "7a:8b", "9c:0d")
	w := getCertificates(s, "Bearer "+testAPISecret)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("list: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	var doc map[string][]map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	want := []map[string]any{
		{"user": "alice", "serial": "1a:2b", "not_after": "2027-01-02T03:04:05Z", "revoked": false},
		{"user": "bob", "serial": "3c:4d", "not_after": "2027-01-02T04:04:05Z", "revoked": true},
	}
	got, _ := json.Marshal(doc["certificates"])
	exp2, _ := json.Marshal(want)
	if len(doc) != 1 || string(got) != string(exp2) {
		t.Errorf("certificates = %s\nwant %s", w.Body, exp2)
	}
	if strings.Contains(w.Body.String(), "BEGIN") {
		t.Error("the answer carries PEM")
	}

	// Nothing issued: an empty list, not null.
	list()
	if w := getCertificates(s, "Bearer "+testAPISecret); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"certificates":[]}` {
		t.Errorf("empty: %d %s", w.Code, w.Body)
	}

	// Fail closed: one unreadable serial or revocation state fails the
	// whole answer (503), never a partial list or a guessed revoked:false.
	for _, bad := range []string{"no-rt", "bad-rt", "no-cert", "vault-500"} {
		list("1a:2b", bad)
		w := getCertificates(s, "Bearer "+testAPISecret)
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "alice") {
			t.Errorf("%s: %d %s", bad, w.Code, w.Body)
		}
	}
	s.listCertificates = func() ([]certRecord, error) { return nil, errors.New("vault sealed") }
	if w := getCertificates(s, "Bearer "+testAPISecret); w.Code != http.StatusServiceUnavailable {
		t.Errorf("vault down: %d", w.Code)
	}
}
