package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// certRoutes are the D23 actions with a valid body for alice.
var certRoutes = map[string]string{
	"/internal/browser-certificates":       `{"user":"alice","days":5,"max_days":30,"max_active":3}`,
	"/internal/yubikey-certificates":       `{"user":"alice","csr":"x"}`,
	"/internal/yubikey-certificates/renew": `{"user":"alice","presented":"x","csr":"x"}`,
	"/internal/certificates/revoke":        `{"user":"alice","serial":"01:02"}`,
}

// countingOps wires every operation to a stub that counts its calls.
func countingOps(s *inviteService) *int {
	n := new(int)
	s.issueBrowser = func(context.Context, string, int, int, int) (*browserCertResult, error) {
		*n++
		return &browserCertResult{P12: []byte{1}, Password: "P", Serial: "01", Filename: "a.p12", NotAfter: time.Now()}, nil
	}
	s.issueYubiKey = func(context.Context, string, string) (*yubiKeyCertResult, error) {
		*n++
		return &yubiKeyCertResult{PEM: "x", Serial: "01", NotAfter: time.Now()}, nil
	}
	s.renewYubiKey = func(context.Context, string, string, string) (*yubiKeyCertResult, error) {
		*n++
		return &yubiKeyCertResult{PEM: "x", Serial: "01", NotAfter: time.Now()}, nil
	}
	s.revoke = func(context.Context, string, string) error { *n++; return nil }
	return n
}

func errorText(t *testing.T, body []byte) string {
	t.Helper()
	var doc struct {
		Error string `json:"error"`
	}
	strictDecode(t, body, &doc)
	return doc.Error
}

func TestCertAPINeedsBearer(t *testing.T) {
	s, _ := testInvites(t)
	calls := countingOps(s)
	for path, body := range certRoutes {
		for _, auth := range []string{"", "Bearer ", "Bearer wrong", "Basic " + testAPISecret, testAPISecret, "bearer " + testAPISecret, "Bearer " + testAPISecret + "x"} {
			hdr := map[string]string{"Content-Type": "application/json"}
			if auth != "" {
				hdr["Authorization"] = auth
			}
			if w := do(s.apiHandler(false), "POST", path, body, hdr); w.Code != http.StatusUnauthorized {
				t.Errorf("%s with %q: %d", path, auth, w.Code)
			}
		}
		// The loopback listener (no secret) doesn't serve them.
		if w := do(s.apiHandler(true), "POST", path, body, map[string]string{"Content-Type": "application/json"}); w.Code != http.StatusNotFound {
			t.Errorf("%s on the loopback listener: %d", path, w.Code)
		}
	}
	if *calls != 0 {
		t.Errorf("%d operations ran without the bearer", *calls)
	}
}

func TestCertAPIStrictBodies(t *testing.T) {
	s, _ := testInvites(t)
	calls := countingOps(s)
	for path, body := range certRoutes {
		for name, c := range map[string]struct {
			body string
			want int
		}{
			"unknown field": {strings.TrimSuffix(body, "}") + `,"extra":1}`, 400},
			"trailing json": {body + `{}`, 400},
			"trailing text": {body + ` x`, 400},
			"not json":      {"user=alice", 400},
			"empty":         {"", 400},
			"array":         {"[" + body + "]", 400},
			"too large":     {strings.TrimSuffix(body, "}") + `,"pad":"` + strings.Repeat("a", 64<<10) + `"}`, 413},
			"no user":       {`{"user":"  "}`, 400},
		} {
			w := postAction(s, path, c.body)
			if w.Code != c.want {
				t.Errorf("%s %s: %d %s", path, name, w.Code, w.Body)
				continue
			}
			if msg := errorText(t, w.Body.Bytes()); msg == "" || strings.Contains(msg, "alice") {
				t.Errorf("%s %s: error text %q", path, name, msg)
			}
		}
		// Trailing whitespace is fine.
		if w := postAction(s, path, body+"\n"); w.Code >= 300 {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}
	if *calls != len(certRoutes) {
		t.Errorf("%d operations ran, want %d (only the good bodies)", *calls, len(certRoutes))
	}
}

func TestCertAPIUnwired503(t *testing.T) {
	s, _ := testInvites(t)
	for path, body := range certRoutes {
		if w := postAction(s, path, body); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s unwired: %d", path, w.Code)
		}
	}
}

func TestCertAPIStatuses(t *testing.T) {
	s, _ := testInvites(t)
	countingOps(s)
	want := map[string]int{
		"/internal/browser-certificates":       201,
		"/internal/yubikey-certificates":       201,
		"/internal/yubikey-certificates/renew": 201,
		"/internal/certificates/revoke":        204,
	}
	for path, body := range certRoutes {
		if w := postAction(s, path, body); w.Code != want[path] {
			t.Errorf("%s: %d, want %d", path, w.Code, want[path])
		}
	}
	// A refusal keeps its status and text; any other failure is a 503
	// that never carries the cause.
	s.revoke = func(context.Context, string, string) error { return refuse(404, "no such certificate") }
	w := postAction(s, "/internal/certificates/revoke", certRoutes["/internal/certificates/revoke"])
	if w.Code != 404 || errorText(t, w.Body.Bytes()) != "no such certificate" {
		t.Errorf("refusal: %d %s", w.Code, w.Body)
	}
	s.revoke = func(context.Context, string, string) error { return errors.New("vault: secret-token-xyz") }
	w = postAction(s, "/internal/certificates/revoke", certRoutes["/internal/certificates/revoke"])
	if w.Code != 503 || strings.Contains(w.Body.String(), "secret-token-xyz") {
		t.Errorf("failure: %d %s", w.Code, w.Body)
	}
	s.revoke = func(context.Context, string, string) error { return refuse(400, "%s", strings.Repeat("é", 300)) }
	w = postAction(s, "/internal/certificates/revoke", certRoutes["/internal/certificates/revoke"])
	if n := len([]rune(errorText(t, w.Body.Bytes()))); n != maxErrorText {
		t.Errorf("error text is %d characters", n)
	}
}

func TestCertAPIDeadline(t *testing.T) {
	if certOpTimeout > 15*time.Second || certOpTimeout <= 0 {
		t.Fatalf("certOpTimeout = %v, want (0, 15s]", certOpTimeout)
	}
	old := certOpTimeout
	certOpTimeout = 100 * time.Millisecond
	t.Cleanup(func() { certOpTimeout = old })
	s, _ := testInvites(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.issueBrowser = func(ctx context.Context, _ string, _, _, _ int) (*browserCertResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("no deadline")
		}
		<-release
		return &browserCertResult{P12: []byte{1}}, nil
	}
	s.revoke = func(ctx context.Context, _, _ string) error { <-ctx.Done(); return ctx.Err() }
	start := time.Now()
	w := postAction(s, "/internal/browser-certificates", certRoutes["/internal/browser-certificates"])
	if w.Code != 503 || time.Since(start) > 2*time.Second {
		t.Errorf("hung create: %d after %v", w.Code, time.Since(start))
	}
	if w := postAction(s, "/internal/certificates/revoke", certRoutes["/internal/certificates/revoke"]); w.Code != 503 {
		t.Errorf("hung revoke: %d", w.Code)
	}

	// A result that arrives after the deadline is discarded (cleared).
	late := make(chan struct{})
	discarded := make(chan *browserCertResult, 1)
	res := &browserCertResult{P12: []byte{1, 2, 3}, Password: "P"}
	_, err := withDeadline(context.Background(), func(context.Context) (*browserCertResult, error) {
		<-late
		return res, nil
	}, func(b *browserCertResult) { b.clear(); discarded <- b })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("late op: %v", err)
	}
	close(late)
	select {
	case b := <-discarded:
		if b != res || b.P12 != nil || b.Password != "" {
			t.Error("the late result wasn't cleared")
		}
	case <-time.After(2 * time.Second):
		t.Error("the late result was never discarded")
	}
}

func TestCertAPIProtectedNames(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	for _, user := range []string{"admin", "Admin", "portcullis-hub", "Portcullis-X", " portcullis-enroll "} {
		u, _ := json.Marshal(user)
		for path, body := range certRoutes {
			w := postAction(s, path, strings.Replace(body, `"alice"`, string(u), 1))
			if w.Code != http.StatusConflict || strings.TrimSpace(w.Body.String()) != `{"error":"protected account"}` {
				t.Errorf("%s for %q: %d %s", path, user, w.Code, w.Body)
			}
		}
	}
	if calls := fp.callList(); len(calls) != 0 {
		t.Errorf("Vault called for protected names: %v", calls)
	}
}

// csrPEMFor is a CSR for cn with key.
func csrPEMFor(t *testing.T, cn string, key *ecdsa.PrivateKey) string {
	t.Helper()
	return csrFor(t, cn, key)
}

func renewBody(user string, presented *x509.Certificate, csr string) string {
	b, _ := json.Marshal(map[string]string{"user": user, "presented": pemCert(presented), "csr": csr})
	return string(b)
}

// issuedDoc decodes a {certificate, serial, not_after} answer like the Hub.
func issuedDoc(t *testing.T, body []byte) (*x509.Certificate, string) {
	t.Helper()
	var doc struct {
		Certificate string    `json:"certificate"`
		Serial      string    `json:"serial"`
		NotAfter    time.Time `json:"not_after"`
	}
	strictDecode(t, body, &doc)
	blk, rest := pem.Decode([]byte(doc.Certificate))
	if blk == nil || blk.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		t.Fatalf("certificate isn't one PEM block: %q", doc.Certificate)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Serial != vaultSerial(c.SerialNumber) || !doc.NotAfter.Equal(c.NotAfter.UTC().Truncate(time.Second)) {
		t.Errorf("serial %q / not_after %v don't match", doc.Serial, doc.NotAfter)
	}
	return c, doc.Serial
}

func TestRenewRefusesBrowserLeaf(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	future := time.Now().Add(10 * 24 * time.Hour)
	csr := csrPEMFor(t, "alice", key)

	// A browser certificate of alice, issued by pki_file.
	browserLeaf, _ := fp.issue(mountBrowser, "alice", &key.PublicKey, future, false)
	// A leaf whose issuer DN is pki_int's, signed by another key.
	impostor := newFakeCA(t, "example.org Intermediate CA", nil)
	forged := impostor.leaf(t, "alice", &key.PublicKey, time.Now().Add(-time.Hour), future)
	if string(forged.RawIssuer) != string(fp.cas[mountYubiKey].cert.RawSubject) {
		t.Fatal("the forged leaf's issuer DN isn't pki_int's")
	}
	// Stored under pki_int as well: only the signature check can refuse it.
	fp.add(mountYubiKey, forged, false)
	// A leaf of another CA altogether.
	other := newFakeCA(t, "Elsewhere CA", nil)
	foreign := other.leaf(t, "alice", &key.PublicKey, time.Now().Add(-time.Hour), future)

	for name, c := range map[string]*x509.Certificate{"browser leaf": browserLeaf, "forged pki_int issuer": forged, "foreign CA": foreign} {
		w := postAction(s, "/internal/yubikey-certificates/renew", renewBody("alice", c, csr))
		if w.Code != http.StatusForbidden || !strings.Contains(errorText(t, w.Body.Bytes()), "not a YubiKey certificate") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if n := fp.count("PUT pki_int/sign/") + fp.count("PUT pki_file/sign/"); n != 0 {
		t.Errorf("%d certificates signed", n)
	}
	if n := fp.count("GET pki_file/"); n != 0 {
		t.Errorf("renewal looked at pki_file: %v", fp.callList())
	}
}

func TestRenewUsesPresentedCert(t *testing.T) {
	fp, cfg := newFakePKI(t)
	cfg.CertTTL = "240h"
	s := browserService(t, cfg)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	future := time.Now().Add(10 * 24 * time.Hour)
	cur, curSerial := fp.issue(mountYubiKey, "alice", &key.PublicKey, future, false)
	fp.issue(mountYubiKey, "alice", &other.PublicKey, future, false) // another of alice's: never used
	bobs, _ := fp.issue(mountYubiKey, "bob", &key.PublicKey, future, false)
	revoked, _ := fp.issue(mountYubiKey, "alice", &key.PublicKey, future, true)
	// Same serial as a stored pki_int certificate, different bytes.
	twin := fp.cas[mountYubiKey].leaf(t, "alice", &key.PublicKey, time.Now().Add(-time.Hour), future)
	twin.SerialNumber = cur.SerialNumber
	tmpl := *twin
	der, _ := x509.CreateCertificate(rand.Reader, &tmpl, fp.cas[mountYubiKey].cert, &key.PublicKey, fp.cas[mountYubiKey].key)
	twin, _ = x509.ParseCertificate(der)

	w := postAction(s, "/internal/yubikey-certificates/renew", renewBody("alice", cur, csrPEMFor(t, "alice", key)))
	if w.Code != http.StatusCreated {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	c, _ := issuedDoc(t, w.Body.Bytes())
	if c.Subject.CommonName != "alice" || !issuedBy(c, fp.cas[mountYubiKey].cert) {
		t.Errorf("renewed certificate: CN %q", c.Subject.CommonName)
	}
	if pub, _ := c.PublicKey.(*ecdsa.PublicKey); pub == nil || !pub.Equal(&key.PublicKey) {
		t.Error("the renewed certificate has another key")
	}
	// The lookup was exactly the presented serial, on pki_int only.
	if !fp.has("GET pki_int/cert/"+curSerial) || fp.count("GET pki_file/") != 0 || fp.count("GET pki_int/cert/") != 2 {
		t.Errorf("lookups: %v", fp.callList()) // cert/ca + the presented serial
	}
	sign := fp.signs[len(fp.signs)-1]
	if !fp.has("PUT pki_int/sign/client-cert") || sign["common_name"] != "alice" || sign["ttl"] != "240h" || len(sign) != 3 {
		t.Errorf("sign request %v", sign)
	}

	for name, body := range map[string]string{
		"csr for another key": renewBody("alice", cur, csrPEMFor(t, "alice", other)),
		"csr for another cn":  renewBody("alice", cur, csrPEMFor(t, "bob", key)),
		"bob's certificate":   renewBody("alice", bobs, csrPEMFor(t, "alice", key)),
		"revoked":             renewBody("alice", revoked, csrPEMFor(t, "alice", key)),
		"not what vault has":  renewBody("alice", twin, csrPEMFor(t, "alice", key)),
	} {
		before := len(fp.signs)
		w := postAction(s, "/internal/yubikey-certificates/renew", body)
		if w.Code != http.StatusForbidden || len(fp.signs) != before {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	// An unknown user is 404; Vault down is a 503.
	if w := postAction(s, "/internal/yubikey-certificates/renew", renewBody("carol", cur, csrPEMFor(t, "carol", key))); w.Code != 404 {
		t.Errorf("unknown user: %d %s", w.Code, w.Body)
	}
	fp.certs[mountYubiKey][curSerial].unreadable = true
	if w := postAction(s, "/internal/yubikey-certificates/renew", renewBody("alice", cur, csrPEMFor(t, "alice", key))); w.Code != 503 {
		t.Errorf("unreadable lookup: %d %s", w.Code, w.Body)
	}
}

func TestYubiKeyIssueValidatesCSR(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := func(user, csr string) string {
		b, _ := json.Marshal(map[string]string{"user": user, "csr": csr})
		return string(b)
	}
	w := postAction(s, "/internal/yubikey-certificates", body("alice", csrPEMFor(t, "bob", key)))
	if w.Code != 400 || errorText(t, w.Body.Bytes()) != "csr common name does not match username" {
		t.Errorf("wrong CN: %d %s", w.Code, w.Body)
	}
	if w := postAction(s, "/internal/yubikey-certificates", body("alice", "garbage")); w.Code != 400 {
		t.Errorf("garbage: %d", w.Code)
	}
	if w := postAction(s, "/internal/yubikey-certificates", body("nobody", csrPEMFor(t, "nobody", key))); w.Code != 404 {
		t.Errorf("unknown user: %d", w.Code)
	}
	if len(fp.signs) != 0 {
		t.Fatalf("signed a refused CSR: %v", fp.signs)
	}
	w = postAction(s, "/internal/yubikey-certificates", body("alice", csrPEMFor(t, "alice", key)))
	if w.Code != http.StatusCreated {
		t.Fatalf("good CSR: %d %s", w.Code, w.Body)
	}
	c, serial := issuedDoc(t, w.Body.Bytes())
	if c.Subject.CommonName != "alice" || !issuedBy(c, fp.cas[mountYubiKey].cert) || fp.certs[mountYubiKey][serial] == nil {
		t.Errorf("issued %q on the wrong CA", c.Subject.CommonName)
	}
	sign := fp.signs[0]
	if !fp.has("PUT pki_int/sign/client-cert") || sign["common_name"] != "alice" || sign["ttl"] != "720h" || len(sign) != 3 {
		t.Errorf("sign request %v", sign)
	}
}

func TestRenewChecksPresented(t *testing.T) {
	// The handler: presented must be one PEM CERTIFICATE block.
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cur, _ := fp.issue(mountYubiKey, "alice", &key.PublicKey, time.Now().Add(time.Hour), false)
	csr := csrPEMFor(t, "alice", key)
	csrBlock := csr
	two := pemCert(cur) + pemCert(cur)
	for name, presented := range map[string]string{
		"empty":       "",
		"base64 only": strings.Join(strings.Split(strings.TrimSpace(pemCert(cur)), "\n")[1:3], ""),
		"a csr":       csrBlock,
		"two blocks":  two,
		"bad der":     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("nope")})),
		"trailing":    pemCert(cur) + "x",
	} {
		b, _ := json.Marshal(map[string]string{"user": "alice", "presented": presented, "csr": csr})
		if w := postAction(s, "/internal/yubikey-certificates/renew", string(b)); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if len(fp.callList()) != 0 {
		t.Errorf("Vault called for a bad presented: %v", fp.callList())
	}

	// checkRenewal (moved from self_test.go).
	p := newTestPKI(t)
	now := time.Now()
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := p.issue(t, "alice", 0x10, key, now.Add(48*time.Hour))
	expired := p.issue(t, "alice", 0x11, key, now.Add(-time.Minute))
	bobs := p.issue(t, "bob", 0x12, key, now.Add(48*time.Hour))
	forged := p.issue(t, "alice", 0x10, key, now.Add(72*time.Hour)) // same serial, different bytes
	vaultData := map[string]*issuedCert{"10": {DER: good.Raw}, "11": {DER: expired.Raw}, "12": {DER: bobs.Raw}}
	lookup := func(serial string) (*issuedCert, error) { return vaultData[serial], nil }
	goodCSR := csrFor(t, "alice", key)
	if err := checkRenewal("alice", good, goodCSR, "", now, lookup); err != nil {
		t.Fatalf("valid renewal refused: %v", err)
	}
	cases := map[string]error{
		"not signed in":  checkRenewal("", good, goodCSR, "", now, lookup),
		"no cert":        checkRenewal("alice", nil, goodCSR, "", now, lookup),
		"foreign cert":   checkRenewal("alice", bobs, goodCSR, "", now, lookup),
		"expired":        checkRenewal("alice", expired, goodCSR, "", now, lookup),
		"not from vault": checkRenewal("alice", forged, goodCSR, "", now, lookup),
		"other key":      checkRenewal("alice", good, csrFor(t, "alice", otherKey), "", now, lookup),
		"csr wrong cn":   checkRenewal("alice", good, csrFor(t, "bob", key), "", now, lookup),
		"vault down": checkRenewal("alice", good, goodCSR, "", now, func(string) (*issuedCert, error) {
			return nil, errors.New("sealed")
		}),
	}
	vaultData["10"] = &issuedCert{DER: good.Raw, Revoked: true}
	cases["revoked"] = checkRenewal("alice", good, goodCSR, "", now, lookup)
	vaultData["10"] = nil
	cases["unknown serial"] = checkRenewal("alice", good, goodCSR, "", now, lookup)
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: renewal accepted", name)
		}
	}
}

func TestRevokeFindsMountAndOwner(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	future := time.Now().Add(24 * time.Hour)
	_, browserSerial := fp.issue(mountBrowser, "alice", nil, future, false)
	_, yubiSerial := fp.issue(mountYubiKey, "alice", nil, future, false)
	_, revokedSerial := fp.issue(mountBrowser, "alice", nil, future, true)
	revoke := func(user, serial string) int {
		b, _ := json.Marshal(map[string]string{"user": user, "serial": serial})
		w := postAction(s, "/internal/certificates/revoke", string(b))
		if w.Code == 204 && w.Body.Len() != 0 {
			t.Errorf("204 with a body: %s", w.Body)
		}
		return w.Code
	}

	if c := revoke("bob", browserSerial); c != 404 {
		t.Errorf("bob revoking alice's: %d", c)
	}
	for _, serial := range []string{"de:ad:be:ef", "not-a-serial", "../ca", ""} {
		if c := revoke("alice", serial); c != 404 {
			t.Errorf("serial %q: %d", serial, c)
		}
	}
	if fp.count("PUT ") != 0 {
		t.Fatalf("revoked something: %v", fp.callList())
	}

	if c := revoke("alice", strings.ToUpper(browserSerial)); c != 204 {
		t.Fatalf("alice's browser certificate: %d", c)
	}
	if !fp.certs[mountBrowser][browserSerial].revoked || !fp.has("PUT pki_file/revoke") || !fp.has("GET pki_file/crl/rotate") {
		t.Errorf("pki_file revoke: %v", fp.callList())
	}
	// Looked up in pki_int first, then pki_file.
	calls := fp.callList()
	iInt, iFile := -1, -1
	for i, c := range calls {
		if c == "GET pki_int/cert/"+browserSerial && iInt < 0 {
			iInt = i
		}
		if c == "GET pki_file/cert/"+browserSerial && iFile < 0 {
			iFile = i
		}
	}
	if iInt < 0 || iFile < iInt {
		t.Errorf("lookup order: %v", calls)
	}

	// A YubiKey certificate: pki_int's revoke + rotate; a failed rotate is still 204.
	fp.failRotate = true
	if c := revoke("alice", yubiSerial); c != 204 {
		t.Errorf("alice's YubiKey certificate: %d", c)
	}
	if !fp.certs[mountYubiKey][yubiSerial].revoked || !fp.has("PUT pki_int/revoke") || !fp.has("GET pki_int/crl/rotate") {
		t.Errorf("pki_int revoke: %v", fp.callList())
	}

	// Already revoked: 204 and no second revoke.
	before := fp.count("PUT ")
	if c := revoke("alice", revokedSerial); c != 204 {
		t.Errorf("already revoked: %d", c)
	}
	if c := revoke("alice", browserSerial); c != 204 {
		t.Errorf("revoked twice: %d", c)
	}
	if fp.count("PUT ") != before {
		t.Errorf("a second revoke was sent: %v", fp.callList())
	}

	// An unreadable lookup is a 503, never a guess.
	_, bad := fp.issue(mountYubiKey, "alice", nil, future, false)
	fp.certs[mountYubiKey][bad].unreadable = true
	if c := revoke("alice", bad); c != 503 {
		t.Errorf("unreadable: %d", c)
	}
}

func TestCertificatesBothMountsKinds(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	exp := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	y, ySerial := fp.issue(mountYubiKey, "Alice", nil, exp, false)
	b, bSerial := fp.issue(mountBrowser, "alice", nil, exp, false)
	_, rSerial := fp.issue(mountBrowser, "bob", nil, exp, true)
	fp.add(mountYubiKey, fp.cas[mountYubiKey].cert, false) // the CA itself: not listed

	w := getCertificates(s, "Bearer "+testAPISecret)
	if w.Code != 200 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var doc struct {
		Certificates []struct {
			User      string    `json:"user"`
			Serial    string    `json:"serial"`
			Kind      string    `json:"kind"`
			NotBefore time.Time `json:"not_before"`
			NotAfter  time.Time `json:"not_after"`
			Revoked   bool      `json:"revoked"`
		} `json:"certificates"`
	}
	strictDecode(t, w.Body.Bytes(), &doc)
	got := map[string]string{}
	for _, c := range doc.Certificates {
		got[c.Serial] = c.User + " " + c.Kind + " " + map[bool]string{true: "revoked", false: "valid"}[c.Revoked]
		switch c.Serial {
		case ySerial:
			if !c.NotBefore.Equal(y.NotBefore.UTC().Truncate(time.Second)) || !c.NotAfter.Equal(y.NotAfter.UTC()) {
				t.Errorf("yubikey dates %v %v", c.NotBefore, c.NotAfter)
			}
		case bSerial:
			if !c.NotBefore.Equal(b.NotBefore.UTC().Truncate(time.Second)) {
				t.Errorf("browser not_before %v", c.NotBefore)
			}
		}
	}
	want := map[string]string{ySerial: "alice yubikey valid", bSerial: "alice browser valid", rSerial: "bob browser revoked"}
	if len(got) != len(want) {
		t.Errorf("certificates = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if certKind(mountYubiKey) != "yubikey" || certKind(mountBrowser) != "browser" || certKind("pki") != "" {
		t.Error("certKind")
	}

	// One unreadable certificate on either mount: 503 for all.
	fp.certs[mountBrowser][bSerial].unreadable = true
	if w := getCertificates(s, "Bearer "+testAPISecret); w.Code != 503 || strings.Contains(w.Body.String(), "alice") {
		t.Errorf("unreadable browser certificate: %d %s", w.Code, w.Body)
	}
}

func TestPublicMuxOnlyInvite(t *testing.T) {
	s, _ := testInvites(t)
	countingOps(s)
	h := publicMux(&Server{}, s)
	for _, c := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/users"}, {"GET", "/certs"}, {"GET", "/self"}, {"GET", "/enroll/alice"},
		{"GET", "/api/users"}, {"POST", "/api/sign"}, {"POST", "/api/self/renew"},
		{"GET", "/internal/certificates"}, {"POST", "/internal/browser-certificates"},
		{"POST", "/internal/invites"}, {"GET", "/oidc/jwks"}, {"GET", "/static/x"},
	} {
		w := do(h, c.method, c.path, "{}", map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + testAPISecret})
		if w.Code != http.StatusNotFound || strings.Contains(w.Header().Get("Content-Type"), "html") {
			t.Errorf("%s %s: %d %q", c.method, c.path, w.Code, w.Header().Get("Content-Type"))
		}
	}
	if w := do(h, "GET", "/healthz", "", nil); w.Code != 200 || w.Body.String() != "ok\n" {
		t.Errorf("/healthz: %d %q", w.Code, w.Body)
	}
	// /invite/<token> is the invite page (here: the "invalid link" one).
	w := do(h, "GET", "/invite/x", "", nil)
	if w.Code != http.StatusNotFound || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "setup link") {
		t.Errorf("/invite/x: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	// Only invite.html is left of enroll's pages.
	entries, err := webFS.ReadDir("web")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "invite.html" {
			t.Errorf("web/%s is still embedded", e.Name())
		}
	}
}

// Users must be plain LLDAP usernames (lowercase ASCII): no Unicode case
// folding can turn one into a protected name or someone else's (review I1).
func TestCertAPIUserGrammar(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	future := time.Now().Add(24 * time.Hour)
	_, hubSerial := fp.issue(mountYubiKey, "portcullis-hub", nil, future, false)
	_, upperSerial := fp.issue(mountBrowser, "Alice", nil, future, false)
	before := len(fp.callList())
	for _, user := range []string{"portculliſ-hub", "ADMIN", "Alice", "alicé", "al ice", "-alice", "", strings.Repeat("a", 65)} {
		u, _ := json.Marshal(user)
		for path, body := range certRoutes {
			body = strings.Replace(body, `"alice"`, string(u), 1)
			if path == "/internal/certificates/revoke" {
				body = strings.Replace(body, `"01:02"`, `"`+hubSerial+`"`, 1)
			}
			w := postAction(s, path, body)
			if w.Code != http.StatusBadRequest && w.Code != http.StatusConflict {
				t.Errorf("%s for %q: %d %s", path, user, w.Code, w.Body)
			}
		}
	}
	if calls := fp.callList()[before:]; len(calls) != 0 {
		t.Errorf("Vault called for refused names: %v", calls)
	}
	// The CN is compared exactly: alice can't revoke a CN "Alice".
	b, _ := json.Marshal(map[string]string{"user": "alice", "serial": upperSerial})
	if w := postAction(s, "/internal/certificates/revoke", string(b)); w.Code != http.StatusNotFound {
		t.Errorf("alice revoking CN Alice: %d", w.Code)
	}
	if fp.certs[mountYubiKey][hubSerial].revoked || fp.certs[mountBrowser][upperSerial].revoked || fp.count("PUT ") != 0 {
		t.Errorf("something was revoked: %v", fp.callList())
	}
}

// The signed leaf must certify the CSR's key, on both paths (review M4).
func TestSignedKeyMatchesCSR(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	fp.swapKey = true
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := json.Marshal(map[string]string{"user": "alice", "csr": csrPEMFor(t, "alice", key)})
	if w := postAction(s, "/internal/yubikey-certificates", string(b)); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "BEGIN") {
		t.Errorf("yubikey issue with another key: %d %s", w.Code, w.Body)
	}
	cur, _ := fp.issue(mountYubiKey, "alice", &key.PublicKey, time.Now().Add(24*time.Hour), false)
	if w := postAction(s, "/internal/yubikey-certificates/renew", renewBody("alice", cur, csrPEMFor(t, "alice", key))); w.Code != http.StatusServiceUnavailable {
		t.Errorf("renewal with another key: %d %s", w.Code, w.Body)
	}
	if w := postAction(s, "/internal/browser-certificates", certRoutes["/internal/browser-certificates"]); w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "p12") {
		t.Errorf("browser create with another key: %d %s", w.Code, w.Body)
	}
	fp.swapKey = false
	if w := postAction(s, "/internal/yubikey-certificates", string(b)); w.Code != http.StatusCreated {
		t.Errorf("matching key: %d %s", w.Code, w.Body)
	}
}

// A refusal never echoes the presented certificate's CN (review M3).
func TestRenewRefusalNoEcho(t *testing.T) {
	fp, cfg := newFakePKI(t)
	s := browserService(t, cfg)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobs, _ := fp.issue(mountYubiKey, "bob-secret-cn", &key.PublicKey, time.Now().Add(24*time.Hour), false)
	w := postAction(s, "/internal/yubikey-certificates/renew", renewBody("alice", bobs, csrPEMFor(t, "alice", key)))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "bob-secret-cn") {
		t.Errorf("foreign certificate: %d %s", w.Code, w.Body)
	}
}
