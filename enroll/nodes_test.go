package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
)

// nodePKI is the fake Vault with pki_node: its own self-signed root, never
// signed by the fake "pki" root (ruling P1).
func nodePKI(t *testing.T) (*fakePKI, *inviteService) {
	t.Helper()
	fp, cfg := newFakePKI(t)
	fp.cas[mountNode] = newFakeCA(t, "example.org Node CA", nil)
	fp.certs[mountNode] = map[string]*fakeIssued{}
	s, _ := testInvites(t)
	s.signNode = cfg.signNodeCert
	s.revokeNode = cfg.revokeNodeCert
	return fp, s
}

type csrOpts struct {
	cn    string
	dns   []string
	ips   []net.IP
	email []string
	uris  []*url.URL
	org   bool
	rsa   bool
}

func makeNodeCSR(t *testing.T, o csrOpts) string {
	t.Helper()
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: o.cn}, DNSNames: o.dns, IPAddresses: o.ips, EmailAddresses: o.email, URIs: o.uris}
	if o.org {
		tpl.Subject.Organization = []string{"x"}
	}
	var key any
	if o.rsa {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		key = k
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key = k
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func nodeSignBody(role, cn, csr string) string {
	b, _ := json.Marshal(map[string]string{"role": role, "common_name": cn, "csr": csr})
	return string(b)
}

func TestNodeSignRoleAndCN(t *testing.T) {
	fp, s := nodePKI(t)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	var csrs []string

	sign := func(role, cn, csr string) (int, map[string]string) {
		csrs = append(csrs, csr)
		w := postAction(s, "/internal/nodes/sign", nodeSignBody(role, cn, csr))
		var out map[string]string
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}

	// node-worker: client + server, CN the worker's name, under pki_node.
	csr := makeNodeCSR(t, csrOpts{cn: "w1.node.portcullis.internal"})
	code, out := sign(roleNodeWorker, "w1.node.portcullis.internal", csr)
	if code != 201 {
		t.Fatalf("node-worker: %d %v", code, out)
	}
	for _, k := range []string{"certificate", "serial", "not_after", "ca"} {
		if out[k] == "" {
			t.Fatalf("answer lacks %s: %v", k, out)
		}
	}
	leafB, _ := pem.Decode([]byte(out["certificate"]))
	caB, _ := pem.Decode([]byte(out["ca"]))
	leaf, _ := x509.ParseCertificate(leafB.Bytes)
	ca, _ := x509.ParseCertificate(caB.Bytes)
	if leaf.Subject.CommonName != "w1.node.portcullis.internal" || !bytes.Equal(ca.Raw, fp.cas[mountNode].cert.Raw) {
		t.Fatalf("leaf %s ca %s", leaf.Subject, ca.Subject)
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("the node CA isn't self-signed: %v", err)
	}
	if ca.CheckSignatureFrom(fp.root.cert) == nil {
		t.Fatal("the node CA is signed by the Portcullis root")
	}

	// node-control: hub.control only.
	if code, out := sign(roleNodeControl, "hub.control", makeNodeCSR(t, csrOpts{cn: "hub.control"})); code != 201 {
		t.Fatalf("node-control: %d %v", code, out)
	}

	for _, c := range []struct {
		name, role, cn string
		csr            csrOpts
		want           int
	}{
		{"node-link", "node-link", "link.control", csrOpts{cn: "link.control"}, 403},
		{"another mount's role", "client-cert", "alice", csrOpts{cn: "alice"}, 403},
		{"empty role", "", "hub.control", csrOpts{cn: "hub.control"}, 403},
		{"worker role, control CN", roleNodeWorker, "hub.control", csrOpts{cn: "hub.control"}, 400},
		{"control role, worker CN", roleNodeControl, "w1.node.portcullis.internal", csrOpts{cn: "w1.node.portcullis.internal"}, 400},
		{"control role, link CN", roleNodeControl, "link.control", csrOpts{cn: "link.control"}, 400},
		{"reserved primary", roleNodeWorker, "primary.node.portcullis.internal", csrOpts{cn: "primary.node.portcullis.internal"}, 400},
		{"two labels", roleNodeWorker, "a.b.node.portcullis.internal", csrOpts{cn: "a.b.node.portcullis.internal"}, 400},
		{"uppercase", roleNodeWorker, "W1.node.portcullis.internal", csrOpts{cn: "W1.node.portcullis.internal"}, 400},
		{"bare domain", roleNodeWorker, "node.portcullis.internal", csrOpts{cn: "node.portcullis.internal"}, 400},
		{"trailing dot", roleNodeWorker, "w1.node.portcullis.internal.", csrOpts{cn: "w1.node.portcullis.internal."}, 400},
		{"csr names another CN", roleNodeWorker, "w1.node.portcullis.internal", csrOpts{cn: "w2.node.portcullis.internal"}, 400},
		{"csr subject has more", roleNodeControl, "hub.control", csrOpts{cn: "hub.control", org: true}, 400},
		{"dns alt name", roleNodeWorker, "w1.node.portcullis.internal", csrOpts{cn: "w1.node.portcullis.internal", dns: []string{"w1.node.portcullis.internal"}}, 400},
		{"other dns alt name", roleNodeControl, "hub.control", csrOpts{cn: "hub.control", dns: []string{"hub.example.org"}}, 400},
		{"ip alt name", roleNodeWorker, "w1.node.portcullis.internal", csrOpts{cn: "w1.node.portcullis.internal", ips: []net.IP{net.ParseIP("10.214.0.10")}}, 400},
		{"email alt name", roleNodeControl, "hub.control", csrOpts{cn: "hub.control", email: []string{"a@example.org"}}, 400},
		{"uri alt name", roleNodeControl, "hub.control", csrOpts{cn: "hub.control", uris: []*url.URL{{Scheme: "spiffe", Host: "x"}}}, 400},
		{"rsa key", roleNodeControl, "hub.control", csrOpts{cn: "hub.control", rsa: true}, 400},
	} {
		if code, out := sign(c.role, c.cn, makeNodeCSR(t, c.csr)); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, out, c.want)
		}
	}
	good := makeNodeCSR(t, csrOpts{cn: "hub.control"})
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"two csr blocks": {nodeSignBody(roleNodeControl, "hub.control", good+good), 400},
		"not a csr":      {nodeSignBody(roleNodeControl, "hub.control", "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"), 400},
		"unknown field":  {strings.TrimSuffix(nodeSignBody(roleNodeControl, "hub.control", good), "}") + `,"alt_names":"x"}`, 400},
		"ttl field":      {strings.TrimSuffix(nodeSignBody(roleNodeControl, "hub.control", good), "}") + `,"ttl":"87600h"}`, 400},
		"too large":      {nodeSignBody(roleNodeControl, "hub.control", good+strings.Repeat("A", 64<<10)), 413},
	} {
		csrs = append(csrs, good)
		if w := postAction(s, "/internal/nodes/sign", c.body); w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", name, w.Code, w.Body, c.want)
		}
	}
	// Bearer and listener.
	if w := do(s.apiHandler(false), "POST", "/internal/nodes/sign", nodeSignBody(roleNodeControl, "hub.control", good), nil); w.Code != 401 {
		t.Errorf("no bearer: %d", w.Code)
	}
	if w := do(s.apiHandler(true), "POST", "/internal/nodes/sign", nodeSignBody(roleNodeControl, "hub.control", good), nil); w.Code != 404 {
		t.Errorf("loopback listener: %d", w.Code)
	}
	if w := do(s.apiHandler(false), "GET", "/internal/nodes/sign", "", map[string]string{"Authorization": "Bearer " + testAPISecret}); w.Code != 405 {
		t.Errorf("GET: %d", w.Code)
	}

	// Vault saw exactly the two good signs, on pki_node's two roles.
	if n := fp.count("PUT pki_node/sign/") + fp.count("POST pki_node/sign/"); n != 2 {
		t.Errorf("%d pki_node signs: %v", n, fp.callList())
	}
	for _, c := range fp.callList() {
		if strings.Contains(c, "node-link") || strings.Contains(c, "pki_int/sign") || strings.Contains(c, "pki_file/sign") {
			t.Errorf("unexpected Vault call %s", c)
		}
	}
	for _, body := range fp.signs {
		for k := range body {
			if k != "csr" && k != "common_name" && k != "ttl" {
				t.Errorf("sign parameter %s", k)
			}
		}
		if body["ttl"] != nodeTTL {
			t.Errorf("ttl %v", body["ttl"])
		}
	}
	// No CSR (or any part of one) in the log.
	l := logs.String()
	if strings.Contains(l, "-----BEGIN") {
		t.Fatalf("PEM in the log:\n%s", l)
	}
	for _, c := range csrs {
		blk, _ := pem.Decode([]byte(c))
		if blk == nil {
			continue
		}
		body := strings.ReplaceAll(strings.SplitN(c, "\n", 2)[1], "\n", "")
		if len(body) > 40 && strings.Contains(l, body[10:40]) {
			t.Fatalf("CSR bytes in the log:\n%s", l)
		}
	}
}

func TestNodeRevoke(t *testing.T) {
	fp, s := nodePKI(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, serial := fp.issue(mountNode, "w1.node.portcullis.internal", &k.PublicKey, fp.cas[mountNode].cert.NotAfter, false)
	_, intSerial := fp.issue(mountYubiKey, "alice", nil, fp.cas[mountYubiKey].cert.NotAfter, false)

	revoke := func(serial string) int {
		b, _ := json.Marshal(map[string]string{"serial": serial})
		return postAction(s, "/internal/nodes/revoke", string(b)).Code
	}
	if code := revoke(strings.ToUpper(serial)); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if !fp.certs[mountNode][serial].revoked || !fp.has("GET pki_node/crl/rotate") {
		t.Fatalf("not revoked / no rotate: %v", fp.callList())
	}
	before := fp.count("PUT pki_node/revoke") + fp.count("POST pki_node/revoke")
	if code := revoke(serial); code != 204 {
		t.Fatalf("second revoke: %d", code)
	}
	if after := fp.count("PUT pki_node/revoke") + fp.count("POST pki_node/revoke"); after != before {
		t.Fatal("revoked twice")
	}
	for name, sr := range map[string]string{"unknown": "0a:0b", "not a serial": "../crl", "empty": "", "a pki_int serial": intSerial} {
		if code := revoke(sr); code != 404 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if fp.certs[mountYubiKey][intSerial].revoked {
		t.Fatal("a pki_int certificate was revoked through the node route")
	}
	if w := postAction(s, "/internal/nodes/revoke", `{"serial":"0a","user":"x"}`); w.Code != 400 {
		t.Errorf("unknown field: %d", w.Code)
	}
	if w := do(s.apiHandler(false), "POST", "/internal/nodes/revoke", `{"serial":"0a"}`, nil); w.Code != 401 {
		t.Errorf("no bearer: %d", w.Code)
	}
	if w := do(s.apiHandler(true), "POST", "/internal/nodes/revoke", `{"serial":"0a"}`, nil); w.Code != 404 {
		t.Errorf("loopback listener: %d", w.Code)
	}
	// Unwired: 503.
	s.revokeNode, s.signNode = nil, nil
	if code := revoke(serial); code != 503 {
		t.Errorf("unwired revoke: %d", code)
	}
	if w := postAction(s, "/internal/nodes/sign", nodeSignBody(roleNodeControl, "hub.control", makeNodeCSR(t, csrOpts{cn: "hub.control"}))); w.Code != 503 {
		t.Errorf("unwired sign: %d", w.Code)
	}
}
