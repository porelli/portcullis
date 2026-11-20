package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"regexp"
	"strings"
	"testing"
)

// nodeadm_api_vectors.json (contract §20.2; byte-copied to the Hub's
// internal/nodeadm/testdata/). A case is one request and its answer;
// client is the caller's certificate (hub.control, frontdoor.control,
// other-ca, or none for no certificate / the public paths), leader whether
// nodeadm holds its Lease, state a short description of the fixture the
// replay sets up first. A body is JSON (body) or raw text (body_text, for
// malformed and signed bodies), never both.
type apiCase struct {
	Name    string `json:"name"`
	Route   string `json:"route"`
	Client  string `json:"client"`
	Leader  bool   `json:"leader"`
	State   string `json:"state"`
	Request struct {
		Method   string            `json:"method"`
		Path     string            `json:"path"`
		Headers  map[string]string `json:"headers"`
		Body     json.RawMessage   `json:"body"`
		BodyText *string           `json:"body_text"`
	} `json:"request"`
	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers"`
		Body    json.RawMessage   `json:"body"`
	} `json:"response"`
}

type apiVectors struct {
	V     int       `json:"v"`
	Cases []apiCase `json:"cases"`
	Proof []struct {
		Name          string `json:"name"`
		Secret        string `json:"secret"`
		Nonce         string `json:"nonce"`
		ServerID      string `json:"server_id"`
		SPKISHA256    string `json:"spki_sha256"`
		WantKeySHA256 string `json:"want_key_sha256"`
		WantProof     string `json:"want_proof"`
	} `json:"proof"`
	SignedRequest []struct {
		Name           string `json:"name"`
		ServerID       string `json:"server_id"`
		Method         string `json:"method"`
		Path           string `json:"path"`
		Time           string `json:"time"`
		Nonce          string `json:"nonce"`
		Body           string `json:"body"`
		WantBodySHA256 string `json:"want_body_sha256"`
		WantCanonical  string `json:"want_canonical"`
	} `json:"signed_request"`
	PKI struct {
		CAPEM       string `json:"ca_pem"`
		CASHA256    string `json:"ca_sha256"`
		NodeCertPEM string `json:"node_cert_pem"`
		NodeCSRPEM  string `json:"node_csr_pem"`
	} `json:"pki"`
	JoinTokens []struct {
		Token string `json:"token"`
		OK    bool   `json:"ok"`
	} `json:"join_tokens"`
}

// Every route of §20.2 and every wire kind.
var apiRoutes = []string{
	"POST /v1/codes", "GET /v1/cluster", "PUT /v1/nodes/{id}/labels", "POST /v1/nodes/{id}/cordon", "POST /v1/nodes/{id}/uncordon",
	"POST /v1/nodes/{id}/drain", "DELETE /v1/nodes/{id}?mode=cooperative", "DELETE /v1/nodes/{id}?mode=revoke",
	"GET /node/join.sh", "GET /node/nodeagent-{arch}", "POST /node/v1/nonce", "POST /node/v1/enrol", "POST /node/v1/join",
}

var apiKinds = map[string]int{"quorum_minimum": 409, "replica_minimum": 409, "unknown_node": 404, "proof_invalid": 403, "mesh_pending": 409, "not_leader": 503}

var k10 = regexp.MustCompile(`^K10[0-9a-f]{64}::.+$`)

func pemDER(t *testing.T, s string) []byte {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		t.Fatalf("not PEM: %.40q", s)
	}
	return b.Bytes
}

func b64u(t *testing.T, s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("not base64url: %v", err)
	}
	return b
}

type canon struct {
	ServerID   string `json:"server_id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Time       string `json:"time"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
}

// TestAPIVectorsShape: the file decodes strictly; every route and every
// error kind has a case with its status; errors are ≤ 200 characters and
// carry a kind only from the table; the proof, the canonical signed bytes,
// the join case's signature and the K10 token rule are consistent.
func TestAPIVectorsShape(t *testing.T) {
	b, err := os.ReadFile("testdata/nodeadm_api_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs apiVectors
	if err := strictVectors(b, &vs); err != nil {
		t.Fatal(err)
	}
	routes, kinds := map[string]int{}, map[string]int{}
	for _, c := range vs.Cases {
		routes[c.Route]++
		if c.Request.BodyText != nil && len(c.Request.Body) > 0 && string(c.Request.Body) != "null" {
			t.Errorf("%s: both body and body_text", c.Name)
		}
		if c.Response.Status >= 400 && string(c.Response.Body) != "null" {
			var e struct {
				Error string `json:"error"`
				Kind  string `json:"kind,omitempty"`
			}
			if err := strictVectors(c.Response.Body, &e); err != nil || e.Error == "" || len(e.Error) > 200 {
				t.Errorf("%s: error body %s", c.Name, c.Response.Body)
			}
			if e.Kind != "" {
				if st, ok := apiKinds[e.Kind]; !ok || st != c.Response.Status {
					t.Errorf("%s: kind %q with status %d", c.Name, e.Kind, c.Response.Status)
				}
				kinds[e.Kind]++
			}
			for _, secret := range []string{"K10", "BEGIN", "pcj2."} {
				if strings.Contains(e.Error, secret) {
					t.Errorf("%s: the error carries %q", c.Name, secret)
				}
			}
		}
	}
	for _, r := range apiRoutes {
		if routes[r] == 0 {
			t.Errorf("no case for %s", r)
		}
	}
	if len(routes) != len(apiRoutes) {
		t.Errorf("routes %v", routes)
	}
	for k := range apiKinds {
		if kinds[k] == 0 {
			t.Errorf("no case for kind %s", k)
		}
	}
	// The proof (§20.2): HMAC-SHA256(key = sha256(secret), "portcullis-node-enrol-v1" ‖ nonce ‖ server_id ‖ sha256(SPKI)).
	for _, p := range vs.Proof {
		key := sha256.Sum256(b64u(t, p.Secret))
		spki, _ := hex.DecodeString(p.SPKISHA256)
		m := hmac.New(sha256.New, key[:])
		m.Write([]byte("portcullis-node-enrol-v1"))
		m.Write(b64u(t, p.Nonce))
		m.Write([]byte(p.ServerID))
		m.Write(spki)
		if hex.EncodeToString(key[:]) != p.WantKeySHA256 || base64.RawURLEncoding.EncodeToString(m.Sum(nil)) != p.WantProof {
			t.Errorf("proof %s doesn't match", p.Name)
		}
	}
	csr, err := x509.ParseCertificateRequest(pemDER(t, vs.PKI.NodeCSRPEM))
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	if len(vs.Proof) == 0 || vs.Proof[0].SPKISHA256 != hex.EncodeToString(spki[:]) {
		t.Error("the proof isn't over the CSR's SPKI")
	}
	// The canonical signed bytes (§20.2 "The signed join request").
	for _, s := range vs.SignedRequest {
		sum := sha256.Sum256([]byte(s.Body))
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.Encode(canon{s.ServerID, s.Method, s.Path, s.Time, s.Nonce, hex.EncodeToString(sum[:])})
		if hex.EncodeToString(sum[:]) != s.WantBodySHA256 || strings.TrimSuffix(buf.String(), "\n") != s.WantCanonical {
			t.Errorf("signed request %s: canonical bytes differ", s.Name)
		}
	}
	// The join case's signature verifies with the node certificate, which
	// the CA signed; the CA's sha256 is the join code's ca_sha256.
	ca, err := x509.ParseCertificate(pemDER(t, vs.PKI.CAPEM))
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(ca.Raw); hex.EncodeToString(sum[:]) != vs.PKI.CASHA256 {
		t.Error("ca_sha256 isn't the CA's")
	}
	node, err := x509.ParseCertificate(pemDER(t, vs.PKI.NodeCertPEM))
	if err != nil || node.CheckSignatureFrom(ca) != nil || node.Subject.CommonName != "n4.cluster.portcullis.internal" {
		t.Fatalf("the node certificate: %v", err)
	}
	signed := 0
	for _, c := range vs.Cases {
		if c.Route != "POST /node/v1/join" || c.Response.Status != 200 {
			continue
		}
		signed++
		der, _ := base64.StdEncoding.DecodeString(c.Request.Headers["Portcullis-Node-Cert"])
		sig := b64u(t, c.Request.Headers["Portcullis-Node-Signature"])
		body := sha256.Sum256([]byte(*c.Request.BodyText))
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.Encode(canon{"n4", c.Request.Method, c.Request.Path, c.Request.Headers["Portcullis-Node-Time"], c.Request.Headers["Portcullis-Node-Nonce"], hex.EncodeToString(body[:])})
		digest := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
		if !bytes.Equal(der, node.Raw) || !ecdsa.VerifyASN1(node.PublicKey.(*ecdsa.PublicKey), digest[:], sig) {
			t.Errorf("%s: the signature doesn't verify", c.Name)
		}
		var ans struct {
			Token string `json:"token"`
		}
		json.Unmarshal(c.Response.Body, &ans)
		if !k10.MatchString(ans.Token) {
			t.Errorf("%s: token not in the K10 form", c.Name)
		}
	}
	if signed == 0 {
		t.Error("no successful join case")
	}
	for _, j := range vs.JoinTokens {
		if k10.MatchString(j.Token) != j.OK {
			t.Errorf("token %.20q: ok %v", j.Token, j.OK)
		}
	}
}
