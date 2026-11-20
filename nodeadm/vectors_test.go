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
		// BodyBytes: a body of that many bytes ('x'), for the 64 KiB limit
		// (checked before decoding).
		BodyBytes int `json:"body_bytes,omitempty"`
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

var apiKinds = map[string]int{"quorum_minimum": 409, "replica_minimum": 409, "unknown_node": 404, "proof_invalid": 403, "mesh_pending": 409, "waiting_admission": 409, "not_leader": 503}

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

// The §20.2 bodies, for the strict per-route check of the cases.
type meshPeerBody struct {
	ID         string   `json:"id"`
	Pub        string   `json:"pub"`
	Endpoint   *string  `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive  int      `json:"keepalive"`
}

type meshPlanBody struct {
	Peers   []meshPeerBody `json:"peers"`
	Forward bool           `json:"forward"`
}

type codeRequest struct {
	ServerID string       `json:"server_id"`
	Role     string       `json:"role"`
	Class    string       `json:"class"`
	Site     string       `json:"site"`
	MeshIP   string       `json:"mesh_ip"`
	Ingress  bool         `json:"ingress"`
	Storage  bool         `json:"storage"`
	Mesh     meshPlanBody `json:"mesh"`
}

type labelsRequest struct {
	Class   string `json:"class"`
	Site    string `json:"site"`
	Ingress bool   `json:"ingress"`
	Storage bool   `json:"storage"`
}

type resources struct {
	CPUm     int64 `json:"cpu_m"`
	MemBytes int64 `json:"mem_bytes"`
}

type voters struct {
	Voters  int `json:"voters"`
	Healthy int `json:"healthy"`
}

type snapshotBody struct {
	V       int    `json:"v"`
	TakenAt string `json:"taken_at"`
	Nodes   []struct {
		Name          string            `json:"name"`
		Role          string            `json:"role"`
		Ready         bool              `json:"ready"`
		NotReadySince *string           `json:"not_ready_since"`
		Unschedulable bool              `json:"unschedulable"`
		Allocatable   resources         `json:"allocatable"`
		Labels        map[string]string `json:"labels"`
		Taints        []struct {
			Key    string `json:"key"`
			Value  string `json:"value"`
			Effect string `json:"effect"`
		} `json:"taints"`
		Addresses struct {
			Mesh   string   `json:"mesh"`
			LAN    []string `json:"lan"`
			Public []string `json:"public"`
		} `json:"addresses"`
		TraefikReady bool `json:"traefik_ready"`
		FencingReady bool `json:"fencing_ready"`
		EtcdMember   bool `json:"etcd_member"`
	} `json:"nodes"`
	Enrolling []struct {
		ID     string `json:"id"`
		Role   string `json:"role"`
		Class  string `json:"class"`
		Site   string `json:"site"`
		MeshIP string `json:"mesh_ip"`
		Mesh   struct {
			Pub    string  `json:"pub"`
			LAN    *string `json:"lan"`
			Public *string `json:"public"`
		} `json:"mesh"`
		EnrolledAt string `json:"enrolled_at"`
	} `json:"enrolling"`
	Pods []struct {
		Name             string    `json:"name"`
		Namespace        string    `json:"namespace"`
		Node             string    `json:"node"`
		Priority         int       `json:"priority"`
		PriorityClass    string    `json:"priority_class"`
		PreemptionPolicy string    `json:"preemption_policy"`
		Requests         resources `json:"requests"`
		Tolerations      []struct {
			Key      string `json:"key"`
			Operator string `json:"operator"`
			Value    string `json:"value"`
			Effect   string `json:"effect"`
			Seconds  *int64 `json:"seconds"`
		} `json:"tolerations"`
		RequiredAffinity [][]struct {
			Key      string   `json:"key"`
			Operator string   `json:"operator"`
			Values   []string `json:"values"`
		} `json:"required_affinity"`
		AntiAffinityHost bool `json:"anti_affinity_host"`
		SpreadHost       bool `json:"spread_host"`
		DaemonSet        bool `json:"daemonset"`
		Set              *struct {
			Name string `json:"name"`
			Min  int    `json:"min"`
		} `json:"set"`
	} `json:"pods"`
	Quorum struct {
		Etcd     voters `json:"etcd"`
		Vault    voters `json:"vault"`
		Sentinel voters `json:"sentinel"`
	} `json:"quorum"`
	Postgres struct {
		Instances    int     `json:"instances"`
		SyncStandbys int     `json:"sync_standbys"`
		Primary      *string `json:"primary"`
	} `json:"postgres"`
	Volumes []struct {
		Name          string  `json:"name"`
		Robustness    string  `json:"robustness"`
		DegradedSince *string `json:"degraded_since"`
	} `json:"volumes"`
	Errors []string `json:"errors"`
}

type empty struct{}

// routeBodies: the request body type of a well-formed request and the
// answer type of a success, per route (nil = no body).
var routeBodies = map[string][2]func() any{
	"POST /v1/codes": {func() any { return &codeRequest{} }, func() any {
		return &struct {
			Code      string `json:"code"`
			ExpiresAt string `json:"expires_at"`
		}{}
	}},
	"GET /v1/cluster":              {nil, func() any { return &snapshotBody{} }},
	"PUT /v1/nodes/{id}/labels":    {func() any { return &labelsRequest{} }, nil},
	"POST /v1/nodes/{id}/cordon":   {func() any { return &empty{} }, nil},
	"POST /v1/nodes/{id}/uncordon": {func() any { return &empty{} }, nil},
	"POST /v1/nodes/{id}/drain":    {func() any { return &empty{} }, nil},
	"POST /node/v1/nonce": {func() any {
		return &struct {
			ServerID string `json:"server_id"`
		}{}
	}, func() any {
		return &struct {
			Nonce string `json:"nonce"`
		}{}
	}},
	"POST /node/v1/enrol": {func() any {
		return &struct {
			ServerID string `json:"server_id"`
			Nonce    string `json:"nonce"`
			Proof    string `json:"proof"`
			CSR      string `json:"csr"`
			Mesh     struct {
				Pub    string  `json:"pub"`
				LAN    *string `json:"lan"`
				Public *string `json:"public"`
			} `json:"mesh"`
		}{}
	}, func() any {
		return &struct {
			Certificate string       `json:"certificate"`
			CA          string       `json:"ca"`
			NotAfter    string       `json:"not_after"`
			Mesh        meshPlanBody `json:"mesh"`
		}{}
	}},
	"POST /node/v1/join": {func() any {
		return &struct {
			ServerID string         `json:"server_id"`
			RTTms    map[string]int `json:"rtt_ms"`
		}{}
	}, func() any {
		return &struct {
			Role      string   `json:"role"`
			ServerURL string   `json:"server_url"`
			Token     string   `json:"token"`
			Flags     []string `json:"flags"`
		}{}
	}},
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
	tooBig := map[bool]bool{}
	for _, c := range vs.Cases {
		routes[c.Route]++
		if c.Request.BodyBytes > 0 {
			if c.Request.BodyBytes <= 64<<10 || c.Response.Status != 413 {
				t.Errorf("%s: a %d-byte body answers %d", c.Name, c.Request.BodyBytes, c.Response.Status)
			}
			tooBig[strings.HasPrefix(c.Route, "POST /node/")] = true
		}
		// A well-formed request (any answer but 400 / 413) and a success
		// carry the route's exact body shape.
		rb := routeBodies[c.Route]
		reqBody := c.Request.Body
		if c.Request.BodyText != nil {
			reqBody = json.RawMessage(*c.Request.BodyText)
		}
		if rb[0] != nil && c.Response.Status != 400 && c.Response.Status != 413 {
			if err := strictVectors(reqBody, rb[0]()); err != nil {
				t.Errorf("%s: request body: %v", c.Name, err)
			}
		}
		if c.Response.Status < 300 {
			if rb[1] == nil {
				if string(c.Response.Body) != "null" {
					t.Errorf("%s: a success with a body on a route that answers none", c.Name)
				}
			} else if err := strictVectors(c.Response.Body, rb[1]()); err != nil {
				t.Errorf("%s: answer body: %v", c.Name, err)
			}
		}
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
	if !tooBig[false] || !tooBig[true] {
		t.Error("a 413 case is needed on both listeners (internal and public)")
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
