package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// ── the enrolment flow, as the nodeagent runs it ──

type joiner struct {
	id     string
	code   string
	jc     joinCodeV2
	key    *ecdsa.PrivateKey
	csrPEM string
	cert   *x509.Certificate
}

func decodeCode(t testing.TB, code string) joinCodeV2 {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, "pcj2."))
	if err != nil {
		t.Fatal(err)
	}
	var jc joinCodeV2
	if err := json.Unmarshal(b, &jc); err != nil {
		t.Fatal(err)
	}
	return jc
}

func (h *harness) issue(t testing.TB, id, role, class, site, mesh string) *joiner {
	pub := "198.51.100.1:51830"
	req := CodeReq{ServerID: id, Role: role, Class: class, Site: site, MeshIP: mesh, Ingress: true,
		Mesh: MeshPlan{Peers: []MeshPeer{{ID: "n1", Pub: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Endpoint: &pub,
			AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25}}}}
	w := h.internal(clientHub, "POST", "/v1/codes", req)
	if w.Code != 201 {
		t.Fatalf("codes: %d %s", w.Code, w.Body)
	}
	var ans struct{ Code string }
	json.Unmarshal(w.Body.Bytes(), &ans)
	j := &joiner{id: id, code: ans.Code, jc: decodeCode(t, ans.Code)}
	j.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: id + "." + clusterDomain}}, j.key)
	j.csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	return j
}

func (h *harness) nonce(t testing.TB, id string) string {
	w := h.public("POST", "/node/v1/nonce", []byte(`{"server_id":"`+id+`"}`), nil)
	var ans struct{ Nonce string }
	json.Unmarshal(w.Body.Bytes(), &ans)
	return ans.Nonce
}

func (j *joiner) proof(nonce string) string {
	secret, _ := base64.RawURLEncoding.DecodeString(j.jc.Secret)
	key := sha256.Sum256(secret)
	b, _ := pem.Decode([]byte(j.csrPEM))
	csr, _ := x509.ParseCertificateRequest(b.Bytes)
	n, _ := base64.RawURLEncoding.DecodeString(nonce)
	return base64.RawURLEncoding.EncodeToString(proofFor(key[:], n, j.id, sha256.Sum256(csr.RawSubjectPublicKeyInfo)))
}

func (h *harness) enrol(t testing.TB, j *joiner, proof string) *httptest.ResponseRecorder {
	nonce := h.nonce(t, j.id)
	if proof == "" {
		proof = j.proof(nonce)
	}
	pub := "203.0.113.9:51830"
	body, _ := json.Marshal(enrolReq{ServerID: j.id, Nonce: nonce, Proof: proof, CSR: j.csrPEM,
		Mesh: MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", Public: &pub}})
	w := h.public("POST", "/node/v1/enrol", body, nil)
	if w.Code == 200 {
		var ans struct{ Certificate string }
		json.Unmarshal(w.Body.Bytes(), &ans)
		b, _ := pem.Decode([]byte(ans.Certificate))
		j.cert, _ = x509.ParseCertificate(b.Bytes)
	}
	return w
}

func (h *harness) join(t testing.TB, j *joiner, rtt map[string]int) *httptest.ResponseRecorder {
	if !h.noAutoAdmit {
		h.syncParams(t)
	}
	body, _ := json.Marshal(joinReq{ServerID: j.id, RTTms: rtt})
	hdr := map[string]string{}
	if j.cert != nil {
		hdr = signedHeaders(j.cert, j.key, j.id, "/node/v1/join", body, h.s.now())
	}
	return h.public("POST", "/node/v1/join", body, hdr)
}

var nearRTT = map[string]int{"n1": 3, "n2": 4, "n3": 5}

// TestEnrolNeedsProofThenCert: no enrolment → no join; a wrong HMAC →
// proof_invalid (the code kept); the right one burns it; its replay →
// proof_invalid logged code_used; after 15 min → logged code_expired.
func TestEnrolNeedsProofThenCert(t *testing.T) {
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	// A join without an enrolment: a valid pki_node certificate, no record.
	c, k := h.ca.client("n4." + clusterDomain)
	if w := h.join(t, &joiner{id: "n4", cert: c, key: k}, nearRTT); w.Code != 403 {
		t.Fatalf("join without enrol: %d", w.Code)
	}
	bad := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if w := h.enrol(t, j, bad); w.Code != 403 || !strings.Contains(w.Body.String(), `"kind":"proof_invalid"`) {
		t.Fatalf("wrong proof: %d %s", w.Code, w.Body)
	}
	if st := h.state(t); st.Codes["n4"].Used || st.Codes["n4"].KeySHA256 == "" {
		t.Fatal("a wrong proof burnt the code")
	}
	if w := h.enrol(t, j, ""); w.Code != 200 {
		t.Fatalf("enrol: %d %s", w.Code, w.Body)
	}
	if st := h.state(t); !st.Codes["n4"].Used || st.Codes["n4"].KeySHA256 != "" {
		t.Fatal("the used code keeps its hash")
	}
	j.cert = nil
	if w := h.enrol(t, j, ""); w.Code != 403 || !strings.Contains(h.logs.String(), "kind=code_used") {
		t.Fatalf("replay: %d, logs %s", w.Code, h.logs)
	}
	j5 := h.issue(t, "n5", "agent", "home", "main", "10.215.0.5")
	h.setNow(vecNow.Add(16 * time.Minute))
	if w := h.enrol(t, j5, ""); w.Code != 403 || !strings.Contains(h.logs.String(), "kind=code_expired") {
		t.Fatalf("expired: %d", w.Code)
	}
	if !jsonEqual(h.enrol(t, j5, "").Body.Bytes(), []byte(`{"error":"the join code's proof doesn't match","kind":"proof_invalid"}`)) {
		t.Fatal("not the no-oracle answer")
	}
	// The sweep deletes an expired code's hash.
	if err := h.s.sweepCodes(context.Background()); err != nil || h.state(t).Codes["n5"].KeySHA256 != "" {
		t.Fatal("the expired code's hash is still stored")
	}
}

// TestEnrolCASOneWinner: two enrolments of one code at once: one wins.
func TestEnrolCASOneWinner(t *testing.T) {
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jj := *j
			codes[i] = h.enrol(t, &jj, "").Code
		}()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d enrolments of one code succeeded: %v", ok, codes)
	}
}

// TestJoinMaterialOnlyOverMTLS: the join material only for a request
// signed by the enrolled node-cluster key (the contract's signed request,
// ruling C1): unsigned → 403; an agent gets a bootstrap token (TTL ≤ 15
// min, authentication only, the k3s bootstrap group), a server the server
// token, both in the K10 form.
func TestJoinMaterialOnlyOverMTLS(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	h.enrol(t, j, "")
	body, _ := json.Marshal(joinReq{ServerID: "n4", RTTms: nearRTT})
	if w := h.public("POST", "/node/v1/join", body, nil); w.Code != 403 {
		t.Fatalf("unsigned join: %d", w.Code)
	}
	// Another key under the enrolled certificate.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if w := h.public("POST", "/node/v1/join", body, signedHeaders(j.cert, other, "n4", "/node/v1/join", body, h.s.now())); w.Code != 403 {
		t.Fatalf("join signed by another key: %d", w.Code)
	}
	w := h.join(t, j, nearRTT)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("join: %d %s", w.Code, w.Body)
	}
	var ans joinAnswer
	json.Unmarshal(w.Body.Bytes(), &ans)
	m := k10Re.FindStringSubmatch(ans.Token)
	if m == nil || m[1] != caHash(testServerToken) || ans.Role != "agent" || strings.Contains(ans.Token, "server:") {
		t.Fatalf("agent token %q", ans.Token)
	}
	l, _ := h.kube.CoreV1().Secrets(bootstrapNS).List(ctx, metav1.ListOptions{})
	if len(l.Items) != 1 {
		t.Fatalf("%d bootstrap Secrets", len(l.Items))
	}
	sec := l.Items[0]
	exp, _ := time.Parse(time.RFC3339, sec.StringData["expiration"])
	if sec.Type != corev1.SecretTypeBootstrapToken || exp.After(h.s.now().Add(15*time.Minute)) ||
		sec.StringData["auth-extra-groups"] != bootstrapGroup || sec.StringData["usage-bootstrap-authentication"] != "true" ||
		sec.StringData["usage-bootstrap-signing"] != "" || !strings.HasSuffix(ans.Token, "::"+sec.StringData["token-id"]+"."+sec.StringData["token-secret"]) {
		t.Fatalf("bootstrap Secret %+v", sec)
	}
	js := h.issue(t, "n5", "server", "home", "main", "10.215.0.5")
	h.enrol(t, js, "")
	w = h.join(t, js, nearRTT)
	json.Unmarshal(w.Body.Bytes(), &ans)
	if w.Code != 200 || ans.Token != testServerToken || ans.Role != "server" {
		t.Fatalf("server join: %d %+v", w.Code, ans)
	}
}

// TestJoinRefusesFarServer: the RTT cases of site_roles_vectors.json, and
// a server 101 ms away gets the text and no k3s material.
func TestJoinRefusesFarServer(t *testing.T) {
	b, err := os.ReadFile("testdata/site_roles_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string `json:"name"`
		Cluster []struct {
			ID      string `json:"id"`
			Role    string `json:"role"`
			Healthy bool   `json:"healthy"`
		} `json:"cluster"`
		New struct {
			RTTms    map[string]int `json:"rtt_ms"`
			Override string         `json:"override"`
		} `json:"new"`
		Want *struct {
			Role string `json:"role"`
		} `json:"want"`
		WantError string `json:"want_error"`
	}
	json.Unmarshal(b, &cases)
	n := 0
	for _, c := range cases {
		var servers []string
		for _, m := range c.Cluster {
			if m.Role == "server" && m.Healthy {
				servers = append(servers, m.ID)
			}
		}
		roles := []string{}
		switch {
		case c.Want != nil:
			roles = append(roles, c.Want.Role)
		case strings.Contains(c.WantError, "servers need"):
			roles = append(roles, "server")
		case strings.Contains(c.WantError, "agents need"):
			roles = append(roles, "agent")
		case strings.HasPrefix(c.WantError, "no mesh answer"):
			roles = append(roles, "server", "agent")
		default:
			continue
		}
		for _, r := range roles {
			n++
			err := checkRTT(r, servers, c.New.RTTms)
			if got := fmt.Sprint(err); (c.WantError == "" && err != nil) || (c.WantError != "" && got != c.WantError) {
				t.Errorf("%s (%s): %v, want %q", c.Name, r, err, c.WantError)
			}
		}
	}
	if n < 10 {
		t.Fatalf("only %d RTT cases", n)
	}
	h := newHarness(t)
	j := h.issue(t, "n5", "server", "home", "main", "10.215.0.5")
	h.enrol(t, j, "")
	w := h.join(t, j, map[string]int{"n1": 101, "n2": 4, "n3": 5})
	if w.Code != 409 || !jsonEqual(w.Body.Bytes(), []byte(`{"error":"too far for one cluster: 101 ms (servers need 100 ms or less)"}`)) {
		t.Fatalf("far server: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "K10") || h.state(t).Nodes["n5"].ServerToken {
		t.Fatal("a refused server got the token")
	}
	// A site with no reachable node: no material either.
	j6 := h.issue(t, "n6", "agent", "home", "edge", "10.215.0.6")
	h.enrol(t, j6, "")
	h.putState(t, func(st *nodeadmState) { st.Nodes["n6"].Mesh.Public = nil })
	w = h.join(t, j6, nearRTT)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "site edge needs one node reachable on UDP 51830 first") {
		t.Fatalf("site gateway: %d %s", w.Code, w.Body)
	}
	if l, _ := h.kube.CoreV1().Secrets(bootstrapNS).List(context.Background(), metav1.ListOptions{}); len(l.Items) != 0 {
		t.Fatal("a refused join minted a bootstrap token")
	}
}

// TestJoinFlagsEqualInitFlags: a server's join flags are the init flags of
// tests/fixtures/k3s-server-flags.txt with the documented substitutions;
// an agent's are its k3s-agent subset.
func TestJoinFlagsEqualInitFlags(t *testing.T) {
	b, err := os.ReadFile("../tests/fixtures/k3s-server-flags.txt")
	if err != nil {
		t.Fatal(err)
	}
	ip := "10.215.0.7"
	var want []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		// A joining server gets the agent token in the answer (written to
		// init's --agent-token-file path).
		if l == "--cluster-init" {
			continue
		}
		l = strings.ReplaceAll(l, "10.215.0.1", ip)
		if strings.HasPrefix(l, "--node-name=") {
			l = "--node-name=n7"
		}
		want = append(want, l)
	}
	server := "https://10.215.0.1:6443"
	// Init and a joining node both register with the unlabelled taint (the
	// fixture has it; labels come from nodeadm / the CLI, R-NODELABELS).
	want = append(want, "--server="+server)
	if !slices.Contains(want, "--node-taint="+unlabelledTaint) {
		t.Fatal("the fixture lacks the unlabelled registration taint")
	}
	sort.Strings(want)
	for _, f := range want {
		if strings.HasPrefix(f, "--node-label=") || strings.HasPrefix(f, "--node-taint=portcullis.io/") {
			t.Fatalf("the fixture passes %s (R-NODELABELS)", f)
		}
	}
	rec := &nodeRecord{Role: "server", Class: "home", Site: "main", MeshIP: ip, Ingress: true, Storage: true}
	got := joinFlags(rec, "n7", server, "10.42.0.0/16")
	if !slices.Equal(got, want) {
		t.Fatalf("server flags\n got %q\nwant %q", got, want)
	}
	for _, f := range []string{"--etcd-arg=heartbeat-interval=200", "--etcd-arg=election-timeout=2000"} {
		if !slices.Contains(got, f) {
			t.Errorf("no %s", f)
		}
	}
	agentOK := []string{"--server=", "--token-file=", "--node-name=", "--node-ip=", "--node-label=", "--node-taint=", "--kubelet-arg=", "--flannel-conf=", "--flannel-iface="}
	var agentWant []string
	for _, f := range want {
		for _, p := range agentOK {
			if strings.HasPrefix(f, p) {
				agentWant = append(agentWant, f)
			}
		}
	}
	rec.Role = "agent"
	if got := joinFlags(rec, "n7", server, "10.42.0.0/16"); !slices.Equal(got, agentWant) {
		t.Fatalf("agent flags\n got %q\nwant %q", got, agentWant)
	}
	// The labels and taints nodeadm sets on the registered Node instead.
	small := &nodeRecord{Role: "agent", Class: "small", Site: "tb", MeshIP: ip}
	for _, f := range joinFlags(small, "pi-1", server, "10.42.0.0/16") {
		if strings.HasPrefix(f, "--node-label=") || strings.HasPrefix(f, "--node-taint=portcullis.io/") {
			t.Fatalf("a join flag sets %s", f)
		}
	}
	n := &corev1.Node{Spec: corev1.NodeSpec{Taints: []corev1.Taint{{Key: taintUnlabelled, Value: "true", Effect: corev1.TaintEffectNoSchedule}}}}
	p := labelPatch(n, LabelsReq{Class: "small", Site: "tb"})
	taints := p["spec"].(map[string]any)["taints"].([]corev1.Taint)
	labels := p["metadata"].(map[string]any)["labels"].(map[string]any)
	if len(taints) != 1 || taints[0].Key != taintSmall || labels["portcullis.io/storage"] != nil || labels["portcullis.io/class"] != "small" {
		t.Fatalf("small: taints %v, labels %v", taints, labels)
	}
	p = labelPatch(n, LabelsReq{Class: "cloud", Site: "edge", Storage: true})
	if l := p["metadata"].(map[string]any)["labels"].(map[string]any); l["node.longhorn.io/create-default-disk"] != nil || l["portcullis.io/storage"] != "true" {
		t.Fatalf("a storage node outside main: %v", l)
	}
}

// TestJoinCodeVectors: the code nodeadm builds is byte-for-byte the
// vector's (joincode_v2_vectors.json valid).
func TestJoinCodeVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/joincode_v2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs struct {
		Valid []struct {
			Code    string     `json:"code"`
			Decoded joinCodeV2 `json:"decoded"`
		} `json:"valid"`
	}
	json.Unmarshal(b, &vs)
	for _, v := range vs.Valid {
		got, err := encodeJoinCode(v.Decoded)
		if err != nil || got != v.Code {
			t.Errorf("%s: %v\n got %s\nwant %s", v.Decoded.ServerID, err, got, v.Code)
		}
	}
}

// secretFlow runs a full lifecycle (code, enrol, agent and server joins, a
// revocation with rotation) and answers every secret it involved and every
// answer it got.
func secretFlow(t *testing.T) (*harness, []string, [][]byte) {
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...),
		nodeSpec{"n6", "server", "home", "main", "10.215.0.6", nil, nil, true, false})...)
	var answers [][]byte
	keep := func(w *httptest.ResponseRecorder) *httptest.ResponseRecorder {
		answers = append(answers, w.Body.Bytes())
		return w
	}
	h.agents.onRotate = func(_, step, tok string) {
		h.boot.mu.Lock()
		switch step {
		case "rotate":
			h.boot.current = tok
		case "rotate-agent":
			h.boot.agent = tok
		}
		h.boot.mu.Unlock()
	}
	var secrets []string
	ja := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	js := h.issue(t, "n5", "server", "home", "main", "10.215.0.5")
	for _, j := range []*joiner{ja, js} {
		raw, _ := base64.RawURLEncoding.DecodeString(j.jc.Secret)
		sum := sha256.Sum256(raw)
		kder, _ := x509.MarshalECPrivateKey(j.key)
		secrets = append(secrets, j.code, j.jc.Secret, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]),
			hex.EncodeToString(raw), j.csrPEM, base64.StdEncoding.EncodeToString(kder))
		keep(h.enrol(t, j, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))))
		keep(h.enrol(t, j, ""))
	}
	w := keep(h.join(t, ja, map[string]int{"n1": 3, "n2": 4, "n3": 5, "n6": 4}))
	if w.Code != 200 {
		t.Fatalf("agent join: %d %s", w.Code, w.Body)
	}
	var ans joinAnswer
	json.Unmarshal(w.Body.Bytes(), &ans)
	secrets = append(secrets, ans.Token, strings.SplitN(ans.Token, "::", 2)[1])
	if _, sec, ok := strings.Cut(strings.SplitN(ans.Token, "::", 2)[1], "."); ok {
		secrets = append(secrets, sec)
	}
	keep(h.join(t, js, map[string]int{"n1": 150, "n2": 4, "n3": 5, "n6": 4}))
	keep(h.join(t, js, map[string]int{"n1": 3, "n2": 4, "n3": 5, "n6": 4}))
	secrets = append(secrets, testServerToken, "0123456789abcdef0123456789abcdef", testAgentToken, "fedcba9876543210fedcba9876543210")
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n3"] = &nodeRecord{Role: "server", Serial: "aa:bb", MeshIP: "10.215.0.3"}
	})
	keep(h.internal(clientHub, "DELETE", "/v1/nodes/n3?mode=revoke", nil))
	secrets = append(secrets, h.agents.tokens...)
	tok, _ := h.s.serverToken(context.Background())
	secrets = append(secrets, tok, strings.TrimPrefix(strings.SplitN(tok, "::", 2)[1], "server:"))
	// Refusals and malformed requests too.
	keep(h.public("POST", "/node/v1/enrol", []byte(`{"server_id":"n4","nonce":"x","proof":"`+ja.jc.Secret+`","csr":"x","mesh":{"pub":"x","lan":null,"public":null}}`), nil))
	keep(h.internal(clientHub, "POST", "/v1/codes", map[string]any{"server_id": "n9", "secret": ja.jc.Secret}))
	return h, secrets, answers
}

// TestJoinNeverLogsSecrets: no log line, error or answer of the whole flow
// carries a join secret, its hash, the code, a token or a key (an answer
// carries only what the contract puts there: the code in POST /v1/codes,
// the token in the join answer).
func TestJoinNeverLogsSecrets(t *testing.T) {
	h, secrets, answers := secretFlow(t)
	logs := h.logs.String()
	if !strings.Contains(logs, "token_id=") || !strings.Contains(logs, "step=done") {
		t.Fatalf("the flow didn't run through: %s", logs)
	}
	for _, sc := range secrets {
		if len(sc) < 8 {
			continue
		}
		if strings.Contains(logs, sc) {
			t.Errorf("a log line carries a secret (%.6s…)", sc)
		}
		for i, a := range answers {
			var e struct{ Error string }
			json.Unmarshal(a, &e)
			if e.Error != "" && strings.Contains(string(a), sc) {
				t.Errorf("answer %d (an error) carries a secret", i)
			}
			var ja joinAnswer
			json.Unmarshal(a, &ja)
			// The contract's secrets: the token, and a server's agent token.
			rest := strings.ReplaceAll(string(a), ja.Token, "")
			if ja.AgentToken != "" {
				rest = strings.ReplaceAll(rest, ja.AgentToken, "")
			}
			if ja.Token != "" && strings.Contains(rest, sc) {
				t.Errorf("join answer %d carries a secret outside its token", i)
			}
			var en struct{ Certificate, CA string }
			json.Unmarshal(a, &en)
			if en.Certificate != "" && strings.Contains(string(a), sc) {
				t.Errorf("enrol answer %d carries a secret", i)
			}
		}
	}
}

// TestTokenNeverLogged: the k3s tokens (server, bootstrap, rotated) never
// in a log line or an error (the same flow, the tokens' parts too).
func TestTokenNeverLogged(t *testing.T) {
	h, secrets, _ := secretFlow(t)
	logs := h.logs.String()
	for _, sc := range secrets {
		if strings.HasPrefix(sc, "K10") && strings.Contains(logs, strings.SplitN(sc, "::", 2)[1]) {
			t.Errorf("a token's credentials are logged")
		}
	}
	if strings.Contains(logs, "K10") {
		t.Error("a K10 token is logged")
	}
	if got := redact("x K10" + strings.Repeat("a", 64) + "::abcdef.0123456789abcdef y"); strings.Contains(got, "abcdef.") {
		t.Errorf("redact keeps %q", got)
	}
}

// TestDrainRefusesBelowMinimum: a server with 3 healthy servers →
// quorum_minimum; a PDB that keeps refusing → replica_minimum, the pod
// left in place (never force-deleted).
func TestDrainRefusesBelowMinimum(t *testing.T) {
	h := newHarness(t)
	w := h.internal(clientHub, "POST", "/v1/nodes/n1/drain", map[string]any{})
	if w.Code != 409 || !jsonEqual(w.Body.Bytes(), []byte(`{"error":"removing n1 would leave fewer than 3 servers","kind":"quorum_minimum"}`)) {
		t.Fatalf("quorum: %d %s", w.Code, w.Body)
	}
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=cooperative", nil); w.Code != 409 || !strings.Contains(w.Body.String(), "quorum_minimum") {
		t.Fatalf("cooperative quorum: %d", w.Code)
	}
	h = newHarness(t, append(append([]nodeSpec{}, baseNodes...), nodeSpec{"n6", "server", "home", "main", "10.215.0.6", nil, nil, true, false})...)
	ctx := context.Background()
	h.kube.CoreV1().Pods(coreNS).Create(ctx, agentPod("keycloak-7d-x", coreNS, "n2", "keycloak-7d", "ReplicaSet", map[string]string{"pod-template-hash": "7d"}), metav1.CreateOptions{})
	evictReactor(h, map[string]bool{"keycloak-7d-x": true})
	deletes := 0
	h.kube.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) { deletes++; return false, nil, nil })
	w = h.internal(clientHub, "POST", "/v1/nodes/n2/drain", map[string]any{})
	if w.Code != 409 || !jsonEqual(w.Body.Bytes(), []byte(`{"error":"draining n2 would take keycloak below its minimum","kind":"replica_minimum"}`)) {
		t.Fatalf("pdb: %d %s", w.Code, w.Body)
	}
	if _, err := h.kube.CoreV1().Pods(coreNS).Get(ctx, "keycloak-7d-x", metav1.GetOptions{}); err != nil || deletes != 0 {
		t.Fatal("the refused pod was deleted")
	}
	if n, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{}); !n.Spec.Unschedulable {
		t.Fatal("the drained node isn't cordoned")
	}
}

// TestRevokeRotatesServerToken: mode=revoke deletes the node, removes its
// etcd member, revokes its certificate through enroll, and rotates the
// server token (rotate on a surviving server, checked old 401 / new 200,
// then apply servers one at a time, then the agents). A rotation not in
// effect keeps the old token in the Secret.
func TestRevokeRotatesServerToken(t *testing.T) {
	agent := nodeSpec{"n4", "agent", "cloud", "edge", "10.215.0.4", nil, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
	ctx := context.Background()
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n2"] = &nodeRecord{Role: "server", Serial: "12:34", MeshIP: "10.215.0.2"}
	})
	h.agents.onRotate = h.bootFollows
	w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil)
	if w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if _, err := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("n2 still there")
	}
	if !slices.Equal(h.agents.etcdRm, []string{"n1:n2:10.215.0.2"}) || !slices.Equal(h.enroll.revoked, []string{"12:34"}) {
		t.Fatalf("etcd %v, revoked %v", h.agents.etcdRm, h.enroll.revoked)
	}
	// Rotated twice (a server target, fix round 6): the second round, after
	// its etcd member is gone, carries the tokens finally in effect.
	round := []string{"rotate:n1", "rotate-agent:n1", "apply:n1", "apply-agent:n1", "apply:n3", "apply-agent:n3", "apply:n4"}
	if want := append(append([]string{}, round...), round...); !slices.Equal(h.agents.rotations, want) {
		t.Fatalf("rotations %v", h.agents.rotations)
	}
	first := append([]string{}, h.agents.tokens[:len(round)]...)
	h.agents.rotations, h.agents.tokens = h.agents.rotations[len(round):], h.agents.tokens[len(round):]
	for _, tok := range first {
		if tok == testServerToken || tok == testAgentToken || slices.Contains(h.agents.tokens, tok) {
			t.Fatal("the first round carried an old or the final token")
		}
	}
	// Both tokens are new; no call to an agent ever carries a server token
	// (old or new): agents get the new agent token, the servers the new
	// server token (apply) and the new agent token (apply-agent).
	sec, _ := h.kube.CoreV1().Secrets(coreNS).Get(ctx, tokenSecret, metav1.GetOptions{})
	newAgent := string(sec.Data[agentTokenKey])
	if newAgent == testAgentToken || !strings.HasPrefix(newAgent, "K10"+caHash(testServerToken)+"::node:") {
		t.Fatalf("the agent token isn't rotated: %.20q", newAgent)
	}
	for i, step := range h.agents.rotations {
		tok := h.agents.tokens[i]
		switch {
		case strings.HasSuffix(step, ":n4"):
			if tok != newAgent || strings.Contains(tok, "::server:") {
				t.Fatalf("the agent n4 was sent %.12q", tok)
			}
		case strings.HasPrefix(step, "apply-agent:"), strings.HasPrefix(step, "rotate-agent:"):
			if tok != newAgent {
				t.Fatalf("%s: not the new agent token", step)
			}
		default:
			if !strings.Contains(tok, "::server:") || tok == testServerToken {
				t.Fatalf("%s: not the new server token", step)
			}
		}
	}
	// The revoked node's old agent token is refused, the new one admitted.
	if st, _ := h.boot.AgentStatus(ctx, "10.215.0.1", testAgentToken); st != 401 {
		t.Fatalf("the old agent token answers %d", st)
	}
	if st, _ := h.boot.AgentStatus(ctx, "10.215.0.1", newAgent); st != 200 {
		t.Fatalf("the new agent token answers %d", st)
	}
	tok, _ := h.s.serverToken(ctx)
	if tok == testServerToken || tok != h.boot.current || caHash(tok) != caHash(testServerToken) || !strings.Contains(tok, "::server:") {
		t.Fatalf("the Secret's token %q", tok)
	}
	if r := h.state(t).Nodes["n2"]; r == nil || !r.Removed || r.Serial != "" || r.Addrs == nil || r.Addrs.Mesh != "10.215.0.2" {
		t.Fatalf("n2 isn't marked removed with its addresses: %+v", r)
	}
	// The new token not in effect: refused, the Secret unchanged.
	h = newHarness(t)
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n3"] = &nodeRecord{Role: "server", Serial: "56:78", MeshIP: "10.215.0.3"}
	})
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n3?mode=revoke", nil); w.Code != 500 {
		t.Fatalf("an unproven rotation: %d", w.Code)
	}
	if tok, _ := h.s.serverToken(ctx); tok != testServerToken {
		t.Fatal("an unproven rotation replaced the token")
	}
}

// TestNotLeaderAnswers503: without the Lease every write is 503 not_leader
// (the snapshot and the public GETs still answer).
func TestNotLeaderAnswers503(t *testing.T) {
	h := newHarness(t)
	h.leader.on.Store(false)
	for _, r := range []struct{ m, p string }{{"POST", "/v1/codes"}, {"PUT", "/v1/nodes/n1/labels"}, {"POST", "/v1/nodes/n1/cordon"},
		{"POST", "/v1/nodes/n1/uncordon"}, {"POST", "/v1/nodes/n1/drain"}, {"DELETE", "/v1/nodes/n1?mode=cooperative"}, {"DELETE", "/v1/nodes/n1?mode=revoke"}} {
		w := h.do(h.s.InternalHandler(), clientHub, r.m, r.p, []byte(`{}`), nil)
		if w.Code != 503 || !strings.Contains(w.Body.String(), `"kind":"not_leader"`) {
			t.Errorf("%s %s: %d", r.m, r.p, w.Code)
		}
	}
	for _, p := range []string{"/node/v1/nonce", "/node/v1/enrol", "/node/v1/join"} {
		if w := h.public("POST", p, []byte(`{}`), nil); w.Code != 503 {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := h.internal(clientHub, "GET", "/v1/cluster", nil); w.Code != 200 {
		t.Errorf("the snapshot: %d", w.Code)
	}
	if w := h.public("GET", "/node/join.sh", nil, nil); w.Code != 200 {
		t.Errorf("join.sh: %d", w.Code)
	}
	// The background loop writes nothing either.
	h.s.reconcile(context.Background())
	if cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(context.Background(), addressesCM, metav1.GetOptions{}); len(cm.Data) != 0 {
		t.Error("a standing-by nodeadm wrote the addresses")
	}
}

// ── the admission params (ruling R-ADM) ──

// TestJoinWaitsForAdmission: enrol → the pending node is in the cluster
// addresses → its join answers waiting_admission (no k3s material) until
// the active params generation covers its addresses; nodeadm never writes
// a params ConfigMap or a binding.
func TestJoinWaitsForAdmission(t *testing.T) {
	h := newHarness(t)
	h.noAutoAdmit = true
	ctx := context.Background()
	writes := 0
	h.kube.PrependReactor("*", "validatingadmissionpolicybindings", func(a k8stesting.Action) (bool, runtime.Object, error) {
		writes++
		return false, nil, nil
	})
	h.kube.PrependReactor("*", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if c, ok := a.(k8stesting.CreateAction); ok {
			if strings.HasPrefix(c.GetObject().(metav1.Object).GetName(), "portcullis-admission-params") {
				writes++
			}
		}
		if a.GetVerb() == "delete" {
			writes++
		}
		return false, nil, nil
	})
	h.admit(t, "10.215.0.1", "10.215.0.2", "10.215.0.3")
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	if w := h.enrol(t, j, ""); w.Code != 200 {
		t.Fatal(w.Body)
	}
	h.s.reconcile(ctx)
	cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, addressesCM, metav1.GetOptions{})
	var doc AddressesDoc
	json.Unmarshal([]byte(cm.Data[addressesKey]), &doc)
	if got := doc.Nodes["n4"]; got.Mesh != "10.215.0.4" || !slices.Equal(got.Public, []string{"203.0.113.9"}) || got.State != statePending {
		t.Fatalf("the pending node isn't in the document: %+v", doc.Nodes)
	}
	w := h.join(t, j, nearRTT)
	if w.Code != 409 || !jsonEqual(w.Body.Bytes(), []byte(`{"error":"waiting for the admission params to include this node: retry","kind":"waiting_admission"}`)) {
		t.Fatalf("before params-sync: %d %s", w.Code, w.Body)
	}
	// Only the mesh address covered: still waiting.
	h.admit(t, "10.215.0.1", "10.215.0.2", "10.215.0.3", "10.215.0.4")
	if w := h.join(t, j, nearRTT); w.Code != 409 {
		t.Fatalf("partly covered: %d", w.Code)
	}
	if l, _ := h.kube.CoreV1().Secrets(bootstrapNS).List(ctx, metav1.ListOptions{}); len(l.Items) != 0 {
		t.Fatal("a waiting join minted a bootstrap token")
	}
	h.syncParams(t)
	if w := h.join(t, j, nearRTT); w.Code != 200 {
		t.Fatalf("after params-sync: %d %s", w.Code, w.Body)
	}
	if writes != 0 {
		t.Fatalf("nodeadm wrote %d admission objects", writes)
	}
	readDoc := func() AddressesDoc {
		cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, addressesCM, metav1.GetOptions{})
		var d AddressesDoc
		json.Unmarshal([]byte(cm.Data[addressesKey]), &d)
		return d
	}
	h.s.reconcile(ctx)
	if readDoc().Nodes["n4"].State != stateActive {
		t.Fatalf("a released node isn't active: %+v", readDoc().Nodes)
	}
	// Removal: removed while the active generation still holds it, then
	// gone once params-sync dropped it.
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=cooperative", nil); w.Code != 204 {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	h.s.reconcile(ctx)
	if got := readDoc().Nodes["n4"]; got.State != stateRemoved || got.Mesh != "10.215.0.4" {
		t.Fatalf("the removed node: %+v", got)
	}
	h.syncParams(t)
	h.s.reconcile(ctx)
	if _, ok := readDoc().Nodes["n4"]; ok || h.state(t).Nodes["n4"] != nil {
		t.Fatal("a removed node stays once the params dropped it")
	}
	// A malformed active record: fail closed.
	acm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, admissionActive, metav1.GetOptions{})
	acm.Data[activeKey] = `{"generation":"x","node_addresses":["10.215.0.9/32"]}`
	h.kube.CoreV1().ConfigMaps(coreNS).Update(ctx, acm, metav1.UpdateOptions{})
	if ok, _ := h.s.admitted(ctx, []string{"10.215.0.9"}); ok {
		t.Fatal("a malformed record admitted a node")
	}
}

// TestParamsGenerationVectors: the generation function equals the CLI's
// (shared vectors; core's shell test runs the same file through
// kube_params_generation).
func TestParamsGenerationVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/params_generation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Name   string            `json:"name"`
		Params map[string]string `json:"params"`
		Want   string            `json:"want_generation"`
	}
	if err := strictVectors(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 3 {
		t.Fatal("too few vectors")
	}
	for _, v := range vs {
		if got := paramsGeneration(v.Params); got != v.Want {
			t.Errorf("%s: %s, want %s", v.Name, got, v.Want)
		}
	}
}

// TestUnparseableAddressesNoRewrite: a node without a mesh address (or
// without its recorded addresses, or an unparseable cluster network) →
// no document (so params-sync changes nothing), the error in the snapshot.
func TestUnparseableAddressesNoRewrite(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mod        func(h *harness)
	}{
		{"no mesh address", "node n2 has no mesh address", func(h *harness) {
			n, _ := h.kube.CoreV1().Nodes().Get(context.Background(), "n2", metav1.GetOptions{})
			n.Status.Addresses = []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.12"}}
			h.kube.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		}},
		{"no recorded addresses", "node n3 has no recorded LAN and public addresses", func(h *harness) {
			n, _ := h.kube.CoreV1().Nodes().Get(context.Background(), "n3", metav1.GetOptions{})
			n.Annotations = nil
			h.kube.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{})
		}},
		{"a bad cluster network", "doesn't parse", func(h *harness) { h.s.cfg.ClusterCIDR = "10.42.0.1/16" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			tc.mod(h)
			h.s.reconcile(ctx)
			cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, addressesCM, metav1.GetOptions{})
			if len(cm.Data) != 0 {
				t.Fatal("the document was written")
			}
			snap, _ := h.s.snapshot(ctx)
			if !slices.ContainsFunc(snap.Errors, func(e string) bool { return strings.Contains(e, tc.want) }) {
				t.Fatalf("errors %v", snap.Errors)
			}
		})
	}
}

// TestProbeTargetsPushed: after a change of the document every Ready
// nodeagent gets the ingress nodes' public addresses with their sites
// (IPv4 only: an IPv6 annotation is dropped, review I4).
func TestProbeTargetsPushed(t *testing.T) {
	nodes := []nodeSpec{
		{"n1", "server", "home", "main", "10.215.0.1", nil, []string{"198.51.100.1"}, true, true},
		{"n2", "server", "home", "main", "10.215.0.2", nil, nil, true, false},
		{"n3", "server", "cloud", "edge", "10.215.0.3", nil, []string{"203.0.113.3", "2001:db8::3"}, true, true},
	}
	h := newHarness(t, nodes...)
	h.s.reconcile(context.Background())
	want := ProbeTargets{Domain: "example.org", EgressHost: "api.porkbun.com", Targets: []ProbeTarget{
		{"n1", "main", "198.51.100.1"}, {"n3", "edge", "203.0.113.3"}}}
	for _, n := range []string{"n1", "n2", "n3"} {
		if got := h.agents.targets[n]; mustJSON(got) != mustJSON(want) {
			t.Errorf("%s got %s", n, mustJSON(got))
		}
	}
}

// TestFrontdoorCert: nodeadm fills frontdoor-control-tls (tls.crt,
// tls.key, ca.crt) and renews it only at ⅓ left.
func TestFrontdoorCert(t *testing.T) {
	h := newHarness(t)
	h.setNow(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	ctx := context.Background()
	h.kube.CoreV1().Secrets(coreNS).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: frontdoorSecret, Namespace: coreNS}}, metav1.CreateOptions{})
	h.s.pki.setCA(h.ca.pem)
	if err := h.s.ensureFrontdoorCert(ctx); err != nil {
		t.Fatal(err)
	}
	sec, _ := h.kube.CoreV1().Secrets(coreNS).Get(ctx, frontdoorSecret, metav1.GetOptions{})
	b, _ := pem.Decode(sec.Data["tls.crt"])
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || c.Subject.CommonName != clientFrontdoor || string(sec.Data["ca.crt"]) != h.ca.pem || len(sec.Data["tls.key"]) == 0 {
		t.Fatalf("secret %v", err)
	}
	h.s.ensureFrontdoorCert(ctx)
	if len(h.enroll.signed) != 1 {
		t.Fatalf("renewed early: %v", h.enroll.signed)
	}
	h.setNow(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	h.s.ensureFrontdoorCert(ctx)
	if len(h.enroll.signed) != 2 || h.enroll.signed[0] != "node-frontdoor:frontdoor.control" {
		t.Fatalf("signed %v", h.enroll.signed)
	}
	if strings.Contains(h.logs.String(), "PRIVATE KEY") {
		t.Fatal("the key is logged")
	}
}

// TestInternalClients: hub.control every route, frontdoor.control only the
// snapshot, a certificate of another CA or none → 403.
func TestInternalClients(t *testing.T) {
	h := newHarness(t)
	if w := h.internal(clientFrontdoor, "GET", "/v1/cluster", nil); w.Code != 200 {
		t.Fatalf("frontdoor snapshot %d", w.Code)
	}
	for _, c := range []string{clientFrontdoor, "other-ca", "none"} {
		if w := h.internal(c, "POST", "/v1/nodes/n1/cordon", map[string]any{}); w.Code != http.StatusForbidden {
			t.Errorf("%s cordon: %d", c, w.Code)
		}
	}
}

// TestEnrolVoidedDuringSigning: a node removed or revoked while enroll
// signs its CSR: the new certificate is revoked at once and the node never
// joins (a Removed record is refused by the signed join).
func TestEnrolVoidedDuringSigning(t *testing.T) {
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	h.enroll.onSign = func() {
		if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=cooperative", nil); w.Code != 204 {
			t.Errorf("void: %d %s", w.Code, w.Body)
		}
	}
	w := h.enrol(t, j, "")
	if w.Code != 409 || strings.Contains(w.Body.String(), "BEGIN") {
		t.Fatalf("enrol: %d %s", w.Code, w.Body)
	}
	if len(h.enroll.revoked) != 1 {
		t.Fatalf("revoked %v", h.enroll.revoked)
	}
	if r := h.state(t).Nodes["n4"]; r == nil || !r.Removed || r.Serial != "" {
		t.Fatalf("record %+v", r)
	}
	// Even with a certificate that chains (the signed one), no material.
	c, k := h.ca.client("n4." + clusterDomain)
	h.putState(t, func(st *nodeadmState) { st.Nodes["n4"].Serial = certSerial(c) })
	if w := h.join(t, &joiner{id: "n4", cert: c, key: k}, nearRTT); w.Code != 403 {
		t.Fatalf("a removed node's join: %d", w.Code)
	}
}

// TestEnrolRefusesBadAddresses: the enrolment report's LAN address must be
// unicast, outside the cluster's networks and nobody else's; the public one
// truly public. A refusal burns nothing.
func TestEnrolRefusesBadAddresses(t *testing.T) {
	for _, tc := range []struct{ name, lan, pub string }{
		{"loopback LAN", "127.0.0.1:51830", ""},
		{"link-local LAN", "169.254.1.1:51830", ""},
		{"LAN in the mesh", "10.215.0.9:51830", ""},
		{"LAN in the cluster network", "10.42.3.4:51830", ""},
		{"another node's LAN address", "192.0.2.11:51830", ""},
		{"a private public address", "", "10.0.0.1:51830"},
		{"a CGNAT public address", "", "100.64.0.1:51830"},
		{"port 0", "", "203.0.113.9:0"},
		{"an IPv6 LAN endpoint", "[fd00::9]:51830", ""},
		{"an IPv6 public endpoint", "", "[2001:4860::9]:51830"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
			nonce := h.nonce(t, "n4")
			rep := MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="}
			if tc.lan != "" {
				rep.LAN = &tc.lan
			}
			if tc.pub != "" {
				rep.Public = &tc.pub
			}
			body, _ := json.Marshal(enrolReq{ServerID: "n4", Nonce: nonce, Proof: j.proof(nonce), CSR: j.csrPEM, Mesh: rep})
			w := h.public("POST", "/node/v1/enrol", body, nil)
			if w.Code != 400 || !strings.Contains(w.Body.String(), "the enrolment report is refused") {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			if st := h.state(t); st.Codes["n4"].Used || st.Nodes["n4"] != nil || len(h.enroll.signed) != 0 {
				t.Fatal("a refused report burnt the code or signed")
			}
		})
	}
	// A valid LAN address is kept normalised.
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	nonce := h.nonce(t, "n4")
	lan := "192.168.7.9:51830"
	body, _ := json.Marshal(enrolReq{ServerID: "n4", Nonce: nonce, Proof: j.proof(nonce), CSR: j.csrPEM,
		Mesh: MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", LAN: &lan}})
	if w := h.public("POST", "/node/v1/enrol", body, nil); w.Code != 200 || *h.state(t).Nodes["n4"].Mesh.LAN != lan {
		t.Fatalf("a valid LAN address: %d", w.Code)
	}
	// An annotation's invalid addresses are dropped (a node can't widen
	// what it publishes by editing its own object).
	if a := h.s.cleanAddrs(NodeAddresses{Mesh: "10.215.0.1", LAN: []string{"127.0.0.1", "192.0.2.10"}, Public: []string{"10.0.0.1", "8.8.8.8"}}); !slices.Equal(a.LAN, []string{"192.0.2.10"}) || !slices.Equal(a.Public, []string{"8.8.8.8"}) {
		t.Fatalf("cleanAddrs %+v", a)
	}
}

// TestLANUniqueness: a LAN address two nodes claim (annotations, status or
// an enrolment record) is dropped on both; an enrolment racing another for
// one LAN address is refused inside the compare-and-swap.
func TestLANUniqueness(t *testing.T) {
	nodes := append([]nodeSpec{}, baseNodes...)
	nodes[1].lan = []string{"192.0.2.11"} // n2 claims n1's LAN address
	h := newHarness(t, nodes...)
	ctx := context.Background()
	cl, err := h.s.clusterNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cl[:2] {
		if contains(c.Addresses.LAN, "192.0.2.11") {
			t.Fatalf("%s keeps a LAN address another node holds", c.Name)
		}
	}
	if !contains(cl[2].Addresses.LAN, "192.0.2.13") {
		t.Fatal("n3's own LAN address dropped")
	}
	// A pending record claiming n3's LAN address: n3 loses it too.
	lan := "192.0.2.13:51830"
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n9"] = &nodeRecord{Role: "agent", Class: "home", Site: "main", MeshIP: "10.215.0.9", Serial: "aa",
			Mesh: MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", LAN: &lan}}
	})
	cl, _ = h.s.clusterNodes(ctx)
	if contains(cl[2].Addresses.LAN, "192.0.2.13") {
		t.Fatal("n3 keeps a LAN address a record claims")
	}
	// TOCTOU: the address is free when the report is checked, taken
	// before the compare-and-swap (another enrolment won it).
	h = newHarness(t)
	j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
	nonce := h.nonce(t, "n4")
	mine := "192.168.50.5:51830"
	h.s.store = &racingStore{memStore: h.store, before: func(st *nodeadmState) {
		st.Nodes["n5"] = &nodeRecord{Role: "agent", MeshIP: "10.215.0.5", Serial: "bb",
			Mesh: MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", LAN: &mine}}
	}}
	body, _ := json.Marshal(enrolReq{ServerID: "n4", Nonce: nonce, Proof: j.proof(nonce), CSR: j.csrPEM,
		Mesh: MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", LAN: &mine}})
	w := h.public("POST", "/node/v1/enrol", body, nil)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "is node n5's") {
		t.Fatalf("racing enrol: %d %s", w.Code, w.Body)
	}
	if st, _, _ := h.store.Load(ctx); st.Codes["n4"].Used || len(h.enroll.signed) != 0 {
		t.Fatal("the refused enrolment burnt the code or signed")
	}
}

// racingStore injects another writer's change the first time the state is
// read inside a compare-and-swap (the third load: after the proof's read
// and the report's check).
type racingStore struct {
	*memStore
	before func(*nodeadmState)
	loads  int
}

func (r *racingStore) Load(ctx context.Context) (*nodeadmState, string, error) {
	r.loads++
	if r.loads == 3 && r.before != nil {
		st, ver, _ := r.memStore.Load(ctx)
		r.before(st)
		r.memStore.Save(ctx, st, ver)
	}
	return r.memStore.Load(ctx)
}
