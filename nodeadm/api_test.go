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
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
)

// The vectors' join case: n4, an agent at edge (cloud, ingress), its
// enrolment report, and the bootstrap plan of the "issue a code" case.
func vecCodeRecord(vs *apiVectors, used bool, issued time.Time) *codeRecord {
	var req CodeReq
	for _, c := range vs.Cases {
		if c.Name == "issue a code" {
			json.Unmarshal(c.Request.Body, &req)
		}
	}
	secret, _ := base64.RawURLEncoding.DecodeString(vs.Proof[0].Secret)
	sum := sha256.Sum256(secret)
	rec := &codeRecord{KeySHA256: hex.EncodeToString(sum[:]), Role: req.Role, Class: req.Class, Site: req.Site, MeshIP: req.MeshIP,
		Ingress: req.Ingress, Storage: req.Storage, Mesh: req.Mesh, IssuedAt: issued, ExpiresAt: issued.Add(codeTTL)}
	if used {
		rec.KeySHA256, rec.Used = "", true
	}
	return rec
}

func vecNodeRecord(serial string, public bool) *nodeRecord {
	pub := "203.0.113.4:51830"
	r := &nodeRecord{Role: "agent", Class: "cloud", Site: "edge", MeshIP: "10.215.0.4", Ingress: true, Serial: serial,
		Mesh: MeshReport{Pub: "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=", Public: &pub}, EnrolledAt: time.Date(2026, 11, 18, 9, 59, 0, 0, time.UTC)}
	if !public {
		r.Mesh.Public = nil
	}
	return r
}

// replayRand: the bytes the case's answer was made from (the code's
// secret, the nonce, the bootstrap token "abcdef.0123456789abcdef").
type replayRand struct{ b []byte }

func (r *replayRand) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	r.b = r.b[n:]
	for i := n; i < len(p); i++ {
		p[i] = 7
	}
	return len(p), nil
}

func tokenBytes(s string) []byte {
	var out []byte
	for _, c := range s {
		out = append(out, byte(strings.IndexRune(tokenAlphabet, c)))
	}
	return out
}

func agentPod(name, ns, node, owner, ownerKind string, labels map[string]string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: labels, UID: types.UID("uid-" + name),
		OwnerReferences: []metav1.OwnerReference{{Kind: ownerKind, Name: owner}}},
		Spec:   corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "c"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	return p
}

// snapshotFixture: the "the snapshot" case's cluster: Traefik and SNR on
// every node, vault-0..2, the Sentinels, CNPG and one Longhorn volume.
func snapshotFixture(t *testing.T, h *harness) {
	ctx := context.Background()
	add := func(p *corev1.Pod) {
		if _, err := h.kube.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for i, n := range []string{"n1", "n2", "n3"} {
		add(agentPod("traefik-"+n, "portcullis-ingress", n, "traefik", "DaemonSet", map[string]string{"app.kubernetes.io/name": "traefik"}))
		add(agentPod("self-node-remediation-ds-"+n, "portcullis-fencing", n, "self-node-remediation-ds", "DaemonSet", nil))
		add(agentPod("sessions-sentinel-"+string(rune('0'+i)), coreNS, n, "sessions-sentinel", "StatefulSet", nil))
		v := agentPod("vault-"+string(rune('0'+i)), coreNS, n, "vault", "StatefulSet", nil)
		v.Spec.Priority = ptr(int32(1000000))
		v.Spec.PriorityClassName = "portcullis-core"
		v.Spec.PreemptionPolicy = ptr(corev1.PreemptLowerPriority)
		v.Spec.Containers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"),
			corev1.ResourceMemory: *resource.NewQuantity(300000000, resource.DecimalSI)}
		v.Spec.Tolerations = []corev1.Toleration{{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists,
			Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr(int64(30))}}
		v.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
					{Key: labelSite, Operator: corev1.NodeSelectorOpIn, Values: []string{"main"}}}}}}},
			PodAntiAffinity: &corev1.PodAntiAffinity{RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{TopologyKey: "kubernetes.io/hostname"}}}}
		add(v)
	}
	add(agentPod("portcullis-pg-1", "cnpg-system", "n1", "portcullis-pg", "Cluster", map[string]string{"cnpg.io/cluster": "portcullis-pg"}))
	pg := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "postgresql.cnpg.io/v1", "kind": "Cluster",
		"metadata": map[string]any{"name": "portcullis-pg", "namespace": "cnpg-system"},
		"spec":     map[string]any{"postgresql": map[string]any{"synchronous": map[string]any{"number": int64(1)}}},
		"status":   map[string]any{"instances": int64(2), "readyInstances": int64(2), "currentPrimary": "portcullis-pg-1"}}}
	vol := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "longhorn.io/v1beta2", "kind": "Volume",
		"metadata": map[string]any{"name": "pvc-123", "namespace": "longhorn-system"},
		"status":   map[string]any{"robustness": "healthy", "kubernetesStatus": map[string]any{"pvcName": "hub-state-r"}}}}
	h.withDynamic(pg, vol)
}

// evictReactor: evictions of pods named in refuse answer 429 (a PDB);
// any other eviction deletes the pod.
func evictReactor(h *harness, refuse map[string]bool) {
	h.kube.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateAction)
		if !ok || ca.GetSubresource() != "eviction" {
			return false, nil, nil
		}
		ev := ca.GetObject().(interface{ GetName() string })
		if refuse[ev.GetName()] {
			return true, nil, apierrors.NewTooManyRequests("Cannot evict pod as it would violate the pod's disruption budget.", 1)
		}
		h.kube.Tracker().Delete(schema.GroupVersionResource{Version: "v1", Resource: "pods"}, a.GetNamespace(), ev.GetName())
		return true, nil, nil
	})
}

// setupCase builds the case's fixture (its state text) and answers the
// request and the harness.
func setupCase(t *testing.T, vs *apiVectors, c apiCase) (*harness, []byte, map[string]string) {
	st := c.State
	nodes := append([]nodeSpec{}, baseNodes...)
	agentN4 := nodeSpec{"n4", "agent", "cloud", "edge", "10.215.0.4", nil, []string{"203.0.113.4"}, true, true}
	switch {
	case strings.HasPrefix(c.Route, "POST /v1/nodes/{id}/drain"), strings.HasPrefix(c.Route, "DELETE "), strings.HasPrefix(c.Route, "PUT "), strings.Contains(c.Route, "cordon"):
		nodes = append(nodes, agentN4)
		if !strings.Contains(st, "3 healthy servers") {
			nodes = append(nodes, nodeSpec{"n6", "server", "home", "main", "10.215.0.6", nil, nil, true, false})
		}
		if strings.Contains(st, "no node object") {
			nodes = nodes[:3]
		}
	}
	h := newHarness(t, nodes...)
	h.leader.on.Store(c.Leader)
	body := []byte(nil)
	switch {
	case c.Request.BodyBytes > 0:
		body = bytes.Repeat([]byte("x"), c.Request.BodyBytes)
	case c.Request.BodyText != nil:
		body = []byte(*c.Request.BodyText)
	case len(c.Request.Body) > 0 && string(c.Request.Body) != "null":
		body = c.Request.Body
	}
	hdr := c.Request.Headers
	ctx := context.Background()
	switch c.Route {
	case "POST /v1/codes":
		secret, _ := base64.RawURLEncoding.DecodeString(vs.Proof[0].Secret)
		h.s.rand = &replayRand{b: secret}
	case "GET /v1/cluster":
		snapshotFixture(t, h)
		h.putState(t, func(s *nodeadmState) { s.Nodes["n4"] = vecNodeRecord("4e:4f:44:45", true) })
	case "POST /node/v1/nonce":
		var ans struct{ Nonce string }
		json.Unmarshal(c.Response.Body, &ans)
		n, _ := base64.RawURLEncoding.DecodeString(ans.Nonce)
		h.s.rand = &replayRand{b: n}
		if strings.Contains(st, "a code for n4") {
			h.putState(t, func(s *nodeadmState) { s.Codes["n4"] = vecCodeRecord(vs, false, vecNow) })
		}
	case "POST /node/v1/enrol":
		issued := vecNow
		if strings.Contains(st, "16 min ago") {
			issued = vecNow.Add(-16 * time.Minute)
		}
		if strings.Contains(st, "the code of valid[0]") {
			h.putState(t, func(s *nodeadmState) {
				s.Codes["n4"] = vecCodeRecord(vs, strings.Contains(st, "the code already used"), issued)
			})
		}
		var req enrolReq
		json.Unmarshal(body, &req)
		nonceFor, at := "n4", vecNow
		if strings.Contains(st, "issued for n5") {
			nonceFor = "n5"
		}
		if strings.Contains(st, "61 s ago") {
			at = vecNow.Add(-61 * time.Second)
		}
		if !strings.Contains(st, "the nonce already used") {
			h.s.nonces[req.Nonce] = nonceRec{serverID: nonceFor, at: at}
		}
		na, _ := time.Parse(time.RFC3339, "2026-12-18T10:00:00Z")
		h.enroll.cert = &SignedCert{CertPEM: vs.PKI.NodeCertPEM, Serial: "4e:4f:44:45", NotAfter: na, CAPEM: vs.PKI.CAPEM}
	case "POST /node/v1/join":
		h.setNow(time.Date(2026, 11, 18, 10, 5, 0, 0, time.UTC))
		if strings.Contains(st, "10:06:01") {
			h.setNow(time.Date(2026, 11, 18, 10, 6, 1, 0, time.UTC))
		}
		h.putState(t, func(s *nodeadmState) {
			s.Nodes["n4"] = vecNodeRecord("4e:4f:44:45", !strings.Contains(st, "public endpoint gone"))
		})
		if strings.Contains(st, "doesn't answer") {
			h.agents.down["n4"] = true
		}
		if !strings.Contains(st, "doesn't hold n4's addresses") {
			h.admit(t, "10.215.0.4", "203.0.113.4")
		}
		if strings.Contains(st, "used 2 min ago") {
			h.s.joinNonces[hdr["Portcullis-Node-Nonce"]] = vecNow.Add(3 * time.Minute)
		}
		h.s.rand = &replayRand{b: tokenBytes("abcdef0123456789abcdef")}
		if strings.Contains(st, "re-signed by the test") {
			// The vectors hold no node key: a test-CA node certificate for n4.
			c4, k4 := h.ca.client("n4.cluster.portcullis.internal")
			h.putState(t, func(s *nodeadmState) { s.Nodes["n4"].Serial = certSerial(c4) })
			body = []byte(`{"server_id":"n4","rtt_ms":{"n1":3,"n2":251,"n3":5}}`)
			hdr = signedHeaders(c4, k4, "n4", c.Request.Path, body, h.s.now())
		}
	case "POST /node/v1/renew", "POST /node/v1/renew/confirm":
		h.setNow(time.Date(2026, 11, 18, 10, 5, 0, 0, time.UTC))
		h.putState(t, func(s *nodeadmState) {
			s.Nodes["n4"] = vecNodeRecord("4e:4f:44:45", true)
		})
		na, _ := time.Parse(time.RFC3339, "2026-12-18T10:00:00Z")
		h.enroll.cert = &SignedCert{CertPEM: vs.PKI.NodeCertPEM, Serial: "4e:4f:44:45", NotAfter: na, CAPEM: vs.PKI.CAPEM}
		if strings.Contains(st, "re-signed by the test") {
			k4, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			var c4 *x509.Certificate
			if strings.Contains(st, "issued an hour ago") {
				_, c4 = h.ca.signAt("n4.cluster.portcullis.internal", &k4.PublicKey, h.s.now().Add(-time.Hour), h.s.now().Add(720*time.Hour))
			} else {
				_, c4 = h.ca.sign("n4.cluster.portcullis.internal", &k4.PublicKey, nil)
			}
			h.putState(t, func(s *nodeadmState) {
				s.Nodes["n4"].Serial = certSerial(c4)
				s.Nodes["n4"].Removed = strings.Contains(st, "record removed")
			})
			cn := "n4.cluster.portcullis.internal"
			if strings.Contains(st, "names n5") {
				cn = "n5.cluster.portcullis.internal"
			}
			nk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, nk)
			csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
			body, _ = json.Marshal(renewReq{ServerID: "n4", CSR: csrPEM})
			if c.Route == "POST /node/v1/renew/confirm" {
				body = []byte(`{"server_id":"n4"}`)
			}
			sk, sc := k4, c4
			if strings.Contains(st, "pending") {
				// A pending renewal: a test-CA certificate for the new key (or
				// the vectors' certificate for the same CSR).
				_, pc := h.ca.sign("n4.cluster.portcullis.internal", &nk.PublicKey, nil)
				sum := sha256.Sum256([]byte(csrPEM))
				ren := &renewal{CSRSHA256: hex.EncodeToString(sum[:]), Serial: certSerial(pc), CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pc.Raw})),
					NotAfter: pc.NotAfter, IssuedAt: h.s.now()}
				if strings.Contains(st, "this very CSR") {
					ren.CertPEM, ren.Serial, ren.NotAfter = vs.PKI.NodeCertPEM, "4e:4f:44:45", na
				}
				h.putState(t, func(s *nodeadmState) { s.Nodes["n4"].Renewal = ren })
				if strings.Contains(st, "with n4's pending renewal certificate") {
					sk, sc = nk, pc
				}
			}
			hdr = signedHeaders(sc, sk, "n4", c.Request.Path, body, h.s.now())
		}
	case "POST /v1/nodes/{id}/drain", "DELETE /v1/nodes/{id}?mode=cooperative":
		if strings.Contains(st, "PDB refuses") {
			set, node := "vault", "n2"
			if strings.Contains(st, "keycloak") {
				set, node = "keycloak", "n4"
			}
			p := agentPod(set+"-abc-xyz", coreNS, node, set+"-abc", "ReplicaSet", map[string]string{"pod-template-hash": "abc"})
			if set == "vault" {
				p = agentPod("vault-1", coreNS, node, "vault", "StatefulSet", nil)
			}
			h.kube.CoreV1().Pods(coreNS).Create(ctx, p, metav1.CreateOptions{})
			evictReactor(h, map[string]bool{p.Name: true})
		} else {
			h.kube.CoreV1().Pods(coreNS).Create(ctx, agentPod("web-1", coreNS, "n4", "web", "StatefulSet", nil), metav1.CreateOptions{})
			h.kube.CoreV1().Pods("portcullis-ingress").Create(ctx, agentPod("traefik-n4", "portcullis-ingress", "n4", "traefik", "DaemonSet", nil), metav1.CreateOptions{})
			evictReactor(h, nil)
		}
		h.putState(t, func(s *nodeadmState) {
			s.Nodes["n4"] = vecNodeRecord("4e:4f:44:45", true)
			if strings.Contains(st, "a code for n5") {
				s.Codes["n5"] = &codeRecord{KeySHA256: strings.Repeat("ab", 32), Role: "agent", Class: "home", Site: "main", MeshIP: "10.215.0.5",
					IssuedAt: vecNow, ExpiresAt: vecNow.Add(codeTTL)}
			}
		})
	case "DELETE /v1/nodes/{id}?mode=revoke":
		if strings.Contains(st, "1 of 4 healthy") {
			for _, id := range []string{"n2", "n3", "n6"} {
				n, _ := h.kube.CoreV1().Nodes().Get(ctx, id, metav1.GetOptions{})
				for i := range n.Status.Conditions {
					if n.Status.Conditions[i].Type == corev1.NodeReady {
						n.Status.Conditions[i].Status = corev1.ConditionFalse
					}
				}
				h.kube.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{})
			}
		}
		h.agents.onRotate = h.bootFollows
	}
	return h, body, hdr
}

// TestAPIVectors replays every case of nodeadm_api_vectors.json: the
// status, the listed headers and the body (byte-for-byte JSON equality,
// except where the case says it's illustrative: the join flags, which
// TestJoinFlagsEqualInitFlags pins, and the snapshot's pods, of which the
// vector lists one).
func TestAPIVectors(t *testing.T) {
	vs := loadVectors(t)
	for _, c := range vs.Cases {
		t.Run(c.Name, func(t *testing.T) {
			h, body, hdr := setupCase(t, vs, c)
			var w *httptest.ResponseRecorder
			if strings.HasPrefix(c.Request.Path, "/node/") {
				w = h.public(c.Request.Method, c.Request.Path, body, hdr)
			} else {
				w = h.do(h.s.InternalHandler(), c.Client, c.Request.Method, c.Request.Path, body, hdr)
			}
			if w.Code != c.Response.Status {
				t.Fatalf("status %d, want %d: %s", w.Code, c.Response.Status, w.Body)
			}
			for k, v := range c.Response.Headers {
				if got := w.Header().Get(k); got != v {
					t.Errorf("header %s = %q, want %q", k, got, v)
				}
			}
			want := string(c.Response.Body)
			switch {
			case want == "null" || want == "":
				switch c.Route {
				case "GET /node/join.sh":
					if !bytes.Equal(w.Body.Bytes(), h.s.cfg.Script) {
						t.Errorf("the script differs")
					}
				case "GET /node/nodeagent-{arch}":
					if c.Response.Status == 200 && !strings.HasPrefix(w.Body.String(), "nodeagent ") {
						t.Errorf("binary %q", w.Body)
					}
				default:
					if w.Body.Len() != 0 {
						t.Errorf("a body %q where none is due", w.Body)
					}
				}
			case c.Route == "GET /v1/cluster" && c.Response.Status == 200:
				compareSnapshot(t, w.Body.Bytes(), c.Response.Body)
			case c.Route == "POST /node/v1/join" && c.Response.Status == 200:
				var got, exp joinAnswer
				json.Unmarshal(w.Body.Bytes(), &got)
				json.Unmarshal(c.Response.Body, &exp)
				if got.Role != exp.Role || got.ServerURL != exp.ServerURL || got.Token != exp.Token ||
					got.ClusterCIDR != exp.ClusterCIDR || got.AgentToken != exp.AgentToken {
					t.Errorf("answer %+v, want %+v", got, exp)
				}
				for _, f := range exp.Flags {
					if !slices.Contains(got.Flags, f) {
						t.Errorf("flag %s missing from %v", f, got.Flags)
					}
				}
				rec := h.state(t).Nodes["n4"]
				if !reflect.DeepEqual(got.Flags, joinFlags(rec, "n4", got.ServerURL, "10.42.0.0/16")) {
					t.Errorf("flags %v", got.Flags)
				}
			default:
				if !jsonEqual(w.Body.Bytes(), c.Response.Body) {
					t.Errorf("body %s\nwant %s", w.Body, c.Response.Body)
				}
			}
			checkCaseEffects(t, h, c)
		})
	}
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

func compareSnapshot(t *testing.T, got, want []byte) {
	var g, w map[string]any
	json.Unmarshal(got, &g)
	json.Unmarshal(want, &w)
	wp := w["pods"].([]any)
	keep := map[string]bool{}
	for _, p := range wp {
		keep[p.(map[string]any)["name"].(string)] = true
	}
	var gp []any
	for _, p := range g["pods"].([]any) {
		if keep[p.(map[string]any)["name"].(string)] {
			gp = append(gp, p)
		}
	}
	g["pods"] = gp
	for k := range w {
		if !reflect.DeepEqual(g[k], w[k]) {
			gb, _ := json.Marshal(g[k])
			wb, _ := json.Marshal(w[k])
			t.Errorf("snapshot %s = %s\nwant %s", k, gb, wb)
		}
	}
	if len(g) != len(w) {
		t.Errorf("snapshot keys differ")
	}
}

// checkCaseEffects: what a success must have done (and a refusal not).
func checkCaseEffects(t *testing.T, h *harness, c apiCase) {
	ctx := context.Background()
	st := h.state(t)
	switch c.Name {
	case "enrol":
		if cd := st.Codes["n4"]; cd == nil || !cd.Used || cd.KeySHA256 != "" {
			t.Errorf("the code isn't burnt with its hash deleted: %+v", cd)
		}
		if n := st.Nodes["n4"]; n == nil || n.Serial != "4e:4f:44:45" {
			t.Errorf("no enrolled n4: %+v", n)
		}
	case "enrol: a wrong proof", "enrol: a CSR of another key than the proof's", "enrol: a reused nonce", "enrol: an expired nonce (61 s)":
		if cd := st.Codes["n4"]; cd == nil || cd.Used || cd.KeySHA256 == "" {
			t.Errorf("a refused enrol burnt the code")
		}
		if len(h.enroll.signed) != 0 {
			t.Errorf("a refused enrol signed a CSR")
		}
	case "renew":
		r := st.Nodes["n4"]
		if r == nil || r.Serial == "4e:4f:44:45" || r.Renewal == nil || r.Renewal.Serial != "4e:4f:44:45" || len(h.enroll.revoked) != 0 ||
			len(h.enroll.signed) != 1 || h.enroll.signed[0] != "node-cluster:n4.cluster.portcullis.internal" {
			t.Errorf("renewal: record %+v, revoked %v, signed %v", r, h.enroll.revoked, h.enroll.signed)
		}
	case "renew confirm":
		r := st.Nodes["n4"]
		if r == nil || r.Renewal != nil || len(h.enroll.revoked) != 1 || r.Serial == h.enroll.revoked[0] {
			t.Errorf("confirm: record %+v, revoked %v", r, h.enroll.revoked)
		}
	case "renew: the same CSR again", "renew: signed with the pending certificate", "renew confirm: with the current certificate":
		if len(h.enroll.signed) != 0 || len(h.enroll.revoked) != 0 || st.Nodes["n4"].Renewal == nil {
			t.Errorf("signed %v, revoked %v, renewal %+v", h.enroll.signed, h.enroll.revoked, st.Nodes["n4"].Renewal)
		}
	case "renew: not due yet", "renew: a CSR for another name", "renew: a removed node", "renew: no signature":
		if len(h.enroll.signed) != 0 {
			t.Errorf("a refused renewal signed %v", h.enroll.signed)
		}
	case "enrol: an expired code (logged code_expired)":
		if !strings.Contains(h.logs.String(), "kind=code_expired") {
			t.Errorf("not logged code_expired: %s", h.logs)
		}
	case "enrol: a used code (logged code_used)":
		if !strings.Contains(h.logs.String(), "kind=code_used") {
			t.Errorf("not logged code_used: %s", h.logs)
		}
	case "remove cooperatively":
		if _, err := h.kube.CoreV1().Nodes().Get(ctx, "n4", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("n4 still there")
		}
		if !slices.Equal(h.enroll.revoked, []string{"4e:4f:44:45"}) {
			t.Errorf("revoked %v", h.enroll.revoked)
		}
		if _, err := h.kube.CoreV1().Pods(coreNS).Get(ctx, "web-1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("web-1 not evicted")
		}
		if _, err := h.kube.CoreV1().Pods("portcullis-ingress").Get(ctx, "traefik-n4", metav1.GetOptions{}); err != nil {
			t.Errorf("the DaemonSet pod was evicted")
		}
	case "remove cooperatively: an unused code":
		if cd := st.Codes["n5"]; cd == nil || cd.KeySHA256 != "" {
			t.Errorf("the code isn't voided")
		}
	case "revoke":
		if _, err := h.kube.CoreV1().Nodes().Get(ctx, "n3", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("n3 still there")
		}
		if !slices.Equal(h.agents.etcdRm, []string{"n1:n3:10.215.0.3"}) {
			t.Errorf("etcd removed %v", h.agents.etcdRm)
		}
		// A server target: rotated twice (before the quorum-gated steps and
		// after its etcd member is gone, fix round 6).
		round := []string{"rotate:n1", "rotate-agent:n1", "apply:n1", "apply-agent:n1", "apply:n2", "apply-agent:n2", "apply:n4"}
		if want := append(append([]string{}, round...), round...); !slices.Equal(h.agents.rotations, want) {
			t.Errorf("rotations %v, want %v", h.agents.rotations, want)
		}
		tok, _ := h.s.serverToken(ctx)
		if tok == testServerToken || tok != h.boot.current {
			t.Errorf("the Secret doesn't hold the rotated token")
		}
	case "revoke: etcd without quorum":
		if _, err := h.kube.CoreV1().Nodes().Get(ctx, "n3", metav1.GetOptions{}); err != nil {
			t.Errorf("n3 was deleted without quorum")
		}
	}
	if c.Response.Status >= 400 && c.Route == "POST /node/v1/join" {
		l, _ := h.kube.CoreV1().Secrets(bootstrapNS).List(ctx, metav1.ListOptions{})
		if len(l.Items) != 0 {
			t.Errorf("a refused join minted a bootstrap token")
		}
	}
}
