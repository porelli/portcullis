package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

// ── fakes ──

type fakeLeader struct{ on atomic.Bool }

func (f *fakeLeader) Leading() bool { return f.on.Load() }

type fakeEnroll struct {
	mu         sync.Mutex
	cert       *SignedCert // answered for node-cluster when set
	ca         *testCA     // else: signs with this CA
	signed     []string    // role:cn
	revoked    []string
	fail       error
	onSign     func() // runs while "enroll signs" (outside the lock)
	revokeFail error  // Revoke only
}

func (f *fakeEnroll) Sign(_ context.Context, role, cn, csrPEM string) (*SignedCert, error) {
	if f.onSign != nil {
		f.onSign()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	f.signed = append(f.signed, role+":"+cn)
	if role == "node-cluster" && f.cert != nil {
		return f.cert, nil
	}
	b, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}
	var dns []string
	if role == "node-nodeadm" {
		dns = []string{"nodeadm.portcullis-nodeadm.svc"}
	}
	der, leaf := f.ca.sign(cn, csr.PublicKey, dns)
	return &SignedCert{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		Serial: certSerial(leaf), NotAfter: leaf.NotAfter, CAPEM: f.ca.pem}, nil
}

func (f *fakeEnroll) Revoke(_ context.Context, serial string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if f.revokeFail != nil {
		return f.revokeFail
	}
	f.revoked = append(f.revoked, serial)
	return nil
}

type fakeAgents struct {
	mu        sync.Mutex
	down      map[string]bool // id → health fails
	rotations []string        // step:id
	tokens    []string        // every new_token seen
	targets   map[string]ProbeTargets
	onRotate  func(id, step, tok string)
	etcdRm    []string          // via:node:mesh
	fail      map[string]error  // "rotate"/"apply"/... or "etcd": the call fails (its error echoes the token)
	effect    map[string]bool   // the failing call took effect first (an answer lost)
	upgrades  []string          // id:amd64[:4]:arm64[:4] (UpgradeAgent; fail "upgrade:<id>")
	peers     map[string]string // id → its health's peers JSON (unset: none, or {} with meshState)
	devPeers  map[string]string // id → its health's device_peers JSON (likewise)
	meshState bool              // every health answer carries peers / device_peers ({} by default) and mesh_pub key-<id>
	pubs      map[string]string // id → its mesh_pub (overrides key-<id>)
}

func (f *fakeAgents) Health(_ context.Context, id, meshIP string) (*AgentHealth, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down[id] {
		return nil, errors.New("nodeagent " + id + " /v1/health: unreachable")
	}
	h := &AgentHealth{ID: id, MeshIP: meshIP, K3s: "absent"}
	if f.meshState {
		h.MeshPub, h.Peers, h.DevicePeers = "key-"+id, json.RawMessage("{}"), json.RawMessage("{}")
	}
	if p, ok := f.peers[id]; ok {
		h.Peers = json.RawMessage(p)
	}
	if p, ok := f.devPeers[id]; ok {
		h.DevicePeers = json.RawMessage(p)
	}
	if p, ok := f.pubs[id]; ok {
		h.MeshPub = p
	}
	return h, nil
}

func (f *fakeAgents) PutProbeTargets(_ context.Context, id, _ string, t ProbeTargets) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.targets == nil {
		f.targets = map[string]ProbeTargets{}
	}
	f.targets[id] = t
	return nil
}

func (f *fakeAgents) TokenRotate(_ context.Context, id, _, tok, step string) error {
	f.mu.Lock()
	if err := f.fail[step]; err != nil {
		cb := f.onRotate
		eff := f.effect[step]
		f.mu.Unlock()
		if eff && cb != nil {
			cb(id, step, tok)
		}
		return fmt.Errorf("%w (request body {\"new_token\":%q})", err, tok)
	}
	f.rotations = append(f.rotations, step+":"+id)
	f.tokens = append(f.tokens, tok)
	cb := f.onRotate
	f.mu.Unlock()
	if cb != nil {
		cb(id, step, tok)
	}
	return nil
}

func (f *fakeAgents) UpgradeAgent(_ context.Context, id, _ string, sums map[string]string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail["upgrade:"+id]; err != nil {
		return "", err
	}
	f.upgrades = append(f.upgrades, id+":"+sums["amd64"][:4]+":"+sums["arm64"][:4])
	return "upgraded", nil
}

func (f *fakeAgents) EtcdRemoveMember(_ context.Context, via, _, node, mesh string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.fail["etcd"]; err != nil {
		return err
	}
	f.etcdRm = append(f.etcdRm, via+":"+node+":"+mesh)
	return nil
}

// fakeBoot: server-bootstrap answers 200 for the rotated token, 401 else;
// the agent call likewise for the node credential k3s derives from the
// server token in effect (no --agent-token-file: the initial one until a
// rotate).
type fakeBoot struct {
	mu      sync.Mutex
	current string
}

func (f *fakeBoot) AgentStatus(_ context.Context, _, token string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur := f.current
	if cur == "" {
		cur = testServerToken
	}
	if token == nodeCredential(cur) {
		return 200, nil
	}
	return 401, nil
}

func (f *fakeBoot) Ready(ctx context.Context, ip, token string) (int, error) {
	return f.AgentStatus(ctx, ip, nodeCredential(token))
}

func (f *fakeBoot) Status(_ context.Context, _, token string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if token == f.current {
		return 200, nil
	}
	return 401, nil
}

// ── a test CA ──

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

var serialN atomic.Int64

func newTestCA(t testing.TB, cn string) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *testCA) sign(cn string, pub any, dns []string) ([]byte, *x509.Certificate) {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1000 + serialN.Add(1)), Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return der, c
}

func (ca *testCA) signAt(cn string, pub any, nb, na time.Time) ([]byte, *x509.Certificate) {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1000 + serialN.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, pub, ca.key)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return der, c
}

func (ca *testCA) client(cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, c := ca.sign(cn, &k.PublicKey, nil)
	return c, k
}

// ── the cluster fixture ──

const (
	testServerToken = "K10b7335c14c0febed58f896145ef153d44a59bd0dfa5065771f18cc99c514c0edb::server:0123456789abcdef0123456789abcdef"
	coreNS          = "portcullis"
)

var vecNow = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

type nodeSpec struct {
	name, role, class, site, mesh string
	lan, public                   []string
	ready, ingress                bool
}

func mkNode(n nodeSpec) *corev1.Node {
	labels := map[string]string{"kubernetes.io/hostname": n.name, labelClass: n.class, labelSite: n.site, labelZone: n.site}
	if n.role == "server" {
		labels[labelServer] = "true"
	}
	if n.ingress {
		labels[labelIngress] = "true"
	}
	st := corev1.ConditionTrue
	if !n.ready {
		st = corev1.ConditionFalse
	}
	ann, _ := json.Marshal(map[string][]string{"lan": nonNil(n.lan), "public": nonNil(n.public)})
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: n.name, Labels: labels, Annotations: map[string]string{annAddresses: string(ann)}},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: *resource.NewQuantity(4000000000, resource.DecimalSI)},
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: st,
				LastTransitionTime: metav1.NewTime(vecNow.Add(-time.Hour))}},
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: n.mesh}}}}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var baseNodes = []nodeSpec{
	{"n1", "server", "home", "main", "10.215.0.1", []string{"192.0.2.11"}, []string{"198.51.100.1"}, true, false},
	{"n2", "server", "home", "main", "10.215.0.2", []string{"192.0.2.12"}, nil, true, false},
	{"n3", "server", "home", "main", "10.215.0.3", []string{"192.0.2.13"}, nil, true, false},
}

type harness struct {
	s       *Server
	kube    *fake.Clientset
	leader  *fakeLeader
	enroll  *fakeEnroll
	agents  *fakeAgents
	boot    *fakeBoot
	probe   *fakeProbe
	store   *memStore
	logs    *bytes.Buffer
	ca      *testCA // signs the internal clients (and, unless replaced, node certificates)
	now     atomic.Value
	clients map[string]*x509.Certificate
	// noAutoAdmit: join() doesn't play params-sync first.
	noAutoAdmit bool
}

func (h *harness) setNow(t time.Time) { h.now.Store(t) }

type lockedBuf struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// newHarness: a leading nodeadm on a fake cluster of n1–n3 (servers at
// main), the vectors' pki_node CA, the vectors' ca / script / agent sums.
func newHarness(t testing.TB, nodes ...nodeSpec) *harness {
	vs := loadVectors(t)
	h := &harness{leader: &fakeLeader{}, agents: &fakeAgents{down: map[string]bool{}}, boot: &fakeBoot{},
		store: &memStore{}, logs: &bytes.Buffer{}, ca: newTestCA(t, "test pki_node CA"), clients: map[string]*x509.Certificate{}}
	h.enroll = &fakeEnroll{ca: h.ca}
	h.setNow(vecNow)
	h.leader.on.Store(true)
	if len(nodes) == 0 {
		nodes = baseNodes
	}
	var objs []runtime.Object
	for _, n := range nodes {
		objs = append(objs, mkNode(n))
	}
	objs = append(objs,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: tokenSecret, Namespace: coreNS}, Data: map[string][]byte{tokenKey: []byte(testServerToken + "\n")}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: addressesCM, Namespace: coreNS}},
		// The CLI's empty removed-node params (removedparams.go).
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: removedCM, Namespace: coreNS}, Data: removedData(nil)},
	)
	h.kube = fake.NewSimpleClientset(objs...)
	cfg := Config{Domain: "example.org", CoreNS: coreNS, NodeadmNS: "portcullis-nodeadm", IngressNS: "portcullis-ingress",
		FencingNS: "portcullis-fencing", LonghornNS: "longhorn-system", ClusterCIDR: "10.42.0.0/16", ServiceCIDR: "10.43.0.0/16",
		EgressHost: "api.porkbun.com", PodName: "nodeadm-0", VaultVoters: 3, SentinelVoters: 3, Script: []byte("#!/bin/sh\necho join\n"),
		ScriptSHA256: strings.Repeat("a", 64), AgentSHA256: map[string]string{"amd64": strings.Repeat("b", 64), "arm64": strings.Repeat("c", 64)},
		AgentFiles: map[string]string{}, AllowDocAddrs: true}
	dir := t.TempDir()
	for _, a := range []string{"amd64", "arm64"} {
		p := dir + "/nodeagent-" + a
		os.WriteFile(p, []byte("nodeagent "+a), 0o644)
		cfg.AgentFiles[a] = p
	}
	s := newServer(cfg)
	s.kube, s.store, s.enroll, s.agents, s.bootstrap, s.leader = h.kube, h.store, h.enroll, h.agents, h.boot, h.leader
	h.probe = &fakeProbe{kube: h.kube}
	s.probe = h.probe
	s.limit = newLimiter(1000, 1000, 1000, 1000)
	s.now = func() time.Time { return h.now.Load().(time.Time) }
	s.rand = rand.Reader
	s.log = slog.New(slog.NewTextHandler(&lockedBuf{b: h.logs}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	// Revokes in the other steps' tests: the revoked node proven cut off
	// (outofservice_test.go uses the real evidence).
	s.cutOffCheck = func(context.Context, *revokeOp) []string { return nil }
	s.timing = Timing{Poll: 5 * time.Millisecond, PDBRefusal: 60 * time.Millisecond, DrainMax: 2 * time.Second,
		NodeReady: time.Second, LonghornEvict: 200 * time.Millisecond, RemovedConfirm: 50 * time.Millisecond}
	if err := s.pki.setCA(vs.PKI.CAPEM); err != nil {
		t.Fatal(err)
	}
	// The internal clients' certificates come from the test CA (the
	// vectors' CA key isn't in the vectors), trusted next to it.
	s.pki.pool.AddCert(h.ca.cert)
	for _, cn := range []string{clientHub, clientFrontdoor} {
		c, _ := h.ca.client(cn)
		h.clients[cn] = c
	}
	other := newTestCA(t, "another CA")
	h.clients["other-ca"], _ = other.client(clientHub)
	h.s = s
	return h
}

// do sends one request: client "none" = no TLS, else a verified-looking
// TLS state with that client's certificate.
func (h *harness) do(handler http.Handler, client, method, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if c := h.clients[client]; c != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func (h *harness) internal(client, method, path string, body any) *httptest.ResponseRecorder {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	return h.do(h.s.InternalHandler(), client, method, path, b, nil)
}

func (h *harness) public(method, path string, body []byte, hdr map[string]string) *httptest.ResponseRecorder {
	return h.do(h.s.PublicHandler(), "none", method, path, body, hdr)
}

func loadVectors(t testing.TB) *apiVectors {
	b, err := os.ReadFile("testdata/nodeadm_api_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs apiVectors
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	return &vs
}

// signedHeaders signs a join request as the node (key k, certificate c).
func signedHeaders(c *x509.Certificate, k *ecdsa.PrivateKey, id, path string, body []byte, at time.Time) map[string]string {
	nb := make([]byte, 16)
	rand.Read(nb)
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	tm := rfc3339(at)
	sum := sha256.Sum256(body)
	digest := sha256.Sum256(canonicalBytes(signedCanon{id, "POST", path, tm, nonce, hex.EncodeToString(sum[:])}))
	sig, _ := ecdsa.SignASN1(rand.Reader, k, digest[:])
	return map[string]string{"Portcullis-Node-Cert": base64.StdEncoding.EncodeToString(c.Raw), "Portcullis-Node-Time": tm,
		"Portcullis-Node-Nonce": nonce, "Portcullis-Node-Signature": base64.RawURLEncoding.EncodeToString(sig)}
}

// putState sets nodeadm's state.
func (h *harness) putState(t testing.TB, fn func(st *nodeadmState)) {
	if err := h.s.mutate(context.Background(), func(st *nodeadmState) error { fn(st); return nil }); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) state(t testing.TB) *nodeadmState {
	st, err := h.s.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func ptr[T any](v T) *T { return &v }

// admit plays the CLI's params-sync: the active (proven) generation's
// record portcullis-admission-active with node_addresses = addrs.
func (h *harness) admit(t testing.TB, addrs ...string) {
	var ps []string
	for _, a := range addrs {
		ps = append(ps, hostPrefix(a))
	}
	sort.Strings(ps)
	rec, _ := json.Marshal(activeRecord{Generation: paramsGeneration(map[string]string{"n": strings.Join(ps, " ")}),
		NodeAddresses: nonNilS(ps), APIAddresses: []string{"10.215.0.1/32"}, ProvenAt: rfc3339(h.s.now())})
	cms := h.kube.CoreV1().ConfigMaps(coreNS)
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: admissionActive, Namespace: coreNS}, Data: map[string]string{activeKey: string(rec)}}
	if _, err := cms.Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		if _, err := cms.Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
}

// syncParams: params-sync from the document nodeadm wrote (every address
// of every node and pending node).
func (h *harness) syncParams(t testing.TB) {
	h.s.reconcile(context.Background())
	cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(context.Background(), addressesCM, metav1.GetOptions{})
	var doc AddressesDoc
	if err := json.Unmarshal([]byte(cm.Data[addressesKey]), &doc); err != nil {
		t.Fatalf("no cluster addresses: %v", err)
	}
	var all []string
	for _, n := range doc.Nodes {
		if n.State != stateRemoved {
			all = append(all, append(append([]string{n.Mesh}, n.LAN...), n.Public...)...)
		}
	}
	h.admit(t, all...)
}

// withDynamic adds a fake dynamic client holding objs (CNPG, Longhorn).
func (h *harness) withDynamic(objs ...runtime.Object) *dynfake.FakeDynamicClient {
	sch := runtime.NewScheme()
	kinds := map[schema.GroupVersionResource]string{
		gvrCNPGCluster: "ClusterList", gvrLonghornNode: "NodeList", gvrLonghornReplica: "ReplicaList", gvrLonghornVolume: "VolumeList"}
	d := dynfake.NewSimpleDynamicClientWithCustomListKinds(sch, kinds, objs...)
	h.s.dyn = d
	return d
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var _ = fmt.Sprint

// fakeProbe plays every API server's answer to the removed-node probe:
// the generation in the ConfigMap is in force, unless down (no answer) or
// stale (the servers still judge with inForce).
type fakeProbe struct {
	kube    *fake.Clientset
	mu      sync.Mutex
	down    bool
	stale   bool
	inForce []string // the names the servers judge by
	calls   int
	// listed: the EndpointSlice's servers (default: n1's); unreachable:
	// servers that don't answer; probed: the last Confirm's list.
	listed      []string
	unreachable map[string]bool
	probed      []string
}

func (p *fakeProbe) Listed(ctx context.Context) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listed == nil {
		return []string{"10.215.0.1:6443"}, nil
	}
	return append([]string{}, p.listed...), nil
}

func (p *fakeProbe) Confirm(ctx context.Context, gen string, servers []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	p.probed = append([]string{}, servers...)
	if p.down {
		return errors.New("the API server 10.215.0.1:6443 doesn't answer")
	}
	for _, srv := range servers {
		if p.unreachable[srv] {
			return errors.New("the API server " + srv + " doesn't answer")
		}
	}
	cm, err := p.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, removedCM, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if p.stale || cm.Data["generation"] != gen {
		return errors.New("the API server 10.215.0.1:6443 doesn't confirm generation " + gen + " yet")
	}
	p.inForce = strings.Fields(cm.Data[removedKey])
	return nil
}

func (p *fakeProbe) refuses(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Contains(p.inForce, id)
}
