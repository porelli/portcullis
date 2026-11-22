package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Leader is the Lease fence (§20.5): writes only while Leading.
type Leader interface {
	Leading() bool
}

// SignedCert is enroll's answer to POST /internal/nodes/sign.
type SignedCert struct {
	CertPEM  string
	Serial   string
	NotAfter time.Time
	CAPEM    string
}

// Enroll signs and revokes pki_node certificates with nodeadm's own bearer
// (contract §17.5: node-cluster, node-frontdoor, node-nodeadm only).
type Enroll interface {
	Sign(ctx context.Context, role, cn, csrPEM string) (*SignedCert, error)
	Revoke(ctx context.Context, serial string) error
}

// Agents is nodeadm's nodeagent client (nodeadm.control, §20.4): only
// GET /v1/health, PUT /v1/probes/targets, POST /v1/k3s/token-rotate,
// POST /v1/etcd/remove-member and POST /v1/agent/upgrade.
type Agents interface {
	Health(ctx context.Context, id, meshIP string) (*AgentHealth, error)
	PutProbeTargets(ctx context.Context, id, meshIP string, t ProbeTargets) error
	TokenRotate(ctx context.Context, id, meshIP, newToken, step string) error
	// EtcdRemoveMember asks server via (its nodeagent, which holds the
	// etcd client key; nodeadm holds none) to remove the member of node,
	// which portcullis-cluster-addresses must list removed.
	EtcdRemoveMember(ctx context.Context, viaID, viaMesh, node, nodeMesh string) error
	// UpgradeAgent has node id take the nodeagent nodeadm serves (the
	// binaries' sums by architecture); "current" or "upgraded".
	UpgradeAgent(ctx context.Context, id, meshIP string, sums map[string]string) (string, error)
}

// K3sBootstrap answers the status of GET https://<server>:6443/v1-k3s/
// server-bootstrap with basic auth server:<token> (the rotation check),
// and AgentStatus an agent-authenticated supervisor call with
// node:<agent token> (the agent token's rotation check).
type K3sBootstrap interface {
	Status(ctx context.Context, serverIP, token string) (int, error)
	AgentStatus(ctx context.Context, serverIP, token string) (int, error)
	// Ready: GET /v1-k3s/readyz with the node credential derived from the
	// server token (k3s's own agents wait on it): 200 once that server's
	// k3s runs with the token (its old process accepts only the one it
	// started with) and its core is up (agent-token fix: a restart is
	// proven before the next server's).
	Ready(ctx context.Context, serverIP, serverToken string) (int, error)
}

// Config is nodeadm's configuration (from the chart's environment).
type Config struct {
	Domain       string // the main domain
	CoreNS       string // the core namespace (Leases, documents, params)
	NodeadmNS    string
	IngressNS    string // portcullis-ingress (Traefik's DaemonSet)
	FencingNS    string // portcullis-fencing (SNR)
	LonghornNS   string
	ClusterCIDR  string
	ServiceCIDR  string
	EgressHost   string // NODEADM_PROBE_EGRESS_HOST
	PodName      string
	Script       []byte            // join.sh
	ScriptSHA256 string            // sha256 of Script (the code's script_sha256)
	AgentFiles   map[string]string // arch → path of nodeagent-<arch>
	AgentSHA256  map[string]string // arch → sha256
	// AllowDocAddrs admits the documentation ranges as public addresses
	// (tests only, like the front door's testprovider build).
	AllowDocAddrs bool
}

// Timing holds the durations the tests shorten.
type Timing struct {
	Poll          time.Duration // between checks while waiting
	PDBRefusal    time.Duration // a PDB refusing this long → replica_minimum (120 s)
	DrainMax      time.Duration // a drain at most (10 min)
	NodeReady     time.Duration // a node Ready again after a token apply
	LonghornEvict time.Duration // Longhorn's replicas off the node
	NodeGone      time.Duration // a deleted server's Node gone (k3s's etcd finalizer) (5 min)
	// RemovedConfirm: a removed name confirmed in force on every API
	// server before its Node is deleted (90 s; removedparams.go).
	RemovedConfirm time.Duration
}

func defaultTiming() Timing {
	return Timing{Poll: 2 * time.Second, PDBRefusal: 120 * time.Second, DrainMax: 10 * time.Minute,
		NodeReady: 5 * time.Minute, LonghornEvict: 10 * time.Minute, NodeGone: 5 * time.Minute, RemovedConfirm: 90 * time.Second}
}

// Server is nodeadm.
type Server struct {
	cfg       Config
	kube      kubernetes.Interface
	dyn       dynamic.Interface
	store     Store
	enroll    Enroll
	agents    Agents
	bootstrap K3sBootstrap
	leader    Leader
	now       func() time.Time
	rand      io.Reader
	log       *slog.Logger
	timing    Timing
	pki       *pkiState
	metrics   *Metrics

	stateMu sync.Mutex // serialises state changes (the CAS guards across processes)
	opMu    sync.Mutex // one node operation (drain, removal, rotation) at a time
	limit   *limiter
	runMu   sync.Mutex
	running map[string]chan struct{} // revoke ops being driven, by node

	nonceMu    sync.Mutex
	nonces     map[string]nonceRec  // enrol nonces (single use, 60 s)
	joinNonces map[string]time.Time // signed-request nonces (5 min)

	snapMu     sync.Mutex
	degraded   map[string]time.Time // Longhorn volume → first seen not healthy
	lastPrim   string
	addrMu     sync.Mutex
	addrState  addrPublished
	kickCh     chan struct{}
	remHold    string // the remediation round's last hold (logged on change)
	remMu      sync.Mutex
	remStuck   []string // the last round's stuck remediations (snapshot errors)
	remUnknown []string // the last round's unknown Nodes (snapshot errors)
	// upMu / upgraded: the nodes whose nodeagent this process saw take its
	// binaries (node → their sums), so each is asked once per process.
	upMu     sync.Mutex
	upgraded map[string]string
	// probe confirms the removed-node params (removedparams.go);
	// removedMu serialises their writes, removedProven is the last
	// generation/resourceVersion every API server confirmed.
	probe         AdmissionProbe
	removedMu     sync.Mutex
	removedProven string
}

// pkiState holds the pki_node CA and nodeadm's own node-nodeadm
// certificate (key in memory only).
type pkiState struct {
	mu     sync.RWMutex
	ca     *x509.Certificate
	caPEM  string
	pool   *x509.CertPool
	own    *tls.Certificate
	ownEnd time.Time
}

func (p *pkiState) setCA(caPEM string) error {
	b, _ := pem.Decode([]byte(caPEM))
	if b == nil || b.Type != "CERTIFICATE" {
		return fmt.Errorf("the pki_node CA isn't one PEM certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || !c.IsCA {
		return fmt.Errorf("the pki_node CA doesn't parse as a CA")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ca, p.caPEM = c, caPEM
	p.pool = x509.NewCertPool()
	p.pool.AddCert(c)
	return nil
}

func (p *pkiState) caPool() *x509.CertPool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pool
}

func (p *pkiState) caSHA256() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.ca == nil {
		return ""
	}
	sum := sha256.Sum256(p.ca.Raw)
	return hex.EncodeToString(sum[:])
}

func (p *pkiState) caPEMString() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.caPEM
}

func (p *pkiState) ownCert() *tls.Certificate {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.own
}

type nonceRec struct {
	serverID string
	at       time.Time
}

// newServer wires a Server; the caller sets the collaborators.
func newServer(cfg Config) *Server {
	return &Server{cfg: cfg, now: time.Now, timing: defaultTiming(), pki: &pkiState{},
		kickCh: make(chan struct{}, 1), running: map[string]chan struct{}{}, nonces: map[string]nonceRec{}, joinNonces: map[string]time.Time{}, degraded: map[string]time.Time{},
		log: slog.New(slog.NewJSONHandler(io.Discard, nil)), metrics: newMetrics(),
		limit: newLimiter(perSourceRate, perSourceBurst, globalRate, globalBurst)}
}
