package main

// nodeadm's own state: the join codes (only the sha256 of each secret,
// which is secret-equivalent: the proof is keyed by it) and the enrolled
// nodes (role, labels, the node-cluster certificate's serial, the mesh
// report). It lives in the Secret nodeadm-state (key state.json) of the core
// namespace, which only nodeadm's Role may read or update (contract §20.3:
// "a nodeadm-only Secret"). Every change is a compare-and-swap on the
// Secret's resourceVersion, so two nodeadm processes (a leader change) can
// never both mark one code used. A hash is deleted when its code is used
// or expires; it is never logged, returned or audited.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	stateSecret = "nodeadm-state"
	stateKey    = "state.json"
)

type codeRecord struct {
	// KeySHA256: hex sha256 of the code's secret; "" once used or expired.
	KeySHA256 string   `json:"key_sha256,omitempty"`
	Role      string   `json:"role"`
	Class     string   `json:"class"`
	Site      string   `json:"site"`
	MeshIP    string   `json:"mesh_ip"`
	Ingress   bool     `json:"ingress"`
	Storage   bool     `json:"storage"`
	Mesh      MeshPlan `json:"mesh"`
	// Forward: the code's forwarded public endpoint (CodeReq.PublicEndpoint).
	Forward   string    `json:"forward,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

type nodeRecord struct {
	Role        string     `json:"role"`
	Class       string     `json:"class"`
	Site        string     `json:"site"`
	MeshIP      string     `json:"mesh_ip"`
	Ingress     bool       `json:"ingress"`
	Storage     bool       `json:"storage"`
	Serial      string     `json:"serial"`
	NotAfter    time.Time  `json:"not_after"`
	Mesh        MeshReport `json:"mesh"`
	EnrolledAt  time.Time  `json:"enrolled_at"`
	JoinedAt    *time.Time `json:"joined_at,omitempty"`
	ServerToken bool       `json:"server_token,omitempty"`
	// JoinState: enrolled → mesh_pending → waiting_admission → released
	// (§20.2); WaitingSince: the first waiting_admission answer.
	JoinState    string     `json:"join_state,omitempty"`
	WaitingSince *time.Time `json:"waiting_since,omitempty"`
	// Removed: the node is being removed; Addrs are the addresses the
	// document keeps for it (state removed) until the active admission
	// generation no longer holds its mesh address.
	Removed bool `json:"removed,omitempty"`
	// TokensStale: a removed node a rotation skipped (it keeps old tokens).
	TokensStale bool `json:"tokens_stale,omitempty"`
	// Labelled: nodeadm set its placement labels on the registered Node.
	Labelled bool `json:"labelled,omitempty"`
	// Renewal: a renewed certificate not yet confirmed (renew.go); until
	// confirm both it and Serial are valid.
	Renewal *renewal       `json:"renewal,omitempty"`
	Addrs   *NodeAddresses `json:"addrs,omitempty"`
	// TokenIDs: the bootstrap tokens issued to it (a revoke deletes them).
	TokenIDs []string `json:"token_ids,omitempty"`
	// Releases: how many times the join material went out (either role).
	Releases int `json:"releases,omitempty"`
	// EtcdPending: a cooperatively removed server whose Node delete was
	// sent and whose etcd member isn't confirmed gone yet (its mesh
	// address): a retry resumes at the etcd step, never at "enrolment
	// voided" (review M1); the record isn't dropped meanwhile.
	EtcdPending string `json:"etcd_pending,omitempty"`
	// Forward: the forwarded public UDP endpoint its code named (a NATed
	// node's way in from the other sites; the Hub plans and confirms it).
	Forward string `json:"forward,omitempty"`
}

type nodeadmState struct {
	V     int                    `json:"v"`
	Codes map[string]*codeRecord `json:"codes"`
	Nodes map[string]*nodeRecord `json:"nodes"`
	// Ops: the revocations under way (ops.go), by node.
	Ops map[string]*revokeOp `json:"ops,omitempty"`
	// OwnSerials: nodeadm's own node-nodeadm certificates; the leader
	// revokes every one but the current (review M11).
	OwnSerials []string `json:"own_serials,omitempty"`
	// PendingRevokes: every node-cluster serial still to revoke through
	// enroll (a removed node's, a renewed-away one, a refused renewal's),
	// by serial. Independent of the node records (a re-enrolment or a
	// dropped record never touches it); reconcile retries it until each is
	// revoked.
	PendingRevokes map[string]*pendingRevoke `json:"pending_revokes,omitempty"`
	// Remediations: per node, when nodeadm last created its
	// SelfNodeRemediation (remediate.go's back-off; nodeadm's own record,
	// never one a node could write).
	Remediations map[string]time.Time `json:"remediations,omitempty"`
	// Maintenance: nodes cordoned through nodeadm's cordon API (an admin's
	// mark: the storm guard skips a cordoned node only with it).
	Maintenance map[string]bool `json:"maintenance,omitempty"`
	// RemovedNames: every node name nodeadm removed (Task 30 fix round 1),
	// published as the cluster addresses' removed_names → params
	// removedNodes: portcullis-removed-nodes refuses that name's kubelet
	// identity a Node CREATE / UPDATE (its client certificate still
	// authenticates). A cooperatively removed name leaves the list when a
	// new node enrols under it (never at code issue: an unused or expired
	// code keeps the old kubelet refused); a revoked one never does (a new
	// code for it is refused: the old kubelet certificate would pass as the
	// new node).
	RemovedNames map[string]*removedName `json:"removed_names,omitempty"`
}

type removedName struct {
	At      time.Time `json:"at"`
	Revoked bool      `json:"revoked,omitempty"`
}

type renewal struct {
	CSRSHA256 string    `json:"csr_sha256"`
	Serial    string    `json:"serial"`
	CertPEM   string    `json:"cert_pem"`
	NotAfter  time.Time `json:"not_after"`
	IssuedAt  time.Time `json:"issued_at"`
}

type pendingRevoke struct {
	NodeID   string    `json:"node_id"`
	QueuedAt time.Time `json:"queued_at"`
}

// newState: every map made (round 5, found live: the Secret store's Load
// decodes into it, and a state saved without remediations / maintenance —
// omitempty — left those maps nil, so the first back-off record or
// maintenance mark panicked nodeadm).
func newState() *nodeadmState {
	return &nodeadmState{V: 1, Codes: map[string]*codeRecord{}, Nodes: map[string]*nodeRecord{}, Ops: map[string]*revokeOp{},
		PendingRevokes: map[string]*pendingRevoke{}, Remediations: map[string]time.Time{}, Maintenance: map[string]bool{},
		RemovedNames: map[string]*removedName{}}
}

func (st *nodeadmState) clone() *nodeadmState {
	b, _ := json.Marshal(st)
	out := newState()
	json.Unmarshal(b, out)
	if out.Codes == nil {
		out.Codes = map[string]*codeRecord{}
	}
	if out.Nodes == nil {
		out.Nodes = map[string]*nodeRecord{}
	}
	if out.Ops == nil {
		out.Ops = map[string]*revokeOp{}
	}
	if out.PendingRevokes == nil {
		out.PendingRevokes = map[string]*pendingRevoke{}
	}
	if out.Remediations == nil {
		out.Remediations = map[string]time.Time{}
	}
	if out.Maintenance == nil {
		out.Maintenance = map[string]bool{}
	}
	if out.RemovedNames == nil {
		out.RemovedNames = map[string]*removedName{}
	}
	return out
}

// errConflict: another writer changed the state since it was read.
var errConflict = errors.New("the state changed meanwhile")

// Store reads and compare-and-swaps the state.
type Store interface {
	Load(ctx context.Context) (*nodeadmState, string, error)
	Save(ctx context.Context, st *nodeadmState, version string) (string, error)
}

// secretStore keeps the state in the Secret nodeadm-state (created by the
// chart, empty; nodeadm has get / update on it only).
type secretStore struct {
	kube kubernetes.Interface
	ns   string
}

func (s *secretStore) Load(ctx context.Context) (*nodeadmState, string, error) {
	sec, err := s.kube.CoreV1().Secrets(s.ns).Get(ctx, stateSecret, metav1.GetOptions{})
	err = secretErr(err)
	if err != nil {
		return nil, "", fmt.Errorf("reading the Secret %s: %w", stateSecret, err)
	}
	st := newState()
	if b := sec.Data[stateKey]; len(b) > 0 {
		var err error
		if st, err = decodeState(b); err != nil {
			return nil, "", err
		}
	}
	return st, sec.ResourceVersion, nil
}

// decodeState: strict (an unknown field, e.g. an older format's, or
// trailing data refuses the state: never loaded with data silently
// dropped). The error names the field, never a value (the state holds
// code hashes).
func decodeState(b []byte) (*nodeadmState, error) {
	st := newState()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(st); err != nil {
		msg := "it doesn't parse"
		if f, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
			msg = "it has the unknown field " + f + " (another nodeadm version's format: nothing is migrated)"
		}
		return nil, fmt.Errorf("the Secret %s is refused: %s", stateSecret, msg)
	}
	if dec.More() {
		return nil, fmt.Errorf("the Secret %s is refused: trailing data", stateSecret)
	}
	return st.clone(), nil
}

func (s *secretStore) Save(ctx context.Context, st *nodeadmState, version string) (string, error) {
	b, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: stateSecret, Namespace: s.ns, ResourceVersion: version,
		Labels: map[string]string{"app.kubernetes.io/managed-by": "portcullis"}},
		Type: corev1.SecretTypeOpaque, Data: map[string][]byte{stateKey: b}}
	out, err := s.kube.CoreV1().Secrets(s.ns).Update(ctx, sec, metav1.UpdateOptions{})
	err = secretErr(err)
	if apierrors.IsConflict(err) {
		return "", errConflict
	}
	if err != nil {
		return "", fmt.Errorf("writing the Secret %s: %w", stateSecret, err)
	}
	return out.ResourceVersion, nil
}

// memStore is an in-process Store (tests).
type memStore struct {
	mu  sync.Mutex
	st  *nodeadmState
	ver int
}

func (m *memStore) Load(context.Context) (*nodeadmState, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil {
		m.st = newState()
	}
	return m.st.clone(), fmt.Sprint(m.ver), nil
}

func (m *memStore) Save(_ context.Context, st *nodeadmState, version string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if version != fmt.Sprint(m.ver) {
		return "", errConflict
	}
	m.ver++
	m.st = st.clone()
	return fmt.Sprint(m.ver), nil
}

// load reads the state.
func (s *Server) load(ctx context.Context) (*nodeadmState, error) {
	st, _, err := s.store.Load(ctx)
	return st, err
}

// mutate applies fn to a fresh copy of the state and compare-and-swaps it;
// on a conflict fn runs again on the newer state (it must re-check what it
// relies on). fn returning an error writes nothing.
func (s *Server) mutate(ctx context.Context, fn func(st *nodeadmState) error) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	for range 5 {
		st, ver, err := s.store.Load(ctx)
		if err != nil {
			return err
		}
		if err := fn(st); err != nil {
			return err
		}
		if _, err := s.store.Save(ctx, st, ver); err != nil {
			if errors.Is(err, errConflict) {
				continue
			}
			return err
		}
		return nil
	}
	return fmt.Errorf("the state kept changing: retry")
}

// sweepCodes deletes the hash of every expired code (and forgets a code
// record a day after its expiry).
func (s *Server) sweepCodes(ctx context.Context) error {
	now := s.now()
	return s.mutate(ctx, func(st *nodeadmState) error {
		for id, c := range st.Codes {
			if now.After(c.ExpiresAt) && c.KeySHA256 != "" {
				c.KeySHA256 = ""
				s.log.Info("join code expired: its hash deleted", "server_id", id)
			}
			if now.After(c.ExpiresAt.Add(24 * time.Hour)) {
				delete(st.Codes, id)
			}
		}
		return nil
	})
}

// secretErr: an API error about a Secret without the API server's message
// (an "invalid" answer may quote the object's values: a token, the state's
// code hashes; review M3). The reason and the code survive, so
// IsConflict / IsNotFound still work.
func secretErr(err error) error {
	if err == nil {
		return nil
	}
	var se apierrors.APIStatus
	if errors.As(err, &se) {
		st := se.Status()
		return &apierrors.StatusError{ErrStatus: metav1.Status{Status: metav1.StatusFailure, Code: st.Code, Reason: st.Reason,
			Message: fmt.Sprintf("the API server answered %d %s (its message withheld: it may quote the Secret)", st.Code, st.Reason)}}
	}
	return errors.New(redact(err.Error()))
}
