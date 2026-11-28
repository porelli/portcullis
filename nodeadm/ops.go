package main

// Revocation as a resumable operation (review C1, I1, M6, M13). A revoke
// is recorded in nodeadm-state (Ops) and driven by the Lease holder in a
// context of its own (never the request's), one recorded step at a time,
// so a closed connection, a failed step or a restart resumes it where it
// stopped:
//
//	marked           the node removed and its certificate revoked (no join
//	                 can pass verifySigned any more);
//	tokens_deleted   its bootstrap tokens deleted from kube-system;
//	server_rotated   a new server token, generated and persisted in the op
//	                 BEFORE the rotate call, in effect (server-bootstrap: the
//	                 new one 200, the old one 401; the node credential k3s
//	                 derives from it likewise) and promoted to the Secret;
//	applied          every Ready surviving server applied (its token file,
//	                 one restart), recorded per node (the revoked node
//	                 skipped); agents hold no shared token: nothing to apply;
//	node_deleted     its Node object deleted          } gated by etcd's
//	                 (only once its name is refused   } quorum (a server:
//	                 on every API server: R-I2)       } revokeQuorum)
//	published        the cluster addresses list it    }
//	                 removed                          }
//	etcd_removed     (a server) its etcd member removed through a surviving
//	                 server's nodeagent;
//	server_rotated2  (a server) the token rotated again, the same way:
//	                 until its member is gone the revoked server could read
//	                 the datastore (the first rotation's bootstrap data too);
//	applied2         every survivor applied (the ones down so far too);
//	done             refused unless every required rotation is recorded;
//	                 the op's tokens dropped.
//
// While parked before node_deleted, a server target is NOT fully cut off:
// its joins are refused and the tokens rotated, but it stays an etcd
// member until quorum returns; a compromised server also holds the etcd
// peer certificates and the cluster CA, so recovery needs rotate-ca.
//
// A resumed rotation first asks the supervisor which token it accepts: the
// new one means the rotate already took effect (promote it), the old one
// means rotate again with the persisted new one. The op's tokens live in
// nodeadm-state only (nodeadm-only; never logged, never in an answer).
//
// One token (agent-token fix, tokens.go): k3s's supported rotation, PUT
// /v1-k3s/token on one server, rewrites that server's cred/passwd (the
// server line, and the node line derived from it) and re-saves the
// datastore's bootstrap copy from its disk; every other server takes the
// new passwd from the datastore at its next start (the token file
// written, one restart). No step changes passwd any other way, so no
// server's disk is ever newer than the datastore. The agent token steps
// (rotate-agent, apply-agent) are gone: k3s re-saves nothing after a
// separate agent token changes, and the next start of every server was
// fatal.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type revokeOp struct {
	Node      string         `json:"node"`
	Role      string         `json:"role"`
	Mesh      string         `json:"mesh"`
	Addrs     *NodeAddresses `json:"addrs,omitempty"`
	Serial    string         `json:"serial,omitempty"`
	TokenIDs  []string       `json:"token_ids,omitempty"`
	Step      string         `json:"step"`
	NewServer string         `json:"new_server,omitempty"`
	Applied   []string       `json:"applied,omitempty"`
	Applied2  []string       `json:"applied2,omitempty"`
	// StepsVersion: the step list the op was recorded under.
	StepsVersion int `json:"steps_version"`
	// The rotations proven in effect (done refuses without them).
	ServerRotated  bool      `json:"server_rotated,omitempty"`
	ServerRotated2 bool      `json:"server_rotated2,omitempty"`
	Skipped        []string  `json:"skipped,omitempty"` // removed nodes the rotation didn't touch (N6)
	Started        time.Time `json:"started"`
	LastError      string    `json:"last_error,omitempty"`
	LastKind       string    `json:"last_kind,omitempty"` // an error kind (quorum_minimum) for the answer
}

// Security first (fix rounds 5, 6): the token is rotated and applied to
// the Ready surviving servers before the quorum-gated Node / etcd steps,
// which blocks the node's supervisor joins at once. A server target is NOT
// fully cut off while it stays an etcd member: it can read the datastore,
// including the rotated token's bootstrap data. So for a server the token
// is rotated AGAIN after etcd_removed (server_rotated2) and applied to
// every surviving server (applied2): the token finally in effect never was
// in a datastore it could reach. An agent needs the first rotation only
// (server_rotated2 does nothing); applied2 then gives the token to the
// servers that were down.
var revokeSteps = []string{"created", "marked", "tokens_deleted", "server_rotated", "applied",
	"out_of_service", "node_deleted", "published", "etcd_removed", "server_rotated2", "applied2", "done"}

// revokeStepsVersion: an op recorded under another step list restarts from
// marked (every step is idempotent; fail closed, fix round 6). 4: the
// agent token steps are gone (agent-token fix). 5: out_of_service (a
// server's Node put out of service after T_fence, its volumes detached,
// before node_deleted: Task 33b VM run 15, ruling A).
const revokeStepsVersion = 5

func stepIndex(s string) int { return slices.Index(revokeSteps, s) }

// fenced is a context cancelled when ctx ends or the Lease is lost (M13).
func (s *Server) fenced(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !s.leader.Leading() {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, cancel
}

// revoke records (or finds) the node's revocation and waits for it while
// the request lasts; the op goes on without it.
func (s *Server) revoke(ctx context.Context, id string) error {
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	if st.Ops[id] == nil {
		n, err := s.getNode(ctx, id)
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			// Revoked and finished (Task 30 fix round 1): its name is
			// listed revoked for good, so a revoke asked again (the Hub
			// restarted mid-call, the CLI asks once more) is done — also
			// while its burnt code's record is still kept (fix round 2,
			// found live: each resend ran a whole new revoke, restarting
			// the servers again), and while its removed record is still kept
			// (dropped only once the active admission generation leaves its
			// addresses; found live too). No op is recorded (a parked or
			// running one is above), so the revocation finished. A revoked
			// name gets no new code.
			if rn := st.RemovedNames[id]; rn != nil && rn.Revoked && (st.Nodes[id] == nil || st.Nodes[id].Removed) {
				return nil
			}
			if st.Nodes[id] == nil && st.Codes[id] == nil {
				return err
			}
			n = nil
		} else if err != nil {
			return err
		}
		op := &revokeOp{Node: id, Step: "created", Started: s.now(), StepsVersion: revokeStepsVersion}
		if n != nil {
			cn := toClusterNode(n)
			cn.Addresses = s.cleanAddrs(cn.Addresses)
			op.Role, op.Mesh, op.Addrs = cn.Role, cn.Mesh, &cn.Addresses
		}
		if rec := st.Nodes[id]; rec != nil {
			if op.Role == "" {
				op.Role, op.Mesh = rec.Role, rec.MeshIP
			}
			op.Serial, op.TokenIDs = rec.Serial, append([]string{}, rec.TokenIDs...)
		}
		// No quorum gate here: the security steps (marked, tokens_deleted)
		// always run at once; revokeStep gates only node_deleted and
		// etcd_removed (fix round 4).
		if err := s.mutate(ctx, func(st *nodeadmState) error {
			if st.Ops[id] == nil {
				st.Ops[id] = op
			}
			return nil
		}); err != nil {
			return err
		}
		s.log.Info("revocation recorded", "node", id)
	}
	done := s.driveOp(id)
	select {
	case <-done:
	case <-ctx.Done():
		return errPlain(http.StatusServiceUnavailable, "the revocation of %s goes on in the background: retry to see it finish", id)
	}
	st, err = s.load(ctx)
	if err != nil {
		return err
	}
	if op := st.Ops[id]; op != nil {
		if op.LastKind != "" {
			return errKind(http.StatusConflict, op.LastKind, "%s", op.LastError)
		}
		return fmt.Errorf("revoking %s stopped at %s: %s", id, op.Step, op.LastError)
	}
	return nil
}

// revokeQuorum (review N2): removing server target must leave a strict
// majority of etcd's current members healthy, judged on live state. The
// members: every server Node, plus every server whose revoke hasn't
// reached etcd_removed (its Node may be gone; it still votes, unhealthy).
// Healthy: the Ready server Nodes now. After the removal: members − 1,
// healthy − (target Ready).
func (s *Server) revokeQuorum(ctx context.Context, target string) error {
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	voters, healthy := map[string]bool{}, map[string]bool{}
	for _, c := range cl {
		if c.Role == "server" {
			voters[c.Name] = true
			if c.Ready {
				healthy[c.Name] = true
			}
		}
	}
	for id, op := range st.Ops {
		if op.Role == "server" && stepIndex(op.Step) < stepIndex("etcd_removed") {
			voters[id] = true
		}
	}
	if !voters[target] {
		return nil
	}
	v, h := len(voters)-1, len(healthy)
	if healthy[target] {
		h--
	}
	if h*2 <= v {
		return errKind(http.StatusConflict, "quorum_minimum",
			"removing %s would leave etcd %d healthy of %d members: parked; security steps done; the server stays an etcd member until quorum returns; a compromised server needs rotate-ca", target, h, v)
	}
	return nil
}

// driveOp runs the node's op unless it already runs; the channel closes
// when this run ends.
func (s *Server) driveOp(id string) <-chan struct{} {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if ch, ok := s.running[id]; ok {
		return ch
	}
	ch := make(chan struct{})
	s.running[id] = ch
	go func() {
		defer func() {
			s.runMu.Lock()
			delete(s.running, id)
			s.runMu.Unlock()
			close(ch)
		}()
		ctx, cancel := s.fenced(context.Background())
		defer cancel()
		s.opMu.Lock()
		defer s.opMu.Unlock()
		if err := s.runRevoke(ctx, id); err != nil {
			msg := trunc(redact(err.Error()), 400)
			s.log.Warn("revocation stopped (resumed later)", "node", id, "err", msg)
			if !s.leader.Leading() {
				return // the next holder resumes it
			}
			kind := ""
			var ae *apiError
			if errors.As(err, &ae) {
				kind = ae.Kind
			}
			_ = s.mutate(context.Background(), func(st *nodeadmState) error {
				if op := st.Ops[id]; op != nil {
					op.LastError, op.LastKind = msg, kind
				}
				return nil
			})
		}
	}()
	return ch
}

// resumeOps drives every recorded op (the leader's loop).
func (s *Server) resumeOps(ctx context.Context) {
	st, err := s.load(ctx)
	if err != nil {
		return
	}
	for id := range st.Ops {
		s.driveOp(id)
	}
}

func (s *Server) opStep(ctx context.Context, id string, fn func(op *revokeOp)) error {
	return s.mutate(ctx, func(st *nodeadmState) error {
		op := st.Ops[id]
		if op == nil {
			return errors.New("the op is gone")
		}
		fn(op)
		op.LastError, op.LastKind = "", ""
		return nil
	})
}

func (s *Server) loadOp(ctx context.Context, id string) (*revokeOp, error) {
	st, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	op := st.Ops[id]
	if op == nil {
		return nil, errors.New("the op is gone")
	}
	return op, nil
}

func (s *Server) runRevoke(ctx context.Context, id string) error {
	for {
		// The Lease fence between steps (M13): a lost Lease stops here.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("stopped: %w", err)
		}
		op, err := s.loadOp(ctx, id)
		if err != nil {
			return err
		}
		if op.StepsVersion != revokeStepsVersion || stepIndex(op.Step) < 0 {
			// Another step list: from marked again, the rotation flags and
			// the applied lists cleared; a persisted new token is kept (it
			// may be in effect: rotateOne proves which one is).
			from := op.StepsVersion
			if err := s.opStep(ctx, id, func(o *revokeOp) {
				o.Step, o.StepsVersion = "created", revokeStepsVersion
				o.ServerRotated, o.ServerRotated2 = false, false
				o.Applied, o.Applied2 = nil, nil
			}); err != nil {
				return err
			}
			s.log.Warn("revocation recorded under another step list: restarted from marked", "node", id, "steps_version", from)
			continue
		}
		if err := s.revokeStep(ctx, op); err != nil {
			return err
		}
		if op.Step == "done" {
			return s.mutate(ctx, func(st *nodeadmState) error { delete(st.Ops, id); return nil })
		}
	}
}

// revokeStep runs the step after op.Step and records it.
func (s *Server) revokeStep(ctx context.Context, op *revokeOp) error {
	id := op.Node
	next := revokeSteps[stepIndex(op.Step)+1]
	// etcd's quorum gates only the steps that delete the Node (and put it
	// out of service first) or change etcd membership; the certificate revoke, the mark and the bootstrap token
	// deletes never wait for it (fix round 4). A refusal parks the op
	// before node_deleted with quorum_minimum, resumed by reconcile.
	if op.Role == "server" && (next == "out_of_service" || next == "node_deleted" || next == "etcd_removed") {
		if err := s.revokeQuorum(ctx, id); err != nil {
			return err
		}
	}
	switch next {
	case "marked":
		if err := s.forget(ctx, id, op.Addrs, true); err != nil {
			return err
		}
	case "tokens_deleted":
		for _, t := range op.TokenIDs {
			err := s.kube.CoreV1().Secrets(bootstrapNS).Delete(ctx, "bootstrap-token-"+t, metav1.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("deleting bootstrap token %s: %w", t, err)
			}
			s.log.Info("bootstrap token deleted", "node", id, "token_id", t)
		}
	case "out_of_service":
		// Servers only (the ruling); an agent's Node is deleted as before.
		if op.Role == "server" {
			if err := s.outOfService(ctx, op); err != nil {
				return err
			}
		}
	case "node_deleted":
		if err := s.clearRemediation(ctx, id); err != nil {
			return err
		}
		// Only once its name is refused on every API server (fix round 2,
		// R-I2); else the step fails, the op parks here and is retried.
		if err := s.deleteRemovedNode(ctx, id); err != nil {
			return err
		}
	case "published":
		if err := s.publishAddresses(ctx); err != nil {
			return err
		}
	case "etcd_removed":
		if op.Role == "server" {
			if err := s.removeEtcdMember(ctx, clusterNode{Name: id, Role: "server", Mesh: op.Mesh}); err != nil {
				return err
			}
		}
	case "server_rotated", "server_rotated2":
		if next == "server_rotated2" && op.Role != "server" {
			break
		}
		if err := s.rotateOne(ctx, op); err != nil {
			return err
		}
		// Proven and promoted: the next rotation makes a new token.
		op.NewServer = ""
		if next == "server_rotated" {
			op.ServerRotated = true
		} else {
			op.ServerRotated2 = true
		}
	case "applied":
		if err := s.applyTokens(ctx, op, false, &op.Applied); err != nil {
			return err
		}
	case "applied2":
		if err := s.applyTokens(ctx, op, true, &op.Applied2); err != nil {
			return err
		}
	case "done":
		if !op.ServerRotated || (op.Role == "server" && !op.ServerRotated2) {
			return fmt.Errorf("the revocation of %s can't finish: a required token rotation isn't recorded", id)
		}
		op.NewServer = ""
		if len(op.Skipped) > 0 {
			skipped := op.Skipped
			if err := s.mutate(ctx, func(st *nodeadmState) error {
				for _, k := range skipped {
					if r := st.Nodes[k]; r != nil {
						r.TokensStale = true
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
	}
	op.Step = next
	if err := s.opStep(ctx, id, func(o *revokeOp) {
		o.Step, o.NewServer = next, op.NewServer
		o.ServerRotated, o.ServerRotated2 = op.ServerRotated, op.ServerRotated2
	}); err != nil {
		return err
	}
	s.log.Info("revocation step done", "node", id, "step", next)
	return nil
}

// survivors: the nodes a rotation applies to, refused while a server has
// no mesh address (it would keep the old token, M6; agents hold no shared
// token and get nothing). A node whose
// record is removed (re-registered after a revoke, or another op's
// target) is skipped, never called: the op records it in Skipped and the
// snapshot names it (review N6).
func (s *Server) survivors(ctx context.Context, gone string) (servers, agents []clusterNode, err error) {
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	var skipped []string
	for _, n := range cl {
		if n.Name == gone {
			continue
		}
		if rec := st.Nodes[n.Name]; rec != nil && rec.Removed {
			skipped = append(skipped, n.Name)
			continue
		}
		if n.Mesh == "" && n.Role == "server" {
			return nil, nil, fmt.Errorf("node %s has no mesh address: the token can't be applied there", n.Name)
		}
		if n.Role == "server" {
			servers = append(servers, n)
		} else {
			agents = append(agents, n)
		}
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	if len(skipped) > 0 {
		sort.Strings(skipped)
		if err := s.opStep(ctx, gone, func(o *revokeOp) {
			for _, k := range skipped {
				if !slices.Contains(o.Skipped, k) {
					o.Skipped = append(o.Skipped, k)
				}
			}
		}); err != nil {
			return nil, nil, err
		}
		s.log.Warn("removed nodes skipped by the token rotation (revoke them again)", "op", gone, "skipped", strings.Join(skipped, ","))
	}
	return servers, agents, nil
}

// rotateOne rotates the server token (and with it the node credential k3s
// derives from it): the new one persisted first, then the supervisor
// asked which one it accepts.
func (s *Server) rotateOne(ctx context.Context, op *revokeOp) error {
	servers, _, err := s.survivors(ctx, op.Node)
	if err != nil {
		return err
	}
	var rot *clusterNode
	for i := range servers {
		if servers[i].Ready {
			rot = &servers[i]
			break
		}
	}
	if rot == nil {
		return errors.New("no Ready server to rotate the k3s token on")
	}
	cur, err := s.serverToken(ctx)
	if err != nil {
		return err
	}
	newTok := op.NewServer
	if newTok == "" {
		if newTok, err = newK10(caHash(cur), serverTokenLabel); err != nil {
			return err
		}
		// Persisted BEFORE the rotate call.
		if err := s.opStep(ctx, op.Node, func(o *revokeOp) { o.NewServer = newTok }); err != nil {
			return err
		}
		op.NewServer = newTok
	}
	secrets := []string{cur, newTok, nodeCredential(cur), nodeCredential(newTok)}
	if s.bootstrap == nil {
		return errors.New("no supervisor check")
	}
	if cur != newTok {
		if st, err := s.bootstrap.Status(ctx, rot.Mesh, newTok); err != nil || st != http.StatusOK {
			// Not in effect yet: rotate (the nodeagent authenticates with its
			// own token file, the old one).
			if err := s.agents.TokenRotate(ctx, rot.Name, rot.Mesh, newTok, "rotate"); err != nil {
				return fmt.Errorf("token rotate on %s: %w", rot.Name, redactErr(err, secrets...))
			}
		}
		// In effect: the new token answers, the old one is refused, and so
		// is the node credential derived from the old one (fail closed: a
		// server whose k3s kept a separate agent token would leave that one
		// working). The nodeagent restarts k3s --no-block: wait for the
		// restart (Timing.NodeReady) rather than fail on the old process.
		_ = s.waitToken(ctx, *rot, newTok)
		newSt, err1 := s.bootstrap.Status(ctx, rot.Mesh, newTok)
		oldSt, err2 := s.bootstrap.Status(ctx, rot.Mesh, cur)
		newNode, err3 := s.bootstrap.AgentStatus(ctx, rot.Mesh, nodeCredential(newTok))
		oldNode, err4 := s.bootstrap.AgentStatus(ctx, rot.Mesh, nodeCredential(cur))
		if err1 != nil || err2 != nil || newSt != http.StatusOK || oldSt != http.StatusUnauthorized {
			return fmt.Errorf("the rotated server token isn't in effect on %s (new %d, old %d)", rot.Name, newSt, oldSt)
		}
		if err3 != nil || err4 != nil || newNode != http.StatusOK || oldNode != http.StatusUnauthorized {
			return fmt.Errorf("the node credential didn't rotate with the server token on %s (new %d, old %d): does its k3s run with --agent-token-file?", rot.Name, newNode, oldNode)
		}
	}
	// Promote the proven token to the Secret.
	sec, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Get(ctx, tokenSecret, metav1.GetOptions{})
	if err = secretErr(err); err != nil {
		return fmt.Errorf("reading the Secret %s: %w", tokenSecret, err)
	}
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data[tokenKey] = []byte(newTok)
	sec.StringData = nil
	if _, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Update(ctx, sec, metav1.UpdateOptions{}); secretErr(err) != nil {
		err = secretErr(err)
		return fmt.Errorf("writing the Secret %s: %w", tokenSecret, err)
	}
	s.log.Info("k3s token rotated", "kind", serverTokenLabel, "on", rot.Name)
	return nil
}

// applyTokens: each surviving server gets the server token (apply: its
// token file, one restart), one at a time, each Ready again before the
// next; recorded per node. Agents get nothing: they hold no shared token
// (their bootstrap token is deleted, they restart on their node identity).
// final false applies the Ready servers and leaves the others for later;
// final true applies every surviving server not applied yet, waiting (the
// op retries) while one isn't Ready.
func (s *Server) applyTokens(ctx context.Context, op *revokeOp, final bool, applied *[]string) error {
	servers, _, err := s.survivors(ctx, op.Node)
	if err != nil {
		return err
	}
	srv, err := s.serverToken(ctx)
	if err != nil {
		return err
	}
	for _, n := range servers {
		if slices.Contains(*applied, n.Name) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("stopped: %w", err)
		}
		if !n.Ready {
			if final {
				return fmt.Errorf("waiting for %s to be Ready to apply the rotated k3s token", n.Name)
			}
			s.log.Info("k3s token deferred until the node is Ready", "node", n.Name)
			continue
		}
		if err := s.agents.TokenRotate(ctx, n.Name, n.Mesh, srv, "apply"); err != nil {
			return fmt.Errorf("token apply on %s: %w", n.Name, redactErr(err, srv, nodeCredential(srv)))
		}
		// Restarted before the next one (found live, agent-token fix): the
		// nodeagent restarts k3s --no-block and the Node stays Ready for a
		// while, so Ready alone let every server restart at once (the API
		// and etcd's quorum gone for a minute). k3s's readyz answering the
		// new token's node credential proves the restart is done (its old
		// process accepts only the token it started with), then Ready.
		if err := s.waitToken(ctx, n, srv); err != nil {
			return err
		}
		if err := s.waitReady(ctx, n.Name); err != nil {
			return err
		}
		*applied = append(*applied, n.Name)
		name, second := n.Name, applied == &op.Applied2
		if err := s.opStep(ctx, op.Node, func(o *revokeOp) {
			l := &o.Applied
			if second {
				l = &o.Applied2
			}
			if !slices.Contains(*l, name) {
				*l = append(*l, name)
			}
		}); err != nil {
			return err
		}
		s.log.Info("k3s token applied", "node", n.Name)
	}
	return nil
}

// waitToken waits (Timing.NodeReady) for n's k3s to run with tok and be
// ready (its supervisor's readyz with the node credential derived from
// tok: the supervisor alone answers seconds into a start, long before the
// API server and etcd, found live).
func (s *Server) waitToken(ctx context.Context, n clusterNode, tok string) error {
	if s.bootstrap == nil {
		return errors.New("no supervisor check")
	}
	deadline := time.Now().Add(s.timing.NodeReady)
	for {
		if st, err := s.bootstrap.Ready(ctx, n.Mesh, tok); err == nil && st == http.StatusOK {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s's k3s doesn't answer with the applied token: not restarted with it yet", n.Name)
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}

// publishAddresses writes the cluster addresses now (a revoke's step).
func (s *Server) publishAddresses(ctx context.Context) error {
	nodes, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	doc, errs := s.buildAddresses(nodes, st)
	if doc == nil {
		return fmt.Errorf("the cluster addresses can't be written: %v", errs)
	}
	return s.writeAddresses(ctx, docJSON(doc))
}
