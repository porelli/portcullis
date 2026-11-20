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
//	node_deleted     its Node object deleted;
//	published        the cluster addresses list it removed;
//	etcd_removed     (a server) its etcd member removed through a surviving
//	                 server's nodeagent;
//	server_rotated   a new server token, generated and persisted in the op
//	                 BEFORE the rotate call, in effect (server-bootstrap: the
//	                 new one 200, the old one 401) and promoted to the Secret;
//	agent_rotated    the same for the agent token;
//	applied          every surviving server then agent applied, recorded
//	                 per node;
//	done             the op's tokens dropped.
//
// A resumed rotation first asks the supervisor which token it accepts: the
// new one means the rotate already took effect (promote it), the old one
// means rotate again with the persisted new one. The op's tokens live in
// nodeadm-state only (nodeadm-only; never logged, never in an answer).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
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
	NewAgent  string         `json:"new_agent,omitempty"`
	Applied   []string       `json:"applied,omitempty"`
	Started   time.Time      `json:"started"`
	LastError string         `json:"last_error,omitempty"`
}

var revokeSteps = []string{"created", "marked", "tokens_deleted", "node_deleted", "published", "etcd_removed",
	"server_rotated", "agent_rotated", "applied", "done"}

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
			if st.Nodes[id] == nil && st.Codes[id] == nil {
				return err
			}
			n = nil
		} else if err != nil {
			return err
		}
		op := &revokeOp{Node: id, Step: "created", Started: s.now()}
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
		if op.Role == "server" {
			// etcd's own quorum rule, before anything changes.
			cl, err := s.clusterNodes(ctx)
			if err != nil {
				return err
			}
			if voters, healthy := etcdQuorum(cl); healthy*2 <= voters {
				return errPlain(http.StatusServiceUnavailable, textNoQuorum)
			}
		}
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
		return fmt.Errorf("revoking %s stopped at %s: %s", id, op.Step, op.LastError)
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
			msg := trunc(redact(err.Error()), 200)
			s.log.Warn("revocation stopped (resumed later)", "node", id, "err", msg)
			if !s.leader.Leading() {
				return // the next holder resumes it
			}
			_ = s.mutate(context.Background(), func(st *nodeadmState) error {
				if op := st.Ops[id]; op != nil {
					op.LastError = msg
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
		op.LastError = ""
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
	switch next {
	case "marked":
		if err := s.forget(ctx, id, op.Addrs); err != nil {
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
	case "node_deleted":
		if err := s.kube.CoreV1().Nodes().Delete(ctx, id, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("deleting node %s: %w", id, err)
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
	case "server_rotated":
		if err := s.rotateOne(ctx, op, false); err != nil {
			return err
		}
	case "agent_rotated":
		if err := s.rotateOne(ctx, op, true); err != nil {
			return err
		}
	case "applied":
		if err := s.applyTokens(ctx, op); err != nil {
			return err
		}
	case "done":
		op.NewServer, op.NewAgent = "", ""
	}
	op.Step = next
	if err := s.opStep(ctx, id, func(o *revokeOp) { o.Step, o.NewServer, o.NewAgent = next, op.NewServer, op.NewAgent }); err != nil {
		return err
	}
	s.log.Info("revocation step done", "node", id, "step", next)
	return nil
}

// survivors: the nodes a rotation applies to, refused while any of them
// has no mesh address (it would keep the old token, M6).
func (s *Server) survivors(ctx context.Context, gone string) (servers, agents []clusterNode, err error) {
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range cl {
		if n.Name == gone {
			continue
		}
		if n.Mesh == "" {
			return nil, nil, fmt.Errorf("node %s has no mesh address: the tokens can't be applied there", n.Name)
		}
		if n.Role == "server" {
			servers = append(servers, n)
		} else {
			agents = append(agents, n)
		}
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	return servers, agents, nil
}

// rotateOne rotates the server (agent false) or the agent token: the new
// one persisted first, then the supervisor asked which one it accepts.
func (s *Server) rotateOne(ctx context.Context, op *revokeOp, agent bool) error {
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
		return errors.New("no Ready server to rotate the k3s tokens on")
	}
	old, err := s.serverToken(ctx)
	if err != nil {
		return err
	}
	cur := old
	user, step, key := serverTokenLabel, "rotate", tokenKey
	if agent {
		if cur, err = s.agentToken(ctx); err != nil {
			return err
		}
		user, step, key = "node", "rotate-agent", agentTokenKey
	}
	newTok := op.NewServer
	if agent {
		newTok = op.NewAgent
	}
	if newTok == "" {
		if newTok, err = newK10(caHash(old), user); err != nil {
			return err
		}
		// Persisted BEFORE the rotate call.
		if err := s.opStep(ctx, op.Node, func(o *revokeOp) {
			if agent {
				o.NewAgent = newTok
			} else {
				o.NewServer = newTok
			}
		}); err != nil {
			return err
		}
		if agent {
			op.NewAgent = newTok
		} else {
			op.NewServer = newTok
		}
	}
	secrets := []string{old, cur, newTok}
	status := func(tok string) (int, error) {
		if s.bootstrap == nil {
			return 0, errors.New("no supervisor check")
		}
		if agent {
			return s.bootstrap.AgentStatus(ctx, rot.Mesh, tok)
		}
		return s.bootstrap.Status(ctx, rot.Mesh, tok)
	}
	if cur != newTok {
		if st, err := status(newTok); err != nil || st != http.StatusOK {
			// Not in effect yet: rotate (the nodeagent authenticates with its
			// own token file, the old one).
			if err := s.agents.TokenRotate(ctx, rot.Name, rot.Mesh, newTok, step); err != nil {
				return fmt.Errorf("token %s on %s: %w", step, rot.Name, redactErr(err, secrets...))
			}
		}
		newSt, err1 := status(newTok)
		oldSt, err2 := status(cur)
		if err1 != nil || err2 != nil || newSt != http.StatusOK || oldSt != http.StatusUnauthorized {
			return fmt.Errorf("the rotated %s token isn't in effect on %s (new %d, old %d)", user, rot.Name, newSt, oldSt)
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
	sec.Data[key] = []byte(newTok)
	sec.StringData = nil
	if _, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Update(ctx, sec, metav1.UpdateOptions{}); secretErr(err) != nil {
		err = secretErr(err)
		return fmt.Errorf("writing the Secret %s: %w", tokenSecret, err)
	}
	s.log.Info("k3s token rotated", "kind", user, "on", rot.Name)
	return nil
}

// applyTokens: each surviving server (apply the server token, apply-agent
// the agent token) one at a time, then each agent (apply the agent token),
// each Ready again before the next; recorded per node.
func (s *Server) applyTokens(ctx context.Context, op *revokeOp) error {
	servers, agents, err := s.survivors(ctx, op.Node)
	if err != nil {
		return err
	}
	srv, err := s.serverToken(ctx)
	if err != nil {
		return err
	}
	agt, err := s.agentToken(ctx)
	if err != nil {
		return err
	}
	call := func(n clusterNode, tok, step string) error {
		if err := s.agents.TokenRotate(ctx, n.Name, n.Mesh, tok, step); err != nil {
			return fmt.Errorf("token %s on %s: %w", step, n.Name, redactErr(err, srv, agt))
		}
		return nil
	}
	for _, n := range append(servers, agents...) {
		if slices.Contains(op.Applied, n.Name) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("stopped: %w", err)
		}
		if n.Role == "server" {
			if err := call(n, srv, "apply"); err != nil {
				return err
			}
			if err := call(n, agt, "apply-agent"); err != nil {
				return err
			}
		} else if err := call(n, agt, "apply"); err != nil {
			return err
		}
		if err := s.waitReady(ctx, n.Name); err != nil {
			return err
		}
		op.Applied = append(op.Applied, n.Name)
		name := n.Name
		if err := s.opStep(ctx, op.Node, func(o *revokeOp) {
			if !slices.Contains(o.Applied, name) {
				o.Applied = append(o.Applied, name)
			}
		}); err != nil {
			return err
		}
		s.log.Info("k3s tokens applied", "node", n.Name)
	}
	return nil
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
