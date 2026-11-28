package main

// A revoked server's volumes (Task 33b VM run 15, controller ruling A):
// nodeadm's revoke deleted the Node with nothing detached, so a
// replicated-tier volume attached there (the Hub's, in that run) kept its
// Kubernetes VolumeAttachment `attached: true` for good and Longhorn never
// attached it on a survivor: the Hub stayed down. Remediation gets its
// force-detach from SNR's out-of-service taint; a revoke never goes
// through SNR, and a deleted Node can carry no taint. So before
// node_deleted the revoke waits until T_fence (fenceTime) has passed since
// it started (a revoked node resets itself about a minute after its
// revoke: contract §20), puts node.kubernetes.io/out-of-service=
// nodeshutdown:NoExecute on the Node (Kubernetes' non-graceful node
// shutdown: its pods are deleted and its volumes force-detached), and
// waits until no VolumeAttachment names the node.
//
// Never on elapsed time alone (security review of ruling A: a revoked
// machine SNR doesn't reset, or a hostile one, may still write; detaching
// its volumes then makes two writers). The taint needs positive evidence,
// observed by nodeadm itself, continuously for the whole T_fence: its Node
// NotReady, its Node lease stale (not renewed within its duration), and
// its mesh peer out of every surviving node's plan (each survivor's
// nodeagent answers and lists no such peer: without the mesh it reaches
// no Longhorn replica). Any of it missing (a survivor's nodeagent silent
// included: fail closed) and the step parks with cutoff_pending, "waiting
// for <id> to be cut off: …", retried; the way out is powering the
// machine off (or cutting its network), and nodeadm finishes. Admission
// (portcullis-removed-nodes) lets nodeadm put exactly that taint, only on
// a node it lists removed, and change no other taint but its own two.

import (
	"context"
	"encoding/json"
	"net/netip"

	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	taintOutOfService = "node.kubernetes.io/out-of-service"
	oosValue          = "nodeshutdown"
)

func isOutOfService(t corev1.Taint) bool {
	return t.Key == taintOutOfService && t.Value == oosValue && t.Effect == corev1.TaintEffectNoExecute
}

// outOfService is the revoke's out_of_service step (servers only).
func (s *Server) outOfService(ctx context.Context, op *revokeOp) error {
	id := op.Node
	// No Node (it never registered, or it went by hand — nodeadm deletes it
	// only at node_deleted, after this step): nothing can carry the taint,
	// so nothing is force-detached; the revoke goes on (its volumes, if
	// any, stay attached to the gone name, never to two writers).
	if _, err := s.kube.CoreV1().Nodes().Get(ctx, id, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		s.log.Warn("revocation: no Node to put out of service: no taint, nothing force-detached", "node", id)
		return nil
	}
	if err := s.waitCutOff(ctx, op); err != nil {
		return err
	}
	for try := 0; ; try++ {
		n, err := s.kube.CoreV1().Nodes().Get(ctx, id, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// Gone during the proof: not tainted.
			s.log.Warn("revocation: the Node went during the cut-off proof: no taint", "node", id)
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading node %s: %w", id, err)
		}
		has := false
		for _, t := range n.Spec.Taints {
			if isOutOfService(t) {
				has = true
			}
		}
		if has {
			break
		}
		// Its name must be refused (in force) first: admission lets the taint
		// only on a node listed removed.
		if err := s.removedInForce(ctx, id); err != nil {
			return err
		}
		taints := append(append([]corev1.Taint{}, n.Spec.Taints...), corev1.Taint{Key: taintOutOfService, Value: oosValue, Effect: corev1.TaintEffectNoExecute})
		b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"resourceVersion": n.ResourceVersion}, "spec": map[string]any{"taints": taints}})
		_, err = s.kube.CoreV1().Nodes().Patch(ctx, id, types.MergePatchType, b, metav1.PatchOptions{})
		if err == nil {
			s.log.Info("revocation: node put out of service (its pods deleted, its volumes force-detached)", "node", id)
			break
		}
		if !apierrors.IsConflict(err) || try >= 5 {
			return fmt.Errorf("putting node %s out of service: %s", id, redact(err.Error()))
		}
	}
	return s.waitDetached(ctx, id)
}

// waitDetached: no VolumeAttachment names node id (≤ Timing.Detach); else
// the step fails naming them and is retried (the security steps are done).
func (s *Server) waitDetached(ctx context.Context, id string) error {
	wait := s.timing.Detach
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		l, err := s.kube.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing the volume attachments: %s", redact(err.Error()))
		}
		var left []string
		for _, va := range l.Items {
			if va.Spec.NodeName == id {
				pv := ""
				if va.Spec.Source.PersistentVolumeName != nil {
					pv = *va.Spec.Source.PersistentVolumeName
				}
				left = append(left, pv)
			}
		}
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			sort.Strings(left)
			return errPlain(http.StatusServiceUnavailable, "node %s is out of service but volumes are still attached to it (%s): the revocation goes on when it is retried", id, strings.Join(left, ", "))
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}

// kindCutoffPending: the revoked server isn't proven cut off yet (§20.2).
const kindCutoffPending = "cutoff_pending"

// waitCutOff returns once node op.Node has been cut off (cutOffReasons
// empty) on every observation for T_fence (Timing.Fence) in a row, polled
// every Timing.Poll for at most T_fence + Timing.Cutoff; else a
// cutoff_pending error naming what is missing.
func (s *Server) waitCutOff(ctx context.Context, op *revokeOp) error {
	id := op.Node
	extra := s.timing.Cutoff
	if extra <= 0 {
		extra = time.Minute
	}
	start := time.Now()
	deadline := start.Add(s.timing.Fence + extra)
	var since time.Time // first observation of the current cut-off run
	var why []string
	s.log.Info("revocation: waiting for the server to be cut off before the out-of-service taint", "node", id, "for", s.timing.Fence.String())
	for {
		if s.cutOffCheck != nil {
			why = s.cutOffCheck(ctx, op)
		} else {
			why = s.cutOffReasons(ctx, op)
		}
		now := time.Now()
		if len(why) > 0 {
			since = time.Time{}
		} else if since.IsZero() {
			since = now
		}
		if !since.IsZero() && now.Sub(since) >= s.timing.Fence {
			s.log.Info("revocation: the server is cut off (NotReady, its lease stale, no mesh peer) for T_fence", "node", id)
			return nil
		}
		if now.After(deadline) {
			if len(why) == 0 {
				why = []string{"cut off only since " + since.UTC().Format(time.RFC3339) + ", less than T_fence"}
			}
			return errKind(http.StatusConflict, kindCutoffPending, "waiting for %s to be cut off: %s; power the machine off (or cut its network) and nodeadm finishes the revoke (retried: ./portcullis node revoke %s)", id, strings.Join(why, "; "), id)
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}

// cutOffReasons: what still shows node op.Node may write, or what isn't
// proven (none: cut off). Fail closed throughout (second security
// review): a missing Node lease or Node is "not proven"; the survivors'
// WireGuard devices are the load-bearing evidence (kubelet timestamps
// alone are weak): every other node's nodeagent must answer with its
// plan peers and its device peers (by public key), no device may hold a
// peer for the revoked node's mesh address, and none may have seen a
// handshake since the revoke from a key that isn't a surviving node's own
// (that covers the revoked key after it left the plan).
func (s *Server) cutOffReasons(ctx context.Context, op *revokeOp) []string {
	id := op.Node
	var why []string
	n, err := s.kube.CoreV1().Nodes().Get(ctx, id, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		why = append(why, "its Node is missing (not deleted by this revoke: not proven)")
	case err != nil:
		why = append(why, "its Node is unreadable")
	default:
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
				why = append(why, "its Node is Ready")
			}
		}
	}
	l, err := s.kube.CoordinationV1().Leases("kube-node-lease").Get(ctx, id, metav1.GetOptions{})
	switch {
	case apierrors.IsNotFound(err):
		why = append(why, "its Node lease is missing (not proven)")
	case err != nil:
		why = append(why, "its Node lease is unreadable")
	default:
		dur := 40 * time.Second
		if l.Spec.LeaseDurationSeconds != nil && *l.Spec.LeaseDurationSeconds > 0 {
			dur = time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second
		}
		if l.Spec.RenewTime == nil {
			why = append(why, "its Node lease has no renew time")
		} else if age := time.Since(l.Spec.RenewTime.Time); age < dur {
			why = append(why, fmt.Sprintf("its Node lease was renewed %s ago", age.Round(time.Second)))
		}
	}
	mesh, err := netip.ParseAddr(op.Mesh)
	if err != nil {
		why = append(why, "its mesh address is unknown")
	}
	// The keys nodeadm itself enrolled (third security review): never a
	// key a node reports. The revoked node's is a denylist, whatever the
	// rest says.
	enrolled, err := s.enrolledKeys(ctx)
	if err != nil {
		return append(why, "the enrolled mesh keys are unreadable")
	}
	revokedKey := enrolled[id].pub
	if revokedKey == "" {
		why = append(why, "its enrolled mesh key is unknown (not proven)")
	}
	allowed := map[string]bool{}
	for name, e := range enrolled {
		if name != id && !e.removed && e.pub != "" {
			allowed[e.pub] = true
		}
	}
	boundary := op.Started.Truncate(time.Second).Add(-handshakeSkew)
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return append(why, "the nodes are unreadable")
	}
	type devPeer struct {
		LatestHandshake *string  `json:"latest_handshake"`
		AllowedIPs      []string `json:"allowed_ips"`
	}
	for _, c := range cl {
		if c.Name == id {
			continue
		}
		if c.Mesh == "" {
			why = append(why, c.Name+" has no mesh address to ask")
			continue
		}
		hc, cancel := context.WithTimeout(ctx, 10*time.Second)
		h, err := s.agents.Health(hc, c.Name, c.Mesh)
		cancel()
		if err != nil {
			why = append(why, c.Name+"'s nodeagent doesn't answer")
			continue
		}
		if own := enrolled[c.Name].pub; own == "" {
			why = append(why, c.Name+" has no enrolled mesh key (not proven)")
		} else if h.MeshPub != own {
			why = append(why, c.Name+" reports a mesh key that isn't its enrolled one (not proven)")
		}
		if isNullJSON(h.Peers) || isNullJSON(h.DevicePeers) {
			why = append(why, c.Name+" reported no mesh state")
			continue
		}
		var plan map[string]json.RawMessage
		var dev map[string]devPeer
		if json.Unmarshal(h.Peers, &plan) != nil || plan == nil || json.Unmarshal(h.DevicePeers, &dev) != nil || dev == nil {
			why = append(why, c.Name+"'s mesh state is unreadable")
			continue
		}
		if _, ok := plan[id]; ok {
			why = append(why, "still a mesh peer of "+c.Name+" (its plan)")
		}
		for _, k := range sortedKeys(dev) {
			p := dev[k]
			if revokedKey != "" && k == revokedKey {
				why = append(why, fmt.Sprintf("%s's WireGuard device still holds the revoked node's enrolled key %s", c.Name, k))
			}
			for _, a := range p.AllowedIPs {
				if pf, err := netip.ParsePrefix(a); err == nil && mesh.IsValid() && pf.Contains(mesh) {
					why = append(why, fmt.Sprintf("%s's WireGuard device still has a peer for %s (key %s)", c.Name, op.Mesh, k))
				}
			}
			if p.LatestHandshake != nil && (!allowed[k] || k == revokedKey) {
				// Since the revoke: anything not strictly before the start's
				// second minus handshakeSkew (WireGuard reports whole seconds).
				if t, err := time.Parse(time.RFC3339, *p.LatestHandshake); err != nil || !t.Before(boundary) {
					why = append(why, fmt.Sprintf("%s saw a handshake at %s from key %s, which isn't a surviving node's enrolled key", c.Name, *p.LatestHandshake, k))
				}
			}
		}
	}
	return why
}

// handshakeSkew: a handshake counts as seen since the revoke unless it is
// strictly before the revoke's start, truncated to the second WireGuard
// reports, minus this (the nodes' clocks; third security review).
const handshakeSkew = 5 * time.Second

type enrolledKey struct {
	pub     string
	removed bool
}

// enrolledKeys: each node's mesh public key as nodeadm enrolled it (its
// record's mesh report), the first node's from the CLI's
// portcullis-first-node (which it never enrolled).
func (s *Server) enrolledKeys(ctx context.Context) (map[string]enrolledKey, error) {
	st, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]enrolledKey{}
	for name, r := range st.Nodes {
		if r != nil {
			out[name] = enrolledKey{pub: r.Mesh.Pub, removed: r.Removed}
		}
	}
	doc, err := s.firstNode(ctx)
	if err != nil {
		return nil, err
	}
	if doc != nil && doc.MeshPub != "" {
		e := out[doc.ID]
		if e.pub == "" {
			e.pub = doc.MeshPub
		}
		out[doc.ID] = e
	}
	return out, nil
}

func isNullJSON(b json.RawMessage) bool {
	t := strings.TrimSpace(string(b))
	return t == "" || t == "null"
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
