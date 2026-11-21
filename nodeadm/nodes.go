package main

// Node operations (contract §20.2): labels, cordon / uncordon, drain
// (the eviction API only, PodDisruptionBudgets respected, never a
// force-delete), cooperative removal and revocation.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const (
	labelClass    = "portcullis.io/class"
	labelSite     = "portcullis.io/site"
	labelZone     = "topology.kubernetes.io/zone"
	labelIngress  = "portcullis.io/ingress"
	labelStorage  = "portcullis.io/storage"
	labelEnableLB = "svccontroller.k3s.cattle.io/enablelb"
	labelDisk     = "node.longhorn.io/create-default-disk"
	labelServer   = "node-role.kubernetes.io/control-plane"
	taintSmall    = "portcullis.io/small"
	// annAddresses: the node's LAN and public addresses, {"lan": [...],
	// "public": [...]}, set by nodeadm from the enrolment report and by the
	// CLI on the first node.
	annAddresses = "portcullis.io/addresses"
)

// clusterNode is one Kubernetes node as nodeadm uses it.
type clusterNode struct {
	Name      string
	Role      string
	Class     string
	Site      string
	Ingress   bool
	Ready     bool
	Mesh      string
	Addresses NodeAddresses
	// RawLAN: its LAN addresses before the uniqueness rule (dedupeLAN).
	RawLAN []string
	Node   *corev1.Node
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func isServer(n *corev1.Node) bool {
	return n.Labels[labelServer] == "true" || n.Labels["node-role.kubernetes.io/master"] == "true"
}

// nodeAddrs: the mesh address (the InternalIP inside 10.215.0.0/24), the
// LAN and public ones (the annotation, an InternalIP outside the mesh, an
// ExternalIP), each valid IPv4/IPv6, deduplicated and sorted.
func nodeAddrs(n *corev1.Node) NodeAddresses {
	var out NodeAddresses
	lan, pub := map[string]bool{}, map[string]bool{}
	var ann struct {
		LAN    []string `json:"lan"`
		Public []string `json:"public"`
	}
	if v := n.Annotations[annAddresses]; v != "" && json.Unmarshal([]byte(v), &ann) == nil {
		for _, a := range ann.LAN {
			lan[a] = true
		}
		for _, a := range ann.Public {
			pub[a] = true
		}
	}
	for _, a := range n.Status.Addresses {
		switch a.Type {
		case corev1.NodeInternalIP:
			if meshAddrOK(a.Address) && out.Mesh == "" {
				out.Mesh = a.Address
			} else {
				lan[a.Address] = true
			}
		case corev1.NodeExternalIP:
			pub[a.Address] = true
		}
	}
	norm := func(m map[string]bool) []string {
		res := []string{}
		for a := range m {
			if ip, err := netip.ParseAddr(a); err == nil && ip.String() == a && !meshPrefix.Contains(ip) {
				res = append(res, a)
			}
		}
		sort.Strings(res)
		return res
	}
	out.LAN, out.Public = norm(lan), norm(pub)
	return out
}

func toClusterNode(n *corev1.Node) clusterNode {
	role := "agent"
	if isServer(n) {
		role = "server"
	}
	site := n.Labels[labelSite]
	if site == "" {
		site = primarySite
	}
	a := nodeAddrs(n)
	return clusterNode{Name: n.Name, Role: role, Class: n.Labels[labelClass], Site: site, Ingress: n.Labels[labelIngress] == "true",
		Ready: nodeReady(n), Mesh: a.Mesh, Addresses: a, Node: n}
}

// clusterNodes lists the Kubernetes nodes, by name.
func (s *Server) clusterNodes(ctx context.Context) ([]clusterNode, error) {
	l, err := s.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing the nodes: %w", err)
	}
	out := make([]clusterNode, 0, len(l.Items))
	for i := range l.Items {
		c := toClusterNode(&l.Items[i])
		c.Addresses = s.cleanAddrs(c.Addresses)
		c.RawLAN = append([]string{}, c.Addresses.LAN...)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	st, err := s.load(ctx)
	if err != nil {
		st = nil
	}
	dedupeLAN(out, st)
	return out, nil
}

func (s *Server) getNode(ctx context.Context, id string) (*corev1.Node, error) {
	n, err := s.kube.CoreV1().Nodes().Get(ctx, id, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, errUnknownNode(id)
	}
	if err != nil {
		return nil, fmt.Errorf("reading node %s: %w", id, err)
	}
	return n, nil
}

// patchNode sends a JSON merge patch.
func (s *Server) patchNode(ctx context.Context, id string, patch any) error {
	b, _ := json.Marshal(patch)
	_, err := s.kube.CoreV1().Nodes().Patch(ctx, id, types.MergePatchType, b, metav1.PatchOptions{})
	if err != nil {
		return fmt.Errorf("patching node %s: %w", id, err)
	}
	return nil
}

// labelPatch is the §20.1 label set of a node (a full replacement of
// nodeadm's labels; nil removes one) and its taints with the small one
// set or removed.
func labelPatch(n *corev1.Node, req LabelsReq) map[string]any {
	set := map[string]bool{}
	for _, l := range nodeLabels(req.Class, req.Site, req.Ingress, req.Storage) {
		k, _, _ := strings.Cut(l, "=")
		set[k] = true
	}
	labels := map[string]any{}
	for _, k := range []string{labelClass, labelSite, labelZone, labelIngress, labelEnableLB, labelStorage, labelDisk} {
		labels[k] = nil
	}
	for _, l := range nodeLabels(req.Class, req.Site, req.Ingress, req.Storage) {
		k, v, _ := strings.Cut(l, "=")
		labels[k] = v
	}
	taints := []corev1.Taint{}
	for _, t := range n.Spec.Taints {
		if t.Key != taintSmall && t.Key != taintUnlabelled {
			taints = append(taints, t)
		}
	}
	if req.Class == "small" {
		taints = append(taints, corev1.Taint{Key: taintSmall, Value: "true", Effect: corev1.TaintEffectNoSchedule})
	}
	return map[string]any{"metadata": map[string]any{"labels": labels}, "spec": map[string]any{"taints": taints}}
}

// PUT /v1/nodes/{id}/labels
func (s *Server) handleLabels(w http.ResponseWriter, r *http.Request) error {
	id, err := nodeID(r)
	if err != nil {
		return err
	}
	b, err := readBody(r)
	if err != nil {
		return err
	}
	var req LabelsReq
	if err := decodeStrict(b, &req); err != nil {
		return err
	}
	if !slices.Contains(classes, req.Class) || !serverIDRe.MatchString(req.Site) {
		return errPlain(400, "class must be small, home or cloud and site a site name")
	}
	n, err := s.getNode(r.Context(), id)
	if err != nil {
		return err
	}
	// The taints are replaced whole: the patch carries the read's
	// resourceVersion, and a conflict reads again (review M8).
	for try := 0; ; try++ {
		p := labelPatch(n, req)
		if n.ResourceVersion != "" {
			p["metadata"].(map[string]any)["resourceVersion"] = n.ResourceVersion
		}
		err := s.patchNode(r.Context(), id, p)
		if err == nil {
			break
		}
		if !apierrors.IsConflict(errors.Unwrap(err)) || try >= 3 {
			return err
		}
		if n, err = s.getNode(r.Context(), id); err != nil {
			return err
		}
	}
	s.log.Info("node labels set", "node", id, "class", req.Class, "site", req.Site, "ingress", req.Ingress, "storage", req.Storage)
	if err := s.mutate(r.Context(), func(st *nodeadmState) error {
		if rec := st.Nodes[id]; rec != nil {
			rec.Class, rec.Site, rec.Ingress, rec.Storage = req.Class, req.Site, req.Ingress, req.Storage
			rec.Labelled = true
		}
		return nil
	}); err != nil {
		return err
	}
	s.kick()
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// POST /v1/nodes/{id}/cordon|uncordon
func (s *Server) handleCordon(on bool) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		id, err := nodeID(r)
		if err != nil {
			return err
		}
		if err := emptyBody(r); err != nil {
			return err
		}
		n, err := s.getNode(r.Context(), id)
		if err != nil {
			return err
		}
		// The maintenance mark (remediate.go): only a cordon made here
		// keeps the node out of fencing — spec.unschedulable alone could be
		// anyone's. Cordon: markAndCordon. Uncordon: the cordon lifted
		// first, then the mark.
		if on {
			if err := s.markAndCordon(r.Context(), id, n); err != nil {
				return err
			}
		} else {
			if err := s.patchNode(r.Context(), id, map[string]any{"spec": map[string]any{"unschedulable": false}}); err != nil {
				return err
			}
			if err := s.mutate(r.Context(), func(st *nodeadmState) error { delete(st.Maintenance, id); return nil }); err != nil {
				return err
			}
		}
		s.log.Info("node cordon", "node", id, "unschedulable", on)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}

// markAndCordon: the maintenance mark first, then the cordon (round 4
// nit 2: a failed state write never leaves a cordon unmarked; a mark
// without the cordon excludes nothing — remediate.go needs both). A failed
// cordon rolls back only a mark THIS call added (round 5 nit 3, and the
// security review of it): never when the mark or the cordon (n, read
// before) was already there, and never when the Node reads back cordoned
// or can't be read (the patch may have landed: keeping the mark is the
// side that never makes a node in maintenance fenceable).
func (s *Server) markAndCordon(ctx context.Context, id string, n *corev1.Node) error {
	was := false
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		was = st.Maintenance[id]
		st.Maintenance[id] = true
		return nil
	}); err != nil {
		return err
	}
	perr := s.patchNode(ctx, id, map[string]any{"spec": map[string]any{"unschedulable": true}})
	if perr == nil || was || n.Spec.Unschedulable {
		return perr
	}
	if cur, err := s.getNode(ctx, id); err != nil || cur.Spec.Unschedulable {
		return perr
	}
	if err := s.mutate(ctx, func(st *nodeadmState) error { delete(st.Maintenance, id); return nil }); err != nil {
		s.log.Warn("couldn't roll back a maintenance mark after a failed cordon", "node", id, "err", redact(err.Error()))
	}
	return perr
}

// POST /v1/nodes/{id}/drain
func (s *Server) handleDrain(w http.ResponseWriter, r *http.Request) error {
	id, err := nodeID(r)
	if err != nil {
		return err
	}
	if err := emptyBody(r); err != nil {
		return err
	}
	n, err := s.getNode(r.Context(), id)
	if err != nil {
		return err
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	ctx, cancel := s.fenced(r.Context())
	defer cancel()
	if err := s.quorumMinimum(ctx, n); err != nil {
		return err
	}
	if err := s.drain(ctx, id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// quorumMinimum refuses taking a server away while 3 or fewer servers are
// healthy (Ready).
func (s *Server) quorumMinimum(ctx context.Context, n *corev1.Node) error {
	if !isServer(n) {
		return nil
	}
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	healthy := 0
	for _, c := range cl {
		if c.Role == "server" && c.Ready {
			healthy++
		}
	}
	if healthy <= 3 {
		return errKind(http.StatusConflict, "quorum_minimum", "removing %s would leave fewer than 3 servers", n.Name)
	}
	return nil
}

// podSetName is the set a pod belongs to: its StatefulSet, its Deployment
// (the ReplicaSet without its pod-template-hash), its CNPG cluster, else
// the pod itself.
func podSetName(p *corev1.Pod) string {
	if c := p.Labels["cnpg.io/cluster"]; c != "" {
		return c
	}
	for _, o := range p.OwnerReferences {
		switch o.Kind {
		case "StatefulSet", "DaemonSet", "Job":
			return o.Name
		case "ReplicaSet":
			if h := p.Labels["pod-template-hash"]; h != "" {
				return strings.TrimSuffix(o.Name, "-"+h)
			}
			return o.Name
		}
	}
	return p.Name
}

func isDaemonSetPod(p *corev1.Pod) bool {
	for _, o := range p.OwnerReferences {
		if o.Kind == "DaemonSet" {
			return true
		}
	}
	return false
}

// drain cordons the node and evicts every pod but DaemonSet and mirror
// pods through the eviction API; a PDB that keeps refusing a pod for
// Timing.PDBRefusal is replica_minimum; at most Timing.DrainMax overall.
func (s *Server) drain(ctx context.Context, id string) error {
	// Planned maintenance (remediate.go): a drained node isn't fenced.
	n, err := s.getNode(ctx, id)
	if err != nil {
		return err
	}
	if err := s.markAndCordon(ctx, id, n); err != nil {
		return err
	}
	start := time.Now()
	pods, err := s.kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("spec.nodeName", id).String()})
	if err != nil {
		return fmt.Errorf("listing %s's pods: %w", id, err)
	}
	var evicted []corev1.Pod
	for _, p := range pods.Items {
		if p.Spec.NodeName != id || isDaemonSetPod(&p) || p.Annotations[corev1.MirrorPodAnnotationKey] != "" ||
			p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		var refusedSince time.Time
		for {
			err := s.kube.PolicyV1().Evictions(p.Namespace).Evict(ctx, &policyv1.Eviction{ObjectMeta: metav1.ObjectMeta{Name: p.Name, Namespace: p.Namespace}})
			if err == nil || apierrors.IsNotFound(err) {
				break
			}
			if !apierrors.IsTooManyRequests(err) {
				return fmt.Errorf("evicting %s/%s: %w", p.Namespace, p.Name, err)
			}
			now := time.Now()
			if refusedSince.IsZero() {
				refusedSince = now
			}
			if now.Sub(refusedSince) >= s.timing.PDBRefusal {
				s.log.Warn("drain refused by a PodDisruptionBudget", "node", id, "pod", p.Namespace+"/"+p.Name)
				return errKind(http.StatusConflict, "replica_minimum", "draining %s would take %s below its minimum", id, podSetName(&p))
			}
			if now.Sub(start) >= s.timing.DrainMax {
				return fmt.Errorf("draining %s took longer than %s", id, s.timing.DrainMax)
			}
			if err := sleepCtx(ctx, s.timing.Poll); err != nil {
				return err
			}
		}
		evicted = append(evicted, p)
	}
	// Wait for the evicted pods to be gone (never a force-delete).
	for {
		left := 0
		for _, p := range evicted {
			cur, err := s.kube.CoreV1().Pods(p.Namespace).Get(ctx, p.Name, metav1.GetOptions{})
			if err == nil && cur.UID == p.UID && cur.Spec.NodeName == id {
				left++
			}
		}
		if left == 0 {
			s.log.Info("node drained", "node", id, "evicted", len(evicted))
			return nil
		}
		if time.Now().Sub(start) >= s.timing.DrainMax {
			return fmt.Errorf("draining %s: %d pods still there after %s", id, left, s.timing.DrainMax)
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}

var (
	gvrLonghornNode    = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "nodes"}
	gvrLonghornReplica = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "replicas"}
	gvrLonghornVolume  = schema.GroupVersionResource{Group: "longhorn.io", Version: "v1beta2", Resource: "volumes"}
	gvrCNPGCluster     = schema.GroupVersionResource{Group: "postgresql.cnpg.io", Version: "v1", Resource: "clusters"}
)

// evictLonghorn asks Longhorn to move the node's replicas away and waits
// until none is left (no Longhorn node: nothing to do).
func (s *Server) evictLonghorn(ctx context.Context, id string) error {
	if s.dyn == nil {
		return nil
	}
	ln := s.dyn.Resource(gvrLonghornNode).Namespace(s.cfg.LonghornNS)
	if _, err := ln.Get(ctx, id, metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) || isNoKind(err) {
			return nil
		}
		return fmt.Errorf("reading Longhorn's node %s: %w", id, err)
	}
	patch := []byte(`{"spec":{"evictionRequested":true,"allowScheduling":false}}`)
	if _, err := ln.Patch(ctx, id, types.MergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("asking Longhorn to evict %s: %w", id, err)
	}
	deadline := time.Now().Add(s.timing.LonghornEvict)
	for {
		l, err := s.dyn.Resource(gvrLonghornReplica).Namespace(s.cfg.LonghornNS).List(ctx, metav1.ListOptions{LabelSelector: "longhornnode=" + id})
		if err == nil && len(l.Items) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return errKind(http.StatusConflict, "replica_minimum", "draining %s would take its storage replicas below their minimum", id)
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}

func isNoKind(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "could not find the requested resource") || strings.Contains(err.Error(), "no matches for kind"))
}

// DELETE /v1/nodes/{id}?mode=cooperative|revoke
func (s *Server) handleRemove(w http.ResponseWriter, r *http.Request) error {
	id, err := nodeID(r)
	if err != nil {
		return err
	}
	mode := r.URL.Query()["mode"]
	if len(mode) != 1 || (mode[0] != "cooperative" && mode[0] != "revoke") {
		return errPlain(http.StatusBadRequest, textMode)
	}
	if mode[0] == "revoke" {
		err = s.revoke(r.Context(), id)
	} else {
		s.opMu.Lock()
		ctx, cancel := s.fenced(r.Context())
		err = s.removeCooperative(ctx, id)
		cancel()
		s.opMu.Unlock()
	}
	if err != nil {
		return err
	}
	s.kick()
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// forget revokes a node's certificate (if any), voids its code, and marks
// it removed with addrs (its document entry, state removed, until the
// active admission generation drops it; ruling R-ADM). A code that never
// enrolled leaves nothing behind.
func (s *Server) forget(ctx context.Context, id string, addrs *NodeAddresses) error {
	// Marked removed first (verifySigned refuses from here on, whether or
	// not enroll is up), the serial queued in PendingRevokes; then every
	// pending serial revoked; a failed one stays queued and is retried by
	// reconcile, the record kept until none is left (review N6).
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		if c := st.Codes[id]; c != nil {
			c.KeySHA256, c.Used = "", true
		}
		rec := st.Nodes[id]
		if rec == nil && addrs == nil {
			return nil
		}
		if rec == nil {
			rec = &nodeRecord{}
			st.Nodes[id] = rec
		}
		if addrs != nil {
			a := *addrs
			rec.Addrs = &a
		}
		st.queueRevoke(id, rec.Serial, s.now())
		if rec.Renewal != nil {
			st.queueRevoke(id, rec.Renewal.Serial, s.now())
			rec.Renewal = nil
		}
		rec.Removed, rec.Serial = true, ""
		return nil
	}); err != nil {
		return err
	}
	return s.revokePending(ctx, id)
}

// revokePending revokes the queued serials (of node id; every node's
// with id ""), dropping each one enroll revoked; an error while one of
// them is left.
func (s *Server) revokePending(ctx context.Context, id string) error {
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	var done []string
	var failed error
	for sr, p := range st.PendingRevokes {
		if id != "" && p.NodeID != id {
			continue
		}
		if err := s.enroll.Revoke(ctx, sr); err != nil {
			failed = fmt.Errorf("revoking %s's certificate %s: %w", p.NodeID, sr, err)
			continue
		}
		s.log.Info("node certificate revoked", "node", p.NodeID, "serial", sr)
		done = append(done, sr)
	}
	if len(done) > 0 {
		if err := s.mutate(ctx, func(st *nodeadmState) error {
			for _, sr := range done {
				delete(st.PendingRevokes, sr)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return failed
}

// queueRevoke records a serial still to revoke (PendingRevokes).
func (s *Server) queueRevoke(ctx context.Context, id, serial string) error {
	return s.mutate(ctx, func(st *nodeadmState) error {
		st.queueRevoke(id, serial, s.now())
		return nil
	})
}

func (st *nodeadmState) queueRevoke(id, serial string, now time.Time) {
	if serial == "" {
		return
	}
	if _, ok := st.PendingRevokes[serial]; !ok {
		st.PendingRevokes[serial] = &pendingRevoke{NodeID: id, QueuedAt: now}
	}
}

// removeCooperative: a code or an enrolling node is voided; a node is
// drained (minimums apply), Longhorn's replicas evicted, its etcd member
// removed (a server), the node deleted and its certificate revoked.
func (s *Server) removeCooperative(ctx context.Context, id string) error {
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	n, err := s.getNode(ctx, id)
	var ae *apiError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		if st.Nodes[id] == nil && st.Codes[id] == nil {
			return err
		}
		s.log.Info("enrolment voided", "node", id)
		return s.forget(ctx, id, nil)
	}
	if err != nil {
		return err
	}
	if err := s.quorumMinimum(ctx, n); err != nil {
		return err
	}
	if err := s.drain(ctx, id); err != nil {
		return err
	}
	if err := s.evictLonghorn(ctx, id); err != nil {
		return err
	}
	// The node marked removed (cert revoked) first, then its Node gone, then
	// the document says so, then (a server) its etcd member removed.
	cn := toClusterNode(n)
	if err := s.forget(ctx, id, &cn.Addresses); err != nil {
		return err
	}
	if err := s.kube.CoreV1().Nodes().Delete(ctx, id, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting node %s: %w", id, err)
	}
	if isServer(n) {
		if err := s.publishAddresses(ctx); err != nil {
			return err
		}
		if err := s.removeEtcdMember(ctx, cn); err != nil {
			return err
		}
	}
	s.log.Info("node removed", "node", id, "mode", "cooperative")
	return nil
}

// etcdQuorum: the server nodes and the Ready ones among them.
func etcdQuorum(cl []clusterNode) (voters, healthy int) {
	for _, c := range cl {
		if c.Role == "server" {
			voters++
			if c.Ready {
				healthy++
			}
		}
	}
	return voters, healthy
}

// removeEtcdMember has a Ready surviving server's nodeagent remove the
// member of n (POST /v1/etcd/remove-member; the nodeagent checks that
// portcullis-cluster-addresses lists n removed, and holds the etcd key).
func (s *Server) removeEtcdMember(ctx context.Context, n clusterNode) error {
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	for _, c := range cl {
		if c.Role == "server" && c.Ready && c.Name != n.Name && c.Mesh != "" {
			if err := s.agents.EtcdRemoveMember(ctx, c.Name, c.Mesh, n.Name, n.Mesh); err != nil {
				return fmt.Errorf("removing %s's etcd member through %s: %w", n.Name, c.Name, err)
			}
			s.log.Info("etcd member removed", "node", n.Name, "through", c.Name)
			return nil
		}
	}
	return errors.New("no Ready server to remove the etcd member through")
}
