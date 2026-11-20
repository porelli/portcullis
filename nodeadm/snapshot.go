package main

// GET /v1/cluster (contract §20.2 "The snapshot"): nodes, enrolling nodes,
// pods (the N−1 input), quorum, Postgres, volumes and the faults nodeadm
// knows. Quorum needs no new credential: etcd from the etcd client nodeadm
// holds, Vault and Sentinel from the readiness of their pods.

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	vaultSet    = "vault"
	sentinelSet = "sessions-sentinel"
	pgCluster   = "portcullis-pg"
)

// GET /v1/cluster
func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) error {
	snap, err := s.snapshot(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, snap)
	return nil
}

func podReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func keepLabel(k string) bool {
	return k == "kubernetes.io/hostname" || k == labelZone || strings.HasPrefix(k, "portcullis.io/") || k == labelDisk || k == labelEnableLB
}

// snapshot builds the §20.2 snapshot.
func (s *Server) snapshot(ctx context.Context) (*Snapshot, error) {
	now := s.now()
	snap := &Snapshot{V: 1, TakenAt: rfc3339(now), Nodes: []SnapNode{}, Enrolling: []SnapEnrolling{}, Pods: []SnapPod{},
		Volumes: []Volume{}, Errors: []string{}}
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return nil, err
	}
	pods, err := s.kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing the pods: %w", err)
	}
	st, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	// etcd's voters are the server nodes, its healthy ones the Ready
	// servers (nodeadm holds no etcd client, ruling I6).
	snap.Quorum.Etcd.Voters, snap.Quorum.Etcd.Healthy = etcdQuorum(cl)
	traefik, fencing := map[string]bool{}, map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if !podReady(p) {
			continue
		}
		switch {
		case p.Namespace == s.cfg.IngressNS && p.Labels["app.kubernetes.io/name"] == "traefik":
			traefik[p.Spec.NodeName] = true
		case p.Namespace == s.cfg.FencingNS && isDaemonSetPod(p) && strings.HasPrefix(p.Name, "self-node-remediation"):
			fencing[p.Spec.NodeName] = true
		}
	}
	names := map[string]bool{}
	for _, c := range cl {
		names[c.Name] = true
		n := c.Node
		sn := SnapNode{Name: c.Name, Role: c.Role, Ready: c.Ready, Unschedulable: n.Spec.Unschedulable,
			Allocatable: Resources{CPUm: n.Status.Allocatable.Cpu().MilliValue(), MemBytes: n.Status.Allocatable.Memory().Value()},
			Labels:      map[string]string{}, Taints: []Taint{}, Addresses: c.Addresses,
			TraefikReady: traefik[c.Name], FencingReady: fencing[c.Name], EtcdMember: c.Role == "server"}
		if !c.Ready {
			for _, cond := range n.Status.Conditions {
				if cond.Type == corev1.NodeReady && !cond.LastTransitionTime.IsZero() {
					t := rfc3339(cond.LastTransitionTime.Time)
					sn.NotReadySince = &t
				}
			}
		}
		for k, v := range n.Labels {
			if keepLabel(k) {
				sn.Labels[k] = v
			}
		}
		for _, t := range n.Spec.Taints {
			sn.Taints = append(sn.Taints, Taint{Key: t.Key, Value: t.Value, Effect: string(t.Effect)})
		}
		if c.Mesh == "" {
			snap.Errors = append(snap.Errors, fmt.Sprintf("node %s has no mesh address: the admission params aren't rewritten", c.Name))
		}
		if rec := st.Nodes[c.Name]; rec != nil && rec.Removed && st.Ops[c.Name] == nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("node %s was removed but registered again (its kubelet still runs): revoke it again and reinstall that machine", c.Name))
		}
		snap.Nodes = append(snap.Nodes, sn)
		s.metrics.nodeReady.WithLabelValues(c.Name).Set(b2f(c.Ready))
		s.metrics.fencing.WithLabelValues(c.Name).Set(b2f(fencing[c.Name]))
	}
	ids := make([]string, 0, len(st.Nodes))
	for id := range st.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rec := st.Nodes[id]
		if rec.JoinState == joinWaitAdmission && rec.WaitingSince != nil && now.Sub(*rec.WaitingSince) > 5*time.Minute {
			snap.Errors = append(snap.Errors, fmt.Sprintf("node %s has waited for the admission params for more than 5 min (is portcullis-kube-params.timer running on the install host?)", id))
		}
		if names[id] || rec.Removed {
			continue
		}
		snap.Enrolling = append(snap.Enrolling, SnapEnrolling{ID: id, Role: rec.Role, Class: rec.Class, Site: rec.Site,
			MeshIP: rec.MeshIP, Mesh: rec.Mesh, EnrolledAt: rfc3339(rec.EnrolledAt)})
	}
	mins := s.setMinimums(ctx, pods.Items)
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		snap.Pods = append(snap.Pods, snapPod(p, mins))
		switch {
		case p.Namespace == s.cfg.CoreNS && strings.HasPrefix(p.Name, sentinelSet+"-"):
			snap.Quorum.Sentinel.Voters++
			if podReady(p) {
				snap.Quorum.Sentinel.Healthy++
			}
		case p.Namespace == s.cfg.CoreNS && ownedBy(p, "StatefulSet", vaultSet):
			snap.Quorum.Vault.Voters++
			if podReady(p) {
				snap.Quorum.Vault.Healthy++
			}
		}
	}
	sort.Slice(snap.Pods, func(i, j int) bool {
		if snap.Pods[i].Namespace != snap.Pods[j].Namespace {
			return snap.Pods[i].Namespace < snap.Pods[j].Namespace
		}
		return snap.Pods[i].Name < snap.Pods[j].Name
	})
	snap.Postgres = s.postgres(ctx, pods.Items)
	snap.Volumes = s.volumes(ctx)
	snap.Errors = append(snap.Errors, s.addrErrors()...)
	for id, op := range st.Ops {
		if op.LastError != "" {
			snap.Errors = append(snap.Errors, fmt.Sprintf("the revocation of %s waits at %s: %s", id, op.Step, op.LastError))
		}
	}
	s.metrics.observe(snap)
	return snap, nil
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func ownedBy(p *corev1.Pod, kind, name string) bool {
	for _, o := range p.OwnerReferences {
		if o.Kind == kind && o.Name == name {
			return true
		}
	}
	return false
}

// setMinimums: per set name, the members it needs: the quorum of Vault
// and the Sentinels (2 of 3), else its PDB's minAvailable, else 1.
func (s *Server) setMinimums(ctx context.Context, pods []corev1.Pod) map[string]int {
	mins := map[string]int{vaultSet: 2, sentinelSet: 2}
	pdbs, err := s.kube.PolicyV1().PodDisruptionBudgets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return mins
	}
	for _, pdb := range pdbs.Items {
		if pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntValue() <= 0 {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}
		for i := range pods {
			p := &pods[i]
			if p.Namespace == pdb.Namespace && sel.Matches(labels.Set(p.Labels)) {
				name := podSetName(p)
				if name != vaultSet && name != sentinelSet {
					mins[name] = max(mins[name], pdb.Spec.MinAvailable.IntValue())
				}
			}
		}
	}
	return mins
}

func snapPod(p *corev1.Pod, mins map[string]int) SnapPod {
	sp := SnapPod{Name: p.Name, Namespace: p.Namespace, Node: p.Spec.NodeName, PriorityClass: p.Spec.PriorityClassName,
		PreemptionPolicy: "PreemptLowerPriority", Tolerations: []Toleration{}, RequiredAffinity: [][]Expr{}, DaemonSet: isDaemonSetPod(p)}
	if p.Spec.Priority != nil {
		sp.Priority = int(*p.Spec.Priority)
	}
	if p.Spec.PreemptionPolicy != nil {
		sp.PreemptionPolicy = string(*p.Spec.PreemptionPolicy)
	}
	for _, c := range p.Spec.Containers {
		sp.Requests.CPUm += c.Resources.Requests.Cpu().MilliValue()
		sp.Requests.MemBytes += c.Resources.Requests.Memory().Value()
	}
	for _, t := range p.Spec.Tolerations {
		sp.Tolerations = append(sp.Tolerations, Toleration{Key: t.Key, Operator: string(t.Operator), Value: t.Value,
			Effect: string(t.Effect), Seconds: t.TolerationSeconds})
	}
	// The required node affinity, each term ANDed with the nodeSelector.
	var sel []Expr
	keys := make([]string, 0, len(p.Spec.NodeSelector))
	for k := range p.Spec.NodeSelector {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sel = append(sel, Expr{Key: k, Operator: "In", Values: []string{p.Spec.NodeSelector[k]}})
	}
	var terms []corev1.NodeSelectorTerm
	if a := p.Spec.Affinity; a != nil && a.NodeAffinity != nil && a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
		terms = a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	}
	for _, t := range terms {
		term := append([]Expr{}, sel...)
		for _, e := range t.MatchExpressions {
			vals := e.Values
			if vals == nil {
				vals = []string{}
			}
			term = append(term, Expr{Key: e.Key, Operator: string(e.Operator), Values: vals})
		}
		sp.RequiredAffinity = append(sp.RequiredAffinity, term)
	}
	if len(terms) == 0 && len(sel) > 0 {
		sp.RequiredAffinity = append(sp.RequiredAffinity, sel)
	}
	if a := p.Spec.Affinity; a != nil && a.PodAntiAffinity != nil {
		for _, t := range a.PodAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution {
			if t.TopologyKey == "kubernetes.io/hostname" {
				sp.AntiAffinityHost = true
			}
		}
	}
	for _, c := range p.Spec.TopologySpreadConstraints {
		if c.TopologyKey == "kubernetes.io/hostname" && c.WhenUnsatisfiable == corev1.DoNotSchedule {
			sp.SpreadHost = true
		}
	}
	if !sp.DaemonSet {
		name := podSetName(p)
		if name != p.Name {
			m := mins[name]
			if m == 0 {
				m = 1
			}
			sp.Set = &PodSet{Name: name, Min: m}
		}
	}
	return sp
}

// postgres reads the CNPG Cluster portcullis-pg (absent: no instance).
func (s *Server) postgres(ctx context.Context, pods []corev1.Pod) Postgres {
	pg := Postgres{}
	if s.dyn == nil {
		return pg
	}
	u, err := s.dyn.Resource(gvrCNPGCluster).Namespace(s.cfg.CoreNS).Get(ctx, pgCluster, metav1.GetOptions{})
	if err != nil {
		return pg
	}
	inst, _, _ := unstructured.NestedInt64(u.Object, "status", "instances")
	ready, _, _ := unstructured.NestedInt64(u.Object, "status", "readyInstances")
	syncN, _, _ := unstructured.NestedInt64(u.Object, "spec", "postgresql", "synchronous", "number")
	prim, _, _ := unstructured.NestedString(u.Object, "status", "currentPrimary")
	pg.Instances = int(inst)
	pg.SyncStandbys = int(min(max(ready-1, 0), syncN))
	for i := range pods {
		if pods[i].Name == prim && pods[i].Namespace == s.cfg.CoreNS && pods[i].Spec.NodeName != "" {
			node := pods[i].Spec.NodeName
			pg.Primary = &node
		}
	}
	s.snapMu.Lock()
	if prim != "" && s.lastPrim != "" && prim != s.lastPrim {
		s.metrics.failovers.WithLabelValues("postgres").Inc()
	}
	if prim != "" {
		s.lastPrim = prim
	}
	s.snapMu.Unlock()
	return pg
}

// volumes reads Longhorn's volumes (robustness; degraded_since tracked
// from the first snapshot that saw it not healthy).
func (s *Server) volumes(ctx context.Context) []Volume {
	out := []Volume{}
	if s.dyn == nil {
		return out
	}
	l, err := s.dyn.Resource(gvrLonghornVolume).Namespace(s.cfg.LonghornNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return out
	}
	now := s.now()
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	seen := map[string]bool{}
	for _, it := range l.Items {
		name := it.GetName()
		if pv, _, _ := unstructured.NestedString(it.Object, "status", "kubernetesStatus", "pvcName"); pv != "" {
			name = pv
		}
		rb, _, _ := unstructured.NestedString(it.Object, "status", "robustness")
		switch rb {
		case "healthy", "degraded", "faulted":
		default:
			rb = "unknown"
		}
		v := Volume{Name: name, Robustness: rb}
		seen[name] = true
		if rb != "healthy" {
			if _, ok := s.degraded[name]; !ok {
				s.degraded[name] = now
			}
			t := rfc3339(s.degraded[name])
			v.DegradedSince = &t
		} else {
			delete(s.degraded, name)
		}
		out = append(out, v)
	}
	for k := range s.degraded {
		if !seen[k] {
			delete(s.degraded, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
