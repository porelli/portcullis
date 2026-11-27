package main

// GET /v1/cluster (contract §20.2 "The snapshot"): nodes, enrolling nodes,
// pods (the N−1 input), quorum, Postgres, volumes and the faults nodeadm
// knows. Quorum needs no new credential: etcd from the server nodes,
// Vault and Sentinel from the readiness of their pods against the
// configured voters (Config.VaultVoters / SentinelVoters).

import (
	"context"
	"fmt"
	"net/http"
	"slices"
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
	// pgNS: the CNPG Cluster and its instances live with the operator
	// (core plan Task 23: the operator's rights end at its namespace).
	pgNS = "cnpg-system"
)

// GET /v1/cluster: a snapshot for the caller only. It never touches the
// metrics (fix round 3: a cancelled or timed-out request must not drop
// the gauges and reset the alerts' holds); the metrics loop alone
// (snapshot) observes.
func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) error {
	snap, err := s.takeSnapshot(r.Context())
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

// selectedLabelKeys: the node label keys a snapshot pod's nodeSelector or
// required node affinity names. The Hub's N−1 check matches each pod's
// required affinity (snapPod) against the snapshot's node labels, so a key
// the snapshot dropped would leave that pod no node at all: k3s' own addons
// select on kubernetes.io/os and nodeadm on
// node-role.kubernetes.io/control-plane, and every node was red (found live
// on the HA VMs). Pods the snapshot leaves out (unscheduled, finished)
// count for nothing.
func selectedLabelKeys(pods []corev1.Pod) map[string]bool {
	keys := map[string]bool{}
	for i := range pods {
		p := &pods[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for k := range p.Spec.NodeSelector {
			keys[k] = true
		}
		if a := p.Spec.Affinity; a != nil && a.NodeAffinity != nil && a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution != nil {
			for _, t := range a.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms {
				for _, e := range t.MatchExpressions {
					keys[e.Key] = true
				}
			}
		}
	}
	return keys
}

// snapshot is the metrics loop's snapshot (main.go, every 30 s): a success
// sets the gauges, a failure drops them (absent, never stale-healthy:
// Metrics.failed). Nothing else calls it.
func (s *Server) snapshot(ctx context.Context) (*Snapshot, error) {
	snap, err := s.takeSnapshot(ctx)
	if err != nil {
		s.metrics.failed()
		return nil, err
	}
	s.metrics.observe(snap)
	return snap, nil
}

func (s *Server) takeSnapshot(ctx context.Context) (*Snapshot, error) {
	now := s.now()
	snap := &Snapshot{V: 1, TakenAt: rfc3339(now), Nodes: []SnapNode{}, Enrolling: []SnapEnrolling{}, ReservedMeshIPs: []string{}, Pods: []SnapPod{},
		Volumes: []Volume{}, Errors: []string{}, pressure: map[string]map[string]bool{}}
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
	ca, err := s.claimAffinities(ctx)
	if err != nil {
		return nil, err
	}
	selected := selectedLabelKeys(pods.Items)
	volumeLabelKeys(pods.Items, ca, selected)
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
		pr := map[string]bool{}
		for _, cond := range n.Status.Conditions {
			for _, pc := range pressureConditions {
				if string(cond.Type) == pc && cond.Status == corev1.ConditionTrue {
					pr[pc] = true
				}
			}
		}
		snap.pressure[c.Name] = pr
		for k, v := range n.Labels {
			if keepLabel(k) || selected[k] {
				sn.Labels[k] = v
			}
		}
		for _, t := range n.Spec.Taints {
			sn.Taints = append(sn.Taints, Taint{Key: t.Key, Value: t.Value, Effect: string(t.Effect)})
		}
		if c.Mesh == "" {
			snap.Errors = append(snap.Errors, fmt.Sprintf("node %s has no mesh address: the admission params aren't rewritten", c.Name))
		}
		if rec := st.Nodes[c.Name]; rec.needsLabels() {
			snap.Errors = append(snap.Errors, fmt.Sprintf("node %s registered but isn't labelled yet: no pinned pod schedules there until nodeadm labels it", c.Name))
		}
		if rec := st.Nodes[c.Name]; rec != nil && rec.Removed && st.Ops[c.Name] == nil {
			snap.Errors = append(snap.Errors, fmt.Sprintf("node %s was removed but registered again (its kubelet still runs; token rotations skip it): revoke it again and reinstall that machine", c.Name))
		}
		snap.Nodes = append(snap.Nodes, sn)
	}
	snap.Errors = append(snap.Errors, s.remediationErrors()...)
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
		if rec.Removed {
			// Its mesh address stays taken until the record goes
			// (dropRemoved's address: the reported one when set).
			mesh := rec.MeshIP
			if rec.Addrs != nil && rec.Addrs.Mesh != "" {
				mesh = rec.Addrs.Mesh
			}
			if mesh != "" && !slices.Contains(snap.ReservedMeshIPs, mesh) {
				snap.ReservedMeshIPs = append(snap.ReservedMeshIPs, mesh)
			}
			continue
		}
		if names[id] {
			continue
		}
		snap.Enrolling = append(snap.Enrolling, SnapEnrolling{ID: id, Role: rec.Role, Class: rec.Class, Site: rec.Site,
			MeshIP: rec.MeshIP, Mesh: rec.Mesh, EnrolledAt: rfc3339(rec.EnrolledAt)})
	}
	sort.Strings(snap.ReservedMeshIPs)
	mins := s.setMinimums(ctx, pods.Items)
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == "" || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		sp := snapPod(p, mins)
		withVolumeAffinity(&sp, volumeTerms(p, ca))
		snap.Pods = append(snap.Pods, sp)
		if p.Namespace == s.cfg.CoreNS && (ownedBy(p, "StatefulSet", "sessions") || ownedBy(p, "StatefulSet", sentinelSet)) {
			if msg := sessionsError(p); msg != "" {
				snap.Errors = append(snap.Errors, fmt.Sprintf("pod %s: %s", p.Name, msg))
			}
		}
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
	// The totals are the configured voters (review I6): a voter that isn't
	// scheduled is still a voter the quorum needs.
	snap.Quorum.Vault = configuredVoters(s.cfg.VaultVoters, snap.Quorum.Vault.Healthy)
	snap.Quorum.Sentinel = configuredVoters(s.cfg.SentinelVoters, snap.Quorum.Sentinel.Healthy)
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
			if op.LastKind == "quorum_minimum" {
				snap.Errors = append(snap.Errors, fmt.Sprintf("the revocation of %s is parked before its Node and etcd member are removed: %s", id, op.LastError))
			} else {
				snap.Errors = append(snap.Errors, fmt.Sprintf("the revocation of %s waits at %s: %s", id, op.Step, op.LastError))
			}
		}
	}
	return snap, nil
}

// configuredVoters: total = the configured voters, healthy = the Ready ones
// (never more than configured).
func configuredVoters(configured, ready int) Voters {
	return Voters{Voters: configured, Healthy: min(ready, configured)}
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

// setKey: a set is (namespace, name): an apps PDB never sets a core
// set's minimum (Task 12 review M9). The snapshot's pod carries the
// namespace.
type setKey struct{ ns, name string }

// setMinimums: per set, the members it needs: the quorum of Vault and the
// Sentinels in the core namespace (2 of 3), else the minAvailable of a PDB
// of its namespace, else 1.
func (s *Server) setMinimums(ctx context.Context, pods []corev1.Pod) map[setKey]int {
	core := s.cfg.CoreNS
	mins := map[setKey]int{{core, vaultSet}: 2, {core, sentinelSet}: 2}
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
				k := setKey{p.Namespace, podSetName(p)}
				if k != (setKey{core, vaultSet}) && k != (setKey{core, sentinelSet}) {
					mins[k] = max(mins[k], pdb.Spec.MinAvailable.IntValue())
				}
			}
		}
	}
	return mins
}

func snapPod(p *corev1.Pod, mins map[setKey]int) SnapPod {
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
			m := mins[setKey{p.Namespace, name}]
			if m == 0 {
				m = 1
			}
			sp.Set = &PodSet{Name: name, Min: m}
		}
	}
	return sp
}

// postgres reads the CNPG Cluster portcullis-pg in cnpg-system (absent: no
// instance).
func (s *Server) postgres(ctx context.Context, pods []corev1.Pod) Postgres {
	pg := Postgres{}
	if s.dyn == nil {
		return pg
	}
	u, err := s.dyn.Resource(gvrCNPGCluster).Namespace(pgNS).Get(ctx, pgCluster, metav1.GetOptions{})
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
		if pods[i].Name == prim && pods[i].Namespace == pgNS && pods[i].Spec.NodeName != "" {
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

// sessionsError is the session store's named error on one of its pods (plan
// Task 25 review M-b): the termination message its init guard or a
// Sentinel's start writes, prefixed "portcullis-sessions:" (the Sentinels
// disagree on the master, none answers, the master fallback), for the HA
// page; "" when none.
func sessionsError(p *corev1.Pod) string {
	const prefix = "portcullis-sessions: "
	all := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
	for _, cs := range all {
		for _, t := range []*corev1.ContainerStateTerminated{cs.State.Terminated, cs.LastTerminationState.Terminated} {
			// Only a failed start: the guard's master fallback and
			// sentinel-init's fallback exit 0 after naming what they did,
			// and that pod is healthy (re-review 2 N-d).
			if t != nil && t.ExitCode != 0 && strings.HasPrefix(t.Message, prefix) {
				// C0, DEL and C1 (U+0080–U+009F, e.g. CSI) to spaces; cut
				// at 200 runes, never inside one (re-review 2 N-b).
				m := []rune(strings.Map(func(r rune) rune {
					if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
						return ' '
					}
					return r
				}, strings.TrimSpace(strings.TrimPrefix(t.Message, prefix))))
				if len(m) > 200 {
					m = m[:200]
				}
				return "the session store: " + string(m)
			}
		}
	}
	return ""
}
