package main

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSnapshotKeepsLabelsPodsSelectOn: the snapshot's node labels hold every
// key a snapshot pod's nodeSelector or required node affinity names, next to
// keepLabel's. The Hub's N−1 check matches each pod's required affinity
// against these labels: k3s' own addons (kubernetes.io/os) and nodeadm
// itself (node-role.kubernetes.io/control-plane) select on labels keepLabel
// drops, which left them no node and every node red (found live on the HA
// VMs, 2026-11-23). A key only a finished pod names, or none, stays dropped.
func TestSnapshotKeepsLabelsPodsSelectOn(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n, err := h.kube.CoreV1().Nodes().Get(ctx, "n1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n.Labels["kubernetes.io/os"] = "linux"
	n.Labels["node-role.kubernetes.io/control-plane"] = "true"
	n.Labels["example.com/unrelated"] = "x"
	n.Labels["example.com/done"] = "y"
	if _, err := h.kube.CoreV1().Nodes().Update(ctx, n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	running := corev1.PodStatus{Phase: corev1.PodRunning}
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "addon", Namespace: "kube-system"},
			Spec: corev1.PodSpec{NodeName: "n1", NodeSelector: map[string]string{"kubernetes.io/os": "linux"}}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "nodeadm-x", Namespace: "portcullis-nodeadm"},
			Spec: corev1.PodSpec{NodeName: "n1", Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "node-role.kubernetes.io/control-plane", Operator: corev1.NodeSelectorOpIn, Values: []string{"true"}}}}}}}}},
			Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "job-done", Namespace: coreNS},
			Spec: corev1.PodSpec{NodeName: "n1", NodeSelector: map[string]string{"example.com/done": "y"}}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}},
	} {
		if _, err := h.kube.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := h.s.snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var labels map[string]string
	for _, sn := range snap.Nodes {
		if sn.Name == "n1" {
			labels = sn.Labels
		}
	}
	if labels == nil {
		t.Fatal("no node n1 in the snapshot")
	}
	for k, want := range map[string]string{"kubernetes.io/os": "linux", "node-role.kubernetes.io/control-plane": "true"} {
		if labels[k] != want {
			t.Errorf("label %s = %q, want %q (a pod selects on it)", k, labels[k], want)
		}
	}
	for _, k := range []string{"example.com/unrelated", "example.com/done"} {
		if _, ok := labels[k]; ok {
			t.Errorf("label %s kept: no running pod selects on it", k)
		}
	}
	if labels["kubernetes.io/hostname"] == "" {
		t.Errorf("keepLabel's kubernetes.io/hostname dropped: %v", labels)
	}
}

// TestSnapshotReservedMeshIPs (Task 33 part B, VM run 6): a cooperatively
// removed node's record keeps its mesh address until the admission params
// let it go (dropRemoved), and code issue refuses that address meanwhile
// ("mesh ip … is used by …"), so the snapshot names it: the Hub's
// allocator skips it instead of offering it to the next node (seen: node
// add right after node remove got the removed node's address and a 409).
// Its LAN-reported address wins over the record's when set, as in
// dropRemoved; a live or enrolling node's address isn't listed here.
func TestSnapshotReservedMeshIPs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["gone"] = &nodeRecord{Role: "agent", Removed: true, MeshIP: "10.215.0.4"}
		st.Nodes["gone2"] = &nodeRecord{Role: "agent", Removed: true, MeshIP: "10.215.0.7", Addrs: &NodeAddresses{Mesh: "10.215.0.8"}}
		st.Nodes["new"] = &nodeRecord{Role: "agent", MeshIP: "10.215.0.9"}
	})
	snap, err := h.s.takeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.215.0.4", "10.215.0.8"}; !reflect.DeepEqual(snap.ReservedMeshIPs, want) {
		t.Fatalf("reserved_mesh_ips %v, want %v", snap.ReservedMeshIPs, want)
	}
	for _, e := range snap.Enrolling {
		if e.ID == "gone" || e.ID == "gone2" {
			t.Fatalf("a removed record listed as enrolling: %+v", e)
		}
	}
	h.putState(t, func(st *nodeadmState) { delete(st.Nodes, "gone"); delete(st.Nodes, "gone2") })
	snap, err = h.s.takeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ReservedMeshIPs == nil || len(snap.ReservedMeshIPs) != 0 {
		t.Fatalf("reserved_mesh_ips %#v after the drop, want []", snap.ReservedMeshIPs)
	}
}
