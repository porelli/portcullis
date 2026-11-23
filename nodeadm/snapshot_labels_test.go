package main

import (
	"context"
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
