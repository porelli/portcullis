package main

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSnapshotVolumeAffinity (Task 33a fix round 1): a pod's required
// affinity in the snapshot carries its bound volumes' node affinity (a
// local volume: its node), ANDed with the pod's own terms; a replicated
// volume (no node affinity) adds nothing; a claim nodeadm can't resolve
// pins the pod to its node (fail closed).
func TestSnapshotVolumeAffinity(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := func(n string) corev1.NodeSelectorTerm {
		return corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{n}}}}
	}
	for _, pv := range []*corev1.PersistentVolume{
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-local"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: &corev1.VolumeNodeAffinity{
			Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{host("n1")}}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-fields"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: &corev1.VolumeNodeAffinity{
			Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{
				{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"n1"}}}}}}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-replicated"}},
	} {
		if _, err := h.kube.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for c, pv := range map[string]string{"data-vault-0": "pv-local", "data-fields": "pv-fields", "hub-state-r": "pv-replicated", "pending": ""} {
		if _, err := h.kube.CoreV1().PersistentVolumeClaims(coreNS).Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: c, Namespace: coreNS},
			Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pv}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	claim := func(names ...string) []corev1.Volume {
		var out []corev1.Volume
		for _, n := range names {
			out = append(out, corev1.Volume{Name: n, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: n}}})
		}
		return out
	}
	running := corev1.PodStatus{Phase: corev1.PodRunning}
	siteMain := &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{
		{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "portcullis.io/site", Operator: corev1.NodeSelectorOpIn, Values: []string{"main"}}}},
		{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "portcullis.io/site", Operator: corev1.NodeSelectorOpIn, Values: []string{"edge"}}}}}}}}
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "vault-0", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Affinity: siteMain, Volumes: claim("data-vault-0")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "fields", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Volumes: claim("data-fields")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "hub-x", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Volumes: claim("hub-state-r")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "lost", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Volumes: claim("pending", "gone")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "plain", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1",
			Volumes: []corev1.Volume{{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}}, Status: running},
	} {
		if _, err := h.kube.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := h.s.takeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][][]Expr{}
	for _, p := range snap.Pods {
		got[p.Name] = p.RequiredAffinity
	}
	on1 := Expr{Key: "kubernetes.io/hostname", Operator: "In", Values: []string{"n1"}}
	site := func(s string) Expr { return Expr{Key: "portcullis.io/site", Operator: "In", Values: []string{s}} }
	for name, want := range map[string][][]Expr{
		"vault-0": {{site("main"), on1}, {site("edge"), on1}},
		"fields":  {{on1}},
		"hub-x":   {},
		"lost":    {{on1, on1}},
		"plain":   {},
	} {
		if !reflect.DeepEqual(got[name], want) {
			t.Errorf("%s: required affinity %+v, want %+v", name, got[name], want)
		}
	}
}

// TestSnapshotVolumeAffinityEdges (Task 33a re-review N5): a matchFields
// nodeadm can't express pins the pod (fail closed); a generic ephemeral
// volume's claim (<pod>-<volume>) is resolved like any other; a PV with
// two terms gives the pod two alternatives; an empty PV term (which the
// scheduler matches against no node) pins the pod instead of matching
// every node.
func TestSnapshotVolumeAffinityEdges(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	host := func(n string) corev1.NodeSelectorTerm {
		return corev1.NodeSelectorTerm{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/hostname", Operator: corev1.NodeSelectorOpIn, Values: []string{n}}}}
	}
	sel := func(terms ...corev1.NodeSelectorTerm) *corev1.VolumeNodeAffinity {
		return &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: terms}}
	}
	for _, pv := range []*corev1.PersistentVolume{
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-uid"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: sel(corev1.NodeSelectorTerm{
			MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.uid", Operator: corev1.NodeSelectorOpIn, Values: []string{"x"}}}})}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-notin"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: sel(corev1.NodeSelectorTerm{
			MatchFields: []corev1.NodeSelectorRequirement{{Key: "metadata.name", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"n2"}}}})}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-eph"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: sel(host("n3"))}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-two"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: sel(host("n2"), host("n3"))}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-empty"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: sel(corev1.NodeSelectorTerm{})}},
		{ObjectMeta: metav1.ObjectMeta{Name: "pv-empty-alt"}, Spec: corev1.PersistentVolumeSpec{NodeAffinity: sel(corev1.NodeSelectorTerm{}, host("n2"))}},
	} {
		if _, err := h.kube.CoreV1().PersistentVolumes().Create(ctx, pv, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for c, pv := range map[string]string{"c-uid": "pv-uid", "c-notin": "pv-notin", "eph-data": "pv-eph", "c-two": "pv-two",
		"c-empty": "pv-empty", "c-empty-alt": "pv-empty-alt"} {
		if _, err := h.kube.CoreV1().PersistentVolumeClaims(coreNS).Create(ctx, &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: c, Namespace: coreNS},
			Spec: corev1.PersistentVolumeClaimSpec{VolumeName: pv}}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	claim := func(n string) []corev1.Volume {
		return []corev1.Volume{{Name: n, VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: n}}}}
	}
	running := corev1.PodStatus{Phase: corev1.PodRunning}
	for _, p := range []*corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "uid", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Volumes: claim("c-uid")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "notin", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Volumes: claim("c-notin")}, Status: running},
		// A generic ephemeral volume "data" of pod "eph": its claim is eph-data.
		{ObjectMeta: metav1.ObjectMeta{Name: "eph", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n3", Volumes: []corev1.Volume{{Name: "data",
			VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}}}}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "two", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n2", Volumes: claim("c-two")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n1", Volumes: claim("c-empty")}, Status: running},
		{ObjectMeta: metav1.ObjectMeta{Name: "empty-alt", Namespace: coreNS}, Spec: corev1.PodSpec{NodeName: "n2", Volumes: claim("c-empty-alt")}, Status: running},
	} {
		if _, err := h.kube.CoreV1().Pods(p.Namespace).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := h.s.takeSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][][]Expr{}
	for _, p := range snap.Pods {
		got[p.Name] = p.RequiredAffinity
	}
	on := func(n string) Expr { return Expr{Key: "kubernetes.io/hostname", Operator: "In", Values: []string{n}} }
	for name, want := range map[string][][]Expr{
		"uid":   {{on("n1")}},             // unsupported field: pinned
		"notin": {{on("n1")}},             // metadata.name NotIn: pinned
		"eph":   {{on("n3")}},             // the ephemeral claim resolved
		"two":   {{on("n2")}, {on("n3")}}, // either of the PV's terms
		"empty": {{on("n1")}},             // an empty term matches no node: pinned, never "anywhere"
		// The empty alternative is dropped (it matches nothing); the other stays.
		"empty-alt": {{on("n2")}},
	} {
		if !reflect.DeepEqual(got[name], want) {
			t.Errorf("%s: required affinity %+v, want %+v", name, got[name], want)
		}
	}
}
