package main

import (
	"context"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
)

var remNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func rn(name, site, class string, ready bool, agoS int, stateful bool) remediationNode {
	return remediationNode{Name: name, Site: site, Class: class, Ready: ready, Since: remNow.Add(-time.Duration(agoS) * time.Second), Stateful: stateful}
}

func TestPlanRemediationGuard(t *testing.T) {
	main3 := func(n2 remediationNode) []remediationNode {
		return []remediationNode{rn("m1", "main", "cloud", true, 3600, true), n2, rn("m3", "main", "cloud", true, 3600, false)}
	}
	cases := []struct {
		name  string
		nodes []remediationNode
		crs   []remediationCR
		want  remediationPlan
	}{
		{"healthy: nothing", main3(rn("m2", "main", "home", true, 3600, true)), nil, remediationPlan{}},
		{"NotReady 20 s: not yet", main3(rn("m2", "main", "home", false, 20, true)), nil, remediationPlan{}},
		{"NotReady 31 s: remediate m2", main3(rn("m2", "main", "home", false, 31, true)), nil, remediationPlan{Create: "m2"}},
		{"a main node holding no stateful pod is still remediated", main3(rn("m2", "main", "home", false, 31, false)), nil, remediationPlan{Create: "m2"}},
		{"one in progress: no second", append(main3(rn("m2", "main", "home", false, 300, true)), rn("e1", "edge", "cloud", false, 300, true)),
			[]remediationCR{{Name: "m2", Created: remNow.Add(-time.Minute)}}, remediationPlan{Hold: "a remediation is in progress (m2)"}},
		{"more than half of main unhealthy: storm, nothing", []remediationNode{rn("m1", "main", "cloud", false, 300, true), rn("m2", "main", "home", false, 300, true), rn("m3", "main", "cloud", true, 3600, true)},
			nil, remediationPlan{Hold: "more than half of the primary site's nodes are unhealthy: no remediation (a partition or an outage, never fenced from here)"}},
		{"exactly half of main (1 of 2) unhealthy: remediated", []remediationNode{rn("m1", "main", "cloud", false, 60, true), rn("m2", "main", "home", true, 3600, true)}, nil, remediationPlan{Create: "m1"}},
		{"edge stateless: held", append(main3(rn("m2", "main", "home", true, 3600, true)), rn("e1", "edge", "cloud", false, 300, false)), nil,
			remediationPlan{Hold: "the unhealthy nodes are edge or small nodes holding no stateful pod"}},
		{"small stateless at main: held", append(main3(rn("m2", "main", "home", true, 3600, true)), rn("s1", "main", "small", false, 300, false)), nil,
			remediationPlan{Hold: "the unhealthy nodes are edge or small nodes holding no stateful pod"}},
		{"edge with a stateful pod: remediated", append(main3(rn("m2", "main", "home", true, 3600, true)), rn("e1", "edge", "cloud", false, 300, true)), nil, remediationPlan{Create: "e1"}},
		{"Ready again and Succeeded: CR removed", main3(rn("m2", "main", "home", true, 60, true)), []remediationCR{{Name: "m2", Created: remNow.Add(-5 * time.Minute), Succeeded: true}},
			remediationPlan{Delete: []string{"m2"}}},
		{"Ready again, not Succeeded yet: kept (in progress)", main3(rn("m2", "main", "home", true, 60, true)), []remediationCR{{Name: "m2", Created: remNow.Add(-5 * time.Minute)}}, remediationPlan{}},
		{"Ready 15 min, never Succeeded: removed", main3(rn("m2", "main", "home", true, 900, true)), []remediationCR{{Name: "m2", Created: remNow.Add(-20 * time.Minute)}},
			remediationPlan{Delete: []string{"m2"}}},
		{"no main node at all: nothing remediated", []remediationNode{rn("e1", "edge", "cloud", false, 300, true)}, nil,
			remediationPlan{Hold: "more than half of the primary site's nodes are unhealthy: no remediation (a partition or an outage, never fenced from here)"}},
	}
	for _, c := range cases {
		got := planRemediation(c.nodes, c.crs, primarySite, remNow)
		if got.Create != c.want.Create || got.Hold != c.want.Hold || strings.Join(got.Delete, ",") != strings.Join(c.want.Delete, ",") {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestRemediateCreatesTheCR: a dead main node with a stateful pod → one
// SelfNodeRemediation in the fencing namespace, named after the node,
// OutOfServiceTaint, logged; a standing-by nodeadm writes nothing; a second
// round while it runs creates nothing more.
func TestRemediateCreatesTheCR(t *testing.T) {
	h := newHarness(t)
	n2, _ := h.kube.CoreV1().Nodes().Get(context.Background(), "n2", metav1.GetOptions{})
	n2.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: metav1.NewTime(vecNow.Add(-time.Minute))}}
	if _, err := h.kube.CoreV1().Nodes().UpdateStatus(context.Background(), n2, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.kube.CoreV1().Pods("portcullis").Create(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "hub-0", Namespace: "portcullis"},
		Spec: corev1.PodSpec{NodeName: "n2", Volumes: []corev1.Volume{{Name: "d", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "hub-state-r"}}}}}},
		metav1.CreateOptions{})
	d := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvrSNR: "SelfNodeRemediationList"})
	h.s.dyn = d
	h.leader.on.Store(false)
	h.s.remediate(context.Background())
	if l, _ := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(context.Background(), metav1.ListOptions{}); len(l.Items) != 0 {
		t.Fatal("a standing-by nodeadm created a remediation")
	}
	h.leader.on.Store(true)
	h.s.remediate(context.Background())
	l, err := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("remediations: %v %v", l, err)
	}
	cr := l.Items[0]
	if s, _, _ := unstructured.NestedString(cr.Object, "spec", "remediationStrategy"); cr.GetName() != "n2" || s != "OutOfServiceTaint" || cr.GetLabels()["app.kubernetes.io/managed-by"] != snrManagedBy {
		t.Fatalf("the remediation: %v", cr.Object)
	}
	if !strings.Contains(h.logs.String(), `remediation started`) || !strings.Contains(h.logs.String(), "node=n2") {
		t.Fatalf("not logged: %s", h.logs.String())
	}
	h.s.remediate(context.Background())
	if l, _ := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(context.Background(), metav1.ListOptions{}); len(l.Items) != 1 {
		t.Fatal("a second remediation")
	}
	if !strings.Contains(h.logs.String(), "a remediation is in progress (n2)") {
		t.Fatalf("hold not logged: %s", h.logs.String())
	}
}
