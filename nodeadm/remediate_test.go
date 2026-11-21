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

func rn(name, site, class string, ready bool, agoS int, replicated bool) remediationNode {
	return remediationNode{Name: name, Site: site, Class: class, Ready: ready, Since: remNow.Add(-time.Duration(agoS) * time.Second), Replicated: replicated}
}

func with(n remediationNode, f func(*remediationNode)) remediationNode { f(&n); return n }

func TestPlanRemediationGuard(t *testing.T) {
	main3 := func(n2 remediationNode) []remediationNode {
		return []remediationNode{rn("m1", "main", "cloud", true, 3600, true), n2, rn("m3", "main", "cloud", true, 3600, false)}
	}
	ago := func(m int) time.Time { return remNow.Add(-time.Duration(m) * time.Minute) }
	cases := []struct {
		name  string
		nodes []remediationNode
		crs   []remediationCR
		want  remediationPlan
	}{
		{"healthy: nothing", main3(rn("m2", "main", "home", true, 3600, true)), nil, remediationPlan{}},
		{"NotReady 20 s: not yet", main3(rn("m2", "main", "home", false, 20, true)), nil, remediationPlan{}},
		{"NotReady 31 s: remediate m2", main3(rn("m2", "main", "home", false, 31, true)), nil, remediationPlan{Create: "m2"}},
		{"a main node without a replicated volume is still remediated", main3(rn("m2", "main", "home", false, 31, false)), nil, remediationPlan{Create: "m2"}},
		{"one in progress: no second", main3(rn("m2", "main", "home", false, 300, true)),
			[]remediationCR{{Name: "m2", Created: ago(1)}}, remediationPlan{}},
		{"in progress and another due: held", []remediationNode{rn("m1", "main", "cloud", false, 300, true), rn("m2", "main", "home", true, 3600, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", false, 300, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(1)}}, remediationPlan{Hold: "a remediation is in progress (m1)"}},
		// Review I3: fenced for good, then a second node dies → remediated.
		{"fenced and still down (Succeeded), then a second node dies → the second remediated, the first kept",
			[]remediationNode{rn("m1", "main", "cloud", false, 1800, true), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(29), Succeeded: true}}, remediationPlan{Create: "m2"}},
		// Review I3 + M2: an edge site's WAN drops — never fenced, main still remediated.
		{"edge WAN down: the edge node never remediated, and a main node dying meanwhile is",
			[]remediationNode{rn("e1", "edge", "cloud", false, 600, true), rn("m1", "main", "cloud", false, 60, true), rn("m2", "main", "home", true, 3600, true), rn("m3", "main", "cloud", true, 3600, true)},
			nil, remediationPlan{Create: "m1"}},
		{"edge node alone down: held, never remediated", append(main3(rn("m2", "main", "home", true, 3600, true)), rn("e1", "edge", "cloud", false, 300, true)), nil,
			remediationPlan{Hold: "nothing to remediate: e1: not at the primary site (nothing there to fail over)"}},
		{"more than half of main unhealthy: storm, nothing", []remediationNode{rn("m1", "main", "cloud", false, 300, true), rn("m2", "main", "home", false, 300, true), rn("m3", "main", "cloud", true, 3600, true)},
			nil, remediationPlan{Hold: "more than half of the primary site's nodes are unhealthy: no remediation (a partition or an outage, never fenced from here)"}},
		{"exactly half of main (1 of 2) unhealthy: remediated", []remediationNode{rn("m1", "main", "cloud", false, 60, true), rn("m2", "main", "home", true, 3600, true)}, nil, remediationPlan{Create: "m1"}},
		{"small at main without a replicated volume: held", append(main3(rn("m2", "main", "home", true, 3600, true)), rn("s1", "main", "small", false, 300, false)), nil,
			remediationPlan{Hold: "nothing to remediate: s1: a small node holding no replicated volume"}},
		{"small at main with a replicated volume: remediated", append(main3(rn("m2", "main", "home", true, 3600, true)), rn("s1", "main", "small", false, 300, true)), nil, remediationPlan{Create: "s1"}},
		// Review M4: planned maintenance.
		{"cordoned / excluded / being removed: held", main3(with(rn("m2", "main", "home", false, 300, true), func(n *remediationNode) { n.Excluded = true })), nil,
			remediationPlan{Hold: "nothing to remediate: m2: in maintenance (cordoned, excluded or being removed)"}},
		// Review M3: flapping.
		{"flapping: down again 10 min after its last remediation → back-off", main3(with(rn("m2", "main", "home", false, 60, true), func(n *remediationNode) { n.LastRemediated = ago(10) })), nil,
			remediationPlan{Hold: "nothing to remediate: m2: remediated less than 20m0s ago (back-off)"}},
		{"flapping: down again 25 min after → remediated", main3(with(rn("m2", "main", "home", false, 60, true), func(n *remediationNode) { n.LastRemediated = ago(25) })), nil, remediationPlan{Create: "m2"}},
		{"Ready again and Succeeded: CR removed", main3(rn("m2", "main", "home", true, 60, true)), []remediationCR{{Name: "m2", Created: ago(5), Succeeded: true}},
			remediationPlan{Delete: []string{"m2"}}},
		{"Ready again, not Succeeded yet: kept (in progress)", main3(rn("m2", "main", "home", true, 60, true)), []remediationCR{{Name: "m2", Created: ago(5)}}, remediationPlan{}},
		{"Ready 15 min, never Succeeded: removed", main3(rn("m2", "main", "home", true, 900, true)), []remediationCR{{Name: "m2", Created: ago(20)}},
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

// TestRemediateRounds: through the real rounds on fakes — a standing-by
// nodeadm writes nothing; the leader records the back-off on the Node and
// creates one SelfNodeRemediation (named after the node, OutOfServiceTaint,
// its label), logged; a second round while it runs creates nothing; once
// it Succeeded and the node is Ready it is removed; a node that goes down
// again within the back-off is held (flapping, review M3).
func TestRemediateRounds(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	setReady := func(st corev1.ConditionStatus, since time.Time) {
		n2, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
		n2.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: st, LastTransitionTime: metav1.NewTime(since)}}
		if _, err := h.kube.CoreV1().Nodes().UpdateStatus(ctx, n2, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	setReady(corev1.ConditionUnknown, vecNow.Add(-time.Minute))
	vol := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "longhorn.io/v1beta2", "kind": "Volume",
		"metadata": map[string]any{"name": "pvc-1", "namespace": "longhorn-system"}, "status": map[string]any{"currentNodeID": "n2"}}}
	d := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrSNR: "SelfNodeRemediationList", gvrLonghornVolume: "VolumeList"}, vol)
	h.s.dyn = d
	list := func() []unstructured.Unstructured {
		l, err := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(ctx, metav1.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return l.Items
	}
	h.leader.on.Store(false)
	h.s.remediate(ctx)
	if len(list()) != 0 {
		t.Fatal("a standing-by nodeadm created a remediation")
	}
	h.leader.on.Store(true)
	h.s.remediate(ctx)
	items := list()
	if len(items) != 1 {
		t.Fatalf("remediations: %d", len(items))
	}
	cr := items[0]
	if s, _, _ := unstructured.NestedString(cr.Object, "spec", "remediationStrategy"); cr.GetName() != "n2" || s != "OutOfServiceTaint" || cr.GetLabels()["app.kubernetes.io/managed-by"] != snrManagedBy {
		t.Fatalf("the remediation: %v", cr.Object)
	}
	n2, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
	if n2.Annotations[annRemediatedAt] != rfc3339(vecNow) {
		t.Fatalf("the back-off record: %v", n2.Annotations)
	}
	if !strings.Contains(h.logs.String(), "remediation started") || !strings.Contains(h.logs.String(), "node=n2") {
		t.Fatalf("not logged: %s", h.logs.String())
	}
	h.s.remediate(ctx)
	if len(list()) != 1 {
		t.Fatal("a second remediation")
	}
	// Succeeded, the node Ready again → removed.
	unstructured.SetNestedSlice(cr.Object, []any{map[string]any{"type": "Succeeded", "status": "True"}}, "status", "conditions")
	if _, err := d.Resource(gvrSNR).Namespace("portcullis-fencing").Update(ctx, &cr, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	setReady(corev1.ConditionTrue, vecNow)
	h.s.remediate(ctx)
	if len(list()) != 0 || !strings.Contains(h.logs.String(), "remediation finished") {
		t.Fatalf("not removed: %d %s", len(list()), h.logs.String())
	}
	// Down again 5 minutes later (flapping): held by the back-off.
	h.setNow(vecNow.Add(5 * time.Minute))
	setReady(corev1.ConditionFalse, vecNow.Add(4*time.Minute))
	h.s.remediate(ctx)
	if len(list()) != 0 || !strings.Contains(h.logs.String(), "n2: remediated less than 20m0s ago (back-off)") {
		t.Fatalf("flapping not held: %d %s", len(list()), h.logs.String())
	}
	// 25 minutes after: remediated again.
	h.setNow(vecNow.Add(25 * time.Minute))
	h.s.remediate(ctx)
	if len(list()) != 1 {
		t.Fatal("not remediated after the back-off")
	}
}
