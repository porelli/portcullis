package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

var remNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func rn(name, site, class string, ready bool, agoS int, replicated bool) remediationNode {
	return remediationNode{Name: name, Site: site, Class: class, Ready: ready, Since: remNow.Add(-time.Duration(agoS) * time.Second), Replicated: replicated}
}

func with(n remediationNode, f func(*remediationNode)) remediationNode { f(&n); return n }

// exl: SNR's exclude label (also maintenance, as remediationInputs sets it).
func exl(n remediationNode) remediationNode { n.ExcludeLabel, n.Excluded = true, true; return n }

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
		// Round 5 I1: fenced = Succeeded AND T_fence since creation AND still NotReady.
		{"fenced and still down (Succeeded, T_fence passed), then a second node dies → the second remediated, the first kept",
			[]remediationNode{rn("m1", "main", "cloud", false, 1800, true), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(29), Succeeded: true}}, remediationPlan{Create: "m2"}},
		{"Succeeded but younger than T_fence (100 s): still in progress, the next held",
			[]remediationNode{rn("m1", "main", "cloud", false, 600, true), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: remNow.Add(-100 * time.Second), Succeeded: true}}, remediationPlan{Hold: "a remediation is in progress (m1)"}},
		{"Succeeded, T_fence passed (151 s), node still NotReady: fenced, the next remediated",
			[]remediationNode{rn("m1", "main", "cloud", false, 600, true), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: remNow.Add(-151 * time.Second), Succeeded: true}}, remediationPlan{Create: "m2"}},
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
		// Round 3 I1d: a remediation can't stall all fencing.
		{"SNR's exclude label before fencing began (SNR skips it): stuck, the next node remediated",
			[]remediationNode{exl(rn("m1", "main", "cloud", false, 600, true)), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(2), Phase: "Fencing-Started"}}, remediationPlan{Create: "m2", Stuck: []string{"m1: labelled exclude-from-remediation before its fencing began (SNR skips it)"}}},
		{"SNR's exclude label after the pre-reboot phase (its agent still resets): the hold kept",
			[]remediationNode{exl(rn("m1", "main", "cloud", false, 600, true)), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(2), Phase: "Pre-Reboot-Completed"}}, remediationPlan{Hold: "a remediation is in progress (m1)"}},
		// Round 4 M1: maintenance, an op in flight or a removal keep the hold until the bound.
		{"an op in flight (or maintenance) on a node with a young remediation: the hold kept",
			[]remediationNode{with(rn("m1", "main", "cloud", false, 600, true), func(n *remediationNode) { n.Excluded = true }), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(2)}}, remediationPlan{Hold: "a remediation is in progress (m1)"}},
		{"not fenced 7 min after it started: stuck, the next node remediated",
			[]remediationNode{rn("m1", "main", "cloud", false, 900, true), rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)},
			[]remediationCR{{Name: "m1", Created: ago(8)}}, remediationPlan{Create: "m2", Stuck: []string{"m1: not fenced 7m0s after it started"}}},
		{"6 min, not Succeeded: still in progress", main3(rn("m2", "main", "home", false, 400, true)), []remediationCR{{Name: "m2", Created: ago(6)}}, remediationPlan{}},
		{"a back-off record in the future (beyond the skew) is ignored: remediated", main3(with(rn("m2", "main", "home", false, 60, true), func(n *remediationNode) { n.LastRemediated = remNow.Add(48 * time.Hour) })), nil, remediationPlan{Create: "m2"}},
		{"a back-off record 30 s ahead (clock skew) still holds", main3(with(rn("m2", "main", "home", false, 60, true), func(n *remediationNode) { n.LastRemediated = remNow.Add(30 * time.Second) })), nil,
			remediationPlan{Hold: "nothing to remediate: m2: remediated less than 20m0s ago (back-off)"}},
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
		if got.Create != c.want.Create || got.Hold != c.want.Hold || strings.Join(got.Delete, ",") != strings.Join(c.want.Delete, ",") || strings.Join(got.Stuck, ",") != strings.Join(c.want.Stuck, ",") {
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
	if st := h.state(t); !st.Remediations["n2"].Equal(vecNow) {
		t.Fatalf("the back-off record in nodeadm's state: %v", st.Remediations)
	}
	if n2, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{}); strings.Contains(fmt.Sprint(n2.Annotations), "nodeadm.portcullis/") {
		t.Fatalf("the back-off must not live on the Node: %v", n2.Annotations)
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

// TestRemediateMaintenanceMark (round 3 I1b): a node cordoned without
// nodeadm's mark (anyone's spec.unschedulable) is still remediated; one
// cordoned through nodeadm's cordon API is skipped. A failed create leaves
// no back-off record.
func TestRemediateMaintenanceMark(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n2, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
	n2.Spec.Unschedulable = true
	n2.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: metav1.NewTime(vecNow.Add(-time.Minute))}}
	h.kube.CoreV1().Nodes().Update(ctx, n2, metav1.UpdateOptions{})
	h.kube.CoreV1().Nodes().UpdateStatus(ctx, n2, metav1.UpdateOptions{})
	d := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrSNR: "SelfNodeRemediationList", gvrLonghornVolume: "VolumeList"})
	h.s.dyn = d
	// A failed create: no CR, no back-off record.
	d.PrependReactor("create", "selfnoderemediations", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("refused")
	})
	h.s.remediate(ctx)
	if st := h.state(t); !st.Remediations["n2"].IsZero() {
		t.Fatal("a failed create recorded a back-off")
	}
	d.ReactionChain = d.ReactionChain[1:]
	// The cordon API's mark: skipped.
	h.putState(t, func(st *nodeadmState) { st.Maintenance["n2"] = true })
	h.s.remediate(ctx)
	if l, _ := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(ctx, metav1.ListOptions{}); len(l.Items) != 0 {
		t.Fatal("a node cordoned through nodeadm was remediated")
	}
	// spec.unschedulable without the mark: remediated.
	h.putState(t, func(st *nodeadmState) { delete(st.Maintenance, "n2") })
	h.s.remediate(ctx)
	if l, _ := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(ctx, metav1.ListOptions{}); len(l.Items) != 1 {
		t.Fatal("a node cordoned by someone else (no nodeadm mark) wasn't remediated")
	}
}

// TestRemediationInputsFenceFacts (round 4 M1, round 5 M2): the round
// reads SNR's exclude label on its own and the CR's phase; only known
// Nodes are inputs — the harness's three (no record, CLI-labelled like the
// first node), a nodeadm-enrolled one once Labelled — and the others (no
// site label, the registration taint, enrolled but not yet labelled) are
// unknown: never counted, never remediated, in the snapshot's errors.
func TestRemediationInputsFenceFacts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n2, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
	n2.Labels[labelExclude] = "true"
	h.kube.CoreV1().Nodes().Update(ctx, n2, metav1.UpdateOptions{})
	down := func(n *corev1.Node) *corev1.Node {
		n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: metav1.NewTime(vecNow.Add(-time.Hour))}}
		return n
	}
	fake := down(mkNode(nodeSpec{"x1", "agent", "home", "", "10.215.0.41", nil, nil, false, false}))
	delete(fake.Labels, labelSite)
	reg := down(mkNode(nodeSpec{"x2", "agent", "home", "main", "10.215.0.42", nil, nil, false, false}))
	reg.Spec.Taints = []corev1.Taint{{Key: taintUnlabelled, Value: "true", Effect: corev1.TaintEffectNoSchedule}}
	pend := down(mkNode(nodeSpec{"x3", "agent", "home", "main", "10.215.0.43", nil, nil, false, false}))
	enr := mkNode(nodeSpec{"x4", "agent", "home", "main", "10.215.0.44", nil, nil, true, false})
	for _, n := range []*corev1.Node{fake, reg, pend, enr} {
		if _, err := h.kube.CoreV1().Nodes().Create(ctx, n, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["x3"] = &nodeRecord{Role: "agent", Class: "home", Site: "main", Serial: "11:22"}
		st.Nodes["x4"] = &nodeRecord{Role: "agent", Class: "home", Site: "main", Serial: "33:44", Labelled: true}
	})
	cr := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "self-node-remediation.medik8s.io/v1alpha1", "kind": "SelfNodeRemediation",
		"metadata": map[string]any{"name": "n2", "namespace": "portcullis-fencing"}, "status": map[string]any{"phase": "Pre-Reboot-Completed"}}}
	h.s.dyn = dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrSNR: "SelfNodeRemediationList", gvrLonghornVolume: "VolumeList"}, cr)
	nodes, crs, unknown, err := h.s.remediationInputs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var got remediationNode
	for _, n := range nodes {
		names = append(names, n.Name)
		if n.Name == "n2" {
			got = n
		}
	}
	if strings.Join(names, ",") != "n1,n2,n3,x4" || strings.Join(unknown, ",") != "x1,x2,x3" {
		t.Fatalf("known %v, unknown %v", names, unknown)
	}
	if !got.ExcludeLabel || !got.Excluded || len(crs) != 1 || crs[0].Phase != "Pre-Reboot-Completed" {
		t.Fatalf("inputs: %+v %+v", got, crs)
	}
	// Through a round: the three unknown down Nodes are neither remediated
	// nor counted (3 of 7 down would be no storm anyway; x1..x3 alone would
	// be a storm of 3 of 4 known+unknown main nodes), and they are reported.
	h.s.dyn = dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrSNR: "SelfNodeRemediationList", gvrLonghornVolume: "VolumeList"})
	h.s.remediate(ctx)
	if l, _ := h.s.dyn.Resource(gvrSNR).Namespace("portcullis-fencing").List(ctx, metav1.ListOptions{}); len(l.Items) != 0 {
		t.Fatalf("an unknown Node was remediated: %v", l.Items[0].GetName())
	}
	errs := strings.Join(h.s.remediationErrors(), "\n")
	for _, x := range []string{"x1", "x2", "x3"} {
		if !strings.Contains(errs, "unknown node registered: "+x+" ") {
			t.Fatalf("not reported: %s\n%s", x, errs)
		}
	}
	if !strings.Contains(h.logs.String(), "unknown node registered") {
		t.Fatalf("not logged: %s", h.logs.String())
	}
}

// TestUnknownNodesNeverCountedInTheGuard (round 5 M2): fake NotReady Nodes
// can't make a real dead node's fencing a "storm".
func TestUnknownNodesNeverCountedInTheGuard(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	n2, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{})
	n2.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown, LastTransitionTime: metav1.NewTime(vecNow.Add(-time.Minute))}}
	h.kube.CoreV1().Nodes().UpdateStatus(ctx, n2, metav1.UpdateOptions{})
	for i := 1; i <= 4; i++ {
		f := mkNode(nodeSpec{fmt.Sprintf("fake%d", i), "agent", "home", "", fmt.Sprintf("10.215.0.%d", 50+i), nil, nil, false, false})
		delete(f.Labels, labelSite)
		h.kube.CoreV1().Nodes().Create(ctx, f, metav1.CreateOptions{})
	}
	d := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvrSNR: "SelfNodeRemediationList", gvrLonghornVolume: "VolumeList"})
	h.s.dyn = d
	h.s.remediate(ctx)
	l, _ := d.Resource(gvrSNR).Namespace("portcullis-fencing").List(ctx, metav1.ListOptions{})
	if len(l.Items) != 1 || l.Items[0].GetName() != "n2" {
		t.Fatalf("the real dead node wasn't fenced (fakes counted?): %d %s", len(l.Items), h.logs.String())
	}
}

// TestFencedFollowsSNRsOrder (round 5 I1): SNR v0.13.0's OutOfServiceTaint
// strategy, as its source orders it (internal/controller/
// selfnoderemediation_controller.go): prepareReboot puts
// remediation.medik8s.io/self-node-remediation:NoSchedule and sets
// Pre-Reboot-Completed; waitForNodeRebooted (safe time 150 s) sets
// Reboot-Completed; useOutOfServiceTaint puts the out-of-service taint,
// waits for the node's pods and attachments to go, then REMOVES it;
// handleRebootCompletedPhase only then sets Fencing-Completed and
// Succeeded. nodeadm counts the remediation in progress through every step
// before Succeeded and frees the next one only after it, with the node
// still NotReady.
func TestFencedFollowsSNRsOrder(t *testing.T) {
	created := remNow.Add(-10 * time.Minute)
	others := []remediationNode{rn("m2", "main", "home", false, 60, true), rn("m3", "main", "cloud", true, 3600, true), rn("m4", "main", "cloud", true, 3600, true), rn("m5", "main", "cloud", true, 3600, true)}
	steps := []struct {
		at        time.Duration // since the CR's creation
		phase     string
		succeeded bool
		fenced    bool
	}{
		{0, "", false, false},                                   // created
		{2 * time.Second, "Fencing-Started", false, false},      // the finalizer added
		{3 * time.Second, "Pre-Reboot-Completed", false, false}, // NoSchedule taint, TimeAssumedRebooted
		{153 * time.Second, "Reboot-Completed", false, false},   // safe time passed; out-of-service taint put
		{170 * time.Second, "Reboot-Completed", false, false},   // pods / attachments gone; the taint removed
		{171 * time.Second, "Fencing-Completed", true, true},    // Succeeded (after the taint is gone)
	}
	for _, st := range steps {
		now := created.Add(st.at)
		m1 := remediationNode{Name: "m1", Site: "main", Class: "cloud", Ready: false, Since: created.Add(-time.Minute), Replicated: true}
		m2 := others[0]
		m2.Since = now.Add(-time.Minute)
		nodes := append([]remediationNode{m1, m2}, others[1:]...)
		p := planRemediation(nodes, []remediationCR{{Name: "m1", Created: created, Succeeded: st.succeeded, Phase: st.phase}}, primarySite, now)
		if st.fenced && p.Create != "m2" {
			t.Errorf("at %s (%s, Succeeded): m1 fenced, m2 should be remediated: %+v", st.at, st.phase, p)
		}
		if !st.fenced && (p.Create != "" || p.Hold != "a remediation is in progress (m1)") {
			t.Errorf("at %s (%s): m1 still in progress: %+v", st.at, st.phase, p)
		}
	}
	// Succeeded but the node Ready again: removed (SNR recovers it).
	p := planRemediation([]remediationNode{rn("m1", "main", "cloud", true, 10, true), rn("m3", "main", "cloud", true, 3600, true)},
		[]remediationCR{{Name: "m1", Created: created, Succeeded: true, Phase: "Fencing-Completed"}}, primarySite, remNow)
	if strings.Join(p.Delete, ",") != "m1" {
		t.Fatalf("Ready again: %+v", p)
	}
}

// TestDropRemovedPrunesRemediationState (round 4 nit 1): a removed node's
// back-off record and maintenance mark leave with its record.
func TestDropRemovedPrunesRemediationState(t *testing.T) {
	h := newHarness(t)
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n9"] = &nodeRecord{Role: "agent", Removed: true, MeshIP: "10.215.0.99"}
		st.Remediations["n9"] = vecNow
		st.Maintenance["n9"] = true
		st.Remediations["n2"] = vecNow
	})
	h.admit(t, "10.215.0.1") // the active generation no longer holds n9's address
	h.s.dropRemoved(context.Background(), h.state(t))
	st := h.state(t)
	if st.Nodes["n9"] != nil || !st.Remediations["n9"].IsZero() || st.Maintenance["n9"] || st.Remediations["n2"].IsZero() {
		t.Fatalf("after the drop: node %v, remediations %v, maintenance %v", st.Nodes["n9"], st.Remediations, st.Maintenance)
	}
}

// TestCordonRollsTheMarkBack (round 5 nit 3): a cordon whose Node patch
// fails leaves no maintenance mark (the cordon API and drain); a cordon
// that works leaves it, an uncordon drops it.
func TestCordonRollsTheMarkBack(t *testing.T) {
	h := newHarness(t)
	h.kube.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("refused")
	})
	if w := h.internal(clientHub, "POST", "/v1/nodes/n1/cordon", map[string]any{}); w.Code < 400 {
		t.Fatalf("the failed cordon answered %d", w.Code)
	}
	h.internal(clientHub, "POST", "/v1/nodes/n2/drain", map[string]any{})
	if st := h.state(t); st.Maintenance["n1"] || st.Maintenance["n2"] {
		t.Fatalf("a mark was left after a failed cordon: %v", st.Maintenance)
	}
	h.kube.ReactionChain = h.kube.ReactionChain[1:]
	if w := h.internal(clientHub, "POST", "/v1/nodes/n1/cordon", map[string]any{}); w.Code != http.StatusNoContent {
		t.Fatalf("cordon: %d %s", w.Code, w.Body)
	}
	if !h.state(t).Maintenance["n1"] {
		t.Fatal("no mark after a cordon")
	}
	if w := h.internal(clientHub, "POST", "/v1/nodes/n1/uncordon", map[string]any{}); w.Code != http.StatusNoContent || h.state(t).Maintenance["n1"] {
		t.Fatalf("uncordon: %d, mark %v", w.Code, h.state(t).Maintenance)
	}
}

// TestCordonRollbackOnlyItsOwnMark (round 5, the security review of the
// rollback): a failed cordon never drops a mark that was already there,
// and a patch that landed but answered an error keeps the mark.
func TestCordonRollbackOnlyItsOwnMark(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.putState(t, func(st *nodeadmState) { st.Maintenance["n1"] = true })
	h.kube.PrependReactor("patch", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("refused")
	})
	if w := h.internal(clientHub, "POST", "/v1/nodes/n1/cordon", map[string]any{}); w.Code < 400 {
		t.Fatalf("the failed cordon answered %d", w.Code)
	}
	if !h.state(t).Maintenance["n1"] {
		t.Fatal("a pre-existing mark was dropped by a failed cordon")
	}
	// The patch lands, then the answer is an error (a timeout after the write).
	h.kube.ReactionChain = h.kube.ReactionChain[1:]
	h.kube.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		n, _ := h.kube.Tracker().Get(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}, "", a.(k8stesting.PatchAction).GetName())
		node := n.(*corev1.Node).DeepCopy()
		node.Spec.Unschedulable = true
		if err := h.kube.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}, node, ""); err != nil {
			t.Fatal(err)
		}
		return true, nil, fmt.Errorf("the request timed out")
	})
	if w := h.internal(clientHub, "POST", "/v1/nodes/n2/cordon", map[string]any{}); w.Code < 400 {
		t.Fatalf("the errored cordon answered %d", w.Code)
	}
	if n, _ := h.kube.CoreV1().Nodes().Get(ctx, "n2", metav1.GetOptions{}); !n.Spec.Unschedulable || !h.state(t).Maintenance["n2"] {
		t.Fatalf("a cordon that landed lost its mark: unschedulable %v, marks %v", n.Spec.Unschedulable, h.state(t).Maintenance)
	}
}

// TestManagerRuleJudgesEveryNodeSpecField (round 5 nit 2): the manager's
// rule in portcullis-node-labels compares every v1 NodeSpec field of the
// vendored k8s.io/api but taints (judged by the taint allowlist), so a new
// NodeSpec field can't pass unjudged.
func TestManagerRuleJudgesEveryNodeSpecField(t *testing.T) {
	b, err := os.ReadFile("../kube/admission/policies.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "request.userInfo.username != 'system:serviceaccount:portcullis-fencing:self-node-remediation-controller-manager'")
	j := strings.Index(s, "message: SNR's manager may only put or lift")
	if i < 0 || j < i {
		t.Fatal("the manager's rule isn't in policies.yaml")
	}
	rule := s[i:j]
	ty := reflect.TypeOf(corev1.NodeSpec{})
	for k := 0; k < ty.NumField(); k++ {
		name := strings.Split(ty.Field(k).Tag.Get("json"), ",")[0]
		if name == "podPreemptionPolicy" {
			// Reviewed exception: alpha in k8s.io/api v0.37, forbidden while
			// the InPlacePodVerticalScalingSchedulerPreemption gate is off (the
			// default; Portcullis never enables it), and absent from the
			// servers' schemas below 1.37 — a CEL reference would make the
			// policy fail to compile on the 1.33 floor.
			continue
		}
		if name == "taints" {
			if !strings.Contains(rule, "variables.newOtherTaints") {
				t.Error("the manager's rule doesn't judge spec.taints")
			}
			continue
		}
		if !strings.Contains(rule, "object.spec."+name) {
			t.Errorf("the manager's rule doesn't judge spec.%s (NodeSpec of the vendored k8s.io/api)", name)
		}
	}
}
