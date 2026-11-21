package main

import (
	"context"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Node remediation (plan Task 24 fix round 1, user ruling "Patch SNR, drop
// NHC"): nodeadm, the leader only, asks Self Node Remediation to fence a
// dead node by creating its SelfNodeRemediation (named after the node, in
// the fencing namespace, strategy OutOfServiceTaint: SNR's manager puts
// node.kubernetes.io/out-of-service once the node is assumed rebooted, its
// agent there has reset it). The storm guard (planRemediation) decides;
// every action and every hold is logged (never a secret: node names and
// durations only).

var gvrSNR = schema.GroupVersionResource{Group: "self-node-remediation.medik8s.io", Version: "v1alpha1", Resource: "selfnoderemediations"}

const (
	// remediateAfter: a node NotReady / Unknown this long is remediated
	// (as NHC's unhealthyConditions were: 30 s).
	remediateAfter = 30 * time.Second
	// remediateEvery: the remediation round's period.
	remediateEvery = 10 * time.Second
	// remediationStale: a remediation of a node Ready again whose
	// SelfNodeRemediation never reported Succeeded is removed after this
	// long Ready (SNR lifts its taints when its CR goes).
	remediationStale = 15 * time.Minute
	snrManagedBy     = "portcullis-nodeadm"
)

// remediationNode is one node as the guard sees it.
type remediationNode struct {
	Name     string
	Site     string
	Class    string
	Ready    bool
	Since    time.Time // the Ready condition's last transition
	Stateful bool      // a pod with a PersistentVolumeClaim runs there
}

// remediationCR is one existing SelfNodeRemediation.
type remediationCR struct {
	Name      string
	Created   time.Time
	Succeeded bool // condition Succeeded True
}

// remediationPlan is one round's decision.
type remediationPlan struct {
	Create string   // the node to remediate now ("" = none)
	Delete []string // finished remediations to remove
	Hold   string   // why nothing is created this round ("" = nothing needed or Create set)
}

// planRemediation is the storm guard (pure, unit-tested):
//   - a node Ready again whose remediation Succeeded (or is
//     remediationStale old Ready) → its CR is removed;
//   - no new remediation while one is in progress (any CR not removed);
//   - no new remediation while more than half of the primary site's nodes
//     are unhealthy (a partition's minority, or a site-wide outage, never
//     fences the majority: the old NHC minHealthy 51 %);
//   - an edge or small node holding no stateful pod is never remediated
//     (nothing to fail over; its reset would only cost);
//   - otherwise the first node by name NotReady longer than remediateAfter.
func planRemediation(nodes []remediationNode, crs []remediationCR, primary string, now time.Time) remediationPlan {
	var p remediationPlan
	byName := map[string]remediationNode{}
	for _, n := range nodes {
		byName[n.Name] = n
	}
	inProgress := []string{}
	for _, c := range crs {
		n, known := byName[c.Name]
		switch {
		case known && n.Ready && (c.Succeeded || now.Sub(n.Since) >= remediationStale):
			p.Delete = append(p.Delete, c.Name)
		case !known && now.Sub(c.Created) >= remediationStale:
			// The node is gone (removed): its remediation with it.
			p.Delete = append(p.Delete, c.Name)
		default:
			inProgress = append(inProgress, c.Name)
		}
	}
	sort.Strings(p.Delete)
	var main, mainDown int
	var due []remediationNode
	for _, n := range nodes {
		if n.Site == primary {
			main++
			if !n.Ready {
				mainDown++
			}
		}
		if !n.Ready && now.Sub(n.Since) >= remediateAfter {
			due = append(due, n)
		}
	}
	if len(due) == 0 {
		return p
	}
	sort.Slice(due, func(i, j int) bool { return due[i].Name < due[j].Name })
	if len(inProgress) > 0 {
		sort.Strings(inProgress)
		p.Hold = "a remediation is in progress (" + strings.Join(inProgress, ", ") + ")"
		return p
	}
	if main == 0 || 2*mainDown > main {
		p.Hold = "more than half of the primary site's nodes are unhealthy: no remediation (a partition or an outage, never fenced from here)"
		return p
	}
	for _, n := range due {
		if (n.Site != primary || n.Class == "small") && !n.Stateful {
			continue
		}
		p.Create = n.Name
		return p
	}
	p.Hold = "the unhealthy nodes are edge or small nodes holding no stateful pod"
	return p
}

// remediationInputs reads the nodes, the pods' PVCs and the existing
// SelfNodeRemediations (fail closed: an unreadable input = no round).
func (s *Server) remediationInputs(ctx context.Context) ([]remediationNode, []remediationCR, error) {
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	pods, err := s.kube.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	stateful := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == "" || p.DeletionTimestamp != nil {
			continue
		}
		for _, v := range p.Spec.Volumes {
			if v.PersistentVolumeClaim != nil {
				stateful[p.Spec.NodeName] = true
			}
		}
	}
	var nodes []remediationNode
	for _, c := range cl {
		rn := remediationNode{Name: c.Name, Site: c.Site, Class: c.Class, Ready: c.Ready, Stateful: stateful[c.Name]}
		for _, cond := range c.Node.Status.Conditions {
			if cond.Type == corev1.NodeReady {
				rn.Since = cond.LastTransitionTime.Time
			}
		}
		if rn.Since.IsZero() {
			rn.Since = c.Node.CreationTimestamp.Time
		}
		nodes = append(nodes, rn)
	}
	l, err := s.dyn.Resource(gvrSNR).Namespace(s.cfg.FencingNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	var crs []remediationCR
	for _, o := range l.Items {
		c := remediationCR{Name: o.GetName(), Created: o.GetCreationTimestamp().Time}
		conds, _, _ := unstructured.NestedSlice(o.Object, "status", "conditions")
		for _, x := range conds {
			m, _ := x.(map[string]any)
			if m["type"] == "Succeeded" && m["status"] == "True" {
				c.Succeeded = true
			}
		}
		crs = append(crs, c)
	}
	return nodes, crs, nil
}

// remediate is one round (leader only; every write under the fence).
func (s *Server) remediate(ctx context.Context) {
	if !s.leader.Leading() || s.dyn == nil || s.cfg.FencingNS == "" {
		return
	}
	nodes, crs, err := s.remediationInputs(ctx)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			s.log.Warn("remediation: inputs unreadable, no round (fail closed)", "err", redact(err.Error()))
		}
		return
	}
	p := planRemediation(nodes, crs, primarySite, s.now())
	wctx, cancel := s.fenced(ctx)
	defer cancel()
	for _, name := range p.Delete {
		if err := s.dyn.Resource(gvrSNR).Namespace(s.cfg.FencingNS).Delete(wctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			s.log.Warn("remediation: couldn't remove a finished SelfNodeRemediation", "node", name, "err", redact(err.Error()))
			continue
		}
		s.log.Info("remediation finished: SelfNodeRemediation removed", "node", name)
	}
	if p.Hold != "" {
		if s.remHold != p.Hold {
			s.log.Warn("remediation held", "why", p.Hold)
		}
		s.remHold = p.Hold
		return
	}
	s.remHold = ""
	if p.Create == "" {
		return
	}
	cr := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "self-node-remediation.medik8s.io/v1alpha1", "kind": "SelfNodeRemediation",
		"metadata": map[string]any{"name": p.Create, "namespace": s.cfg.FencingNS,
			"labels": map[string]any{"app.kubernetes.io/managed-by": snrManagedBy}},
		"spec": map[string]any{"remediationStrategy": "OutOfServiceTaint"},
	}}
	if _, err := s.dyn.Resource(gvrSNR).Namespace(s.cfg.FencingNS).Create(wctx, cr, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			s.log.Warn("remediation: couldn't create the SelfNodeRemediation", "node", p.Create, "err", redact(err.Error()))
		}
		return
	}
	s.metrics.failovers.WithLabelValues("fence").Inc()
	s.log.Info("remediation started: SelfNodeRemediation created (SNR fences the node, then the out-of-service taint)", "node", p.Create)
}

// remediateLoop runs a round every remediateEvery.
func (s *Server) remediateLoop(ctx context.Context) {
	t := time.NewTicker(remediateEvery)
	defer t.Stop()
	for {
		s.remediate(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
