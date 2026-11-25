package main

// The pods' volume constraints in the snapshot (contract §20.2, Task 33a
// fix round 1): a pod on a PersistentVolume with a required node affinity
// (portcullis-core's local-path volumes: the one node that holds the
// directory) can only ever run where that affinity matches, as the
// scheduler's VolumeBinding filter judges it. Without it the Hub's N−1
// check (§20.7) placed a StatefulSet member on a local volume elsewhere,
// and the drain proved it stays Pending (found by e2e-ha-k3d's
// ha_n_minus_1: group-gate-0, mcp-gate-0, vault-2). A replicated volume
// (Longhorn's) has no node affinity and constrains nothing.

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// claimAffinity: "<namespace>/<claim>" → the bound volume's required node
// affinity terms (empty: none). A claim missing from the map is unknown.
type claimAffinity map[string][]corev1.NodeSelectorTerm

func (s *Server) claimAffinities(ctx context.Context) (claimAffinity, error) {
	pvcs, err := s.kube.CoreV1().PersistentVolumeClaims("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing the volume claims: %w", err)
	}
	pvs, err := s.kube.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing the volumes: %w", err)
	}
	byName := map[string]*corev1.PersistentVolume{}
	for i := range pvs.Items {
		byName[pvs.Items[i].Name] = &pvs.Items[i]
	}
	out := claimAffinity{}
	for _, c := range pvcs.Items {
		pv := byName[c.Spec.VolumeName]
		if c.Spec.VolumeName == "" || pv == nil {
			continue // unbound or its volume unseen: unknown
		}
		terms := []corev1.NodeSelectorTerm{}
		if a := pv.Spec.NodeAffinity; a != nil && a.Required != nil {
			terms = a.Required.NodeSelectorTerms
		}
		out[c.Namespace+"/"+c.Name] = terms
	}
	return out, nil
}

// podClaims: the claims a pod's volumes name (a generic ephemeral
// volume's is <pod>-<volume>).
func podClaims(p *corev1.Pod) []string {
	var out []string
	for _, v := range p.Spec.Volumes {
		switch {
		case v.PersistentVolumeClaim != nil:
			out = append(out, v.PersistentVolumeClaim.ClaimName)
		case v.Ephemeral != nil:
			out = append(out, p.Name+"-"+v.Name)
		}
	}
	return out
}

// volumeTerms: one pod's volume constraints, each volume's terms (any one
// must match). Fail closed: a claim whose volume nodeadm can't see, or a
// volume term it can't express, pins the pod to its current node (lost
// with it: unplaced, never placed where the scheduler may refuse it).
func volumeTerms(p *corev1.Pod, ca claimAffinity) [][][]Expr {
	pin := [][]Expr{{{Key: "kubernetes.io/hostname", Operator: "In", Values: []string{p.Spec.NodeName}}}}
	var out [][][]Expr
	for _, c := range podClaims(p) {
		terms, ok := ca[p.Namespace+"/"+c]
		if !ok {
			out = append(out, pin)
			continue
		}
		if len(terms) == 0 {
			continue
		}
		var alts [][]Expr
		for _, t := range terms {
			var term []Expr
			for _, e := range t.MatchExpressions {
				vals := e.Values
				if vals == nil {
					vals = []string{}
				}
				term = append(term, Expr{Key: e.Key, Operator: string(e.Operator), Values: vals})
			}
			for _, f := range t.MatchFields {
				// metadata.name In: the node's name, its hostname label on
				// a k3s node. Any other field: not expressible.
				if f.Key != "metadata.name" || f.Operator != corev1.NodeSelectorOpIn {
					return append(out, pin)
				}
				term = append(term, Expr{Key: "kubernetes.io/hostname", Operator: "In", Values: append([]string{}, f.Values...)})
			}
			alts = append(alts, term)
		}
		out = append(out, alts)
	}
	return out
}

// withVolumeAffinity ANDs a snapshot pod's required affinity with its
// volumes' (term by term: any pod term with any term of each volume).
func withVolumeAffinity(sp *SnapPod, vols [][][]Expr) {
	if len(vols) == 0 {
		return
	}
	base := sp.RequiredAffinity
	if len(base) == 0 {
		base = [][]Expr{{}}
	}
	for _, alts := range vols {
		var next [][]Expr
		for _, b := range base {
			for _, a := range alts {
				next = append(next, append(append([]Expr{}, b...), a...))
			}
		}
		base = next
	}
	sp.RequiredAffinity = base
}

// volumeLabelKeys: the node label keys the pods' volume constraints name
// (selectedLabelKeys' complement: the snapshot keeps them on its nodes).
func volumeLabelKeys(pods []corev1.Pod, ca claimAffinity, keys map[string]bool) {
	for i := range pods {
		for _, alts := range volumeTerms(&pods[i], ca) {
			for _, t := range alts {
				for _, e := range t {
					keys[e.Key] = true
				}
			}
		}
	}
}
