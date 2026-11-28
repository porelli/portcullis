package main

// A revoked server's volumes (Task 33b VM run 15, controller ruling A):
// nodeadm's revoke deleted the Node with nothing detached, so a
// replicated-tier volume attached there (the Hub's, in that run) kept its
// Kubernetes VolumeAttachment `attached: true` for good and Longhorn never
// attached it on a survivor: the Hub stayed down. Remediation gets its
// force-detach from SNR's out-of-service taint; a revoke never goes
// through SNR, and a deleted Node can carry no taint. So before
// node_deleted the revoke waits until T_fence (fenceTime) has passed since
// it started (a revoked node resets itself about a minute after its
// revoke: contract §20), puts node.kubernetes.io/out-of-service=
// nodeshutdown:NoExecute on the Node (Kubernetes' non-graceful node
// shutdown: its pods are deleted and its volumes force-detached), and
// waits until no VolumeAttachment names the node. Admission
// (portcullis-removed-nodes) lets nodeadm put exactly that taint, only on
// a node it lists removed, and change no other taint but its own two.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	taintOutOfService = "node.kubernetes.io/out-of-service"
	oosValue          = "nodeshutdown"
)

func isOutOfService(t corev1.Taint) bool {
	return t.Key == taintOutOfService && t.Value == oosValue && t.Effect == corev1.TaintEffectNoExecute
}

// outOfService is the revoke's out_of_service step (servers only).
func (s *Server) outOfService(ctx context.Context, op *revokeOp) error {
	id := op.Node
	if wait := op.Started.Add(s.timing.Fence).Sub(s.now()); wait > 0 {
		s.log.Info("revocation: waiting for T_fence before the out-of-service taint", "node", id, "wait", wait.Round(time.Second).String())
		if err := sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
	for try := 0; ; try++ {
		n, err := s.kube.CoreV1().Nodes().Get(ctx, id, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			// No Node (it never registered, or it was deleted by hand):
			// nothing can carry the taint, and a wait would never end.
			s.log.Warn("revocation: no Node to put out of service", "node", id)
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading node %s: %w", id, err)
		}
		has := false
		for _, t := range n.Spec.Taints {
			if isOutOfService(t) {
				has = true
			}
		}
		if has {
			break
		}
		// Its name must be refused (in force) first: admission lets the taint
		// only on a node listed removed.
		if err := s.removedInForce(ctx, id); err != nil {
			return err
		}
		taints := append(append([]corev1.Taint{}, n.Spec.Taints...), corev1.Taint{Key: taintOutOfService, Value: oosValue, Effect: corev1.TaintEffectNoExecute})
		b, _ := json.Marshal(map[string]any{"metadata": map[string]any{"resourceVersion": n.ResourceVersion}, "spec": map[string]any{"taints": taints}})
		_, err = s.kube.CoreV1().Nodes().Patch(ctx, id, types.MergePatchType, b, metav1.PatchOptions{})
		if err == nil {
			s.log.Info("revocation: node put out of service (its pods deleted, its volumes force-detached)", "node", id)
			break
		}
		if !apierrors.IsConflict(err) || try >= 5 {
			return fmt.Errorf("putting node %s out of service: %s", id, redact(err.Error()))
		}
	}
	return s.waitDetached(ctx, id)
}

// waitDetached: no VolumeAttachment names node id (≤ Timing.Detach); else
// the step fails naming them and is retried (the security steps are done).
func (s *Server) waitDetached(ctx context.Context, id string) error {
	wait := s.timing.Detach
	if wait <= 0 {
		wait = 5 * time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		l, err := s.kube.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("listing the volume attachments: %s", redact(err.Error()))
		}
		var left []string
		for _, va := range l.Items {
			if va.Spec.NodeName == id {
				pv := ""
				if va.Spec.Source.PersistentVolumeName != nil {
					pv = *va.Spec.Source.PersistentVolumeName
				}
				left = append(left, pv)
			}
		}
		if len(left) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			sort.Strings(left)
			return errPlain(http.StatusServiceUnavailable, "node %s is out of service but volumes are still attached to it (%s): the revocation goes on when it is retried", id, strings.Join(left, ", "))
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}
