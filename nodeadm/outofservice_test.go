package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// oosEvents records, in order, the out-of-service taint put on a Node
// (by a patch) and each Node delete; with detach, a patch that puts the
// taint deletes that node's VolumeAttachments (Kubernetes' force-detach).
type oosEvents struct {
	mu  sync.Mutex
	got []string
}

func (e *oosEvents) add(s string) { e.mu.Lock(); e.got = append(e.got, s); e.mu.Unlock() }
func (e *oosEvents) list() string { e.mu.Lock(); defer e.mu.Unlock(); return strings.Join(e.got, " ") }

func watchOutOfService(t *testing.T, h *harness, detach bool) *oosEvents {
	ev := &oosEvents{}
	h.kube.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		p := a.(k8stesting.PatchAction)
		if strings.Contains(string(p.GetPatch()), taintOutOfService) {
			ev.add("oos:" + p.GetName())
			if detach {
				go func(name string) {
					l, _ := h.kube.StorageV1().VolumeAttachments().List(context.Background(), metav1.ListOptions{})
					for _, va := range l.Items {
						if va.Spec.NodeName == name {
							h.kube.StorageV1().VolumeAttachments().Delete(context.Background(), va.Name, metav1.DeleteOptions{})
						}
					}
				}(p.GetName())
			}
		}
		return false, nil, nil
	})
	h.kube.PrependReactor("delete", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ev.add("delete:" + a.(k8stesting.DeleteAction).GetName())
		return false, nil, nil
	})
	return ev
}

func attachVolume(t *testing.T, h *harness, node, pv string) {
	t.Helper()
	va := &storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "csi-" + pv},
		Spec: storagev1.VolumeAttachmentSpec{Attacher: "driver.longhorn.io", NodeName: node, Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pv}}}
	if _, err := h.kube.StorageV1().VolumeAttachments().Create(context.Background(), va, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func revokeHarness(t *testing.T, fence, detach time.Duration) *harness {
	agent := nodeSpec{"n4", "agent", "cloud", "edge", "10.215.0.4", nil, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
	h.agents.onRotate = h.bootFollows
	h.s.timing.Fence, h.s.timing.Detach = fence, detach
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n2"] = &nodeRecord{Role: "server", Serial: "12:34", MeshIP: "10.215.0.2"}
		st.Nodes["n4"] = &nodeRecord{Role: "agent", Serial: "12:44", MeshIP: "10.215.0.4"}
	})
	return h
}

// TestRevokePutsServerOutOfServiceFirst (Task 33b VM run 15, ruling A): a
// server's revoke puts its Node out of service (exactly the taint), only
// after T_fence since the revoke started, and deletes the Node only once
// no VolumeAttachment names it (another node's attachment is no matter).
func TestRevokePutsServerOutOfServiceFirst(t *testing.T) {
	h := revokeHarness(t, 300*time.Millisecond, 5*time.Second)
	attachVolume(t, h, "n2", "pvc-hub-state")
	attachVolume(t, h, "n1", "pvc-domains")
	ev := watchOutOfService(t, h, true)
	start := time.Now()
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n2: %d %s", w.Code, w.Body)
	}
	if got := ev.list(); got != "oos:n2 delete:n2" {
		t.Fatalf("events %q, want the taint, then the Node delete", got)
	}
	if el := time.Since(start); el < 300*time.Millisecond {
		t.Fatalf("the taint came %v after the revoke started, before T_fence", el)
	}
	if !strings.Contains(h.logs.String(), "waiting for T_fence") {
		t.Fatal("the T_fence wait isn't logged")
	}
	l, _ := h.kube.StorageV1().VolumeAttachments().List(context.Background(), metav1.ListOptions{})
	if len(l.Items) != 1 || l.Items[0].Spec.NodeName != "n1" {
		t.Fatalf("attachments %+v: want only n1's left", l.Items)
	}
	if op := h.state(t).Ops["n2"]; op != nil {
		t.Fatalf("the revoke didn't finish: %+v", op)
	}
}

// TestRevokeKeepsNodeWhileAttached: volumes still attached after the
// taint park the revoke before node_deleted, naming them (the Node kept,
// the security steps done); once they detach, the retry finishes.
func TestRevokeKeepsNodeWhileAttached(t *testing.T) {
	h := revokeHarness(t, 0, 50*time.Millisecond)
	attachVolume(t, h, "n2", "pvc-hub-state")
	ev := watchOutOfService(t, h, false)
	w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil)
	if w.Code/100 == 2 {
		t.Fatalf("revoke with an attached volume: %d %s", w.Code, w.Body)
	}
	op := h.state(t).Ops["n2"]
	if op == nil || op.Step != "applied" || !strings.Contains(op.LastError, "volumes are still attached to it (pvc-hub-state)") {
		t.Fatalf("op %+v: want it parked before out_of_service, naming the volume", op)
	}
	if !nodeExists(t, h, "n2") {
		t.Fatal("n2's Node was deleted with a volume attached")
	}
	if r := h.state(t).Nodes["n2"]; r == nil || !r.Removed {
		t.Fatalf("the security steps aren't done: %+v", r)
	}
	n, _ := h.kube.CoreV1().Nodes().Get(context.Background(), "n2", metav1.GetOptions{})
	oos := 0
	for _, tt := range n.Spec.Taints {
		if isOutOfService(tt) {
			oos++
		} else if tt.Key == taintOutOfService {
			t.Fatalf("an out-of-service taint of another shape: %+v", tt)
		}
	}
	if oos != 1 {
		t.Fatalf("taints %+v: want the out-of-service taint once", n.Spec.Taints)
	}
	// Detached: the retry finishes, without a second taint patch.
	h.kube.StorageV1().VolumeAttachments().Delete(context.Background(), "csi-pvc-hub-state", metav1.DeleteOptions{})
	h.resume(t, "n2")
	if got := ev.list(); got != "oos:n2 delete:n2" {
		t.Fatalf("events %q", got)
	}
	if op := h.state(t).Ops["n2"]; op != nil {
		t.Fatalf("the revoke didn't finish: %+v", op)
	}
}

// TestRevokeAgentNoOutOfService: an agent's revoke deletes its Node as
// before (the ruling is for servers).
func TestRevokeAgentNoOutOfService(t *testing.T) {
	h := revokeHarness(t, time.Hour, time.Hour)
	ev := watchOutOfService(t, h, false)
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n4: %d %s", w.Code, w.Body)
	}
	if got := ev.list(); got != "delete:n4" {
		t.Fatalf("events %q: want only the Node delete", got)
	}
}
