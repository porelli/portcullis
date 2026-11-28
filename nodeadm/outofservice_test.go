package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
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

func putLease(t *testing.T, h *harness, node string, renewed time.Time) {
	t.Helper()
	d := int32(40)
	rt := metav1.NewMicroTime(renewed)
	l := &coordinationv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "kube-node-lease"},
		Spec: coordinationv1.LeaseSpec{HolderIdentity: &node, LeaseDurationSeconds: &d, RenewTime: &rt}}
	ctx := context.Background()
	h.kube.CoordinationV1().Leases("kube-node-lease").Delete(ctx, node, metav1.DeleteOptions{})
	if _, err := h.kube.CoordinationV1().Leases("kube-node-lease").Create(ctx, l, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func setReady(t *testing.T, h *harness, node string, ready bool) {
	t.Helper()
	ctx := context.Background()
	n, err := h.kube.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: st}}
	if _, err := h.kube.CoreV1().Nodes().UpdateStatus(ctx, n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func attachVolume(t *testing.T, h *harness, node, pv string) {
	t.Helper()
	va := &storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: "csi-" + pv},
		Spec: storagev1.VolumeAttachmentSpec{Attacher: "driver.longhorn.io", NodeName: node, Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pv}}}
	if _, err := h.kube.StorageV1().VolumeAttachments().Create(context.Background(), va, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// revokeHarness: n2 (the server to revoke) is down: NotReady, its Node
// lease stale (renewed 10 min ago), no survivor lists it a mesh peer.
func revokeHarness(t *testing.T, fence, detach time.Duration) *harness {
	agent := nodeSpec{"n4", "agent", "cloud", "edge", "10.215.0.4", nil, nil, true, false}
	n2 := nodeSpec{"n2", "server", "home", "main", "10.215.0.2", []string{"192.0.2.12"}, nil, false, false}
	h := newHarness(t, baseNodes[0], n2, baseNodes[2], agent)
	h.agents.onRotate = h.bootFollows
	h.s.timing.Fence, h.s.timing.Detach, h.s.timing.Cutoff = fence, detach, 300*time.Millisecond
	h.s.cutOffCheck = nil // the real evidence
	h.agents.mu.Lock()
	h.agents.meshState = true // every survivor answers with its (empty) mesh state
	h.agents.mu.Unlock()
	putLease(t, h, "n2", time.Now().Add(-10*time.Minute))
	// The enrolled mesh keys (key-<id>, what the fake nodeagents report).
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n1"] = &nodeRecord{Role: "server", MeshIP: "10.215.0.1", Mesh: MeshReport{Pub: "key-n1"}}
		st.Nodes["n2"] = &nodeRecord{Role: "server", Serial: "12:34", MeshIP: "10.215.0.2", Mesh: MeshReport{Pub: "key-n2"}}
		st.Nodes["n3"] = &nodeRecord{Role: "server", MeshIP: "10.215.0.3", Mesh: MeshReport{Pub: "key-n3"}}
		st.Nodes["n4"] = &nodeRecord{Role: "agent", Serial: "12:44", MeshIP: "10.215.0.4", Mesh: MeshReport{Pub: "key-n4"}}
	})
	return h
}

// TestRevokePutsServerOutOfServiceFirst (Task 33b VM run 15, ruling A): a
// server's revoke puts its Node out of service (exactly the taint), only
// once it has been proven cut off for T_fence, and deletes the Node only
// once no VolumeAttachment names it (another node's attachment is no
// matter).
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
		t.Fatalf("the taint came %v after the revoke started, before T_fence of proof", el)
	}
	if !strings.Contains(h.logs.String(), "is cut off (NotReady, its lease stale, no mesh peer) for T_fence") {
		t.Fatal("the cut-off proof isn't logged")
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
	setReady(t, h, "n2", true) // every server up: an agent's revoke applies its tokens to all
	ev := watchOutOfService(t, h, false)
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n4: %d %s", w.Code, w.Body)
	}
	if got := ev.list(); got != "delete:n4" {
		t.Fatalf("events %q: want only the Node delete", got)
	}
}

// TestRevokeNoTaintWithoutCutOffProof (security review of ruling A): a
// server still Ready, one whose Node lease is fresh, one still a mesh
// peer of a survivor (a handshake after the revoke), and one whose
// survivor's nodeagent doesn't answer are never put out of service: the
// revoke parks with cutoff_pending naming why, the Node and its volumes
// kept; proven cut off, the retry finishes.
func TestRevokeNoTaintWithoutCutOffProof(t *testing.T) {
	recent := time.Now().UTC().Add(time.Hour).Format(time.RFC3339) // after the revoke (vecNow)
	// The revoke starts at vecNow (the harness clock), a whole second: the
	// boundary is vecNow − handshakeSkew.
	sameSec := vecNow.UTC().Format(time.RFC3339)
	skewed := vecNow.Add(-3 * time.Second).UTC().Format(time.RFC3339)
	after3 := vecNow.Add(3 * time.Second).UTC().Format(time.RFC3339)
	for _, c := range []struct {
		name, why string
		setup     func(t *testing.T, h *harness)
		heal      func(t *testing.T, h *harness)
	}{
		{"still Ready", "its Node is Ready",
			func(t *testing.T, h *harness) { setReady(t, h, "n2", true) },
			func(t *testing.T, h *harness) { setReady(t, h, "n2", false) }},
		{"fresh lease", "its Node lease was renewed",
			func(t *testing.T, h *harness) { putLease(t, h, "n2", time.Now()) },
			func(t *testing.T, h *harness) { putLease(t, h, "n2", time.Now().Add(-10*time.Minute)) }},
		{"still in a survivor's plan", "still a mesh peer of n1 (its plan)",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.peers = map[string]string{"n1": `{"n2":{"latest_handshake":null,"endpoint":null}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.peers = nil; h.agents.mu.Unlock() }},
		{"still a device peer for its mesh address", "n1's WireGuard device still has a peer for 10.215.0.2 (key key-n2)",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n1": `{"key-n2":{"latest_handshake":null,"endpoint":null,"allowed_ips":["10.215.0.2/32"]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"a handshake after the start from a key no longer in the plan", "n3 saw a handshake at " + recent + " from key key-gone, which isn't a surviving node's enrolled key",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n3": `{"key-gone":{"latest_handshake":"` + recent + `","endpoint":null,"allowed_ips":[]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"a same-second handshake from the revoked key", "n3 saw a handshake at " + sameSec + " from key key-n2",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n3": `{"key-n2":{"latest_handshake":"` + sameSec + `","endpoint":null,"allowed_ips":[]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"a handshake 3 s before the start (inside the skew)", "n3 saw a handshake at " + skewed + " from key key-x",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n3": `{"key-x":{"latest_handshake":"` + skewed + `","endpoint":null,"allowed_ips":[]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"a handshake 3 s after the start", "n1 saw a handshake at " + after3 + " from key key-x",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n1": `{"key-x":{"latest_handshake":"` + after3 + `","endpoint":null,"allowed_ips":[]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"a survivor reporting a mesh_pub that isn't its enrolled key", "n3 reports a mesh key that isn't its enrolled one (not proven)",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.pubs = map[string]string{"n3": "key-n2"} // vouching for the revoked key
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.pubs = nil; h.agents.mu.Unlock() }},
		{"a survivor vouching for another key by its mesh_pub", "n3 saw a handshake at " + after3 + " from key key-x, which isn't a surviving node's enrolled key",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.pubs = map[string]string{"n1": "key-x"} // asked first
				h.agents.devPeers = map[string]string{"n3": `{"key-x":{"latest_handshake":"` + after3 + `","endpoint":null,"allowed_ips":[]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.pubs, h.agents.devPeers = nil, nil
				h.agents.mu.Unlock()
			}},
		{"the revoked node's enrolled key held by a survivor under other allowed IPs", "n1's WireGuard device still holds the revoked node's enrolled key key-n2",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n1": `{"key-n2":{"latest_handshake":null,"endpoint":null,"allowed_ips":["10.215.0.77/32"]}}`}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"peers missing", "n1 reported no mesh state",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.peers = map[string]string{"n1": ""}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.peers = nil; h.agents.mu.Unlock() }},
		{"peers null", "n1 reported no mesh state",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.peers = map[string]string{"n1": "null"}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.peers = nil; h.agents.mu.Unlock() }},
		{"device_peers missing", "n3 reported no mesh state",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n3": ""}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"device_peers null", "n3 reported no mesh state",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.devPeers = map[string]string{"n3": "null"}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.devPeers = nil; h.agents.mu.Unlock() }},
		{"a missing Lease", "its Node lease is missing (not proven)",
			func(t *testing.T, h *harness) {
				h.kube.CoordinationV1().Leases("kube-node-lease").Delete(context.Background(), "n2", metav1.DeleteOptions{})
			},
			func(t *testing.T, h *harness) { putLease(t, h, "n2", time.Now().Add(-10*time.Minute)) }},
		{"survivor silent", "n3's nodeagent doesn't answer",
			func(t *testing.T, h *harness) {
				h.agents.mu.Lock()
				h.agents.down = map[string]bool{"n3": true}
				h.agents.mu.Unlock()
			},
			func(t *testing.T, h *harness) { h.agents.mu.Lock(); h.agents.down = nil; h.agents.mu.Unlock() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := revokeHarness(t, 50*time.Millisecond, 2*time.Second)
			attachVolume(t, h, "n2", "pvc-hub-state")
			ev := watchOutOfService(t, h, true)
			c.setup(t, h)
			w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil)
			if w.Code != 409 || !strings.Contains(w.Body.String(), "waiting for n2 to be cut off") || !strings.Contains(w.Body.String(), c.why) {
				t.Fatalf("revoke: %d %s; want 409 cutoff_pending naming %q", w.Code, w.Body, c.why)
			}
			if !strings.Contains(w.Body.String(), kindCutoffPending) || !strings.Contains(w.Body.String(), "power the machine off") {
				t.Fatalf("the answer lacks its kind or the way out: %s", w.Body)
			}
			if got := ev.list(); got != "" {
				t.Fatalf("events %q: the node was tainted or deleted without proof", got)
			}
			if op := h.state(t).Ops["n2"]; op == nil || op.Step != "applied" || op.LastKind != kindCutoffPending {
				t.Fatalf("op %+v: want it parked before out_of_service", op)
			}
			if r := h.state(t).Nodes["n2"]; r == nil || !r.Removed {
				t.Fatalf("the security steps aren't done: %+v", r)
			}
			c.heal(t, h)
			if w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil); w.Code != 204 {
				t.Fatalf("revoke once cut off: %d %s", w.Code, w.Body)
			}
			if got := ev.list(); got != "oos:n2 delete:n2" {
				t.Fatalf("events %q", got)
			}
		})
	}
}

// TestRevokeMissingNodeNeverTainted (second security review): a Node that
// isn't there (nodeadm deletes it only at node_deleted, after this step)
// is never proven cut off and never tainted: the revoke goes on without a
// taint or a force-detach.
func TestRevokeMissingNodeNeverTainted(t *testing.T) {
	h := revokeHarness(t, 50*time.Millisecond, time.Second)
	ctx := context.Background()
	if why := h.s.cutOffReasons(ctx, &revokeOp{Node: "gone", Mesh: "10.215.0.9", Started: vecNow}); !strings.Contains(strings.Join(why, "; "), "its Node is missing (not deleted by this revoke: not proven)") {
		t.Fatalf("a missing Node: reasons %v", why)
	}
	ev := watchOutOfService(t, h, false)
	h.kube.CoreV1().Nodes().Delete(ctx, "n2", metav1.DeleteOptions{})
	ev.mu.Lock()
	ev.got = nil
	ev.mu.Unlock()
	h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil)
	if strings.Contains(ev.list(), "oos:") {
		t.Fatalf("events %q: a missing Node was tainted", ev.list())
	}
}

// TestHealthAnswerVectorsCutOff: the shared health answers
// (testdata/nodeagent_call_vectors.json health_answers, byte copy in the
// Hub's nodeagent) decode strictly into AgentHealth and judge as the
// nodeagent means them: a device without the revoked node confirms; its
// key still a device peer (out of the plan, a handshake after the revoke)
// and an unreadable device (null) don't.
func TestHealthAnswerVectorsCutOff(t *testing.T) {
	b, err := os.ReadFile("testdata/nodeagent_call_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Answers []struct {
			Name   string          `json:"name"`
			Answer json.RawMessage `json:"answer"`
		} `json:"health_answers"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Answers) != 3 {
		t.Fatalf("health_answers: %v", err)
	}
	want := []string{"", "n1's WireGuard device still has a peer for 10.215.0.2", "n1 reported no mesh state"}
	for i, a := range f.Answers {
		t.Run(a.Name, func(t *testing.T) {
			var ah AgentHealth
			if err := strictJSON(a.Answer, &ah); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			h := revokeHarness(t, 0, time.Second)
			h.putState(t, func(st *nodeadmState) {
				st.Nodes["n1"].Mesh.Pub = "c1wVmg+oSgt7CNxscBVVhrNfF8ov37hpOdtk57TYzxI="
				st.Nodes["n2"].Mesh.Pub = "47iJcR3LLHiqWFVZTK1jQtJAZoLg2WT5srm2F2V3Nsw="
				st.Nodes["n3"].Mesh.Pub = "0JgPr0SArMeTmpPu3/PtK5VHQor0553KrI79Wqr1XoE="
			})
			h.agents.mu.Lock()
			h.agents.peers = map[string]string{"n1": string(ah.Peers)}
			h.agents.devPeers = map[string]string{"n1": string(ah.DevicePeers)}
			// n3's own key is the one n1's device has (the first answer).
			h.agents.pubs = map[string]string{"n1": ah.MeshPub, "n3": "0JgPr0SArMeTmpPu3/PtK5VHQor0553KrI79Wqr1XoE="}
			h.agents.mu.Unlock()
			why := strings.Join(h.s.cutOffReasons(context.Background(), &revokeOp{Node: "n2", Mesh: "10.215.0.2", Started: vecNow}), "; ")
			if want[i] == "" {
				if strings.Contains(why, "n1") {
					t.Fatalf("a confirming answer counted against: %s", why)
				}
			} else if !strings.Contains(why, want[i]) {
				t.Fatalf("reasons %q, want %q", why, want[i])
			}
			if i == 1 && (!strings.Contains(why, "n1 saw a handshake at 2026-11-28T09:59:58Z from key 47iJcR3LLHiqWFVZTK1jQtJAZoLg2WT5srm2F2V3Nsw=") ||
				!strings.Contains(why, "n1's WireGuard device still holds the revoked node's enrolled key 47iJcR3LLHiqWFVZTK1jQtJAZoLg2WT5srm2F2V3Nsw=")) {
				t.Fatalf("the revoked key's handshake after the start isn't named: %s", why)
			}
		})
	}
}

// TestHandshakeBoundary: only a handshake strictly before the start's
// second minus handshakeSkew counts as before the revoke.
func TestHandshakeBoundary(t *testing.T) {
	h := revokeHarness(t, 0, time.Second)
	start := vecNow.Add(700 * time.Millisecond) // sub-second precision
	for _, c := range []struct {
		at   time.Time
		seen bool
	}{
		{vecNow.Add(-handshakeSkew - time.Second), false},
		{vecNow.Add(-handshakeSkew), true},
		{vecNow, true},
		{start, true},
	} {
		h.agents.mu.Lock()
		h.agents.devPeers = map[string]string{"n1": `{"key-x":{"latest_handshake":"` + c.at.UTC().Format(time.RFC3339) + `","endpoint":null,"allowed_ips":[]}}`}
		h.agents.mu.Unlock()
		why := strings.Join(h.s.cutOffReasons(context.Background(), &revokeOp{Node: "n2", Mesh: "10.215.0.2", Started: start}), "; ")
		if got := strings.Contains(why, "from key key-x"); got != c.seen {
			t.Errorf("a handshake at %s, the start %s: seen %v, want %v (%s)", c.at.Format(time.RFC3339), start.Format(time.RFC3339Nano), got, c.seen, why)
		}
	}
}

// TestFirstNodeEnrolledKey: the first node (never enrolled by nodeadm,
// no record) is trusted by the key the CLI recorded in
// portcullis-first-node, never by the key it reports.
func TestFirstNodeEnrolledKey(t *testing.T) {
	h := revokeHarness(t, 0, time.Second)
	ctx := context.Background()
	h.putState(t, func(st *nodeadmState) { delete(st.Nodes, "n1") })
	op := &revokeOp{Node: "n2", Mesh: "10.215.0.2", Started: vecNow}
	if why := strings.Join(h.s.cutOffReasons(ctx, op), "; "); !strings.Contains(why, "n1 has no enrolled mesh key (not proven)") {
		t.Fatalf("no record, no ConfigMap: %s", why)
	}
	doc := `{"v":1,"id":"n1","mesh_pub":"key-n1","serials":[]}`
	h.kube.CoreV1().ConfigMaps(coreNS).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: firstNodeCM, Namespace: coreNS},
		Data: map[string]string{firstNodeKey: doc}}, metav1.CreateOptions{})
	if why := strings.Join(h.s.cutOffReasons(ctx, op), "; "); strings.Contains(why, "n1") {
		t.Fatalf("the CLI's recorded key for n1 isn't trusted: %s", why)
	}
	h.agents.mu.Lock()
	h.agents.pubs = map[string]string{"n1": "key-other"}
	h.agents.mu.Unlock()
	if why := strings.Join(h.s.cutOffReasons(ctx, op), "; "); !strings.Contains(why, "n1 reports a mesh key that isn't its enrolled one") {
		t.Fatalf("a first node reporting another key: %s", why)
	}
}
