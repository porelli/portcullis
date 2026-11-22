package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// Task 30 fix round 2 (re-review R-I2): a removed name is refused on every
// API server BEFORE its Node is deleted; a push that can't be confirmed
// stops the removal there (fail closed).

// watchDeletes records, for every Node delete, whether the API servers
// already refused that name (the fake probe's in-force list).
func watchDeletes(h *harness) *[]string {
	var got []string
	h.kube.PrependReactor("delete", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := a.(k8stesting.DeleteAction).GetName()
		if h.probe.refuses(name) {
			got = append(got, name+":refused")
		} else {
			got = append(got, name+":ADMITTED")
		}
		return false, nil, nil
	})
	return &got
}

func nodeExists(t *testing.T, h *harness, id string) bool {
	t.Helper()
	_, err := h.kube.CoreV1().Nodes().Get(context.Background(), id, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return err == nil
}

// TestRevokeDeletesNodeOnlyOnceRefused: an agent's revoke and a
// cooperative removal (agent and server) delete the Node only after the
// name is in the removed-node params every API server judges by.
func TestRevokeDeletesNodeOnlyOnceRefused(t *testing.T) {
	a4 := nodeSpec{"n4", "agent", "home", "main", "10.215.0.4", []string{"192.0.2.14"}, nil, true, false}
	a5 := nodeSpec{"n5", "agent", "home", "main", "10.215.0.5", []string{"192.0.2.15"}, nil, true, false}
	s6 := nodeSpec{"n6", "server", "home", "main", "10.215.0.6", []string{"192.0.2.16"}, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), a4, a5, s6)...)
	h.agents.onRotate = h.bootFollows
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n4"] = &nodeRecord{Role: "agent", Serial: "aa:04", MeshIP: "10.215.0.4"}
		st.Nodes["n5"] = &nodeRecord{Role: "agent", Serial: "aa:05", MeshIP: "10.215.0.5"}
		st.Nodes["n6"] = &nodeRecord{Role: "server", Serial: "aa:06", MeshIP: "10.215.0.6"}
	})
	deletes := watchDeletes(h)
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n4: %d %s", w.Code, w.Body)
	}
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n5?mode=cooperative", nil); w.Code != 204 {
		t.Fatalf("remove n5: %d %s", w.Code, w.Body)
	}
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n6?mode=cooperative", nil); w.Code != 204 {
		t.Fatalf("remove n6: %d %s", w.Code, w.Body)
	}
	want := "n4:refused n5:refused n6:refused"
	if got := strings.Join(*deletes, " "); got != want {
		t.Fatalf("Node deletes %q, want %q", got, want)
	}
	cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(context.Background(), removedCM, metav1.GetOptions{})
	if cm.Data[removedKey] != "n4 n5 n6" || cm.Data["generation"] != removedData([]string{"n4", "n5", "n6"})["generation"] {
		t.Fatalf("params %v", cm.Data)
	}
}

// TestUnconfirmedPushStopsTheRemoval: while the API servers don't confirm
// the list (one doesn't answer, one still judges an older one, or the
// ConfigMap is gone), the revoke parks before node_deleted and the
// cooperative removal answers 503, each with the Node kept; once they
// confirm, the retry deletes it. The security steps (marked,
// tokens_deleted) never wait for it.
func TestUnconfirmedPushStopsTheRemoval(t *testing.T) {
	for _, why := range []string{"down", "stale", "missing"} {
		t.Run(why, func(t *testing.T) {
			a4 := nodeSpec{"n4", "agent", "home", "main", "10.215.0.4", []string{"192.0.2.14"}, nil, true, false}
			a5 := nodeSpec{"n5", "agent", "home", "main", "10.215.0.5", []string{"192.0.2.15"}, nil, true, false}
			h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), a4, a5)...)
			h.agents.onRotate = h.bootFollows
			h.putState(t, func(st *nodeadmState) {
				st.Nodes["n4"] = &nodeRecord{Role: "agent", Serial: "aa:04", MeshIP: "10.215.0.4", TokenIDs: []string{"abc123"}}
				st.Nodes["n5"] = &nodeRecord{Role: "agent", Serial: "aa:05", MeshIP: "10.215.0.5"}
			})
			ctx := context.Background()
			var saved *corev1.ConfigMap
			switch why {
			case "down":
				h.probe.down = true
			case "stale":
				h.probe.stale = true
			case "missing":
				saved, _ = h.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, removedCM, metav1.GetOptions{})
				h.kube.CoreV1().ConfigMaps(coreNS).Delete(ctx, removedCM, metav1.DeleteOptions{})
			}
			w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil)
			if w.Code/100 == 2 {
				t.Fatalf("revoke n4 unconfirmed: %d %s", w.Code, w.Body)
			}
			op := h.state(t).Ops["n4"]
			if op == nil || !strings.Contains(op.LastError, "n4's Node isn't deleted") {
				t.Fatalf("op %+v: want the unconfirmed push as its error", op)
			}
			if op == nil || stepIndex(op.Step) >= stepIndex("node_deleted") || stepIndex(op.Step) < stepIndex("applied") {
				t.Fatalf("op %+v: want it parked after applied, before node_deleted", op)
			}
			if !nodeExists(t, h, "n4") {
				t.Fatal("n4's Node was deleted before its name was confirmed refused")
			}
			if w := h.internal(clientHub, "DELETE", "/v1/nodes/n5?mode=cooperative", nil); w.Code != 503 || !strings.Contains(w.Body.String(), "n5's Node isn't deleted") {
				t.Fatalf("remove n5 unconfirmed: %d %s", w.Code, w.Body)
			}
			if !nodeExists(t, h, "n5") {
				t.Fatal("n5's Node was deleted before its name was confirmed refused")
			}
			if r := h.state(t).Nodes["n5"]; r == nil || !r.Removed {
				t.Fatalf("n5 not marked removed (its certificate revoked) before the push: %+v", r)
			}
			// Confirmed: the retries finish.
			h.probe.mu.Lock()
			h.probe.down, h.probe.stale = false, false
			h.probe.mu.Unlock()
			if saved != nil {
				saved.ResourceVersion = ""
				h.kube.CoreV1().ConfigMaps(coreNS).Create(ctx, saved, metav1.CreateOptions{})
			}
			deletes := watchDeletes(h)
			if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
				t.Fatalf("revoke n4 retried: %d %s", w.Code, w.Body)
			}
			if w := h.internal(clientHub, "DELETE", "/v1/nodes/n5?mode=cooperative", nil); w.Code != 204 {
				t.Fatalf("remove n5 retried: %d %s", w.Code, w.Body)
			}
			if got := strings.Join(*deletes, " "); got != "n4:refused n5:refused" {
				t.Fatalf("Node deletes %q", got)
			}
		})
	}
}

// TestPushRemovedSerialised: the list written is always the state's at the
// time of the write (never an older one over a newer one), and a
// confirmed generation isn't probed again until the ConfigMap changes.
func TestPushRemovedSerialised(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.putState(t, func(st *nodeadmState) { st.RemovedNames = map[string]*removedName{"a1": {At: vecNow}} })
	if names, err := h.s.pushRemoved(ctx, 0); err != nil || strings.Join(names, " ") != "a1" {
		t.Fatalf("%v %v", names, err)
	}
	calls := h.probe.calls
	if _, err := h.s.pushRemoved(ctx, 0); err != nil || h.probe.calls != calls {
		t.Fatalf("a confirmed generation probed again (%d → %d): %v", calls, h.probe.calls, err)
	}
	// A hand edit of the ConfigMap is put back and confirmed again.
	cm, _ := h.kube.CoreV1().ConfigMaps(coreNS).Get(ctx, removedCM, metav1.GetOptions{})
	cm.Data = map[string]string{"generation": "0000000000000000"}
	cm.ResourceVersion = "edited"
	h.kube.CoreV1().ConfigMaps(coreNS).Update(ctx, cm, metav1.UpdateOptions{})
	if names, err := h.s.pushRemoved(ctx, 0); err != nil || strings.Join(names, " ") != "a1" || h.probe.calls == calls {
		t.Fatalf("after a hand edit: %v %v", names, err)
	}
	if !h.probe.refuses("a1") {
		t.Fatal("a1 not in force")
	}
	// The mark itself pushes (its CSRs refused long before its Node goes);
	// a push it can't confirm doesn't stop the mark.
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["a2"] = &nodeRecord{Role: "agent", Serial: "aa:a2", MeshIP: "10.215.0.12"}
	})
	if err := h.s.forget(ctx, "a2", nil, true); err != nil || !h.probe.refuses("a2") {
		t.Fatalf("forget a2 didn't put it in force: %v", err)
	}
	h.probe.down = true
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["a3"] = &nodeRecord{Role: "agent", Serial: "aa:a3", MeshIP: "10.215.0.13"}
	})
	if err := h.s.forget(ctx, "a3", nil, true); err != nil || h.state(t).RemovedNames["a3"] == nil {
		t.Fatalf("an unconfirmed push stopped the mark: %v", err)
	}
}

// TestReservedProbeID (nit 2): no code for an id under
// portcullis-admission-: the probes' node identity.
func TestReservedProbeID(t *testing.T) {
	h := newHarness(t)
	for _, id := range []string{"portcullis-admission-probe", "portcullis-admission-x"} {
		if code, body := askCode(h, id, "10.215.0.9"); code != 400 || !strings.Contains(body, "reserved") {
			t.Errorf("%s: %d %s", id, code, body)
		}
	}
	if code, body := askCode(h, "portcullis-a", "10.215.0.9"); code != 201 {
		t.Errorf("portcullis-a: %d %s", code, body)
	}
}

// TestForwardedEndpointUnique (nit 1): a forwarded endpoint another node
// (or a live code) already has is refused, naming it.
func TestForwardedEndpointUnique(t *testing.T) {
	h := newHarness(t)
	pub := "198.51.100.1:51830"
	ask := func(id, mesh, fwd string) (int, string) {
		req := CodeReq{ServerID: id, Role: "agent", Class: "small", Site: "edge", MeshIP: mesh, PublicEndpoint: fwd,
			Mesh: MeshPlan{Peers: []MeshPeer{{ID: "n1", Pub: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Endpoint: &pub,
				AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25}}}}
		w := h.internal(clientHub, "POST", "/v1/codes", req)
		return w.Code, w.Body.String()
	}
	if code, body := ask("e1", "10.215.0.8", "203.0.113.9:40000"); code != 201 {
		t.Fatalf("e1: %d %s", code, body)
	}
	if code, body := ask("e2", "10.215.0.9", "203.0.113.9:40000"); code != 409 || !strings.Contains(body, "already node e1's") {
		t.Fatalf("e2 with e1's code endpoint: %d %s", code, body)
	}
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["e3"] = &nodeRecord{Site: "edge", MeshIP: "10.215.0.10", Mesh: MeshReport{Public: &[]string{"203.0.113.10:51830"}[0]}}
	})
	if code, body := ask("e4", "10.215.0.11", "203.0.113.10:51830"); code != 409 || !strings.Contains(body, "already node e3's") {
		t.Fatalf("e4 with e3's reported endpoint: %d %s", code, body)
	}
	// A new code for e1 itself keeps its own endpoint.
	if code, body := ask("e1", "10.215.0.8", "203.0.113.9:40000"); code != 201 {
		t.Fatalf("e1 again: %d %s", code, body)
	}
}

// TestRejoinWaitsForUnlisted: a cooperatively removed name re-used by a new
// node: its join material waits (waiting_admission) until the list without
// it is in force on every API server.
func TestRejoinWaitsForUnlisted(t *testing.T) {
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	h.enrol(t, j, "")
	if err := h.s.forget(context.Background(), "n4", &NodeAddresses{Mesh: "10.215.0.4", LAN: []string{}, Public: []string{}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.pushRemoved(context.Background(), 0); err != nil || !h.probe.refuses("n4") {
		t.Fatalf("n4 not refused: %v", err)
	}
	h.putState(t, func(st *nodeadmState) { delete(st.Nodes, "n4") })
	j2 := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	if w := h.enrol(t, j2, ""); w.Code != 200 {
		t.Fatalf("enrol: %d %s", w.Code, w.Body)
	}
	h.probe.mu.Lock()
	h.probe.stale = true
	h.probe.mu.Unlock()
	if w := h.join(t, j2, nearRTT); w.Code != 409 || !strings.Contains(w.Body.String(), "waiting_admission") {
		t.Fatalf("join while n4 is still refused: %d %s", w.Code, w.Body)
	}
	h.probe.mu.Lock()
	h.probe.stale = false
	h.probe.mu.Unlock()
	if w := h.join(t, j2, nearRTT); w.Code != 200 {
		t.Fatalf("join once unlisted: %d %s", w.Code, w.Body)
	}
	if h.probe.refuses("n4") {
		t.Fatal("n4 still refused after its release")
	}
}

// TestProbeAnswer: only the binding's own refusal naming the generation
// confirms it; an admission, another binding's or another generation's
// refusal doesn't.
func TestProbeAnswer(t *testing.T) {
	g := "0123456789abcdef"
	ok := errors.New(`nodes "portcullis-admission-probe" is forbidden: ValidatingAdmissionPolicy 'portcullis-removed-nodes' with binding 'portcullis-nodes-guard-removed' denied request: admission probe: params generation 0123456789abcdef in effect`)
	if err := probeAnswer("10.215.0.1:6443", g, ok); err != nil {
		t.Fatal(err)
	}
	for _, e := range []error{nil,
		errors.New(strings.Replace(ok.Error(), g, "fedcba9876543210", 1)),
		errors.New(strings.Replace(ok.Error(), "portcullis-nodes-guard-removed", "portcullis-nodes-guard-labels-x", 1)),
		errors.New("dial tcp 10.215.0.1:6443: connection refused")} {
		if err := probeAnswer("10.215.0.1:6443", g, e); err == nil {
			t.Errorf("%v confirmed", e)
		}
	}
}
