package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

// bootFollows: the fake supervisor accepts what a rotate set.
func (h *harness) bootFollows(_, step, tok string) {
	h.boot.mu.Lock()
	defer h.boot.mu.Unlock()
	switch step {
	case "rotate":
		h.boot.current = tok
	case "rotate-agent":
		h.boot.agent = tok
	}
}

func (h *harness) failAgent(step string, effect bool) {
	h.agents.mu.Lock()
	defer h.agents.mu.Unlock()
	if h.agents.fail == nil {
		h.agents.fail, h.agents.effect = map[string]error{}, map[string]bool{}
	}
	h.agents.fail[step] = errors.New("nodeagent 500")
	h.agents.effect[step] = effect
}

func (h *harness) healAgents() {
	h.agents.mu.Lock()
	defer h.agents.mu.Unlock()
	h.agents.fail, h.agents.effect = nil, nil
}

// resume: what the Lease holder's loop does after a restart.
func (h *harness) resume(t *testing.T, id string) {
	t.Helper()
	h.s.resumeOps(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := h.state(t)
		if st.Ops[id] == nil {
			return
		}
		if st.Ops[id].LastError != "" {
			h.s.runMu.Lock()
			_, running := h.s.running[id]
			h.s.runMu.Unlock()
			if !running {
				t.Fatalf("the resumed op stopped at %s: %s", st.Ops[id].Step, st.Ops[id].LastError)
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the resumed op didn't finish")
}

func (h *harness) secretTokens(t *testing.T) (srv, agt string) {
	sec, err := h.kube.CoreV1().Secrets(coreNS).Get(context.Background(), tokenSecret, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(sec.Data[tokenKey])), string(sec.Data[agentTokenKey])
}

// TestRevokeResumesAtEachStep (review C1): a revoke failing at each step
// leaves a recorded op whose persisted tokens are never lost; resumed, it
// finishes, and the Secret ends with the tokens the supervisor accepts.
func TestRevokeResumesAtEachStep(t *testing.T) {
	agent := nodeSpec{"n4", "agent", "cloud", "edge", "10.215.0.4", nil, nil, true, false}
	for _, c := range []struct {
		name, step string
		effect     bool
		stopsAt    string
	}{
		{"etcd removal fails", "etcd", false, "published"},
		{"rotate fails", "rotate", false, "etcd_removed"},
		{"rotate took effect, its answer lost", "rotate", true, "etcd_removed"},
		{"rotate ok, rotate-agent fails", "rotate-agent", false, "server_rotated"},
		{"rotate-agent took effect, its answer lost", "rotate-agent", true, "server_rotated"},
		{"an apply fails", "apply", false, "agent_rotated"},
		{"an apply-agent fails", "apply-agent", false, "agent_rotated"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
			h.putState(t, func(st *nodeadmState) {
				st.Nodes["n2"] = &nodeRecord{Role: "server", Serial: "12:34", MeshIP: "10.215.0.2"}
			})
			h.agents.onRotate = h.bootFollows
			h.failAgent(c.step, c.effect)
			w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil)
			if w.Code != 500 {
				t.Fatalf("revoke with %s failing: %d %s", c.step, w.Code, w.Body)
			}
			st := h.state(t)
			op := st.Ops["n2"]
			if op == nil || op.Step != c.stopsAt || op.LastError == "" {
				t.Fatalf("op %+v, want stopped at %s", op, c.stopsAt)
			}
			// Marked first (I1): the node can't join from here on.
			if r := st.Nodes["n2"]; r == nil || !r.Removed || r.Serial != "" {
				t.Fatalf("n2 isn't marked removed: %+v", r)
			}
			// A token the supervisor accepts is always persisted somewhere.
			srv, agt := h.secretTokens(t)
			h.boot.mu.Lock()
			cur, curAgent := h.boot.current, h.boot.agent
			h.boot.mu.Unlock()
			if cur != "" && cur != srv && cur != op.NewServer {
				t.Fatal("the server token the supervisor accepts is lost")
			}
			if curAgent != "" && curAgent != agt && curAgent != op.NewAgent {
				t.Fatal("the agent token the supervisor accepts is lost")
			}
			// No secret in the error, the answer or the log.
			for _, sec := range []string{testServerToken, testAgentToken, op.NewServer, op.NewAgent, cur, curAgent} {
				if sec == "" {
					continue
				}
				if strings.Contains(op.LastError, sec) || strings.Contains(w.Body.String(), sec) || strings.Contains(h.logs.String(), sec) {
					t.Fatal("a token leaked into an error, the answer or the log")
				}
			}
			h.healAgents()
			h.resume(t, "n2")
			srv, agt = h.secretTokens(t)
			h.boot.mu.Lock()
			cur, curAgent = h.boot.current, h.boot.agent
			h.boot.mu.Unlock()
			if srv == testServerToken || srv != cur || agt == testAgentToken || agt != curAgent {
				t.Fatal("after the resume the Secret doesn't hold the tokens in effect")
			}
			if !slices.Equal(h.agents.etcdRm, []string{"n1:n2:10.215.0.2"}) {
				t.Fatalf("etcd removals %v", h.agents.etcdRm)
			}
			// Every survivor applied once, with the final tokens.
			applied := map[string]int{}
			for i, r := range h.agents.rotations {
				if strings.HasPrefix(r, "apply") {
					applied[r]++
					want := srv
					if strings.HasPrefix(r, "apply-agent") || strings.HasSuffix(r, ":n4") {
						want = agt
					}
					if h.agents.tokens[i] != want {
						t.Fatalf("%s carried a stale token", r)
					}
				}
			}
			for _, r := range []string{"apply:n1", "apply-agent:n1", "apply:n3", "apply-agent:n3", "apply:n4"} {
				if applied[r] == 0 {
					t.Fatalf("%s never ran: %v", r, h.agents.rotations)
				}
			}
			if r := h.state(t).Nodes["n2"]; r == nil || !r.Removed {
				t.Fatal("the record isn't removed")
			}
		})
	}
}

// TestRevokeDetachedFromRequest (C1): the Hub's connection closing doesn't
// stop a revoke: it answers 503 and the op finishes in the background.
func TestRevokeDetachedFromRequest(t *testing.T) {
	h := newHarness(t)
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n3"] = &nodeRecord{Role: "server", Serial: "56:78", MeshIP: "10.215.0.3"}
	})
	release := make(chan struct{})
	h.agents.onRotate = func(id, step, tok string) {
		if step == "rotate" {
			<-release
		}
		h.bootFollows(id, step, tok)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- h.s.revoke(ctx, "n3") }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	err := <-errc
	var ae *apiError
	if !errors.As(err, &ae) || ae.Status != 503 {
		t.Fatalf("a cancelled request: %v", err)
	}
	close(release)
	h.resume(t, "n3")
	if srv, _ := h.secretTokens(t); srv == testServerToken {
		t.Fatal("the detached revoke didn't rotate")
	}
}

// TestRevokeStopsOnLeaseLoss (M13): losing the Lease cancels the op's
// context; the next holder resumes it.
func TestRevokeStopsOnLeaseLoss(t *testing.T) {
	h := newHarness(t)
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n3"] = &nodeRecord{Role: "server", Serial: "56:78", MeshIP: "10.215.0.3"}
	})
	h.agents.onRotate = func(id, step, tok string) {
		if step == "rotate" && h.leader.on.Load() {
			h.leader.on.Store(false)
			time.Sleep(400 * time.Millisecond) // the fence notices
		}
		h.bootFollows(id, step, tok)
	}
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n3?mode=revoke", nil); w.Code < 500 {
		t.Fatalf("a revoke losing the Lease: %d", w.Code)
	}
	if op := h.state(t).Ops["n3"]; op == nil || op.NewServer == "" {
		t.Fatalf("the op or its new token isn't recorded: %+v", op)
	}
	h.leader.on.Store(true)
	h.resume(t, "n3")
	srv, _ := h.secretTokens(t)
	h.boot.mu.Lock()
	cur := h.boot.current
	h.boot.mu.Unlock()
	if srv != cur {
		t.Fatal("the next holder didn't promote the token in effect")
	}
}

// TestJoinRacingRevokeRefused (I1): once a revoke started, the node's
// signed join is refused (403), however far the revoke got.
func TestJoinRacingRevokeRefused(t *testing.T) {
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	if w := h.enrol(t, j, ""); w.Code != 200 {
		t.Fatalf("enrol: %d %s", w.Code, w.Body)
	}
	h.failAgent("etcd", false) // n4 is an agent: the op runs to the rotation
	h.failAgent("rotate", false)
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 500 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w := h.join(t, j, nearRTT); w.Code != 403 {
		t.Fatalf("a join during a revoke: %d %s", w.Code, w.Body)
	}
	l, _ := h.kube.CoreV1().Secrets(bootstrapNS).List(context.Background(), metav1.ListOptions{})
	if len(l.Items) != 0 {
		t.Fatal("a revoked node got a bootstrap token")
	}
}

// TestJoinMaterialOnce (I2): released, the material is refused once the
// Node registered, after the window and past the token cap.
func TestJoinMaterialOnce(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	if w := h.enrol(t, j, ""); w.Code != 200 {
		t.Fatalf("enrol: %d", w.Code)
	}
	if w := h.join(t, j, nearRTT); w.Code != 200 {
		t.Fatalf("join: %d %s", w.Code, w.Body)
	}
	// A lost answer: a retry within the window, before the Node exists.
	if w := h.join(t, j, nearRTT); w.Code != 200 {
		t.Fatalf("a retried join: %d %s", w.Code, w.Body)
	}
	if w := h.join(t, j, nearRTT); w.Code != 200 {
		t.Fatalf("a third join: %d %s", w.Code, w.Body)
	}
	if w := h.join(t, j, nearRTT); w.Code != 409 {
		t.Fatalf("past the token cap: %d %s", w.Code, w.Body)
	}
	if n := len(h.state(t).Nodes["n4"].TokenIDs); n != maxJoinTokens {
		t.Fatalf("%d token ids recorded", n)
	}
	// The Node registered: refused.
	h2 := newHarness(t)
	j2 := h2.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	h2.enrol(t, j2, "")
	if w := h2.join(t, j2, nearRTT); w.Code != 200 {
		t.Fatalf("join: %d", w.Code)
	}
	h2.kube.CoreV1().Nodes().Create(ctx, mkNode(nodeSpec{"n4", "agent", "home", "main", "10.215.0.4", nil, nil, true, false}), metav1.CreateOptions{})
	if w := h2.join(t, j2, nearRTT); w.Code != 409 {
		t.Fatalf("after the Node registered: %d", w.Code)
	}
	// After the window: refused.
	h3 := newHarness(t)
	j3 := h3.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	h3.enrol(t, j3, "")
	if w := h3.join(t, j3, nearRTT); w.Code != 200 {
		t.Fatalf("join: %d", w.Code)
	}
	h3.setNow(h3.s.now().Add(rejoinWindow + time.Minute))
	if w := h3.join(t, j3, nearRTT); w.Code != 409 && w.Code != 403 {
		t.Fatalf("after the window: %d", w.Code)
	}
}

// TestPublicRateLimit (I5): past a source's burst the public writes answer
// 429 before any work; another source still passes; the global bucket
// caps them all.
func TestPublicRateLimit(t *testing.T) {
	h := newHarness(t)
	h.s.limit = newLimiter(0.001, 3, 0.001, 5)
	send := func(xff string) int {
		return h.do(h.s.PublicHandler(), "none", "POST", "/node/v1/nonce", []byte(`{"server_id":"n9"}`),
			map[string]string{"X-Forwarded-For": xff}).Code
	}
	for i := 0; i < 3; i++ {
		if c := send("203.0.113.7"); c == 429 {
			t.Fatalf("request %d limited", i)
		}
	}
	if c := send("203.0.113.7"); c != 429 {
		t.Fatalf("past the burst: %d", c)
	}
	// The rightmost X-Forwarded-For entry counts (a forged left one doesn't).
	if c := send("203.0.113.7, 198.51.100.2"); c == 429 {
		t.Fatal("another source limited")
	}
	if c := send("198.51.100.3"); c == 429 {
		t.Fatal("a third source limited")
	}
	if c := send("198.51.100.4"); c != 429 {
		t.Fatalf("past the global burst: %d", c)
	}
	// GETs (join.sh, the agent binaries) aren't limited here.
	if c := h.do(h.s.PublicHandler(), "none", "GET", "/node/join.sh", nil, nil).Code; c == 429 {
		t.Fatal("join.sh limited")
	}
}

// TestLabelsPatchOptimistic (review M8): the label / taint patch carries
// the read's resourceVersion; a conflict (a lifecycle taint written in
// between) reads again and patches the fresh object.
func TestLabelsPatchOptimistic(t *testing.T) {
	h := newHarness(t)
	var versions []string
	conflicts := 1
	rv := 40
	h.kube.PrependReactor("get", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		o, err := h.kube.Tracker().Get(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}, "", a.(k8stesting.GetAction).GetName())
		if err != nil {
			return true, nil, err
		}
		n := o.(*corev1.Node).DeepCopy()
		rv++
		n.ResourceVersion = fmt.Sprint(rv)
		return true, n, nil
	})
	h.kube.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		var p struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		json.Unmarshal(a.(k8stesting.PatchAction).GetPatch(), &p)
		versions = append(versions, p.Metadata.ResourceVersion)
		if conflicts > 0 {
			conflicts--
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "nodes"}, "n1", errors.New("the object has been modified"))
		}
		return false, nil, nil
	})
	w := h.internal(clientHub, "PUT", "/v1/nodes/n1/labels", LabelsReq{Class: "home", Site: "main", Ingress: true, Storage: true})
	if w.Code/100 != 2 {
		t.Fatalf("labels: %d %s", w.Code, w.Body)
	}
	if len(versions) != 2 || versions[0] == "" || versions[1] == "" || versions[0] == versions[1] {
		t.Fatalf("patches carried resourceVersions %q (want each patch to carry one, a conflict retried once)", versions)
	}
}
