package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Task 30 fix round 1: the first node's certificates (review I2) and the
// removed names (portcullis-removed-nodes).

func putFirstNode(t *testing.T, h *harness, doc string) {
	t.Helper()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: firstNodeCM, Namespace: coreNS}, Data: map[string]string{firstNodeKey: doc}}
	if _, err := h.kube.CoreV1().ConfigMaps(coreNS).Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// askCode: POST /v1/codes for id, as issue() sends it.
func askCode(h *harness, id, mesh string) (int, string) {
	pub := "198.51.100.1:51830"
	req := CodeReq{ServerID: id, Role: "agent", Class: "home", Site: "main", MeshIP: mesh, Ingress: true,
		Mesh: MeshPlan{Peers: []MeshPeer{{ID: "n1", Pub: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Endpoint: &pub,
			AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25}}}}
	w := h.internal(clientHub, "POST", "/v1/codes", req)
	return w.Code, w.Body.String()
}

func docOf(t *testing.T, h *harness) *AddressesDoc {
	t.Helper()
	cl, err := h.s.clusterNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	doc, errs := h.s.buildAddresses(cl, h.state(t))
	if doc == nil {
		t.Fatalf("no document: %v", errs)
	}
	return doc
}

// TestFirstNodeRevokeRevokesItsSerials (review I2): nodeadm holds no
// record of init's node, so its revoke found no serial and its 30-day
// node-cluster certificate stayed valid. The CLI records every serial it
// had Vault sign in portcullis-first-node; the revoke revokes each one not
// yet expired, and lists the name removed for good: a new code for it is
// refused.
func TestFirstNodeRevokeRevokesItsSerials(t *testing.T) {
	agent := nodeSpec{"n4", "agent", "home", "main", "10.215.0.4", []string{"192.0.2.14"}, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
	h.agents.onRotate = h.bootFollows
	putFirstNode(t, h, `{"v":1,"id":"n1","serials":[{"serial":"AA:01","not_after":"`+vecNow.Add(20*24*time.Hour).Format(time.RFC3339)+`"},`+
		`{"serial":"aa:02","not_after":"`+vecNow.Add(-time.Hour).Format(time.RFC3339)+`"}]}`)
	if st := h.state(t); st.Nodes["n1"] != nil {
		t.Fatal("the harness has a record of n1")
	}
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n1?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n1: %d %s", w.Code, w.Body)
	}
	if !slices.Equal(h.enroll.revoked, []string{"aa:01"}) {
		t.Fatalf("revoked %v, want the unexpired adopted serial aa:01 only", h.enroll.revoked)
	}
	if p := pending(h.state(t)); len(p) != 0 {
		t.Fatalf("still pending %v", p)
	}
	if rn := h.state(t).RemovedNames["n1"]; rn == nil || !rn.Revoked {
		t.Fatalf("n1 not listed revoked: %+v", rn)
	}
	if d := docOf(t, h); !slices.Equal(d.RemovedNames, []string{"n1"}) {
		t.Fatalf("removed_names %v", d.RemovedNames)
	}
	h.putState(t, func(st *nodeadmState) { delete(st.Nodes, "n1") })
	if code, body := askCode(h, "n1", "10.215.0.9"); code != 409 || !strings.Contains(body, "node n1 was revoked") {
		t.Fatalf("a code for a revoked name: %d %s", code, body)
	}
	// Another node's removal never touches the first node's serials.
	h2 := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
	putFirstNode(t, h2, `{"v":1,"id":"n1","serials":[{"serial":"aa:01","not_after":"`+vecNow.Add(20*24*time.Hour).Format(time.RFC3339)+`"}]}`)
	if err := h2.s.forget(context.Background(), "n4", &NodeAddresses{Mesh: "10.215.0.4", LAN: []string{}, Public: []string{}}, false); err != nil {
		t.Fatal(err)
	}
	if len(h2.enroll.revoked) != 0 {
		t.Fatalf("n4's removal revoked %v", h2.enroll.revoked)
	}
}

// TestFirstNodeRecordUnreadableStops: a malformed portcullis-first-node
// stops the removal before anything is marked (fail closed), every time.
func TestFirstNodeRecordUnreadableStops(t *testing.T) {
	for _, doc := range []string{`not json`, `{"v":1,"id":"n1","serials":[{"serial":"zz","not_after":"2999-01-01T00:00:00Z"}]}`,
		`{"v":2,"id":"n1","serials":[]}`, `{"v":1,"id":"n1","serials":[],"extra":1}`} {
		h := newHarness(t)
		putFirstNode(t, h, doc)
		if err := h.s.forget(context.Background(), "n1", &NodeAddresses{Mesh: "10.215.0.1", LAN: []string{}, Public: []string{}}, true); err == nil {
			t.Errorf("%s: forget went on", doc)
		}
		if st := h.state(t); st.Nodes["n1"] != nil || len(st.RemovedNames) != 0 || len(h.enroll.revoked) != 0 {
			t.Errorf("%s: marked anyway: %+v %v", doc, st.Nodes["n1"], st.RemovedNames)
		}
	}
}

// TestRemovedNameCooperative: a cooperatively removed name is listed
// removed (its kubelet can't register again) until a new node actually
// enrols under it (security review: never at code issue — the old kubelet
// stays refused while a code is unused, and after it expires); an unknown
// id leaves no name.
func TestRemovedNameCooperative(t *testing.T) {
	h := newHarness(t)
	j := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	h.enrol(t, j, "")
	if err := h.s.forget(context.Background(), "n4", &NodeAddresses{Mesh: "10.215.0.4", LAN: []string{}, Public: []string{}}, false); err != nil {
		t.Fatal(err)
	}
	if rn := h.state(t).RemovedNames["n4"]; rn == nil || rn.Revoked {
		t.Fatalf("n4 %+v", rn)
	}
	if d := docOf(t, h); !slices.Equal(d.RemovedNames, []string{"n4"}) {
		t.Fatalf("removed_names %v", d.RemovedNames)
	}
	// Still being removed while its record lasts; then a new code drops
	// the name.
	if code, body := askCode(h, "n4", "10.215.0.4"); code != 409 || !strings.Contains(body, "still being removed") {
		t.Fatalf("a code while removed: %d %s", code, body)
	}
	h.putState(t, func(st *nodeadmState) { delete(st.Nodes, "n4") })
	j2 := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	if d := docOf(t, h); !slices.Equal(d.RemovedNames, []string{"n4"}) {
		t.Fatalf("a code issued unlisted n4 (its old kubelet could register): %v", d.RemovedNames)
	}
	// The code expires unused: still listed.
	h.setNow(vecNow.Add(codeTTL + time.Minute))
	if err := h.s.sweepCodes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := docOf(t, h); !slices.Equal(d.RemovedNames, []string{"n4"}) {
		t.Fatalf("an expired code unlisted n4: %v", d.RemovedNames)
	}
	// A new code whose enrolment fails at the signing (security review):
	// still listed, so the old kubelet's registration stays refused.
	h.setNow(vecNow)
	_ = j2
	jf := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	h.enroll.mu.Lock()
	h.enroll.fail = errors.New("vault sealed")
	h.enroll.mu.Unlock()
	if w := h.enrol(t, jf, ""); w.Code/100 == 2 {
		t.Fatalf("an enrolment with the signing failing passed: %d", w.Code)
	}
	h.enroll.mu.Lock()
	h.enroll.fail = nil
	h.enroll.mu.Unlock()
	if d := docOf(t, h); !slices.Equal(d.RemovedNames, []string{"n4"}) {
		t.Fatalf("a failed signing unlisted n4: %v", d.RemovedNames)
	}
	// A new code, and the new node enrols with it: unlisted.
	j3 := h.issue(t, "n4", "agent", "home", "main", "10.215.0.4")
	if d := docOf(t, h); !slices.Equal(d.RemovedNames, []string{"n4"}) {
		t.Fatalf("before the enrolment: %v", d.RemovedNames)
	}
	if w := h.enrol(t, j3, ""); w.Code != 200 {
		t.Fatalf("the enrolment: %d %s", w.Code, w.Body)
	}
	if _, ok := h.state(t).RemovedNames["n4"]; ok {
		t.Fatal("the new node enrolled and n4 is still listed removed")
	}
	if d := docOf(t, h); len(d.RemovedNames) != 0 {
		t.Fatalf("removed_names %v", d.RemovedNames)
	}
	if err := h.s.forget(context.Background(), "n9", nil, false); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.state(t).RemovedNames["n9"]; ok {
		t.Fatal("an unknown id was listed removed")
	}
}

// TestCooperativeServerRemovalResumes (review M1): a server's removal that
// stops after its Node delete (the etcd step failed) resumes at the etcd
// step on the next try — never "enrolment voided" — and its record isn't
// dropped until the member is confirmed gone.
func TestCooperativeServerRemovalResumes(t *testing.T) {
	n4 := nodeSpec{"n4", "server", "home", "main", "10.215.0.4", []string{"192.0.2.14"}, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), n4)...)
	ctx := context.Background()
	h.agents.mu.Lock()
	h.agents.fail = map[string]error{"etcd": errors.New("nodeagent down")}
	h.agents.mu.Unlock()
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=cooperative", nil); w.Code/100 == 2 {
		t.Fatalf("the removal passed with the etcd step failing: %d", w.Code)
	}
	if _, err := h.kube.CoreV1().Nodes().Get(ctx, "n4", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("the Node wasn't deleted before the etcd step")
	}
	if r := h.state(t).Nodes["n4"]; r == nil || !r.Removed || r.EtcdPending != "10.215.0.4" {
		t.Fatalf("record %+v", r)
	}
	h.admit(t) // the active generation no longer holds n4
	h.s.dropRemoved(ctx, h.state(t))
	if h.state(t).Nodes["n4"] == nil {
		t.Fatal("the record was dropped with its etcd step pending")
	}
	h.agents.mu.Lock()
	h.agents.fail = nil
	h.agents.mu.Unlock()
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=cooperative", nil); w.Code != 204 {
		t.Fatalf("the resumed removal: %d %s", w.Code, w.Body)
	}
	if !slices.Contains(h.agents.etcdRm, "n1:n4:10.215.0.4") {
		t.Fatalf("etcd member not removed: %v", h.agents.etcdRm)
	}
	if r := h.state(t).Nodes["n4"]; r == nil || r.EtcdPending != "" {
		t.Fatalf("record after %+v", r)
	}
}

// TestUpgradeAgents (Task 30 fix round 1): each Ready node nodeadm
// enrolled takes the nodeagent it serves, once per process; a failure is
// retried; the first node (no record), a removed node and one under an op
// are never asked.
func TestUpgradeAgents(t *testing.T) {
	n4 := nodeSpec{"n4", "agent", "home", "main", "10.215.0.4", []string{"192.0.2.14"}, nil, true, false}
	n5 := nodeSpec{"n5", "agent", "home", "main", "10.215.0.5", []string{"192.0.2.15"}, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), n4, n5)...)
	ctx := context.Background()
	joined := vecNow
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n2"] = &nodeRecord{Role: "server", MeshIP: "10.215.0.2", Serial: "aa:02", JoinedAt: &joined}
		st.Nodes["n4"] = &nodeRecord{Role: "agent", MeshIP: "10.215.0.4", Serial: "aa:04", JoinedAt: &joined}
		st.Nodes["n5"] = &nodeRecord{Role: "agent", MeshIP: "10.215.0.5", Serial: "aa:05", JoinedAt: &joined, Removed: true}
		st.Ops["n3"] = &revokeOp{Node: "n3", Step: "created", StepsVersion: revokeStepsVersion}
		st.Nodes["n3"] = &nodeRecord{Role: "server", MeshIP: "10.215.0.3", Serial: "aa:03", JoinedAt: &joined}
	})
	h.agents.mu.Lock()
	h.agents.fail = map[string]error{"upgrade:n4": errors.New("unreachable")}
	h.agents.mu.Unlock()
	cl, err := h.s.clusterNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.s.upgradeAgents(ctx, cl, h.state(t))
	h.agents.mu.Lock()
	got := slices.Clone(h.agents.upgrades)
	h.agents.fail = nil
	h.agents.mu.Unlock()
	if !slices.Equal(got, []string{"n2:bbbb:cccc"}) {
		t.Fatalf("first round %v", got)
	}
	h.s.upgradeAgents(ctx, cl, h.state(t))
	h.agents.mu.Lock()
	got = slices.Clone(h.agents.upgrades)
	h.agents.mu.Unlock()
	if !slices.Equal(got, []string{"n2:bbbb:cccc", "n4:bbbb:cccc"}) {
		t.Fatalf("second round %v (n2 asked again, or n4 not retried)", got)
	}
}

// TestForwardedEndpointIsGateway (Task 30 fix round 1, the NAT model): a
// NATed node, the first at its site, reports no public endpoint; the
// forwarded one its code names makes it the site's gateway (the Hub plans
// and confirms it), so its join passes the gateway rule. A private or
// malformed one is refused when the code is asked.
func TestForwardedEndpointIsGateway(t *testing.T) {
	h := newHarness(t)
	pub := "198.51.100.1:51830"
	ask := func(id, mesh, fwd string) (int, string) {
		req := CodeReq{ServerID: id, Role: "agent", Class: "small", Site: "edge", MeshIP: mesh, PublicEndpoint: fwd,
			Mesh: MeshPlan{Peers: []MeshPeer{{ID: "n1", Pub: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Endpoint: &pub,
				AllowedIPs: []string{"10.215.0.1/32"}, Keepalive: 25}}}}
		w := h.internal(clientHub, "POST", "/v1/codes", req)
		return w.Code, w.Body.String()
	}
	for _, bad := range []string{"192.168.1.9:40000", "203.0.113.9", "[2001:db8::1]:51830", "203.0.113.9:0"} {
		if code, body := ask("e1", "10.215.0.8", bad); code != 400 || !strings.Contains(body, "public_endpoint") {
			t.Errorf("%s: %d %s", bad, code, body)
		}
	}
	if code, body := ask("e1", "10.215.0.8", "203.0.113.9:40000"); code != 201 {
		t.Fatalf("a forwarded endpoint: %d %s", code, body)
	}
	if c := h.state(t).Codes["e1"]; c == nil || c.Forward != "203.0.113.9:40000" {
		t.Fatalf("code %+v", c)
	}
	st := h.state(t)
	st.Nodes["e1"] = &nodeRecord{Site: "edge", Forward: "203.0.113.9:40000"}
	cl, _ := h.s.clusterNodes(context.Background())
	if err := siteGateway(cl, st, "e1"); err != nil {
		t.Fatalf("a forwarded node at its own site: %v", err)
	}
	st.Nodes["e1"].Forward = ""
	if err := siteGateway(cl, st, "e1"); err == nil {
		t.Fatal("a NATed node without a forwarded endpoint passed the gateway rule")
	}
}

// TestRevokeAgainIsDone (Task 30 fix round 1, found live): the Hub
// restarted (its Lease lost while the servers restarted) before it
// recorded nodeadm's answer; asked again after the revocation finished
// and the record was dropped, nodeadm answers done (its name is listed
// revoked), never unknown_node. A name never revoked is still unknown.
func TestRevokeAgainIsDone(t *testing.T) {
	agent := nodeSpec{"n4", "agent", "home", "main", "10.215.0.4", []string{"192.0.2.14"}, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
	h.agents.onRotate = h.bootFollows
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n4"] = &nodeRecord{Role: "agent", Serial: "aa:04", MeshIP: "10.215.0.4"}
	})
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	h.putState(t, func(st *nodeadmState) {
		delete(st.Nodes, "n4") // dropped once the params left it
		// Its burnt code's record (fix round 2, found live: the revoke ran
		// again from the start, restarting every server again).
		st.Codes["n4"] = &codeRecord{Used: true, Role: "agent", MeshIP: "10.215.0.4", IssuedAt: vecNow, ExpiresAt: vecNow.Add(codeTTL)}
	})
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("the revoke asked again: %d %s", w.Code, w.Body)
	}
	if n := strings.Count(h.logs.String(), "revocation recorded"); n != 1 {
		t.Fatalf("the revoke asked again started a new revocation (%d recorded)", n)
	}
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n9?mode=revoke", nil); w.Code != 404 {
		t.Fatalf("an unknown node: %d %s", w.Code, w.Body)
	}
}
