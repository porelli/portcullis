package main

// A model of what decides, in the pinned k3s (v1.37.2+k3s1), whether a
// server starts again after its tokens changed (agent-token fix). Per
// server: its disk (cred/passwd and its mtime, the --token-file, the
// --agent-token-file if any) and what its running supervisor accepts
// (passwd as loaded at start); one datastore bootstrap copy (passwd, its
// timestamp, the passphrase it is encrypted under). The k3s code each
// step stands for:
//
//   - a start: pkg/daemons/control/server.go prepare → cluster.Bootstrap
//     (pkg/cluster/bootstrap.go ReconcileBootstrapData: the bootstrap key
//     of the token file's passphrase, else "encrypted with different
//     token"; per file isNewerFile: equal → nothing, the disk's mtime ≥
//     the datastore's timestamp + systemTimeSkew (3 s) → fatal "newer than
//     datastore", else the disk rewritten from the datastore with the
//     datastore's timestamp), THEN deps.GenServerDeps → genUsers (the
//     server line from the token, the node line from --agent-token(-file)
//     or else the server passphrase; written only when changed), then
//     cluster.Save(override=false) once etcd is up: the key exists, so
//     nothing (the datastore's copy is never refreshed by a start);
//   - PUT /v1-k3s/token (pkg/server/handlers/token.go tokenRotate): passwd
//     read from disk, the server line set, the node line too when it equals
//     the old server passphrase and no agent token is configured, passwd
//     written; RotateBootstrapToken re-keys the bootstrap copy; then
//     cluster.Save(override=true) re-reads every bootstrap file from THIS
//     server's disk (their mtimes as timestamps). The running supervisor
//     keeps authenticating with what it loaded until it restarts.
//
// The nodeagent's token steps (Hub internal/nodeagent/host/k3s.go
// TokenStep) drive it: rotate = the PUT unless etcd holds the new key,
// then the token file and a restart; apply = the token file and a
// restart; the removed rotate-agent / apply-agent = the agent token file
// and a restart.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type mPasswd struct{ server, node string }

type mServer struct {
	name, mesh string
	tokenFile  string // the --token-file's K10 token
	agentFile  string // the --agent-token-file's K10 token, "" without one
	disk       mPasswd
	diskMtime  int64
	mem        mPasswd // what the running supervisor accepts
	up         bool
}

type k3sModel struct {
	mu      sync.Mutex
	clock   int64 // seconds
	ds      mPasswd
	dsTime  int64
	dsKey   string // the passphrase the bootstrap copy is encrypted under
	servers map[string]*mServer
	fatal   []string // name: reason, every failed start
}

const modelSkew = 3 // pkg/cluster/bootstrap.go systemTimeSkew

// passOf is k3s's NormalizeToken: the passphrase after K10<hash>::<user>:.
func passOf(tok string) string {
	m := k10Re.FindStringSubmatch(tok)
	if m == nil {
		return tok
	}
	if _, p, ok := strings.Cut(m[2], ":"); ok {
		return p
	}
	return m[2]
}

// newK3sModel: servers name → mesh, every one started on tok (agentTok
// non-empty: every one with --agent-token-file holding it), the first
// one's start writing the datastore's copy (cluster-init).
func newK3sModel(tok, agentTok string, servers map[string]string) *k3sModel {
	m := &k3sModel{clock: 1000, servers: map[string]*mServer{}}
	node := passOf(tok)
	if agentTok != "" {
		node = passOf(agentTok)
	}
	m.ds, m.dsTime, m.dsKey = mPasswd{server: passOf(tok), node: node}, m.clock, passOf(tok)
	for n, mesh := range servers {
		m.servers[n] = &mServer{name: n, mesh: mesh, tokenFile: tok, agentFile: agentTok, disk: m.ds, diskMtime: m.clock, mem: m.ds, up: true}
	}
	return m
}

func (m *k3sModel) tick() { m.clock += 10 }

// start is one k3s server start (the caller holds mu).
func (m *k3sModel) start(s *mServer) error {
	m.tick()
	s.up = false
	pass := passOf(s.tokenFile)
	if pass != m.dsKey {
		m.fatal = append(m.fatal, s.name+": bootstrap data already found and encrypted with different token")
		return errors.New(m.fatal[len(m.fatal)-1])
	}
	if s.disk != m.ds {
		if s.diskMtime-m.dsTime >= modelSkew {
			m.fatal = append(m.fatal, s.name+": cred/passwd newer than datastore and could cause a cluster outage")
			return errors.New(m.fatal[len(m.fatal)-1])
		}
		s.disk, s.diskMtime = m.ds, m.dsTime
	}
	want := mPasswd{server: pass, node: pass}
	if s.agentFile != "" {
		want.node = passOf(s.agentFile)
	}
	if want != s.disk {
		s.disk, s.diskMtime = want, m.clock
	}
	s.mem, s.up = s.disk, true
	return nil
}

func (m *k3sModel) restart(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.start(m.servers[name])
}

// restartAll stops every server, then starts them (etcd's quorum is not
// modelled: the order of the starts doesn't matter here).
func (m *k3sModel) restartAll() []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.servers))
	for n := range m.servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, n := range names {
		m.servers[n].up = false
	}
	for _, n := range names {
		if err := m.start(m.servers[n]); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// put is PUT /v1-k3s/token on s, authenticated with old.
func (m *k3sModel) put(s *mServer, old, newTok string) error {
	if !s.up || passOf(old) != s.mem.server {
		return errors.New("401")
	}
	m.tick()
	oldPass, newPass := s.disk.server, passOf(newTok)
	if s.disk.server != newPass {
		s.disk.server = newPass
		if s.disk.node == oldPass && s.agentFile == "" {
			s.disk.node = newPass
		}
		s.diskMtime = m.clock
	}
	m.dsKey = newPass                    // RotateBootstrapToken
	m.ds, m.dsTime = s.disk, s.diskMtime // Save(override=true): from this disk
	return nil
}

// step is the nodeagent's TokenStep on server id.
func (m *k3sModel) step(id, step, tok string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.servers[id]
	if s == nil {
		return fmt.Errorf("%s: not a modelled server", id)
	}
	switch step {
	case "rotate":
		if m.dsKey != passOf(tok) { // etcd doesn't hold the new key yet
			if err := m.put(s, s.tokenFile, tok); err != nil {
				return err
			}
		}
		s.tokenFile = tok
	case "apply":
		s.tokenFile = tok
	case "rotate-agent", "apply-agent":
		s.agentFile = tok
	default:
		return fmt.Errorf("step %s", step)
	}
	return m.start(s)
}

// The supervisor's answers (nodeadm's K3sBootstrap), from the server at
// that mesh address.
func (m *k3sModel) at(mesh string) (*mServer, error) {
	for _, s := range m.servers {
		if s.mesh == mesh {
			if !s.up {
				return nil, errors.New("the k3s supervisor is unreachable")
			}
			return s, nil
		}
	}
	return nil, errors.New("the k3s supervisor is unreachable")
}

func (m *k3sModel) Status(_ context.Context, mesh, tok string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.at(mesh)
	if err != nil {
		return 0, err
	}
	if strings.Contains(tok, "::server:") && passOf(tok) == s.mem.server {
		return 200, nil
	}
	return 401, nil
}

func (m *k3sModel) Ready(ctx context.Context, mesh, tok string) (int, error) {
	return m.AgentStatus(ctx, mesh, nodeCredential(tok))
}

func (m *k3sModel) AgentStatus(_ context.Context, mesh, tok string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.at(mesh)
	if err != nil {
		return 0, err
	}
	if strings.Contains(tok, "::node:") && passOf(tok) == s.mem.node {
		return 200, nil
	}
	return 401, nil
}

// withModel wires the model into the harness: the fake nodeagents run its
// steps on the servers it models, the supervisor checks ask it.
func (h *harness) withModel(m *k3sModel) {
	h.s.bootstrap = m
	h.agents.onRotate = func(id, step, tok string) {
		if err := m.step(id, step, tok); err != nil {
			m.mu.Lock()
			m.fatal = append(m.fatal, id+": step "+step+": "+err.Error())
			m.mu.Unlock()
		}
	}
}

func (m *k3sModel) failures() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.fatal)
}

// everyRestartWorks: each server restarted alone, three times, then all
// together, twice: no start fails, and each one accepts tok (and the node
// credential derived from it) and refuses old.
func everyRestartWorks(t *testing.T, m *k3sModel, tok, old string) {
	t.Helper()
	names := make([]string, 0, len(m.servers))
	for n := range m.servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for range 3 {
		for _, n := range names {
			if err := m.restart(n); err != nil {
				t.Fatalf("restarting %s alone: %v", n, err)
			}
		}
	}
	for range 2 {
		if errs := m.restartAll(); len(errs) > 0 {
			t.Fatalf("restarting every server together: %v", errs)
		}
	}
	ctx := context.Background()
	for _, n := range names {
		mesh := m.servers[n].mesh
		if st, _ := m.Status(ctx, mesh, tok); st != 200 {
			t.Fatalf("%s refuses the token in effect (%d)", n, st)
		}
		if st, _ := m.Status(ctx, mesh, old); st != 401 {
			t.Fatalf("%s accepts the old token (%d)", n, st)
		}
		if st, _ := m.AgentStatus(ctx, mesh, nodeCredential(tok)); st != 200 {
			t.Fatalf("%s refuses the node credential in effect (%d)", n, st)
		}
		if st, _ := m.AgentStatus(ctx, mesh, nodeCredential(old)); st != 401 {
			t.Fatalf("%s accepts the old node credential (%d)", n, st)
		}
	}
	if f := m.failures(); len(f) > 0 {
		t.Fatalf("failed starts: %v", f)
	}
}

// TestK3sModelSeparateAgentTokenIsFatal: the model reproduces the bug
// found live (Task 30 concern 1): with --agent-token-file, the old
// rotate / rotate-agent / apply / apply-agent sequence leaves every server
// unable to start again ("cred/passwd newer than datastore"), so the
// model is a fair judge of the fixed sequence below.
func TestK3sModelSeparateAgentTokenIsFatal(t *testing.T) {
	agentTok := "K10" + caHash(testServerToken) + "::node:fedcba9876543210fedcba9876543210"
	m := newK3sModel(testServerToken, agentTok, map[string]string{"n1": "10.215.0.1", "n2": "10.215.0.2", "n3": "10.215.0.3"})
	newSrv, _ := newK10(caHash(testServerToken), "server")
	newAgt, _ := newK10(caHash(testServerToken), "node")
	for _, c := range []struct{ id, step, tok string }{
		{"n1", "rotate", newSrv}, {"n1", "rotate-agent", newAgt},
		{"n2", "apply", newSrv}, {"n2", "apply-agent", newAgt},
		{"n3", "apply", newSrv}, {"n3", "apply-agent", newAgt},
	} {
		if err := m.step(c.id, c.step, c.tok); err != nil {
			t.Fatalf("%s on %s: %v (the old sequence ran to its end live)", c.step, c.id, err)
		}
	}
	for _, n := range []string{"n1", "n2", "n3"} {
		err := m.restart(n)
		if err == nil || !strings.Contains(err.Error(), "newer than datastore") {
			t.Fatalf("%s's next restart: %v (want the fatal seen live)", n, err)
		}
	}
	// Removing passwd brings a server back once only (seen live): the
	// start rewrites the node line from the agent token file again.
	s := m.servers["n1"]
	s.disk, s.diskMtime = mPasswd{}, 0
	if err := m.restart("n1"); err != nil {
		t.Fatalf("the start after removing passwd: %v", err)
	}
	if err := m.restart("n1"); err == nil || !strings.Contains(err.Error(), "newer than datastore") {
		t.Fatalf("the start after that: %v (want fatal again)", err)
	}
}

// TestRevokeLeavesEveryServerRestartable (agent-token fix): nodeadm's
// whole revoke of an agent, then of a server (rotated twice), driven
// against the model: every surviving server restarts, alone and all
// together, after each; the old token and the node credential derived
// from it are refused everywhere; the agent never gets a token call.
func TestRevokeLeavesEveryServerRestartable(t *testing.T) {
	agent := nodeSpec{"n4", "agent", "cloud", "edge", "10.215.0.4", nil, nil, true, false}
	h := newHarness(t, append(append([]nodeSpec{}, baseNodes...), agent)...)
	m := newK3sModel(testServerToken, "", map[string]string{"n1": "10.215.0.1", "n2": "10.215.0.2", "n3": "10.215.0.3"})
	h.withModel(m)
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n4"] = &nodeRecord{Role: "agent", Serial: "ab:cd", MeshIP: "10.215.0.4"}
		st.Nodes["n2"] = &nodeRecord{Role: "server", Serial: "12:34", MeshIP: "10.215.0.2"}
	})
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n4?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n4: %d %s (failed starts %v)", w.Code, w.Body, m.failures())
	}
	tok1, _ := h.s.serverToken(context.Background())
	if tok1 == testServerToken {
		t.Fatal("the server token wasn't rotated")
	}
	everyRestartWorks(t, m, tok1, testServerToken)
	for _, r := range h.agents.rotations {
		if strings.HasSuffix(r, ":n4") || strings.Contains(r, "agent") {
			t.Fatalf("a token call to the agent or an agent token step: %v", h.agents.rotations)
		}
	}
	// A server target: its member goes, the token rotates twice; the
	// survivors restart as before.
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n2?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke n2: %d %s (failed starts %v)", w.Code, w.Body, m.failures())
	}
	m.mu.Lock()
	delete(m.servers, "n2") // gone from the cluster (its member removed)
	m.mu.Unlock()
	tok2, _ := h.s.serverToken(context.Background())
	if tok2 == tok1 || tok2 == testServerToken {
		t.Fatal("the server token wasn't rotated for the server revoke")
	}
	everyRestartWorks(t, m, tok2, tok1)
	everyRestartWorks(t, m, tok2, testServerToken)
}

// slowBoot: each server's supervisor accepts the token it restarted with,
// and a token step's restart lands only a while after the call returned
// (the nodeagent's systemctl restart --no-block).
type slowBoot struct {
	mu   sync.Mutex
	tok  map[string]string // mesh → the token its ready k3s runs with
	sup  map[string]string // mesh → the token its supervisor accepts (up seconds into a start)
	lag  time.Duration
	seen []string // a violation: a step while an earlier server hadn't restarted
}

func (b *slowBoot) Status(_ context.Context, mesh, tok string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sup[mesh] == tok {
		return 200, nil
	}
	return 401, nil
}

// Ready: only once the restart is done (b.tok); the supervisor (Status)
// answers the new token at once, as seen live.
func (b *slowBoot) Ready(ctx context.Context, mesh, tok string) (int, error) {
	return b.AgentStatus(ctx, mesh, nodeCredential(tok))
}

func (b *slowBoot) AgentStatus(_ context.Context, mesh, tok string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if nodeCredential(b.tok[mesh]) == tok {
		return 200, nil
	}
	return 401, nil
}

// TestApplyWaitsForEachRestart (found live, agent-token fix): the apply
// round restarts one server at a time: the next server's apply comes only
// once the previous one's k3s answers with the new token (its Node is
// still Ready right after a --no-block restart, so Ready alone let every
// server restart at once and the API went away).
func TestApplyWaitsForEachRestart(t *testing.T) {
	h := newHarness(t)
	mesh := map[string]string{"n1": "10.215.0.1", "n2": "10.215.0.2", "n3": "10.215.0.3"}
	b := &slowBoot{tok: map[string]string{}, sup: map[string]string{}, lag: 60 * time.Millisecond}
	for _, m := range mesh {
		b.tok[m], b.sup[m] = testServerToken, testServerToken
	}
	h.s.bootstrap = b
	var pending sync.WaitGroup
	restarting := map[string]bool{}
	h.agents.onRotate = func(id, step, tok string) {
		b.mu.Lock()
		if b.tok[mesh[id]] == tok { // the nodeagent: "already in place", no restart
			b.mu.Unlock()
			return
		}
		for other := range restarting {
			if other != id {
				b.seen = append(b.seen, step+":"+id+" while "+other+" restarts")
			}
		}
		restarting[id] = true
		b.sup[mesh[id]] = tok
		b.mu.Unlock()
		pending.Add(1)
		time.AfterFunc(b.lag, func() {
			defer pending.Done()
			b.mu.Lock()
			b.tok[mesh[id]] = tok
			delete(restarting, id)
			b.mu.Unlock()
		})
	}
	h.putState(t, func(st *nodeadmState) {
		st.Nodes["n3"] = &nodeRecord{Role: "server", Serial: "56:78", MeshIP: "10.215.0.3"}
	})
	h.s.timing.NodeReady = 5 * time.Second
	if w := h.internal(clientHub, "DELETE", "/v1/nodes/n3?mode=revoke", nil); w.Code != 204 {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	pending.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.seen) > 0 {
		t.Fatalf("a token step while another server was still restarting: %v", b.seen)
	}
	if !slices.Contains(h.agents.rotations, "apply:n2") {
		t.Fatalf("rotations %v", h.agents.rotations)
	}
}
