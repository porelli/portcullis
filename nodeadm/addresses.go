package main

// The cluster addresses document (contract §20.9; ruling R-ADM): nodeadm
// writes it after every join, removal and address change, with every node
// AND every pending node (enrolled, no node object yet), so the CLI's
// params-sync puts a joining node's addresses into the admission params
// before the node gets any k3s material. After a change the probe targets
// go to every nodeagent (§20.4). Fail closed: a node without a mesh
// address, or one whose LAN / public addresses nodeadm doesn't know (no
// portcullis.io/addresses annotation, no enrolment report), or an
// unparseable cluster network, writes no document, and the snapshot shows
// why.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	addressesCM  = "portcullis-cluster-addresses"
	addressesKey = "addresses.json"
)

type addrPublished struct {
	written string            // the document this process last wrote
	errs    []string          // the faults of the last build
	pushed  map[string]string // node → hash of the probe targets it holds
}

func (s *Server) addrErrors() []string {
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	return append([]string{}, s.addrState.errs...)
}

// reportAddrs: a pending node's addresses from its enrolment report.
func reportAddrs(rec *nodeRecord) NodeAddresses {
	a := NodeAddresses{Mesh: rec.MeshIP, LAN: []string{}, Public: []string{}}
	if rec.Mesh.LAN != nil {
		if ap, err := netip.ParseAddrPort(*rec.Mesh.LAN); err == nil {
			a.LAN = append(a.LAN, ap.Addr().String())
		}
	}
	if rec.Mesh.Public != nil {
		if ap, err := netip.ParseAddrPort(*rec.Mesh.Public); err == nil {
			a.Public = append(a.Public, ap.Addr().String())
		}
	}
	return a
}

// nodeAllAddrs: mesh, LAN and public, the set a join must be admitted for.
func nodeAllAddrs(a NodeAddresses) []string {
	return append(append([]string{a.Mesh}, a.LAN...), a.Public...)
}

// buildAddresses: the §20.9 document (every node, pending node and node
// being removed, with its state), or nil and why.
func (s *Server) buildAddresses(cl []clusterNode, st *nodeadmState) (*AddressesDoc, []string) {
	var errs []string
	for _, c := range []string{s.cfg.ClusterCIDR, s.cfg.ServiceCIDR} {
		if p, err := netip.ParsePrefix(c); err != nil || !p.Addr().Is4() || p.Masked() != p {
			errs = append(errs, fmt.Sprintf("the cluster network %q doesn't parse: no cluster addresses written", c))
		}
	}
	var live []clusterNode
	for _, c := range cl {
		if r := st.Nodes[c.Name]; r == nil || !r.Removed {
			live = append(live, c)
		}
	}
	doc := &AddressesDoc{V: 1, MeshCIDR: meshPrefix.String(), ClusterCIDR: s.cfg.ClusterCIDR, ServiceCIDR: s.cfg.ServiceCIDR,
		API: serverMeshIPs(live), Nodes: map[string]DocNode{}}
	for _, c := range live {
		switch {
		case c.Mesh == "":
			errs = append(errs, fmt.Sprintf("node %s has no mesh address: no cluster addresses written", c.Name))
		case c.Node.Annotations[annAddresses] != "":
			doc.Nodes[c.Name] = docNode(c.Addresses, stateActive)
		case st.Nodes[c.Name] != nil:
			// A joined node whose annotation isn't written yet.
			doc.Nodes[c.Name] = docNode(reportAddrs(st.Nodes[c.Name]), stateActive)
		default:
			errs = append(errs, fmt.Sprintf("node %s has no recorded LAN and public addresses: no cluster addresses written", c.Name))
		}
	}
	holders := lanHolders(cl, st)
	for id, rec := range st.Nodes {
		if _, ok := doc.Nodes[id]; ok {
			continue
		}
		switch {
		case rec.Removed:
			a := reportAddrs(rec)
			if rec.Addrs != nil {
				a = *rec.Addrs
			}
			doc.Nodes[id] = docNode(a, stateRemoved)
		case rec.Serial == "":
			// Enrolling: no certificate yet, no material can follow.
		case !meshAddrOK(rec.MeshIP):
			errs = append(errs, fmt.Sprintf("node %s has no mesh address: no cluster addresses written", id))
		default:
			a := s.cleanAddrs(reportAddrs(rec))
			keep := []string{}
			for _, l := range a.LAN {
				if lanTaken(holders, l, id) == "" {
					keep = append(keep, l)
				}
			}
			a.LAN = keep
			state := statePending
			if rec.JoinedAt != nil {
				state = stateActive
			}
			doc.Nodes[id] = docNode(a, state)
		}
	}
	if len(doc.API) == 0 {
		errs = append(errs, "no server has a mesh address: no cluster addresses written")
	}
	sort.Strings(errs)
	if len(errs) > 0 {
		return nil, errs
	}
	return doc, nil
}

func docJSON(d *AddressesDoc) string {
	b, _ := json.Marshal(d)
	return string(b)
}

// annotateJoined writes portcullis.io/addresses on a node nodeadm enrolled
// (from its enrolment report: the LAN and public endpoints' addresses).
func (s *Server) annotateJoined(ctx context.Context, cl []clusterNode, st *nodeadmState) {
	for i := range cl {
		c := &cl[i]
		rec := st.Nodes[c.Name]
		if rec == nil || c.Node.Annotations[annAddresses] != "" {
			continue
		}
		ra := reportAddrs(rec)
		b, _ := json.Marshal(map[string][]string{"lan": ra.LAN, "public": ra.Public})
		if err := s.patchNode(ctx, c.Name, map[string]any{"metadata": map[string]any{"annotations": map[string]string{annAddresses: string(b)}}}); err != nil {
			s.log.Warn("couldn't record a node's addresses", "node", c.Name, "err", err.Error())
			continue
		}
		if c.Node.Annotations == nil {
			c.Node.Annotations = map[string]string{}
		}
		c.Node.Annotations[annAddresses] = string(b)
		c.Addresses = s.cleanAddrs(nodeAddrs(c.Node))
		c.RawLAN = append([]string{}, c.Addresses.LAN...)
	}
	dedupeLAN(cl, st)
}

// writeAddresses replaces the ConfigMap's document (nodeadm's one right
// on it is update: an unconditional replacement, no read). Unchanged since
// the last write of this process: nothing sent.
func (s *Server) writeAddresses(ctx context.Context, doc string) error {
	s.addrMu.Lock()
	same := s.addrState.written == doc
	s.addrMu.Unlock()
	if same {
		return nil
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: addressesCM, Namespace: s.cfg.CoreNS,
		Labels: map[string]string{"app.kubernetes.io/managed-by": "portcullis"}}, Data: map[string]string{addressesKey: doc}}
	if _, err := s.kube.CoreV1().ConfigMaps(s.cfg.CoreNS).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("writing the ConfigMap %s: %w", addressesCM, err)
	}
	s.addrMu.Lock()
	s.addrState.written = doc
	s.addrMu.Unlock()
	s.log.Info("cluster addresses written")
	return nil
}

// probeTargets: every ingress node's public addresses, with its site.
func (s *Server) probeTargets(nodes []clusterNode, doc *AddressesDoc) ProbeTargets {
	t := ProbeTargets{Domain: s.cfg.Domain, Targets: []ProbeTarget{}, EgressHost: s.cfg.EgressHost}
	for _, c := range nodes {
		if !c.Ingress || doc.Nodes[c.Name].State != stateActive {
			continue
		}
		for _, a := range doc.Nodes[c.Name].Public {
			t.Targets = append(t.Targets, ProbeTarget{Node: c.Name, Site: c.Site, Address: a})
		}
	}
	sort.Slice(t.Targets, func(i, j int) bool {
		if t.Targets[i].Node != t.Targets[j].Node {
			return t.Targets[i].Node < t.Targets[j].Node
		}
		return t.Targets[i].Address < t.Targets[j].Address
	})
	return t
}

// pushTargets sends the targets to each Ready node that doesn't hold them
// yet; one unreachable nodeagent doesn't block the others.
func (s *Server) pushTargets(ctx context.Context, nodes []clusterNode, t ProbeTargets) {
	if s.cfg.EgressHost == "" {
		return
	}
	b, _ := json.Marshal(t)
	sum := sha256.Sum256(b)
	h := hex.EncodeToString(sum[:])
	for _, c := range nodes {
		if !c.Ready || c.Mesh == "" {
			continue
		}
		s.addrMu.Lock()
		done := s.addrState.pushed[c.Name] == h
		s.addrMu.Unlock()
		if done {
			continue
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.agents.PutProbeTargets(pctx, c.Name, c.Mesh, t)
		cancel()
		if err != nil {
			s.log.Warn("probe targets not delivered", "node", c.Name, "err", err.Error())
			continue
		}
		s.addrMu.Lock()
		if s.addrState.pushed == nil {
			s.addrState.pushed = map[string]string{}
		}
		s.addrState.pushed[c.Name] = h
		s.addrMu.Unlock()
	}
}

// reconcile is one round of the leader's loop.
func (s *Server) reconcile(ctx context.Context) {
	if !s.leader.Leading() {
		return
	}
	if err := s.sweepCodes(ctx); err != nil {
		s.log.Warn("couldn't sweep the join codes", "err", err.Error())
	}
	s.resumeOps(ctx)
	s.revokeOldOwnCerts(ctx)
	if err := s.ensureFrontdoorCert(ctx); err != nil {
		s.log.Warn("the front door's certificate", "err", redact(err.Error()))
	}
	nodes, err := s.clusterNodes(ctx)
	if err != nil {
		s.log.Warn("reconcile", "err", err.Error())
		return
	}
	st, err := s.load(ctx)
	if err != nil {
		s.log.Warn("reconcile", "err", err.Error())
		return
	}
	s.annotateJoined(ctx, nodes, st)
	s.expireRenewals(ctx, st)
	s.dropRemoved(ctx, st)
	doc, errs := s.buildAddresses(nodes, st)
	s.addrMu.Lock()
	s.addrState.errs = errs
	s.addrMu.Unlock()
	if doc == nil {
		return
	}
	if err := s.writeAddresses(ctx, docJSON(doc)); err != nil {
		s.log.Warn("cluster addresses", "err", err.Error())
		return
	}
	s.pushTargets(ctx, nodes, s.probeTargets(nodes, doc))
}

// dropRemoved deletes a removed node's record (so its entry leaves the
// document) once the active admission generation no longer holds its mesh
// address.
func (s *Server) dropRemoved(ctx context.Context, st *nodeadmState) {
	var gone []string
	// Revokes enroll refused: retried here, until each is revoked
	// (PendingRevokes is independent of the records dropped below).
	if len(st.PendingRevokes) > 0 {
		if err := s.revokePending(ctx, ""); err != nil {
			s.log.Warn("node certificates aren't revoked yet (retried)", "pending", len(st.PendingRevokes))
		}
	}
	for id, r := range st.Nodes {
		if !r.Removed || st.Ops[id] != nil {
			continue
		}
		mesh := r.MeshIP
		if r.Addrs != nil {
			mesh = r.Addrs.Mesh
		}
		if held, err := s.admitted(ctx, []string{mesh}); err == nil && !held {
			gone = append(gone, id)
		}
	}
	if len(gone) == 0 {
		return
	}
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		for _, id := range gone {
			if r := st.Nodes[id]; r != nil && r.Removed && st.Ops[id] == nil {
				delete(st.Nodes, id)
			}
		}
		return nil
	}); err != nil {
		s.log.Warn("couldn't drop removed nodes", "err", err.Error())
		return
	}
	for _, id := range gone {
		delete(st.Nodes, id)
		s.log.Info("removed node left the admission params: dropped", "node", id)
	}
}

// kick runs a reconcile round soon (after a join, a removal, a label).
func (s *Server) kick() {
	select {
	case s.kickCh <- struct{}{}:
	default:
	}
}

// loop reconciles every 30 s and after each kick.
func (s *Server) loop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		s.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kickCh:
		}
	}
}
