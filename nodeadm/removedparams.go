package main

// The removed-node params (Task 30 fix round 2, re-review R-I1/R-I2/R-M2).
//
// portcullis-removed-nodes refuses every node identity's Node write (nodes,
// nodes/status) and CSR create for a name nodeadm lists removed: a removed
// or revoked node's kubelet client certificate still authenticates for
// about a year. The list must be in force on every API server BEFORE the
// Node is deleted, else the old kubelet can register again in between. So
// it can't ride the CLI's params generations (ruling R-ADM: nodeadm writes
// no admission object, and a params generation is made by the CLI's
// params-sync timer, which may be down): the policy's binding (fixed name
// portcullis-nodes-guard-removed, made by the CLI) reads its own params,
// the ConfigMap portcullis-removed-nodes in the core namespace (created
// empty by the CLI), which nodeadm alone updates in place — the narrowest
// right that orders the list before the delete:
//
//   - configmaps update on that one name (no create, no delete: a missing
//     ConfigMap is the binding's parameterNotFoundAction Deny, and a
//     missing key refuses every node identity's write: fail closed);
//   - impersonate on exactly the user system:node:portcullis-admission-probe
//     (no group: not a node to the Node authorizer or NodeRestriction),
//     whose only right is nodes create (ClusterRole
//     portcullis-admission-probe), and the policy refuses any of its writes
//     that isn't a dry run;
//   - get on the EndpointSlice default/kubernetes (the API servers).
//
// A write is confirmed by the probe on EVERY API server of that
// EndpointSlice, dialled one by one (each has its own params cache): a
// server dry-run CREATE of the probe Node annotated
// portcullis.io/removed-nodes-generation=<generation> must be refused by
// the binding naming that generation (the policy's first rules: the params
// hold the key, then the probe). The generation is the params' content
// hash (paramsGeneration), so a confirmed generation is the list itself.
// Until every server confirms, the removal stops before the Node delete and
// says so (removedInForce); no timer is waited for.

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	removedCM      = "portcullis-removed-nodes"
	removedKey     = "removedNodes"
	removedBinding = "portcullis-nodes-guard-removed"
	removedAnn     = "portcullis.io/removed-nodes-generation"
	// The probe's node name and identity (reserved: no node may take an
	// id under reservedIDPrefix, nit 2).
	probeNodeName    = "portcullis-admission-probe"
	probeIdentity    = "system:node:" + probeNodeName
	reservedIDPrefix = "portcullis-admission-"
)

// AdmissionProbe confirms a removed-node params generation in force.
type AdmissionProbe interface {
	// Confirm: nil once every API server refuses the probe naming gen.
	Confirm(ctx context.Context, gen string) error
}

// removedData is the ConfigMap's data for names (sorted, unique).
func removedData(names []string) map[string]string {
	d := map[string]string{removedKey: strings.Join(names, " ")}
	d["generation"] = paramsGeneration(d)
	return d
}

// removedNames: the state's removed names, sorted.
func removedNames(st *nodeadmState) []string {
	out := make([]string, 0, len(st.RemovedNames))
	for id := range st.RemovedNames {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// pushRemoved writes the state's removed names into portcullis-removed-nodes
// (when they differ) and waits up to wait (one try when 0) for every API
// server to confirm that generation; the names it confirmed. Serialised
// (removedMu): the state is read inside, so a later push never writes an
// older list over a newer one.
func (s *Server) pushRemoved(ctx context.Context, wait time.Duration) ([]string, error) {
	s.removedMu.Lock()
	defer s.removedMu.Unlock()
	st, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	names := removedNames(st)
	data := removedData(names)
	gen := data["generation"]
	cms := s.kube.CoreV1().ConfigMaps(s.cfg.CoreNS)
	var rv string
	for attempt := 0; ; attempt++ {
		cm, err := cms.Get(ctx, removedCM, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("the ConfigMap %s is missing (the CLI creates it: ./portcullis up)", removedCM)
		}
		if err != nil {
			return nil, fmt.Errorf("reading the ConfigMap %s: %w", removedCM, err)
		}
		if maps.Equal(cm.Data, data) {
			rv = cm.ResourceVersion
			break
		}
		cm = cm.DeepCopy()
		cm.Data = data
		up, err := cms.Update(ctx, cm, metav1.UpdateOptions{})
		if apierrors.IsConflict(err) && attempt < 3 {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("writing the ConfigMap %s: %w", removedCM, err)
		}
		rv = up.ResourceVersion
		s.log.Info("removed-node params written", "generation", gen, "names", len(names))
		break
	}
	key := gen + "/" + rv
	if s.removedProven == key {
		return names, nil
	}
	deadline := time.Now().Add(wait)
	for {
		err := s.probe.Confirm(ctx, gen)
		if err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("removed-node params generation %s isn't confirmed in force: %w", gen, err)
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return nil, err
		}
	}
	s.removedProven = key
	s.log.Info("removed-node params in force on every API server", "generation", gen)
	return names, nil
}

// removedInForce: id is listed removed and that list is confirmed in force
// on every API server; called right before a removed node's Node is
// deleted (the old kubelet can't register it again). Else the removal stops
// here (fail closed) and is retried; nothing waits for a timer.
func (s *Server) removedInForce(ctx context.Context, id string) error {
	wait := s.timing.RemovedConfirm
	if wait <= 0 {
		wait = 90 * time.Second
	}
	names, err := s.pushRemoved(ctx, wait)
	if err != nil {
		s.log.Warn("a removed node's Node is kept: its name isn't confirmed refused", "node", id, "err", err.Error())
		return errPlain(http.StatusServiceUnavailable, "node %s's Node isn't deleted: %v; the removal stops here (its kubelet could register it again) and goes on when retried", id, err)
	}
	if !slices.Contains(names, id) {
		return fmt.Errorf("node %s isn't listed removed: its Node isn't deleted", id)
	}
	return nil
}

// deleteRemovedNode deletes a removed node's Node once its name is in
// force (removedInForce); an absent Node is fine.
func (s *Server) deleteRemovedNode(ctx context.Context, id string) error {
	if err := s.removedInForce(ctx, id); err != nil {
		return err
	}
	if err := s.kube.CoreV1().Nodes().Delete(ctx, id, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting node %s: %w", id, err)
	}
	return nil
}

// apiProbe is the real AdmissionProbe: the dry-run probe on each API server
// of the EndpointSlice default/kubernetes, as the probe identity.
type apiProbe struct {
	base *rest.Config
	kube kubernetes.Interface
}

func probeNode(gen string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: probeNodeName, Annotations: map[string]string{removedAnn: gen}}}
}

// probeRefusal is the refusal that confirms gen (the API server's form:
// "ValidatingAdmissionPolicy '<policy>' with binding '<binding>' denied
// request: <message>").
func probeRefusal(gen string) string {
	return "binding '" + removedBinding + "' denied request: admission probe: params generation " + gen + " in effect"
}

// probeAnswer judges one API server's answer to the probe.
func probeAnswer(server, gen string, err error) error {
	if err == nil {
		return fmt.Errorf("the API server %s admitted the probe: portcullis-removed-nodes doesn't judge there", server)
	}
	if !strings.Contains(err.Error(), probeRefusal(gen)) {
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("the API server %s doesn't confirm generation %s yet: %s", server, gen, msg)
	}
	return nil
}

func (p *apiProbe) servers(ctx context.Context) ([]string, error) {
	sl, err := p.kube.DiscoveryV1().EndpointSlices("default").Get(ctx, "kubernetes", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("reading the API servers (EndpointSlice default/kubernetes): %w", err)
	}
	port := 0
	for _, pt := range sl.Ports {
		if pt.Port != nil && (pt.Name == nil || *pt.Name == "https") {
			port = int(*pt.Port)
		}
	}
	var out []string
	for _, ep := range sl.Endpoints {
		for _, a := range ep.Addresses {
			if net.ParseIP(a) != nil {
				out = append(out, net.JoinHostPort(a, strconv.Itoa(port)))
			}
		}
	}
	if port == 0 || len(out) == 0 {
		return nil, fmt.Errorf("the EndpointSlice default/kubernetes lists no API server")
	}
	sort.Strings(out)
	return out, nil
}

func (p *apiProbe) Confirm(ctx context.Context, gen string) error {
	servers, err := p.servers(ctx)
	if err != nil {
		return err
	}
	for _, srv := range servers {
		cfg := rest.CopyConfig(p.base)
		cfg.Host = "https://" + srv
		cfg.Impersonate = rest.ImpersonationConfig{UserName: probeIdentity}
		cfg.Timeout = 10 * time.Second
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		_, err = cs.CoreV1().Nodes().Create(ctx, probeNode(gen), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if err := probeAnswer(srv, gen, err); err != nil {
			return err
		}
	}
	return nil
}
