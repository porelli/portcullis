package main

// The admission params (contract §6 "Params generations"; ruling R-ADM).
// nodeadm writes no admission object at all: the API server never applies
// ValidatingAdmissionPolicies to policies, bindings or (usefully) to their
// params, so any such right would be an unguardable bypass. The CLI alone
// rewrites the generation (`./portcullis kube params-sync`, every 30 s
// from portcullis-kube-params.timer) from the cluster addresses document
// nodeadm writes, and keeps a copy of the proven generation in the
// ConfigMap portcullis-admission-active, which nodeadm may only get:
// a join's k3s material waits until that generation's nodeAddresses cover
// the joining node (waiting_admission). The generation function is the
// CLI's (shared vectors params_generation_vectors.json).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	admissionActive = "portcullis-admission-active"
	activeKey       = "active.json"
)

var genRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// paramsGeneration: the first 16 hex digits of the sha256 of every
// key<TAB>value line but generation's, sorted bytewise, each ended by a
// newline (the CLI's `printf '%s\t%s\n' … | LC_ALL=C sort | sha256sum`).
func paramsGeneration(kv map[string]string) string {
	lines := make([]string, 0, len(kv))
	for k, v := range kv {
		if k != "generation" {
			lines = append(lines, k+"\t"+v+"\n")
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])[:16]
}

func hostPrefix(a string) string {
	ip, err := netip.ParseAddr(a)
	if err != nil {
		return ""
	}
	return netip.PrefixFrom(ip, ip.BitLen()).String()
}

// activeRecord is portcullis-admission-active (key active.json), which
// params-sync writes after each proven swap (§20.9).
type activeRecord struct {
	Generation    string   `json:"generation"`
	NodeAddresses []string `json:"node_addresses"`
	APIAddresses  []string `json:"api_addresses"`
	ProvenAt      string   `json:"proven_at"`
}

// admitted: the active (proven) generation's node addresses hold every one
// of addrs. Unreadable or malformed record: not admitted (fail closed).
func (s *Server) admitted(ctx context.Context, addrs []string) (bool, error) {
	cm, err := s.kube.CoreV1().ConfigMaps(s.cfg.CoreNS).Get(ctx, admissionActive, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("reading the ConfigMap %s: %w", admissionActive, err)
	}
	var rec activeRecord
	if err := strictJSON([]byte(cm.Data[activeKey]), &rec); err != nil || !genRe.MatchString(rec.Generation) {
		return false, fmt.Errorf("the ConfigMap %s doesn't parse", admissionActive)
	}
	have := map[string]bool{}
	for _, a := range rec.NodeAddresses {
		if p, err := netip.ParsePrefix(a); err == nil && p.IsSingleIP() {
			have[p.Addr().String()] = true
		} else if ip, err := netip.ParseAddr(a); err == nil {
			have[ip.String()] = true
		}
	}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil || !have[ip.String()] {
			return false, nil
		}
	}
	return true, nil
}
