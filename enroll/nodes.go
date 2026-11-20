package main

// Node certificates for multiple servers (contract §17), on the Hub's
// internal listener (:8444, the invite bearer; never the loopback one).
// NEW (HA, §17.5): nodeadm's own bearer (secrets/enroll/nodeadm-api-secret)
// signs node-cluster (<server id>.cluster.portcullis.internal),
// node-frontdoor (frontdoor.control) and node-nodeadm (nodeadm.control,
// its one SAN nodeadm.portcullis-nodeadm.svc) and nothing else, and
// revokes only those; the invites' bearer signs none of the three:
//
//	POST /internal/nodes/sign   {"role","common_name","csr"}
//	     → 201 {"certificate","serial","not_after","ca"}
//	POST /internal/nodes/revoke {"serial"} → 204
//
// pki_node is its own self-signed root (ruling P1), never under pki: no
// Traefik, Keycloak or group-gate trust list holds it, so a node
// certificate can't sign anyone in. Only the node-worker
// (<server id>.node.portcullis.internal) and node-control (hub.control)
// roles are signed here; node-link is signed by the CLI with the root
// token, never by enroll (its policy has no path for it either). The CSR
// must be one P-256 request naming exactly that CN and nothing else
// (no SANs of any kind); Vault takes the CN from common_name only
// (use_csr_common_name=false, use_csr_sans=false). CSRs and certificates
// never reach a log.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

const (
	mountNode       = "pki_node"
	roleNodeWorker  = "node-worker"
	roleNodeControl = "node-control"
	// nodeTTL is both roles' lifetime (30 d; the Hub renews at ⅓ left).
	nodeTTL = "720h"
	// NodeDomain names workers: <server id>.node.portcullis.internal.
	nodeDomain = "node.portcullis.internal"
	// controlCN is the Hub's control certificate.
	controlCN = "hub.control"

	// HA (contract §17.5): nodeadm's three roles.
	roleNodeCluster   = "node-cluster"
	roleNodeFrontdoor = "node-frontdoor"
	roleNodeNodeadm   = "node-nodeadm"
	frontdoorCN       = "frontdoor.control"
	nodeadmCN         = "nodeadm.control"
	nodeadmSAN        = "nodeadm.portcullis-nodeadm.svc"
)

// nodeClusterCNRe: a cluster node, <server id>.cluster.portcullis.internal.
var nodeClusterCNRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}\.cluster\.portcullis\.internal$`)

// nodeadmMayHold: a CN nodeadm's bearer may sign or revoke.
func nodeadmMayHold(cn string) bool {
	return nodeClusterCNRe.MatchString(cn) || cn == frontdoorCN || cn == nodeadmCN
}

// nodeWorkerCNRe: the server id grammar (the Hub's servers.IDRe) under
// nodeDomain. "primary" is reserved (the local engine).
var nodeWorkerCNRe = regexp.MustCompile(`^([a-z][a-z0-9-]{0,30})\.node\.portcullis\.internal$`)

// nodeCertResult is a signed node certificate and the pki_node CA.
type nodeCertResult struct {
	PEM      string
	Serial   string
	NotAfter time.Time
	CA       string
}

// checkNodeRequest refuses (before Vault) a role the bearer may not sign
// (the invites' bearer: node-worker / node-control; nodeadm's: node-cluster,
// node-frontdoor, node-nodeadm), a CN outside the role's pattern, and any
// CSR but one signed P-256 request whose subject is exactly that CN with no
// SANs.
func checkNodeRequest(role, cn, csrPEM string, nodeadm bool) error {
	ha := role == roleNodeCluster || role == roleNodeFrontdoor || role == roleNodeNodeadm
	if nodeadm && !ha {
		return refuse(403, "nodeadm's bearer signs only node-cluster, node-frontdoor and node-nodeadm")
	}
	if !nodeadm && ha {
		return refuse(403, "only nodeadm's bearer signs %s", role)
	}
	switch role {
	case roleNodeCluster:
		if !nodeClusterCNRe.MatchString(cn) {
			return refuse(400, "common_name must be <server id>.cluster.portcullis.internal")
		}
	case roleNodeFrontdoor:
		if cn != frontdoorCN {
			return refuse(400, "common_name must be %s", frontdoorCN)
		}
	case roleNodeNodeadm:
		if cn != nodeadmCN {
			return refuse(400, "common_name must be %s", nodeadmCN)
		}
	case roleNodeWorker:
		m := nodeWorkerCNRe.FindStringSubmatch(cn)
		if m == nil || m[1] == "primary" {
			return refuse(400, "common_name must be <server id>.%s", nodeDomain)
		}
	case roleNodeControl:
		if cn != controlCN {
			return refuse(400, "common_name must be %s", controlCN)
		}
	default:
		return refuse(403, "only the node-worker and node-control roles are signed here")
	}
	b, rest := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return refuse(400, "csr must be one PEM CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return refuse(400, "csr must be one PEM CERTIFICATE REQUEST block")
	}
	if pk, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		return refuse(400, "the csr's key must be ECDSA P-256")
	}
	if csr.Subject.CommonName != cn || len(csr.Subject.Names) != 1 {
		return refuse(400, "the csr's subject must be exactly CN=%s", cn)
	}
	if len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0 {
		return refuse(400, "the csr must carry no alternative names")
	}
	for _, e := range csr.Extensions {
		if e.Id.Equal(oidSAN) {
			return refuse(400, "the csr must carry no alternative names")
		}
	}
	return nil
}

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// signNodeCert signs csrPEM on pki_node/sign/<role> for cn. The answer is
// checked: CN, the CSR's key, issued by pki_node's own CA.
func (cfg *Config) signNodeCert(ctx context.Context, role, cn, csrPEM string, nodeadm bool) (*nodeCertResult, error) {
	if err := checkNodeRequest(role, cn, csrPEM, nodeadm); err != nil {
		return nil, err
	}
	ca, err := cfg.caCert(ctx, mountNode)
	if err != nil {
		return nil, err
	}
	var extra []map[string]interface{}
	wantDNS := []string{cn}
	if role == roleNodeNodeadm {
		// Its serving name is its one SAN (the Hub and the front door
		// verify it); enroll's policy admits exactly these two values.
		extra = append(extra, map[string]interface{}{"alt_names": nodeadmSAN, "exclude_cn_from_sans": "true"})
		wantDNS = []string{nodeadmSAN}
	}
	signed, err := cfg.signOn(ctx, mountNode, role, cn, csrPEM, nodeTTL, extra...)
	if err != nil {
		return nil, err
	}
	if !issuedBy(signed.Leaf, ca) {
		return nil, fmt.Errorf("vault sign on %s: the certificate isn't issued by pki_node's CA", mountNode)
	}
	if len(signed.Leaf.IPAddresses)+len(signed.Leaf.URIs)+len(signed.Leaf.EmailAddresses) != 0 ||
		(len(signed.Leaf.DNSNames) != 0 && !slices.Equal(signed.Leaf.DNSNames, wantDNS)) ||
		(role == roleNodeNodeadm && !slices.Equal(signed.Leaf.DNSNames, wantDNS)) {
		return nil, fmt.Errorf("vault sign on %s: the certificate names other alternative names", mountNode)
	}
	log.Printf("node certificate %s for %s (%s)", signed.Serial, cn, role)
	return &nodeCertResult{
		PEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signed.Leaf.Raw})),
		Serial:   signed.Serial,
		NotAfter: signed.Leaf.NotAfter.UTC(),
		CA:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
	}, nil
}

// revokeNodeCert revokes serial on pki_node (unknown: 404; already
// revoked: nil), then rotates pki_node's CRL (a failure is only logged).
// Accepts any certificate whose chain verifies to the pki_node root (any
// node role: node-worker, node-control, node-link). A cert that doesn't
// chain to pki_node gets 403; with nodeadm's bearer, one nodeadm didn't
// have signed (another CN than its three roles') too.
func (cfg *Config) revokeNodeCert(ctx context.Context, serial string, nodeadm bool) error {
	s := strings.ToLower(strings.TrimSpace(serial))
	notFound := refuse(404, "no such certificate")
	if !serialRe.MatchString(s) {
		return notFound
	}
	ic, err := cfg.lookupIssued(ctx, mountNode, s)
	if err != nil {
		return err
	}
	if ic == nil {
		return notFound
	}
	// Idempotent: already revoked succeeds before any role check.
	if ic.Revoked {
		log.Printf("node certificate %s: already revoked", s)
		return nil
	}
	// Parse the certificate and verify it chains to pki_node's root.
	cert, err := x509.ParseCertificate(ic.DER)
	if err != nil {
		return fmt.Errorf("parsing certificate %s: %w", s, err)
	}
	ca, err := cfg.caCert(ctx, mountNode)
	if err != nil {
		return err
	}
	if !issuedBy(cert, ca) {
		return refuse(403, "the certificate doesn't chain to pki_node")
	}
	if nodeadm && !nodeadmMayHold(cert.Subject.CommonName) {
		return refuse(403, "nodeadm's bearer revokes only node-cluster, node-frontdoor and node-nodeadm certificates")
	}
	err = cfg.vault.do(func(vc *vault.Client) error {
		_, err := vc.Logical().WriteWithContext(ctx, mountNode+"/revoke", map[string]interface{}{"serial_number": s})
		return err
	})
	if err != nil {
		return fmt.Errorf("revoke %s on %s: %w", s, mountNode, err)
	}
	log.Printf("revoked node certificate %s", s)
	err = cfg.vault.do(func(vc *vault.Client) error {
		_, err := vc.Logical().ReadWithContext(ctx, mountNode+"/crl/rotate")
		return err
	})
	if err != nil {
		log.Printf("WARNING: %s/crl/rotate after revoking %s failed: %v", mountNode, s, err)
	}
	return nil
}

// nodeAuthorized: the invites' bearer (nodeadm false) or nodeadm's own
// (true, constant time; never equal to the invites' one); else 401.
func (s *inviteService) nodeAuthorized(w http.ResponseWriter, r *http.Request) (bool, bool) {
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok && got != "" && s.nodeadmSecret != "" && s.nodeadmSecret != s.apiSecret &&
		subtle.ConstantTimeCompare([]byte(got), []byte(s.nodeadmSecret)) == 1 {
		return true, true
	}
	return false, s.apiAuthorized(w, r)
}

// POST /internal/nodes/sign
func (s *inviteService) handleNodeSign(w http.ResponseWriter, r *http.Request) {
	nodeadm, ok := s.nodeAuthorized(w, r)
	if !ok {
		return
	}
	op := s.signNode
	if op == nil {
		jsonError(w, http.StatusServiceUnavailable, "node certificates unavailable")
		return
	}
	var req struct {
		Role       string `json:"role"`
		CommonName string `json:"common_name"`
		CSR        string `json:"csr"`
	}
	if !decodeAction(w, r, &req) {
		return
	}
	// Refused before Vault (and before op), with the request's own text.
	if err := checkNodeRequest(req.Role, req.CommonName, req.CSR, nodeadm); err != nil {
		actionFailed(w, "node sign", "a node", err)
		return
	}
	res, err := withDeadline(r.Context(), func(ctx context.Context) (*nodeCertResult, error) {
		return op(ctx, req.Role, req.CommonName, req.CSR, nodeadm)
	}, nil)
	if err != nil {
		actionFailed(w, "node sign", req.CommonName, err)
		return
	}
	writeCreated(w, struct {
		Certificate string `json:"certificate"`
		Serial      string `json:"serial"`
		NotAfter    string `json:"not_after"`
		CA          string `json:"ca"`
	}{res.PEM, res.Serial, res.NotAfter.UTC().Format(time.RFC3339), res.CA})
}

// POST /internal/nodes/revoke
func (s *inviteService) handleNodeRevoke(w http.ResponseWriter, r *http.Request) {
	nodeadm, ok := s.nodeAuthorized(w, r)
	if !ok {
		return
	}
	op := s.revokeNode
	if op == nil {
		jsonError(w, http.StatusServiceUnavailable, "node revocation unavailable")
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	if !decodeAction(w, r, &req) {
		return
	}
	_, err := withDeadline(r.Context(), func(ctx context.Context) (struct{}, error) {
		return struct{}{}, op(ctx, req.Serial, nodeadm)
	}, nil)
	if err != nil {
		actionFailed(w, "node revoke", "a node", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
