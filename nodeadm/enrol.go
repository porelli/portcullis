package main

// Node enrolment (contract §20.2, §20.3): POST /v1/codes (the Hub), then on
// the joining node GET /node/join.sh, GET /node/nodeagent-<arch>,
// POST /node/v1/nonce, POST /node/v1/enrol (the proof, then the code burnt,
// then the CSR signed) and POST /node/v1/join (a request signed with the
// node-cluster key; the k3s material only for a verified node whose mesh
// answers and whose RTT and site pass).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	// rejoinWindow / maxJoinTokens: a released node that hasn't registered
	// may ask again (its answer lost) only this long and this often.
	rejoinWindow  = 30 * time.Minute
	maxJoinTokens = 3
	codeTTL       = 15 * time.Minute
	nonceTTL      = 60 * time.Second
	joinNonceTTL  = 5 * time.Minute
	signedSkew    = 60 * time.Second
	clusterDomain = "cluster.portcullis.internal"
	maxNonces     = 4096
	proofLabel    = "portcullis-node-enrol-v1"
)

// The join code v2 (§20.3), its keys in this order.
type joinCodeV2 struct {
	V            int       `json:"v"`
	Kind         string    `json:"kind"`
	Endpoint     string    `json:"endpoint"`
	Servers      []string  `json:"servers"`
	ServerID     string    `json:"server_id"`
	Role         string    `json:"role"`
	Class        string    `json:"class"`
	Site         string    `json:"site"`
	CASHA256     string    `json:"ca_sha256"`
	ScriptSHA256 string    `json:"script_sha256"`
	AgentSHA256  agentSums `json:"agent_sha256"`
	MeshIP       string    `json:"mesh_ip"`
	Secret       string    `json:"secret"`
}

type agentSums struct {
	AMD64 string `json:"amd64"`
	ARM64 string `json:"arm64"`
}

// encodeJoinCode: "pcj2." + base64url (no padding) of the JSON, ≤ 4 KiB.
func encodeJoinCode(c joinCodeV2) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return "", err
	}
	s := "pcj2." + base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	if len(s) > 4096 {
		return "", errPlain(http.StatusBadRequest, "join code: too long")
	}
	return s, nil
}

var classes = []string{"small", "home", "cloud"}

// POST /v1/codes
func (s *Server) handleCodes(w http.ResponseWriter, r *http.Request) error {
	b, err := readBody(r)
	if err != nil {
		return err
	}
	var req CodeReq
	if err := decodeStrict(b, &req); err != nil {
		return err
	}
	switch {
	case !serverIDRe.MatchString(req.ServerID):
		return errPlain(400, "server_id must match ^[a-z][a-z0-9-]{0,30}$")
	case req.Role != "server" && req.Role != "agent":
		return errPlain(400, "role must be server or agent")
	case !slices.Contains(classes, req.Class):
		return errPlain(400, "class must be small, home or cloud")
	case !serverIDRe.MatchString(req.Site):
		return errPlain(400, "site must match ^[a-z][a-z0-9-]{0,30}$")
	case !meshAddrOK(req.MeshIP):
		return errPlain(400, "mesh_ip outside 10.215.0.0/24")
	}
	if err := checkMeshPlan(req.Mesh); err != nil {
		return errPlain(400, "the mesh plan is invalid: %v", err)
	}
	ctx := r.Context()
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	for _, n := range cl {
		if n.Name == req.ServerID {
			return errPlain(409, "node %s is already in the cluster", req.ServerID)
		}
		if n.Mesh == req.MeshIP {
			return errPlain(409, "mesh ip %s is used by %s", req.MeshIP, n.Name)
		}
	}
	servers := serverMeshIPs(cl)
	if len(servers) == 0 {
		return fmt.Errorf("no server has a mesh address")
	}
	ca := s.pki.caSHA256()
	if ca == "" {
		return fmt.Errorf("the pki_node CA isn't known yet")
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, secret); err != nil {
		return err
	}
	code, err := encodeJoinCode(joinCodeV2{V: 2, Kind: "cluster", Endpoint: "https://" + s.cfg.Domain + "/node",
		Servers: servers, ServerID: req.ServerID, Role: req.Role, Class: req.Class, Site: req.Site,
		CASHA256: ca, ScriptSHA256: s.cfg.ScriptSHA256,
		AgentSHA256: agentSums{s.cfg.AgentSHA256["amd64"], s.cfg.AgentSHA256["arm64"]},
		MeshIP:      req.MeshIP, Secret: base64.RawURLEncoding.EncodeToString(secret)})
	if err != nil {
		return err
	}
	key := sha256.Sum256(secret)
	now := s.now()
	err = s.mutate(ctx, func(st *nodeadmState) error {
		if n, ok := st.Nodes[req.ServerID]; ok && n.Serial == "" && !n.Removed && n.JoinedAt == nil {
			delete(st.Nodes, req.ServerID)
		}
		if n, ok := st.Nodes[req.ServerID]; ok {
			if n.Removed {
				return errPlain(409, "node %s is still being removed: retry later", req.ServerID)
			}
			return errPlain(409, "node %s is already enrolled", req.ServerID)
		}
		for id, n := range st.Nodes {
			if n.MeshIP == req.MeshIP {
				return errPlain(409, "mesh ip %s is used by %s", req.MeshIP, id)
			}
		}
		for id, c := range st.Codes {
			if id != req.ServerID && c.MeshIP == req.MeshIP && c.KeySHA256 != "" {
				return errPlain(409, "mesh ip %s is used by %s", req.MeshIP, id)
			}
		}
		// A new code for the id voids the older one.
		st.Codes[req.ServerID] = &codeRecord{KeySHA256: hex.EncodeToString(key[:]), Role: req.Role, Class: req.Class,
			Site: req.Site, MeshIP: req.MeshIP, Ingress: req.Ingress, Storage: req.Storage, Mesh: req.Mesh,
			IssuedAt: now, ExpiresAt: now.Add(codeTTL)}
		return nil
	})
	if err != nil {
		return err
	}
	s.log.Info("join code issued", "server_id", req.ServerID, "role", req.Role, "expires_at", rfc3339(now.Add(codeTTL)))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]string{"code": code, "expires_at": rfc3339(now.Add(codeTTL))})
	return nil
}

// GET /node/join.sh
func (s *Server) handleJoinScript(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(s.cfg.Script)
	return nil
}

// GET /node/nodeagent-{arch}
func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) error {
	arch, ok := strings.CutPrefix(r.PathValue("file"), "nodeagent-")
	path := s.cfg.AgentFiles[arch]
	if !ok || (arch != "amd64" && arch != "arm64") || path == "" {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("the nodeagent binary for %s: %w", arch, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "nodeagent-"+arch, st.ModTime(), f)
	return nil
}

// POST /node/v1/nonce: always a nonce (no oracle), single use, 60 s.
func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request) error {
	b, err := readBody(r)
	if err != nil {
		return err
	}
	var req struct {
		ServerID string `json:"server_id"`
	}
	if err := decodeStrict(b, &req); err != nil {
		return err
	}
	n := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, n); err != nil {
		return err
	}
	nonce := base64.RawURLEncoding.EncodeToString(n)
	now := s.now()
	s.nonceMu.Lock()
	// At most one live nonce per server_id (a new one replaces it), so a
	// flood of requests for other ids can't evict a node's own nonce.
	sid := trunc(req.ServerID, 64)
	for k, v := range s.nonces {
		if now.Sub(v.at) > nonceTTL || v.serverID == sid {
			delete(s.nonces, k)
		}
	}
	if len(s.nonces) >= maxNonces {
		var oldest string
		for k, v := range s.nonces {
			if oldest == "" || v.at.Before(s.nonces[oldest].at) {
				oldest = k
			}
		}
		delete(s.nonces, oldest)
	}
	s.nonces[nonce] = nonceRec{serverID: trunc(req.ServerID, 64), at: now}
	s.nonceMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"nonce": nonce})
	return nil
}

type enrolReq struct {
	ServerID string     `json:"server_id"`
	Nonce    string     `json:"nonce"`
	Proof    string     `json:"proof"`
	CSR      string     `json:"csr"`
	Mesh     MeshReport `json:"mesh"`
}

// refuseEnrol logs why (the kind of nodeadm's own log, never the secret,
// its hash or the proof) and answers proof_invalid.
func (s *Server) refuseEnrol(id, why string) error {
	s.log.Warn("enrolment refused", "server_id", trunc(id, 40), "kind", why)
	return errProof
}

// proofFor is the §20.2 proof: HMAC-SHA256(key = sha256(secret),
// label ‖ nonce ‖ server_id ‖ sha256(SPKI)).
func proofFor(key, nonce []byte, serverID string, spkiSHA [32]byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(proofLabel))
	m.Write(nonce)
	m.Write([]byte(serverID))
	m.Write(spkiSHA[:])
	return m.Sum(nil)
}

// parseNodeCSR: one PEM request, a valid signature, P-256, the subject
// exactly CN=<id>.cluster.portcullis.internal, no alternative names.
func parseNodeCSR(csrPEM, id string) (*x509.CertificateRequest, error) {
	b, rest := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("not one PEM request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("not a signed request")
	}
	if pk, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		return nil, errors.New("not P-256")
	}
	if csr.Subject.CommonName != id+"."+clusterDomain || len(csr.Subject.Names) != 1 ||
		len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0 {
		return nil, errors.New("another subject")
	}
	return csr, nil
}

// POST /node/v1/enrol
func (s *Server) handleEnrol(w http.ResponseWriter, r *http.Request) error {
	b, err := readBody(r)
	if err != nil {
		return err
	}
	var req enrolReq
	if err := decodeStrict(b, &req); err != nil {
		return err
	}
	if checkMeshReport(req.Mesh) != nil {
		return errMalformed
	}
	now := s.now()
	// 1. The nonce: known, unexpired, bound to this server_id; spent here.
	s.nonceMu.Lock()
	nr, ok := s.nonces[req.Nonce]
	delete(s.nonces, req.Nonce)
	s.nonceMu.Unlock()
	if !ok || now.Sub(nr.at) > nonceTTL || nr.serverID != req.ServerID {
		return s.refuseEnrol(req.ServerID, "nonce_invalid")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil {
		return s.refuseEnrol(req.ServerID, "nonce_invalid")
	}
	// 2. The proof (constant time), keyed by the stored hash. The same work
	// (the CSR parsed, an HMAC computed, with a random key when there is no
	// live code) whatever the code's state, so the answer's timing tells an
	// unauthenticated caller nothing; only then the branch.
	st, err := s.load(r.Context())
	if err != nil {
		return err
	}
	c := st.Codes[req.ServerID]
	key := make([]byte, 32)
	live := c != nil && c.KeySHA256 != "" && serverIDRe.MatchString(req.ServerID)
	if live {
		if k, err := hex.DecodeString(c.KeySHA256); err == nil && len(k) == 32 {
			key = k
		} else {
			live = false
		}
	}
	if !live {
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
	}
	var spki [32]byte
	csr, csrErr := parseNodeCSR(req.CSR, req.ServerID)
	if csrErr == nil {
		spki = sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	}
	got, err2 := base64.RawURLEncoding.DecodeString(req.Proof)
	want := proofFor(key, nonce, req.ServerID, spki)
	match := err2 == nil && subtle.ConstantTimeCompare(got, want) == 1
	switch {
	case c == nil || !serverIDRe.MatchString(req.ServerID):
		return s.refuseEnrol(req.ServerID, "unknown_server_id")
	case c.KeySHA256 == "" && c.Used:
		return s.refuseEnrol(req.ServerID, "code_used")
	case c.KeySHA256 == "":
		return s.refuseEnrol(req.ServerID, "code_expired")
	case csrErr != nil:
		return s.refuseEnrol(req.ServerID, "csr_invalid")
	case !live || !match:
		return s.refuseEnrol(req.ServerID, "proof_mismatch")
	}
	// 3. Only now: the expiry and the compare-and-swap that burns the code.
	if now.After(c.ExpiresAt) {
		return s.refuseEnrol(req.ServerID, "code_expired")
	}
	// The node's self-reported addresses (refused, never silently dropped).
	cl, err := s.clusterNodes(r.Context())
	if err != nil {
		return err
	}
	if req.Mesh, err = s.checkReport(req.Mesh, req.ServerID, cl, st); err != nil {
		s.log.Warn("enrolment refused: its report", "server_id", req.ServerID, "why", err.Error())
		return errPlain(http.StatusBadRequest, "the enrolment report is refused: %v", err)
	}
	var code codeRecord
	err = s.mutate(r.Context(), func(st *nodeadmState) error {
		cur := st.Codes[req.ServerID]
		if cur == nil || cur.KeySHA256 != c.KeySHA256 || cur.Used {
			return errProof
		}
		// The LAN address again, against this state (two enrolments racing
		// for one address: the second is refused here).
		if req.Mesh.LAN != nil {
			if ap, err := netip.ParseAddrPort(*req.Mesh.LAN); err == nil {
				if err := lanFree(ap.Addr().String(), req.ServerID, cl, st); err != nil {
					return errPlain(http.StatusBadRequest, "the enrolment report is refused: %v", err)
				}
			}
		}
		cur.Used, cur.KeySHA256 = true, ""
		code = *cur
		st.Nodes[req.ServerID] = &nodeRecord{Role: cur.Role, Class: cur.Class, Site: cur.Site, MeshIP: cur.MeshIP,
			Ingress: cur.Ingress, Storage: cur.Storage, Mesh: req.Mesh, EnrolledAt: now, JoinState: joinEnrolled}
		return nil
	})
	if errors.Is(err, errProof) {
		return s.refuseEnrol(req.ServerID, "code_used")
	}
	if err != nil {
		return err
	}
	s.log.Info("join code used", "server_id", req.ServerID)
	// 4. The CSR signed (node-cluster) through enroll.
	signed, err := s.enroll.Sign(r.Context(), "node-cluster", req.ServerID+"."+clusterDomain, req.CSR)
	if err != nil {
		// The code is burnt; the serial-less record goes so a new code can
		// be issued for the id at once.
		if derr := s.mutate(r.Context(), func(st *nodeadmState) error {
			if n := st.Nodes[req.ServerID]; n != nil && n.Serial == "" && !n.Removed {
				delete(st.Nodes, req.ServerID)
			}
			return nil
		}); derr != nil {
			s.log.Warn("couldn't drop a failed enrolment's record", "server_id", req.ServerID)
		}
		return fmt.Errorf("signing %s's node-cluster certificate: %w", req.ServerID, redactErr(err, req.CSR))
	}
	if err := s.mutate(r.Context(), func(st *nodeadmState) error {
		n := st.Nodes[req.ServerID]
		if n == nil || n.Removed {
			return errVoided
		}
		n.Serial, n.NotAfter = normSerial(signed.Serial), signed.NotAfter
		return nil
	}); err != nil {
		if errors.Is(err, errVoided) {
			// Removed or revoked while enroll signed: the new certificate
			// is revoked at once and no node record keeps it.
			if rerr := s.enroll.Revoke(r.Context(), normSerial(signed.Serial)); rerr != nil {
				s.log.Error("couldn't revoke a voided enrolment's certificate", "server_id", req.ServerID, "serial", normSerial(signed.Serial))
			}
			s.log.Warn("enrolment voided during signing: certificate revoked", "server_id", req.ServerID)
			return errPlain(http.StatusConflict, "node %s was removed during its enrolment", req.ServerID)
		}
		return err
	}
	s.log.Info("node enrolled", "server_id", req.ServerID, "serial", normSerial(signed.Serial))
	s.kick()
	writeJSON(w, http.StatusOK, struct {
		Certificate string   `json:"certificate"`
		CA          string   `json:"ca"`
		NotAfter    string   `json:"not_after"`
		Mesh        MeshPlan `json:"mesh"`
	}{signed.CertPEM, s.pki.caPEMString(), rfc3339(signed.NotAfter), code.Mesh})
	return nil
}

// normSerial: Vault's form, lowercase colon-separated hex.
func normSerial(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func certSerial(c *x509.Certificate) string {
	b := c.SerialNumber.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

// signedCanon is the canonical JSON the node signs (§20.2).
type signedCanon struct {
	ServerID   string `json:"server_id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Time       string `json:"time"`
	Nonce      string `json:"nonce"`
	BodySHA256 string `json:"body_sha256"`
}

func canonicalBytes(c signedCanon) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(c)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// verifySigned checks the signed join request and answers the node's id.
// Any fault is errUnsigned (403, no k3s material).
func (s *Server) verifySigned(r *http.Request, body []byte, st *nodeadmState) (string, error) {
	h := r.Header
	certB64, tm, nonce, sigB64 := h.Get("Portcullis-Node-Cert"), h.Get("Portcullis-Node-Time"), h.Get("Portcullis-Node-Nonce"), h.Get("Portcullis-Node-Signature")
	if certB64 == "" || tm == "" || nonce == "" || sigB64 == "" {
		return "", errUnsigned
	}
	der, err := base64.StdEncoding.DecodeString(certB64)
	if err != nil {
		return "", errUnsigned
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", errUnsigned
	}
	pool := s.pki.caPool()
	now := s.now()
	if pool == nil {
		return "", errUnsigned
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", errUnsigned
	}
	id, ok := strings.CutSuffix(cert.Subject.CommonName, "."+clusterDomain)
	if !ok || !serverIDRe.MatchString(id) {
		return "", errUnsigned
	}
	rec := st.Nodes[id]
	if rec == nil || rec.Removed || rec.Serial == "" || rec.Serial != certSerial(cert) {
		return "", errUnsigned
	}
	t, err := time.Parse(time.RFC3339, tm)
	if err != nil || t.Sub(now) > signedSkew || now.Sub(t) > signedSkew {
		return "", errUnsigned
	}
	if nb, err := base64.RawURLEncoding.DecodeString(nonce); err != nil || len(nb) != 16 {
		return "", errUnsigned
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", errUnsigned
	}
	path := r.RequestURI
	if path == "" {
		path = r.URL.RequestURI()
	}
	sum := sha256.Sum256(body)
	digest := sha256.Sum256(canonicalBytes(signedCanon{id, r.Method, path, tm, nonce, hex.EncodeToString(sum[:])}))
	pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pk, digest[:], sig) {
		return "", errUnsigned
	}
	// The nonce: refused for 5 min after its first use (only a verified
	// request spends one).
	s.nonceMu.Lock()
	defer s.nonceMu.Unlock()
	for k, at := range s.joinNonces {
		if now.Sub(at) > joinNonceTTL {
			delete(s.joinNonces, k)
		}
	}
	if _, used := s.joinNonces[nonce]; used {
		return "", errUnsigned
	}
	s.joinNonces[nonce] = now
	return id, nil
}

type joinReq struct {
	ServerID string         `json:"server_id"`
	RTTms    map[string]int `json:"rtt_ms"`
}

type joinAnswer struct {
	Role      string   `json:"role"`
	ServerURL string   `json:"server_url"`
	Token     string   `json:"token"`
	Flags     []string `json:"flags"`
}

// POST /node/v1/join
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	b, err := readBody(r)
	if err != nil {
		return err
	}
	st, err := s.load(ctx)
	if err != nil {
		return err
	}
	id, err := s.verifySigned(r, b, st)
	if err != nil {
		s.log.Warn("join refused: not signed by an enrolled node")
		return err
	}
	var req joinReq
	if err := decodeStrict(b, &req); err != nil {
		return err
	}
	if req.ServerID != id {
		return errUnsigned
	}
	rec := st.Nodes[id]
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	// The material goes out once per enrolment: once released, never again
	// after the node registered, after rejoinWindow, or past maxJoinTokens
	// (a lost answer may be retried briefly; a stolen key mints nothing).
	if rec.JoinState == joinReleased {
		if clusterNodeByName(cl, id) != nil || rec.JoinedAt == nil || s.now().Sub(*rec.JoinedAt) > rejoinWindow || len(rec.TokenIDs) >= maxJoinTokens {
			s.log.Warn("join refused: the material was given already", "server_id", id)
			return errPlain(http.StatusConflict, "node %s has joined: its k3s material is given once", id)
		}
	}
	// The RTT limits (§20.11, the Hub's CheckRTT): fail closed.
	if err := checkRTT(rec.Role, serverNames(cl, id), req.RTTms); err != nil {
		s.log.Warn("join refused", "server_id", id, "why", err.Error())
		return errPlain(http.StatusConflict, "%s", err.Error())
	}
	// The site gateway (§20.11): a site with no reachable node.
	if err := siteGateway(cl, st, id); err != nil {
		s.log.Warn("join refused", "server_id", id, "why", err.Error())
		return errPlain(http.StatusConflict, "%s", err.Error())
	}
	// The mesh: nodeadm reaches the node's nodeagent over pcmesh.
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	hl, err := s.agents.Health(hctx, id, rec.MeshIP)
	cancel()
	if err != nil || hl.ID != id {
		s.setJoinState(ctx, id, joinMeshPending)
		return errMesh
	}
	// The admission params (ruling R-ADM): the active generation must
	// cover the node's addresses before any k3s material is released.
	var mine []string
	if n := clusterNodeByName(cl, id); n != nil && n.Node.Annotations[annAddresses] != "" {
		mine = nodeAllAddrs(n.Addresses)
	} else {
		mine = nodeAllAddrs(reportAddrs(rec))
	}
	ok, err := s.admitted(ctx, mine)
	if err != nil {
		s.log.Warn("join waits: the active admission params can't be read", "server_id", id, "err", err.Error())
	}
	if !ok {
		s.setJoinState(ctx, id, joinWaitAdmission)
		s.kick()
		return errWaitAdmission
	}
	serverIP := firstServer(cl, id)
	if serverIP == "" {
		return fmt.Errorf("no Ready server with a mesh address")
	}
	serverURL := "https://" + serverIP + ":6443"
	// Released only while the node is still enrolled with this
	// certificate (a removal or revocation meanwhile: no material).
	// A bootstrap token's id is recorded before the token exists, so a
	// revoke can always delete it.
	now := s.now()
	tokID := ""
	if rec.Role != "server" {
		if tokID, err = randString(s.rand, 6); err != nil {
			return err
		}
	}
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		n := st.Nodes[id]
		if n == nil || n.Removed || n.Serial != rec.Serial {
			return errUnsigned
		}
		if n.JoinedAt == nil {
			n.JoinedAt = &now
		}
		if tokID != "" {
			n.TokenIDs = append(n.TokenIDs, tokID)
		}
		n.ServerToken = n.ServerToken || rec.Role == "server"
		n.JoinState, n.WaitingSince = joinReleased, nil
		return nil
	}); err != nil {
		return err
	}
	var token string
	if rec.Role == "server" {
		token, err = s.serverToken(ctx)
	} else {
		token, err = s.bootstrapToken(ctx, tokID)
	}
	if err != nil {
		return err
	}
	flags := joinFlags(rec, id, serverURL)
	s.log.Info("join material issued", "server_id", id, "role", rec.Role, "token_id", tokenID(token))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, joinAnswer{Role: rec.Role, ServerURL: serverURL, Token: token, Flags: flags})
	return nil
}

// The join states (§20.2).
const (
	joinEnrolled      = "enrolled"
	joinMeshPending   = "mesh_pending"
	joinWaitAdmission = "waiting_admission"
	joinReleased      = "released"
)

// setJoinState records a join's state (only a change is written).
func (s *Server) setJoinState(ctx context.Context, id, state string) {
	now := s.now()
	err := s.mutate(ctx, func(st *nodeadmState) error {
		n := st.Nodes[id]
		if n == nil || n.JoinState == state {
			return errNoChange
		}
		n.JoinState = state
		if state == joinWaitAdmission && n.WaitingSince == nil {
			n.WaitingSince = &now
		}
		return nil
	})
	if err != nil && !errors.Is(err, errNoChange) {
		s.log.Warn("couldn't record a join state", "server_id", id, "err", err.Error())
	}
}

var (
	errNoChange = errors.New("no change")
	errVoided   = errors.New("voided")
)

// checkRTT: §20.11's limits, the Hub's texts (site_roles_vectors.json):
// every server in the report, a server ≤ 100 ms, an agent ≤ 250 ms.
func checkRTT(role string, servers []string, rtt map[string]int) error {
	sort.Strings(servers)
	worst := -1
	for _, sv := range servers {
		v, ok := rtt[sv]
		if !ok {
			return fmt.Errorf("no mesh answer from %s: the node can't join", sv)
		}
		worst = max(worst, v)
	}
	if role == "server" && worst > 100 {
		return fmt.Errorf("too far for one cluster: %d ms (servers need 100 ms or less)", worst)
	}
	if role != "server" && worst > 250 {
		return fmt.Errorf("too far for one cluster: %d ms (agents need 250 ms or less)", worst)
	}
	return nil
}

// siteGateway: with 2 or more sites (the joining node's included), the
// node's site needs a node reachable on UDP 51830 (§20.11's refusal).
func siteGateway(cl []clusterNode, st *nodeadmState, id string) error {
	rec := st.Nodes[id]
	sites := map[string]bool{rec.Site: true}
	reachable := rec.Mesh.Public != nil
	for _, n := range cl {
		if n.Name == id {
			continue
		}
		sites[n.Site] = true
		if n.Site == rec.Site && nodeReachable(n, st) {
			reachable = true
		}
	}
	for oid, o := range st.Nodes {
		if oid != id && o.Site == rec.Site && o.Mesh.Public != nil {
			reachable = true
		}
	}
	if len(sites) >= 2 && !reachable {
		return fmt.Errorf("site %s needs one node reachable on UDP 51830 first (a cloud node, or one forwarded port)", rec.Site)
	}
	return nil
}

// nodeReachable: its enrolment reported a public endpoint, or (a node
// nodeadm didn't enrol, the first one) it has a public address.
func nodeReachable(n clusterNode, st *nodeadmState) bool {
	if r := st.Nodes[n.Name]; r != nil {
		return r.Mesh.Public != nil
	}
	return len(n.Addresses.Public) > 0
}

// serverNames: the healthy (Ready) servers, the ones the RTT report must
// cover (site_roles_vectors.json: an unhealthy server needs no answer).
func serverNames(cl []clusterNode, except string) []string {
	var out []string
	for _, n := range cl {
		if n.Role == "server" && n.Ready && n.Name != except {
			out = append(out, n.Name)
		}
	}
	return out
}

// serverMeshIPs: every server's mesh address, in address order.
func serverMeshIPs(cl []clusterNode) []string {
	var as []netip.Addr
	for _, n := range cl {
		if n.Role == "server" && n.Mesh != "" {
			as = append(as, netip.MustParseAddr(n.Mesh))
		}
	}
	slices.SortFunc(as, func(a, b netip.Addr) int { return a.Compare(b) })
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

func clusterNodeByName(cl []clusterNode, id string) *clusterNode {
	for i := range cl {
		if cl[i].Name == id {
			return &cl[i]
		}
	}
	return nil
}

// firstServer: the first Ready server (by name) with a mesh address.
func firstServer(cl []clusterNode, except string) string {
	for _, n := range cl {
		if n.Role == "server" && n.Ready && n.Mesh != "" && n.Name != except {
			return n.Mesh
		}
	}
	return ""
}
