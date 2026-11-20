package main

// The nodeadm API (contract §20.2): the internal listener (:8443, TLS 1.3,
// a pki_node client certificate: hub.control every route, frontdoor.control
// GET /v1/cluster only) and the public one behind Traefik (:8080, plain
// HTTP, the /node/ paths). Bodies are strict JSON both ways, ≤ 64 KiB;
// errors are {"error", "kind"?}. Never a token, a secret, a CSR or a key in
// an error, an answer that isn't meant to carry it, or a log line.

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

const (
	maxBody = 64 << 10

	clientHub       = "hub.control"
	clientFrontdoor = "frontdoor.control"

	textMalformed = "the request body is malformed"
	textTooBig    = "the request body is over 64 KiB"
	textForbidden = "this client may not call this route"
	textNotLeader = "this nodeadm isn't the leader: retry"
	textProof     = "the join code's proof doesn't match"
	textUnsigned  = "the join request isn't signed by the node"
	textMesh      = "the node mesh isn't ready yet: retry"
	textRate      = "too many requests: retry in a minute"
	textMode      = "mode must be cooperative or revoke"
	textAdmission = "waiting for the admission params to include this node: retry"
)

// apiError is an answer other than a success: the status, the text (≤ 200
// characters, never a secret) and the kind where a caller branches on it.
type apiError struct {
	Status int
	Text   string
	Kind   string
}

func (e *apiError) Error() string { return e.Text }

func errKind(status int, kind, format string, a ...any) *apiError {
	return &apiError{Status: status, Text: fmt.Sprintf(format, a...), Kind: kind}
}

func errPlain(status int, format string, a ...any) *apiError {
	return &apiError{Status: status, Text: fmt.Sprintf(format, a...)}
}

var (
	errMalformed = errPlain(http.StatusBadRequest, textMalformed)
	errForbidden = errPlain(http.StatusForbidden, textForbidden)
	errNotLeader = errKind(http.StatusServiceUnavailable, "not_leader", textNotLeader)
	errProof     = errKind(http.StatusForbidden, "proof_invalid", textProof)
	errUnsigned  = errPlain(http.StatusForbidden, textUnsigned)
	errMesh      = errKind(http.StatusConflict, "mesh_pending", textMesh)
	errRate      = errPlain(http.StatusTooManyRequests, textRate)
	// errWaitAdmission (ruling R-ADM): the CLI's params-sync hasn't put the
	// node's addresses into the active admission params yet.
	errWaitAdmission = errKind(http.StatusConflict, "waiting_admission", textAdmission)
)

func errUnknownNode(id string) *apiError {
	return errKind(http.StatusNotFound, "unknown_node", "unknown node %s", id)
}

// serverIDRe is the server id grammar (§17.3), also the Kubernetes node name.
var serverIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// writeJSON answers v (Go encoding/json, no HTML escaping).
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		status, buf = http.StatusInternalServerError, *bytes.NewBufferString(`{"error":"internal error"}` + "\n")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// writeErr answers err: an *apiError as itself, anything else a 500 whose
// text names no detail (the detail is logged by the caller, never a secret).
func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		s.log.Error("request failed", "route", r.Method+" "+r.URL.Path, "err", redact(err.Error()))
		ae = errPlain(http.StatusInternalServerError, "nodeadm couldn't complete the request: see its log")
	}
	body := map[string]string{"error": ae.Text}
	if ae.Kind != "" {
		body["kind"] = ae.Kind
	}
	writeJSON(w, ae.Status, body)
}

// readBody reads at most 64 KiB (413 beyond).
func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, errMalformed
	}
	if len(b) > maxBody {
		return nil, errPlain(http.StatusRequestEntityTooLarge, textTooBig)
	}
	return b, nil
}

// decodeStrict decodes b into v: one JSON value, no unknown field, no
// trailing data, every field present (strictFields), else 400.
func decodeStrict(b []byte, v any) error {
	if err := strictJSON(b, v); err != nil {
		return errMalformed
	}
	return nil
}

// clientOf is the verified pki_node client of an internal request: its CN
// when the leaf chains to the pki_node CA for client auth, else "".
func (s *Server) clientOf(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	pool := s.pki.caPool()
	if pool == nil {
		return ""
	}
	leaf := r.TLS.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: s.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return ""
	}
	return leaf.Subject.CommonName
}

// internal wraps an internal route: the client allowed (frontdoor only on
// read routes marked so), then the leader for writes.
func (s *Server) internal(write, frontdoor bool, h func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch s.clientOf(r) {
		case clientHub:
		case clientFrontdoor:
			if !frontdoor {
				s.writeErr(w, r, errForbidden)
				return
			}
		default:
			s.writeErr(w, r, errForbidden)
			return
		}
		if write && !s.leader.Leading() {
			s.writeErr(w, r, errNotLeader)
			return
		}
		if err := h(w, r); err != nil {
			s.writeErr(w, r, err)
		}
	}
}

// public wraps a public route (no client certificate; Traefik in front).
func (s *Server) public(write bool, h func(w http.ResponseWriter, r *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if write && !s.limit.allow(sourceIP(r)) {
			s.writeErr(w, r, errRate)
			return
		}
		if write && !s.leader.Leading() {
			s.writeErr(w, r, errNotLeader)
			return
		}
		if err := h(w, r); err != nil {
			s.writeErr(w, r, err)
		}
	}
}

// InternalHandler serves the internal routes (§20.2).
func (s *Server) InternalHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/codes", s.internal(true, false, s.handleCodes))
	mux.HandleFunc("GET /v1/cluster", s.internal(false, true, s.handleCluster))
	mux.HandleFunc("PUT /v1/nodes/{id}/labels", s.internal(true, false, s.handleLabels))
	mux.HandleFunc("POST /v1/nodes/{id}/cordon", s.internal(true, false, s.handleCordon(true)))
	mux.HandleFunc("POST /v1/nodes/{id}/uncordon", s.internal(true, false, s.handleCordon(false)))
	mux.HandleFunc("POST /v1/nodes/{id}/drain", s.internal(true, false, s.handleDrain))
	mux.HandleFunc("DELETE /v1/nodes/{id}", s.internal(true, false, s.handleRemove))
	return mux
}

// PublicHandler serves the /node/ paths (§20.2 "Public paths").
func (s *Server) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /node/join.sh", s.public(false, s.handleJoinScript))
	mux.HandleFunc("GET /node/{file}", s.public(false, s.handleAgentBinary))
	mux.HandleFunc("POST /node/v1/nonce", s.public(true, s.handleNonce))
	mux.HandleFunc("POST /node/v1/enrol", s.public(true, s.handleEnrol))
	mux.HandleFunc("POST /node/v1/join", s.public(true, s.handleJoin))
	return mux
}

// emptyBody: the body {} exactly (strict: no field).
func emptyBody(r *http.Request) error {
	b, err := readBody(r)
	if err != nil {
		return err
	}
	var e struct{}
	return decodeStrict(b, &e)
}

func nodeID(r *http.Request) (string, error) {
	id := r.PathValue("id")
	if !serverIDRe.MatchString(id) {
		return "", errUnknownNode(strings.ToValidUTF8(trunc(id, 40), "?"))
	}
	return id, nil
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
