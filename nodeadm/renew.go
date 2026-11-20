package main

// Certificate renewal in two phases (Task 9 rulings I4 and the re-review):
//
// POST /node/v1/renew, signed like /node/v1/join with the node's current
// certificate (the recorded serial), carries a CSR for
// <id>.cluster.portcullis.internal; the current certificate must be valid
// (5 min skew) and in the last ⅔ of its life. enroll signs a new
// node-cluster certificate (same CN, the role's TTL), recorded as the
// node's pending Renewal; nothing is revoked: until the node confirms,
// both certificates are valid (verifySigned, the nodeagent pin). The same
// CSR again (by sha256) while that renewal is pending answers the same
// certificate (a lost answer is retried without a new signature); another
// CSR supersedes it, and the superseded new certificate is queued for
// revocation.
//
// POST /node/v1/renew/confirm, signed with the NEW certificate, makes it
// the recorded one and queues the old serial in PendingRevokes. A renewal
// not confirmed within renewConfirmTTL is dropped by reconcile and its new
// certificate queued for revocation. Both are rate-limited like every
// public write.
//
// (The public paths come through the edge router, which terminates TLS:
// "authenticated with the new certificate" is the signed-request proof of
// its key, the same as join.)

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"time"
)

const renewConfirmTTL = 24 * time.Hour

type renewReq struct {
	ServerID string `json:"server_id"`
	CSR      string `json:"csr"`
}

type renewConfirmReq struct {
	ServerID string `json:"server_id"`
}

var (
	errNotDue    = errPlain(http.StatusConflict, "the certificate isn't due for renewal yet: renew in the last two thirds of its life")
	errRenewed   = errPlain(http.StatusConflict, "the certificate was renewed by another request")
	errRenewCSR  = errPlain(http.StatusBadRequest, "the renewal CSR must be for this node's name, signed by its key")
	errRenewBody = errPlain(http.StatusBadRequest, "the renewal request is malformed")
	errNoRenewal = errPlain(http.StatusConflict, "no renewal of this certificate is pending")
)

type renewAnswer struct {
	Certificate string `json:"certificate"`
	CA          string `json:"ca"`
	NotAfter    string `json:"not_after"`
}

// signedCert: the request's certificate (verifySigned checked it).
func signedCert(r *http.Request) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(r.Header.Get("Portcullis-Node-Cert"))
	if err != nil {
		return nil, errUnsigned
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errUnsigned
	}
	return c, nil
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) error {
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
		s.log.Warn("renewal refused: not signed by an enrolled node")
		return err
	}
	var req renewReq
	if err := decodeStrict(b, &req); err != nil {
		return errRenewBody
	}
	if req.ServerID != id {
		return errUnsigned
	}
	cur, err := signedCert(r)
	if err != nil {
		return err
	}
	rec := st.Nodes[id]
	oldSerial := certSerial(cur)
	if oldSerial != rec.Serial {
		// Signed with the pending renewal's certificate: confirm it instead.
		return errPlain(http.StatusConflict, "this certificate is a pending renewal: confirm it (POST /node/v1/renew/confirm)")
	}
	sum := sha256.Sum256([]byte(req.CSR))
	csrSum := hex.EncodeToString(sum[:])
	w.Header().Set("Cache-Control", "no-store")
	// The same CSR while its renewal is pending: the same answer.
	if p := rec.Renewal; p != nil && p.CSRSHA256 == csrSum {
		s.log.Info("node certificate renewal answered again (pending)", "server_id", id, "serial", p.Serial)
		writeJSON(w, http.StatusOK, renewAnswer{p.CertPEM, s.pki.caPEMString(), rfc3339(p.NotAfter)})
		return nil
	}
	life := cur.NotAfter.Sub(cur.NotBefore)
	if s.now().Before(cur.NotBefore.Add(life / 3)) {
		return errNotDue
	}
	blk, _ := pem.Decode([]byte(req.CSR))
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return errRenewCSR
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != id+"."+clusterDomain ||
		len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) > 0 || len(csr.DNSNames) > 1 ||
		(len(csr.DNSNames) == 1 && csr.DNSNames[0] != id+"."+clusterDomain) {
		return errRenewCSR
	}
	signed, err := s.enroll.Sign(ctx, "node-cluster", id+"."+clusterDomain, req.CSR)
	if err != nil {
		return redactErr(err, req.CSR)
	}
	newSerial := normSerial(signed.Serial)
	var superseded string
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		n := st.Nodes[id]
		if n == nil || n.Removed {
			return errUnsigned
		}
		if n.Serial != oldSerial {
			return errRenewed
		}
		if p := n.Renewal; p != nil {
			if p.CSRSHA256 == csrSum {
				// A concurrent identical request won: this one's certificate
				// goes, the pending one answers.
				return errRenewed
			}
			superseded = p.Serial
			st.queueRevoke(id, p.Serial, s.now())
		}
		n.Renewal = &renewal{CSRSHA256: csrSum, Serial: newSerial, CertPEM: signed.CertPEM, NotAfter: signed.NotAfter, IssuedAt: s.now()}
		return nil
	}); err != nil {
		// The new certificate is never kept: queued for revocation.
		if qerr := s.queueRevoke(context.WithoutCancel(ctx), id, newSerial); qerr != nil {
			s.log.Error("couldn't queue a refused renewal's certificate for revocation", "server_id", id, "serial", newSerial)
		}
		_ = s.revokePending(context.WithoutCancel(ctx), id)
		if errors.Is(err, errRenewed) {
			if st, lerr := s.load(ctx); lerr == nil {
				if n := st.Nodes[id]; n != nil && n.Serial == oldSerial && n.Renewal != nil && n.Renewal.CSRSHA256 == csrSum {
					p := n.Renewal
					writeJSON(w, http.StatusOK, renewAnswer{p.CertPEM, s.pki.caPEMString(), rfc3339(p.NotAfter)})
					return nil
				}
			}
		}
		var ae *apiError
		if errors.As(err, &ae) {
			s.log.Warn("renewal refused", "server_id", id, "why", ae.Text)
		}
		return err
	}
	if superseded != "" {
		s.log.Info("an unconfirmed renewal superseded: its certificate queued for revocation", "server_id", id, "serial", superseded)
		_ = s.revokePending(context.WithoutCancel(ctx), id)
	}
	s.log.Info("node certificate renewed (pending confirm)", "server_id", id, "serial", newSerial, "current", oldSerial)
	writeJSON(w, http.StatusOK, renewAnswer{signed.CertPEM, s.pki.caPEMString(), rfc3339(signed.NotAfter)})
	return nil
}

// POST /node/v1/renew/confirm: signed with the renewed certificate.
func (s *Server) handleRenewConfirm(w http.ResponseWriter, r *http.Request) error {
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
		s.log.Warn("renewal confirm refused: not signed by an enrolled node")
		return err
	}
	var req renewConfirmReq
	if err := decodeStrict(b, &req); err != nil {
		return errRenewBody
	}
	if req.ServerID != id {
		return errUnsigned
	}
	c, err := signedCert(r)
	if err != nil {
		return err
	}
	sr := certSerial(c)
	var old string
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		n := st.Nodes[id]
		if n == nil || n.Removed {
			return errUnsigned
		}
		if n.Serial == sr && n.Renewal == nil {
			old = "" // confirmed already (a lost answer): the same answer
			return nil
		}
		if n.Renewal == nil || n.Renewal.Serial != sr {
			return errNoRenewal
		}
		old = n.Serial
		n.Serial, n.NotAfter, n.Renewal = sr, n.Renewal.NotAfter, nil
		st.queueRevoke(id, old, s.now())
		return nil
	}); err != nil {
		return err
	}
	if old != "" {
		s.log.Info("node certificate renewal confirmed: the previous one queued for revocation", "server_id", id, "serial", sr, "previous", old)
		if err := s.revokePending(context.WithoutCancel(ctx), id); err != nil {
			s.log.Warn("the renewed-away certificate isn't revoked yet (retried)", "server_id", id)
		}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// expireRenewals (reconcile): an unconfirmed renewal older than
// renewConfirmTTL goes; its new certificate is queued for revocation.
func (s *Server) expireRenewals(ctx context.Context, st *nodeadmState) {
	now := s.now()
	var due []string
	for id, n := range st.Nodes {
		if n.Renewal != nil && now.Sub(n.Renewal.IssuedAt) > renewConfirmTTL {
			due = append(due, id)
		}
	}
	if len(due) == 0 {
		return
	}
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		for _, id := range due {
			if n := st.Nodes[id]; n != nil && n.Renewal != nil && now.Sub(n.Renewal.IssuedAt) > renewConfirmTTL {
				st.queueRevoke(id, n.Renewal.Serial, now)
				n.Renewal = nil
			}
		}
		return nil
	}); err != nil {
		s.log.Warn("couldn't expire unconfirmed renewals", "err", err.Error())
		return
	}
	for _, id := range due {
		s.log.Warn("an unconfirmed renewal expired: its certificate queued for revocation", "server_id", id)
	}
}
