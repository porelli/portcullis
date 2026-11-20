package main

// POST /node/v1/renew (Task 9 ruling I4): a node renews its node-cluster
// certificate. The request is signed like /node/v1/join (verifySigned:
// the current certificate, chained to pki_node, the recorded serial, a
// non-removed node, ±60 s, a single-use nonce) and carries a CSR for
// <id>.cluster.portcullis.internal. Accepted only while the current
// certificate is valid and in the last ⅔ of its life; enroll signs a new
// node-cluster certificate (same CN, same role TTL); the record's serial
// moves to it in a compare-and-swap on the old one, and the old serial is
// revoked. Rate-limited like every public write.

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
)

type renewReq struct {
	ServerID string `json:"server_id"`
	CSR      string `json:"csr"`
}

var (
	errNotDue    = errPlain(http.StatusConflict, "the certificate isn't due for renewal yet: renew in the last two thirds of its life")
	errRenewed   = errPlain(http.StatusConflict, "the certificate was renewed by another request")
	errRenewCSR  = errPlain(http.StatusBadRequest, "the renewal CSR must be for this node's name, signed by its key")
	errRenewBody = errPlain(http.StatusBadRequest, "the renewal request is malformed")
)

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
	// The current certificate (verifySigned checked it): its life.
	der, _ := base64.StdEncoding.DecodeString(r.Header.Get("Portcullis-Node-Cert"))
	cur, err := x509.ParseCertificate(der)
	if err != nil {
		return errUnsigned
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
	oldSerial := certSerial(cur)
	signed, err := s.enroll.Sign(ctx, "node-cluster", id+"."+clusterDomain, req.CSR)
	if err != nil {
		return redactErr(err, req.CSR)
	}
	newSerial := normSerial(signed.Serial)
	if err := s.mutate(ctx, func(st *nodeadmState) error {
		n := st.Nodes[id]
		if n == nil || n.Removed {
			return errUnsigned
		}
		if n.Serial != oldSerial {
			return errRenewed
		}
		n.Serial, n.NotAfter = newSerial, signed.NotAfter
		return nil
	}); err != nil {
		// The new certificate is never kept: revoked at once, or queued and
		// retried by reconcile.
		if rerr := s.enroll.Revoke(ctx, newSerial); rerr != nil {
			s.log.Warn("a refused renewal's certificate isn't revoked yet (retried)", "server_id", id, "serial", newSerial)
			if qerr := s.queueRevoke(context.WithoutCancel(ctx), id, newSerial); qerr != nil {
				s.log.Error("couldn't queue a refused renewal's certificate for revocation", "server_id", id, "serial", newSerial)
			}
		}
		var ae *apiError
		if errors.As(err, &ae) {
			s.log.Warn("renewal refused", "server_id", id, "why", ae.Text)
		}
		return err
	}
	if err := s.enroll.Revoke(ctx, oldSerial); err != nil {
		// The record no longer accepts it (the serial moved); the revoke is
		// retried by reconcile (PendingRevoke).
		s.log.Warn("the renewed certificate's predecessor isn't revoked yet (retried)", "server_id", id, "serial", oldSerial)
		if qerr := s.queueRevoke(context.WithoutCancel(ctx), id, oldSerial); qerr != nil {
			s.log.Error("couldn't queue a renewed-away certificate for revocation", "server_id", id, "serial", oldSerial)
		}
	}
	s.log.Info("node certificate renewed", "server_id", id, "serial", newSerial, "previous", oldSerial)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, struct {
		Certificate string `json:"certificate"`
		CA          string `json:"ca"`
		NotAfter    string `json:"not_after"`
	}{signed.CertPEM, s.pki.caPEMString(), rfc3339(signed.NotAfter)})
	return nil
}
