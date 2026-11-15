package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/portcullis/wg/internal/link"
	"github.com/portcullis/wg/internal/linkdoc"
	"github.com/portcullis/wg/internal/status"
	"github.com/portcullis/wg/internal/tunnel"
	"github.com/portcullis/wg/internal/vpndoc"
)

// LinkCN is the common name of link's client certificate (pki_node
// role node-link).
const LinkCN = "link.control"

// genkeyTLS writes a new P-256 private key (PKCS#8 PEM) into the existing
// file in place, as genkey: the single-file bind pins the inode.
func genkeyTLS(path string) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.New("no randomness")
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return errors.New("encoding the key failed")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return errors.New("can't open the key file for writing")
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return errors.New("writing the key failed")
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return errors.New("setting the key file's mode failed")
	}
	return f.Close()
}

// linkCSR is a PEM CSR for CN link.control signed with the key at path
// (no SANs: the node-link role takes the bare domain).
func linkCSR(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("the TLS key file is unreadable")
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("the TLS key file holds no PKCS#8 key (run wg genkey-tls)")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("the TLS key file holds no PKCS#8 key (run wg genkey-tls)")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("the TLS key isn't a P-256 key")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: LinkCN}}, ek)
	if err != nil {
		return nil, errors.New("making the CSR failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// loadLinkKey reads the link role's WireGuard key; an empty file is an
// error here (WG_LINK=on without ./portcullis link init).
func loadLinkKey(path string) ([32]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, errors.New("link: the key file is unreadable")
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return [32]byte{}, errors.New("link: no key (run ./portcullis link init)")
	}
	k, err := vpndoc.ParseKey(s)
	if err != nil {
		return [32]byte{}, errors.New("link: the key file holds no WireGuard key")
	}
	return k, nil
}

// linkRole is the running link role (nil when WG_LINK=off).
type linkRole struct {
	l        *link.Link
	gatherer prometheus.Gatherer

	mu       sync.Mutex
	startErr string
	docErr   string
	lnErr    map[string]string
}

func (r *linkRole) setLnErr(which, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if msg == "" {
		delete(r.lnErr, which)
	} else {
		r.lnErr[which] = msg
	}
}

func (r *linkRole) status() *status.Link {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := &status.Link{}
	switch {
	case r.startErr != "":
		st.Role = status.Role{OK: false, Error: r.startErr}
		return st
	case r.docErr != "":
		st.Role = status.Role{OK: false, Error: r.docErr}
	default:
		if ok, msg := r.l.Status(); !ok {
			st.Role = status.Role{OK: false, Error: msg}
		} else if len(r.lnErr) > 0 {
			for _, m := range r.lnErr {
				st.Role = status.Role{OK: false, Error: m}
				break
			}
		} else {
			st.Role = status.Role{OK: true}
		}
	}
	st.Peers = r.l.Peers()
	return st
}

// startLink starts the link role: its own stack on 10.214.0.1 (port
// WG_LINK_PORT, MTU 1380), the link.json watcher, the two CONNECT
// listeners on wg's portcullis-link / portcullis-link-data addresses (never
// in the netstack) and the agent metrics gatherer.
func startLink(ctx context.Context, cfg *config, reg *prometheus.Registry) *linkRole {
	if !cfg.Link {
		return nil
	}
	r := &linkRole{lnErr: map[string]string{}}
	key, err := loadLinkKey(cfg.LinkKey)
	if err != nil {
		r.startErr = err.Error()
		log.Printf("wg: %v", err)
		return r
	}
	stack, err := tunnel.New(tunnel.Config{PrivateKey: key, ListenPort: cfg.LinkPort, Address: linkdoc.LinkAddr, MTU: link.MTU})
	if err != nil {
		r.startErr = err.Error()
		log.Printf("wg: link: %v", err)
		return r
	}
	go func() { <-ctx.Done(); stack.Close() }()
	var doc atomic.Pointer[linkdoc.Doc]
	r.l = link.New(stack, doc.Load)
	reg.MustRegister(r.l.Collectors()...)
	r.gatherer = &link.AgentGatherer{Link: r.l, CertFile: cfg.LinkTLSCert, KeyFile: cfg.LinkTLSKey, CAFile: cfg.LinkCAFile}
	r.docErr = "link.json: not read yet"
	w := &linkdoc.Watcher{Path: cfg.LinkFile, Every: 2 * time.Second}
	go w.Run(ctx, func(d *linkdoc.Doc, err error) {
		doc.Store(d)
		r.mu.Lock()
		if err != nil {
			r.docErr = err.Error()
			log.Printf("wg: %v: the link role has no peers", err)
		} else {
			r.docErr = ""
		}
		r.mu.Unlock()
		r.l.Reload(d)
	})
	go r.listen(ctx, "control", cfg.LinkControl.String(), r.l.ServeControl)
	go r.listen(ctx, "data", cfg.LinkData.String(), r.l.ServeData)
	return r
}

func (r *linkRole) listen(ctx context.Context, which, addr string, serve func(context.Context, net.Listener) error) {
	for {
		ln, err := net.Listen("tcp4", addr)
		if err == nil {
			r.setLnErr(which, "")
			if err := serve(ctx, ln); err != nil && ctx.Err() == nil {
				log.Printf("wg: link %s: %v", which, err)
			}
		} else {
			r.setLnErr(which, "link: listening on the "+which+" address failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
