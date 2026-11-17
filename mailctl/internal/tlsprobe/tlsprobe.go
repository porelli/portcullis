// Package tlsprobe reads the certificate one of the mail server's own
// listeners presents (implicit TLS or SMTP STARTTLS), never port 25 of
// anyone else: the certificate check, MailStatus.cert and the TLS reload's
// answer (contract §19.3, §19.8).
package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/smtp"
	"time"
)

// Dialer opens the TCP connection (tests replace it).
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// SPKI is a certificate's TLSA 3 1 1 data: sha256 (hex) of its SPKI.
func SPKI(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

// Leaf is the certificate addr presents. The chain is never judged
// against a root store (staging certificates): callers judge the name, the
// expiry and the SPKI. serverName is the SNI (MAIL_HOSTNAME).
func Leaf(ctx context.Context, dial Dialer, addr, serverName string, starttls bool) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	var st tls.ConnectionState
	if starttls {
		c, err := smtp.NewClient(conn, serverName)
		if err != nil {
			return nil, errors.New("greeting: " + err.Error())
		}
		if err := c.Hello("adapter." + serverName); err != nil {
			return nil, errors.New("EHLO: " + err.Error())
		}
		if err := c.StartTLS(cfg); err != nil {
			return nil, errors.New("STARTTLS: " + err.Error())
		}
		st, _ = c.TLSConnectionState()
		_ = c.Quit()
	} else {
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		st = tc.ConnectionState()
	}
	if len(st.PeerCertificates) == 0 {
		return nil, errors.New("no certificate")
	}
	return st.PeerCertificates[0], nil
}
