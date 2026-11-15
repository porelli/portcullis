package checks

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"slices"
	"strings"
	"time"
)

// certPorts are mail's own listeners (portcullis-mail; never port 25).
var certPorts = []struct {
	Port     int
	StartTLS bool
	Name     string
}{{10465, false, "submissions"}, {10993, false, "imaps"}, {10025, true, "smtp (STARTTLS)"}, {10587, true, "submission (STARTTLS)"}}

// CertWarnDays: within this the certificate is a Warning.
const CertWarnDays = 14

// SPKI is a certificate's TLSA 3 1 1 data.
func SPKI(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

func (d Deps) dial(ctx context.Context, addr string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, "tcp", addr)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, "tcp", addr)
}

// leafAt is the certificate one listener presents.
func leafAt(ctx context.Context, d Deps, port int, starttls bool) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := d.dial(ctx, net.JoinHostPort(d.Cfg.MailIP, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// The chain is judged below (name, expiry, TLSA), not against a root
	// store: the server presents what mail-cert issued.
	cfg := &tls.Config{ServerName: d.Cfg.Hostname, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	var st tls.ConnectionState
	if starttls {
		c, err := smtp.NewClient(conn, d.Cfg.Hostname)
		if err != nil {
			return nil, fmt.Errorf("greeting: %w", err)
		}
		if err := c.Hello("mailctl." + d.Cfg.Hostname); err != nil {
			return nil, fmt.Errorf("EHLO: %w", err)
		}
		if err := c.StartTLS(cfg); err != nil {
			return nil, fmt.Errorf("STARTTLS: %w", err)
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
		return nil, fmt.Errorf("no certificate")
	}
	return st.PeerCertificates[0], nil
}

// certCheck: every TLS listener presents MAIL_HOSTNAME's certificate, not
// expired (a Warning within 14 days), and with TLSA published its SPKI is
// one of them. Only those are definite failures (outcome "fail"); a
// listener that can't be reached or a handshake / timeout error is
// "unknown", never a failure (security ruling). It has its own deadline.
func certCheck(ctx context.Context, d Deps) Check {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	c := Check{ID: "cert", Severity: OK, outcome: "pass"}
	unknown := 0
	now := d.now()
	tlsaWant := d.M.TLSAWanted()
	var notes []string
	var soonest time.Time
	raise := func(sev string) {
		if sevRank[sev] > sevRank[c.Severity] {
			c.Severity = sev
		}
	}
	for _, p := range certPorts {
		leaf, err := leafAt(ctx, d, p.Port, p.StartTLS)
		if err != nil {
			unknown++
			notes = append(notes, fmt.Sprintf("%s (%d) couldn't be checked: %v", p.Name, p.Port, err))
			continue
		}
		if err := leaf.VerifyHostname(d.Cfg.Hostname); err != nil {
			raise(Problem)
			notes = append(notes, fmt.Sprintf("%s (%d): the certificate isn't for %s", p.Name, p.Port, d.Cfg.Hostname))
		}
		switch left := leaf.NotAfter.Sub(now); {
		case left <= 0:
			raise(Problem)
			notes = append(notes, fmt.Sprintf("%s (%d): the certificate expired %s", p.Name, p.Port, leaf.NotAfter.UTC().Format(time.RFC3339)))
		case left < CertWarnDays*24*time.Hour:
			raise(Warning)
			notes = append(notes, fmt.Sprintf("%s (%d): the certificate expires %s", p.Name, p.Port, leaf.NotAfter.UTC().Format(time.RFC3339)))
		}
		if len(tlsaWant) > 0 && !slices.Contains(tlsaWant, SPKI(leaf)) {
			raise(Problem)
			notes = append(notes, fmt.Sprintf("%s (%d): the key doesn't match the published TLSA record", p.Name, p.Port))
		}
		if soonest.IsZero() || leaf.NotAfter.Before(soonest) {
			soonest = leaf.NotAfter
		}
	}
	if len(notes) == 0 {
		c.Detail = fmt.Sprintf("%s's certificate on 465 / 993 / 25 / 587, valid until %s", d.Cfg.Hostname, soonest.UTC().Format(time.RFC3339))
		if len(tlsaWant) > 0 {
			c.Detail += ", matching TLSA"
		}
		return c
	}
	c.Detail = strings.Join(notes, "; ")
	switch {
	case c.Severity == Problem:
		c.outcome = "fail"
	case unknown > 0:
		c.outcome = "unknown"
		if c.Severity == OK {
			c.Severity = Info
		}
	}
	c.Steps = []string{"Run ./portcullis mail cert (it renews below 30 days and reloads Stalwart); ./portcullis mail rotate also republishes TLSA."}
	return c
}
