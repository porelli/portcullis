package checks

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/tlsprobe"
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
func SPKI(c *x509.Certificate) string { return tlsprobe.SPKI(c) }

// leafAt is the certificate one of mail's own listeners presents.
func leafAt(ctx context.Context, d Deps, port int, starttls bool) (*x509.Certificate, error) {
	return tlsprobe.Leaf(ctx, d.Dial, net.JoinHostPort(d.Cfg.MailIP, fmt.Sprint(port)), d.Cfg.Hostname, starttls)
}

// certCheck: every TLS listener presents MAIL_HOSTNAME's certificate, not
// expired (a Warning within 14 days), with an SPKI in the document's
// tls.spki_sha256 (core's current and next key, contract §19.8). Only those are definite failures (outcome "fail"); a
// listener that can't be reached or a handshake / timeout error is
// "unknown", never a failure (security ruling). It has its own deadline.
func certCheck(ctx context.Context, d Deps, want []string) Check {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	c := Check{ID: "cert", Severity: OK, outcome: "pass"}
	unknown := 0
	now := d.now()
	var notes []string
	if len(want) == 0 {
		unknown++
		notes = append(notes, "the mail certificate's keys aren't known yet (no accepted document)")
	}
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
		if len(want) > 0 && !slices.Contains(want, SPKI(leaf)) {
			raise(Problem)
			notes = append(notes, fmt.Sprintf("%s (%d): the key isn't the mail certificate's (core's mail-cert)", p.Name, p.Port))
		}
		if soonest.IsZero() || leaf.NotAfter.Before(soonest) {
			soonest = leaf.NotAfter
		}
	}
	if len(notes) == 0 {
		c.Detail = fmt.Sprintf("%s's certificate on 465 / 993 / 25 / 587, valid until %s", d.Cfg.Hostname, soonest.UTC().Format(time.RFC3339))
		c.Detail += ", with the mail certificate's key"
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
	c.Steps = []string{"Run ./portcullis mail rotate on the host: it renews the certificate below 30 days and reloads the mail server."}
	return c
}
