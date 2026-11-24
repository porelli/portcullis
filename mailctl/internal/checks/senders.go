package checks

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/state"
)

// IDSenderRcpt is the provider check that the app mail senders' addresses
// are refused at RCPT (contract §19.14): the base plan's RCPT rule for
// them exists only in stores bootstrapped by a mailctl that has it, so an
// older store takes their mail (and bounces it) until the rule is added by
// hand (the stalwart app page).
const (
	IDSenderRcpt    = "x-sender_rcpt"
	titleSenderRcpt = "App mail senders refuse inbound mail"
	// SenderRcptProbe is the sub-address the check tries next to the
	// address itself.
	SenderRcptProbe = "portcullis-check"
)

// senderRcptCheck asks the MX listener (10025, unauthenticated, null
// sender, never DATA) for the first sender's address and a sub-address
// of it: each must be 550 5.1.1. One that is accepted is a Problem (and a
// log line), one it can't ask is Info.
func senderRcptCheck(ctx context.Context, d Deps, doc *state.Doc) Check {
	c := Check{ID: IDSenderRcpt, Title: titleSenderRcpt}
	senders := doc.SenderList()
	if len(senders) == 0 {
		c.Severity, c.Detail = OK, "no app mail senders"
		return c
	}
	addr := senders[0].Address
	local, dom, _ := strings.Cut(addr, "@")
	probes := []string{addr, local + "+" + SenderRcptProbe + "@" + dom}
	replies, err := rcptProbe(ctx, d, probes)
	if err != nil {
		c.Severity, c.Detail = Info, "the mail server couldn't be asked: "+err.Error()
		return c
	}
	for i, r := range replies {
		if strings.HasPrefix(r, "2") {
			c.Severity = Problem
			c.Detail = fmt.Sprintf("the mail server accepts mail for the app sender address %s (%s): its store has no RCPT rule for app mail senders", probes[i], firstLine(r))
			c.Steps = []string{"Add the senders' RCPT rule to the mail server's store by hand (the stalwart app page, \"Stores bootstrapped before app mail senders\"), or rebuild the store."}
			if d.Logf != nil {
				d.Logf("checks: %s: the mail server accepts mail for %s: the store lacks the senders' RCPT rule (add it by hand)", IDSenderRcpt, probes[i])
			}
			return c
		}
		if !strings.HasPrefix(r, "550") || !strings.Contains(r, "5.1.1") {
			c.Severity, c.Detail = Info, fmt.Sprintf("the mail server answered %s for %s (want 550 5.1.1)", firstLine(r), probes[i])
			return c
		}
	}
	c.Severity, c.Detail = OK, "mail for the app senders' addresses (and their sub-addresses) is refused at RCPT"
	return c
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// rcptProbe: one SMTP session on the MX listener, MAIL FROM:<>, one RCPT
// per address; the replies ("<code> <text>"), then RSET and QUIT.
func rcptProbe(ctx context.Context, d Deps, rcpts []string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	dial := d.Dial
	if dial == nil {
		var nd net.Dialer
		dial = nd.DialContext
	}
	conn, err := dial(ctx, "tcp", net.JoinHostPort(d.Cfg.MailIP, "10025"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tp := textproto.NewConn(conn)
	tp.Reader = *textproto.NewReader(bufio.NewReader(conn))
	read := func(want int) (string, error) {
		code, msg, err := tp.ReadResponse(want)
		if err != nil && code == 0 {
			return "", err
		}
		return fmt.Sprintf("%d %s", code, msg), nil
	}
	cmd := func(want int, f string, a ...any) (string, error) {
		if err := tp.PrintfLine(f, a...); err != nil {
			return "", err
		}
		return read(want)
	}
	if r, err := read(220); err != nil || !strings.HasPrefix(r, "220") {
		return nil, fmt.Errorf("greeting: %q %v", r, err)
	}
	host := d.Cfg.Hostname
	if host == "" {
		host = "localhost.localdomain"
	}
	if r, err := cmd(250, "EHLO %s", host); err != nil || !strings.HasPrefix(r, "250") {
		return nil, fmt.Errorf("EHLO: %q %v", firstLine(r), err)
	}
	if r, err := cmd(250, "MAIL FROM:<>"); err != nil || !strings.HasPrefix(r, "250") {
		return nil, fmt.Errorf("MAIL FROM: %q %v", firstLine(r), err)
	}
	var out []string
	for _, a := range rcpts {
		r, err := cmd(250, "RCPT TO:<%s>", a)
		if err != nil {
			return nil, fmt.Errorf("RCPT: %v", err)
		}
		out = append(out, r)
	}
	_, _ = cmd(250, "RSET")
	_, _ = cmd(221, "QUIT")
	return out, nil
}
