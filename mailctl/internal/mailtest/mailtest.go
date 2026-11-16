// Package mailtest is `mailctl test --to <addr>` (contract §19.10): one
// message from the first postmaster account's own address, submitted on
// mail's submission listener (10587, STARTTLS, the certificate pinned) so
// Stalwart signs it with the primary domain's DKIM keys like any person's
// mail. A short-lived mail password (send only, pinned to mailctl's /32)
// exists only for the submission and is destroyed after it, also on error.
package mailtest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// Sender sends the test.
type Sender struct {
	C          *stalwart.Client
	Doc        *state.Doc
	SubmitAddr string // mail's 10587
	MailctlIP  netip.Addr
	TLS        func(now time.Time) *tls.Config
	Now        func() time.Time
	// Dial is the submission connection (tests).
	Dial func(ctx context.Context, addr string) (net.Conn, error)
}

// Result is what the CLI prints.
type Result struct {
	From      string `json:"from"`
	To        string `json:"to"`
	MessageID string `json:"message_id"`
	Queued    string `json:"queued"` // the server's answer to DATA (its queue id)
}

// ErrNoPostmaster: the document names no postmaster account.
var ErrNoPostmaster = errors.New("no postmaster account in the applied document (Settings → Mail)")

// Message is the test message.
func Message(from, to, msgID string, now time.Time) string {
	return strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: Portcullis mail test",
		"Date: " + now.UTC().Format(time.RFC1123Z),
		"Message-ID: <" + msgID + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"This is a test message from your Portcullis mail server.",
		"",
		"Open its headers (\"Show original\" / \"View source\") and check the",
		"Authentication-Results header: dkim=pass, spf=pass and dmarc=pass mean",
		"receivers can verify mail from this server.",
		"",
	}, "\r\n")
}

// Send submits the test to `to`.
func (s *Sender) Send(ctx context.Context, to string) (res Result, err error) {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if s.Doc == nil || len(s.Doc.Postmaster) == 0 {
		return res, ErrNoPostmaster
	}
	user := s.Doc.Postmaster[0]
	from := strings.ToLower(user + "@" + s.Doc.PrimaryDomain)
	live, err := reconcile.Read(ctx, s.C)
	if err != nil {
		return res, err
	}
	id := reconcile.FindAccount(live, s.Doc, user)
	if id == "" {
		return res, fmt.Errorf("the postmaster account %s isn't in Stalwart yet", user)
	}
	r, err := s.C.As(id).Set(ctx, "AppPassword", map[string]any{"t": map[string]any{
		"description": "portcullis mail test",
		"expiresAt":   now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
		"allowedIps":  map[string]bool{netip.PrefixFrom(s.MailctlIP, 32).String(): true},
		"permissions": map[string]any{"@type": "Replace", "permissions": map[string]bool{"authenticate": true, "emailSend": true}},
	}}, nil, nil)
	if err == nil {
		err = r.Failed()
	}
	if err != nil {
		return res, fmt.Errorf("x:AppPassword/set: %w", err)
	}
	pwID := r.CreatedID("t")
	var secret string
	_ = json.Unmarshal(r.Created["t"]["secret"], &secret)
	defer func() {
		if pwID == "" {
			return
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		dr, derr := s.C.As(id).Set(cctx, "AppPassword", nil, nil, []string{pwID})
		if derr == nil {
			derr = dr.Failed()
		}
		if derr != nil {
			err = errors.Join(err, fmt.Errorf("the test password %s could not be destroyed: %w", pwID, derr))
		}
	}()
	if pwID == "" || secret == "" {
		return res, errors.New("x:AppPassword/set: no id or secret in the answer")
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	res = Result{From: from, To: to, MessageID: "portcullis-test-" + hex.EncodeToString(b) + "@" + s.Doc.PrimaryDomain}
	dial := s.Dial
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	conn, err := dial(ctx, s.SubmitAddr)
	if err != nil {
		return res, fmt.Errorf("submission: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClientStartTLS(conn, s.TLS(now()))
	if err != nil {
		conn.Close()
		return res, fmt.Errorf("submission STARTTLS: %w", err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", from, secret)); err != nil {
		return res, fmt.Errorf("submission AUTH: %w", err)
	}
	secret = ""
	if err := c.Mail(from, nil); err != nil {
		return res, fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to, nil); err != nil {
		return res, fmt.Errorf("RCPT TO %s: %w", to, err)
	}
	w, err := c.Data()
	if err != nil {
		return res, fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write([]byte(Message(from, to, res.MessageID, now()))); err != nil {
		return res, fmt.Errorf("DATA: %w", err)
	}
	dr, err := w.CloseWithResponse()
	if err != nil {
		return res, fmt.Errorf("DATA: %w", err)
	}
	res.Queued = dr.StatusText
	_ = c.Quit()
	return res, nil
}

func init() {
	stalwart.Used = append(stalwart.Used,
		stalwart.Use{Object: "x:AppPassword", Field: "description"}, stalwart.Use{Object: "x:AppPassword", Field: "expiresAt"},
		stalwart.Use{Object: "x:AppPassword", Field: "allowedIps"}, stalwart.Use{Object: "x:AppPassword", Field: "permissions"},
		stalwart.Use{Enum: "Permission", Value: "emailSend"},
	)
}
