// Package export streams a former account's mailbox as mbox (M5): mailctl
// lifts `authenticate` on that former account only, makes a one-hour app
// password limited to IMAP reading and to its own portcullis-mail address,
// reads every mailbox over IMAPS, and destroys the password and disables
// the account again, also on error. CLI only, never through the Hub.
package export

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// ErrNotFormer: the id isn't a parked former account (exit 2).
var ErrNotFormer = errors.New("not a former account (former-<uuid> on the parking domain)")

var reFormer = regexp.MustCompile(`^former-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Exporter holds what an export needs.
type Exporter struct {
	C          *stalwart.Client
	IMAPAddr   string     // mail's portcullis-mail address :10993
	ServerName string     // MAIL_HOSTNAME (SNI)
	MailctlIP  netip.Addr // the password is pinned to it
	Now        func() time.Time
	// SPKI are the mail certificate's key pins (sha256 of the leaf's
	// SubjectPublicKeyInfo, hex), as mail-cert reported them (`mailctl
	// rotate` stores them): the leaf Stalwart presents must be one of them,
	// name MAIL_HOSTNAME and be valid now. No pin, no export.
	SPKI []string
	// DataDir is mailctl_data: the export password is recorded there
	// (state.RecordExport) so the reconcile sweep can tell it from a
	// look-alike.
	DataDir string
	// Dial connects (tests replace it).
	Dial func(addr string, cfg *tls.Config) (*imapclient.Client, error)
}

func setErr(obj string, r stalwart.SetResult, err error) error {
	if err != nil {
		return fmt.Errorf("x:%s/set: %w", obj, err)
	}
	if e := r.Failed(); e != nil {
		return fmt.Errorf("x:%s/set: %w", obj, e)
	}
	return nil
}

// Export writes the former account's every message to w; it returns the
// number of messages.
func (e *Exporter) Export(ctx context.Context, formerID string, w io.Writer) (n int, err error) {
	if !reFormer.MatchString(formerID) {
		return 0, ErrNotFormer
	}
	live, err := reconcile.Read(ctx, e.C)
	if err != nil {
		return 0, err
	}
	id := reconcile.FormerAccount(live, formerID)
	if id == "" {
		return 0, ErrNotFormer
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	// The restore is registered before anything changes: whatever fails
	// after this point (the lift itself included), the export password
	// goes and the account is disabled again. The reconciler re-asserts
	// Disabled on every parked account on each pass as well.
	var pwID string
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if pwID != "" {
			r, derr := e.C.As(id).Set(cctx, "AppPassword", nil, nil, []string{pwID})
			if derr := setErr("AppPassword", r, derr); derr != nil {
				err = errors.Join(err, derr)
			}
			// Always: an unrecorded password is a stray to the sweep.
			if derr := state.RemoveExport(e.DataDir, pwID); derr != nil {
				err = errors.Join(err, derr)
			}
		}
		r, derr := e.C.Set(cctx, "Account", nil, map[string]map[string]any{id: {"permissions": reconcile.Disabled}}, nil)
		if derr := setErr("Account", r, derr); derr != nil {
			err = errors.Join(err, fmt.Errorf("could not disable %s again: %w", formerID, derr))
		}
	}()
	if len(e.SPKI) == 0 {
		return 0, errors.New("the mail certificate's key isn't known to mailctl yet (run ./portcullis mail rotate)")
	}
	perms := map[string]bool{}
	for _, p := range stalwart.ExportPermissions {
		perms[p] = true
	}
	if e.DataDir == "" {
		return 0, errors.New("export: no data directory to record the export in")
	}
	expires := now().Add(reconcile.ExportLifetime).UTC().Truncate(time.Second)
	r, err := e.C.As(id).Set(ctx, "AppPassword", map[string]any{"x": map[string]any{
		"description": reconcile.ExportDescription,
		"expiresAt":   expires.Format(time.RFC3339),
		"allowedIps":  map[string]bool{netip.PrefixFrom(e.MailctlIP, 32).String(): true},
		"permissions": map[string]any{"@type": "Replace", "permissions": perms},
	}}, nil, nil)
	if err := setErr("AppPassword", r, err); err != nil {
		return 0, err
	}
	pwID = r.CreatedID("x")
	var secret string
	_ = json.Unmarshal(r.Created["x"]["secret"], &secret)
	if pwID == "" || secret == "" {
		return 0, errors.New("x:AppPassword/set: no id or secret in the answer")
	}
	// Recorded before the lift: the sweep spares only a recorded export.
	if err := state.RecordExport(e.DataDir, state.ExportRecord{AccountID: id, PasswordID: pwID, ExpiresAt: expires}); err != nil {
		return 0, err
	}
	// Lifted only once the password exists: the reconciler sees the valid
	// export password and leaves the lift alone (final review L8).
	// Lift authenticate only (sending and receiving stay off).
	lifted := map[string]any{"@type": "Merge", "enabledPermissions": map[string]bool{},
		"disabledPermissions": map[string]bool{"emailSend": true, "emailReceive": true}}
	r, err = e.C.Set(ctx, "Account", nil, map[string]map[string]any{id: {"permissions": lifted}}, nil)
	if err := setErr("Account", r, err); err != nil {
		return 0, err
	}
	dial := e.Dial
	if dial == nil {
		dial = func(addr string, cfg *tls.Config) (*imapclient.Client, error) {
			return imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: cfg})
		}
	}
	c, err := dial(e.IMAPAddr, e.tlsConfig(now()))
	if err != nil {
		return 0, fmt.Errorf("imap: %w", err)
	}
	defer c.Close()
	if err := c.Login(formerID+"@"+state.ParkingDomain, secret).Wait(); err != nil {
		return 0, fmt.Errorf("imap login: %w", err)
	}
	secret = ""
	boxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		return 0, fmt.Errorf("imap list: %w", err)
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	for _, b := range boxes {
		if hasAttr(b.Attrs, imap.MailboxAttrNoSelect) {
			continue
		}
		sel, err := c.Select(b.Mailbox, &imap.SelectOptions{ReadOnly: true}).Wait()
		if err != nil {
			return n, fmt.Errorf("imap examine %s: %w", b.Mailbox, err)
		}
		// The UIDs and dates in batches (small), then one message at a
		// time, its body streamed straight into the mbox through a
		// bounded buffer (final review M5: never a whole message, let
		// alone a batch of them, in memory).
		for start := uint32(1); start <= sel.NumMessages; start += 500 {
			end := min(start+499, sel.NumMessages)
			var set imap.SeqSet
			set.AddRange(start, end)
			heads, err := c.Fetch(set, &imap.FetchOptions{UID: true, InternalDate: true}).Collect()
			if err != nil {
				return n, fmt.Errorf("imap fetch %s: %w", b.Mailbox, err)
			}
			for _, h := range heads {
				if err := streamOne(c, h.UID, h.InternalDate, bw); err != nil {
					return n, fmt.Errorf("imap fetch %s: %w", b.Mailbox, err)
				}
				n++
			}
		}
	}
	if err := bw.Flush(); err != nil {
		return n, err
	}
	_ = c.Logout().Wait()
	return n, nil
}

// streamOne writes message uid as one mbox entry, its body read from the
// IMAP literal as it arrives.
func streamOne(c *imapclient.Client, uid imap.UID, date time.Time, w io.Writer) error {
	cmd := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{Peek: true}}})
	wrote := false
	for msg := cmd.Next(); msg != nil; msg = cmd.Next() {
		for item := msg.Next(); item != nil; item = msg.Next() {
			body, ok := item.(imapclient.FetchItemDataBodySection)
			if !ok || wrote {
				continue
			}
			var r io.Reader = strings.NewReader("")
			if body.Literal != nil {
				r = body.Literal
			}
			if err := WriteMboxFrom(w, date, r); err != nil {
				_ = cmd.Close()
				return err
			}
			wrote = true
		}
	}
	if err := cmd.Close(); err != nil {
		return err
	}
	if !wrote {
		return fmt.Errorf("UID %d: no body in the answer", uid)
	}
	return nil
}

func (e *Exporter) tlsConfig(now time.Time) *tls.Config { return PinnedTLS(e.ServerName, e.SPKI, now) }

// PinnedTLS trusts exactly the mail certificate: its key one of spki
// (sha256 of the SPKI, hex), valid now, naming serverName.
func PinnedTLS(serverName string, spki []string, now time.Time) *tls.Config {
	return &tls.Config{
		ServerName: serverName, MinVersion: tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the SPKI pin in VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("tls: no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return fmt.Errorf("tls: certificate: %w", err)
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			pinned := false
			for _, p := range spki {
				if strings.EqualFold(p, hex.EncodeToString(sum[:])) {
					pinned = true
				}
			}
			if !pinned {
				return errors.New("tls: the certificate's key isn't the mail certificate's (SPKI pin)")
			}
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errors.New("tls: the certificate isn't valid now")
			}
			return leaf.VerifyHostname(serverName)
		},
	}
}

func hasAttr(attrs []imap.MailboxAttr, a imap.MailboxAttr) bool {
	for _, x := range attrs {
		if strings.EqualFold(string(x), string(a)) {
			return true
		}
	}
	return false
}

var fromLine = regexp.MustCompile(`^>*From `)

// WriteMbox writes one message in mboxrd form: a "From " separator line,
// LF line ends, ">"-quoted "From " lines, a blank line after.
func WriteMbox(w io.Writer, date time.Time, msg []byte) error {
	return WriteMboxFrom(w, date, bytes.NewReader(msg))
}

// mboxChunk bounds what WriteMboxFrom holds of a message: one line, or a
// piece of a longer one.
const mboxChunk = 32 << 10

var lf = []byte("\n")

// WriteMboxFrom is WriteMbox reading the message from r, holding at most
// mboxChunk bytes of it at a time.
func WriteMboxFrom(w io.Writer, date time.Time, r io.Reader) error {
	if date.IsZero() {
		date = time.Unix(0, 0)
	}
	if _, err := fmt.Fprintf(w, "From MAILER-DAEMON %s\n", date.UTC().Format("Mon Jan _2 15:04:05 2006")); err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, mboxChunk)
	lineStart, cr, empty, lastLF := true, false, true, false
	write := func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		empty, lastLF = false, b[len(b)-1] == '\n'
		_, err := w.Write(b)
		return err
	}
	for {
		chunk, err := br.ReadSlice('\n')
		if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
			return err
		}
		if len(chunk) > 0 {
			// A CR held back from the previous piece: a CRLF split
			// across pieces becomes LF, a lone CR stays.
			if cr {
				cr = false
				if chunk[0] != '\n' {
					if err := write([]byte("\r")); err != nil {
						return err
					}
				}
			}
			if lineStart && fromLine.Match(chunk) {
				if err := write([]byte(">")); err != nil {
					return err
				}
			}
			out, tail := chunk, []byte(nil)
			switch {
			case bytes.HasSuffix(out, []byte("\r\n")):
				out, tail = out[:len(out)-2], lf
			case out[len(out)-1] == '\r':
				out, cr = out[:len(out)-1], true
			}
			if werr := write(out); werr != nil {
				return werr
			}
			if werr := write(tail); werr != nil {
				return werr
			}
			lineStart = chunk[len(chunk)-1] == '\n'
		}
		if err == io.EOF {
			break
		}
	}
	if cr {
		if err := write([]byte("\r")); err != nil {
			return err
		}
	}
	if !empty && !lastLF {
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte("\n"))
	return err
}
