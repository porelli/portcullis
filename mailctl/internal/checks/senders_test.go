package checks

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/portcullis/mailctl/internal/state"
)

// fakeMX answers one SMTP session: RCPT with rcpt(addr).
func fakeMX(t *testing.T, rcpt func(string) string) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		w := bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 mail.example.com ESMTP")
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			mu.Lock()
			seen = append(seen, line)
			mu.Unlock()
			switch {
			case strings.HasPrefix(line, "EHLO"):
				say("250-mail.example.com")
				say("250 8BITMIME")
			case strings.HasPrefix(line, "RCPT TO:<"):
				say(rcpt(strings.TrimSuffix(strings.TrimPrefix(line, "RCPT TO:<"), ">")))
			case line == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return ln.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, seen...) }
}

func sendersDocFor(t *testing.T, e *env) {
	t.Helper()
	e.st.Update(func(p *state.Persistent) error {
		l := []state.Sender{{Username: "portcullis-app-fxa", UUID: "7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e", Address: "portcullis-app-fxa@example.com"}}
		p.Doc.Senders = &l
		return nil
	})
}

// x-sender_rcpt: the senders' addresses and their sub-addresses refused
// at RCPT (550 5.1.1) is OK; one accepted is a Problem and a log line (a
// store bootstrapped before the senders' RCPT rule); no senders, OK
// without a session; an unreachable server, Info.
func TestSenderRcptCheck(t *testing.T) {
	e := newEnv(t)
	if c := senderRcptCheck(context.Background(), e.d, e.st.Get().Doc); c.Severity != OK || c.Detail != "no app mail senders" {
		t.Fatalf("no senders: %+v", c)
	}
	sendersDocFor(t, e)
	doc := e.st.Get().Doc
	dialTo := func(addr string) {
		e.d.Dial = func(ctx context.Context, network, a string) (net.Conn, error) {
			if a != "172.31.255.2:10025" {
				t.Fatalf("dialled %s", a)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	addr, seen := fakeMX(t, func(string) string { return "550 5.1.1 Mailbox does not exist" })
	dialTo(addr)
	if c := senderRcptCheck(context.Background(), e.d, doc); c.Severity != OK {
		t.Fatalf("refused: %+v", c)
	}
	want := []string{"EHLO mail.example.com", "MAIL FROM:<>", "RCPT TO:<portcullis-app-fxa@example.com>", "RCPT TO:<portcullis-app-fxa+portcullis-check@example.com>", "RSET", "QUIT"}
	if strings.Join(seen(), "|") != strings.Join(want, "|") {
		t.Fatalf("session %q", seen())
	}
	// The sub-address accepted (no glob key / an old rule): a Problem.
	var logged []string
	e.d.Logf = func(f string, a ...any) { logged = append(logged, f) }
	addr, _ = fakeMX(t, func(a string) string {
		if strings.Contains(a, "+") {
			return "250 2.1.5 ok"
		}
		return "550 5.1.1 Mailbox does not exist"
	})
	dialTo(addr)
	c := senderRcptCheck(context.Background(), e.d, doc)
	if c.Severity != Problem || !strings.Contains(c.Detail, "portcullis-app-fxa+portcullis-check@example.com") || len(c.Steps) != 1 || len(logged) != 1 {
		t.Fatalf("accepted: %+v (logged %v)", c, logged)
	}
	// Unreachable: Info. And it is in the catalog and in Run.
	e.d.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	if c := senderRcptCheck(context.Background(), e.d, doc); c.Severity != Info {
		t.Fatalf("unreachable: %+v", c)
	}
	if !InCatalog(IDSenderRcpt) {
		t.Fatal("not in the catalog")
	}
	found := false
	for _, id := range Catalog {
		found = found || id == IDSenderRcpt
	}
	if !found {
		t.Fatal("not listed in GET /v1/provider checks")
	}
	if c := find(t, Run(context.Background(), e.d).Checks, IDSenderRcpt); c.Severity != Info {
		t.Fatalf("run: %+v", c)
	}
}
