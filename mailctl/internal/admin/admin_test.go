package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

const hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestParseRotate(t *testing.T) {
	ok := []string{
		`{"dnssec_state":"secure","spki":{"current":"` + hexA + `","next":""}}`,
		`{"dnssec_state":"","spki":{"current":"","next":""}}`,
	}
	for _, s := range ok {
		if _, err := ParseRotate([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{
		`{"dnssec_state":"secure","spki":{"current":"zz","next":""}}`,
		`{"dnssec_state":"secure","spki":{"current":""}}`,
		`{"spki":{"current":"","next":""}}`,
		`{"dnssec_state":"secure","spki":{"current":"","next":""},"x":1}`,
		`{"dnssec_state":"a","dnssec_state":"b","spki":{"current":"","next":""}}`,
		`{"dnssec_state":"secure","spki":{"current":"","next":""}} {}`,
	}
	for _, s := range bad {
		if _, err := ParseRotate([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

func TestParseTLSKey(t *testing.T) {
	if c, err := ParseTLSKey([]byte(`{"current":"` + strings.ToUpper(hexA) + `"}`)); err != nil || c != hexA {
		t.Fatalf("= %q %v", c, err)
	}
	for _, s := range []string{`{}`, `{"current":""}`, `{"current":"zz"}`, `{"current":"` + hexA + `","next":""}`,
		`{"current":"` + hexA + `","current":"` + hexA + `"}`, `{"current":"` + hexA + `"} {}`} {
		if _, err := ParseTLSKey([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
}

// Before any document: tls-key records the current key (mail test's pin)
// and nothing else; rotate still refuses without the main domain's set.
func TestSocketTLSKeyWithoutDocument(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	st, _ := state.Open(t.TempDir())
	m := machines.New(stalwart.New(f.URL(), stalwart.Bearer("API_k")), st,
		machines.Config{MainDomain: "example.com", Hostname: "mail.example.com", RotateEvery: time.Hour, Reachable: true}, t.Logf)
	dir, _ := os.MkdirTemp("/tmp", "mck")
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: Handler(m, Status{ClientIP: "preserved"})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if out, err := Call(path, "POST", "/tls-key", []byte(`{"current":"`+hexA+`"}`)); err != nil || !strings.Contains(string(out), hexA) {
		t.Fatalf("tls-key %s %v", out, err)
	}
	p := st.Get()
	if got := state.SPKIs(p); len(got) != 1 || got[0] != hexA {
		t.Fatalf("SPKIs = %v", got)
	}
	if p.TimerSeenAt != nil {
		t.Fatal("tls-key counted as the timer's visit")
	}
	if _, err := Call(path, "POST", "/tls-key", []byte(`{"current":"x"}`)); err == nil {
		t.Fatal("bad input accepted")
	}
	if _, err := Call(path, "POST", "/rotate", []byte(`{"dnssec_state":"","spki":{"current":"`+hexA+`","next":""}}`)); err == nil || !strings.Contains(err.Error(), "has the Hub sent one?") {
		t.Fatalf("rotate without a document %v", err)
	}
}

// The socket is 0600 and answers dns / rotate / status.
func TestSocket(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	f.Put("Domain", "", map[string]any{"name": "example.com"})
	b, _ := os.ReadFile("../state/testdata/mailstate_v1.json")
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := state.Open(t.TempDir())
	st.Update(func(p *state.Persistent) error { p.Doc = doc; return nil })
	m := machines.New(stalwart.New(f.URL(), stalwart.Bearer("API_k")), st,
		machines.Config{MainDomain: "example.com", Hostname: "mail.example.com", RotateEvery: time.Hour, Reachable: true}, t.Logf)
	m.Visible = func(context.Context, string, string) bool { return false }
	dir, _ := os.MkdirTemp("/tmp", "mcs")
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: Handler(m, Status{ClientIP: "preserved"})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	out, err := Call(path, "POST", "/rotate", []byte(`{"dnssec_state":"secure","spki":{"current":"`+hexA+`","next":""}}`))
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	json.Unmarshal(out, &r)
	if r["tlsa"] != "published" || r["switch_key"] != false || r["next_key"] != false || !strings.Contains(string(out), "3 1 1 "+hexA) {
		t.Fatalf("rotate %s", out)
	}
	if out, err = Call(path, "GET", "/dns/main", nil); err != nil || !strings.Contains(string(out), `"domain":"example.com"`) {
		t.Fatalf("dns %s %v", out, err)
	}
	// The rotate pass made pending keys: a second rotation is refused.
	if _, err := Call(path, "POST", "/dkim-rotate", []byte(`{"domain":"Example.com"}`)); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("dkim rotate while pending %v", err)
	}
	if out, err = Call(path, "POST", "/dkim-rotate", []byte(`{"domain":"team-b.example.org"}`)); err != nil || !strings.Contains(string(out), `"domain":"team-b.example.org"`) {
		t.Fatalf("dkim rotate %s %v", out, err)
	}
	if _, err := Call(path, "POST", "/dkim-rotate", []byte(`{"domain":"nope.example"}`)); err == nil || !strings.Contains(err.Error(), "isn't a mail domain") {
		t.Fatalf("unknown domain %v", err)
	}
	if out, err = Call(path, "GET", "/status", nil); err != nil || !strings.Contains(string(out), `"timer_seen_at":"`) || !strings.Contains(string(out), `"checks":null`) {
		t.Fatalf("status %s %v", out, err)
	}
	if _, err := Call(path, "POST", "/rotate", []byte(`{}`)); err == nil {
		t.Fatal("bad input accepted")
	}
}
