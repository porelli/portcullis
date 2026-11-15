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
	if out, err = Call(path, "GET", "/status", nil); err != nil || !strings.Contains(string(out), `"timer_seen_at":"`) {
		t.Fatalf("status %s %v", out, err)
	}
	if _, err := Call(path, "POST", "/rotate", []byte(`{}`)); err == nil {
		t.Fatal("bad input accepted")
	}
}
