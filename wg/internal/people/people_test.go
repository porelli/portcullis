package people

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/portcullis/wg/internal/tunnel"
	"github.com/portcullis/wg/internal/vpndoc"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }

func freePort(t *testing.T) int {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func newRole(t *testing.T, c *clock) (*Role, *tunnel.Stack) {
	t.Helper()
	k, _ := tunnel.GenerateKey()
	s, err := tunnel.New(tunnel.Config{PrivateKey: k, ListenPort: freePort(t), Address: netip.MustParseAddr("10.213.0.1"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return NewRole(s, netip.MustParsePrefix("10.213.0.0/22"), c.now), s
}

func peerKeys(t *testing.T, s *tunnel.Stack) string {
	t.Helper()
	hs, err := s.Handshakes()
	if err != nil {
		t.Fatal(err)
	}
	var ks []string
	for k := range hs {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return strings.Join(ks, ",")
}

func keyPair(t *testing.T) string {
	k, _ := tunnel.GenerateKey()
	return tunnel.KeyString(tunnel.PublicKeyOf(k))
}

func doc(t *testing.T, serverKey string, peers ...string) *vpndoc.Doc {
	t.Helper()
	var ps []string
	for i, p := range peers {
		ps = append(ps, `{"ip":"10.213.0.`+string(rune('5'+i))+`","public_key":"`+p+`","device_id":"d`+string(rune('a'+i))+`","expires":null}`)
	}
	return docRaw(t, serverKey, strings.Join(ps, ","))
}

func docRaw(t *testing.T, serverKey, peers string) *vpndoc.Doc {
	t.Helper()
	d, err := vpndoc.Parse([]byte(`{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"` + serverKey +
		`","domains":[],"peers":[` + peers + `]},"providers":[{"id":"builtin","source":"builtin","ranges":["10.213.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false}],"devices":[]}`))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return d
}

func TestPeopleRoleSyncsPeers(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)}
	r, s := newRole(t, c)
	a, b, cc := keyPair(t), keyPair(t), keyPair(t)
	join := func(ks ...string) string { sort.Strings(ks); return strings.Join(ks, ",") }

	r.SetDoc(doc(t, s.PublicKey(), a, b), nil)
	if got := peerKeys(t, s); got != join(a, b) {
		t.Fatalf("peers %s", got)
	}
	if ok, e := r.Status(); !ok || e != "" {
		t.Fatalf("status %v %q", ok, e)
	}
	r.SetDoc(doc(t, s.PublicKey(), b, cc), nil) // a removed, c added
	if got := peerKeys(t, s); got != join(b, cc) {
		t.Fatalf("peers after change %s", got)
	}
	// Another server's key: no peers at all, role not ok.
	r.SetDoc(doc(t, keyPair(t), a, b), nil)
	if got := peerKeys(t, s); got != "" {
		t.Fatalf("peers kept under a foreign server key: %s", got)
	}
	if ok, e := r.Status(); ok || !strings.Contains(e, "server_public_key") {
		t.Fatalf("status %v %q", ok, e)
	}
	// A broken document: no peers, not ok.
	r.SetDoc(doc(t, s.PublicKey(), a), nil)
	r.SetDoc(nil, errors.New("vpn.json: missing"))
	if got := peerKeys(t, s); got != "" {
		t.Fatalf("peers kept without a document: %s", got)
	}
	if ok, e := r.Status(); ok || e != "vpn.json: missing" {
		t.Fatalf("status %v %q", ok, e)
	}
	// Another subnet than this role's: refused.
	d, err := vpndoc.Parse([]byte(`{"version":2,"builtin":{"subnet":"10.99.0.0/22","server_public_key":"` + s.PublicKey() + `","domains":[],"peers":[]},"providers":[{"id":"builtin","source":"builtin","ranges":["10.99.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false}],"devices":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	r.SetDoc(d, nil)
	if ok, _ := r.Status(); ok {
		t.Fatal("foreign subnet accepted")
	}
}

// TestExpiredPeerDroppedByClock (Review Focus 4): the Hub is stopped, the
// document never changes, the peer's expires passes: the next tick drops it.
func TestExpiredPeerDroppedByClock(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)}
	r, s := newRole(t, c)
	a, b := keyPair(t), keyPair(t)
	r.SetDoc(docRaw(t, s.PublicKey(),
		`{"ip":"10.213.0.5","public_key":"`+a+`","device_id":"d1","expires":"2026-11-13T10:00:05Z"},`+
			`{"ip":"10.213.0.6","public_key":"`+b+`","device_id":"d2","expires":null}`), nil)
	if got := peerKeys(t, s); !strings.Contains(got, a) {
		t.Fatal("peer missing before expiry")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, 10*time.Millisecond)
	c.set(c.now().Add(6 * time.Second))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := peerKeys(t, s); got == b {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expired peer kept: %s", peerKeys(t, s))
}

func TestPeopleHTTPRedirect(t *testing.T) {
	h := RedirectHandler()
	for _, tc := range []struct{ host, target, want string }{
		{"app.example.org", "/x/y?z=1", "https://app.example.org/x/y?z=1"},
		{"app.example.org:80", "/", "https://app.example.org/"},
	} {
		req := httptest.NewRequest("GET", "http://"+tc.host+tc.target, nil)
		req.Host = tc.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != tc.want {
			t.Fatalf("%s%s: %d %q", tc.host, tc.target, w.Code, w.Header().Get("Location"))
		}
	}
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.Host = ""
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no host: %d", w.Code)
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "people.key")
	os.WriteFile(p, nil, 0o640)
	if _, on, err := LoadKey(p); on || err != nil {
		t.Fatalf("empty: %v %v", on, err)
	}
	k, _ := tunnel.GenerateKey()
	os.WriteFile(p, []byte(tunnel.KeyString(k)+"\n"), 0o640)
	got, on, err := LoadKey(p)
	if !on || err != nil || got != k {
		t.Fatalf("key: %v %v", on, err)
	}
	os.WriteFile(p, []byte("garbage\n"), 0o640)
	if _, _, err := LoadKey(p); err == nil || strings.Contains(err.Error(), "garbage") {
		t.Fatalf("garbage: %v", err)
	}
	if _, _, err := LoadKey(filepath.Join(dir, "none")); err == nil {
		t.Fatal("missing file accepted")
	}
}
