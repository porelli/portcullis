package link

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/portcullis/wg/internal/linkdoc"
	"github.com/portcullis/wg/internal/tunnel"
)

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func newStack(t *testing.T, addr string, port int) (*tunnel.Stack, [32]byte) {
	t.Helper()
	k, err := tunnel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := tunnel.New(tunnel.Config{PrivateKey: k, ListenPort: port, Address: netip.MustParseAddr(addr), MTU: MTU})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, tunnel.PublicKeyOf(k)
}

// worker is a fake agent: a client stack at ip that dials the link server,
// with an echo on 7443 and a data listener on 7000 that records the first
// line and then echoes.
type worker struct {
	id    string
	ip    netip.Addr
	stack *tunnel.Stack
	pub   [32]byte
	lines chan string
}

func newWorker(t *testing.T, id, ip string, linkPub [32]byte, linkPort int) *worker {
	t.Helper()
	return newWorkerCtl(t, id, ip, linkPub, linkPort, func(c net.Conn) { io.Copy(c, c) })
}

// newWorkerCtl is newWorker with its own control (7443) handler.
func newWorkerCtl(t *testing.T, id, ip string, linkPub [32]byte, linkPort int, ctlH func(net.Conn)) *worker {
	t.Helper()
	s, pub := newStack(t, ip, 0)
	if err := s.SyncPeers([]tunnel.PeerConfig{{PublicKey: linkPub, IP: linkdoc.LinkAddr,
		Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(linkPort)), Keepalive: 1}}); err != nil {
		t.Fatal(err)
	}
	w := &worker{id: id, ip: netip.MustParseAddr(ip), stack: s, pub: pub, lines: make(chan string, 16)}
	ctl, err := s.ListenTCP(ControlPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctl.Close() })
	go acceptLoop(ctl, ctlH)
	data, err := s.ListenTCP(DataPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { data.Close() })
	go acceptLoop(data, func(c net.Conn) {
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		w.lines <- line
		io.Copy(c, br)
	})
	return w
}

func acceptLoop(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { defer c.Close(); h(c) }()
	}
}

func keyB64(k [32]byte) string { return tunnel.KeyString(k) }

type fixture struct {
	t        *testing.T
	stack    *tunnel.Stack
	pub      [32]byte
	port     int
	link     *Link
	doc      atomic.Pointer[linkdoc.Doc]
	ctlAddr  string
	dataAddr string
	noWait   bool // apply doesn't wait for handshakes
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, port: freeUDP(t)}
	f.stack, f.pub = newStack(t, linkdoc.LinkAddr.String(), f.port)
	f.link = New(f.stack, f.doc.Load)
	f.link.DialTimeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.ctlAddr, f.dataAddr = cl.Addr().String(), dl.Addr().String()
	go f.link.ServeControl(ctx, cl)
	go f.link.ServeData(ctx, dl)
	return f
}

type relaySpec struct{ token, instance, server string }

func sha(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

// apply writes a document with the given workers (state per worker) and
// relays, parses it like wg does and reloads.
func (f *fixture) apply(peers map[*worker]string, relays ...relaySpec) {
	f.t.Helper()
	d := map[string]any{"version": 1, "written_at": "2026-11-15T10:00:00Z", "subnet": "10.214.0.0/24"}
	ps := []any{}
	for w, st := range peers {
		ps = append(ps, map[string]any{"id": w.id, "public_key": keyB64(w.pub), "ip": w.ip.String(), "state": st})
	}
	rs := []any{}
	for _, r := range relays {
		rs = append(rs, map[string]any{"token_sha256": sha(r.token), "instance": r.instance, "server": r.server})
	}
	d["peers"], d["relays"] = ps, rs
	b, _ := json.Marshal(d)
	doc, err := linkdoc.Parse(b)
	if err != nil {
		f.t.Fatalf("fixture doc: %v", err)
	}
	f.doc.Store(doc)
	f.link.Reload(doc)
	// Wait for every worker's handshake (a rejected initiation is retried
	// after WireGuard's 5 s rekey timeout).
	if f.noWait {
		return
	}
	deadline := time.Now().Add(20 * time.Second)
	for w := range peers {
		for {
			st, _ := f.stack.PeerStats()
			if s, ok := st[keyB64(w.pub)]; ok && !s.Handshake.IsZero() {
				break
			}
			if w.stack == nil || time.Now().After(deadline) {
				f.t.Fatalf("no handshake from %s", w.id)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (f *fixture) none() {
	f.doc.Store(nil)
	f.link.Reload(nil)
}

// connect sends a CONNECT and returns the status and, on 200, the open
// connection (with its reader).
func connect(t *testing.T, addr, method, target string, hdr map[string]string) (int, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	host := target
	if strings.HasPrefix(target, "/") {
		host = "link"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, target, host)
	for k, v := range hdr {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	if _, err := c.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		c.Close()
		t.Fatalf("%s %s: %v", method, target, err)
	}
	if resp.StatusCode != 200 {
		c.Close()
		return resp.StatusCode, nil, nil
	}
	c.SetDeadline(time.Time{})
	t.Cleanup(func() { c.Close() })
	return 200, c, br
}

func echoes(t *testing.T, c net.Conn, br *bufio.Reader, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != msg {
		t.Fatalf("echo %q: %q %v", msg, got, err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitClosed fails unless c reads EOF (or a reset) within d.
func waitClosed(t *testing.T, c net.Conn, br *bufio.Reader, d time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(d))
	_, err := br.ReadByte()
	if err == nil {
		t.Fatal("stream still delivers data")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("stream still open after %s", d)
	}
}

func TestControlConnectRules(t *testing.T) {
	f := newFixture(t)
	w := newWorker(t, "w1", "10.214.0.10", f.pub, f.port)
	f.apply(map[*worker]string{w: linkdoc.StateReady})

	if code, _, _ := connect(t, f.ctlAddr, "GET", "/", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", code)
	}
	for _, target := range []string{
		"10.214.0.10:7000", "10.214.0.10:22", "10.214.0.10:443", // other ports of a peer
		"10.214.0.99:7443", "10.214.0.1:7443", "10.214.0.9:7443", // not a peer / link itself / outside .10–.250
		"10.213.0.2:7443", "172.31.254.82:7443", "127.0.0.1:7443", // a people peer, a Docker address, loopback
		"w1.node.portcullis.internal:7443", "[::1]:7443", "10.214.0.010:7443",
		"gitea.web.relay:8080",
	} {
		if code, _, _ := connect(t, f.ctlAddr, "CONNECT", target, nil); code != http.StatusForbidden {
			t.Fatalf("CONNECT %s: %d, want 403", target, code)
		}
	}
	code, c, br := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
	if code != 200 {
		t.Fatalf("CONNECT to the ready peer: %d", code)
	}
	echoes(t, c, br, "hello agent")

	// An enrolling peer is reachable on the control path too.
	f.apply(map[*worker]string{w: linkdoc.StateEnrolling})
	echoes(t, c, br, "ready to enrolling keeps the stream")
	code, c, br = connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
	if code != 200 {
		t.Fatalf("CONNECT to the enrolling peer: %d", code)
	}
	echoes(t, c, br, "enrol")

	if got := testutil.ToFloat64(f.link.rejected.WithLabelValues("control", "target")); got < 1 {
		t.Fatalf("rejected{control,target} = %v", got)
	}
}

func TestDataConnectRules(t *testing.T) {
	f := newFixture(t)
	w := newWorker(t, "w1", "10.214.0.10", f.pub, f.port)
	f.apply(map[*worker]string{w: linkdoc.StateReady},
		relaySpec{"tok-a", "gitea", "w1"}, relaySpec{"tok-b", "gitea-b", "w1"})

	cases := []struct {
		name, target string
		hdr          map[string]string
		reason       string
	}{
		{"no bearer", "gitea.web.relay:3000", nil, "no_bearer"},
		{"basic auth", "gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Basic dG9rLWE="}, "no_bearer"},
		{"unknown token", "gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer nope"}, "unknown_token"},
		{"A's token for B", "gitea-b.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}, "other_instance"},
		{"worker address", "10.214.0.10:7000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}, "target"},
		{"no relay suffix", "gitea.web:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}, "target"},
		{"bad port", "gitea.web.relay:0", map[string]string{"Proxy-Authorization": "Bearer tok-a"}, "target"},
		{"no service", "gitea.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}, "target"},
		{"bad instance", "Gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}, "target"},
	}
	for _, c := range cases {
		before := testutil.ToFloat64(f.link.rejected.WithLabelValues("data", c.reason))
		if code, _, _ := connect(t, f.dataAddr, "CONNECT", c.target, c.hdr); code != http.StatusForbidden {
			t.Fatalf("%s: %d, want 403", c.name, code)
		}
		if testutil.ToFloat64(f.link.rejected.WithLabelValues("data", c.reason)) != before+1 {
			t.Fatalf("%s: reason %s not counted", c.name, c.reason)
		}
	}
	if code, _, _ := connect(t, f.dataAddr, "GET", "/", nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", code)
	}
	// The data path never reaches the control port, whatever the target says.
	if code, _, _ := connect(t, f.dataAddr, "CONNECT", "gitea.web.relay:7443", map[string]string{"Proxy-Authorization": "Bearer tok-a"}); code != 200 {
		t.Fatalf("data CONNECT: %d", code)
	}
	if line := <-w.lines; line != `{"instance":"gitea","service":"web","port":7443}`+"\n" {
		t.Fatalf("preamble %q", line)
	}

	// The relay's own preamble is just payload after link's.
	code, c, br := connect(t, f.dataAddr, "CONNECT", "gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"})
	if code != 200 {
		t.Fatalf("data CONNECT: %d", code)
	}
	select {
	case line := <-w.lines:
		if line != `{"instance":"gitea","service":"web","port":3000}`+"\n" {
			t.Fatalf("preamble %q", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no preamble")
	}
	echoes(t, c, br, `{"instance":"gitea-b","service":"web","port":3000}`+"\n")
}

func TestReloadDropsPeers(t *testing.T) {
	f := newFixture(t)
	a := newWorker(t, "a", "10.214.0.10", f.pub, f.port)
	b := newWorker(t, "b", "10.214.0.11", f.pub, f.port)
	f.apply(map[*worker]string{a: linkdoc.StateReady, b: linkdoc.StateReady})
	for _, target := range []string{"10.214.0.10:7443", "10.214.0.11:7443"} {
		if code, _, _ := connect(t, f.ctlAddr, "CONNECT", target, nil); code != 200 {
			t.Fatalf("%s: %d", target, code)
		}
	}
	f.apply(map[*worker]string{a: linkdoc.StateReady})
	st, err := f.stack.PeerStats()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st[keyB64(b.pub)]; ok || len(st) != 1 {
		t.Fatalf("device peers after reload: %v", st)
	}
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.11:7443", nil); code != http.StatusForbidden {
		t.Fatalf("dropped peer: %d", code)
	}
	// b's own tunnel can't reach link any more.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if c, err := b.stack.DialTCP(ctx, netip.AddrPortFrom(linkdoc.LinkAddr, 1)); err == nil {
		c.Close()
		t.Fatal("dropped peer's dial was answered")
	}
	ps := f.link.Peers()
	if len(ps) != 1 || ps[0].ID != "a" || ps[0].Handshake == nil {
		t.Fatalf("Peers: %+v", ps)
	}
	// A key swap for the same id (enrolment) replaces the device peer.
	a2 := newWorker(t, "a", "10.214.0.10", f.pub, f.port)
	a.stack.Close()
	f.apply(map[*worker]string{a2: linkdoc.StateReady})
	code, c, br := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
	if code != 200 {
		t.Fatalf("after key swap: %d", code)
	}
	echoes(t, c, br, "new key")
}

func TestRevokeClosesOpenStreams(t *testing.T) {
	f := newFixture(t)
	w := newWorker(t, "w1", "10.214.0.10", f.pub, f.port)
	f.apply(map[*worker]string{w: linkdoc.StateReady}, relaySpec{"tok-a", "gitea", "w1"}, relaySpec{"tok-b", "nc", "w1"})

	_, ctl, ctlR := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
	_, da, daR := connect(t, f.dataAddr, "CONNECT", "gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"})
	_, db, dbR := connect(t, f.dataAddr, "CONNECT", "nc.app.relay:80", map[string]string{"Proxy-Authorization": "Bearer tok-b"})
	if ctl == nil || da == nil || db == nil {
		t.Fatal("streams not opened")
	}
	<-w.lines
	<-w.lines
	echoes(t, ctl, ctlR, "x")
	echoes(t, da, daR, "y")
	echoes(t, db, dbR, "z")

	// gitea's token rotates: its stream ends at the reload, the others stay.
	f.apply(map[*worker]string{w: linkdoc.StateReady}, relaySpec{"tok-a2", "gitea", "w1"}, relaySpec{"tok-b", "nc", "w1"})
	waitClosed(t, da, daR, 2*time.Second)
	echoes(t, ctl, ctlR, "still")
	echoes(t, db, dbR, "still")
	if code, _, _ := connect(t, f.dataAddr, "CONNECT", "gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}); code != http.StatusForbidden {
		t.Fatalf("old token: %d", code)
	}

	// The server is revoked (gone from link.json): everything of it ends.
	f.apply(map[*worker]string{})
	waitClosed(t, ctl, ctlR, 2*time.Second)
	waitClosed(t, db, dbR, 2*time.Second)
	if n := f.link.OpenStreams(); n != 0 {
		t.Fatalf("%d streams left", n)
	}
	if got := testutil.ToFloat64(f.link.closed.WithLabelValues("data")); got != 2 {
		t.Fatalf("closed{data} = %v", got)
	}
}

func TestBadDocMeansNoPeers(t *testing.T) {
	f := newFixture(t)
	w := newWorker(t, "w1", "10.214.0.10", f.pub, f.port)
	f.apply(map[*worker]string{w: linkdoc.StateReady}, relaySpec{"tok-a", "gitea", "w1"})
	_, c, br := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
	if c == nil {
		t.Fatal("no stream")
	}
	f.none()
	waitClosed(t, c, br, 2*time.Second)
	if st, _ := f.stack.PeerStats(); len(st) != 0 {
		t.Fatalf("peers with no document: %v", st)
	}
	if ok, msg := f.link.Status(); ok || msg == "" {
		t.Fatalf("status %v %q", ok, msg)
	}
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil); code != http.StatusForbidden {
		t.Fatalf("control: %d", code)
	}
	if code, _, _ := connect(t, f.dataAddr, "CONNECT", "gitea.web.relay:3000", map[string]string{"Proxy-Authorization": "Bearer tok-a"}); code != http.StatusForbidden {
		t.Fatalf("data: %d", code)
	}

	// A document the device refuses (a peer with link's own key) = no peers.
	d := fmt.Sprintf(`{"version":1,"written_at":"2026-11-15T10:00:00Z","subnet":"10.214.0.0/24","peers":[{"id":"w1","public_key":%q,"ip":"10.214.0.10","state":"ready"},{"id":"self","public_key":%q,"ip":"10.214.0.12","state":"ready"}],"relays":[]}`, keyB64(w.pub), keyB64(f.pub))
	doc, err := linkdoc.Parse([]byte(d))
	if err != nil {
		t.Fatal(err)
	}
	f.doc.Store(doc)
	f.link.Reload(doc)
	if st, _ := f.stack.PeerStats(); len(st) != 0 {
		t.Fatalf("peers after a refused update: %v", st)
	}
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil); code != http.StatusForbidden {
		t.Fatalf("control after a refused update: %d", code)
	}

	// The live document must also allow it: a newer (nil) document not yet
	// reloaded refuses.
	f.noWait = true
	f.apply(map[*worker]string{w: linkdoc.StateReady})
	f.doc.Store(nil)
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil); code != http.StatusForbidden {
		t.Fatalf("control with the live doc gone: %d", code)
	}
}

// M7: Saturating data streams doesn't block control streams (separate caps).
// Tests the admission logic directly without WireGuard handshakes: fake peers
// in the document, test only that newStreamLocked counts by path and refuses
// at the right caps.
func TestSeparateStreamCaps(t *testing.T) {
	doc := &linkdoc.Doc{
		Version: 1, WrittenAt: time.Now().UTC(), Subnet: "10.214.0.0/24",
		Peers: []linkdoc.Peer{
			{ID: "w1", PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", IP: "10.214.0.10", State: "ready"},
		},
		Relays: []linkdoc.Relay{
			{TokenSHA256: strings.Repeat("a", 64), Instance: "gitea", Server: "w1"},
		},
	}
	doc, err := linkdoc.Parse(mustJSON(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	stack, _ := newStack(t, linkdoc.LinkAddr.String(), freeUDP(t))
	l := New(stack, func() *linkdoc.Doc { return doc })
	l.MaxControlStreams = 2
	l.MaxDataStreams = 4
	l.Reload(doc)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := doc.PeerByID("w1")

	// Fill data streams to cap (4).
	var dataStreams []*stream
	for i := 0; i < 4; i++ {
		l.mu.Lock()
		s := l.newStreamLocked(ctx, "data", p)
		l.mu.Unlock()
		if s == nil {
			t.Fatalf("data stream %d: refused before cap", i)
		}
		dataStreams = append(dataStreams, s)
	}

	// Data cap reached: the next data stream gets nil.
	l.mu.Lock()
	s := l.newStreamLocked(ctx, "data", p)
	l.mu.Unlock()
	if s != nil {
		t.Fatal("data stream beyond cap: accepted, want refused")
	}

	// Control streams still open (cap 2, independent of data).
	var controlStreams []*stream
	for i := 0; i < 2; i++ {
		l.mu.Lock()
		s := l.newStreamLocked(ctx, "control", p)
		l.mu.Unlock()
		if s == nil {
			t.Fatalf("control stream %d: refused before cap", i)
		}
		controlStreams = append(controlStreams, s)
	}

	// Control cap also reached: the next control stream gets nil.
	l.mu.Lock()
	s = l.newStreamLocked(ctx, "control", p)
	l.mu.Unlock()
	if s != nil {
		t.Fatal("control stream beyond cap: accepted, want refused")
	}

	// Close one data stream: data opens again, but control still at cap.
	l.mu.Lock()
	delete(l.streams, dataStreams[0])
	l.mu.Unlock()
	dataStreams[0].cancel()

	l.mu.Lock()
	s = l.newStreamLocked(ctx, "data", p)
	l.mu.Unlock()
	if s == nil {
		t.Fatal("data stream after freeing one: refused")
	}

	// Control still at cap.
	l.mu.Lock()
	s = l.newStreamLocked(ctx, "control", p)
	l.mu.Unlock()
	if s != nil {
		t.Fatal("control still at cap after freeing data: accepted")
	}
}

// TestLinkZeroNetstackListeners: from a peer's own netstack every TCP port
// of 10.214.0.1 answers RST, with the CONNECT servers running.
func TestLinkZeroNetstackListeners(t *testing.T) {
	f := newFixture(t)
	w := newWorker(t, "w1", "10.214.0.10", f.pub, f.port)
	f.apply(map[*worker]string{w: linkdoc.StateReady})
	// A first exchange so the handshake is done.
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil); code != 200 {
		t.Fatalf("CONNECT: %d", code)
	}
	ports := map[int]bool{22: true, 53: true, 80: true, 443: true, 3128: true, 3129: true, 7000: true, 7443: true, 8080: true, 9100: true, 51821: true}
	for i := 0; len(ports) < 2011; i++ {
		ports[1+int(uint32(i)*2654435761%65535)] = true
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	var mu sync.Mutex
	var bad []string
	for p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := w.stack.DialTCP(ctx, netip.AddrPortFrom(linkdoc.LinkAddr, uint16(p)))
			if err == nil {
				c.Close()
				mu.Lock()
				bad = append(bad, fmt.Sprintf("%d accepted", p))
				mu.Unlock()
				return
			}
			if !strings.Contains(err.Error(), "refused") {
				mu.Lock()
				bad = append(bad, fmt.Sprintf("%d: %v", p, err))
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()
	if len(bad) > 0 {
		t.Fatalf("%d of %d ports not refused: %v", len(bad), len(ports), bad[:min(len(bad), 10)])
	}
	// UDP: nothing answers either (no listener; a datagram gets no reply).
	pc, err := w.stack.Net().DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(linkdoc.LinkAddr, 53))
	if err == nil {
		pc.Write([]byte("x"))
		pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if n, err := pc.Read(make([]byte, 16)); err == nil {
			t.Fatalf("udp/53 answered %d bytes", n)
		}
		pc.Close()
	}
}

// TestLinkRoleIsolated: a people stack and the link stack share no path.
func TestLinkRoleIsolated(t *testing.T) {
	f := newFixture(t)
	w := newWorker(t, "w1", "10.214.0.10", f.pub, f.port)
	f.apply(map[*worker]string{w: linkdoc.StateReady})

	// The people role: its own stack 10.213.0.1 with an "edge" on 443 and a
	// person's device 10.213.0.2.
	pport := freeUDP(t)
	people, peoplePub := newStack(t, "10.213.0.1", pport)
	pl, err := people.ListenTCP(443)
	if err != nil {
		t.Fatal(err)
	}
	defer pl.Close()
	go acceptLoop(pl, func(c net.Conn) { io.Copy(c, c) })
	dev, devPub := newStack(t, "10.213.0.2", 0)
	if err := people.SyncPeers([]tunnel.PeerConfig{{PublicKey: devPub, IP: netip.MustParseAddr("10.213.0.2")}}); err != nil {
		t.Fatal(err)
	}
	devListen, err := dev.ListenTCP(7443)
	if err != nil {
		t.Fatal(err)
	}
	defer devListen.Close()
	go acceptLoop(devListen, func(c net.Conn) { io.Copy(c, c) })

	ep := func(port int) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	}
	dial := func(s *tunnel.Stack, to string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, err := s.DialTCP(ctx, netip.MustParseAddrPort(to))
		if err == nil {
			c.Close()
		}
		return err
	}

	// The device routes the worker's address into the people tunnel: the
	// people stack forwards nothing.
	if err := dev.SyncPeers([]tunnel.PeerConfig{{PublicKey: peoplePub, IP: netip.MustParseAddr("10.214.0.10"), Endpoint: ep(pport), Keepalive: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := dial(dev, "10.214.0.10:7443"); err == nil {
		t.Fatal("a people device reached a link peer")
	}
	if err := dial(dev, "10.214.0.1:1"); err == nil {
		t.Fatal("a people device reached the link address")
	}
	// Sanity: the people tunnel works for its own address.
	if err := dev.SyncPeers([]tunnel.PeerConfig{{PublicKey: peoplePub, IP: netip.MustParseAddr("10.213.0.1"), Endpoint: ep(pport), Keepalive: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := dial(dev, "10.213.0.1:443"); err != nil {
		t.Fatalf("people tunnel itself broken: %v", err)
	}

	// The worker routes people addresses into the link tunnel: the link
	// stack forwards nothing either.
	for _, target := range []string{"10.213.0.1:443", "10.213.0.2:7443"} {
		ip := netip.MustParseAddrPort(target).Addr()
		if err := w.stack.SyncPeers([]tunnel.PeerConfig{{PublicKey: f.pub, IP: ip, Endpoint: ep(f.port), Keepalive: 1}}); err != nil {
			t.Fatal(err)
		}
		if err := dial(w.stack, target); err == nil {
			t.Fatalf("a link peer reached %s", target)
		}
	}
	// And link's CONNECT never dials a people address.
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.213.0.2:7443", nil); code != http.StatusForbidden {
		t.Fatalf("CONNECT to a people device: %d", code)
	}
}

// --- agent metrics ---

type testPKI struct {
	caPEM    []byte
	caKey    *ecdsa.PrivateKey
	ca       *x509.Certificate
	dir      string
	certFile string
	keyFile  string
	caFile   string
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Node CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caKey: k, ca: ca, dir: t.TempDir()}
	p.caFile = filepath.Join(p.dir, "ca.crt")
	os.WriteFile(p.caFile, p.caPEM, 0o600)
	cert, key := p.leaf(t, "link.control", nil, x509.ExtKeyUsageClientAuth)
	p.certFile, p.keyFile = filepath.Join(p.dir, "link.crt"), filepath.Join(p.dir, "link.key")
	os.WriteFile(p.certFile, cert, 0o600)
	os.WriteFile(p.keyFile, key, 0o600)
	return p
}

func (p *testPKI) leaf(t *testing.T, cn string, dns []string, eku x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: dns, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{eku}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

// agentTLS serves /v1/metrics with mTLS on the worker's control port.
func (p *testPKI) serveAgent(t *testing.T, w *worker, dnsName, body string) {
	t.Helper()
	certPEM, keyPEM := p.leaf(t, dnsName, []string{dnsName}, x509.ExtKeyUsageServerAuth)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	ln, err := w.stack.ListenTCP(ControlPort + 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/metrics" || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "link.control" {
			http.Error(rw, "no", 403)
			return
		}
		io.WriteString(rw, body)
	}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
}

func TestAgentMetricsRelabelled(t *testing.T) {
	f := newFixture(t)
	a := newWorker(t, "a", "10.214.0.10", f.pub, f.port)
	b := newWorker(t, "b", "10.214.0.11", f.pub, f.port)
	f.apply(map[*worker]string{a: linkdoc.StateReady, b: linkdoc.StateReady})
	p := newPKI(t)
	p.serveAgent(t, a, "a.node.portcullis.internal", "# TYPE portcullis_agent_up gauge\nportcullis_agent_up 1\nportcullis_agent_up{server=\"forged\",x=\"1\"} 1\n"+
		"# TYPE portcullis_agent_info gauge\nportcullis_agent_info{server=\"a\",version=\"v1\"} 1\n"+
		"# TYPE wg_link_peer_rx_bytes_total counter\nwg_link_peer_rx_bytes_total{server=\"x\"} 9\n"+
		// Families the primary's alerts read: never passed from an agent.
		"# TYPE portcullis_status_ok gauge\nportcullis_status_ok 0\n"+
		"# TYPE portcullis_backup_last_success_timestamp_seconds gauge\nportcullis_backup_last_success_timestamp_seconds 1\n"+
		"# TYPE go_goroutines gauge\ngo_goroutines 3\n")
	// b presents a's name: refused by the ServerName check.
	p.serveAgent(t, b, "a.node.portcullis.internal", "# TYPE portcullis_agent_up gauge\nportcullis_agent_up 1\n")
	g := &AgentGatherer{Link: f.link, CertFile: p.certFile, KeyFile: p.keyFile, CAFile: p.caFile, Timeout: 5 * time.Second,
		// The test agents listen on 7444 (7443 is the fixture's echo).
		dial: func(ctx context.Context, to netip.AddrPort) (net.Conn, error) {
			return f.stack.DialTCP(ctx, netip.AddrPortFrom(to.Addr(), ControlPort+1))
		}}
	reg := prometheus.NewRegistry()
	reg.MustRegister(f.link.Collectors()...)
	fams, err := prometheus.Gatherers{reg, g}.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var lines []string
	for _, fam := range fams {
		for _, m := range fam.Metric {
			var ls []string
			for _, lp := range m.Label {
				ls = append(ls, lp.GetName()+"="+lp.GetValue())
			}
			v := m.GetGauge().GetValue() + m.GetCounter().GetValue()
			lines = append(lines, fmt.Sprintf("%s{%s} %v", fam.GetName(), strings.Join(ls, ","), v))
		}
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{"portcullis_agent_up{server=a} 1", "wg_link_agent_scrape_ok{server=a} 1", "wg_link_agent_scrape_ok{server=b} 0", "wg_link_peer_handshake_age_seconds{server=a}", "wg_link_peer_ready{server=a} 1"} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing %q in\n%s", want, all)
		}
	}
	if !strings.Contains(all, "portcullis_agent_info{server=a,version=v1} 1") {
		t.Fatalf("the agent's own server label: missing in\n%s", all)
	}
	for _, bad := range []string{"forged", "x=1", "server=x", "portcullis_agent_up{server=b}", "portcullis_status_ok", "portcullis_backup_last_success", "go_goroutines"} {
		if strings.Contains(all, bad) {
			t.Fatalf("%q in\n%s", bad, all)
		}
	}
	// Without the certificate files nothing is scraped and nothing fails.
	g.CertFile = filepath.Join(p.dir, "missing")
	if fams, err := g.Gather(); err != nil || len(fams) != 0 {
		t.Fatalf("no cert: %v %v", fams, err)
	}
}

// TestNoNetstackListenCalls: no non-test code of the role opens a listener
// on (or reaches into) the link stack's netstack.
func TestNoNetstackListenCalls(t *testing.T) {
	for _, f := range []string{"link.go", "connect.go", "metrics.go", "../../link_role.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"ListenTCP(", "ListenUDP(", ".Net()", "ListenPing"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s calls %s", f, bad)
			}
		}
	}
}

// TestPerPeerCapsDontStarveOthers: a worker holding its whole control
// share open gets 503 busy, and another worker's control CONNECT still
// answers 200 and echoes.
func TestPerPeerCapsDontStarveOthers(t *testing.T) {
	f := newFixture(t)
	f.link.MaxControlPerPeer = 2
	a := newWorker(t, "a", "10.214.0.10", f.pub, f.port)
	b := newWorker(t, "b", "10.214.0.11", f.pub, f.port)
	f.apply(map[*worker]string{a: linkdoc.StateReady, b: linkdoc.StateReady})
	for i := 0; i < 2; i++ {
		code, c, br := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
		if code != 200 {
			t.Fatalf("a's stream %d: %d", i, code)
		}
		echoes(t, c, br, fmt.Sprintf("a%d", i))
	}
	if code, _, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("a beyond its share: %d, want 503", code)
	}
	code, c, br := connect(t, f.ctlAddr, "CONNECT", "10.214.0.11:7443", nil)
	if code != 200 {
		t.Fatalf("b while a is at its share: %d, want 200", code)
	}
	echoes(t, c, br, "b")
	if n := f.link.OpenStreams(); n != 3 {
		t.Fatalf("open streams: %d, want 3", n)
	}
}

// TestPerPeerDataCap: the data share is per server too (admission).
func TestPerPeerDataCap(t *testing.T) {
	doc := &linkdoc.Doc{
		Version: 1, WrittenAt: time.Now().UTC(), Subnet: "10.214.0.0/24",
		Peers: []linkdoc.Peer{
			{ID: "w1", PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", IP: "10.214.0.10", State: "ready"},
			{ID: "w2", PublicKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", IP: "10.214.0.11", State: "ready"},
		},
		Relays: []linkdoc.Relay{},
	}
	doc, err := linkdoc.Parse(mustJSON(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	stack, _ := newStack(t, linkdoc.LinkAddr.String(), freeUDP(t))
	l := New(stack, func() *linkdoc.Doc { return doc })
	l.MaxDataPerPeer = 3
	l.Reload(doc)
	ctx := context.Background()
	open := func(id string) *stream {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.newStreamLocked(ctx, "data", doc.PeerByID(id))
	}
	for i := 0; i < 3; i++ {
		if open("w1") == nil {
			t.Fatalf("w1 data %d refused under its share", i)
		}
	}
	if open("w1") != nil {
		t.Fatal("w1 beyond its data share: accepted")
	}
	if open("w2") == nil {
		t.Fatal("w2 refused while w1 is at its share")
	}
	// The control share is separate from the data share.
	l.mu.Lock()
	s := l.newStreamLocked(ctx, "control", doc.PeerByID("w1"))
	l.mu.Unlock()
	if s == nil {
		t.Fatal("w1 control refused because of its data streams")
	}
}

// TestDrainTimeoutEndsHalfClosedStream: the client closes; a worker that
// reads but never answers nor closes can hold the stream only for the
// drain timeout.
func TestDrainTimeoutEndsHalfClosedStream(t *testing.T) {
	f := newFixture(t)
	f.link.DrainTimeout = 500 * time.Millisecond
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	w := newWorkerCtl(t, "w1", "10.214.0.10", f.pub, f.port, func(c net.Conn) {
		io.Copy(io.Discard, c) // reads to EOF, never writes, never closes
		<-hold
	})
	f.apply(map[*worker]string{w: linkdoc.StateReady})
	code, c, _ := connect(t, f.ctlAddr, "CONNECT", "10.214.0.10:7443", nil)
	if code != 200 {
		t.Fatalf("CONNECT: %d", code)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if n := f.link.OpenStreams(); n != 1 {
		t.Fatalf("open streams: %d, want 1", n)
	}
	c.Close()
	deadline := time.Now().Add(3 * time.Second)
	for f.link.OpenStreams() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("stream still open %v after the client closed (drain 500ms)", 3*time.Second)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
