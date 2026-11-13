package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/portcullis/wg/internal/vpndoc"
)

// echoTraefik keeps each connection open and echoes lines after the
// PROXY header.
func echoTraefik(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				if _, err := proxyproto.Read(br); err != nil {
					return
				}
				io.Copy(c, br)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

type fixture struct {
	t    *testing.T
	e    *Edge
	doc  atomic.Pointer[vpndoc.Doc]
	mu   sync.Mutex
	now  time.Time
	addr string
}

func (f *fixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newFixture(t *testing.T, doc string) *fixture {
	f := &fixture{t: t, now: now0}
	f.doc.Store(mustDoc(t, doc))
	f.e = New(echoTraefik(t), netip.MustParseAddr("127.0.0.1"), f.doc.Load, f.clock)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go f.e.ServeProvider(ctx, portListener{ln, 9001}, "hs")
	f.addr = ln.Addr().String()
	return f
}

// open makes an admitted connection and proves it works.
func (f *fixture) open(src string) (net.Conn, *bufio.Reader) {
	f.t.Helper()
	c, err := net.Dial("tcp4", f.addr)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { c.Close() })
	c.Write(v2Header(src))
	br := bufio.NewReader(c)
	f.ping(c, br)
	return c, br
}

func (f *fixture) ping(c net.Conn, br *bufio.Reader) {
	f.t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		f.t.Fatalf("write: %v", err)
	}
	if l, err := br.ReadString('\n'); err != nil || l != "ping\n" {
		f.t.Fatalf("echo: %q %v", l, err)
	}
}

func closedSoon(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadString('\n'); err == nil {
		t.Fatal("connection still open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("connection not closed within the deadline")
	}
}

func (f *fixture) closed(reason string) float64 {
	return testutil.ToFloat64(f.e.closed.WithLabelValues("hs", reason))
}

func waitSessions(t *testing.T, e *Edge, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e.Sessions() == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("sessions = %d, want %d", e.Sessions(), n)
}

func TestEdgeRevokedMidConnection(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	c, br := f.open("100.64.0.7:40000")
	// The device leaves the map (revoked in the provider).
	f.doc.Store(mustDoc(t, strings.Replace(docJSON("127.0.0.1", false),
		`{"ip":"100.64.0.7","provider":"hs","user":"alice","device_id":"hs:1","name":"a","expires":null},`, "", 1)))
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("revoked"); v != 1 {
		t.Fatalf("closed{revoked} = %v", v)
	}
	waitSessions(t, f.e, 0)
}

func TestEdgeReassignedAddressCloses(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	c, br := f.open("100.64.0.7:40000")
	// The mesh hands the address to someone else's node.
	f.doc.Store(mustDoc(t, strings.Replace(docJSON("127.0.0.1", false), `"user":"alice","device_id":"hs:1"`, `"user":"mallory","device_id":"hs:9"`, 1)))
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("revoked"); v != 1 {
		t.Fatalf("closed{revoked} = %v", v)
	}
}

func TestEdgeDocNilClosesAll(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	c1, b1 := f.open("100.64.0.7:40000")
	c2, b2 := f.open("100.64.0.7:40001")
	waitSessions(t, f.e, 2)
	f.doc.Store(nil)
	f.e.Revalidate()
	closedSoon(t, c1, b1)
	closedSoon(t, c2, b2)
	if v := f.closed("no_doc"); v != 2 {
		t.Fatalf("closed{no_doc} = %v", v)
	}
	waitSessions(t, f.e, 0)
}

func TestEdgeStaleByClockCloses(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	c, br := f.open("100.64.0.7:40000")
	f.advance(3 * time.Minute) // past stale_after 10:03
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("stale"); v != 1 {
		t.Fatalf("closed{stale} = %v", v)
	}
}

func TestEdgeValidConnectionStaysOpen(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	c, br := f.open("100.64.0.7:40000")
	for i := 0; i < 3; i++ {
		f.doc.Store(mustDoc(t, docJSON("127.0.0.1", false))) // a reload, same facts
		f.e.Revalidate()
		f.advance(10 * time.Second)
		f.ping(c, br)
	}
	for _, r := range CloseReasons {
		if v := f.closed(r); v != 0 {
			t.Fatalf("closed{%s} = %v", r, v)
		}
	}
	if f.e.Sessions() != 1 {
		t.Fatalf("sessions %d", f.e.Sessions())
	}
}

func TestEdgeLifetimeCap(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	f.e.MaxLifetime = time.Minute
	f.e.IdleTimeout = time.Hour
	c, br := f.open("100.64.0.7:40000")
	f.advance(30 * time.Second)
	f.ping(c, br)
	f.e.Revalidate()
	f.ping(c, br)
	f.advance(31 * time.Second) // 61 s old, still busy
	f.ping(c, br)
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("lifetime"); v != 1 {
		t.Fatalf("closed{lifetime} = %v", v)
	}
}

func TestEdgeIdleDeadline(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	f.e.IdleTimeout = 20 * time.Second
	c, br := f.open("100.64.0.7:40000")
	f.advance(15 * time.Second)
	f.e.Revalidate()
	f.ping(c, br) // activity resets idle
	f.advance(15 * time.Second)
	f.e.Revalidate()
	f.ping(c, br)
	f.advance(21 * time.Second) // still before stale_after (10:03)
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("idle"); v != 1 {
		t.Fatalf("closed{idle} = %v", v)
	}
}

// TestEdgeRunTicks: the periodic tick closes a revoked connection with no
// explicit Revalidate call, within one tick.
func TestEdgeRunTicks(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.e.Run(ctx, 50*time.Millisecond)
	c, br := f.open("100.64.0.7:40000")
	f.doc.Store(nil)
	closedSoon(t, c, br)
	if v := f.closed("no_doc"); v != 1 {
		t.Fatalf("closed{no_doc} = %v", v)
	}
}

// TestEdgeConcurrentClose: revalidation racing with the peers closing
// themselves never double-closes or double-counts (run with -race).
func TestEdgeConcurrentClose(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	var conns []net.Conn
	for i := 0; i < 20; i++ {
		c, _ := f.open(fmt.Sprintf("100.64.0.7:%d", 40000+i))
		conns = append(conns, c)
	}
	waitSessions(t, f.e, 20)
	f.doc.Store(nil)
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(2)
		go func() { defer wg.Done(); f.e.Revalidate() }()
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				c.Close()
			}
		}()
	}
	wg.Wait()
	waitSessions(t, f.e, 0)
	total := f.closed("no_doc")
	if total > 20 {
		t.Fatalf("closed{no_doc} = %v > 20 sessions", total)
	}
}

// TestEdgeValidUntilClosesAndRejects: once vpn.json is past its
// valid_until (the Hub stopped republishing), every admitted connection
// closes and a new one is rejected, although nothing else changed.
func TestEdgeValidUntilClosesAndRejects(t *testing.T) {
	doc := strings.Replace(docJSON("127.0.0.1", false), `"valid_until":"2099-01-01T00:00:00Z"`, `"valid_until":"2026-11-13T10:02:00Z"`, 1)
	f := newFixture(t, doc)
	c, br := f.open("100.64.0.7:40000")
	f.ping(c, br)
	f.e.Revalidate()
	f.ping(c, br) // 10:01: still valid
	f.advance(time.Minute)
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("expired"); v != 1 {
		t.Fatalf("closed{expired} = %v", v)
	}
	c2, err := net.Dial("tcp4", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.Write(v2Header("100.64.0.7:40001"))
	c2.Write([]byte("ping\n"))
	closedSoon(t, c2, bufio.NewReader(c2))
	if v := testutil.ToFloat64(f.e.rejected.WithLabelValues("hs", "expired")); v != 1 {
		t.Fatalf("rejected{expired} = %v", v)
	}
}

// TestEdgeReboundClosesOldIngress: when the Hub moves a provider's
// gateway (or re-slots its edge port), sessions admitted through the old
// ingress close on the next re-check.
func TestEdgeReboundClosesOldIngress(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	c, br := f.open("100.64.0.7:40000")
	f.e.Revalidate()
	f.ping(c, br) // the same gateway: kept
	f.doc.Store(mustDoc(t, docJSON("127.0.0.2", false)))
	f.e.Revalidate()
	closedSoon(t, c, br)
	if v := f.closed("rebound"); v != 1 {
		t.Fatalf("closed{rebound} = %v", v)
	}
	f2 := newFixture(t, docJSON("127.0.0.1", false))
	c2, br2 := f2.open("100.64.0.7:40000")
	f2.doc.Store(mustDoc(t, strings.Replace(docJSON("127.0.0.1", false), `"edge_port":9001`, `"edge_port":9002`, 1)))
	f2.e.Revalidate()
	closedSoon(t, c2, br2)
	if v := f2.closed("rebound"); v != 1 {
		t.Fatalf("closed{rebound} after a re-slot = %v", v)
	}
}

// TestEdgeCaps: past the per-client cap a new connection is rejected
// (busy); one closes, a new one is admitted again. The provider cap counts
// connections from accept, before their header.
func TestEdgeCaps(t *testing.T) {
	f := newFixture(t, docJSON("127.0.0.1", false))
	f.e.MaxPerClient = 2
	c1, br1 := f.open("100.64.0.7:40001")
	f.open("100.64.0.7:40002")
	raw := func(src string) (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp4", f.addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.Write(v2Header(src))
		c.Write([]byte("ping\n"))
		return c, bufio.NewReader(c)
	}
	c3, br3 := raw("100.64.0.7:40003")
	closedSoon(t, c3, br3)
	if v := testutil.ToFloat64(f.e.rejected.WithLabelValues("hs", "busy")); v != 1 {
		t.Fatalf("rejected{busy} = %v", v)
	}
	c1.Close()
	closedSoon(t, c1, br1)
	deadline := time.Now().Add(2 * time.Second)
	for f.e.Sessions() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	f.open("100.64.0.7:40004") // a slot again

	g := newFixture(t, docJSON("127.0.0.1", false))
	g.e.MaxPerProvider = 1
	idle, err := net.Dial("tcp4", g.addr) // accepted, no header yet: it counts
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		g.e.capMu.Lock()
		n := g.e.perProv["hs"]
		g.e.capMu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c, err := net.Dial("tcp4", g.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(v2Header("100.64.0.7:40005"))
	c.Write([]byte("ping\n"))
	closedSoon(t, c, bufio.NewReader(c))
	if v := testutil.ToFloat64(g.e.rejected.WithLabelValues("hs", "busy")); v != 1 {
		t.Fatalf("provider cap: rejected{busy} = %v", v)
	}
}
