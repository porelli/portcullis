package edge

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/portcullis/wg/internal/vpndoc"
)

var now0 = time.Date(2026, 11, 13, 10, 1, 0, 0, time.UTC)

func mustDoc(t *testing.T, s string) *vpndoc.Doc {
	t.Helper()
	d, err := vpndoc.Parse([]byte(s))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return d
}

func docJSON(gateway string, stale bool) string {
	st := "false"
	if stale {
		st = "true"
	}
	return `{"version":2,"valid_until":"2099-01-01T00:00:00Z",
 "builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":[],
  "peers":[{"ip":"10.213.0.5","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d1","expires":null}]},
 "providers":[{"id":"builtin","source":"builtin","ranges":["10.213.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false},
  {"id":"hs","source":"hook","label":"t","ranges":["100.64.0.0/10"],"edge_port":9001,"gateway_ip":"` + gateway + `",
   "refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":` + st + `}],
 "devices":[{"ip":"100.64.0.7","provider":"hs","user":"alice","device_id":"hs:1","name":"a","expires":null},
  {"ip":"10.213.0.5","provider":"builtin","user":"bob","device_id":"d1","name":"p","expires":null}]}`
}

// fakeTraefik records the PROXY header and the payload of each connection.
type fakeTraefik struct {
	ln  net.Listener
	got chan received
}

type received struct {
	hdr     *proxyproto.Header
	payload string
}

func newFakeTraefik(t *testing.T) *fakeTraefik {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTraefik{ln: ln, got: make(chan received, 8)}
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
				h, err := proxyproto.Read(br)
				if err != nil {
					f.got <- received{}
					return
				}
				line, _ := br.ReadString('\n')
				c.Write([]byte("pong\n"))
				f.got <- received{hdr: h, payload: line}
			}()
		}
	}()
	return f
}

func (f *fakeTraefik) addr() netip.AddrPort {
	return netip.MustParseAddrPort(f.ln.Addr().String())
}

// portListener reports a fixed local port on every accepted connection,
// standing in for the provider's 9001+slot listener.
type portListener struct {
	net.Listener
	port int
}

type portConn struct {
	net.Conn
	port int
}

func (l portListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return portConn{c, l.port}, nil
}

func (c portConn) LocalAddr() net.Addr {
	a := c.Conn.LocalAddr().(*net.TCPAddr)
	return &net.TCPAddr{IP: a.IP, Port: c.port}
}

func (c portConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }

func v2Header(src string) []byte {
	h := proxyproto.HeaderProxyFromAddrs(2,
		net.TCPAddrFromAddrPort(netip.MustParseAddrPort(src)),
		&net.TCPAddr{IP: net.IPv4(172, 31, 254, 3), Port: 9001})
	b, err := h.Format()
	if err != nil {
		panic(err)
	}
	return b
}

func TestEdgeAcceptRules(t *testing.T) {
	cases := []struct {
		name    string
		doc     string // "" = no doc
		port    int
		send    []byte
		reason  string // "" = accepted
		wantSrc string
	}{
		{name: "accepted", doc: docJSON("127.0.0.1", false), port: 9001, send: v2Header("100.64.0.7:40000"), wantSrc: "100.64.0.7:40000"},
		{name: "wrong port", doc: docJSON("127.0.0.1", false), port: 9002, send: v2Header("100.64.0.7:40000"), reason: "wrong_port"},
		{name: "wrong gateway", doc: docJSON("127.0.0.9", false), port: 9001, send: v2Header("100.64.0.7:40000"), reason: "wrong_gateway"},
		{name: "no header", doc: docJSON("127.0.0.1", false), port: 9001, send: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), reason: "no_header"},
		{name: "v1 header", doc: docJSON("127.0.0.1", false), port: 9001, send: []byte("PROXY TCP4 100.64.0.7 172.31.254.3 40000 9001\r\n"), reason: "no_header"},
		{name: "slow header", doc: docJSON("127.0.0.1", false), port: 9001, send: v2Header("100.64.0.7:40000")[:6], reason: "slow_header"},
		{name: "outside ranges", doc: docJSON("127.0.0.1", false), port: 9001, send: v2Header("10.9.9.9:40000"), reason: "outside_ranges"},
		{name: "ipv6 source", doc: docJSON("127.0.0.1", false), port: 9001, send: v2Header("[fd00::7]:40000"), reason: "outside_ranges"},
		{name: "not in map", doc: docJSON("127.0.0.1", false), port: 9001, send: v2Header("100.64.0.8:40000"), reason: "not_in_map"},
		{name: "stale", doc: docJSON("127.0.0.1", true), port: 9001, send: v2Header("100.64.0.7:40000"), reason: "stale"},
		{name: "no doc", doc: "", port: 9001, send: v2Header("100.64.0.7:40000"), reason: "no_doc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := newFakeTraefik(t)
			var d *vpndoc.Doc
			if tc.doc != "" {
				d = mustDoc(t, tc.doc)
			}
			e := New(tr.addr(), netip.MustParseAddr("127.0.0.1"), func() *vpndoc.Doc { return d }, func() time.Time { return now0 })
			e.HeaderTimeout = 200 * time.Millisecond
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go e.ServeProvider(ctx, portListener{ln, tc.port}, "hs")
			c, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write(tc.send)
			if tc.reason == "" {
				c.Write([]byte("ping\n"))
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				reply, _ := bufio.NewReader(c).ReadString('\n')
				r := <-tr.got
				if r.hdr == nil {
					t.Fatal("Traefik got no PROXY header")
				}
				if r.hdr.Version != 2 || r.hdr.SourceAddr.String() != tc.wantSrc {
					t.Fatalf("header %+v, want v2 from %s", r.hdr, tc.wantSrc)
				}
				if r.payload != "ping\n" || reply != "pong\n" {
					t.Fatalf("payload %q reply %q", r.payload, reply)
				}
				if v := testutil.ToFloat64(e.accepted.WithLabelValues("hs")); v != 1 {
					t.Fatalf("accepted = %v", v)
				}
				return
			}
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadAll(c); err != nil && !strings.Contains(err.Error(), "reset") {
				t.Fatalf("connection not closed: %v", err)
			}
			if v := testutil.ToFloat64(e.rejected.WithLabelValues("hs", tc.reason)); v != 1 {
				t.Fatalf("rejected{%s} = %v", tc.reason, v)
			}
			select {
			case <-tr.got:
				t.Fatal("a rejected connection reached Traefik")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestEdgeGatewayClaimsBuiltinAddress(t *testing.T) {
	tr := newFakeTraefik(t)
	d := mustDoc(t, docJSON("127.0.0.1", false))
	e := New(tr.addr(), netip.MustParseAddr("127.0.0.1"), func() *vpndoc.Doc { return d }, func() time.Time { return now0 })
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.ServeProvider(ctx, portListener{ln, 9001}, "hs")
	c, _ := net.Dial("tcp4", ln.Addr().String())
	defer c.Close()
	c.Write(v2Header("10.213.0.5:40000")) // a real built-in device's address
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	io.ReadAll(c)
	if v := testutil.ToFloat64(e.rejected.WithLabelValues("hs", "outside_ranges")); v != 1 {
		t.Fatalf("outside_ranges = %v", v)
	}
}

func TestEdgeNoDocDeniesAll(t *testing.T) {
	tr := newFakeTraefik(t)
	e := New(tr.addr(), netip.MustParseAddr("127.0.0.1"), func() *vpndoc.Doc { return nil }, func() time.Time { return now0 })
	// The in-process built-in path too.
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { e.Handle(a, vpndoc.BuiltinID, netip.MustParseAddr("10.213.0.5")); close(done) }()
	<-done
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("pipe still open")
	}
	if v := testutil.ToFloat64(e.rejected.WithLabelValues("builtin", "no_doc")); v != 1 {
		t.Fatalf("no_doc = %v", v)
	}
	// A parse error is the same nil doc: the caller keeps nothing.
	if _, err := vpndoc.Parse([]byte(`{"version":2,"valid_until":"2099-01-01T00:00:00Z","bogus":1}`)); err == nil {
		t.Fatal("bogus doc parsed")
	}
}

func TestEdgeBuiltinHandle(t *testing.T) {
	tr := newFakeTraefik(t)
	d := mustDoc(t, docJSON("127.0.0.1", false))
	e := New(tr.addr(), netip.MustParseAddr("127.0.0.1"), func() *vpndoc.Doc { return d }, func() time.Time { return now0 })
	for _, tc := range []struct{ ip, reason string }{
		{"10.213.0.5", ""},
		{"10.213.0.6", "not_in_map"},
		{"100.64.0.7", "outside_ranges"}, // a tailnet address can't come from the built-in stack
	} {
		srv, cli := net.Pipe()
		go e.Handle(srv, vpndoc.BuiltinID, netip.MustParseAddr(tc.ip))
		if tc.reason != "" {
			cli.SetReadDeadline(time.Now().Add(2 * time.Second))
			io.ReadAll(cli)
			if v := testutil.ToFloat64(e.rejected.WithLabelValues("builtin", tc.reason)); v != 1 {
				t.Fatalf("%s: %s = %v", tc.ip, tc.reason, v)
			}
			continue
		}
		cli.Write([]byte("ping\n"))
		r := <-tr.got
		if r.hdr == nil || !strings.HasPrefix(r.hdr.SourceAddr.String(), tc.ip+":") {
			t.Fatalf("header %+v", r.hdr)
		}
		cli.Close()
	}
}
