// Command forwarder is Portcullis' PROXY v2 forwarder for VPN apps whose
// node has a real tunnel interface (NetBird, plain WireGuard): it runs in
// the VPN client's network namespace (compose network_mode: service:),
// listens on FORWARDER_LISTEN (default :443) and forwards every
// connection to the wg service's edge port PORTCULLIS_VPN_EDGE with a
// PROXY v2 header whose source is the peer address it sees, i.e. the
// tunnel address of the device (contract §16). The edge checks that
// address against the provider's ranges and device map. No state, no
// configuration beyond the two variables, no secrets.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/pires/go-proxyproto"
)

func main() {
	os.Exit(run(os.Getenv, os.Stderr))
}

func run(getenv func(string) string, stderr io.Writer) int {
	edge, err := netip.ParseAddrPort(getenv("PORTCULLIS_VPN_EDGE"))
	if err != nil || !edge.Addr().Is4() || edge.Port() == 0 {
		fmt.Fprintln(stderr, "forwarder: PORTCULLIS_VPN_EDGE must be the wg edge's <ipv4>:<port> (the Hub sets it on a wired provider)")
		return 2
	}
	listen := getenv("FORWARDER_LISTEN")
	if listen == "" {
		listen = ":443"
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		fmt.Fprintln(stderr, "forwarder: FORWARDER_LISTEN must be [<host>]:<port>")
		return 2
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(stderr, "forwarder: listen %s: %v\n", listen, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Printf("forwarder: %s → %s (PROXY v2)", listen, edge)
	serve(ctx, ln, edge.String())
	return 0
}

// serve accepts until ctx ends.
func serve(ctx context.Context, ln net.Listener, edge string) {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go forward(c, edge)
	}
}

func forward(c net.Conn, edge string) {
	up, err := net.DialTimeout("tcp4", edge, 5*time.Second)
	if err != nil {
		c.Close()
		return
	}
	h := proxyproto.HeaderProxyFromAddrs(2, c.RemoteAddr(), c.LocalAddr())
	if _, err := h.WriteTo(up); err != nil {
		up.Close()
		c.Close()
		return
	}
	splice(c, up)
}

// splice copies both ways; when one side finishes sending, the other side
// gets a half-close (CloseWrite), so request bodies and answers after it
// still flow. Both are closed once both directions end.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
