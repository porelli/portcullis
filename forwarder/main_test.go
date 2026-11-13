package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

// edgeStub accepts one connection, reads the PROXY header and hands the
// rest of the stream to fn.
func edgeStub(t *testing.T, fn func(h *proxyproto.Header, c net.Conn, br *bufio.Reader)) string {
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
				h, err := proxyproto.Read(br)
				if err != nil {
					return
				}
				fn(h, c, br)
			}()
		}
	}()
	return ln.Addr().String()
}

func startForwarder(t *testing.T, edge string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go serve(ctx, ln, edge)
	return ln.Addr().String()
}

func TestForwardsWithHeader(t *testing.T) {
	got := make(chan *proxyproto.Header, 1)
	edge := edgeStub(t, func(h *proxyproto.Header, c net.Conn, br *bufio.Reader) {
		got <- h
		line, _ := br.ReadString('\n')
		c.Write([]byte("re:" + line))
	})
	fw := startForwarder(t, edge)
	c, err := net.Dial("tcp4", fw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hello\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, _ := bufio.NewReader(c).ReadString('\n')
	h := <-got
	if h.Version != 2 || !h.Command.IsProxy() || h.TransportProtocol != proxyproto.TCPv4 {
		t.Fatalf("header %+v", h)
	}
	if h.SourceAddr.String() != c.LocalAddr().String() {
		t.Fatalf("source %s, want the peer %s", h.SourceAddr, c.LocalAddr())
	}
	if h.DestinationAddr.String() != fw {
		t.Fatalf("destination %s, want %s", h.DestinationAddr, fw)
	}
	if reply != "re:hello\n" {
		t.Fatalf("reply %q", reply)
	}
}

func TestRefusesWithoutEdge(t *testing.T) {
	for _, v := range []string{"", "edge", "edge:9001", "172.31.254.3", "172.31.254.3:0", "[fd00::3]:9001", "172.31.254.3:70000"} {
		var stderr bytes.Buffer
		code := run(func(k string) string {
			if k == "PORTCULLIS_VPN_EDGE" {
				return v
			}
			return ""
		}, &stderr)
		if code != 2 {
			t.Fatalf("PORTCULLIS_VPN_EDGE=%q: exit %d", v, code)
		}
		if !strings.Contains(stderr.String(), "PORTCULLIS_VPN_EDGE") {
			t.Fatalf("message %q", stderr.String())
		}
	}
	var stderr bytes.Buffer
	code := run(func(k string) string {
		return map[string]string{"PORTCULLIS_VPN_EDGE": "172.31.254.3:9001", "FORWARDER_LISTEN": "nonsense"}[k]
	}, &stderr)
	if code != 2 {
		t.Fatalf("bad FORWARDER_LISTEN: exit %d", code)
	}
}

// TestHalfCloseSplice: the client finishes sending (CloseWrite) and still
// reads the whole answer the edge sends after seeing EOF.
func TestHalfCloseSplice(t *testing.T) {
	edge := edgeStub(t, func(h *proxyproto.Header, c net.Conn, br *bufio.Reader) {
		body, _ := io.ReadAll(br) // until the client's half-close
		c.Write([]byte("got " + string(body)))
		c.(*net.TCPConn).CloseWrite()
	})
	fw := startForwarder(t, edge)
	c, err := net.Dial("tcp4", fw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("request body"))
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	all, err := io.ReadAll(c)
	if err != nil || string(all) != "got request body" {
		t.Fatalf("read %q %v", all, err)
	}
}

func TestEdgeDownClosesClient(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	fw := startForwarder(t, dead)
	c, err := net.Dial("tcp4", fw)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("client still open with the edge down")
	}
}
