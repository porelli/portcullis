package main

import (
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAPIOnlyOnItsNetwork(t *testing.T) {
	p := netip.MustParsePrefix("172.31.252.0/28")
	for addr, want := range map[string]bool{
		"172.31.252.2:8080":          true, // portcullis-domains
		"127.0.0.1:8080":             true, // health check
		"[::1]:8080":                 true,
		"172.31.253.3:8080":          false, // portcullis-certs (Traefik)
		"10.0.0.5:8080":              false, // domains-egress
		"[::ffff:172.31.252.2]:8080": true,
	} {
		ta, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := apiLocalAllowed(ta, p); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	// Through the wrapper: a loopback connection (the health check) passes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	l := subnetListener{Listener: ln, allowed: p, logf: t.Logf}
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestCertExpiryWarning(t *testing.T) {
	now := time.Now()
	if w := certExpiryWarning(&x509.Certificate{NotAfter: now.Add(10 * 24 * time.Hour)}, now); !strings.Contains(w, "./portcullis up") {
		t.Fatalf("warning %q", w)
	}
	if w := certExpiryWarning(&x509.Certificate{NotAfter: now.Add(200 * 24 * time.Hour)}, now); w != "" {
		t.Fatalf("no warning expected: %q", w)
	}
}
