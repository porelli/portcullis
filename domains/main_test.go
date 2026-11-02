package main

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// TestTimeoutTransport: a server that sends headers and then stalls the
// body can't hold a request (as porkbun's own http.Client{} would) longer
// than the per-request deadline.
func TestTimeoutTransport(t *testing.T) {
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(200)
		w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stall)
	orig := http.DefaultTransport
	defer func() { http.DefaultTransport = orig; http.DefaultClient.Timeout = 0 }()
	setHTTPDefaults(300 * time.Millisecond)
	start := time.Now()
	resp, err := (&http.Client{}).Get(srv.URL) // like porkbun: no client timeout
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("a stalled body read succeeded")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stalled for %s", d)
	}
}
