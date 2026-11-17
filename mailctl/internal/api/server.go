// Package api is mailctl's Hub API (integration contract §19.5): served on
// the adapter's portcullis-mail-api address only, behind the Hub ⇄ provider
// bearer secret. A request addressed outside PORTCULLIS_MAIL_API_SUBNET, or with
// another bearer, gets 403 and an empty body; GET /healthz answers on
// loopback only (the container's health check).
package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// MinSecret is the shortest Hub secret accepted (contract §19.1).
const MinSecret = 32

// ReadSecret reads a secret file: trimmed, at least min characters.
func ReadSecret(path string, min int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%s is unreadable", path)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return "", fmt.Errorf("%s is unreadable", path)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	if len(s) < min {
		return "", fmt.Errorf("%s holds fewer than %d characters", path, min)
	}
	return s, nil
}

// Server guards Handler (the v1 routes).
type Server struct {
	Subnet     netip.Prefix // PORTCULLIS_MAIL_API_SUBNET
	SecretFile string       // read at every request (a rotated secret works at once)
	Handler    http.Handler
	Logf       func(string, ...any)
}

func localAddr(r *http.Request) (netip.Addr, bool) {
	a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return netip.Addr{}, false
	}
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	return ip.Unmap(), ok
}

func refuse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
}

func (s *Server) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, ok := localAddr(r)
	if !ok {
		refuse(w)
		return
	}
	if !s.Subnet.Contains(ip) {
		if ip.IsLoopback() && r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("ok\n"))
			return
		}
		s.logf("api: refused a request to %s (not on portcullis-mail-api)", ip)
		refuse(w)
		return
	}
	secret, err := ReadSecret(s.SecretFile, MinSecret)
	if err != nil {
		s.logf("api: refusing every request: the Hub secret %v", err)
		refuse(w)
		return
	}
	want := sha256.Sum256([]byte("Bearer " + secret))
	got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		refuse(w)
		return
	}
	if s.Handler == nil {
		http.NotFound(w, r)
		return
	}
	s.Handler.ServeHTTP(w, r)
}
