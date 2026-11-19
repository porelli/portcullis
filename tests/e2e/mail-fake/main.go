// mail-fake is a CI-only mail provider (mail provider plan Task 26): the
// provider API v1 (contract §19.5) over a store kept in its data volume,
// honouring the slot gate (P3), with no mail server behind it (its
// listeners accept and close). Core e2e-mail switches to it (11), contains it in hostile mode
// (12) and runs the conformance suite's api level against it (16).
//
//	mail-fake [serve]                 the provider (gate first)
//	mail-fake mode honest|hostile     switch a running fake (its mode file)
//	mail-fake healthcheck             exit 0 when the API answers on loopback
//
// Environment: PORTCULLIS_MAIL_API_SUBNET (required: requests addressed
// outside it are refused), MAIL_FAKE_NAME (the provider's label),
// MAIL_FAKE_DATA (default /data: the mode file and the store, state.json,
// which survives a restart like a real provider's), MAIL_FAKE_SLOT
// (default /run/portcullis/mail/slot), PORTCULLIS_MAIL_VOID_SESSION (void
// mode), PORTCULLIS_MAIL_HOSTNAME (the MTA-STS policy's mx).
package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/portcullis/mail-fake/internal/fake"
)

func main() { os.Exit(run(os.Args[1:], os.Getenv)) }

func run(args []string, env func(string) string) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	data := or(env("MAIL_FAKE_DATA"), "/data")
	switch cmd {
	case "serve":
	case "mode":
		if len(args) != 2 || (args[1] != fake.ModeHonest && args[1] != fake.ModeHostile) {
			fmt.Fprintln(os.Stderr, "usage: mail-fake mode honest|hostile")
			return 2
		}
		if err := os.WriteFile(filepath.Join(data, "mode"), []byte(args[1]+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "mail-fake:", err)
			return 1
		}
		fmt.Println("mode", args[1])
		return 0
	case "healthcheck":
		c := http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get("http://127.0.0.1:8080/healthz")
		if err != nil || resp.StatusCode != 200 {
			return 1
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, "usage: mail-fake [serve | mode honest|hostile | healthcheck]")
		return 2
	}
	slot := or(env("MAIL_FAKE_SLOT"), or(env("PORTCULLIS_MAIL_SLOT_DIR"), "/run/portcullis/mail/slot"))
	if err := Gate(slot, env("PORTCULLIS_MAIL_VOID_SESSION")); err != nil {
		fmt.Fprintln(os.Stderr, "mail-fake: the slot gate refuses the start:", err)
		return 1
	}
	sub, err := netip.ParsePrefix(strings.TrimSpace(env("PORTCULLIS_MAIL_API_SUBNET")))
	if err != nil {
		fmt.Fprintln(os.Stderr, "mail-fake: PORTCULLIS_MAIL_API_SUBNET must be a network:", err)
		return 1
	}
	name := or(env("MAIL_FAKE_NAME"), "Mail fake")
	s := fake.New(filepath.Join(slot, "api-secret"), sub, name)
	// The store in the data volume: it survives the void-mode start.
	if err := s.UseStateFile(filepath.Join(data, "state.json")); err != nil {
		fmt.Fprintln(os.Stderr, "mail-fake: the store:", err)
		return 1
	}
	go watchMode(s, filepath.Join(data, "mode"))
	host := or(env("PORTCULLIS_MAIL_HOSTNAME"), "mail.invalid")
	errc := make(chan error, 8)
	serve := func(addr string, h http.Handler) {
		srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		errc <- srv.ListenAndServe()
	}
	go serve(":8080", healthz(s.Handler()))
	go serve(":8081", wellknown(host))
	go serve(":9100", metrics(filepath.Join(slot, "metrics-secret"), name))
	for _, p := range []string{"10025", "10465", "10587", "10993"} {
		go acceptClose(":"+p, errc)
	}
	log.Printf("mail-fake %q serving (provider API :8080, well-known :8081, metrics :9100, listeners accept and close)", name)
	err = <-errc
	fmt.Fprintln(os.Stderr, "mail-fake:", err)
	return 1
}

func or(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

// Gate is P3: void-pending absent and .present exactly portcullis-mail-gate
// (one optional trailing newline); or void-pending present, void-session
// non-empty and equal to the env's session byte for byte. Anything else,
// an unreadable file included, refuses.
func Gate(slot, session string) error {
	_, err := os.Lstat(filepath.Join(slot, "void-pending"))
	switch {
	case err == nil:
		b, rerr := os.ReadFile(filepath.Join(slot, "void-session"))
		if rerr != nil || len(b) == 0 || session == "" || string(b) != session {
			return errors.New("void mode without this session")
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("void-pending: %w", err)
	}
	b, err := os.ReadFile(filepath.Join(slot, ".present"))
	if err != nil {
		return errors.New("not wired (no .present)")
	}
	if v := strings.TrimSuffix(string(b), "\n"); v != "portcullis-mail-gate" {
		return errors.New(".present isn't the gate sentinel")
	}
	return nil
}

// watchMode applies the mode file every second (mail-fake mode …).
func watchMode(s *fake.Server, file string) {
	last := ""
	for {
		b, err := os.ReadFile(file)
		m := strings.TrimSpace(string(b))
		if err != nil {
			m = fake.ModeHonest
		}
		if m != last && s.SetMode(m) {
			log.Printf("mail-fake: mode %s", m)
			last = m
		}
		time.Sleep(time.Second)
	}
}

// healthz answers GET /healthz on loopback (the container's check); the
// rest goes to the guarded API.
func healthz(api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			if a, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok && a.IP.IsLoopback() {
				w.Write([]byte("ok\n"))
				return
			}
		}
		api.ServeHTTP(w, r)
	})
}

// wellknown serves the MTA-STS policy (mode enforce, the mail host).
func wellknown(host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "version: STSv1\nmode: enforce\nmx: %s\nmax_age: 86400\n", host)
	})
}

// metrics: a gauge or two behind Basic auth prometheus:<metrics-secret>.
func metrics(secretFile, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(secretFile)
		u, p, ok := r.BasicAuth()
		if err != nil || !ok || u != "prometheus" || p != strings.TrimSpace(string(b)) {
			w.WriteHeader(401)
			return
		}
		fmt.Fprintf(w, "# TYPE portcullis_mail_queue_messages gauge\nportcullis_mail_queue_messages 0\n# TYPE mail_fake_info gauge\nmail_fake_info{name=%q} 1\n", name)
	})
}

// acceptClose: a listener that accepts and closes (a port the Hub's
// override publishes; no mail behind it).
func acceptClose(addr string, errc chan<- error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		errc <- err
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		c.Close()
	}
}
