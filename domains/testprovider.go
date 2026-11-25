//go:build testprovider

package main

// CI-only build (go build -tags testprovider; Dockerfile build arg
// GO_TAGS=testprovider): adds provider "fake" — an in-memory zone shared by
// every domain, served as DNS on DOMAINS_FAKEDNS_ADDR (default :8053) for
// Pebble's DNS-01 validation and the records check. Token "bad-token-0000" is
// rejected (backoff tests). DOMAINS_FAKEDNS_API_ADDR / _REMOTE share the
// service's zone with the one-shots (fakedns.Remote). Never in the
// production image.

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/portcullis/domains/internal/fakedns"
)

func startTestProvider(logger *log.Logger) error {
	zone := fakedns.NewZone()
	// DOMAINS_FAKEDNS_REMOTE (a one-shot: dns-tool, mail-cert): provider
	// "fake" writes into the domains service's zone at that URL, so the
	// records outlive the one-shot. DOMAINS_FAKEDNS_API_ADDR (the
	// service): serve this zone's provider calls there (fakedns.APIHandler).
	remote := os.Getenv("DOMAINS_FAKEDNS_REMOTE")
	providers["fake"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		if remote != "" {
			return &fakedns.Remote{URL: remote, Token: c["api_token"]}, nil
		}
		return &fakedns.Provider{Zone: zone, Token: c["api_token"], Accept: fakeAccept}, nil
	}}
	if api := os.Getenv("DOMAINS_FAKEDNS_API_ADDR"); api != "" {
		ln, err := net.Listen("tcp", api)
		if err != nil {
			return err
		}
		go (&http.Server{Handler: fakedns.APIHandler(zone, fakeAccept), ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
		logger.Printf("WARNING: test build — the fake zone's provider API on %s", ln.Addr())
	}
	addr := os.Getenv("DOMAINS_FAKEDNS_ADDR")
	if addr == "" {
		addr = ":8053"
	}
	srv, err := fakedns.Serve(zone, addr)
	if err != nil {
		return err
	}
	logger.Printf("WARNING: test build — provider \"fake\" enabled, fake DNS on %s (never use this image in production)", srv.Addr)
	return nil
}

// fakeAccept: the fake provider's token check ("bad-token-0000" refused:
// the backoff tests).
func fakeAccept(t string) bool { return t != "bad-token-0000" }

// runTestCommand runs the test build's own commands; ok false for any
// other (the production build has none). `domains fakezone`: a fake zone
// alone, its provider API on DOMAINS_FAKEDNS_API_ADDR (required) and its
// DNS on DOMAINS_FAKEDNS_ADDR (only when set), every accepted change
// logged (fakedns.ChangeLog), until SIGTERM. CI's e2e-ha-k3d runs it
// outside the cluster as the front door's zone (DOMAINS_FAKEDNS_REMOTE):
// the records outlive every front-door restart, and the harness reads
// them and their history.
func runTestCommand(args []string) (int, bool) {
	if len(args) == 0 || args[0] != "fakezone" {
		return 0, false
	}
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: domains fakezone")
		return 2, true
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	api := os.Getenv("DOMAINS_FAKEDNS_API_ADDR")
	if api == "" {
		logger.Print("refusing to start: DOMAINS_FAKEDNS_API_ADDR is required")
		return exitFailure, true
	}
	zone := fakedns.NewZone()
	if addr := os.Getenv("DOMAINS_FAKEDNS_ADDR"); addr != "" {
		srv, err := fakedns.Serve(zone, addr)
		if err != nil {
			logger.Print(err)
			return exitFailure, true
		}
		defer srv.Close()
	}
	ln, err := net.Listen("tcp", api)
	if err != nil {
		logger.Print(err)
		return exitFailure, true
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	srv := &http.Server{Handler: fakedns.ChangeLog(fakedns.APIHandler(zone, fakeAccept), logger.Printf), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	logger.Printf("WARNING: test build — a fake zone alone, its provider API on %s (never use this image in production)", ln.Addr())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Print(err)
		return exitFailure, true
	}
	return 0, true
}

// testProviderBuild: the test build (CI's fake zone) publishes the
// documentation ranges (frontdoor.AddrPolicy).
const testProviderBuild = true
