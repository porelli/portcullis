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
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/portcullis/domains/internal/fakedns"
)

func startTestProvider(logger *log.Logger) error {
	zone := fakedns.NewZone()
	accept := func(t string) bool { return t != "bad-token-0000" }
	// DOMAINS_FAKEDNS_REMOTE (a one-shot: dns-tool, mail-cert): provider
	// "fake" writes into the domains service's zone at that URL, so the
	// records outlive the one-shot. DOMAINS_FAKEDNS_API_ADDR (the
	// service): serve this zone's provider calls there (fakedns.APIHandler).
	remote := os.Getenv("DOMAINS_FAKEDNS_REMOTE")
	providers["fake"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		if remote != "" {
			return &fakedns.Remote{URL: remote, Token: c["api_token"]}, nil
		}
		return &fakedns.Provider{Zone: zone, Token: c["api_token"], Accept: accept}, nil
	}}
	if api := os.Getenv("DOMAINS_FAKEDNS_API_ADDR"); api != "" {
		ln, err := net.Listen("tcp", api)
		if err != nil {
			return err
		}
		go (&http.Server{Handler: fakedns.APIHandler(zone, accept), ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
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

// testProviderBuild: the test build (CI's fake zone) publishes the
// documentation ranges (frontdoor.AddrPolicy).
const testProviderBuild = true
