//go:build testprovider

package main

// CI-only build (go build -tags testprovider; Dockerfile build arg
// GO_TAGS=testprovider): adds provider "fake" — an in-memory zone shared by
// every domain, served as DNS on DOMAINS_FAKEDNS_ADDR (default :8053) for
// Pebble's DNS-01 validation and the records check. Token "bad-token-0000" is
// rejected (backoff tests). Never in the production image.

import (
	"log"
	"os"

	"github.com/portcullis/domains/internal/fakedns"
)

func startTestProvider(logger *log.Logger) error {
	zone := fakedns.NewZone()
	providers["fake"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return &fakedns.Provider{Zone: zone, Token: c["api_token"], Accept: func(t string) bool { return t != "bad-token-0000" }}, nil
	}}
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
