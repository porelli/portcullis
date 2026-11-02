// Command domains is Portcullis' domains service (integration contract
// §12): it holds the DNS credentials of the domains Hub admins enroll,
// points <d> and *.<d> at the server, obtains and renews a wildcard
// certificate per domain with ACME DNS-01, and hands the certificates to
// Traefik's HTTP provider over mutual TLS.
//
//	domains            run the service
//	domains keygen     print a new age X25519 identity (secrets/domains/age.key)
//	domains healthcheck  exit 0 if the API answers /healthz (Docker HEALTHCHECK)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/go-acme/lego/v4/challenge/dns01"
	legolog "github.com/go-acme/lego/v4/log"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "keygen":
			id, err := age.GenerateX25519Identity()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), id.Recipient(), id)
			return
		case "healthcheck":
			c := &http.Client{Timeout: 3 * time.Second}
			resp, err := c.Get("http://127.0.0.1" + env("DOMAINS_API_ADDR", ":8080") + "/healthz")
			if err != nil || resp.StatusCode != 200 {
				os.Exit(1)
			}
			return
		default:
			fmt.Fprintf(os.Stderr, "usage: domains [keygen|healthcheck]\n")
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
}

// readSecret reads the API secret file (at least 32 characters).
func readSecret(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("API secret %s unreadable", path)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", fmt.Errorf("API secret %s unreadable", path)
	}
	s := strings.TrimSpace(string(b))
	if len(s) < 32 {
		return "", fmt.Errorf("API secret %s must hold at least 32 characters", path)
	}
	return s, nil
}

func parseIP(name string, want4 bool) (netip.Addr, error) {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(v)
	if err != nil || ip.Is4() != want4 || ip.Is4In6() {
		return netip.Addr{}, fmt.Errorf("%s=%q is not an IPv%s address", name, v, map[bool]string{true: "4", false: "6"}[want4])
	}
	return ip, nil
}

func run() error {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	// lego logs ACME progress (domains, never DNS credentials: the
	// challenge provider is ours).
	legolog.Logger = log.New(os.Stderr, "lego: ", log.LstdFlags)

	mainDomain := strings.ToLower(strings.TrimSuffix(os.Getenv("PORTCULLIS_DOMAIN"), "."))
	if !validHostname(mainDomain) {
		return fmt.Errorf("PORTCULLIS_DOMAIN=%q is not a valid hostname", mainDomain)
	}
	secret, err := readSecret(env("DOMAINS_API_SECRET_FILE", "/run/portcullis/domains/api-secret"))
	if err != nil {
		return err
	}
	id, err := loadIdentity(env("DOMAINS_AGE_KEY_FILE", "/run/portcullis/domains/age.key"))
	if err != nil {
		return err
	}
	ip4, err := parseIP("DOMAINS_PUBLIC_IPV4", true)
	if err != nil {
		return err
	}
	ip6, err := parseIP("DOMAINS_PUBLIC_IPV6", false)
	if err != nil {
		return err
	}
	if !ip4.IsValid() {
		logger.Printf("WARNING: DOMAINS_PUBLIC_IPV4 is not set: records can't be created until ./portcullis up detects it")
	}
	var resolvers []string
	for _, r := range strings.Split(env("DOMAINS_RESOLVERS", "1.1.1.1:53,8.8.8.8:53"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			resolvers = append(resolvers, r)
		}
	}
	// The SOA lookups (zone of a domain) and lego's propagation check use
	// the same public resolvers as the records check.
	_ = dns01.AddRecursiveNameservers(resolvers)(nil)

	cfg := Config{
		MainDomain: mainDomain,
		Email:      env("ACME_EMAIL", "admin@"+mainDomain),
		CAServer:   env("ACME_CA_SERVER", "https://acme-v02.api.letsencrypt.org/directory"),
		IPv4:       ip4, IPv6: ip6,
		Resolvers: resolvers,
		Secret:    secret,
		Logger:    logger,
	}
	svc, err := NewService(cfg, OpenStore(env("DOMAINS_DATA_DIR", "/data"), id))
	if err != nil {
		return err
	}
	certsTLS, err := endpointTLS(
		env("DOMAINS_CERTS_CA", "/run/portcullis/domains/certs-endpoint/ca.crt"),
		env("DOMAINS_CERTS_CERT", "/run/portcullis/domains/certs-endpoint/server.crt"),
		env("DOMAINS_CERTS_KEY", "/run/portcullis/domains/certs-endpoint/server.key"))
	if err != nil {
		return err
	}
	if err := startTestProvider(logger); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	api := &http.Server{Addr: env("DOMAINS_API_ADDR", ":8080"), Handler: svc.APIHandler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 2 * time.Minute}
	certs := &http.Server{Addr: env("DOMAINS_CERTS_ADDR", ":8443"), Handler: svc.CertsHandler(), TLSConfig: certsTLS,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		ErrorLog: log.New(io.Discard, "", 0)} // TLS handshake failures (no client cert) are expected noise
	errc := make(chan error, 2)
	go func() { errc <- api.ListenAndServe() }()
	go func() { errc <- certs.ListenAndServeTLS("", "") }()
	go svc.Run(ctx)
	logger.Printf("domains: API on %s, certificate endpoint on %s (mTLS), main domain %s, ACME %s", api.Addr, certs.Addr, mainDomain, cfg.CAServer)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api.Shutdown(shutdown)
	certs.Shutdown(shutdown)
	return nil
}

// endpointTLS is the certificate endpoint's TLS: its server certificate
// and a client certificate from the endpoint CA required on every
// connection (contract §12.4).
func endpointTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("certificate endpoint CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("certificate endpoint CA %s: no certificate", caFile)
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("certificate endpoint server certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
