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
	"net"
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

// setHTTPDefaults bounds every HTTP request of libraries that build their
// own client on http.DefaultTransport / http.DefaultClient (porkbun,
// hetzner, ...): they ignore contexts, and a hung provider must not hold
// a records step (and with it DELETE) forever.
func setHTTPDefaults(perRequest time.Duration) {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
		t.TLSHandshakeTimeout = 15 * time.Second
		t.ResponseHeaderTimeout = 60 * time.Second
		t.ExpectContinueTimeout = 5 * time.Second
		t.IdleConnTimeout = 90 * time.Second
		// Libraries that build `&http.Client{}` (porkbun, hetzner) get no
		// overall timeout from DefaultClient: bound every request, body
		// included, in the transport itself.
		http.DefaultTransport = timeoutTransport{base: t, d: perRequest}
	}
	http.DefaultClient.Timeout = perRequest
}

// timeoutTransport gives every request a deadline (headers and body);
// the deadline's context is released when the body is closed.
type timeoutTransport struct {
	base http.RoundTripper
	d    time.Duration
}

func (t timeoutTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), t.d)
	resp, err := t.base.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// subnetListener accepts only connections addressed to the API's own
// network (portcullis-domains, DOMAINS_API_SUBNET) or loopback (the health
// check): the API port is also reachable on portcullis-certs (Traefik) and
// domains-egress (Pebble in CI), which must never talk to it.
type subnetListener struct {
	net.Listener
	allowed netip.Prefix
	logf    func(string, ...any)
}

func (l subnetListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if apiLocalAllowed(c.LocalAddr(), l.allowed) {
			return c, nil
		}
		l.logf("domains API: refused a connection to %s (not on the Hub network)", c.LocalAddr())
		c.Close()
	}
}

func apiLocalAllowed(a net.Addr, allowed netip.Prefix) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || allowed.Contains(ip)
}

// certExpiryWarning: a warning when the endpoint's own server certificate
// has less than 30 days left ("" otherwise). ./portcullis up renews it.
func certExpiryWarning(leaf *x509.Certificate, now time.Time) string {
	if left := leaf.NotAfter.Sub(now); left < 30*24*time.Hour {
		return fmt.Sprintf("WARNING: the certificate endpoint's server certificate expires %s (%d days): run ./portcullis up to renew it",
			leaf.NotAfter.UTC().Format(time.RFC3339), int(left.Hours()/24))
	}
	return ""
}

func run() error {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	setHTTPDefaults(2 * time.Minute)
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
	apiNet, err := netip.ParsePrefix(strings.TrimSpace(os.Getenv("DOMAINS_API_SUBNET")))
	if err != nil {
		return fmt.Errorf("DOMAINS_API_SUBNET (the portcullis-domains subnet the API answers on) is required: %v", err)
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
	if leaf, err := x509.ParseCertificate(certsTLS.Certificates[0].Certificate[0]); err == nil {
		go func() {
			for {
				if w := certExpiryWarning(leaf, time.Now()); w != "" {
					logger.Print(w)
				}
				time.Sleep(24 * time.Hour)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	api := &http.Server{Addr: env("DOMAINS_API_ADDR", ":8080"), Handler: svc.APIHandler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		// Budget: DELETE waits ≤ 90 s for a records step + ≤ 60 s removing
		// records < this < the Hub's 4-min client timeout.
		WriteTimeout: 3 * time.Minute, IdleTimeout: 2 * time.Minute}
	certs := &http.Server{Addr: env("DOMAINS_CERTS_ADDR", ":8443"), Handler: svc.CertsHandler(), TLSConfig: certsTLS,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
		ErrorLog: log.New(io.Discard, "", 0)} // TLS handshake failures (no client cert) are expected noise
	errc := make(chan error, 2)
	apiLn, err := net.Listen("tcp", api.Addr)
	if err != nil {
		return err
	}
	go func() {
		errc <- api.Serve(subnetListener{Listener: apiLn, allowed: apiNet.Masked(), logf: logger.Printf})
	}()
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
