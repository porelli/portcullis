// Command mailctl is the only holder of Stalwart's API key (integration
// contract §19): it turns the Hub's desired state into Stalwart objects,
// renders the mail record set, runs the DKIM / MTA-STS / TLSA / DMARC state
// machines, serves the well-known files and the spam rules, runs the
// checks and exposes metrics.
//
//	mailctl [serve]      run the service (the Hub API, well-known files, rules, metrics)
//	mailctl healthcheck  exit 0 when the API answers /healthz on loopback
//	mailctl bootstrap | void | dns | rotate | reload-tls | status | export | test
//
// Unknown subcommands exit 2.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/portcullis/mailctl/internal/api"
	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/config"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/metrics"
	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/stalwart"
)

const usage = `usage: mailctl [serve|healthcheck|bootstrap [--rotate-key|--verify-gone]|void|dns|rotate|reload-tls|status|export|test]`

// later are the subcommands later tasks fill (each talks to the running
// serve process or to Stalwart directly, as its task says).
var later = map[string]bool{
	"void": true, "dns": true, "rotate": true, "status": true, "export": true, "test": true,
}

func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr)) }

func run(args []string, env func(string) string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch {
	case cmd == "-h" || cmd == "--help" || cmd == "help":
		fmt.Fprintln(stdout, usage)
		return 0
	case cmd == "serve":
		if err := serve(env, stderr); err != nil {
			fmt.Fprintf(stderr, "mailctl: refusing to start: %s\n", logx.Redact(err.Error()))
			return 1
		}
		return 0
	case cmd == "healthcheck":
		return healthcheck(env)
	case cmd == "bootstrap":
		return bootstrapCmd(args[1:], env, os.Stdin, stdout, stderr)
	case cmd == "reload-tls":
		return reloadTLS(env, stderr)
	case later[cmd]:
		fmt.Fprintf(stderr, "mailctl %s: not available in this build\n", cmd)
		return 1
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
}

func healthcheck(env func(string) string) int {
	addr := env("MAILCTL_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// checkStart is the fail-closed start check (contract §19.5): the API key
// and the Hub secret are present, and one of this container's addresses is
// inside MAILCTL_API_SUBNET (its portcullis-mailctl address).
func checkStart(cfg config.Config, addrs func() ([]net.Addr, error)) error {
	key, err := api.ReadSecret(cfg.APIKeyFile, 1)
	if err != nil {
		return fmt.Errorf("Stalwart's API key: %w (run ./portcullis mail enable)", err)
	}
	logx.AddSecret(key)
	hub, err := api.ReadSecret(cfg.HubSecretFile, api.MinSecret)
	if err != nil {
		return fmt.Errorf("the Hub secret: %w", err)
	}
	logx.AddSecret(hub)
	as, err := addrs()
	if err != nil {
		return fmt.Errorf("reading this container's addresses: %w", err)
	}
	for _, a := range as {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && cfg.APISubnet.Contains(ip.Unmap()) {
			return nil
		}
	}
	return fmt.Errorf("no address of this container is inside MAILCTL_API_SUBNET=%s (not on portcullis-mailctl?)", cfg.APISubnet)
}

func serve(env func(string) string, stderr io.Writer) error {
	logger := logx.New(stderr)
	cfg, err := config.Load(env)
	if err != nil {
		return err
	}
	if err := checkStart(cfg, net.InterfaceAddrs); err != nil {
		return err
	}
	m := metrics.New()
	key, _ := api.ReadSecret(cfg.APIKeyFile, 1)
	sw := stalwart.New(cfg.StalwartURL, stalwart.Bearer(key))

	apiSrv := &api.Server{Subnet: cfg.APISubnet, SecretFile: cfg.HubSecretFile, Logf: logger.Printf}
	servers := []*http.Server{
		newServer(cfg.APIAddr, apiSrv),
		// The well-known files (Task 8); until then every path is 404.
		newServer(cfg.WellKnownAddr, http.NotFoundHandler()),
		newServer(cfg.RulesAddr, spamrules.Handler()),
		newServer(cfg.MetricsAddr, m.Handler()),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, len(servers))
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", s.Addr, err)
		}
		go func(s *http.Server, ln net.Listener) {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}(s, ln)
	}
	go keepLookupsOff(ctx, sw, logger.Printf)
	logger.Printf("mailctl: serving the Hub API on %s, well-known files on %s, spam rules on %s, metrics on %s",
		cfg.APIAddr, cfg.WellKnownAddr, cfg.RulesAddr, cfg.MetricsAddr)
	select {
	case <-ctx.Done():
	case err = <-errc:
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(sctx)
	}
	return err
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 64 << 10}
}

// keepLookupsOff re-checks the spam rules' external lookups (contract
// §19.8: no surprise egress): every minute for the first 10 minutes (the
// first import runs after the first normal start), then every 15 minutes.
func keepLookupsOff(ctx context.Context, sw *stalwart.Client, logf func(string, ...any)) {
	start := time.Now()
	for {
		cctx, cancel := context.WithTimeout(ctx, time.Minute)
		n, err := bootstrap.DisableExternalLookups(cctx, sw)
		cancel()
		switch {
		case err != nil:
			logf("spam rules: can't check the external lookups: %v", err)
		case n > 0:
			logf("spam rules: disabled %d external lookups", n)
		}
		wait := 15 * time.Minute
		if time.Since(start) < 10*time.Minute {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// bootstrapCmd is `mailctl bootstrap [--rotate-key]` (stdin: the input,
// contract §19.4) and `mailctl bootstrap --verify-gone` (stdin: the
// recovery credentials; exit 0 only when the login is refused).
func bootstrapCmd(args []string, env func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	rotate, verify := false, false
	for _, a := range args {
		switch a {
		case "--rotate-key":
			rotate = true
		case "--verify-gone":
			verify = true
		default:
			fmt.Fprintln(stderr, "usage: mailctl bootstrap [--rotate-key | --verify-gone] < input.json")
			return 2
		}
	}
	if rotate && verify {
		fmt.Fprintln(stderr, "mailctl bootstrap: --rotate-key and --verify-gone exclude each other")
		return 2
	}
	cfg, err := config.Load(env)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %s\n", logx.Redact(err.Error()))
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if verify {
		cr, err := bootstrap.ReadCredentials(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "mailctl bootstrap --verify-gone: %v\n", err)
			return 2
		}
		logx.AddSecret(cr.RecoveryPassword)
		if err := bootstrap.VerifyGone(ctx, cfg.StalwartURL, cr); err != nil {
			fmt.Fprintf(stderr, "mailctl bootstrap --verify-gone: %s\n", logx.Redact(err.Error()))
			return 1
		}
		return 0
	}
	in, err := bootstrap.ReadInput(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %v\n", err)
		return 2
	}
	logx.AddSecret(in.RecoveryPassword)
	logger := logx.New(stderr)
	p, err := planParams(cfg, in)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %v\n", err)
		return 1
	}
	res, err := bootstrap.Apply(ctx, stalwart.New(cfg.StalwartURL, stalwart.Basic(in.RecoveryUser, in.RecoveryPassword)), p, rotate, logger.Printf)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %s\n", logx.Redact(err.Error()))
		return 1
	}
	out := map[string]any{"api_key": nil}
	if res.APIKey != "" {
		out["api_key"] = res.APIKey
	}
	b, _ := json.Marshal(out)
	fmt.Fprintln(stdout, string(b))
	return 0
}

func planParams(cfg config.Config, in bootstrap.Input) (bootstrap.Params, error) {
	u, err := url.Parse(cfg.StalwartURL)
	if err != nil {
		return bootstrap.Params{}, err
	}
	mailIP, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return bootstrap.Params{}, fmt.Errorf("MAILCTL_STALWART_URL=%s: the host must be mail's address", cfg.StalwartURL)
	}
	res, _ := netip.ParseAddrPort(cfg.LocalResolver)
	lookups, err := spamrules.HTTPLookups()
	if err != nil {
		return bootstrap.Params{}, err
	}
	return bootstrap.Params{
		Hostname: in.Hostname, PrimaryDomain: in.PrimaryDomain, MailIP: mailIP, MailctlIP: cfg.MailIP,
		ResolverIP: res.Addr(), ResolverPort: int(res.Port()),
		RulesURL: "http://" + cfg.RulesAddr + spamrules.Path, ClientIP: in.ClientIP,
		Relay: in.Relay, MetricsUser: in.MetricsUser, HTTPLookups: lookups, LocalNetworks: in.LocalNetworks,
	}, nil
}

// reloadTLS is `mailctl reload-tls`: Stalwart rereads the certificate
// files (after mail-cert renewed them).
func reloadTLS(env func(string) string, stderr io.Writer) int {
	cfg, err := config.Load(env)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl reload-tls: %v\n", err)
		return 1
	}
	key, err := api.ReadSecret(cfg.APIKeyFile, 1)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl reload-tls: Stalwart's API key: %v\n", err)
		return 1
	}
	logx.AddSecret(key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := stalwart.New(cfg.StalwartURL, stalwart.Bearer(key)).Action(ctx, "ReloadTlsCertificates"); err != nil {
		fmt.Fprintf(stderr, "mailctl reload-tls: %s\n", logx.Redact(err.Error()))
		return 1
	}
	return 0
}
