// Command mailctl is the stalwart template's adapter (integration
// contract §19): it serves the provider API v1 to the Hub, turns MailState
// v2 into Stalwart objects, renders each mail domain's record set, runs the
// DKIM / MTA-STS / DMARC state machines, serves the well-known files and
// the spam rules, runs the checks and exposes metrics. It is the only
// holder of Stalwart's API key; it has no control socket and no engine,
// DNS, LLDAP or Keycloak access.
//
//	mailctl [serve]                            run the adapter (gated: contract §19.4)
//	mailctl healthcheck                        exit 0 when the API answers /healthz on loopback
//	mailctl bootstrap --job -- <server argv…>  the template's one-off bootstrap job
//	mailctl export --former <former-id>        one former account as mbox on stdout
//
// Unknown subcommands exit 2.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/mailctl/internal/api"
	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/checks"
	"github.com/portcullis/mailctl/internal/config"
	"github.com/portcullis/mailctl/internal/export"
	"github.com/portcullis/mailctl/internal/gate"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/mailtest"
	"github.com/portcullis/mailctl/internal/metrics"
	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/resolve"
	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
	"github.com/portcullis/mailctl/internal/tlsprobe"
	"github.com/portcullis/mailctl/internal/wellknown"
)

const usage = `usage: mailctl [serve | healthcheck | bootstrap --job -- <server argv…> | export --former <former-id>]`

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
		return bootstrapCmd(args[1:], env, stderr)
	case cmd == "export":
		return exportCmd(args[1:], env, stdout, stderr)
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

// checkStart is the fail-closed start check (contract §19.4, §19.5): the
// gate predicate (P3) over the slot's files, the API secret, the metrics
// secret and Stalwart's API key present, PORTCULLIS_MAIL_API_SUBNET parsed
// (config.Load) and one of this container's addresses inside it (the
// override's pinned provider address on portcullis-mail-api).
func checkStart(cfg config.Config, addrs func() ([]net.Addr, error)) error {
	if err := gate.CheckLayout(cfg.SlotDir); err != nil {
		return err
	}
	if err := gate.Check(cfg.SlotDir, cfg.VoidSession); err != nil {
		return err
	}
	hub, err := api.ReadSecret(cfg.APISecretFile(), api.MinSecret)
	if err != nil {
		return fmt.Errorf("the API secret: %w", err)
	}
	logx.AddSecret(hub)
	ms, err := api.ReadSecret(cfg.MetricsSecretFile(), metrics.MinSecret)
	if err != nil {
		return fmt.Errorf("the metrics secret: %w", err)
	}
	logx.AddSecret(ms)
	key, err := api.ReadSecret(cfg.APIKeyFile, 1)
	if err != nil {
		return fmt.Errorf("Stalwart's API key: %w (the bootstrap job writes it)", err)
	}
	logx.AddSecret(key)
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
	return fmt.Errorf("no address of this container is inside PORTCULLIS_MAIL_API_SUBNET=%s (not wired on portcullis-mail-api?)", cfg.APISubnet)
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

	st, err := state.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	runner := reconcile.NewRunner(sw, st, logger.Printf)
	runner.MailctlIP = cfg.MailIP
	runner.DQSKeyFile = cfg.DQSKeyFile
	mc := machines.New(sw, st, machinesConfig(cfg), logger.Printf)
	runner.OnApplied = mc.Trigger
	ck := &checks.Runner{D: checks.Deps{C: sw, M: mc, Store: st, Cfg: checksConfig(cfg), DNS: resolve.Query, Logf: logger.Printf},
		OnResult: func(r checks.Result) {
			vals := map[string]float64{}
			for _, c := range r.Checks {
				vals[c.ID] = checks.Value(c.Severity)
			}
			m.SetChecks(vals)
		}}
	mc.CertOK = ck.CertState
	serving := func(ctx context.Context) (*x509.Certificate, error) {
		return tlsprobe.Leaf(ctx, nil, net.JoinHostPort(mailIP(cfg.StalwartURL), "10465"), mc.Hostname(), false)
	}
	mc.Serving = serving
	v1 := &api.V1{Store: st, C: sw, Runner: runner, Logf: logger.Printf, M: mc, Checks: ck,
		TLSDir: cfg.TLSDir, Serving: serving, Export: true, Test: testSender(cfg, sw)}
	apiSrv := &api.Server{Subnet: cfg.APISubnet, SecretFile: cfg.APISecretFile(), Logf: logger.Printf, Handler: v1.Handler()}
	servers := []*http.Server{
		newServer(cfg.APIAddr, apiSrv),
		newServer(cfg.WellKnownAddr, wellknown.Handler(mc)),
		newServer(cfg.RulesAddr, spamrules.Handler()),
		newServer(cfg.MetricsAddr, m.Handler(cfg.MetricsSecretFile(), api.ReadSecret, logger.Printf)),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, len(servers))
	for i, s := range servers {
		ln, err := net.Listen("tcp", s.Addr)
		if err != nil {
			// The metrics address is an alias on portcullis-metrics-mail,
			// which void mode doesn't attach: no listener until it
			// resolves (a metrics outage, never a refused start).
			var dnsErr *net.DNSError
			if i == len(servers)-1 && errors.As(err, &dnsErr) {
				go serveWhenResolvable(ctx, s, net.Listen, 30*time.Second, logger.Printf, errc)
				continue
			}
			return fmt.Errorf("listening on %s: %w", s.Addr, err)
		}
		go func(s *http.Server, ln net.Listener) {
			if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}(s, ln)
	}
	go keepLookupsOff(ctx, sw, st, logger.Printf)
	go runner.Run(ctx)
	go mc.Loop(ctx)
	go ck.Loop(ctx, 6*time.Hour)
	go statusMetrics(ctx, mc, m, v1)
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

// serveWhenResolvable retries s's listener every period while its host
// name doesn't resolve (the metrics alias outside void mode's networks),
// then serves; any other listen error goes to errc. It stops with ctx.
func serveWhenResolvable(ctx context.Context, s *http.Server, listen func(string, string) (net.Listener, error),
	period time.Duration, logf func(string, ...any), errc chan<- error) {
	logf("mailctl: metrics off until %s resolves (not on portcullis-metrics-mail: void mode)", s.Addr)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(period):
		}
		ln, err := listen("tcp", s.Addr)
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			continue
		}
		if err != nil {
			errc <- fmt.Errorf("listening on %s: %w", s.Addr, err)
			return
		}
		logf("mailctl: metrics on %s", s.Addr)
		if err := s.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("%s: %w", s.Addr, err)
		}
		return
	}
}

// machinesConfig is the state machines' part of the environment.
func machinesConfig(cfg config.Config) machines.Config {
	return machines.Config{Resolvers: cfg.Resolvers, Reachable: slices.Contains(cfg.WellKnownEntry, "websecure")}
}

// checksConfig is the checks' part of the environment.
func checksConfig(cfg config.Config) checks.Config {
	return checks.Config{PublicIPv4: cfg.PublicIPv4, PublicIPv6: cfg.PublicIPv6,
		Resolvers: cfg.Resolvers, LocalResolver: cfg.LocalResolver, DQSKeyFile: cfg.DQSKeyFile, MailIP: mailIP(cfg.StalwartURL)}
}

// mailIP is mail's address from MAILCTL_STALWART_URL (http://<ip>:8080).
func mailIP(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Hostname()
	}
	return ""
}

// statusMetrics refreshes the status gauges every minute.
func statusMetrics(ctx context.Context, mc *machines.Machines, m *metrics.Metrics, v1 *api.V1) {
	for {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if st, err := mc.Status(cctx, v1.Bootstrapped(cctx)); err == nil {
			stages := make([]metrics.Stage, 0, len(st.DKIM))
			for _, k := range st.DKIM {
				stages = append(stages, metrics.Stage{Domain: k.Domain, Stage: k.Stage})
			}
			m.SetStatus(st.Queue.Messages, st.Queue.Deferred, stages)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// testSender is POST /v1/actions/test: a message from the first postmaster
// account, submitted on Stalwart's 10587 with the document's SPKIs pinned.
func testSender(cfg config.Config, sw *stalwart.Client) func(ctx context.Context, doc *state.Doc, to string) (string, error) {
	return func(ctx context.Context, doc *state.Doc, to string) (string, error) {
		s := &mailtest.Sender{C: sw, Doc: doc, SubmitAddr: net.JoinHostPort(mailIP(cfg.StalwartURL), "10587"), MailctlIP: cfg.MailIP,
			TLS: func(now time.Time) *tls.Config { return export.PinnedTLS(doc.MailHostname, doc.TLS.SPKISHA256, now) }}
		res, err := s.Send(ctx, to)
		return res.Queued, err
	}
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 2 * time.Minute,
		MaxHeaderBytes: 64 << 10}
}

// keepLookupsOff runs bootstrap.SpamRulesPass forever: the vendored
// spam rules' import, then the external lookups turned off again (contract
// §19.8: no surprise egress; an import turns them on).
func keepLookupsOff(ctx context.Context, sw *stalwart.Client, st *state.Store, logf func(string, ...any)) {
	lastFast := time.Now()
	for {
		var wait time.Duration
		lastFast, wait = bootstrap.SpamRulesPass(ctx, sw, st, time.Now(), lastFast, logf)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// bootstrapCmd is `mailctl bootstrap --job -- <server argv…>`: the
// template's one-off job (bootstrap.Job). The server argv is started as a
// child process (its environment plus the job's; the recovery password
// only ever in that environment), never through a shell.
func bootstrapCmd(args []string, env func(string) string, stderr io.Writer) int {
	if len(args) < 3 || args[0] != "--job" || args[1] != "--" {
		fmt.Fprintln(stderr, "usage: mailctl bootstrap --job -- <server argv…>")
		return 2
	}
	argv := args[2:]
	cfg, err := config.LoadJob(env)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %s\n", logx.Redact(err.Error()))
		return 1
	}
	j, err := jobFor(cfg, argv, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if err := j.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "mailctl bootstrap: %s\n", logx.Redact(err.Error()))
		return 1
	}
	return 0
}

// jobFor is the job of cfg: it reaches its own server over loopback
// (JobLocalURL), never the adapter's MAILCTL_STALWART_URL (Ruling T17-b).
func jobFor(cfg config.Config, argv []string, stderr io.Writer) (*bootstrap.Job, error) {
	p, err := planParams(cfg)
	if err != nil {
		return nil, err
	}
	logger := logx.New(stderr)
	return &bootstrap.Job{URL: cfg.JobLocalURL, DataDir: cfg.DataDir, KeyFile: cfg.APIKeyFile, StoreDir: cfg.StoreDir, SessionFile: cfg.JobSessionFile, ServerImage: cfg.ServerImage,
		Params: p, Start: childServer(argv, stderr), Logf: logger.Printf}, nil
}

// childServer starts argv with the job's environment plus env; stop sends
// SIGTERM and waits (30 s, then SIGKILL).
func childServer(argv []string, out io.Writer) bootstrap.Server {
	return func(ctx context.Context, extra []string) (func() error, error) {
		for _, e := range extra {
			if strings.HasPrefix(e, "STALWART_RECOVERY_ADMIN=") {
				_, pw, _ := strings.Cut(strings.TrimPrefix(e, "STALWART_RECOVERY_ADMIN="), ":")
				logx.AddSecret(pw)
			}
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), extra...)
		// The child's output goes through the redaction (the recovery
		// password is a registered secret).
		rw := logx.NewRedactingWriter(out)
		cmd.Stdout, cmd.Stderr = rw, rw
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		done := make(chan error, 1)
		go func() {
			err := cmd.Wait() // every write of the child's output is done
			_ = rw.Close()
			done <- err
		}()
		return func() error {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(30 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			return nil
		}, nil
	}
}

// planParams is the neutral part of the base plan from the template's
// wiring (the document's part comes from adapter_data or ApplyDoc).
func planParams(cfg config.Config) (bootstrap.Params, error) {
	res, _ := netip.ParseAddrPort(cfg.LocalResolver)
	lookups, err := spamrules.HTTPLookups()
	if err != nil {
		return bootstrap.Params{}, err
	}
	return bootstrap.Params{MailctlIP: cfg.MailIP, ResolverIP: res.Addr(), ResolverPort: int(res.Port()),
		RulesURL: "http://" + cfg.RulesAddr + spamrules.Path, MetricsUser: metrics.User, HTTPLookups: lookups}, nil
}

// exportCmd is `mailctl export --former <former-id>` (M5): mbox to stdout,
// one log line on stderr (no content). A non-former account exits 2.
func exportCmd(args []string, env func(string) string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--former" {
		fmt.Fprintln(stderr, "usage: mailctl export --former <former-id>")
		return 2
	}
	cfg, err := config.Load(env)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl export: %v\n", err)
		return 1
	}
	key, err := api.ReadSecret(cfg.APIKeyFile, 1)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl export: Stalwart's API key: %v\n", err)
		return 1
	}
	logx.AddSecret(key)
	u, _ := url.Parse(cfg.StalwartURL)
	st, err := state.Open(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl export: %v\n", err)
		return 1
	}
	e := &export.Exporter{C: stalwart.New(cfg.StalwartURL, stalwart.Bearer(key)), IMAPAddr: net.JoinHostPort(u.Hostname(), "10993"),
		ServerName: hostOf(st.Get()), MailctlIP: cfg.MailIP, SPKI: state.SPKIs(st.Get()), DataDir: cfg.DataDir}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	n, err := e.Export(ctx, args[1], stdout)
	logger := logx.New(stderr)
	if errors.Is(err, export.ErrNotFormer) {
		fmt.Fprintf(stderr, "mailctl export: %s: %v\n", args[1], err)
		return 2
	}
	if err != nil {
		logger.Printf("export former=%s messages=%d failed: %v", args[1], n, err)
		return 1
	}
	logger.Printf("export former=%s messages=%d", args[1], n)
	return 0
}

// hostOf is the accepted document's mail_hostname ("" = none yet).
func hostOf(p state.Persistent) string {
	if p.Doc == nil {
		return ""
	}
	return p.Doc.MailHostname
}
