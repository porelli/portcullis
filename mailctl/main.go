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
	"crypto/tls"
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
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/mailctl/internal/admin"
	"github.com/portcullis/mailctl/internal/api"
	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/checks"
	"github.com/portcullis/mailctl/internal/config"
	"github.com/portcullis/mailctl/internal/creds"
	"github.com/portcullis/mailctl/internal/export"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/mailtest"
	"github.com/portcullis/mailctl/internal/metrics"
	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/resolve"
	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
	"github.com/portcullis/mailctl/internal/wellknown"
)

const usage = `usage: mailctl [serve|healthcheck|bootstrap [--rotate-key|--verify-gone]|void|dns|rotate|tls-key|reload-tls|status|export|test]`

// later are the subcommands later tasks fill (each talks to the running
// serve process or to Stalwart directly, as its task says).
var later = map[string]bool{}

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
	case cmd == "void":
		return voidCmd(args[1:], env, os.Stdin, stdout, stderr)
	case cmd == "export":
		return exportCmd(args[1:], env, stdout, stderr)
	case cmd == "reload-tls":
		return reloadTLS(env, stderr)
	case cmd == "dns" || cmd == "rotate" || cmd == "tls-key" || cmd == "status" || cmd == "dkim":
		return adminCmd(cmd, args[1:], os.Stdin, stdout, stderr)
	case cmd == "test":
		return testCmd(args[1:], env, stdout, stderr)
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

	st, err := state.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	runner := reconcile.NewRunner(sw, st, cfg.FormerRetain, cfg.LANOnly, logger.Printf)
	runner.MailctlIP = cfg.MailIP
	rewritten := cfg.ClientIP == config.ClientIPRewritten
	runner.Rewritten = rewritten
	runner.DQSKeyFile = cfg.DQSKeyFile
	mc := machines.New(sw, st, machinesConfig(cfg), logger.Printf)
	ck := &checks.Runner{D: checks.Deps{C: sw, M: mc, Store: st, Cfg: checksConfig(cfg), DNS: resolve.Query, Logf: logger.Printf},
		OnResult: func(r checks.Result) {
			vals := map[string]float64{}
			for _, c := range r.Checks {
				vals[c.ID] = checks.Value(c.Severity)
			}
			m.SetChecks(vals)
		}}
	mc.CertOK = ck.CertState
	v1 := &api.V1{Store: st, C: sw, Runner: runner, LANOnly: cfg.LANOnly, Rewritten: rewritten, Logf: logger.Printf, M: mc, Checks: ck}
	apiSrv := &api.Server{Subnet: cfg.APISubnet, SecretFile: cfg.HubSecretFile, Logf: logger.Printf, Handler: v1.Handler()}
	servers := []*http.Server{
		newServer(cfg.APIAddr, apiSrv),
		newServer(cfg.WellKnownAddr, wellknown.Handler(mc)),
		newServer(cfg.RulesAddr, spamrules.Handler()),
		newServer(cfg.MetricsAddr, m.Handler()),
	}
	adminLn, err := admin.Listen(admin.Socket)
	if err != nil {
		return fmt.Errorf("the control socket %s: %w", admin.Socket, err)
	}
	clientIP := config.ClientIPPreserved
	if rewritten {
		clientIP = config.ClientIPRewritten
	}
	adminSrv := newServer("", admin.Handler(mc, admin.Status{Bootstrapped: v1.Bootstrapped, ClientIP: clientIP,
		Checks: func(ctx context.Context) any { return ck.Get(ctx, false) }}))
	adminSrv.WriteTimeout = 5 * time.Minute
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
	go func() {
		if err := adminSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("%s: %w", admin.Socket, err)
		}
	}()
	servers = append(servers, adminSrv)
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

// machinesConfig is the state machines' part of the environment.
func machinesConfig(cfg config.Config) machines.Config {
	mc := machines.Config{MainDomain: cfg.MainDomain, Hostname: cfg.Hostname, Resolvers: cfg.Resolvers,
		RotateEvery: cfg.DKIMRotate, Reachable: slices.Contains(cfg.WellKnownEntry, "websecure")}
	if cfg.Relay != nil {
		mc.SPFInclude = cfg.Relay.SPFInclude
	}
	return mc
}

// checksConfig is the checks' part of the environment.
func checksConfig(cfg config.Config) checks.Config {
	return checks.Config{Hostname: cfg.Hostname, MainDomain: cfg.MainDomain, PublicIPv4: cfg.PublicIPv4, PublicIPv6: cfg.PublicIPv6,
		Resolvers: cfg.Resolvers, LocalResolver: cfg.LocalResolver, DQSKeyFile: cfg.DQSKeyFile,
		ClientIP: cfg.ClientIP, MailIP: mailIP(cfg.StalwartURL)}
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
		if st, err := mc.Status(cctx, v1.Bootstrapped(cctx), ""); err == nil {
			var na time.Time
			if st.Cert != nil {
				na = st.Cert.NotAfter
			}
			stages := make([]metrics.Stage, 0, len(st.DKIM))
			for _, k := range st.DKIM {
				stages = append(stages, metrics.Stage{Domain: k.Domain, Stage: k.Stage})
			}
			m.SetStatus(na, st.Queue.Messages, st.Queue.Deferred, stages)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

// testCmd is `mailctl test --to <addr>`: the test message (contract
// §19.10), one JSON line on stdout.
func testCmd(args []string, env func(string) string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--to" || !strings.Contains(args[1], "@") || strings.ContainsAny(args[1], " <>\r\n") {
		fmt.Fprintln(stderr, "usage: mailctl test --to <address>")
		return 2
	}
	cfg, err := config.Load(env)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl test: %v\n", err)
		return 1
	}
	key, err := api.ReadSecret(cfg.APIKeyFile, 1)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl test: Stalwart's API key: %v\n", err)
		return 1
	}
	logx.AddSecret(key)
	st, err := state.Open(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl test: %v\n", err)
		return 1
	}
	p := st.Get()
	spki := state.SPKIs(p)
	if len(spki) == 0 {
		fmt.Fprintln(stderr, "mailctl test: the mail certificate's key isn't known to mailctl yet (run ./portcullis mail rotate)")
		return 1
	}
	s := &mailtest.Sender{C: stalwart.New(cfg.StalwartURL, stalwart.Bearer(key)), Doc: p.Doc,
		SubmitAddr: net.JoinHostPort(mailIP(cfg.StalwartURL), "10587"), MailctlIP: cfg.MailIP,
		TLS: func(now time.Time) *tls.Config { return export.PinnedTLS(cfg.Hostname, spki, now) }}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := s.Send(ctx, args[1])
	if err != nil {
		fmt.Fprintf(stderr, "mailctl test: %s\n", logx.Redact(err.Error()))
		return 1
	}
	json.NewEncoder(stdout).Encode(res)
	return 0
}

// adminCmd is `mailctl dns --main --json`, `mailctl rotate --json` (stdin:
// {"dnssec_state", "spki": {"current", "next"}}) and `mailctl status
// --json`, `mailctl tls-key --json` (stdin: {"current"}): one call on the running serve's control socket, its JSON on
// stdout.
func adminCmd(cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	want := map[string][]string{"dns": {"--main", "--json"}, "rotate": {"--json"}, "tls-key": {"--json"}, "status": {"--json"}, "dkim": {"rotate", "<domain>", "--json"}}[cmd]
	var domain string
	if cmd == "dkim" && len(args) == 3 && args[0] == "rotate" && args[2] == "--json" {
		domain, args = strings.ToLower(args[1]), []string{"rotate", "<domain>", "--json"}
	}
	if !slices.Equal(args, want) {
		fmt.Fprintf(stderr, "usage: mailctl %s %s\n", cmd, strings.Join(want, " "))
		return 2
	}
	var (
		b   []byte
		err error
	)
	switch cmd {
	case "dns":
		b, err = admin.Call(admin.Socket, http.MethodGet, "/dns/main", nil)
	case "status":
		b, err = admin.Call(admin.Socket, http.MethodGet, "/status", nil)
	case "dkim":
		body, _ := json.Marshal(map[string]string{"domain": domain})
		b, err = admin.Call(admin.Socket, http.MethodPost, "/dkim-rotate", body)
	case "rotate":
		in, rerr := io.ReadAll(io.LimitReader(stdin, 64<<10))
		if rerr != nil {
			fmt.Fprintf(stderr, "mailctl rotate: reading stdin: %v\n", rerr)
			return 2
		}
		if _, perr := admin.ParseRotate(in); perr != nil {
			fmt.Fprintf(stderr, "mailctl rotate: %v\n", perr)
			return 2
		}
		b, err = admin.Call(admin.Socket, http.MethodPost, "/rotate", in)
	case "tls-key":
		in, rerr := io.ReadAll(io.LimitReader(stdin, 4096))
		if rerr != nil {
			fmt.Fprintf(stderr, "mailctl tls-key: reading stdin: %v\n", rerr)
			return 2
		}
		if _, perr := admin.ParseTLSKey(in); perr != nil {
			fmt.Fprintf(stderr, "mailctl tls-key: %v\n", perr)
			return 2
		}
		b, err = admin.Call(admin.Socket, http.MethodPost, "/tls-key", in)
	}
	if err != nil {
		fmt.Fprintf(stderr, "mailctl %s: %s\n", cmd, logx.Redact(err.Error()))
		return 1
	}
	stdout.Write(b)
	return 0
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
		Relay: in.Relay, MetricsUser: in.MetricsUser, HTTPLookups: lookups, LocalNetworks: in.LocalNetworks, LANOnly: in.LANOnly,
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

// voidCmd is `mailctl void --reason restore` (stdin: the recovery
// credentials; contract §19.11): every app password of every account is
// destroyed and restored_at recorded. Prints {"voided": n}.
func voidCmd(args []string, env func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--reason" || args[1] != "restore" {
		fmt.Fprintln(stderr, "usage: mailctl void --reason restore < credentials.json")
		return 2
	}
	cfg, err := config.Load(env)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl void: %v\n", err)
		return 1
	}
	cr, err := bootstrap.ReadCredentials(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl void: %v\n", err)
		return 2
	}
	logx.AddSecret(cr.RecoveryPassword)
	st, err := state.Open(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "mailctl void: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	n, err := creds.VoidAll(ctx, stalwart.New(cfg.StalwartURL, stalwart.Basic(cr.RecoveryUser, cr.RecoveryPassword)))
	if err != nil {
		fmt.Fprintf(stderr, "mailctl void: %s (voided %d)\n", logx.Redact(err.Error()), n)
		return 1
	}
	now := time.Now().UTC()
	if err := st.Update(func(p *state.Persistent) error { p.RestoredAt = &now; return nil }); err != nil {
		fmt.Fprintf(stderr, "mailctl void: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "{\"voided\":%d}\n", n)
	return 0
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
		ServerName: cfg.Hostname, MailctlIP: cfg.MailIP, SPKI: state.SPKIs(st.Get()), DataDir: cfg.DataDir}
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
