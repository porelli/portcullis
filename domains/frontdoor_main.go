package main

// `domains frontdoor` (contract §20.8): the front-door role in HA. It
// holds the main domain's DNS credentials (the Secret frontdoor-env,
// mounted as the file credentials.json: never argv, never the
// environment, never logged) and writes the main domain's address set
// through the same providers as the service (records.go, behind the
// redacting wrapper), while it holds the Lease portcullis-frontdoor.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/portcullis/domains/frontdoor"
	"github.com/portcullis/domains/internal/dnsplan"
)

// frontdoorCreds is credentials.json: the main domain's provider and its
// credentials (the dns tool's keys, contract §12.2).
type frontdoorCreds struct {
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
}

// loadFrontdoorCreds reads and checks credentials.json (≤ 64 KiB, strict
// JSON). No message ever carries a value.
func loadFrontdoorCreds(path string) (frontdoorCreds, error) {
	f, err := os.Open(path)
	if err != nil {
		return frontdoorCreds{}, fmt.Errorf("the DNS credentials %s are unreadable", path)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(b) > 64<<10 {
		return frontdoorCreds{}, fmt.Errorf("the DNS credentials %s are unreadable or over 64 KiB", path)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c frontdoorCreds
	if err := dec.Decode(&c); err != nil || dec.More() {
		return frontdoorCreds{}, fmt.Errorf("the DNS credentials %s aren't one JSON object {\"provider\", \"credentials\"}", path)
	}
	if err := validateCredentials(c.Provider, c.Credentials); err != nil {
		return frontdoorCreds{}, err
	}
	return c, nil
}

// providerMinTTL is the shortest TTL the provider keeps.
func providerMinTTL(provider string) time.Duration {
	if provider == "porkbun" {
		return porkbunMinTTL
	}
	return 0
}

// frontdoorPolicy is the addresses the front door may publish: public
// only, never the node mesh, pod or service CIDRs (FRONTDOOR_EXCLUDED_CIDRS,
// required); the documentation ranges only in the testprovider build.
func frontdoorPolicy(excluded string) (frontdoor.AddrPolicy, error) {
	pol := frontdoor.AddrPolicy{AllowDocumentation: testProviderBuild}
	for _, f := range strings.FieldsFunc(excluded, func(r rune) bool { return r == ',' || r == ' ' }) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return pol, fmt.Errorf("FRONTDOOR_EXCLUDED_CIDRS: %q is not a CIDR", f)
		}
		pol.Excluded = append(pol.Excluded, p.Masked())
	}
	if len(pol.Excluded) == 0 {
		return pol, errors.New("FRONTDOOR_EXCLUDED_CIDRS (the node mesh, pod and service CIDRs) is required")
	}
	return pol, nil
}

// newFrontdoorWriter builds the main domain's writer from the
// credentials (the service's provider behind redacting) and the
// redaction of every message the front door logs. Its Fence is set by
// the caller (nil: every write refused).
func newFrontdoorWriter(domain string, c frontdoorCreds, policy frontdoor.AddrPolicy, findZone func(string) (string, error)) (*frontdoor.Writer, func(string) string, error) {
	clean := func(s string) string { return redact(s, c.Credentials) }
	p, err := buildProvider(&Domain{Name: domain, Provider: c.Provider, Credentials: c.Credentials})
	if err != nil {
		return nil, clean, errors.New(clean(err.Error()))
	}
	inner, cleanErr := unwrap(p)
	var zone string
	if zf, ok := inner.(zoneFinder); ok {
		zone, err = zf.FindZone(dns.Fqdn(domain))
		err = cleanErr(err)
	} else {
		zone, err = findZone(dns.Fqdn(domain))
	}
	if err != nil {
		return nil, clean, fmt.Errorf("finding the DNS zone of %s: %s", domain, clean(err.Error()))
	}
	return &frontdoor.Writer{Domain: domain, Zone: dns.Fqdn(zone), P: p, TTL: frontdoor.TTL(providerMinTTL(c.Provider)), Policy: policy}, clean, nil
}

// The front door's control listener (loopback only: reached by
// `domains frontdoor account-uri | issue` run inside its own pod with
// `kubectl exec`; the NetworkPolicy and the pod's network namespace keep
// everyone else out). Not an API to the cluster: §20.8's "no API besides
// health" holds for every other address.
const frontdoorControlAddr = "127.0.0.1:8091"

// issueTimeout bounds one requested order (lego's propagation wait is
// 10 min at most).
const issueTimeout = 15 * time.Minute

// runFrontdoor is `domains frontdoor [account-uri | issue --account-uri <uri>]`.
func runFrontdoor(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		return runFrontdoorClient(args, env("FRONTDOOR_CONTROL_ADDR", frontdoorControlAddr), stdout, stderr)
	}
	logger := log.New(stderr, "", log.LstdFlags)
	if err := startTestProvider(logger); err != nil {
		logger.Print(err)
		return exitFailure
	}
	setHTTPDefaults(2 * time.Minute)
	domain := strings.ToLower(strings.TrimSuffix(os.Getenv("PORTCULLIS_DOMAIN"), "."))
	if !validHostname(domain) {
		logger.Printf("refusing to start: PORTCULLIS_DOMAIN=%q is not a valid hostname", domain)
		return exitFailure
	}
	pod, ns := os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE")
	if pod == "" || ns == "" {
		logger.Print("refusing to start: POD_NAME and POD_NAMESPACE are required (the Lease identity)")
		return exitFailure
	}
	policy, err := frontdoorPolicy(os.Getenv("FRONTDOOR_EXCLUDED_CIDRS"))
	if err != nil {
		logger.Printf("refusing to start: %v", err)
		return exitFailure
	}
	creds, err := loadFrontdoorCreds(env("FRONTDOOR_CREDENTIALS_FILE", "/run/portcullis/frontdoor/credentials.json"))
	if err != nil {
		logger.Printf("refusing to start: %v", err)
		return exitFailure
	}
	w, clean, err := newFrontdoorWriter(domain, creds, policy, legoZoneFinder)
	if err != nil {
		logger.Printf("refusing to start: %s", clean(err.Error()))
		return exitFailure
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		logger.Printf("refusing to start: the kube API: %v", err)
		return exitFailure
	}
	kc, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Printf("refusing to start: the kube API: %v", err)
		return exitFailure
	}
	fence := frontdoor.NewFence(kc, ns, pod)
	w.Fence = fence
	// The domains service's mail-host exclusion (servableHA), the same value.
	mailHost := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(os.Getenv("DOMAINS_MAIL_HOSTNAME")), "."))
	ctlAddr := env("FRONTDOOR_CONTROL_ADDR", frontdoorControlAddr)
	if !loopbackAddr(ctlAddr) {
		logger.Printf("refusing to start: FRONTDOOR_CONTROL_ADDR=%q is not a loopback address", ctlAddr)
		return exitFailure
	}
	skip := false
	if dp, ok := w.P.(dnsProvider); ok {
		inner, _ := unwrap(dp)
		_, skip = inner.(propagationSkipper)
	}
	certs := &frontdoor.Certs{
		Domain: domain, Store: frontdoor.SecretStore{Client: kc, Namespace: ns}, DNS: w, Fence: fence,
		ACME: &frontdoorACME{email: env("ACME_EMAIL", "admin@"+domain), caServer: env("ACME_CA_SERVER", "https://acme-v02.api.letsencrypt.org/directory"),
			skipPropagation: skip},
		Check: func(chain, key string, now time.Time) error { return servableHA(chain, key, domain, mailHost, now) },
		Log:   func(m string) { logger.Print(clean(m)) },
	}
	// The HA Traefik's default certificate (Task 31 fix round 2, M3): the
	// served pair mirrored into the ingress namespace's
	// traefik-default-cert (FRONTDOOR_INGRESS_NAMESPACE, the chart's).
	var mirror *frontdoor.DefaultCertMirror
	if ins := strings.TrimSpace(os.Getenv("FRONTDOOR_INGRESS_NAMESPACE")); ins != "" {
		mirror = &frontdoor.DefaultCertMirror{Client: kc, Namespace: ins, Store: certs.Store, Check: certs.Check, Fence: fence,
			Log: func(m string) { logger.Print(clean(m)) }}
	} else {
		logger.Print("frontdoor: FRONTDOOR_INGRESS_NAMESPACE is empty: Traefik's default certificate isn't kept up to date")
	}
	metrics := frontdoor.NewMetrics()
	sink := frontdoor.ConfigMapSink{Client: kc, Namespace: ns, Leader: pod}
	r := &frontdoor.Runner{
		Engine: frontdoor.NewEngine(w.Names()), Writer: w,
		Source: frontdoor.MTLSSource{NodeadmURL: env("FRONTDOOR_NODEADM_URL", "https://nodeadm.portcullis-nodeadm.svc:8443"),
			TLSDir: env("FRONTDOOR_TLS_DIR", "/run/portcullis/frontdoor-tls"), Policy: policy},
		Status: sink, Metrics: metrics, Log: logger, Redact: clean, Identity: pod,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// The last change an earlier front door wrote: one change per name
	// per 60 s across leaders.
	sctx, scancel := context.WithTimeout(ctx, frontdoor.ReadTimeout)
	if last, err := sink.LastChanges(sctx); err != nil {
		logger.Printf("frontdoor: reading %s: %v", frontdoor.StatusConfigMap, err)
	} else {
		r.Engine.Seed(last)
	}
	scancel()
	health := http.NewServeMux()
	health.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(rw, "{\"leading\": %v}\n", fence.Leading())
	})
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))
	for _, s := range []*http.Server{
		{Addr: env("FRONTDOOR_HEALTH_ADDR", ":8090"), Handler: health, ReadHeaderTimeout: 5 * time.Second},
		{Addr: env("FRONTDOOR_METRICS_ADDR", ":9106"), Handler: mux, ReadHeaderTimeout: 5 * time.Second},
	} {
		go func(s *http.Server) {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Printf("frontdoor: %s: %v", s.Addr, err)
				stop()
			}
		}(s)
	}
	fenceDone := make(chan struct{})
	go func() {
		defer close(fenceDone)
		if err := fence.Run(ctx); err != nil {
			logger.Printf("frontdoor: the Lease: %v", err)
		}
	}()
	ctl := &http.Server{Addr: ctlAddr, Handler: frontdoorControl(certs, clean), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := ctl.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("frontdoor: %s: %v", ctlAddr, err)
			stop()
		}
	}()
	// The certificate: renewed by the leader when less than 30 days are
	// left (a certificate of the current account only; the first one is
	// ordered by the CAA flip). Checked every minute (the Secret), and
	// the served pair mirrored as Traefik's default.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			if ordered, err := certs.Renew(ctx); err != nil {
				logger.Printf("frontdoor: renewing the certificate: %s", clean(err.Error()))
			} else if ordered {
				logger.Print("frontdoor: certificate renewed")
			}
			if mirror != nil {
				if _, err := mirror.Sync(ctx); err != nil {
					logger.Printf("frontdoor: Traefik's default certificate: %s", clean(err.Error()))
				}
			}
			// The served pair's expiry; unreadable = 0 (the help says so).
			c, err := certs.Store.LoadServed(ctx)
			if err != nil {
				c = frontdoor.Cert{}
			}
			metrics.CertExpiry(c.ChainPEM)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	logger.Printf("frontdoor: %s (zone %s, TTL %s), Lease %s/%s as %s", domain, w.Zone, w.TTL, ns, frontdoor.LeaseName, pod)
	rctx, rcancel := context.WithCancel(ctx)
	ran := make(chan struct{})
	go func() { defer close(ran); r.Run(rctx) }()
	select {
	case <-ctx.Done():
		rcancel()
		<-ran
		return 0
	case <-fenceDone:
		// Standing by is final in this process: stop the loop (the engine
		// isn't shared), one last status round (no write: the fence is
		// closed), then exit so a fresh pod campaigns again.
		rcancel()
		<-ran
		r.Step(context.Background(), time.Now().UTC())
		logger.Print("frontdoor: standing by (the Lease was lost): exiting")
		return exitFailure
	}
}

// loopbackAddr: host:port with a loopback IP host.
func loopbackAddr(a string) bool {
	h, _, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

// frontdoorControl is the loopback control API:
//
//	GET  /v1/account                  {"account_uri"} (the leader registers one when there is none)
//	POST /v1/issue?account_uri=<uri>  order <d> and *.<d> now with that (the current) account:
//	                                  {"issued", "current", "account_uri", "not_after"} (issued false,
//	                                  current true: the stored certificate already is that account's
//	                                  with more than 30 days left, nothing ordered)
//	GET  /v1/cert                     the stored certificate's state (frontdoor.CertStatus)
//
// Errors: 409 standing by / no account / another account, 502 the CA or
// the provider (the message redacted).
func frontdoorControl(c *frontdoor.Certs, clean func(string) string) http.Handler {
	mux := http.NewServeMux()
	fail := func(rw http.ResponseWriter, err error) {
		code := http.StatusBadGateway
		if errors.Is(err, frontdoor.ErrStandingBy) || errors.Is(err, frontdoor.ErrNoAccount) || errors.Is(err, frontdoor.ErrOtherAccount) {
			code = http.StatusConflict
		}
		writeJSON(rw, code, map[string]string{"error": clean(err.Error())})
	}
	mux.HandleFunc("GET /v1/account", func(rw http.ResponseWriter, r *http.Request) {
		uri, err := c.AccountURI(r.Context())
		if err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, http.StatusOK, map[string]string{"account_uri": uri})
	})
	mux.HandleFunc("POST /v1/issue", func(rw http.ResponseWriter, r *http.Request) {
		want := r.URL.Query().Get("account_uri")
		if !dnsplan.ValidAccountURI(want) {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "account_uri: an ACME account URI is required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), issueTimeout)
		defer cancel()
		issued, err := c.IssueMainFor(ctx, want)
		if err != nil {
			fail(rw, err)
			return
		}
		cert, err := c.Store.LoadServed(ctx)
		if err != nil {
			fail(rw, err)
			return
		}
		na, _ := frontdoor.NotAfter(cert.ChainPEM)
		writeJSON(rw, http.StatusOK, map[string]any{"issued": issued, "current": true, "account_uri": cert.AccountURI, "not_after": na.UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("GET /v1/cert", func(rw http.ResponseWriter, r *http.Request) {
		st, err := c.Status(r.Context())
		if err != nil {
			fail(rw, err)
			return
		}
		writeJSON(rw, http.StatusOK, st)
	})
	return mux
}

// runFrontdoorClient is `domains frontdoor account-uri` (prints the
// front door's account URI) and `domains frontdoor issue --account-uri
// <uri>` (prints {"issued", "account_uri", "not_after"}), run in the front
// door's pod. Exit 0 ok, 1 refused (standing by, no account, another
// account), 2 usage, 3 a failure (the CA, the provider, the front door
// unreachable).
func runFrontdoorClient(args []string, addr string, stdout, stderr io.Writer) int {
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "domains frontdoor: %s\nusage: domains frontdoor [account-uri | cert-status | issue --account-uri <uri>]\n", msg)
		return exitUsage
	}
	if !loopbackAddr(addr) {
		return usage("FRONTDOOR_CONTROL_ADDR is not a loopback address")
	}
	var req *http.Request
	switch {
	case len(args) == 1 && args[0] == "account-uri":
		req, _ = http.NewRequest(http.MethodGet, "http://"+addr+"/v1/account", nil)
	case len(args) == 1 && args[0] == "cert-status":
		req, _ = http.NewRequest(http.MethodGet, "http://"+addr+"/v1/cert", nil)
	case len(args) == 3 && args[0] == "issue" && args[1] == "--account-uri":
		if !dnsplan.ValidAccountURI(args[2]) {
			return usage(fmt.Sprintf("%q is not an ACME account URI", args[2]))
		}
		req, _ = http.NewRequest(http.MethodPost, "http://"+addr+"/v1/issue?account_uri="+url.QueryEscape(args[2]), nil)
	default:
		return usage("unexpected arguments")
	}
	resp, err := (&http.Client{Timeout: issueTimeout + time.Minute}).Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "domains frontdoor: the running front door doesn't answer on %s: %v\n", addr, err)
		return exitFailure
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		fmt.Fprintf(stderr, "domains frontdoor: unreadable answer (HTTP %d)\n", resp.StatusCode)
		return exitFailure
	}
	switch {
	case resp.StatusCode == http.StatusOK && args[0] == "account-uri":
		u, _ := body["account_uri"].(string)
		if !dnsplan.ValidAccountURI(u) {
			fmt.Fprintln(stderr, "domains frontdoor: the answer holds no account URI")
			return exitFailure
		}
		fmt.Fprintln(stdout, u)
		return exitOK
	case resp.StatusCode == http.StatusOK:
		b, _ := json.Marshal(body)
		fmt.Fprintln(stdout, string(b))
		return exitOK
	}
	msg, _ := body["error"].(string)
	fmt.Fprintf(stderr, "domains frontdoor: %s\n", msg)
	if resp.StatusCode == http.StatusConflict {
		// The refusal also on stdout, so a caller over kubectl exec tells
		// it apart from kubectl's own exit 1 (a lost connection, no pod).
		b, _ := json.Marshal(map[string]string{"refused": msg})
		fmt.Fprintln(stdout, string(b))
		return exitProblem
	}
	return exitFailure
}
