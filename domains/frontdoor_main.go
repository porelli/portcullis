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
	"net/http"
	"net/netip"
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

// runFrontdoor is `domains frontdoor`.
func runFrontdoor(stderr io.Writer) int {
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
