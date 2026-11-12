package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/domains/internal/dnsplan"
	"github.com/portcullis/domains/internal/dnssec"
)

// Domain states (contract §12.2).
const (
	StatePending  = "pending"
	StateRecords  = "records"
	StateIssuing  = "issuing"
	StateReady    = "ready"
	StateRenewing = "renewing"
	StateError    = "error"
)

// renewBefore: certificates are renewed when less than this is left.
const renewBefore = 30 * 24 * time.Hour

// Config is the service's configuration (main.go reads it from the
// environment; tests set it directly).
type Config struct {
	MainDomain string
	Email      string
	CAServer   string
	IPv4, IPv6 netip.Addr
	// Resolvers answer the records check (contract: 1.1.1.1:53 and
	// 8.8.8.8:53; CI points them at its fake DNS server).
	Resolvers []string
	// Secret is the API bearer secret (secrets/domains/api-secret).
	Secret string
	// PropagationTimeout bounds lego's wait for the TXT record.
	PropagationTimeout time.Duration
	// PropagationInterval: lego's wait before and between checks.
	PropagationInterval time.Duration
	// RecordsWait / RecordsPoll: how long one attempt polls the records
	// check before it fails (and backs off), and how often.
	RecordsWait, RecordsPoll time.Duration
	// RecheckEvery: how often a ready domain's records are re-checked.
	RecheckEvery time.Duration
	// Tick: how often the worker looks for due work.
	Tick time.Duration
	// CAA: the caa record set is on (DNS_CAA). CAAIssuer is the CA's CAA
	// issuer domain (dnsplan.IssuerFor at start; "" = unknown CA: nothing
	// written, nothing judged). CAAIODEF: optional iodef (DNS_CAA_IODEF).
	CAA       bool
	CAAIssuer string
	CAAIODEF  string
	// MainAccountURI: Traefik's ACME account URI (main-domain.env), the
	// pin the read-only main-domain plan judges against.
	MainAccountURI string
	// MailFrom: ALERT_SMTP_FROM (no nomail recommendation for its domain).
	MailFrom string
	// ACMEHTTPClient overrides lego's HTTP client (tests: Pebble's TLS).
	ACMEHTTPClient *http.Client
	Now            func() time.Time
	Logger         *log.Logger
}

// Service is the domains service: the API (:8080), the certificate
// endpoint (:8443) and the background worker share its state.
type Service struct {
	cfg      Config
	store    *Store
	findZone func(fqdn string) (string, error)

	mu   sync.Mutex // guards doc and busy; never held across network calls
	doc  *storeDoc
	busy map[string]*job // running work per domain name
	kick chan struct{}

	// plans caches the last plan per domain name (mainPlanKey: the main
	// domain), guarded by mu; built outside mu.
	plans map[string]cachedPlan

	acmeMu      sync.Mutex // serialises ACME account registration
	lastDropped string     // last logged list of dropped certificates (guarded by mu)
	wg          sync.WaitGroup
}

// NewService loads the store.
func NewService(cfg Config, store *Store) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	if cfg.PropagationTimeout == 0 {
		cfg.PropagationTimeout = 10 * time.Minute
	}
	if cfg.PropagationInterval == 0 {
		cfg.PropagationInterval = 5 * time.Second
	}
	if cfg.RecordsWait == 0 {
		cfg.RecordsWait = 10 * time.Minute
	}
	if cfg.RecordsPoll == 0 {
		cfg.RecordsPoll = 15 * time.Second
	}
	if cfg.RecheckEvery == 0 {
		cfg.RecheckEvery = time.Hour
	}
	if cfg.Tick == 0 {
		cfg.Tick = 30 * time.Second
	}
	doc, err := store.Load()
	if err != nil {
		return nil, err
	}
	// Records set to other addresses than the configured ones are due now.
	for _, d := range doc.Domains {
		// An unknown IPv4 (a failed lookup) is no address change: the
		// records set before stay and renewals go on (work).
		if d.AppliedIPv4 == "" || d.State != StateReady || !cfg.IPv4.IsValid() {
			continue
		}
		if d.AppliedIPv4 != addrString(cfg.IPv4) || d.AppliedIPv6 != addrString(cfg.IPv6) {
			cfg.Logger.Printf("domain %s: the server's addresses changed (%s/%s → %s/%s): records due", d.Name,
				d.AppliedIPv4, d.AppliedIPv6, addrString(cfg.IPv4), addrString(cfg.IPv6))
			d.State = StatePending
		}
	}
	return &Service{cfg: cfg, store: store, findZone: legoZoneFinder, doc: doc, busy: map[string]*job{}, kick: make(chan struct{}, 1),
		plans: map[string]cachedPlan{}}, nil
}

// job is one running attempt for a domain. rec (a one-slot semaphore) is
// held while it sets records and records what it set, so a DELETE or a
// credentials replacement can wait for that — bounded by its request's
// context — and then see every record, including ones created after it
// started.
type job struct {
	rec chan struct{}
	// held: the worker goroutine holds rec (only that goroutine touches
	// it, so its recover can release exactly its own slot).
	held bool
}

func newJob() *job { return &job{rec: make(chan struct{}, 1)} }

func (j *job) lock()   { j.rec <- struct{}{}; j.held = true }
func (j *job) unlock() { j.held = false; <-j.rec }

// waitRecords waits until no records step of j is running (ctx bounds it).
func (j *job) waitIdle(ctx context.Context) error {
	if j == nil {
		return nil
	}
	select {
	case j.rec <- struct{}{}:
		<-j.rec
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// recordsStepWait bounds how long DELETE / token wait for a records step.
// Budget (DELETE): this wait + recordsDeleteTimeout < the API's 3-min
// WriteTimeout < the Hub client's 4 min.
const recordsStepWait = 90 * time.Second

// recordsDeleteTimeout bounds removing a deleted domain's records.
const recordsDeleteTimeout = 60 * time.Second

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// newGenerationLocked hands out a never-reused generation. Caller holds mu.
func (s *Service) newGenerationLocked() int {
	s.doc.NextGeneration++
	return s.doc.NextGeneration
}

func (s *Service) logf(format string, args ...any) { s.cfg.Logger.Printf(format, args...) }

// ── API (contract §12.2) ─────────────────────────────────

// View is the domain object of the API: never credentials.
type View struct {
	Name         string  `json:"name"`
	Provider     string  `json:"provider"`
	RecordsOK    bool    `json:"records_ok"`
	CertNotAfter *string `json:"cert_not_after"`
	LastError    string  `json:"last_error"`
	State        string  `json:"state"`
	CAAOK        bool    `json:"caa_ok"`
	DNSSEC       string  `json:"dnssec"`
}

func (s *Service) viewLocked(d *Domain) View {
	v := View{Name: d.Name, Provider: d.Provider, RecordsOK: d.RecordsOK, LastError: d.LastError, State: d.State,
		CAAOK: d.CAAOK, DNSSEC: d.DNSSEC}
	if v.DNSSEC == "" {
		v.DNSSEC = string(dnssec.Unknown)
	}
	// cert_not_after is the expiry of the certificate actually served.
	if d.CertNotAfter != nil && servable(d, s.cfg.MainDomain, s.cfg.Now()) == nil {
		t := d.CertNotAfter.UTC().Format(time.RFC3339)
		v.CertNotAfter = &t
	}
	return v
}

// APIHandler serves the API behind the bearer secret; /healthz is open.
func (s *Service) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /domains", s.handleList)
	mux.HandleFunc("PUT /domains/{name}", s.handleEnroll)
	mux.HandleFunc("POST /domains/{name}/token", s.handleToken)
	mux.HandleFunc("DELETE /domains/{name}", s.handleDelete)
	mux.HandleFunc("GET /domains/{name}/dns", s.handlePlan)
	mux.HandleFunc("POST /domains/{name}/dns/apply", s.handleApply)
	mux.HandleFunc("POST /domains/{name}/dnssec", s.handleDNSSEC)
	mux.HandleFunc("GET /main/dns", s.handleMainPlan)
	mux.HandleFunc("GET /acme/account", s.handleAccount)
	want := sha256.Sum256([]byte("Bearer " + s.cfg.Secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			w.Write([]byte("ok\n"))
			return
		}
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// pathName validates {name} (contract §12.2).
func (s *Service) pathName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if err := checkName(name, s.cfg.MainDomain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return name, true
}

type credsBody struct {
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
}

// readCreds decodes and validates {provider, credentials}. Errors never
// quote the body (it holds the credentials).
func readCreds(w http.ResponseWriter, r *http.Request) (credsBody, bool) {
	var b credsBody
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, `body must be {"provider": "<provider>", "credentials": {"<key>": "<string>", ...}}`)
		return b, false
	}
	if err := validateCredentials(b.Provider, b.Credentials); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return b, false
	}
	return b, true
}

func (s *Service) handleList(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]View, 0, len(s.doc.Domains))
	for _, d := range s.doc.Domains {
		out = append(out, s.viewLocked(d))
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleEnroll(w http.ResponseWriter, r *http.Request) {
	name, ok := s.pathName(w, r)
	if !ok {
		return
	}
	b, ok := readCreds(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if _, exists := s.doc.Domains[name]; exists {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, name+" is already enrolled")
		return
	}
	gen := s.newGenerationLocked()
	d := &Domain{Name: name, Provider: b.Provider, Credentials: b.Credentials, State: StatePending, Generation: gen, EnrollID: gen}
	s.doc.Domains[name] = d
	err := s.store.Save(s.doc)
	if err != nil {
		delete(s.doc.Domains, name)
	}
	v := s.viewLocked(d)
	s.mu.Unlock()
	if err != nil {
		s.logf("enroll %s: saving the store failed: %v", name, err)
		writeError(w, http.StatusInternalServerError, "saving the store failed")
		return
	}
	s.logf("domain %s enrolled (provider %s)", name, b.Provider)
	s.Kick()
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Service) handleToken(w http.ResponseWriter, r *http.Request) {
	name, ok := s.pathName(w, r)
	if !ok {
		return
	}
	b, ok := readCreds(w, r)
	if !ok {
		return
	}
	// Let a running records step record what it set under the old
	// credentials first (bounded by the request).
	s.mu.Lock()
	j := s.busy[name]
	s.mu.Unlock()
	wctx, cancel := context.WithTimeout(r.Context(), recordsStepWait)
	werr := j.waitIdle(wctx)
	cancel()
	if werr != nil {
		writeError(w, http.StatusServiceUnavailable, "a records step for "+name+" is still running: retry")
		return
	}
	s.mu.Lock()
	d, exists := s.doc.Domains[name]
	if !exists || d.Deleting {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	old := *d
	d.Provider, d.Credentials = b.Provider, b.Credentials
	d.Generation = s.newGenerationLocked()
	d.State, d.LastError, d.Failures, d.NextAttempt = StatePending, "", 0, time.Time{}
	err := s.store.Save(s.doc)
	if err != nil {
		*d = old
	}
	v := s.viewLocked(d)
	s.mu.Unlock()
	if err != nil {
		s.logf("token %s: saving the store failed: %v", name, err)
		writeError(w, http.StatusInternalServerError, "saving the store failed")
		return
	}
	s.logf("domain %s: credentials replaced (provider %s)", name, b.Provider)
	s.Kick()
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	name, ok := s.pathName(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	d, exists := s.doc.Domains[name]
	if !exists || d.Deleting {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	// No new work, running work stops at its next step; wait until a
	// running records step has recorded what it set.
	d.Deleting = true
	j := s.busy[name]
	s.mu.Unlock()
	wctx, cancel := context.WithTimeout(r.Context(), recordsStepWait)
	werr := j.waitIdle(wctx)
	cancel()
	if werr != nil {
		s.mu.Lock()
		d.Deleting = false
		s.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, "a records step for "+name+" is still running: retry the delete")
		return
	}
	s.mu.Lock()
	snap := copyDomain(d)
	delete(s.doc.Domains, name)
	delete(s.plans, name)
	err := s.store.Save(s.doc)
	if err != nil {
		d.Deleting = false
		s.doc.Domains[name] = d
	}
	s.mu.Unlock()
	if err != nil {
		s.logf("delete %s: saving the store failed: %v", name, err)
		writeError(w, http.StatusInternalServerError, "saving the store failed")
		return
	}
	// The certificate is gone from the endpoint; now the records.
	s.logf("domain %s removed", name)
	if len(snap.Records) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), recordsDeleteTimeout)
	defer cancel()
	p, perr := buildProvider(snap)
	if perr == nil {
		zones := make([]string, 0, len(snap.Records))
		for z := range snap.Records {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		var errs []error
		for _, z := range zones {
			if err := deleteRecords(ctx, p, z, snap.Records[z]); err != nil {
				errs = append(errs, fmt.Errorf("zone %s: %w", z, err))
			}
		}
		perr = errors.Join(errs...)
	}
	if perr != nil {
		msg := redact(perr.Error(), snap.Credentials)
		s.logf("domain %s: removing its DNS records failed: %s", name, msg)
		writeJSON(w, http.StatusOK, map[string]string{"warning": "some DNS records couldn't be removed (remove them by hand): " + msg})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func copyDomain(d *Domain) *Domain {
	c := *d
	c.Credentials = make(map[string]string, len(d.Credentials))
	for k, v := range d.Credentials {
		c.Credentials[k] = v
	}
	c.Records = make(map[string][]RecordRef, len(d.Records))
	for z, refs := range d.Records {
		c.Records[z] = append([]RecordRef(nil), refs...)
	}
	return &c
}

// ── certificate endpoint (contract §12.4) ────────────────

// CertsHandler serves GET /traefik/dynamic (the listener requires a client
// certificate from the endpoint CA; main.go sets that up).
func (s *Service) CertsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /traefik/dynamic", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		doc, dropped := buildDynamic(s.doc.Domains, s.cfg.MainDomain, s.cfg.Now())
		if d := strings.Join(dropped, "; "); d != s.lastDropped {
			s.lastDropped = d
			if d != "" {
				s.logf("certificate endpoint: not serving: %s", d)
			}
		}
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, doc)
	})
	return mux
}

// ── worker ───────────────────────────────────────────────

// Kick asks the worker to look for due work now.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run is the worker loop; it returns once ctx is done and running work
// has finished.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.Tick)
	defer t.Stop()
	for {
		s.dispatch(ctx)
		select {
		case <-ctx.Done():
			s.wg.Wait()
			return
		case <-t.C:
		case <-s.kick:
		}
	}
}

// Wait waits for running work (tests).
func (s *Service) Wait() { s.wg.Wait() }

func (s *Service) needsCert(d *Domain, now time.Time) bool {
	return d.CertNotAfter == nil || servable(d, s.cfg.MainDomain, now) != nil || d.CertNotAfter.Sub(now) < renewBefore
}

func (s *Service) dueLocked(d *Domain, now time.Time) bool {
	if now.Before(d.NextAttempt) {
		return false
	}
	if d.State == StateReady {
		return s.needsCert(d, now) || now.Sub(d.RecordsCheckedAt) >= s.cfg.RecheckEvery ||
			s.caaDueLocked(d, s.accountURILocked()) || len(d.DueSets) > 0 || d.SignRequested
	}
	return true
}

// caaDueLocked: the caa set must be applied — CAA on with a known issuer
// and the live pin written for another account URI than uri (or the
// stored account no longer matches the configured CA / email, so a new
// one registers first); or CAA off while CAA entries we wrote are still
// recorded (removal). Caller holds mu.
func (s *Service) caaDueLocked(d *Domain, uri string) bool {
	if !s.cfg.CAA {
		return hasCAARefs(d)
	}
	if s.cfg.CAAIssuer == "" {
		return false
	}
	return d.CAAAccountURI == "" || d.CAAAccountURI != uri || !s.accountCurrentLocked()
}

func hasCAARefs(d *Domain) bool {
	for _, refs := range d.Records {
		for _, r := range refs {
			if r.Type == "CAA" {
				return true
			}
		}
	}
	return false
}

// dispatch starts work for every due domain that isn't already busy.
func (s *Service) dispatch(ctx context.Context) {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, d := range s.doc.Domains {
		if s.busy[name] != nil || d.Deleting || !s.dueLocked(d, now) {
			continue
		}
		// A stored name that breaks the rules (e.g. the main domain changed
		// to a parent of it) gets no records and no ACME order — ever.
		if err := checkName(name, s.cfg.MainDomain); err != nil {
			msg := "this name can't be served: " + err.Error()
			if d.State != StateError || d.LastError != msg {
				d.State, d.LastError, d.RecordsOK = StateError, msg, false
				s.logf("domain %s: %s", name, msg)
			}
			d.NextAttempt = now.Add(6 * time.Hour)
			if err := s.store.Save(s.doc); err != nil {
				s.logf("domain %s: saving the store failed: %v", name, err)
			}
			continue
		}
		j := newJob()
		s.busy[name] = j
		snap := copyDomain(d)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				// A panicking provider library must not take the service down.
				if r := recover(); r != nil {
					// Release the records step if the panic hit inside it
					// (a held slot would block DELETE and token for good).
					if j.held {
						j.unlock()
					}
					s.logf("domain %s: internal error (panic) during work — retried with backoff", snap.Name)
					s.update(snap.Name, snap.Generation, func(d *Domain) {
						d.State, d.LastError = StateError, "internal error while working on this domain"
						d.Failures++
						d.NextAttempt = s.cfg.Now().Add(backoff(d.Failures))
					})
					s.mu.Lock()
					delete(s.busy, snap.Name)
					s.mu.Unlock()
				}
			}()
			s.work(ctx, snap, j)
			s.mu.Lock()
			delete(s.busy, snap.Name)
			s.mu.Unlock()
		}()
	}
}

// update applies f to the domain if it still exists with the same
// generation and isn't being deleted, and saves; false = the work is
// stale (deleted, re-enrolled or new credentials).
func (s *Service) update(name string, gen int, f func(d *Domain)) bool {
	return s.updateIf(name, gen, false, f)
}

// updateRecords records the records a step created: whatever the
// generation (new credentials) and while a DELETE waits, as long as it is
// the same enrollment.
func (s *Service) updateRecords(name string, enrollID int, f func(d *Domain)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.doc.Domains[name]
	if !ok || d.EnrollID != enrollID {
		return
	}
	f(d)
	if err := s.store.Save(s.doc); err != nil {
		s.logf("domain %s: saving the store failed: %v", name, err)
	}
}

// updateIf: deleting=true also commits while a DELETE waits.
func (s *Service) updateIf(name string, gen int, deleting bool, f func(d *Domain)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.doc.Domains[name]
	if !ok || d.Generation != gen || (d.Deleting && !deleting) {
		return false
	}
	f(d)
	if err := s.store.Save(s.doc); err != nil {
		s.logf("domain %s: saving the store failed: %v", name, err)
	}
	return true
}

// backoff after n consecutive failures: 1 min, doubling, at most 6 h.
func backoff(n int) time.Duration {
	d := time.Minute
	for i := 1; i < n && d < 6*time.Hour; i++ {
		d *= 2
	}
	if d > 6*time.Hour {
		d = 6 * time.Hour
	}
	return d
}

// work runs one attempt for a domain: records (set, unless only a ready
// domain's re-check is due), the certificate if there's no valid one or it
// is within 30 days of expiry, then the records check. Any failure is
// recorded (redacted) with backoff; a still-valid certificate stays served.
func (s *Service) work(ctx context.Context, snap *Domain, j *job) {
	name, gen := snap.Name, snap.Generation
	now := s.cfg.Now()
	fail := func(err error) {
		msg := redact(err.Error(), snap.Credentials)
		s.update(name, gen, func(d *Domain) {
			d.State, d.LastError = StateError, msg
			d.Failures++
			d.NextAttempt = s.cfg.Now().Add(backoff(d.Failures))
		})
		s.logf("domain %s: %s", name, msg)
	}
	p, err := buildProvider(snap)
	if err != nil {
		fail(err)
		return
	}
	needCert := s.needsCert(snap, now)
	hasValid := snap.CertNotAfter != nil && servable(snap, s.cfg.MainDomain, now) == nil
	s.mu.Lock()
	caaDue := s.caaDueLocked(snap, s.accountURILocked())
	s.mu.Unlock()
	// The account first (registration is never CAA-checked), so the CAA
	// can be pinned to its URI before any order (contract §12.4).
	var u *acmeUser
	uri := ""
	if needCert || caaDue {
		if u, err = s.account(); err != nil {
			fail(err)
			return
		}
		uri = u.reg.URI
	}
	// The server's IPv4 unknown (./portcullis up couldn't detect it) but
	// records were set before: keep them and go on (a renewal must not
	// stall on an address lookup); the check compares with what was set.
	keepRecords := !s.cfg.IPv4.IsValid() && snap.AppliedIPv4 != ""
	recordsStep := !(snap.State == StateReady && !needCert) || caaDue || len(snap.DueSets) > 0 || snap.SignRequested
	if recordsStep {
		var sets []string
		for _, set := range dnsplan.Sets {
			switch {
			case set == dnsplan.SetAddress && keepRecords:
				s.logf("domain %s: the server's public IPv4 is unknown: keeping the records set for %s (records step skipped)", name, snap.AppliedIPv4)
			case set == dnsplan.SetAddress:
				sets = append(sets, set)
			case set == dnsplan.SetCAA:
				if u != nil && (s.cfg.CAA && s.cfg.CAAIssuer != "" || !s.cfg.CAA && hasCAARefs(snap)) {
					sets = append(sets, set)
				}
			case contains(snap.Sets, set) || contains(snap.DueSets, set):
				sets = append(sets, set)
			}
		}
		j.lock()
		if !s.update(name, gen, func(d *Domain) { d.State = StateRecords }) {
			j.unlock()
			return
		}
		rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		var written, removed []RecordRef
		var zone string
		if len(sets) > 0 {
			written, removed, zone, err = s.applySets(rctx, p, snap, sets, uri)
		}
		if err == nil && snap.SignRequested {
			err = s.enableSigning(rctx, snap)
		}
		cancel()
		// Recorded even on failure (a partial apply may have created
		// some) and while a DELETE waits, so DELETE removes them.
		if zone != "" {
			s.updateRecords(name, snap.EnrollID, func(d *Domain) {
				if d.Records == nil {
					d.Records = map[string][]RecordRef{}
				}
				d.Records[zone] = mergeRecords(dropRecords(d.Records[zone], removed), written)
				if err == nil && contains(sets, dnsplan.SetAddress) {
					d.AppliedIPv4, d.AppliedIPv6 = addrString(s.cfg.IPv4), addrString(s.cfg.IPv6)
				}
			})
		}
		j.unlock()
		if err != nil {
			s.update(name, gen, func(d *Domain) { d.RecordsOK = false })
			fail(err)
			return
		}
		applied := sets
		s.update(name, gen, func(d *Domain) {
			var left []string
			for _, x := range d.DueSets {
				if !contains(applied, x) {
					left = append(left, x)
				}
			}
			d.DueSets = left
			if snap.SignRequested {
				d.SignRequested = false
			}
			if contains(applied, dnsplan.SetCAA) && !s.cfg.CAA {
				d.CAAAccountURI, d.CAAOK = "", false
			}
		})
		// Pinned: wait until every resolver lets the CA issue to this
		// account, and only then order.
		if contains(sets, dnsplan.SetCAA) && s.cfg.CAA {
			if err := s.waitCAA(ctx, name, uri); err != nil {
				s.update(name, gen, func(d *Domain) { d.CAAOK = false })
				fail(fmt.Errorf("CAA not visible at the public resolvers yet: %w", err))
				return
			}
			s.update(name, gen, func(d *Domain) { d.CAAAccountURI = uri })
		}
	}
	if needCert {
		st := StateIssuing
		if hasValid {
			st = StateRenewing
		}
		if !s.update(name, gen, func(d *Domain) { d.State = st }) {
			return
		}
		s.logf("domain %s: %s a certificate for %s and *.%s", name, map[bool]string{true: "renewing", false: "requesting"}[hasValid], name, name)
		certPEM, keyPEM, notAfter, err := s.obtain(name, p, u)
		if err != nil {
			fail(err)
			return
		}
		// Never store (and keep re-ordering) a certificate the endpoint
		// would refuse to serve.
		probe := copyDomain(snap)
		probe.CertPEM, probe.KeyPEM, probe.CertNotAfter = certPEM, keyPEM, &notAfter
		if err := servable(probe, s.cfg.MainDomain, s.cfg.Now()); err != nil {
			fail(fmt.Errorf("the issued certificate can't be served: %w", err))
			return
		}
		if !s.update(name, gen, func(d *Domain) { d.CertPEM, d.KeyPEM, d.CertNotAfter = certPEM, keyPEM, &notAfter }) {
			return
		}
		s.logf("domain %s: certificate valid until %s", name, notAfter.Format(time.RFC3339))
	}
	err = s.waitRecords(ctx, name)
	s.update(name, gen, func(d *Domain) { d.RecordsOK, d.RecordsCheckedAt = err == nil, s.cfg.Now() })
	if err != nil {
		fail(fmt.Errorf("records not visible at the public resolvers yet: %w", err))
		return
	}
	s.refreshChecks(ctx, name, gen, p)
	if s.update(name, gen, func(d *Domain) {
		d.State, d.LastError, d.Failures, d.NextAttempt = StateReady, "", 0, time.Time{}
	}) && snap.State != StateReady {
		s.logf("domain %s: ready", name)
	}
}

// enableSigning turns DNSSEC signing on for d's zone (SignRequested).
func (s *Service) enableSigning(ctx context.Context, d *Domain) error {
	r, _, err := buildDNSSEC(d)
	if err != nil {
		return err
	}
	signer, ok := r.(dnssec.Signer)
	if !ok {
		return fmt.Errorf("%s can't sign the zone through its API", d.Provider)
	}
	zone, err := dnssec.FindZone(ctx, s.cfg.Resolvers, d.Name)
	if err != nil {
		return fmt.Errorf("finding the DNS zone of %s: %w", d.Name, err)
	}
	if err := signer.EnableDNSSEC(ctx, zone); err != nil {
		return fmt.Errorf("turning on DNSSEC signing for %s: %w", strings.TrimSuffix(zone, "."), err)
	}
	s.logf("domain %s: DNSSEC signing turned on for the zone %s", d.Name, strings.TrimSuffix(zone, "."))
	return nil
}

// refreshChecks builds the domain's plan (public checks + provider view)
// and records caa_ok and dnssec from it.
func (s *Service) refreshChecks(ctx context.Context, name string, gen int, p dnsProvider) {
	s.mu.Lock()
	d, ok := s.doc.Domains[name]
	if !ok {
		s.mu.Unlock()
		return
	}
	snap := copyDomain(d)
	s.mu.Unlock()
	pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	pl := s.finishPlan(s.buildPlan(pctx, snap, p))
	s.mu.Lock()
	s.plans[name] = cachedPlan{plan: pl, at: s.cfg.Now()}
	s.mu.Unlock()
	caaOK := s.cfg.CAA && s.cfg.CAAIssuer != "" && pl.CAA.WouldIssue
	for _, it := range pl.Items {
		if it.Set == dnsplan.SetCAA && it.Status != dnsplan.StatusOK && it.Status != dnsplan.StatusForeign {
			caaOK = false
		}
	}
	s.update(name, gen, func(d *Domain) { d.CAAOK, d.DNSSEC = caaOK, string(pl.DNSSEC.State) })
}

// ── DNS plans (contract §12.2) ───────────────────────────

// planRefreshEvery throttles ?refresh=1: one build per name per 30 s.
const planRefreshEvery = 30 * time.Second

// planTimeout bounds one plan build.
const planTimeout = 60 * time.Second

// mainPlanKey is the main domain's key in plans (never a valid name).
const mainPlanKey = "@main"

type cachedPlan struct {
	plan dnsplan.Plan
	at   time.Time
}

// cachedLocked returns the cached plan to answer with, if any: always
// without refresh, within the throttle window with it. Caller holds mu.
func (s *Service) cachedLocked(key string, refresh bool) (dnsplan.Plan, bool) {
	c, ok := s.plans[key]
	if !ok {
		return dnsplan.Plan{}, false
	}
	if !refresh || s.cfg.Now().Sub(c.at) < planRefreshEvery {
		return c.plan, true
	}
	return dnsplan.Plan{}, false
}

// errNotEnrolled: plan() for a name the service doesn't hold.
var errNotEnrolled = errors.New("not enrolled")

// plan is the domain's plan, cached; refresh rebuilds it (throttled).
func (s *Service) plan(ctx context.Context, name string, refresh bool) (dnsplan.Plan, error) {
	s.mu.Lock()
	d, ok := s.doc.Domains[name]
	if !ok || d.Deleting {
		s.mu.Unlock()
		return dnsplan.Plan{}, errNotEnrolled
	}
	if pl, ok := s.cachedLocked(name, refresh); ok {
		s.mu.Unlock()
		return pl, nil
	}
	snap := copyDomain(d)
	s.mu.Unlock()
	p, err := buildProvider(snap)
	if err != nil {
		p = nil // read-only plan; the records step reports the error
	}
	pl := s.finishPlan(s.buildPlan(ctx, snap, p))
	s.mu.Lock()
	s.plans[name] = cachedPlan{plan: pl, at: s.cfg.Now()}
	s.mu.Unlock()
	return pl, nil
}

// mainPlan is the main domain's read-only plan (no credentials: public
// checks only, pinned to Traefik's account URI from main-domain.env).
func (s *Service) mainPlan(ctx context.Context, refresh bool) dnsplan.Plan {
	s.mu.Lock()
	if pl, ok := s.cachedLocked(mainPlanKey, refresh); ok {
		s.mu.Unlock()
		return pl
	}
	s.mu.Unlock()
	sp := dnsplan.Spec{Name: s.cfg.MainDomain, IPv4: s.cfg.IPv4, IPv6: s.cfg.IPv6, CAA: s.cfg.CAA, Issuer: s.cfg.CAAIssuer,
		AccountURI: s.cfg.MainAccountURI, IODEF: s.cfg.CAAIODEF, Main: true}
	pl := s.finishPlan(dnsplan.Build(ctx, dnsplan.Input{Spec: sp, Resolvers: s.cfg.Resolvers, Now: s.cfg.Now()}))
	s.mu.Lock()
	s.plans[mainPlanKey] = cachedPlan{plan: pl, at: s.cfg.Now()}
	s.mu.Unlock()
	return pl
}

// finishPlan drops the nomail recommendation for a name that sends the
// alert mail (ALERT_SMTP_FROM at it or under it, spec §3).
func (s *Service) finishPlan(pl dnsplan.Plan) dnsplan.Plan {
	_, dom, ok := strings.Cut(s.cfg.MailFrom, "@")
	dom = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(dom), "."))
	if !ok || dom == "" || (dom != pl.Name && !strings.HasSuffix(dom, "."+pl.Name)) {
		return pl
	}
	items := make([]dnsplan.Item, 0, len(pl.Items))
	for _, it := range pl.Items {
		if it.Set == dnsplan.SetNoMail && it.Status == dnsplan.StatusMissing && it.Severity == dnsplan.SevInfo {
			continue
		}
		items = append(items, it)
	}
	pl.Items = items
	return pl
}

func (s *Service) handlePlan(w http.ResponseWriter, r *http.Request) {
	name, ok := s.pathName(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), planTimeout)
	defer cancel()
	pl, err := s.plan(ctx, name, r.URL.Query().Get("refresh") == "1")
	if err != nil {
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	writeJSON(w, http.StatusOK, pl)
}

func (s *Service) handleMainPlan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), planTimeout)
	defer cancel()
	writeJSON(w, http.StatusOK, s.mainPlan(ctx, r.URL.Query().Get("refresh") == "1"))
}

func (s *Service) handleAccount(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	uri := s.accountURILocked()
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"ca_server": s.cfg.CAServer, "account_uri": uri, "caa_issuer": s.cfg.CAAIssuer})
}

// decodeStrict decodes exactly one JSON object with known fields only.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(v) == nil && dec.Decode(&struct{}{}) == io.EOF
}

func (s *Service) handleApply(w http.ResponseWriter, r *http.Request) {
	name, ok := s.pathName(w, r)
	if !ok {
		return
	}
	var b struct {
		Sets []string `json:"sets"`
	}
	usage := `body must be {"sets": [...]} with sets from ` + strings.Join(dnsplan.Sets, ", ")
	if !decodeStrict(w, r, &b) || len(b.Sets) == 0 {
		writeError(w, http.StatusBadRequest, usage)
		return
	}
	for _, set := range b.Sets {
		if !contains(dnsplan.Sets, set) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown record set %q: %s", set, usage))
			return
		}
	}
	s.mu.Lock()
	d, exists := s.doc.Domains[name]
	if !exists || d.Deleting {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	oldSets, oldDue := d.Sets, d.DueSets
	for _, set := range b.Sets {
		if set == dnsplan.SetNoMail && !contains(d.Sets, set) {
			d.Sets = append(append([]string(nil), d.Sets...), set)
		}
		if !contains(d.DueSets, set) {
			d.DueSets = append(append([]string(nil), d.DueSets...), set)
		}
	}
	d.NextAttempt = time.Time{}
	err := s.store.Save(s.doc)
	if err != nil {
		d.Sets, d.DueSets = oldSets, oldDue
	}
	v := s.viewLocked(d)
	s.mu.Unlock()
	if err != nil {
		s.logf("dns apply %s: saving the store failed: %v", name, err)
		writeError(w, http.StatusInternalServerError, "saving the store failed")
		return
	}
	s.logf("domain %s: record sets due: %s", name, strings.Join(b.Sets, ", "))
	s.Kick()
	writeJSON(w, http.StatusAccepted, v)
}

func (s *Service) handleDNSSEC(w http.ResponseWriter, r *http.Request) {
	name, ok := s.pathName(w, r)
	if !ok {
		return
	}
	var b struct {
		Enable *bool `json:"enable"`
	}
	if !decodeStrict(w, r, &b) || b.Enable == nil || !*b.Enable {
		writeError(w, http.StatusBadRequest, `body must be {"enable": true} (signing is never turned off)`)
		return
	}
	s.mu.Lock()
	d, exists := s.doc.Domains[name]
	if !exists || d.Deleting {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	snap := copyDomain(d)
	s.mu.Unlock()
	if _, can, err := buildDNSSEC(snap); err != nil || !can {
		writeError(w, http.StatusConflict, snap.Provider+" can't sign the zone through its API")
		return
	}
	s.mu.Lock()
	d, exists = s.doc.Domains[name]
	if !exists || d.Deleting {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	d.SignRequested, d.NextAttempt = true, time.Time{}
	err := s.store.Save(s.doc)
	if err != nil {
		d.SignRequested = false
	}
	v := s.viewLocked(d)
	s.mu.Unlock()
	if err != nil {
		s.logf("dnssec %s: saving the store failed: %v", name, err)
		writeError(w, http.StatusInternalServerError, "saving the store failed")
		return
	}
	s.logf("domain %s: DNSSEC signing requested", name)
	s.Kick()
	writeJSON(w, http.StatusAccepted, v)
}

// buildPlan is d's plan (provider p may be nil: read-only).
func (s *Service) buildPlan(ctx context.Context, d *Domain, p dnsProvider) dnsplan.Plan {
	s.mu.Lock()
	// The pin wanted is the current account's (an account switch shows
	// the old pin as wrong); before any registration, the one written.
	uri := s.accountURILocked()
	if uri == "" {
		uri = d.CAAAccountURI
	}
	s.mu.Unlock()
	in := dnsplan.Input{Spec: s.spec(d, uri), ProviderName: d.Provider, Resolvers: s.cfg.Resolvers, Now: s.cfg.Now()}
	if p != nil {
		in.Provider = p
		if zone, err := s.zoneOf(p, d.Name); err == nil {
			in.Zone = zone
		}
		if r, can, err := buildDNSSEC(d); err == nil {
			in.DNSSEC, in.CanSign = r, can
		}
	}
	return dnsplan.Build(ctx, in)
}

// wantAddrs are the addresses <name>'s records must show: the configured
// ones, or — the IPv4 unknown — the IPv4 the records were last set to
// (and the last IPv6 unless a configured one is known: a fresh IPv6
// always counts).
func (s *Service) wantAddrs(name string) (netip.Addr, netip.Addr) {
	if s.cfg.IPv4.IsValid() {
		return s.cfg.IPv4, s.cfg.IPv6
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.doc.Domains[name]
	if !ok {
		return netip.Addr{}, netip.Addr{}
	}
	v4, _ := netip.ParseAddr(d.AppliedIPv4)
	if s.cfg.IPv6.IsValid() {
		return v4, s.cfg.IPv6
	}
	v6, _ := netip.ParseAddr(d.AppliedIPv6)
	return v4, v6
}

// waitRecords polls the records check for up to RecordsWait.
func (s *Service) waitRecords(ctx context.Context, name string) error {
	deadline := time.Now().Add(s.cfg.RecordsWait)
	for {
		v4, v6 := s.wantAddrs(name)
		err := s.checkRecords(ctx, name, v4, v6)
		if err == nil || time.Now().Add(s.cfg.RecordsPoll).After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(s.cfg.RecordsPoll):
		}
	}
}

// dropRecords removes refs from list.
func dropRecords(list, refs []RecordRef) []RecordRef {
	var out []RecordRef
	for _, r := range list {
		if !containsRef(refs, r) {
			out = append(out, r)
		}
	}
	return out
}

func containsRef(list []RecordRef, r RecordRef) bool {
	for _, x := range list {
		if x == r {
			return true
		}
	}
	return false
}

func mergeRecords(old, add []RecordRef) []RecordRef {
	seen := map[RecordRef]bool{}
	var out []RecordRef
	for _, r := range append(append([]RecordRef(nil), old...), add...) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
