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
	busy map[string]bool
	kick chan struct{}

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
	return &Service{cfg: cfg, store: store, findZone: legoZoneFinder, doc: doc, busy: map[string]bool{}, kick: make(chan struct{}, 1)}, nil
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
}

func (s *Service) viewLocked(d *Domain) View {
	v := View{Name: d.Name, Provider: d.Provider, RecordsOK: d.RecordsOK, LastError: d.LastError, State: d.State}
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
	d := &Domain{Name: name, Provider: b.Provider, Credentials: b.Credentials, State: StatePending}
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
	s.mu.Lock()
	d, exists := s.doc.Domains[name]
	if !exists {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	old := *d
	d.Provider, d.Credentials = b.Provider, b.Credentials
	d.Generation++
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
	if !exists {
		s.mu.Unlock()
		writeError(w, http.StatusNotFound, name+" is not enrolled")
		return
	}
	snap := copyDomain(d)
	delete(s.doc.Domains, name)
	err := s.store.Save(s.doc)
	if err != nil {
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
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	p, perr := buildProvider(snap)
	if perr == nil {
		perr = deleteRecords(ctx, p, snap.Zone, snap.Records)
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
	c.Records = append([]RecordRef(nil), d.Records...)
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
		return s.needsCert(d, now) || now.Sub(d.RecordsCheckedAt) >= s.cfg.RecheckEvery
	}
	return true
}

// dispatch starts work for every due domain that isn't already busy.
func (s *Service) dispatch(ctx context.Context) {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, d := range s.doc.Domains {
		if s.busy[name] || !s.dueLocked(d, now) {
			continue
		}
		s.busy[name] = true
		snap := copyDomain(d)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.work(ctx, snap)
			s.mu.Lock()
			delete(s.busy, snap.Name)
			s.mu.Unlock()
		}()
	}
}

// update applies f to the domain if it still exists with the same
// credentials (generation) and saves; false = the work is stale.
func (s *Service) update(name string, gen int, f func(d *Domain)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.doc.Domains[name]
	if !ok || d.Generation != gen {
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
func (s *Service) work(ctx context.Context, snap *Domain) {
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
	if !(snap.State == StateReady && !needCert) {
		if !s.update(name, gen, func(d *Domain) { d.State = StateRecords }) {
			return
		}
		rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		refs, zone, err := s.setRecords(rctx, p, name)
		cancel()
		if err != nil {
			s.update(name, gen, func(d *Domain) { d.RecordsOK = false })
			fail(err)
			return
		}
		if !s.update(name, gen, func(d *Domain) { d.Records, d.Zone = mergeRecords(d.Records, refs), zone }) {
			return
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
		certPEM, keyPEM, notAfter, err := s.obtain(name, p)
		if err != nil {
			fail(err)
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
	if s.update(name, gen, func(d *Domain) {
		d.State, d.LastError, d.Failures, d.NextAttempt = StateReady, "", 0, time.Time{}
	}) && snap.State != StateReady {
		s.logf("domain %s: ready", name)
	}
}

// waitRecords polls the records check for up to RecordsWait.
func (s *Service) waitRecords(ctx context.Context, name string) error {
	deadline := time.Now().Add(s.cfg.RecordsWait)
	for {
		err := s.checkRecords(ctx, name)
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
