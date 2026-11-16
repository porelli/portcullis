// Package machines drives the per-domain state machines (DKIM, MTA-STS,
// DMARC) and the main host's TLSA from the applied document, renders each
// domain's wanted mail set (dnsset), and answers status, the well-known
// files and the actions (contract §19.5, §19.7). State lives in
// state.json's ext.
package machines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/mailctl/internal/dkim"
	"github.com/portcullis/mailctl/internal/dmarc"
	"github.com/portcullis/mailctl/internal/dnsset"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/mtasts"
	"github.com/portcullis/mailctl/internal/resolve"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
	"github.com/portcullis/mailctl/internal/tlsa"
	"golang.org/x/net/publicsuffix"
)

// Ext keys.
const (
	extDKIM   = "dkim"
	extMTASTS = "mtasts"
	extDMARC  = "dmarc"
	extTLSA   = "tlsa"
	extDNSSEC = "main_dnssec"
)

// ErrNotMailDomain: not a domain of the applied document (404).
var ErrNotMailDomain = errors.New("not a mail domain")

// ErrNothingToDo is a 409 with its reason.
type ErrNothingToDo struct{ Why string }

func (e ErrNothingToDo) Error() string { return e.Why }

// Config is what the machines need besides the document.
type Config struct {
	MainDomain  string
	Hostname    string
	SPFInclude  string
	Resolvers   []string // the public resolvers (DKIM visibility)
	RotateEvery time.Duration
	Reachable   bool // the well-known router is on websecure (not VPN-only)
}

// Machines is the driver.
type Machines struct {
	C     *stalwart.Client
	Store *state.Store
	Cfg   Config
	Now   func() time.Time
	Logf  func(string, ...any)
	// Visible overrides the resolver lookup (tests).
	Visible func(ctx context.Context, name, value string) bool
	// CertOK: the last certificate check (ok, known). nil = ok. Only a
	// known failure moves enforce back (local evidence); anything but a
	// known pass holds testing.
	CertOK func() (ok, known bool)
	// Verify authenticates report messages (nil: every report is
	// unauthenticated, display only).
	Verify Verify

	mu   sync.Mutex
	wake chan struct{}

	seenMu sync.Mutex
	seen   map[string]bool // reports already logged

	repMu sync.Mutex
	repAt time.Time // the last report read (the cache below), 0: none
	reps  []Report

	hashMu  sync.Mutex
	hashKey string            // the state revision and the main zone's DNSSEC state
	hashes  map[string]string // DNSHashes' last answer for hashKey
}

// New returns the driver.
func New(c *stalwart.Client, st *state.Store, cfg Config, logf func(string, ...any)) *Machines {
	return &Machines{C: c, Store: st, Cfg: cfg, Now: time.Now, Logf: logf, wake: make(chan struct{}, 1)}
}

func (m *Machines) now() time.Time { return m.Now().UTC().Truncate(time.Second) }

type dnssecRec struct {
	State string    `json:"state"`
	At    time.Time `json:"at"`
}

func read[T any](p state.Persistent, key string) T {
	var v T
	_ = json.Unmarshal(p.Ext[key], &v)
	return v
}

func put(p *state.Persistent, key string, v any) {
	b, _ := json.Marshal(v)
	p.Ext[key] = b
}

// Trigger asks for a pass now.
func (m *Machines) Trigger() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Loop runs a pass every 5 minutes and on Trigger.
func (m *Machines) Loop(ctx context.Context) {
	for {
		if err := m.Step(ctx); err != nil && m.Logf != nil {
			m.Logf("machines: %s", logx.Redact(err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-time.After(5 * time.Minute):
		}
	}
}

func (m *Machines) visible(ctx context.Context, name, value string) bool {
	if m.Visible != nil {
		return m.Visible(ctx, name, value)
	}
	return resolve.VisibleAll(ctx, m.Cfg.Resolvers, name, value)
}

func (m *Machines) domainIDs(ctx context.Context) (map[string]string, error) {
	ids, err := m.C.Query(ctx, "Domain", nil)
	if err != nil {
		return nil, err
	}
	var doms []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if len(ids) > 0 {
		if err := m.C.Get(ctx, "Domain", ids, []string{"id", "name"}, &doms); err != nil {
			return nil, err
		}
	}
	out := map[string]string{}
	for _, d := range doms {
		out[d.Name] = d.ID
	}
	return out, nil
}

// Report is one aggregate report as received (DMARC or TLS-RPT). Reports
// are unauthenticated mail: anyone can send one. Security ruling (T9):
// reports never weaken a policy on their own. A report counts for state
// (holding a progression) or a doctor Problem only when authenticated:
// its message passed DKIM aligned with its From domain, by the mail
// server's own verification (Verify); Sender is then that DKIM d= domain's
// registrable domain. Org and From are display only.
type Report struct {
	Kind          string // dmarc | tls
	ID            string
	Domain        string          // the report's policy domain, lowercase
	To            map[string]bool // the addresses it was sent to, lowercase
	Org           string          // the reporting organisation (display only)
	From          string          // the From address's domain (display only)
	End           time.Time
	Failing       bool
	Authenticated bool   // aligned DKIM pass (Verify)
	Sender        string // the registrable domain of the aligned DKIM d= ("" unless authenticated)
}

// Verify gives a report message's DKIM result: the d= domain of a passing
// signature and whether it passed. Stalwart v1.1.0's x:DmarcExternalReport
// / x:TlsExternalReport carry no verification result, so serve sets none
// and every report is unauthenticated (display only) until a verified
// source exists.
type Verify func(ctx context.Context, r Report) (dkimDomain string, pass bool)

// Registrable is a domain's registrable part (eTLD+1), "" when it has none.
func Registrable(d string) string {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	r, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return ""
	}
	return r
}

// authenticate fills Authenticated / Sender: a DKIM pass whose d= is
// aligned (relaxed: same registrable domain) with the From domain.
func (m *Machines) authenticate(ctx context.Context, rs []Report) {
	if m.Verify == nil {
		return
	}
	for i := range rs {
		dd, pass := m.Verify(ctx, rs[i])
		from := Registrable(rs[i].From)
		if pass && from != "" && Registrable(dd) == from {
			rs[i].Authenticated, rs[i].Sender = true, from
		}
	}
}

// skew: a report ending later than now + skew is dropped.
const skew = 5 * time.Minute

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}

func lowerSet(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k, v := range m {
		if v {
			out[strings.ToLower(k)] = true
		}
	}
	return out
}

// ReportsCacheFor: a status read answers the reports read at most this
// long ago (final review L12: the Hub polls status every minute, and the
// reports can be large); Step and the actions always read them fresh.
const ReportsCacheFor = 5 * time.Minute

// cachedReports is the last report read when it's younger than
// ReportsCacheFor, else a fresh one.
func (m *Machines) cachedReports(ctx context.Context) ([]Report, error) {
	m.repMu.Lock()
	if !m.repAt.IsZero() && m.now().Sub(m.repAt) < ReportsCacheFor && !m.now().Before(m.repAt) {
		r := append([]Report(nil), m.reps...)
		m.repMu.Unlock()
		m.authenticate(ctx, r)
		return r, nil
	}
	m.repMu.Unlock()
	return m.reports(ctx)
}

// reports reads every aggregate report Stalwart holds (and caches it).
func (m *Machines) reports(ctx context.Context) ([]Report, error) {
	out, err := m.readReports(ctx)
	if err != nil {
		return nil, err
	}
	// Cached as read; authenticated on every use (a copy).
	m.repMu.Lock()
	m.repAt, m.reps = m.now(), append([]Report(nil), out...)
	m.repMu.Unlock()
	m.authenticate(ctx, out)
	return out, nil
}

func (m *Machines) readReports(ctx context.Context) ([]Report, error) {
	var out []Report
	ids, err := m.C.Query(ctx, "DmarcExternalReport", nil)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		var rs []struct {
			ID     string          `json:"id"`
			From   string          `json:"from"`
			To     map[string]bool `json:"to"`
			Report struct {
				PolicyDomain string    `json:"policyDomain"`
				OrgName      string    `json:"orgName"`
				End          time.Time `json:"dateRangeEnd"`
				Records      map[string]struct {
					Dkim string `json:"evaluatedDkim"`
					Spf  string `json:"evaluatedSpf"`
				} `json:"records"`
			} `json:"report"`
		}
		if err := m.C.Get(ctx, "DmarcExternalReport", ids, []string{"id", "from", "to", "report"}, &rs); err != nil {
			return nil, err
		}
		for _, r := range rs {
			fail := false
			for _, rec := range r.Report.Records {
				if rec.Dkim != "pass" && rec.Spf != "pass" {
					fail = true
				}
			}
			out = append(out, Report{Kind: "dmarc", ID: r.ID, Domain: strings.ToLower(r.Report.PolicyDomain), To: lowerSet(r.To),
				Org: strings.ToLower(strings.TrimSpace(r.Report.OrgName)), From: domainOf(r.From), End: r.Report.End, Failing: fail})
		}
	}
	ids, err = m.C.Query(ctx, "TlsExternalReport", nil)
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		var rs []struct {
			ID     string          `json:"id"`
			From   string          `json:"from"`
			To     map[string]bool `json:"to"`
			Report struct {
				Org      string    `json:"organizationName"`
				End      time.Time `json:"dateRangeEnd"`
				Policies map[string]struct {
					Domain string `json:"policyDomain"`
					Failed int    `json:"totalFailedSessions"`
				} `json:"policies"`
			} `json:"report"`
		}
		if err := m.C.Get(ctx, "TlsExternalReport", ids, []string{"id", "from", "to", "report"}, &rs); err != nil {
			return nil, err
		}
		for _, r := range rs {
			per := map[string]bool{}
			for _, p := range r.Report.Policies {
				d := strings.ToLower(p.Domain)
				per[d] = per[d] || p.Failed > 0
			}
			for d, fail := range per {
				out = append(out, Report{Kind: "tls", ID: r.ID, Domain: d, To: lowerSet(r.To),
					Org: strings.ToLower(strings.TrimSpace(r.Report.Org)), From: domainOf(r.From), End: r.Report.End, Failing: fail})
			}
		}
	}
	return out, nil
}

// Accepted are the reports of kind for domain that count: about that
// domain, received at its own report address (dmarc-reports@ /
// tls-reports@), ending no later than now + skew and not before since.
// Every dropped failing report is logged once (reporter and policy
// domain, never the body).
func (m *Machines) Accepted(rs []Report, kind, domain string, since, now time.Time) []Report {
	rua := "dmarc-reports@" + domain
	if kind == "tls" {
		rua = "tls-reports@" + domain
	}
	var out []Report
	for _, r := range rs {
		if r.Kind != kind || r.Domain != domain {
			continue
		}
		why := ""
		switch {
		case !r.To[rua]:
			why = "not sent to " + rua
		case r.End.After(now.Add(skew)):
			why = "dated in the future"
		case r.End.Before(since):
			why = "older than the current policy"
		}
		if why != "" {
			if r.Failing {
				m.logOnce(r, "ignored ("+why+")")
			}
			continue
		}
		if r.Failing {
			m.logOnce(r, "counted")
		}
		out = append(out, r)
	}
	return out
}

func (m *Machines) logOnce(r Report, what string) {
	key := r.Kind + "|" + r.ID + "|" + r.Domain + "|" + what
	m.seenMu.Lock()
	defer m.seenMu.Unlock()
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	if m.seen[key] || m.Logf == nil {
		return
	}
	m.seen[key] = true
	auth := "unauthenticated"
	if r.Authenticated {
		auth = "DKIM " + r.Sender
	}
	m.Logf("reports: a failing %s report for %s from %q (%s, %s) %s", r.Kind, r.Domain, r.Org, r.From, auth, what)
}

// Reporters counts independent reporters among failing, authenticated
// reports: distinct registrable domains of the aligned DKIM signature.
// Unauthenticated reports never count.
func Reporters(rs []Report) int {
	seen := map[string]bool{}
	for _, r := range rs {
		if r.Failing && r.Authenticated && r.Sender != "" {
			seen[r.Sender] = true
		}
	}
	return len(seen)
}

// MinReporters authenticated registrable domains are what holding a
// progression or a doctor Problem needs.
const MinReporters = 2

// inputs: MTA-STS moves back to testing only on local evidence (the
// certificate check), never on reports (ruling); reports from
// MinReporters authenticated reporters only hold testing from becoming
// enforce, which never weakens the current policy.
func (m *Machines) inputs(d state.Domain, rs []Report, now time.Time) mtasts.Inputs {
	cert := func() (bool, bool) {
		if m.CertOK == nil {
			return true, true
		}
		return m.CertOK()
	}
	return mtasts.Inputs{Mail: d.Mail, Reachable: m.Cfg.Reachable, MX: m.Cfg.Hostname,
		Failure: func(time.Time) bool { ok, known := cert(); return known && !ok },
		Blocking: func(since time.Time) bool {
			ok, known := cert()
			return !(ok && known) || Reporters(m.Accepted(rs, "tls", d.Name, since, now)) >= MinReporters
		}}
}

// dmarcReports are what the DMARC machine observes: failing reports hold
// a proposal only when MinReporters authenticated reporters sent them
// (holding a progression never lowers p=; nothing here ever lowers it).
func dmarcReports(rs []Report) []dmarc.Report {
	if Reporters(rs) < MinReporters {
		return nil
	}
	var out []dmarc.Report
	for _, r := range rs {
		if r.Authenticated {
			out = append(out, dmarc.Report{End: r.End, Failing: r.Failing})
		}
	}
	return out
}

// Step is one pass over every domain of the applied document.
func (m *Machines) Step(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.Store.Get()
	doc := p.Doc
	if doc == nil {
		return nil
	}
	now := m.now()
	ids, err := m.domainIDs(ctx)
	if err != nil {
		return err
	}
	reps, rerr := m.reports(ctx)
	ks := read[dkim.State](p, extDKIM)
	sts := read[map[string]mtasts.Domain](p, extMTASTS)
	dms := read[map[string]dmarc.Domain](p, extDMARC)
	if sts == nil {
		sts = map[string]mtasts.Domain{}
	}
	if dms == nil {
		dms = map[string]dmarc.Domain{}
	}
	var errs []error
	if rerr != nil {
		errs = append(errs, rerr)
	}
	for _, d := range doc.Domains {
		if rerr == nil {
			// A failed read never downgrades (no reports = no failures).
			sts[d.Name] = mtasts.Step(sts[d.Name], m.inputs(d, reps, now), now)
		}
		if _, ok := dms[d.Name]; !ok {
			dms[d.Name] = dmarc.Start(d.DMARCStart, now)
		}
		dms[d.Name] = dmarc.Observe(dms[d.Name], dmarcReports(m.Accepted(reps, "dmarc", d.Name, dms[d.Name].Since, now)))
		if d.Mail != state.MailOn || ids[d.Name] == "" {
			continue
		}
		next, acts := dkim.Step(ks, d.Name, now, m.Cfg.RotateEvery, func(n, v string) bool { return m.visible(ctx, n, v) })
		next, err := m.execute(ctx, ks, next, acts, ids[d.Name])
		if err != nil {
			errs = append(errs, fmt.Errorf("dkim %s: %w", d.Name, err))
		}
		ks = next
	}
	// A domain gone from the document keeps its MTA-STS dwell (cached
	// policies name our MX) until it is off.
	listed := map[string]state.Domain{}
	for _, d := range doc.Domains {
		listed[d.Name] = d
	}
	for name := range sts {
		if _, ok := listed[name]; !ok {
			sts[name] = mtasts.Step(sts[name], m.inputs(state.Domain{Name: name, Mail: state.MailOff}, reps, now), now)
		}
	}
	ks, rerrs := m.retireDomains(ctx, doc, ids, ks, sts, listed)
	errs = append(errs, rerrs...)
	if err := m.Store.Update(func(s *state.Persistent) error {
		put(s, extDKIM, ks)
		put(s, extMTASTS, sts)
		put(s, extDMARC, dms)
		return nil
	}); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// retireDomains removes from Stalwart every domain whose mail is off for
// good (final review M4): gone from the document or listed off, and its
// MTA-STS dwell over. Its DKIM signatures are destroyed (Stalwart refuses
// to destroy a Domain that a DkimSignature or an alias links to, so the
// keys go first and an alias left by hand keeps it, with the error), then
// the Domain: is_local_domain is false once it's gone (checked on the
// builder: RCPT turns from 5.1.1 unknown mailbox to 5.7.1 relay), so mail
// from our users goes to the domain's new MX instead of bouncing locally.
// Never the primary domain or the parking domain.
func (m *Machines) retireDomains(ctx context.Context, doc *state.Doc, ids map[string]string, ks dkim.State, sts map[string]mtasts.Domain, listed map[string]state.Domain) (dkim.State, []error) {
	var errs []error
	var gone []string
	for name := range ids {
		d, inDoc := listed[name]
		if name == state.ParkingDomain || name == doc.PrimaryDomain || (inDoc && d.Mail != state.MailOff) {
			continue
		}
		if st, ok := sts[name]; ok && st.Mode != mtasts.Off && st.Mode != "" {
			continue // still dwelling
		}
		gone = append(gone, name)
	}
	if len(gone) == 0 {
		return ks, nil
	}
	sort.Strings(gone)
	var sigs []struct {
		ID       string `json:"id"`
		DomainID string `json:"domainId"`
	}
	sigIDs, err := m.C.Query(ctx, "DkimSignature", nil)
	if err == nil && len(sigIDs) > 0 {
		err = m.C.Get(ctx, "DkimSignature", sigIDs, []string{"id", "domainId"}, &sigs)
	}
	if err != nil {
		return ks, []error{fmt.Errorf("retiring %s: x:DkimSignature: %w", strings.Join(gone, ", "), err)}
	}
	changed := false
	for _, name := range gone {
		id := ids[name]
		var destroy []string
		for _, sg := range sigs {
			if sg.DomainID == id {
				destroy = append(destroy, sg.ID)
			}
		}
		if len(destroy) > 0 {
			r, err := m.C.Set(ctx, "DkimSignature", nil, nil, destroy)
			if err == nil {
				err = r.Failed()
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("retiring %s: its DKIM keys: %w", name, err))
				continue
			}
			changed = true
		}
		// The keys are retired: out of the state (no record, no rotation).
		var keep []dkim.Key
		for _, k := range ks.Keys {
			if k.Domain != name {
				keep = append(keep, k)
			}
		}
		ks.Keys = keep
		delete(ks.RotateNow, name)
		r, err := m.C.Set(ctx, "Domain", nil, nil, []string{id})
		if err == nil {
			err = r.Failed()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("retiring %s: x:Domain: %w", name, err))
			continue
		}
		changed = true
		if _, inDoc := listed[name]; !inDoc {
			delete(sts, name)
		}
		if m.Logf != nil {
			m.Logf("machines: %s: mail is off: the domain and its DKIM keys are removed from Stalwart", name)
		}
	}
	if changed {
		if err := m.C.Action(ctx, "InvalidateCaches"); err != nil {
			errs = append(errs, fmt.Errorf("InvalidateCaches: %w", err))
		}
	}
	return ks, errs
}

// execute runs the DKIM actions. A failed create leaves its key without
// an ID (retried next pass). Stage changes go in one unit per algorithm
// (the old active's retiring and the pending key's active together): if
// any of them fails, the ones that went through are put back in Stalwart
// and every key of the unit keeps its previous stage and since in the
// returned state, so the next pass tries again.
func (m *Machines) execute(ctx context.Context, prev, next dkim.State, acts []dkim.Action, domainID string) (dkim.State, error) {
	var errs []error
	prevKey := map[string]dkim.Key{}
	for _, k := range prev.Keys {
		if k.ID != "" {
			prevKey[k.ID] = k
		}
	}
	algoOf := func(id string) string {
		for _, k := range next.Keys {
			if k.ID == id {
				return k.Algorithm
			}
		}
		return prevKey[id].Algorithm
	}
	units := map[string][]dkim.Action{}
	var order []string
	for _, a := range acts {
		switch a.Kind {
		case "create":
			id, pub, err := m.create(ctx, a.Key, domainID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for i := range next.Keys {
				if next.Keys[i].Domain == a.Key.Domain && next.Keys[i].Selector == a.Key.Selector {
					next.Keys[i].ID, next.Keys[i].PublicKey = id, pub
				}
			}
		case "stage":
			if a.ID == "" {
				continue
			}
			al := algoOf(a.ID)
			if _, ok := units[al]; !ok {
				order = append(order, al)
			}
			units[al] = append(units[al], a)
		case "destroy":
			r, err := m.C.Set(ctx, "DkimSignature", nil, nil, []string{a.ID})
			if err == nil {
				err = r.Failed()
			}
			if err != nil {
				errs = append(errs, err)
				// Keep the retired key: destroyed next pass.
				if k, ok := prevKey[a.ID]; ok {
					next.Keys = append(next.Keys, k)
				}
			}
		}
	}
	staged := false
	for _, al := range order {
		unit := units[al]
		update := map[string]map[string]any{}
		for _, a := range unit {
			update[a.ID] = map[string]any{"stage": a.Stage}
		}
		r, err := m.C.Set(ctx, "DkimSignature", nil, update, nil)
		if err == nil {
			err = r.Failed()
		}
		if err == nil {
			staged = true
			continue
		}
		errs = append(errs, fmt.Errorf("dkim %s stage change (rolled back): %w", al, err))
		// Put back what went through (r.Updated), then the state.
		undo := map[string]map[string]any{}
		for id := range r.Updated {
			if k, ok := prevKey[id]; ok {
				undo[id] = map[string]any{"stage": k.Stage}
			}
		}
		if len(undo) > 0 {
			ur, uerr := m.C.Set(ctx, "DkimSignature", nil, undo, nil)
			if uerr == nil {
				uerr = ur.Failed()
			}
			if uerr != nil {
				errs = append(errs, fmt.Errorf("dkim %s: putting the stage back: %w", al, uerr))
			}
			staged = true
		}
		for _, a := range unit {
			for i := range next.Keys {
				if next.Keys[i].ID == a.ID {
					if k, ok := prevKey[a.ID]; ok {
						next.Keys[i].Stage, next.Keys[i].Since = k.Stage, k.Since
					}
				}
			}
		}
	}
	if staged {
		// Signers are cached (P55): every stage change is followed by it.
		if err := m.C.Action(ctx, "InvalidateCaches"); err != nil {
			errs = append(errs, err)
		}
	}
	return next, errors.Join(errs...)
}

// create makes one key in Stalwart: generated here, signed and verified
// in-process while the private half is still in memory (P2), sent once,
// and Stalwart's derived publicKey checked against it.
func (m *Machines) create(ctx context.Context, k dkim.Key, domainID string) (string, string, error) {
	pemKey, pubs, err := dkim.Generate(k.Algorithm)
	if err != nil {
		return "", "", err
	}
	if err := dkim.SelfTest(pemKey, k.Algorithm, pubs[0]); err != nil {
		return "", "", fmt.Errorf("dkim %s: the new key fails its own signature test: %w", k.Selector, err)
	}
	r, err := m.C.Set(ctx, "DkimSignature", map[string]any{"k": map[string]any{
		"@type": dkim.Variant(k.Algorithm), "domainId": domainID, "selector": k.Selector,
		"stage": dkim.Pending, "privateKey": map[string]any{"@type": "Text", "secret": pemKey},
	}}, nil, nil)
	pemKey = ""
	if err == nil {
		err = r.Failed()
	}
	if err != nil {
		return "", "", err
	}
	id := r.CreatedID("k")
	var got []struct {
		PublicKey string `json:"publicKey"`
	}
	if err := m.C.Get(ctx, "DkimSignature", []string{id}, []string{"publicKey"}, &got); err != nil || len(got) != 1 {
		return "", "", fmt.Errorf("reading the new key's publicKey: %v", err)
	}
	if !slices.Contains(pubs, got[0].PublicKey) {
		return "", "", fmt.Errorf("Stalwart's publicKey for %s isn't the generated key's", k.Selector)
	}
	return id, got[0].PublicKey, nil
}

// mainSecure is the main zone's DNSSEC state: the newest mailctl holds
// (mailctl rotate's, within 48 h, else the document's).
func (m *Machines) mainState(p state.Persistent) string {
	r := read[dnssecRec](p, extDNSSEC)
	if r.State != "" && m.now().Sub(r.At) < 48*time.Hour {
		return r.State
	}
	if p.Doc != nil {
		for _, d := range p.Doc.Domains {
			if d.Name == m.Cfg.MainDomain {
				return d.DNSSEC
			}
		}
	}
	return "unknown"
}

// DNSSet is GET /v1/dns/{domain}.
type DNSSet struct {
	Domain  string          `json:"domain"`
	Records []dnsset.Record `json:"records"`
	DKIM    string          `json:"dkim"`
	TLSA    string          `json:"tlsa"`
}

// DNSHashes is MailStatus.dns: every mail domain of the document (the
// main one included) → sha256 of the canonical record set Set serves at
// /v1/dns/<domain> (records sorted by name, type, value, TTL). It changes
// whenever the set does (a key made or moving stage, the MTA-STS id, a
// DMARC step, the TLSA …): the Hub rewrites an added domain's set then.
// Cached per state revision and the main zone's DNSSEC state (the one
// input Set reads besides the state: its 48 h freshness).
func (m *Machines) DNSHashes() map[string]string {
	p, rev := m.Store.GetRev()
	out := map[string]string{}
	if p.Doc == nil {
		return out
	}
	key := fmt.Sprintf("%d|%s", rev, m.mainState(p))
	m.hashMu.Lock()
	defer m.hashMu.Unlock()
	if m.hashes != nil && m.hashKey == key {
		return maps.Clone(m.hashes)
	}
	for _, d := range p.Doc.Domains {
		set, err := m.Set(d.Name)
		if err != nil {
			continue
		}
		out[d.Name] = setHash(set.Records)
	}
	m.hashKey, m.hashes = key, out
	return maps.Clone(out)
}

// setHash: sha256 hex of the records in canonical order.
func setHash(recs []dnsset.Record) string {
	rs := append([]dnsset.Record(nil), recs...)
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		return a.TTL < b.TTL
	})
	b, _ := json.Marshal(rs)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Set renders one domain's wanted mail set (an added domain with its
// wildcard address record).
func (m *Machines) Set(domain string) (DNSSet, error) { return m.SetFor(domain, false) }

// SetFor renders it; noWildcard: an added domain's plan has no *.<e>
// address record (the CNAMEs).
func (m *Machines) SetFor(domain string, noWildcard bool) (DNSSet, error) {
	p := m.Store.Get()
	if p.Doc == nil {
		return DNSSet{}, ErrNotMailDomain
	}
	var dom *state.Domain
	for i := range p.Doc.Domains {
		if p.Doc.Domains[i].Name == domain {
			dom = &p.Doc.Domains[i]
		}
	}
	if dom == nil {
		return DNSSet{}, ErrNotMailDomain
	}
	ks := read[dkim.State](p, extDKIM)
	sts := read[map[string]mtasts.Domain](p, extMTASTS)
	dms := read[map[string]dmarc.Domain](p, extDMARC)
	main := domain == m.Cfg.MainDomain
	in := dnsset.Input{Domain: domain, Main: main, Hostname: m.Cfg.Hostname, SPFInclude: m.Cfg.SPFInclude, Mail: dom.Mail,
		DMARC: dms[domain].Policy, MTASTSID: sts[domain].ID, NoWildcard: noWildcard}
	if in.DMARC == "" {
		in.DMARC = dmarc.Start(dom.DMARCStart, m.now()).Policy
	}
	for _, k := range dkim.Published(ks, domain) {
		in.DKIM = append(in.DKIM, dnsset.DKIMRecord{Selector: k.Selector, Value: dkim.TXT(k)})
	}
	out := DNSSet{Domain: domain, DKIM: "auto", TLSA: "withheld: not the mail host's zone"}
	if main {
		st := m.mainState(p)
		if st == "secure" {
			in.TLSA = tlsa.Wanted(state.TLSA(p), true)
			out.TLSA = "published"
			if len(in.TLSA) == 0 {
				out.TLSA = "withheld: the mail certificate's key isn't known yet"
			}
		} else {
			out.TLSA = "withheld: dnssec " + st
		}
	}
	out.Records = dnsset.Wanted(in)
	if out.Records == nil {
		out.Records = []dnsset.Record{}
	}
	return out, nil
}

// RotateIn is `mailctl rotate --json`'s stdin.
type RotateIn struct {
	DNSSECState string `json:"dnssec_state"`
	SPKI        struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	} `json:"spki"`
}

// RotateOut is its answer: the main domain's set and the mail-cert steps due.
type RotateOut struct {
	DNSSet
	NextKey   bool `json:"next_key"`
	SwitchKey bool `json:"switch_key"`
}

// Rotate is the daily timer's step.
func (m *Machines) Rotate(ctx context.Context, in RotateIn) (RotateOut, error) {
	now := m.now()
	var sw bool
	if err := m.Store.Update(func(s *state.Persistent) error {
		ts, switchKey := tlsa.Update(state.TLSA(*s), strings.ToLower(in.SPKI.Current), strings.ToLower(in.SPKI.Next), now)
		sw = switchKey
		put(s, extTLSA, ts)
		if in.DNSSECState != "" {
			put(s, extDNSSEC, dnssecRec{State: in.DNSSECState, At: now})
		}
		s.TimerSeenAt = &now
		return nil
	}); err != nil {
		return RotateOut{}, err
	}
	err := m.Step(ctx)
	set, serr := m.Set(m.Cfg.MainDomain)
	if serr != nil {
		return RotateOut{}, errors.Join(err, serr)
	}
	return RotateOut{DNSSet: set, SwitchKey: sw}, err
}

// RecordKey records the mail certificate's current SPKI only (`mailctl
// tls-key`: mail enable, before the Hub's first document — Rotate needs
// one for the main domain's set). The same TLSA update as Rotate's with
// no next key; nothing else (no pass, not the timer's visit).
func (m *Machines) RecordKey(current string) error {
	now := m.now()
	return m.Store.Update(func(s *state.Persistent) error {
		ts, _ := tlsa.Update(state.TLSA(*s), strings.ToLower(current), "", now)
		put(s, extTLSA, ts)
		return nil
	})
}

// DKIMRotate is the dkim-rotate action.
func (m *Machines) DKIMRotate(ctx context.Context, domain string) error {
	m.mu.Lock() // Step rewrites these records: no action in between
	defer m.mu.Unlock()
	if !m.mailOn(domain) {
		return ErrNotMailDomain
	}
	if err := m.Store.Update(func(s *state.Persistent) error {
		ks := read[dkim.State](*s, extDKIM)
		if ks.RotateNow == nil {
			ks.RotateNow = map[string]bool{}
		}
		for _, k := range ks.Keys {
			if k.Domain == domain && k.Stage == dkim.Pending {
				return ErrNothingToDo{"a DKIM rotation is already running (a key is pending)"}
			}
		}
		ks.RotateNow[domain] = true
		put(s, extDKIM, ks)
		return nil
	}); err != nil {
		return err
	}
	m.Trigger()
	return nil
}

func (m *Machines) mailOn(domain string) bool {
	p := m.Store.Get()
	if p.Doc == nil {
		return false
	}
	for _, d := range p.Doc.Domains {
		if d.Name == domain {
			return d.Mail != state.MailOff
		}
	}
	return false
}

// DMARCPromote applies the proposal.
func (m *Machines) DMARCPromote(domain string) error {
	m.mu.Lock() // Step rewrites these records: no action in between
	defer m.mu.Unlock()
	if !m.mailOn(domain) {
		return ErrNotMailDomain
	}
	return m.Store.Update(func(s *state.Persistent) error {
		dms := read[map[string]dmarc.Domain](*s, extDMARC)
		d, err := dmarc.Promote(dms[domain], m.now())
		if err != nil {
			return ErrNothingToDo{err.Error()}
		}
		dms[domain] = d
		put(s, extDMARC, dms)
		return nil
	})
}

// MTASTSEnforce applies mtasts-enforce when the conditions hold.
func (m *Machines) MTASTSEnforce(ctx context.Context, domain string) error {
	m.mu.Lock() // Step rewrites these records: no action in between
	defer m.mu.Unlock()
	if !m.mailOn(domain) {
		return ErrNotMailDomain
	}
	reps, err := m.reports(ctx)
	if err != nil {
		return err
	}
	p := m.Store.Get()
	var dom state.Domain
	for _, d := range p.Doc.Domains {
		if d.Name == domain {
			dom = d
		}
	}
	return m.Store.Update(func(s *state.Persistent) error {
		sts := read[map[string]mtasts.Domain](*s, extMTASTS)
		d, err := mtasts.DoEnforce(sts[domain], m.inputs(dom, reps, m.now()), m.now())
		if err != nil {
			return ErrNothingToDo{err.Error()}
		}
		sts[domain] = d
		put(s, extMTASTS, sts)
		return nil
	})
}

// Status parts the machines own (MailStatus, contract §19.5).
type DKIMStatus struct {
	Domain    string    `json:"domain"`
	Algorithm string    `json:"algorithm"`
	Selector  string    `json:"selector"`
	Stage     string    `json:"stage"`
	Since     time.Time `json:"since"`
}

// MTASTSStatus is one domain's MTA-STS.
type MTASTSStatus struct {
	Domain       string    `json:"domain"`
	Mode         string    `json:"mode"`
	Since        time.Time `json:"since"`
	EnforceReady bool      `json:"enforce_ready"`
}

// DMARCStatus is one domain's DMARC.
type DMARCStatus struct {
	Domain   string    `json:"domain"`
	Policy   string    `json:"policy"`
	Since    time.Time `json:"since"`
	Proposed *string   `json:"proposed"`
}

// Statuses are the machines' MailStatus lists.
func (m *Machines) Statuses(ctx context.Context) ([]DKIMStatus, []MTASTSStatus, []DMARCStatus) {
	p := m.Store.Get()
	ks := read[dkim.State](p, extDKIM)
	sts := read[map[string]mtasts.Domain](p, extMTASTS)
	dms := read[map[string]dmarc.Domain](p, extDMARC)
	dk := []DKIMStatus{}
	for _, k := range ks.Keys {
		dk = append(dk, DKIMStatus{Domain: k.Domain, Algorithm: k.Algorithm, Selector: k.Selector, Stage: k.Stage, Since: k.Since})
	}
	ms, ds := []MTASTSStatus{}, []DMARCStatus{}
	if p.Doc != nil {
		reps, _ := m.cachedReports(ctx)
		for _, d := range p.Doc.Domains {
			st := sts[d.Name]
			mode := st.Mode
			if mode == "" {
				mode = mtasts.Off
			}
			ms = append(ms, MTASTSStatus{Domain: d.Name, Mode: mode, Since: st.Since,
				EnforceReady: mtasts.EnforceReady(st, m.inputs(d, reps, m.now()), m.now()) == nil})
			dm := dms[d.Name]
			var prop *string
			if pp := dmarc.Proposed(dm, m.now()); pp != "" {
				prop = &pp
			}
			ds = append(ds, DMARCStatus{Domain: d.Name, Policy: dm.Policy, Since: dm.Since, Proposed: prop})
		}
	}
	sort.Slice(dk, func(i, j int) bool { return dk[i].Domain+dk[i].Selector < dk[j].Domain+dk[j].Selector })
	return dk, ms, ds
}

// Source for the well-known handler.
func (m *Machines) MailDomain(domain string) bool { return m.mailOn(domain) }

// Policy is the served MTA-STS policy ("" = none).
func (m *Machines) Policy(domain string) string {
	if !m.Cfg.Reachable {
		return ""
	}
	return read[map[string]mtasts.Domain](m.Store.Get(), extMTASTS)[domain].Policy
}

// Hostname is MAIL_HOSTNAME.
func (m *Machines) Hostname() string { return m.Cfg.Hostname }

func init() {
	for _, u := range []stalwart.Use{
		{Object: "x:DkimSignature", Variant: "Dkim1Ed25519Sha256", Field: "selector"},
		{Object: "x:DkimSignature", Variant: "Dkim1RsaSha256", Field: "selector"},
		{Object: "x:DkimSignature", Field: "domainId"}, {Object: "x:DkimSignature", Field: "stage"},
		{Object: "x:DkimSignature", Field: "privateKey"}, {Object: "x:DkimSignature", Field: "publicKey"},
		{Object: "x:SecretText", Variant: "Text", Field: "secret"},
		{Enum: "DkimRotationStage", Value: "pending"}, {Enum: "DkimRotationStage", Value: "active"},
		{Enum: "DkimRotationStage", Value: "retiring"}, {Enum: "DkimRotationStage", Value: "retired"},
		{Object: "x:DmarcExternalReport", Field: "report"}, {Object: "x:DmarcReport", Field: "policyDomain"},
		{Object: "x:DmarcReport", Field: "dateRangeEnd"}, {Object: "x:DmarcReport", Field: "records"},
		{Object: "x:DmarcReportRecord", Field: "evaluatedDkim"}, {Object: "x:DmarcReportRecord", Field: "evaluatedSpf"},
		{Object: "x:TlsExternalReport", Field: "report"}, {Object: "x:TlsReport", Field: "policies"},
		{Object: "x:TlsReport", Field: "dateRangeEnd"}, {Object: "x:TlsReportPolicy", Field: "policyDomain"},
		{Object: "x:TlsReportPolicy", Field: "totalFailedSessions"},
	} {
		stalwart.Used = append(stalwart.Used, u)
	}
}

// Reports reads every aggregate report Stalwart holds (the checks).
func (m *Machines) Reports(ctx context.Context) ([]Report, error) { return m.cachedReports(ctx) }

// Keys are every domain's DKIM keys as the state holds them.
func (m *Machines) Keys() []dkim.Key { return read[dkim.State](m.Store.Get(), extDKIM).Keys }

// TLSAWanted are the SPKIs published at _25._tcp.<MAIL_HOSTNAME> right now
// (none unless the main zone is secure).
func (m *Machines) TLSAWanted() []string {
	p := m.Store.Get()
	return tlsa.Wanted(state.TLSA(p), m.mainState(p) == "secure")
}
