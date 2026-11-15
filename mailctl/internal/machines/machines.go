// Package machines drives the per-domain state machines (DKIM, MTA-STS,
// DMARC) and the main host's TLSA from the applied document, renders each
// domain's wanted mail set (dnsset), and answers status, the well-known
// files and the actions (contract §19.5, §19.7). State lives in
// state.json's ext.
package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	// CertOK: the certificate check (Task 9's checks; nil = ok).
	CertOK func() bool

	mu   sync.Mutex
	wake chan struct{}
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

// tlsFailures: aggregate TLS reports for the domain with failed sessions,
// by their end time.
func (m *Machines) reports(ctx context.Context) (dm map[string][]dmarc.Report, tl map[string][]time.Time, err error) {
	dm, tl = map[string][]dmarc.Report{}, map[string][]time.Time{}
	ids, err := m.C.Query(ctx, "DmarcExternalReport", nil)
	if err != nil {
		return nil, nil, err
	}
	if len(ids) > 0 {
		var rs []struct {
			Report struct {
				PolicyDomain string    `json:"policyDomain"`
				End          time.Time `json:"dateRangeEnd"`
				Records      map[string]struct {
					Dkim string `json:"evaluatedDkim"`
					Spf  string `json:"evaluatedSpf"`
				} `json:"records"`
			} `json:"report"`
		}
		if err := m.C.Get(ctx, "DmarcExternalReport", ids, []string{"report"}, &rs); err != nil {
			return nil, nil, err
		}
		for _, r := range rs {
			fail := false
			for _, rec := range r.Report.Records {
				if rec.Dkim != "pass" && rec.Spf != "pass" {
					fail = true
				}
			}
			d := strings.ToLower(r.Report.PolicyDomain)
			dm[d] = append(dm[d], dmarc.Report{End: r.Report.End, Failing: fail})
		}
	}
	ids, err = m.C.Query(ctx, "TlsExternalReport", nil)
	if err != nil {
		return nil, nil, err
	}
	if len(ids) > 0 {
		var rs []struct {
			Report struct {
				End      time.Time `json:"dateRangeEnd"`
				Policies map[string]struct {
					Domain string `json:"policyDomain"`
					Failed int    `json:"totalFailedSessions"`
				} `json:"policies"`
			} `json:"report"`
		}
		if err := m.C.Get(ctx, "TlsExternalReport", ids, []string{"report"}, &rs); err != nil {
			return nil, nil, err
		}
		for _, r := range rs {
			for _, p := range r.Report.Policies {
				if p.Failed > 0 {
					d := strings.ToLower(p.Domain)
					tl[d] = append(tl[d], r.Report.End)
				}
			}
		}
	}
	return dm, tl, nil
}

func (m *Machines) failure(tl map[string][]time.Time, domain string) func(time.Time) bool {
	return func(since time.Time) bool {
		if m.CertOK != nil && !m.CertOK() {
			return true
		}
		for _, t := range tl[domain] {
			if t.After(since) {
				return true
			}
		}
		return false
	}
}

func (m *Machines) inputs(d state.Domain, tl map[string][]time.Time) mtasts.Inputs {
	return mtasts.Inputs{Mail: d.Mail, Reachable: m.Cfg.Reachable, MX: m.Cfg.Hostname, Failure: m.failure(tl, d.Name)}
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
	dmRep, tlRep, rerr := m.reports(ctx)
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
		sts[d.Name] = mtasts.Step(sts[d.Name], m.inputs(d, tlRep), now)
		if _, ok := dms[d.Name]; !ok {
			dms[d.Name] = dmarc.Start(d.DMARCStart, now)
		}
		dms[d.Name] = dmarc.Observe(dms[d.Name], dmRep[d.Name])
		if d.Mail != state.MailOn || ids[d.Name] == "" {
			continue
		}
		next, acts := dkim.Step(ks, d.Name, now, m.Cfg.RotateEvery, func(n, v string) bool { return m.visible(ctx, n, v) })
		next, err := m.execute(ctx, next, acts, ids[d.Name])
		if err != nil {
			errs = append(errs, fmt.Errorf("dkim %s: %w", d.Name, err))
		}
		ks = next
	}
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

// execute runs the DKIM actions; a failed create leaves its key without
// an ID (retried next pass), a failed stage change keeps the old stage.
func (m *Machines) execute(ctx context.Context, next dkim.State, acts []dkim.Action, domainID string) (dkim.State, error) {
	var errs []error
	staged := false
	for _, a := range acts {
		switch a.Kind {
		case "create":
			pemKey, pubs, err := dkim.Generate(a.Key.Algorithm)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			r, err := m.C.Set(ctx, "DkimSignature", map[string]any{"k": map[string]any{
				"@type": dkim.Variant(a.Key.Algorithm), "domainId": domainID, "selector": a.Key.Selector,
				"stage": dkim.Pending, "privateKey": map[string]any{"@type": "Text", "secret": pemKey},
			}}, nil, nil)
			pemKey = ""
			if err == nil {
				err = r.Failed()
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			id := r.CreatedID("k")
			var got []struct {
				PublicKey string `json:"publicKey"`
			}
			if err := m.C.Get(ctx, "DkimSignature", []string{id}, []string{"publicKey"}, &got); err != nil || len(got) != 1 {
				errs = append(errs, fmt.Errorf("reading the new key's publicKey: %v", err))
				continue
			}
			if !slices.Contains(pubs, got[0].PublicKey) {
				errs = append(errs, fmt.Errorf("Stalwart's publicKey for %s isn't the generated key's", a.Key.Selector))
				continue
			}
			for i := range next.Keys {
				if next.Keys[i].Domain == a.Key.Domain && next.Keys[i].Selector == a.Key.Selector {
					next.Keys[i].ID, next.Keys[i].PublicKey = id, got[0].PublicKey
				}
			}
		case "stage":
			r, err := m.C.Set(ctx, "DkimSignature", nil, map[string]map[string]any{a.ID: {"stage": a.Stage}}, nil)
			if err == nil {
				err = r.Failed()
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
			staged = true
		case "destroy":
			r, err := m.C.Set(ctx, "DkimSignature", nil, nil, []string{a.ID})
			if err == nil {
				err = r.Failed()
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if staged {
		// Signers are cached (P55): harmless, and the contract's rule.
		if err := m.C.Action(ctx, "InvalidateCaches"); err != nil {
			errs = append(errs, err)
		}
	}
	return next, errors.Join(errs...)
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
	_, tl, err := m.reports(ctx)
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
		d, err := mtasts.DoEnforce(sts[domain], m.inputs(dom, tl), m.now())
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
		_, tl, _ := m.reports(ctx)
		for _, d := range p.Doc.Domains {
			st := sts[d.Name]
			mode := st.Mode
			if mode == "" {
				mode = mtasts.Off
			}
			ms = append(ms, MTASTSStatus{Domain: d.Name, Mode: mode, Since: st.Since,
				EnforceReady: mtasts.EnforceReady(st, m.inputs(d, tl), m.now()) == nil})
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
