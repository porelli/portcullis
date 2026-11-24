package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/creds"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// SMTPPort is the MX listener (submission is every other SMTP listener).
const SMTPPort = 10025

// Runner applies the accepted document: at once on every new one, every
// 5 s while something failed (a removal is retried until it is done), and
// every minute otherwise (drift).
//
// LAN-only (submission_lan_only), the client address mode (client_ip:
// rewritten = the Local networks can't be told apart, so LAN-only admits
// loopback only, fail closed) and former_retention are the accepted
// document's (MailState v2), never the environment's.
type Runner struct {
	C     *stalwart.Client
	Store *state.Store
	// MailctlIP: mailctl's portcullis-mail address (an export password is
	// pinned to it).
	MailctlIP netip.Addr
	// DQSKeyFile: the Spamhaus DQS key (Settings).
	DQSKeyFile string
	Now        func() time.Time
	Logf       func(string, ...any)
	// OnApplied: called after a pass applied a new generation (mailctl
	// wakes its machines: a new domain's DKIM keys at once).
	OnApplied func()
	wake      chan struct{}
	// pass serialises a whole pass with the API's credential creates
	// (LockPass): a create never lands on an account a pass is parking.
	pass sync.Mutex
}

// LockPass / UnlockPass: held by the API from its snapshot to the
// password's create (final review M2).
func (r *Runner) LockPass()   { r.pass.Lock() }
func (r *Runner) UnlockPass() { r.pass.Unlock() }

// NewRunner returns a runner.
func NewRunner(c *stalwart.Client, st *state.Store, logf func(string, ...any)) *Runner {
	return &Runner{C: c, Store: st, Now: time.Now, Logf: logf, wake: make(chan struct{}, 1)}
}

// Trigger asks for a pass now.
func (r *Runner) Trigger() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run loops until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	for {
		err := r.Once(ctx)
		wait := time.Minute
		if err != nil {
			wait = 5 * time.Second
			if r.Logf != nil {
				r.Logf("reconcile: %v (retrying in 5 s)", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-time.After(wait):
		}
	}
}

// SASLExpression is MtaStageAuth.saslMechanisms: PLAIN and LOGIN over TLS
// on the submission listeners, and with LAN-only only from the networks
// (defence in depth next to every mail password's allowedIps).
func SASLExpression(lanOnly bool, local []string) map[string]any {
	return creds.SASLExpression(lanOnly, local, SMTPPort)
}

// sameJSON: raw (Stalwart's answer) and v encode the same value.
func sameJSON(raw json.RawMessage, v any) bool {
	var a, b any
	wb, _ := json.Marshal(v)
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal(wb, &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// Once is one pass.
func (r *Runner) Once(ctx context.Context) error {
	r.pass.Lock()
	defer r.pass.Unlock()
	p := r.Store.Get()
	if p.Doc == nil {
		return nil
	}
	err := r.once(ctx, p)
	msg := []string{}
	if err != nil {
		msg = []string{logx.Redact(err.Error())}
	}
	gen := p.Doc.Generation
	applied := false
	if uerr := r.Store.Update(func(s *state.Persistent) error {
		s.Errors = msg
		if err == nil && s.Doc != nil && s.Doc.Generation == gen {
			applied = s.AppliedGeneration != gen
			s.AppliedGeneration = gen
		}
		return nil
	}); uerr != nil && err == nil {
		err = uerr
	} else if uerr == nil && applied && r.OnApplied != nil {
		r.OnApplied()
	}
	return err
}

func (r *Runner) once(ctx context.Context, p state.Persistent) error {
	doc := p.Doc
	l, readErr := Read(ctx, r.C)
	// LAN-only first, on its own path: a failing plan never skips it.
	lanErr := r.lanOnly(ctx, l, doc, p)
	// Spam scores, DNSBLs, allow / block, outbound limits: on their own
	// path too.
	setErr := Settings(ctx, r.C, doc, SettingsOpts{Rewritten: doc.Rewritten(), DQSKeyFile: r.DQSKeyFile})
	// The host name, the relay and degraded mode (MailState v2's part of
	// the base plan): their own path too.
	_, baseErr := bootstrap.ApplyDoc(ctx, r.C, doc)
	if readErr != nil {
		return errors.Join(readErr, lanErr, setErr, baseErr)
	}
	return errors.Join(r.apply(ctx, l, doc, p), lanErr, setErr, baseErr)
}

func (r *Runner) apply(ctx context.Context, l *Live, doc *state.Doc, p state.Persistent) error {
	exporting, sweepErr := SweepParked(ctx, r.C, l, r.Now(), r.Store.Dir(), r.MailctlIP)
	ops, err := Plan(l, doc, p.Former, r.Now(), state.Period(doc.FormerRetention), p.MassRemoval)
	// An export under way (its password not expired yet) keeps its lift
	// until it ends (final review L8); the export's own defer re-locks,
	// and so does this pass once the password expired.
	var redisable []string
	for _, id := range ops.Redisable {
		if !exporting[id] {
			redisable = append(redisable, id)
		}
	}
	ops.Redisable = redisable
	// A failed sweep never skips the rest of the pass (an account whose
	// passwords couldn't be read counts as not exporting: re-disabled).
	applyErr := r.applyOps(ctx, l, doc, ops, err)
	// The senders (contract §19.14) on their own path: excluded from the
	// mass-removal rule, so a refused removal of people (or any other
	// failure above) never holds them back.
	senderErr := ApplySenders(ctx, r.C, l, doc, PlanSenders(l, doc))
	return errors.Join(sweepErr, applyErr, senderErr)
}

func (r *Runner) applyOps(ctx context.Context, l *Live, doc *state.Doc, ops Ops, err error) error {
	if errors.Is(err, ErrMassRemoval) && len(ops.Redisable) > 0 {
		// A pending mass removal never keeps a parked account lifted.
		if rerr := Apply(ctx, r.C, l, doc, Ops{Redisable: ops.Redisable}, nil); rerr != nil {
			return errors.Join(err, rerr)
		}
	}
	if err != nil {
		return err
	}
	if !ops.Empty {
		err = Apply(ctx, r.C, l, doc, ops, func(uuid, username string) error {
			return r.Store.Update(func(s *state.Persistent) error {
				if _, ok := s.Former[uuid]; !ok {
					s.Former[uuid] = state.Former{Username: username, Since: r.Now().UTC()}
				}
				return nil
			})
		})
		if err != nil {
			return err
		}
	}
	// Former records: purged ones go, rejoined ones go.
	active := map[string]bool{}
	for _, a := range doc.Accounts {
		active[a.UUID] = true
	}
	return r.Store.Update(func(s *state.Persistent) error {
		for _, u := range ops.PurgedUUIDs {
			delete(s.Former, u)
		}
		for u := range s.Former {
			if active[u] {
				delete(s.Former, u)
			}
		}
		return nil
	})
}

// SweepParked reads every parked account's app passwords (final review
// M5). A password counts as an export under way only when mailctl itself
// recorded it (state.Exports: this account, this password id, not
// expired), its allowedIps is exactly mailctl's /32 and its permissions
// are exactly stalwart.ExportPermissions; its account id is in the
// answer. Every other password of a parked account (a parked account has
// none; a look-alike's description and expiry prove nothing) is
// destroyed. Records whose password is gone or expired are removed.
func SweepParked(ctx context.Context, c *stalwart.Client, l *Live, now time.Time, dataDir string, mailctlIP netip.Addr) (map[string]bool, error) {
	exporting := map[string]bool{}
	recs, err := state.Exports(dataDir)
	if err != nil {
		recs = map[string]state.ExportRecord{} // fail closed: nothing spared
	}
	errs := []error{err}
	want := map[string]bool{}
	for _, p := range stalwart.ExportPermissions {
		want[p] = true
	}
	alive := map[string]bool{}
	for _, la := range l.Accounts {
		if !la.Parked(l) {
			continue
		}
		ac := c.As(la.ID)
		ids, err := ac.Query(ctx, "AppPassword", nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("x:AppPassword/query: %w", err))
			continue
		}
		if len(ids) == 0 {
			continue
		}
		var ps []struct {
			ID          string          `json:"id"`
			AllowedIPs  map[string]bool `json:"allowedIps"`
			Permissions struct {
				Type        string          `json:"@type"`
				Permissions map[string]bool `json:"permissions"`
			} `json:"permissions"`
		}
		if err := ac.Get(ctx, "AppPassword", ids, []string{"id", "allowedIps", "permissions"}, &ps); err != nil {
			errs = append(errs, fmt.Errorf("x:AppPassword/get: %w", err))
			continue
		}
		var gone []string
		for _, p := range ps {
			rec, ok := recs[p.ID]
			if ok && rec.AccountID == la.ID && now.Before(rec.ExpiresAt) && pinnedTo(p.AllowedIPs, mailctlIP) &&
				p.Permissions.Type == "Replace" && sameSet(p.Permissions.Permissions, want) {
				exporting[la.ID] = true
				alive[p.ID] = true
				continue
			}
			gone = append(gone, p.ID)
		}
		if len(gone) > 0 {
			res, err := ac.Set(ctx, "AppPassword", nil, nil, gone)
			if err := setErr("AppPassword", res, err); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for id := range recs {
		if !alive[id] {
			if err := state.RemoveExport(dataDir, id); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return exporting, errors.Join(errs...)
}

// pinnedTo: allowedIps is exactly ip (Stalwart answers a /32 as the bare
// address: checked on the builder).
func pinnedTo(ips map[string]bool, ip netip.Addr) bool {
	if !ip.IsValid() || len(ips) != 1 {
		return false
	}
	for k, v := range ips {
		if !v {
			return false
		}
		if a, err := netip.ParseAddr(k); err == nil {
			return a == ip
		}
		p, err := netip.ParsePrefix(k)
		return err == nil && p.Bits() == ip.BitLen() && p.Addr() == ip
	}
	return false
}

// sameSet: got's true keys are exactly want's.
func sameSet(got, want map[string]bool) bool {
	n := 0
	for k, v := range got {
		if !v || !want[k] {
			return false
		}
		n++
	}
	return n == len(want)
}

// ExportDescription / ExportLifetime: the export's password (mailctl
// export): its description and the most it lives.
const (
	ExportDescription = "portcullis export"
	ExportLifetime    = time.Hour
)

// LocalNets are the networks LAN-only admits: the document's, or none at
// all (= loopback only) when client addresses are rewritten.
func LocalNets(doc *state.Doc, rewritten bool) []string {
	if rewritten || doc == nil {
		return nil
	}
	return doc.LocalNetworks
}

// lanOnly keeps the SASL rule and every mail password's allowedIps on the
// Local networks while the document's submission_lan_only is on.
func (r *Runner) lanOnly(ctx context.Context, l *Live, doc *state.Doc, p state.Persistent) error {
	// The live rule, every pass (a bootstrap run, a hand edit): never a
	// cached copy of what was written.
	lan := doc.SubmissionLANOnly
	expr := SASLExpression(lan, LocalNets(doc, doc.Rewritten()))
	var live []struct {
		SASL json.RawMessage `json:"saslMechanisms"`
	}
	if err := r.C.Get(ctx, "MtaStageAuth", []string{"singleton"}, []string{"saslMechanisms"}, &live); err != nil {
		return fmt.Errorf("x:MtaStageAuth/get: %w", err)
	}
	if len(live) != 1 || !sameJSON(live[0].SASL, expr) {
		res, err := r.C.Set(ctx, "MtaStageAuth", nil, map[string]map[string]any{"singleton": {"saslMechanisms": expr}}, nil)
		if err := setErr("MtaStageAuth", res, err); err != nil {
			return err
		}
		if err := r.C.Action(ctx, "ReloadSettings"); err != nil {
			return fmt.Errorf("ReloadSettings: %w", err)
		}
		if r.Logf != nil {
			r.Logf("reconcile: the SASL rule differed from the wanted one (LAN-only %v): rewritten", lan)
		}
	}
	if !lan {
		return nil
	}
	if l == nil {
		return errors.New("LAN-only: can't read the accounts to restrict their mail passwords")
	}
	allowed := creds.AllowedIPs(true, LocalNets(doc, doc.Rewritten()))
	var errs []error
	for _, a := range doc.Accounts {
		if id := FindAccount(l, doc, a.Username); id != "" {
			if _, err := creds.Restrict(ctx, r.C, id, allowed); err != nil {
				errs = append(errs, fmt.Errorf("restricting %s's mail passwords: %w", a.Username, err))
			}
		}
	}
	return errors.Join(errs...)
}

func init() {
	for _, u := range []stalwart.Use{
		{Object: "x:Account", Variant: "User", Field: "aliases"}, {Object: "x:Account", Variant: "User", Field: "quotas"},
		{Object: "x:Account", Variant: "User", Field: "permissions"}, {Object: "x:Account", Variant: "User", Field: "roles"},
		{Object: "x:Account", Variant: "User", Field: "name"}, {Object: "x:Account", Variant: "User", Field: "domainId"},
		{Object: "x:Account", Variant: "User", Field: "description"}, {Object: "x:Account", Variant: "User", Field: "credentials"},
		{Object: "x:EmailAlias", Field: "name"}, {Object: "x:EmailAlias", Field: "domainId"}, {Object: "x:EmailAlias", Field: "enable"},
		{Object: "x:Permissions", Variant: "Merge", Field: "enabledPermissions"}, {Object: "x:Permissions", Variant: "Merge", Field: "disabledPermissions"},
		{Object: "x:Permissions", Variant: "Inherit"}, {Object: "x:UserRoles", Variant: "User"},
		{Object: "x:Credential", Variant: "Password", Field: "secret"},
		{Enum: "StorageQuota", Value: "maxDiskQuota"},
		{Object: "x:MailingList", Field: "name"}, {Object: "x:MailingList", Field: "domainId"},
		{Object: "x:MailingList", Field: "recipients"}, {Object: "x:MailingList", Field: "description"},
		{Object: "x:MemoryLookupKey", Field: "namespace"}, {Object: "x:MemoryLookupKey", Field: "key"}, {Object: "x:MemoryLookupKey", Field: "isGlobPattern"},
		{Object: "x:MtaInboundThrottle", Field: "description"}, {Object: "x:MtaInboundThrottle", Field: "enable"},
		{Object: "x:MtaInboundThrottle", Field: "key"}, {Object: "x:MtaInboundThrottle", Field: "rate"}, {Object: "x:MtaInboundThrottle", Field: "match"},
		{Object: "x:Rate", Field: "count"}, {Object: "x:Rate", Field: "period"},
		{Enum: "MtaInboundThrottleKey", Value: "authenticatedAs"},
		{Object: "x:MtaStageAuth", Field: "saslMechanisms"},
		{Object: "x:Action", Variant: "ReloadLookupStores"}, {Enum: "ActionType", Value: "ReloadLookupStores"},
		{Object: "x:Domain", Field: "name"},
	} {
		stalwart.Used = append(stalwart.Used, u)
	}
}
