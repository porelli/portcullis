package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

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
type Runner struct {
	C         *stalwart.Client
	Store     *state.Store
	Retention time.Duration
	LANOnly   bool
	// Rewritten: client addresses are rewritten (rootless Podman), so the
	// Local networks can't be told apart; LAN-only then admits loopback
	// only (fail closed). The CLI refuses LAN-only there.
	Rewritten bool
	// DQSKeyFile: the Spamhaus DQS key (Settings).
	DQSKeyFile string
	Now        func() time.Time
	Logf       func(string, ...any)
	wake       chan struct{}
}

// NewRunner returns a runner.
func NewRunner(c *stalwart.Client, st *state.Store, retention time.Duration, lanOnly bool, logf func(string, ...any)) *Runner {
	return &Runner{C: c, Store: st, Retention: retention, LANOnly: lanOnly, Now: time.Now, Logf: logf, wake: make(chan struct{}, 1)}
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
	if uerr := r.Store.Update(func(s *state.Persistent) error {
		s.Errors = msg
		if err == nil && s.Doc != nil && s.Doc.Generation == gen {
			s.AppliedGeneration = gen
		}
		return nil
	}); uerr != nil && err == nil {
		err = uerr
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
	setErr := Settings(ctx, r.C, doc, SettingsOpts{Rewritten: r.Rewritten, DQSKeyFile: r.DQSKeyFile})
	if readErr != nil {
		return errors.Join(readErr, lanErr, setErr)
	}
	return errors.Join(r.apply(ctx, l, doc, p), lanErr, setErr)
}

func (r *Runner) apply(ctx context.Context, l *Live, doc *state.Doc, p state.Persistent) error {
	ops, err := Plan(l, doc, p.Former, r.Now(), r.Retention)
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

// LocalNets are the networks LAN-only admits: the document's, or none at
// all (= loopback only) when client addresses are rewritten.
func LocalNets(doc *state.Doc, rewritten bool) []string {
	if rewritten || doc == nil {
		return nil
	}
	return doc.LocalNetworks
}

// lanOnly keeps the SASL rule and every mail password's allowedIps on the
// Local networks while MAIL_SUBMISSION_LAN_ONLY is on.
func (r *Runner) lanOnly(ctx context.Context, l *Live, doc *state.Doc, p state.Persistent) error {
	// The live rule, every pass (a bootstrap run, a hand edit): never a
	// cached copy of what was written.
	expr := SASLExpression(r.LANOnly, LocalNets(doc, r.Rewritten))
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
			r.Logf("reconcile: the SASL rule differed from the wanted one (LAN-only %v): rewritten", r.LANOnly)
		}
	}
	if !r.LANOnly {
		return nil
	}
	if l == nil {
		return errors.New("LAN-only: can't read the accounts to restrict their mail passwords")
	}
	allowed := creds.AllowedIPs(true, LocalNets(doc, r.Rewritten))
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
