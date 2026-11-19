// Package checks is mailctl's deliverability checks (contract §19.8,
// GET /v1/checks): every 6 h and on refresh (one run at a time; a refresh
// within 60 s answers the last result). No check ever dials port 25 of
// anyone: port25 reads Stalwart's queue only, and the certificate check
// dials mail's own listeners on portcullis-mail (10025 / 10465 / 10587 /
// 10993).
package checks

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// Severities.
const (
	OK      = "ok"
	Info    = "info"
	Warning = "warning"
	Problem = "problem"
)

// Check is one result. Title only on x- checks (contract §19.8).
type Check struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title,omitempty"`
	Detail   string   `json:"detail"`
	Steps    []string `json:"steps"`
	// Reason: fcrdns_v4 / fcrdns_v6 when not ok, "missing" | "mismatch".
	Reason string `json:"reason,omitempty"`
	// outcome: the cert check's "pass" | "fail" (definite) | "unknown".
	outcome string
}

// Result is GET /v1/checks.
type Result struct {
	CheckedAt time.Time `json:"checked_at"`
	Checks    []Check   `json:"checks"`
}

// Value is the metric value of a severity (1 ok / info, 0 otherwise).
func Value(sev string) float64 {
	if sev == OK || sev == Info {
		return 1
	}
	return 0
}

// Querier asks a DNS server one question (resolve.Query).
type Querier func(ctx context.Context, server, name string, qtype uint16, dnssec bool) (*dns.Msg, error)

// Config is what the checks need besides the document. Hostname and
// ClientIP are the accepted document's (Run fills them).
type Config struct {
	Hostname      string
	PublicIPv4    netip.Addr
	PublicIPv6    netip.Addr
	Resolvers     []string // the public resolvers
	LocalResolver string   // mail-resolver
	DQSKeyFile    string
	ClientIP      string // preserved | rewritten
	MailIP        string // mail's portcullis-mail address (the certificate check)
}

// Deps are the checks' inputs.
type Deps struct {
	C     *stalwart.Client
	M     *machines.Machines
	Store *state.Store
	Cfg   Config
	Now   func() time.Time
	DNS   Querier
	Dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	Logf  func(string, ...any)
}

func (d Deps) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// Run runs every check once.
func Run(ctx context.Context, d Deps) Result {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	p := d.Store.Get()
	var want []string
	if p.Doc != nil {
		d.Cfg.Hostname, d.Cfg.ClientIP, want = p.Doc.MailHostname, p.Doc.ClientIP, p.Doc.TLS.SPKISHA256
	}
	var out []Check
	q, qerr := readQueue(ctx, d)
	out = append(out, port25(d, q, qerr, p))
	out = append(out, fcrdns(ctx, d, d.Cfg.PublicIPv4, false), fcrdns(ctx, d, d.Cfg.PublicIPv6, true))
	out = append(out, blocklist(ctx, d, p.Doc))
	out = append(out, certCheck(ctx, d, want))
	out = append(out, dkimChecks(ctx, d, p.Doc)...)
	out = append(out, reportChecks(ctx, d, p.Doc)...)
	out = append(out, clientIP(d))
	out = append(out, rateHeld(d, q, qerr, p.Doc)...)
	out = append(out, dane(ctx, d), spamRulesCheck(p), lookupsCheck(p))
	for i := range out {
		if out[i].Steps == nil {
			out[i].Steps = []string{}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return Result{CheckedAt: d.now(), Checks: out}
}

// Runner caches the last result.
type Runner struct {
	D        Deps
	OnResult func(Result)

	mu      sync.Mutex    // the fields below; never held during a run
	running chan struct{} // closed when the run in flight ends (nil: none)
	last    *Result
	lastAt  time.Time
	lastGen int64 // the document generation the last run saw

	certMu    sync.Mutex
	certLast  string      // the last cert outcome
	certFails []time.Time // consecutive definite cert failures
}

// CertDowngradeGap: MTA-STS enforce → testing needs two consecutive
// definite cert failures at least this far apart (security ruling).
const CertDowngradeGap = 15 * time.Minute

// CertState is the certificate check for the MTA-STS machine: ok and
// known. A definite pass is (true, true). An unknown result, or a failure
// not yet confirmed (two consecutive definite failures ≥ 15 min apart), is
// (false, false): it holds testing but never moves enforce back. Only the
// confirmed failure is (false, true).
func (r *Runner) CertState() (bool, bool) {
	r.certMu.Lock()
	defer r.certMu.Unlock()
	switch r.certLast {
	case "pass":
		return true, true
	case "fail":
		n := len(r.certFails)
		if n >= 2 && r.certFails[n-1].Sub(r.certFails[0]) >= CertDowngradeGap {
			return false, true
		}
	}
	return false, false
}

func (r *Runner) noteCert(res Result) {
	r.certMu.Lock()
	defer r.certMu.Unlock()
	for _, c := range res.Checks {
		if c.ID != "cert" {
			continue
		}
		switch c.outcome {
		case "pass":
			r.certFails = nil
		case "fail":
			r.certFails = append(r.certFails, res.CheckedAt)
		}
		r.certLast = c.outcome
	}
}

// RefreshWithin: a refresh within this answers the last result.
const RefreshWithin = 60 * time.Second

// Get answers the last result (running the first one), or a fresh run
// on refresh unless the last is younger than RefreshWithin and saw the
// current document. Single flight (final review L7): one run at a time,
// every caller waits for the run in flight instead of starting another,
// and no longer than its own context (then it gets the last result, with
// its checked_at; none yet: an empty one).
func (r *Runner) Get(ctx context.Context, refresh bool) Result {
	r.mu.Lock()
	gen := r.D.Store.Get().Generation
	if r.running == nil && r.last != nil && (!refresh || (r.D.now().Sub(r.lastAt) < RefreshWithin && gen == r.lastGen)) {
		res := *r.last
		r.mu.Unlock()
		return res
	}
	if r.running == nil {
		done := make(chan struct{})
		r.running = done
		// The run never inherits the request's cancellation (a client
		// hanging up mustn't turn checks into failures); Run has its own
		// timeout.
		go func() {
			res := Run(context.WithoutCancel(ctx), r.D)
			r.noteCert(res)
			r.mu.Lock()
			r.last, r.lastAt, r.lastGen = &res, r.D.now(), gen
			r.running = nil
			r.mu.Unlock()
			// Before the waiters wake (OnResult must not call Get).
			if r.OnResult != nil {
				r.OnResult(res)
			}
			close(done)
		}()
	}
	done := r.running
	r.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return Result{}
	}
	return *r.last
}

// Last is the last result's check by id (ok=false: none yet).
func (r *Runner) Last(id string) (Check, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		return Check{}, false
	}
	for _, c := range r.last.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

// Loop runs every 6 h (the first run at once).
func (r *Runner) Loop(ctx context.Context, every time.Duration) {
	for {
		r.Get(ctx, true)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// query asks each server in turn; the first answer wins.
func query(ctx context.Context, d Deps, servers []string, name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	var last error
	for _, s := range servers {
		m, err := d.DNS(ctx, s, name, qtype, dnssec)
		if err == nil {
			return m, nil
		}
		last = err
	}
	if last == nil {
		last = errNoResolver
	}
	return nil, last
}

type errString string

func (e errString) Error() string { return string(e) }

const errNoResolver = errString("no resolver configured")

func joinMax(items []string, n int) string {
	if len(items) > n {
		return strings.Join(items[:n], ", ") + ", …"
	}
	return strings.Join(items, ", ")
}

const dnsTypeTXT = dns.TypeTXT

type dnsTXT = dns.TXT

// Catalog is the ids the adapter reports (GET /v1/provider checks): the
// neutral catalog's (contract §19.8; per-domain and per-account ids by
// their prefix) and its own x- ids.
var Catalog = []string{
	"port25", "fcrdns_v4", "fcrdns_v6", "blocklist", "cert", "dane", "client_ip",
	"dmarc_reports", "tlsrpt_reports", "dkim_selftest:", "dkim_stuck:", "rate_held:",
	IDSpamRules, IDExternalLookups,
}

// neutral are the contract's fixed ids, prefixes ending in ":".
var neutral = []string{
	"port25", "fcrdns_v4", "fcrdns_v6", "blocklist", "cert", "dane", "client_ip", "dmarc_reports", "tlsrpt_reports",
	"records:", "dkim_selftest:", "dkim_stuck:", "dkim_manual:", "rate_held:",
}

var reXID = regexp.MustCompile(`^x-[a-z0-9_]{1,40}$`)

// InCatalog: id is one the contract allows (a neutral id, a prefixed one
// with a non-empty suffix, or x-[a-z0-9_]{1,40}).
func InCatalog(id string) bool {
	for _, n := range neutral {
		if strings.HasSuffix(n, ":") {
			if rest, ok := strings.CutPrefix(id, n); ok && rest != "" {
				return true
			}
		} else if id == n {
			return true
		}
	}
	return reXID.MatchString(id)
}
