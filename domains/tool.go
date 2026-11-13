package main

// One-shot subcommands of the domains image (contract §12.1):
//
//	domains dns plan|apply [--wait auto|<dur>] [--settle [--settle-after <unix>]]|ttl|check|dnssec-enable
//	    the main domain's DNS plan, run by ./portcullis as the compose
//	    service dns-tool (egress only, no volumes, no environment). Input:
//	    one JSON object on stdin — the provider credentials only ever
//	    arrive there. Output: the plan JSON on stdout. Exit 0 ok; 1 check
//	    found a problem / apply --wait ended before every applied set was
//	    visible (or, --settle, before the old records' caches expired: the
//	    records were written either way, see wait.go); 2 usage or input; 3 provider or lookup failure (the
//	    message on stderr, redacted).
//	domains traefik-account-uri <acme.json>
//	    prints exactly Traefik's ACME account URI (the file holds private
//	    keys: nothing else of it is ever printed).
//	domains report --main --json
//	    {"main": <plan>, "domains": {"<name>": <plan>}} from the running
//	    service's loopback API (./portcullis status).

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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/portcullis/domains/internal/dnsplan"
	"github.com/portcullis/domains/internal/dnssec"
)

// toolInput is the dns tool's stdin (F7: every key snake_case, unknown
// keys refused).
type toolInput struct {
	Name        string            `json:"name"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
	IPv4        string            `json:"ipv4"`
	IPv6        string            `json:"ipv6"`
	CAServer    string            `json:"ca_server"`
	CAA         struct {
		Enabled    bool   `json:"enabled"`
		Issuer     string `json:"issuer"`
		AccountURI string `json:"account_uri"`
		IODEF      string `json:"iodef"`
	} `json:"caa"`
	NoMail bool     `json:"nomail"`
	Sets   []string `json:"sets"`
	// MailFrom: ALERT_SMTP_FROM; drops the nomail recommendation as the
	// service does (F15d).
	MailFrom string `json:"mail_from"`
}

const toolInputMax = 64 << 10

// Tool exit codes.
const (
	exitOK      = 0
	exitProblem = 1
	exitUsage   = 2
	exitFailure = 3
)

// toolPollEvery: apply --wait re-checks the public view this often.
var toolPollEvery = 10 * time.Second

// toolEnv is what the tool reads from its surroundings (tests set it).
type toolEnv struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	resolvers      []string
}

func resolversFromEnv() []string {
	var out []string
	for _, r := range strings.Split(env("DOMAINS_RESOLVERS", "1.1.1.1:53,8.8.8.8:53"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// runDNSTool is `domains dns <args>`.
func runDNSTool(args []string, e toolEnv) int {
	usage := func(msg string) int {
		fmt.Fprintf(e.stderr, "domains dns: %s\nusage: domains dns plan|apply [--wait auto|<duration>] [--settle [--settle-after <unix>]]|ttl|check|dnssec-enable  (input: one JSON object on stdin)\n", msg)
		return exitUsage
	}
	if len(args) == 0 {
		return usage("missing subcommand")
	}
	sub, rest := args[0], args[1:]
	var wait waitOpts
	switch sub {
	case "plan", "check", "dnssec-enable", "ttl":
		if len(rest) > 0 {
			return usage("unexpected argument " + rest[0])
		}
	case "apply":
		for len(rest) > 0 {
			switch {
			case rest[0] == "--settle":
				wait.settle, rest = true, rest[1:]
			case rest[0] == "--settle-after" && len(rest) >= 2:
				n, err := strconv.ParseInt(rest[1], 10, 64)
				if err != nil || n <= 0 {
					return usage("--settle-after needs a Unix time")
				}
				wait.settleAfter, rest = n, rest[2:]
			case rest[0] == "--wait" && len(rest) >= 2:
				if rest[1] == "auto" {
					wait.auto, wait.fixed = true, 0
				} else {
					d, err := time.ParseDuration(rest[1])
					if err != nil || d <= 0 {
						return usage("--wait needs auto or a duration (e.g. 5m)")
					}
					wait.auto, wait.fixed = false, d
				}
				rest = rest[2:]
			default:
				return usage("unexpected argument " + rest[0])
			}
		}
		if wait.settle && !wait.on() {
			return usage("--settle needs --wait")
		}
		if wait.settleAfter > 0 && !wait.settle {
			return usage("--settle-after needs --settle")
		}
	default:
		return usage("unknown subcommand " + sub)
	}
	in, err := readToolInput(e.stdin)
	if err != nil {
		return usage(err.Error())
	}
	fail := func(code int, err error) int {
		fmt.Fprintf(e.stderr, "domains dns %s: %s\n", sub, redact(err.Error(), in.Credentials))
		return code
	}
	spec, err := in.spec()
	if err != nil {
		return fail(exitUsage, err)
	}
	if sub == "check" && len(in.Credentials) > 0 {
		return fail(exitUsage, errors.New("check takes no credentials"))
	}
	if (sub == "apply" || sub == "dnssec-enable" || sub == "ttl") && in.Provider == "" {
		return fail(exitUsage, errors.New(sub+" needs a provider and its credentials"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute+wait.ctxBudget())
	defer cancel()
	base := dnsplan.Input{Spec: spec, ProviderName: in.Provider, Resolvers: e.resolvers}
	write := base
	if sub != "check" && in.Provider != "" {
		if err := validateCredentials(in.Provider, in.Credentials); err != nil {
			return fail(exitUsage, err)
		}
		d := &Domain{Name: spec.Name, Provider: in.Provider, Credentials: in.Credentials}
		p, err := buildProvider(d)
		if err != nil {
			return fail(exitFailure, err)
		}
		r, can, err := buildDNSSEC(d)
		if err != nil {
			return fail(exitFailure, err)
		}
		write.Provider, write.DNSSEC, write.CanSign = p, r, can
		if z, err := toolZone(ctx, p, spec.Name, e.resolvers); err == nil {
			write.Zone = z
		} else if sub == "apply" || sub == "ttl" {
			return fail(exitFailure, err)
		}
	}
	build := func(in2 dnsplan.Input) dnsplan.Plan {
		in2.Now = time.Now()
		return dropNoMailFor(dnsplan.Build(ctx, in2), in.MailFrom)
	}
	switch sub {
	case "plan":
		return printPlan(e, build(write), exitOK)
	case "ttl":
		// How long caches may hold the sets' current records (read before
		// a write: the shell saves it before the relax, contract §12.1).
		if err := checkSets(in.Sets); err != nil {
			return fail(exitUsage, err)
		}
		cur, err := dnsplan.Stored(ctx, write.Provider, write.Zone, spec.Name, in.Sets)
		if err != nil {
			return fail(exitFailure, err)
		}
		auth := toolAuthServers(ctx, e.resolvers, write.Zone)
		return printJSON(e, map[string]int{"ttl": secs(ttlBound(effectiveTTLs(ctx, cur, auth), nil, 0))}, exitOK)
	case "check":
		pl := build(base)
		code := exitOK
		if planHasProblem(pl) {
			code = exitProblem
		}
		return printPlan(e, pl, code)
	case "dnssec-enable":
		signer, ok := write.DNSSEC.(dnssec.Signer)
		if !ok {
			return fail(exitFailure, fmt.Errorf("%s can't sign the zone through its API", in.Provider))
		}
		zone, err := dnssec.FindZone(ctx, e.resolvers, spec.Name)
		if err != nil {
			return fail(exitFailure, fmt.Errorf("finding the DNS zone of %s: %w", spec.Name, err))
		}
		if err := signer.EnableDNSSEC(ctx, zone); err != nil {
			return fail(exitFailure, err)
		}
		return printPlan(e, build(write), exitOK)
	}
	// apply
	if err := checkSets(in.Sets); err != nil {
		return fail(exitUsage, err)
	}
	// The RRsets as the provider stores them before and after the write,
	// and as the authoritative servers serve them: their TTLs bound the
	// wait. A failed read assumes the worst (the whole cap).
	var before map[string]dnsplan.RRset
	var readErr error
	var auth []string
	var beforeTTL map[string]time.Duration
	if wait.on() {
		auth = toolAuthServers(ctx, e.resolvers, write.Zone)
		before, readErr = dnsplan.Stored(ctx, write.Provider, write.Zone, spec.Name, in.Sets)
		beforeTTL = effectiveTTLs(ctx, before, auth)
	}
	if _, _, err := dnsplan.Apply(ctx, write, in.Sets); err != nil {
		return fail(exitFailure, err)
	}
	if !wait.on() {
		return printPlan(e, build(write), exitOK)
	}
	writtenAt := toolNow()
	after, err := dnsplan.Stored(ctx, write.Provider, write.Zone, spec.Name, in.Sets)
	ttl := ttlBound(beforeTTL, effectiveTTLs(ctx, after, auth), dnsplan.NegativeTTL(ctx, auth, e.resolvers, write.Zone))
	if readErr != nil || err != nil {
		ttl = max(ttl, unknownTTL)
	}
	changed := readErr != nil || err != nil || !sameRRsets(before, after)
	fmt.Fprintln(e.stderr, progressMessage(wait, ttl, e.resolvers))
	// The polls are read-only (public view); the plan printed at the end is
	// built with the provider, like apply's own (can_write, fix: auto).
	rep, ok := waitApplied(ctx, e, build, base, in.Sets, wait, ttl, writtenAt, changed)
	code := exitOK
	if !ok {
		fmt.Fprintln(e.stderr, waitMessage(rep))
		code = exitProblem
	}
	return printJSON(e, applyOutput{Plan: build(write), Wait: rep}, code)
}

// checkSets: apply and ttl need known sets.
func checkSets(sets []string) error {
	if len(sets) == 0 {
		return errors.New("needs sets (address, caa, nomail)")
	}
	for _, s := range sets {
		if !contains(dnsplan.Sets, s) {
			return fmt.Errorf("unknown record set %q (one of %s)", s, strings.Join(dnsplan.Sets, ", "))
		}
	}
	return nil
}

// sameRRsets: the same RRsets with the same data (TTLs aside).
func sameRRsets(a, b map[string]dnsplan.RRset) bool {
	if len(a) != len(b) {
		return false
	}
	for k, x := range a {
		y, ok := b[k]
		if !ok || strings.Join(x.Data, "\x00") != strings.Join(y.Data, "\x00") {
			return false
		}
	}
	return true
}

func readToolInput(r io.Reader) (toolInput, error) {
	var in toolInput
	raw, err := io.ReadAll(io.LimitReader(r, toolInputMax+1))
	if err != nil {
		return in, fmt.Errorf("reading stdin: %w", err)
	}
	if len(raw) > toolInputMax {
		return in, fmt.Errorf("stdin holds more than %d bytes", toolInputMax)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		// Never quote the input (it holds the credentials).
		return in, errors.New("stdin must be one JSON object with the documented keys (name, provider, credentials, ipv4, ipv6, ca_server, caa, nomail, sets, mail_from)")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return in, errors.New("stdin must hold exactly one JSON object")
	}
	return in, nil
}

// spec is the main domain's wanted state from the input.
func (in toolInput) spec() (dnsplan.Spec, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Name), "."))
	if !validHostname(name) {
		return dnsplan.Spec{}, fmt.Errorf("name %q is not a valid hostname", in.Name)
	}
	parse := func(k, v string, want4 bool) (netip.Addr, error) {
		if v == "" {
			return netip.Addr{}, nil
		}
		ip, err := netip.ParseAddr(v)
		if err != nil || ip.Is4() != want4 || ip.Is4In6() {
			return netip.Addr{}, fmt.Errorf("%s %q is not an IPv%s address", k, v, map[bool]string{true: "4", false: "6"}[want4])
		}
		return ip, nil
	}
	v4, err := parse("ipv4", in.IPv4, true)
	if err != nil {
		return dnsplan.Spec{}, err
	}
	v6, err := parse("ipv6", in.IPv6, false)
	if err != nil {
		return dnsplan.Spec{}, err
	}
	if u := in.CAA.AccountURI; u != "" && !dnsplan.ValidAccountURI(u) {
		return dnsplan.Spec{}, fmt.Errorf("caa.account_uri %q is not an ACME account URI (https, no spaces, quotes or ';')", u)
	}
	issuer, _ := dnsplan.IssuerFor(in.CAServer, in.CAA.Issuer)
	return dnsplan.Spec{Name: name, IPv4: v4, IPv6: v6, CAA: in.CAA.Enabled, Issuer: issuer, AccountURI: in.CAA.AccountURI,
		IODEF: strings.TrimSpace(in.CAA.IODEF), NoMail: in.NoMail, Main: true}, nil
}

// toolZone: the provider's own zone, else the SOA lookup.
func toolZone(ctx context.Context, p dnsProvider, name string, resolvers []string) (string, error) {
	inner, clean := unwrap(p)
	if zf, ok := inner.(zoneFinder); ok {
		z, err := zf.FindZone(name + ".")
		return z, clean(err)
	}
	z, err := dnssec.FindZone(ctx, resolvers, name)
	if err != nil {
		return "", fmt.Errorf("finding the DNS zone of %s: %w", name, err)
	}
	return z, nil
}

// planHasProblem: an item or the DNSSEC state is a Problem.
func planHasProblem(pl dnsplan.Plan) bool {
	for _, it := range pl.Items {
		if it.Severity == dnsplan.SevProblem {
			return true
		}
	}
	return pl.DNSSEC.State == dnssec.Bogus || pl.DNSSEC.State == dnssec.DSMismatch
}

// appliedVisible: every item of the applied sets that Portcullis owns
// (not foreign, not an Info note) is ok at the public resolvers.
func appliedVisible(pl dnsplan.Plan, sets []string) bool {
	for _, it := range pl.Items {
		if !contains(sets, it.Set) || it.Status == dnsplan.StatusForeign || it.Severity == dnsplan.SevInfo {
			continue
		}
		if it.Status != dnsplan.StatusOK {
			return false
		}
	}
	return true
}

func printPlan(e toolEnv, pl dnsplan.Plan, code int) int { return printJSON(e, pl, code) }

func printJSON(e toolEnv, v any, code int) int {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(e.stderr, err)
		return exitFailure
	}
	fmt.Fprintf(e.stdout, "%s\n", b)
	return code
}

// runTraefikAccountURI is `domains traefik-account-uri <acme.json>`.
func runTraefikAccountURI(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: domains traefik-account-uri <acme.json>")
		return exitUsage
	}
	path := args[0]
	none := func() int {
		fmt.Fprintf(stderr, "no Traefik ACME account in %s\n", path)
		return exitFailure
	}
	f, err := os.Open(path)
	if err != nil {
		return none()
	}
	defer f.Close()
	var doc struct {
		Letsencrypt *struct {
			Account *struct {
				Registration *struct {
					URI string `json:"uri"`
				} `json:"Registration"`
			} `json:"Account"`
		} `json:"letsencrypt"`
	}
	if err := json.NewDecoder(io.LimitReader(f, 64<<20)).Decode(&doc); err != nil {
		return none()
	}
	if doc.Letsencrypt == nil || doc.Letsencrypt.Account == nil || doc.Letsencrypt.Account.Registration == nil {
		return none()
	}
	u := doc.Letsencrypt.Account.Registration.URI
	if !dnsplan.ValidAccountURI(u) {
		return none()
	}
	fmt.Fprintln(stdout, u)
	return exitOK
}

// reportFreshTimeout bounds report --fresh's rebuild of the main plan
// (public lookups); past it the cached plan is used (tests shorten it).
var reportFreshTimeout = 20 * time.Second

// runReport is `domains report --main --json [--fresh]` against base (the
// API): --fresh asks for the main plan rebuilt unless it is under 30 s old
// (GET /main/dns?refresh=1, the service's throttle), so a CAA changed
// outside Portcullis shows at once; if that fails or takes longer than
// reportFreshTimeout, the cached plan, and "main_fresh": false says so;
// `domains report --main --refresh` drops the service's cached main plan
// and has it rebuilt (POST /main/dns/refresh: after the dns tool wrote
// the main domain's records), printing nothing.
func runReport(args []string, base, secret string, stdout, stderr io.Writer) int {
	fresh := len(args) == 3 && args[1] == "--json" && args[2] == "--fresh"
	if !(len(args) == 2 || fresh) || args[0] != "--main" || (args[1] != "--json" && args[1] != "--refresh") {
		fmt.Fprintln(stderr, "usage: domains report --main --json [--fresh] | --main --refresh")
		return exitUsage
	}
	c := &http.Client{Timeout: 3 * time.Minute}
	if args[1] == "--refresh" {
		req, err := http.NewRequest(http.MethodPost, base+"/main/dns/refresh", nil)
		if err != nil {
			fmt.Fprintf(stderr, "domains report: %v\n", err)
			return exitFailure
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := c.Do(req)
		if err != nil {
			fmt.Fprintf(stderr, "domains report: POST /main/dns/refresh: %v\n", err)
			return exitFailure
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<20))
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(stderr, "domains report: POST /main/dns/refresh: HTTP %d\n", resp.StatusCode)
			return exitFailure
		}
		return exitOK
	}
	getWith := func(c *http.Client, path string, out any) error {
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, err := c.Do(req)
		if err != nil {
			return fmt.Errorf("GET %s: %w", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
	}
	get := func(path string, out any) error { return getWith(c, path, out) }
	var report struct {
		Main json.RawMessage `json:"main"`
		// MainFresh: main was rebuilt for this report (--fresh) or is
		// under 30 s old; false = the cached plan, possibly stale.
		MainFresh bool                       `json:"main_fresh"`
		Domains   map[string]json.RawMessage `json:"domains"`
	}
	report.Domains = map[string]json.RawMessage{}
	if fresh {
		err := getWith(&http.Client{Timeout: reportFreshTimeout}, "/main/dns?refresh=1", &report.Main)
		report.MainFresh = err == nil
		if err != nil {
			fmt.Fprintf(stderr, "domains report: the main plan couldn't be rebuilt (%v): using the cached one\n", err)
		}
	}
	if !report.MainFresh {
		if err := get("/main/dns", &report.Main); err != nil {
			fmt.Fprintf(stderr, "domains report: %v\n", err)
			return exitFailure
		}
	}
	var list []View
	if err := get("/domains", &list); err != nil {
		fmt.Fprintf(stderr, "domains report: %v\n", err)
		return exitFailure
	}
	for _, v := range list {
		var pl json.RawMessage
		if err := get("/domains/"+url.PathEscape(v.Name)+"/dns", &pl); err != nil {
			fmt.Fprintf(stderr, "domains report: %v\n", err)
			return exitFailure
		}
		report.Domains[v.Name] = pl
	}
	b, err := json.Marshal(report)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitFailure
	}
	fmt.Fprintf(stdout, "%s\n", b)
	return exitOK
}

// toolLogger: the test provider's start message goes to stderr.
func toolLogger() *log.Logger { return log.New(os.Stderr, "", 0) }
