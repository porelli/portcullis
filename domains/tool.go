package main

// One-shot subcommands of the domains image (contract §12.1):
//
//	domains dns plan|apply [--wait <dur>]|check|dnssec-enable
//	    the main domain's DNS plan, run by ./portcullis as the compose
//	    service dns-tool (egress only, no volumes, no environment). Input:
//	    one JSON object on stdin — the provider credentials only ever
//	    arrive there. Output: the plan JSON on stdout. Exit 0 ok; 1 check
//	    found a problem / apply --wait timed out before every applied set
//	    was visible; 2 usage or input; 3 provider or lookup failure (the
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
		fmt.Fprintf(e.stderr, "domains dns: %s\nusage: domains dns plan|apply [--wait <duration>]|check|dnssec-enable  (input: one JSON object on stdin)\n", msg)
		return exitUsage
	}
	if len(args) == 0 {
		return usage("missing subcommand")
	}
	sub, rest := args[0], args[1:]
	var wait time.Duration
	switch sub {
	case "plan", "check", "dnssec-enable":
		if len(rest) > 0 {
			return usage("unexpected argument " + rest[0])
		}
	case "apply":
		for len(rest) > 0 {
			if rest[0] != "--wait" || len(rest) < 2 {
				return usage("unexpected argument " + rest[0])
			}
			d, err := time.ParseDuration(rest[1])
			if err != nil || d <= 0 {
				return usage("--wait needs a duration (e.g. 5m)")
			}
			wait, rest = d, rest[2:]
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
	if (sub == "apply" || sub == "dnssec-enable") && in.Provider == "" {
		return fail(exitUsage, errors.New(sub+" needs a provider and its credentials"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute+wait)
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
		} else if sub == "apply" {
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
	if len(in.Sets) == 0 {
		return fail(exitUsage, errors.New("apply needs sets (address, caa, nomail)"))
	}
	for _, s := range in.Sets {
		if !contains(dnsplan.Sets, s) {
			return fail(exitUsage, fmt.Errorf("unknown record set %q (one of %s)", s, strings.Join(dnsplan.Sets, ", ")))
		}
	}
	if _, _, err := dnsplan.Apply(ctx, write, in.Sets); err != nil {
		return fail(exitFailure, err)
	}
	if wait == 0 {
		return printPlan(e, build(write), exitOK)
	}
	// Wait until the public resolvers show every applied set.
	deadline := time.Now().Add(wait)
	// The polls are read-only (public view); the plan printed at the end is
	// built with the provider, like apply's own (can_write, fix: auto).
	for {
		pl := build(base)
		if appliedVisible(pl, in.Sets) {
			return printPlan(e, build(write), exitOK)
		}
		if time.Now().Add(toolPollEvery).After(deadline) || ctx.Err() != nil {
			fmt.Fprintf(e.stderr, "domains dns apply: not every applied record is visible at the public resolvers after %s\n", wait)
			return printPlan(e, build(write), exitProblem)
		}
		select {
		case <-ctx.Done():
		case <-time.After(toolPollEvery):
		}
	}
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

func printPlan(e toolEnv, pl dnsplan.Plan, code int) int {
	b, err := json.Marshal(pl)
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

// runReport is `domains report --main --json` against base (the API).
func runReport(args []string, base, secret string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "--main" || args[1] != "--json" {
		fmt.Fprintln(stderr, "usage: domains report --main --json")
		return exitUsage
	}
	c := &http.Client{Timeout: 3 * time.Minute}
	get := func(path string, out any) error {
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
	var report struct {
		Main    json.RawMessage            `json:"main"`
		Domains map[string]json.RawMessage `json:"domains"`
	}
	report.Domains = map[string]json.RawMessage{}
	if err := get("/main/dns", &report.Main); err != nil {
		fmt.Fprintf(stderr, "domains report: %v\n", err)
		return exitFailure
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
