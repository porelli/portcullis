package dnsplan

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

// CAA (RFC 8659, RFC 8657): what Portcullis writes, how it merges with
// what is there, and how a CA judges the effective set.

// issuers maps ACME directories to the CAA issuer domain the CA checks.
// Let's Encrypt production and staging both check "letsencrypt.org".
var issuers = map[string]string{
	"https://acme-v02.api.letsencrypt.org/directory":         "letsencrypt.org",
	"https://acme-staging-v02.api.letsencrypt.org/directory": "letsencrypt.org",
}

// IssuerFor returns the CAA issuer domain for an ACME directory: the
// override when set, else the fixed map; any other CA is unknown.
func IssuerFor(caServer, override string) (string, bool) {
	if o := strings.TrimSpace(override); o != "" {
		return normIssuer(o), true
	}
	if i, ok := issuers[strings.TrimSpace(caServer)]; ok {
		return i, true
	}
	return "", false
}

// ValidAccountURI: an ACME account URI fit for a CAA value (https, a
// host, nothing a CAA parameter or a quoted string can't hold).
func ValidAccountURI(u string) bool {
	if u == "" || strings.ContainsAny(u, " \t\r\n\";") {
		return false
	}
	pu, err := url.Parse(u)
	return err == nil && pu.Scheme == "https" && pu.Host != ""
}

// CAAValue is the issue / issuewild value Portcullis writes: pinned to an
// ACME account when the URI is known, CA-only otherwise; DNS-01 only.
func CAAValue(issuer, accountURI string) string {
	if accountURI == "" {
		return issuer + "; validationmethods=dns-01"
	}
	return issuer + "; accounturi=" + accountURI + "; validationmethods=dns-01"
}

func normIssuer(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// caaValue is a parsed issue / issuewild value.
type caaValue struct {
	issuer string            // normalised; "" = no CA may issue (";")
	params map[string]string // lowercase keys, trimmed values
	ok     bool              // well-formed
}

func parseValue(v string) caaValue {
	parts := strings.Split(v, ";")
	out := caaValue{issuer: normIssuer(parts[0]), params: map[string]string{}, ok: true}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, val, found := strings.Cut(p, "=")
		if !found || strings.TrimSpace(k) == "" {
			out.ok = false
			continue
		}
		out.params[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
	}
	return out
}

func issueTag(tag string) bool {
	t := strings.ToLower(tag)
	return t == "issue" || t == "issuewild"
}

// ours: an issue / issuewild entry for our issuer.
func ours(c libdns.CAA, issuer string) bool {
	return issueTag(c.Tag) && parseValue(c.Value).issuer == issuer
}

// signature: the main domain's entries Portcullis wrote (our issuer and
// validationmethods=dns-01); the user's own entries without it stay.
func signature(c libdns.CAA, issuer string) bool {
	if !ours(c, issuer) {
		return false
	}
	return strings.EqualFold(parseValue(c.Value).params["validationmethods"], "dns-01")
}

// ownCAA are the entries Portcullis writes for s.
func ownCAA(s Spec) []libdns.CAA {
	v := CAAValue(s.Issuer, s.AccountURI)
	out := []libdns.CAA{
		{Name: "@", TTL: TTLCAA, Flags: 0, Tag: "issue", Value: v},
		{Name: "@", TTL: TTLCAA, Flags: 0, Tag: "issuewild", Value: v},
	}
	if s.IODEF != "" {
		out = append(out, libdns.CAA{Name: "@", TTL: TTLCAA, Flags: 0, Tag: "iodef", Value: s.IODEF})
	}
	return out
}

// MergeCAA returns the full CAA RRset to write at <d>: every entry that
// isn't ours kept, ours (issue + issuewild, and iodef when configured)
// replaced; others lists the other CAs' issuer domains that stay.
func MergeCAA(live []libdns.CAA, s Spec) (next []libdns.CAA, others []string) {
	seen := map[string]bool{}
	for _, c := range live {
		if ours(c, s.Issuer) || (s.IODEF != "" && strings.EqualFold(c.Tag, "iodef")) {
			continue
		}
		c.TTL = TTLCAA
		next = append(next, c)
		if issueTag(c.Tag) {
			if i := parseValue(c.Value).issuer; i != "" && !seen[i] {
				seen[i] = true
				others = append(others, i)
			}
		}
	}
	sort.Strings(others)
	return append(next, ownCAA(s)...), others
}

// removalCAA are the live entries to delete with CAA off: exactly the
// owned refs (enrolled domains), or the entries with Portcullis'
// signature (main domain).
func removalCAA(live []libdns.CAA, s Spec) []libdns.CAA {
	var out []libdns.CAA
	for _, c := range live {
		if s.Main {
			if s.Issuer != "" && signature(c, s.Issuer) {
				out = append(out, c)
			}
			continue
		}
		for _, r := range s.Owned {
			if r.Type == "CAA" && dataKey("CAA", r.Value) == dataKey("CAA", c.RR().Data) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// EffectiveCAA finds the CAA RRset that applies to name (RFC 8659 §3):
// the RRset at the name, else at its parent, and so on, stopping before
// the TLD. A wildcard name starts at the name right of "*.". The first
// resolver that answers is used; owner "" means no CAA anywhere.
func EffectiveCAA(ctx context.Context, resolvers []string, name string) (string, []*dns.CAA, error) {
	cur := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(name, "*."), "."))
	for strings.Contains(cur, ".") {
		in, err := ask(ctx, resolvers, cur, dns.TypeCAA)
		if err != nil {
			return "", nil, err
		}
		var rrs []*dns.CAA
		for _, rr := range in.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				rrs = append(rrs, c)
			}
		}
		if len(rrs) > 0 {
			return cur, rrs, nil
		}
		_, cur, _ = strings.Cut(cur, ".")
	}
	return "", nil, nil
}

// knownTags are the property tags a CA understands; a critical unknown
// one forbids issuance (RFC 8659 §4.1).
var knownTags = map[string]bool{"issue": true, "issuewild": true, "iodef": true,
	"contactemail": true, "contactphone": true, "issuemail": true, "issuevmc": true}

// WouldIssue judges an effective CAA set the way the CA would for our
// issuer and ACME account (RFC 8659 + RFC 8657 accounturi and
// validationmethods; DNS-01 is the only method we use).
func WouldIssue(rrs []*dns.CAA, issuer, accountURI string, wildcard bool) bool {
	if issuer == "" {
		return false // unknown CA: can't be judged (fail closed)
	}
	issuer = normIssuer(issuer)
	var issue, wild []*dns.CAA
	for _, c := range rrs {
		tag := strings.ToLower(c.Tag)
		if c.Flag&128 != 0 && !knownTags[tag] {
			return false
		}
		switch tag {
		case "issue":
			issue = append(issue, c)
		case "issuewild":
			wild = append(wild, c)
		}
	}
	relevant := issue
	if wildcard && len(wild) > 0 {
		relevant = wild
	}
	if len(relevant) == 0 {
		return true
	}
	for _, c := range relevant {
		v := parseValue(c.Value)
		if !v.ok || v.issuer == "" || v.issuer != issuer {
			continue
		}
		if u, ok := v.params["accounturi"]; ok && u != accountURI {
			continue
		}
		if m, ok := v.params["validationmethods"]; ok {
			found := false
			for _, x := range strings.Split(m, ",") {
				if strings.EqualFold(strings.TrimSpace(x), "dns-01") {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		return true
	}
	return false
}

// ask queries the resolvers in order; the first NOERROR / NXDOMAIN
// answer wins.
func ask(ctx context.Context, resolvers []string, name string, qt uint16) (*dns.Msg, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers configured")
	}
	var errs []error
	for _, r := range resolvers {
		in, err := exchange(ctx, r, name, qt)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return in, nil
	}
	return nil, errors.Join(errs...)
}

func exchange(ctx context.Context, resolver, name string, qt uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	m.SetEdns0(4096, false)
	c := &dns.Client{Timeout: lookupTimeout}
	in, _, err := c.ExchangeContext(ctx, m, resolver)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, resolver)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s at %s: %w", dns.TypeToString[qt], name, resolver, err)
	}
	if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("%s %s at %s: %s", dns.TypeToString[qt], name, resolver, dns.RcodeToString[in.Rcode])
	}
	return in, nil
}
