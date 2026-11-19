package checks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"

	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/state"
)

type dnsblList struct {
	Name, Zone string
	v6         bool
}

// lists are the switched-on DNSBLs (Spamhaus through DQS with a key).
func lists(doc *state.Doc, dqsKey string) []dnsblList {
	var out []dnsblList
	if doc == nil || doc.Spam.DNSBL.Spamhaus {
		z, n := "zen.spamhaus.org", "Spamhaus ZEN"
		if dqsKey != "" {
			z, n = dqsKey+".zen.dq.spamhaus.net", "Spamhaus ZEN (DQS)"
		}
		out = append(out, dnsblList{n, z, true})
	}
	if doc == nil || doc.Spam.DNSBL.Spamcop {
		out = append(out, dnsblList{"SpamCop", "bl.spamcop.net", false})
	}
	if doc == nil || doc.Spam.DNSBL.Barracuda {
		out = append(out, dnsblList{"Barracuda", "b.barracudacentral.org", false})
	}
	return out
}

// reversed is the DNSBL query label of an address.
func reversed(ip netip.Addr) string {
	arpa, _ := dns.ReverseAddr(ip.String())
	arpa = strings.TrimSuffix(arpa, ".")
	arpa = strings.TrimSuffix(arpa, ".in-addr.arpa")
	return strings.TrimSuffix(arpa, ".ip6.arpa")
}

var sevRank = map[string]int{OK: 0, Info: 1, Warning: 2, Problem: 3}

// blocklist: each public address against the switched-on lists through
// mail-resolver. 127.0.0.10/.11 on ZEN = the PBL (residential range);
// 127.255.255.x = the list refused the query: a Warning, never ok.
func blocklist(ctx context.Context, d Deps, doc *state.Doc) Check {
	c := Check{ID: "blocklist", Severity: OK}
	key, err := reconcile.DQSKey(d.Cfg.DQSKeyFile)
	if err != nil {
		key = ""
	}
	var ips []netip.Addr
	for _, ip := range []netip.Addr{d.Cfg.PublicIPv4, d.Cfg.PublicIPv6} {
		if ip.IsValid() {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		c.Severity, c.Detail = Info, "the public address isn't known: blocklists not checked"
		return c
	}
	raise := func(sev string) {
		if sevRank[sev] > sevRank[c.Severity] {
			c.Severity = sev
		}
	}
	var notes []string
	pbl := false
	for _, ip := range ips {
		for _, l := range lists(doc, key) {
			if ip.Is6() && !l.v6 {
				continue
			}
			m, err := d.DNS(ctx, d.Cfg.LocalResolver, reversed(ip)+"."+l.Zone, dns.TypeA, false)
			if err != nil {
				raise(Warning)
				notes = append(notes, fmt.Sprintf("%s: %s couldn't be checked", ip, l.Name))
				continue
			}
			if m.Rcode == dns.RcodeNameError {
				continue
			}
			if m.Rcode != dns.RcodeSuccess {
				raise(Warning)
				notes = append(notes, fmt.Sprintf("%s: %s answered %s", ip, l.Name, dns.RcodeToString[m.Rcode]))
				continue
			}
			for _, rr := range m.Answer {
				a, ok := rr.(*dns.A)
				if !ok {
					continue
				}
				v := a.A.To4()
				switch {
				case v[0] == 127 && v[1] == 255 && v[2] == 255:
					raise(Warning)
					notes = append(notes, fmt.Sprintf("%s: %s refused the query (%s): DNSBL refused the query, not checked", ip, l.Name, v))
				case strings.HasPrefix(l.Name, "Spamhaus") && v[0] == 127 && v[1] == 0 && v[2] == 0 && (v[3] == 10 || v[3] == 11):
					raise(Problem)
					pbl = true
					notes = append(notes, fmt.Sprintf("%s is in %s's PBL (%s): residential range: use a relay", ip, l.Name, v))
				case v[0] == 127:
					raise(Problem)
					notes = append(notes, fmt.Sprintf("%s is listed by %s (%s)", ip, l.Name, v))
				}
			}
		}
	}
	if len(notes) == 0 {
		c.Detail = "not listed"
		return c
	}
	c.Detail = strings.Join(notes, "; ")
	if pbl {
		c.Steps = append(c.Steps, "The address is in a residential (dynamic) range that receivers refuse: send through a relay (Settings → Mail → Relay).")
	}
	if c.Severity == Problem {
		c.Steps = append(c.Steps, "Request delisting at each list's lookup page (Spamhaus: check.spamhaus.org, SpamCop: spamcop.net/bl.shtml, Barracuda: barracudacentral.org/lookups) once the cause is fixed.")
	}
	if c.Severity == Warning && strings.Contains(c.Detail, "refused") {
		c.Steps = append(c.Steps, "Spamhaus refuses queries from large public resolvers: set the stalwart app's dqs_key setting (a free Spamhaus DQS key).")
	}
	return c
}
