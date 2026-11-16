package checks

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// PTRSteps are the per-provider ways to set reverse DNS (one line each,
// the generic one last).
func PTRSteps(ip netip.Addr, host string) []string {
	return []string{
		fmt.Sprintf("Set the reverse DNS (PTR) of %s to %s, and keep %s's A/AAAA record pointing at %s:", ip, host, host, ip),
		fmt.Sprintf("Hetzner: Cloud Console → the server → Networking → the IP's reverse DNS → %s (Robot: IPs → the address → Reverse DNS).", host),
		"DigitalOcean: rename the Droplet to the mail host name exactly; its PTR follows the Droplet's name.",
		"AWS EC2: Elastic IPs → the address → Actions → Update reverse DNS (the A record must already point at it).",
		"AWS Lightsail: submit the \"Request to remove email sending limitations\" form for the static IP with the reverse DNS name.",
		"OVH: Bare Metal / VPS → IP → the address's \"…\" menu → Modify the reverse path.",
		"Elsewhere: ask your provider to set the PTR record of the address (only the address's owner can).",
	}
}

// fcrdns: the PTR of the public address resolves to a name that resolves
// back to it (through the public resolvers). reason "missing" (no PTR, or
// none of its names resolves) or "mismatch" (they resolve elsewhere).
func fcrdns(ctx context.Context, d Deps, ip netip.Addr, v6 bool) Check {
	c := Check{ID: "fcrdns_v4"}
	bad := Problem
	if v6 {
		c.ID, bad = "fcrdns_v6", Info
	}
	if !ip.IsValid() {
		if v6 {
			c.Severity, c.Detail = OK, "no public IPv6 address: outbound mail uses IPv4"
			return c
		}
		c.Severity, c.Reason = Warning, "missing"
		c.Detail = "the public IPv4 address isn't known (set PORTCULLIS_PUBLIC_IPV4 in .env): reverse DNS can't be checked"
		return c
	}
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		c.Severity, c.Reason, c.Detail = bad, "missing", err.Error()
		return c
	}
	m, err := query(ctx, d, d.Cfg.Resolvers, arpa, dns.TypePTR, false)
	if err != nil {
		c.Severity, c.Detail = Info, "reverse DNS couldn't be looked up: "+err.Error()
		return c
	}
	var names []string
	for _, rr := range m.Answer {
		if p, ok := rr.(*dns.PTR); ok {
			names = append(names, strings.ToLower(strings.TrimSuffix(p.Ptr, ".")))
		}
	}
	fail := func(reason, detail string) Check {
		c.Severity, c.Reason, c.Detail = bad, reason, detail
		c.Steps = PTRSteps(ip, d.Cfg.Hostname)
		if v6 {
			c.Detail += "; outbound mail uses IPv4 only until it's fixed"
		}
		return c
	}
	if len(names) == 0 {
		return fail("missing", fmt.Sprintf("%s has no reverse DNS (PTR) record", ip))
	}
	qt := dns.TypeA
	if v6 {
		qt = dns.TypeAAAA
	}
	resolved := false
	var elsewhere []string
	for _, n := range names {
		am, err := query(ctx, d, d.Cfg.Resolvers, n, qt, false)
		if err != nil {
			continue
		}
		for _, rr := range am.Answer {
			var a netip.Addr
			switch r := rr.(type) {
			case *dns.A:
				a, _ = netip.AddrFromSlice(r.A.To4())
			case *dns.AAAA:
				a, _ = netip.AddrFromSlice(r.AAAA)
			default:
				continue
			}
			resolved = true
			if a == ip {
				c.Severity, c.Detail = OK, fmt.Sprintf("%s ↔ %s", ip, n)
				if n != d.Cfg.Hostname {
					c.Detail += fmt.Sprintf(" (not %s, which some receivers prefer)", d.Cfg.Hostname)
				}
				return c
			}
			elsewhere = append(elsewhere, n+" → "+a.String())
		}
	}
	if !resolved {
		return fail("missing", fmt.Sprintf("%s's reverse DNS name %s doesn't resolve", ip, joinMax(names, 2)))
	}
	return fail("mismatch", fmt.Sprintf("%s's reverse DNS doesn't resolve back to it (%s)", ip, joinMax(elsewhere, 2)))
}
