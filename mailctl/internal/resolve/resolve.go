// Package resolve asks DNS servers directly (the public resolvers for the
// DKIM check, mail-resolver for the others) with miekg/dns.
package resolve

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TXT returns the TXT values at name from server (ip:port): each record's
// strings joined (a long DKIM key is several ≤ 255-byte strings).
func TXT(ctx context.Context, server, name string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	c := &dns.Client{Timeout: 5 * time.Second}
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, server)
	}
	if err != nil {
		return nil, fmt.Errorf("TXT %s at %s: %w", name, server, err)
	}
	switch in.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
	default:
		return nil, fmt.Errorf("TXT %s at %s: %s", name, server, dns.RcodeToString[in.Rcode])
	}
	var out []string
	for _, rr := range in.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// VisibleAll reports every server serving exactly value at name (a failed
// lookup is false).
func VisibleAll(ctx context.Context, servers []string, name, value string) bool {
	if len(servers) == 0 {
		return false
	}
	for _, s := range servers {
		vals, err := TXT(ctx, s, name)
		if err != nil {
			return false
		}
		found := false
		for _, v := range vals {
			if v == value {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Query asks server one question (recursion desired, EDNS0; dnssec sets
// the DO bit), over TCP when the UDP answer is truncated. Any rcode is
// returned in the message; err is a transport failure.
func Query(ctx context.Context, server, name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, dnssec)
	c := &dns.Client{Timeout: 5 * time.Second}
	in, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, server)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s at %s: %w", dns.TypeToString[qtype], name, server, err)
	}
	return in, nil
}
