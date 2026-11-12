// Package dnssec checks a name's DNSSEC chain through public resolvers
// (miekg/dns): find the zone (SOA), read its DNSKEY set and the parent's
// DS set, compute DS from the zone's keys to match them, and ask every
// resolver whether it validates (AD), retrying a SERVFAIL with CD set to
// tell a broken chain from a failed lookup.
package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// State is a name's DNSSEC state (contract §12.2 plan dnssec.state).
type State string

const (
	Secure     State = "secure"
	Unsigned   State = "unsigned"
	DSMissing  State = "ds_missing"
	DSMismatch State = "ds_mismatch"
	Bogus      State = "bogus"
	Unknown    State = "unknown"
)

// DS is one delegation signer record.
type DS struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
}

// Result of Check.
type Result struct {
	State State
	// Zone is the zone apex (FQDN, trailing dot).
	Zone string
	// DS: computed from the zone's KSKs (digest type 2, SHA-256).
	DS []DS
	// ParentDS: the DS set the parent serves.
	ParentDS []DS
	Err      string
}

// StatusReader reads a zone's signing status and DS values from a
// provider's API.
type StatusReader interface {
	DNSSECStatus(ctx context.Context, zone string) (status string, ds []DS, err error)
}

// Signer can also turn signing on. There is deliberately no way to turn
// it off.
type Signer interface {
	StatusReader
	EnableDNSSEC(ctx context.Context, zone string) error
}

const timeout = 5 * time.Second

// exchange asks one resolver (DO set, CD as given), over TCP when the UDP
// answer is truncated.
func exchange(ctx context.Context, resolver, name string, qt uint16, cd bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.RecursionDesired = true
	m.CheckingDisabled = cd
	m.SetEdns0(4096, true)
	c := &dns.Client{Timeout: timeout}
	in, _, err := c.ExchangeContext(ctx, m, resolver)
	if err == nil && in.Truncated {
		c.Net = "tcp"
		in, _, err = c.ExchangeContext(ctx, m, resolver)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s at %s: %w", dns.TypeToString[qt], dns.Fqdn(name), resolver, err)
	}
	return in, nil
}

// first asks the resolvers in order and returns the first usable answer
// (NOERROR or NXDOMAIN).
func first(ctx context.Context, resolvers []string, name string, qt uint16) (*dns.Msg, error) {
	if len(resolvers) == 0 {
		return nil, errors.New("no resolvers")
	}
	var errs []error
	for _, r := range resolvers {
		in, err := exchange(ctx, r, name, qt, true)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
			errs = append(errs, fmt.Errorf("%s %s at %s: %s", dns.TypeToString[qt], dns.Fqdn(name), r, dns.RcodeToString[in.Rcode]))
			continue
		}
		return in, nil
	}
	return nil, errors.Join(errs...)
}

// FindZone returns the zone apex holding name (FQDN): the owner of the
// SOA in the answer or authority section, climbing one label at a time.
func FindZone(ctx context.Context, resolvers []string, name string) (string, error) {
	cur := strings.ToLower(dns.Fqdn(name))
	for {
		in, err := first(ctx, resolvers, cur, dns.TypeSOA)
		if err != nil {
			return "", err
		}
		for _, sec := range [][]dns.RR{in.Answer, in.Ns} {
			for _, rr := range sec {
				if soa, ok := rr.(*dns.SOA); ok {
					return strings.ToLower(dns.Fqdn(soa.Hdr.Name)), nil
				}
			}
		}
		i, end := dns.NextLabel(cur, 0)
		if end {
			return "", fmt.Errorf("no SOA found for %s", dns.Fqdn(name))
		}
		cur = cur[i:]
		if cur == "." {
			return "", fmt.Errorf("no SOA found for %s", dns.Fqdn(name))
		}
	}
}

func fromDS(d *dns.DS) DS {
	return DS{KeyTag: d.KeyTag, Algorithm: d.Algorithm, DigestType: d.DigestType, Digest: strings.ToUpper(d.Digest)}
}

// Check runs the chain check for name.
func Check(ctx context.Context, resolvers []string, name string) Result {
	unknown := func(zone string, err error) Result { return Result{State: Unknown, Zone: zone, Err: err.Error()} }
	zone, err := FindZone(ctx, resolvers, name)
	if err != nil {
		return unknown("", err)
	}
	res := Result{Zone: zone}
	in, err := first(ctx, resolvers, zone, dns.TypeDNSKEY)
	if err != nil {
		return unknown(zone, err)
	}
	var keys, ksks []*dns.DNSKEY
	for _, rr := range in.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
			if k.Flags&dns.SEP != 0 {
				ksks = append(ksks, k)
			}
		}
	}
	if len(ksks) == 0 {
		ksks = keys
	}
	for _, k := range ksks {
		if d := k.ToDS(dns.SHA256); d != nil {
			res.DS = append(res.DS, fromDS(d))
		}
	}
	in, err = first(ctx, resolvers, zone, dns.TypeDS)
	if err != nil {
		return unknown(zone, err)
	}
	var parent []*dns.DS
	for _, rr := range in.Answer {
		if d, ok := rr.(*dns.DS); ok {
			parent = append(parent, d)
			res.ParentDS = append(res.ParentDS, fromDS(d))
		}
	}
	switch {
	case len(keys) == 0 && len(parent) == 0:
		res.State = Unsigned
		return res
	case len(parent) == 0:
		res.State = DSMissing
		return res
	case len(keys) == 0:
		res.State = Bogus
		res.Err = "a DS is published but the zone serves no DNSKEY"
		return res
	}
	if !dsMatches(keys, parent) {
		res.State = DSMismatch
		return res
	}
	// The keys match: does every resolver validate?
	for _, r := range resolvers {
		a, err := exchange(ctx, r, name, dns.TypeA, false)
		if err != nil {
			return unknown(zone, err)
		}
		if a.Rcode == dns.RcodeServerFailure {
			cd, err := exchange(ctx, r, name, dns.TypeA, true)
			if err != nil {
				return unknown(zone, err)
			}
			if cd.Rcode == dns.RcodeServerFailure {
				return unknown(zone, fmt.Errorf("A %s at %s: SERVFAIL (also with CD)", dns.Fqdn(name), r))
			}
			res.State = Bogus
			res.Err = fmt.Sprintf("%s fails validation for %s (answers only with checking disabled)", r, dns.Fqdn(name))
			return res
		}
		if !a.AuthenticatedData {
			res.State = Bogus
			res.Err = fmt.Sprintf("%s doesn't validate %s (no AD)", r, dns.Fqdn(name))
			return res
		}
	}
	res.State = Secure
	return res
}

// dsMatches: some parent DS equals a DS computed from a zone key with the
// same digest type.
func dsMatches(keys []*dns.DNSKEY, parent []*dns.DS) bool {
	for _, p := range parent {
		for _, k := range keys {
			d := k.ToDS(p.DigestType)
			if d != nil && d.KeyTag == p.KeyTag && d.Algorithm == p.Algorithm && strings.EqualFold(d.Digest, p.Digest) {
				return true
			}
		}
	}
	return false
}
