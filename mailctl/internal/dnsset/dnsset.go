// Package dnsset renders a mail domain's wanted `mail` record set
// (contract §19.7): every record exactly as the domains service's mail set
// takes it (name, type, TTL, value; targets absolute).
package dnsset

import (
	"fmt"
	"sort"
)

// TTL of every record of the set. Never A, AAAA, CAA or TLSA, and nothing
// at MAIL_HOSTNAME: its CAA is mail-cert's, its TLSA, HELO SPF and address
// records are core's (contract §19.3, §19.7).
const TTL = 3600

// Record is one wanted record.
type Record struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   int    `json:"ttl"`
	Value string `json:"value"`
}

// DKIMRecord is one published DKIM key.
type DKIMRecord struct{ Selector, Value string }

// Input is one domain's state.
type Input struct {
	Domain     string
	Hostname   string // MAIL_HOSTNAME (the document's mail_hostname)
	SPFInclude string // the relay's spf_include
	Mail       string // on | draining | off
	DMARC      string // none | quarantine | reject
	DKIM       []DKIMRecord
	MTASTSID   string // "" = no _mta-sts record
	// NoWildcard: the Hub asked with wildcard=false (the domain's plan has
	// no *.<e> address record): CNAME <h>. at mta-sts / autoconfig /
	// autodiscover.
	NoWildcard bool
}

// Wanted is the domain's mail set: on → the full table; draining → only
// _mta-sts (the policy says mode none); off → nothing.
func Wanted(in Input) []Record {
	var out []Record
	add := func(name, typ, value string) {
		out = append(out, Record{Name: name, Type: typ, TTL: TTL, Value: value})
	}
	h := in.Hostname + "."
	switch in.Mail {
	case "draining":
		if in.MTASTSID != "" {
			add("_mta-sts."+in.Domain, "TXT", "v=STSv1; id="+in.MTASTSID)
		}
		return out
	case "on":
	default:
		return nil
	}
	add(in.Domain, "MX", "10 "+h)
	spf := "v=spf1 mx"
	if in.SPFInclude != "" {
		spf += " include:" + in.SPFInclude
	}
	add(in.Domain, "TXT", spf+" -all")
	dk := append([]DKIMRecord(nil), in.DKIM...)
	sort.Slice(dk, func(i, j int) bool { return dk[i].Selector < dk[j].Selector })
	for _, k := range dk {
		add(k.Selector+"._domainkey."+in.Domain, "TXT", k.Value)
	}
	add("_dmarc."+in.Domain, "TXT", fmt.Sprintf("v=DMARC1; p=%s; adkim=s; aspf=s; rua=mailto:dmarc-reports@%s", in.DMARC, in.Domain))
	if in.MTASTSID != "" {
		add("_mta-sts."+in.Domain, "TXT", "v=STSv1; id="+in.MTASTSID)
	}
	add("_smtp._tls."+in.Domain, "TXT", "v=TLSRPTv1; rua=mailto:tls-reports@"+in.Domain)
	add("_submissions._tcp."+in.Domain, "SRV", "0 1 465 "+h)
	add("_imaps._tcp."+in.Domain, "SRV", "0 1 993 "+h)
	add("_submission._tcp."+in.Domain, "SRV", "0 1 587 "+h)
	for _, s := range []string{"_imap._tcp.", "_pop3._tcp.", "_pop3s._tcp."} {
		add(s+in.Domain, "SRV", "0 0 0 .")
	}
	if in.NoWildcard {
		for _, l := range []string{"mta-sts.", "autoconfig.", "autodiscover."} {
			add(l+in.Domain, "CNAME", h)
		}
	}
	return out
}
