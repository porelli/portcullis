// Package dnsset renders a mail domain's wanted `mail` record set
// (contract §19.7): every record exactly as the domains service's mail set
// takes it (name, type, TTL, value; targets absolute).
package dnsset

import (
	"fmt"
	"sort"
)

// TTL of every record of the set (CAA at MAIL_HOSTNAME is mail-cert's).
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
	Main       bool   // the main domain: MAIL_HOSTNAME's HELO SPF and TLSA
	Hostname   string // MAIL_HOSTNAME
	SPFInclude string // MAIL_RELAY_SPF_INCLUDE
	Mail       string // on | draining | off
	DMARC      string // none | quarantine | reject
	DKIM       []DKIMRecord
	MTASTSID   string   // "" = no _mta-sts record
	TLSA       []string // SPKI sha256 hex; only on the main domain, only while secure
	// NoWildcard: an added domain whose plan has no *.<e> address record
	// gets CNAME <h>. at mta-sts / autoconfig / autodiscover (never the
	// main domain: its *.<d> is core's).
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
	if in.Main {
		add(in.Hostname, "TXT", "v=spf1 a -all")
	}
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
	if in.NoWildcard && !in.Main {
		for _, l := range []string{"mta-sts.", "autoconfig.", "autodiscover."} {
			add(l+in.Domain, "CNAME", h)
		}
	}
	if in.Main {
		for _, spki := range in.TLSA {
			add("_25._tcp."+in.Hostname, "TLSA", "3 1 1 "+spki)
		}
	}
	return out
}
