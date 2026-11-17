package dnsplan

// The shared mail set rules (contract §19.7 "Set validation"): the one
// rule set the Hub's internal/mailprovider/dnsrules.go and the domains
// service's PUT /domains/{name}/sets/mail apply, held equal by the shared
// vectors (testdata/mail_dns_vectors.json, a byte copy of the Hub's). A
// record is allowed only with a name and value from the contract's table;
// the provider can't point mail at another host, widen SPF, receive
// reports elsewhere, lower DMARC or touch CAA, TLSA or address records.
//
// Per record, in list order (the first failing record is the answer):
// not under the domain → a type the set never holds → a name outside the
// table or the wrong type for the name → the value. Texts are
// "mail set: <name> <type>: <why>".

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

// RuleContext is what the rules judge a set against.
type RuleContext struct {
	Domain       string // the mail domain <e>
	MailHostname string // MAIL_HOSTNAME <h>
	RelayInclude string // the relay's SPF include ("" = none)
	DMARCFloor   string // none | quarantine | reject
	Wildcard     bool   // the domain's plan has a *.<e> address record (no CNAMEs then)
}

var (
	reSTS    = regexp.MustCompile(`^v=STSv1; id=[A-Za-z0-9]{1,32}$`)
	reTLSRPT = regexp.MustCompile(`^v=TLSRPTv1; rua=mailto:(\S+)$`)
	reSRV    = regexp.MustCompile(`^([0-9]{1,5}) ([0-9]{1,5}) ([0-9]{1,5}) (\S+)$`)
	reMX     = regexp.MustCompile(`^([0-9]{1,5}) (\S+)$`)
	reLabel1 = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
)

var dmarcRank = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

// The allowed types of the set.
var ruleTypes = map[string]bool{"MX": true, "TXT": true, "SRV": true, "CNAME": true}

// srvPorts: the SRV names with a service, by port; the others are "0 0 0 .".
var srvPorts = map[string]string{"_submissions._tcp": "465", "_submission._tcp": "587", "_imaps._tcp": "993"}
var srvNull = []string{"_imap._tcp", "_pop3._tcp", "_pop3s._tcp"}

// ValidateMailSet judges rs against c (contract §19.7): nil, or the first
// refusal's text.
func ValidateMailSet(c RuleContext, rs []MailRecord) error {
	e := bare(c.Domain)
	h := bare(c.MailHostname)
	spf := 0
	for _, r := range rs {
		n, t := bare(r.Name), strings.ToUpper(r.Type)
		refuse := func(why string) error { return fmt.Errorf("mail set: %s %s: %s", n, t, why) }
		if !under(n, e) {
			return refuse("not under " + e)
		}
		if !ruleTypes[t] {
			return refuse(t + " records are not allowed")
		}
		rel := strings.TrimSuffix(strings.TrimSuffix(n, e), ".")
		v := strings.TrimSpace(r.Value)
		switch {
		case n == e:
			switch t {
			case "MX":
				m := reMX.FindStringSubmatch(v)
				if m == nil || !strings.EqualFold(m[2], h+".") {
					return refuse("the target must be " + h + ".")
				}
			case "TXT":
				if !strings.HasPrefix(v, "v=spf1 ") {
					return refuse("only one v=spf1 TXT here")
				}
				spf++
				if spf > 1 {
					return refuse("more than one SPF record")
				}
				for _, term := range strings.Fields(v)[1:] {
					ok := term == "mx" || term == "-all" || term == "~all" ||
						(c.RelayInclude != "" && strings.EqualFold(term, "include:"+bare(c.RelayInclude)))
					if !ok {
						return refuse("SPF term " + term + " is not allowed")
					}
				}
			default:
				return refuse("only MX and TXT here")
			}
		case strings.HasSuffix(rel, "._domainkey") || rel == "_domainkey":
			sel := strings.TrimSuffix(rel, "._domainkey")
			if rel == "_domainkey" || strings.Contains(sel, ".") || !reLabel1.MatchString(sel) {
				return refuse("the DKIM selector must be one DNS label")
			}
			if t != "TXT" {
				return refuse("only TXT here")
			}
			if !strings.HasPrefix(v, "v=DKIM1;") {
				return refuse("must start with v=DKIM1;")
			}
		case rel == "_dmarc":
			if t != "TXT" {
				return refuse("only TXT here")
			}
			if err := dmarcRule(v, e, c.DMARCFloor); err != "" {
				return refuse(err)
			}
		case rel == "_mta-sts":
			if t != "TXT" {
				return refuse("only TXT here")
			}
			if !reSTS.MatchString(v) {
				return refuse("must be v=STSv1; id=<1–32 letters or digits>")
			}
		case rel == "_smtp._tls":
			if t != "TXT" {
				return refuse("only TXT here")
			}
			m := reTLSRPT.FindStringSubmatch(v)
			if m == nil || !onDomain(m[1], e) {
				return refuse("must be v=TLSRPTv1; rua=mailto:<an address on " + e + ">")
			}
		case srvPorts[rel] != "":
			if t != "SRV" {
				return refuse("only SRV here")
			}
			m := reSRV.FindStringSubmatch(v)
			if m == nil || m[3] != srvPorts[rel] || !strings.EqualFold(m[4], h+".") {
				return refuse("must be <priority> <weight> " + srvPorts[rel] + " " + h + ".")
			}
		case contains(srvNull, rel):
			if t != "SRV" {
				return refuse("only SRV here")
			}
			if strings.Join(strings.Fields(v), " ") != "0 0 0 ." {
				return refuse("must be 0 0 0 .")
			}
		case contains(mailCNAMELabels, rel):
			if t != "CNAME" {
				return refuse("only CNAME here")
			}
			if c.Wildcard {
				return refuse("only when the Hub asked with wildcard=false")
			}
			if !strings.EqualFold(v, h+".") {
				return refuse("the target must be " + h + ".")
			}
		default:
			return refuse("not a mail record name")
		}
	}
	return nil
}

// dmarcRule: "" or the why. p= at or above the floor, rua only mailto:
// addresses on e, no ruf.
func dmarcRule(v, e, floor string) string {
	if !strings.HasPrefix(v, "v=DMARC1;") {
		return "must start with v=DMARC1;"
	}
	p := ""
	for _, tag := range strings.Split(v, ";")[1:] {
		k, val, _ := strings.Cut(strings.TrimSpace(tag), "=")
		k, val = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(val)
		switch k {
		case "p":
			p = strings.ToLower(val)
		case "ruf":
			return "ruf is not allowed"
		case "rua":
			for _, u := range strings.Split(val, ",") {
				u = strings.TrimSpace(u)
				addr, ok := strings.CutPrefix(strings.ToLower(u), "mailto:")
				if !ok || !onDomain(addr, e) {
					return "rua " + u + " is not on " + e
				}
			}
		}
	}
	rp, ok := dmarcRank[p]
	if !ok {
		return "must carry p=none, quarantine or reject"
	}
	if rf, ok := dmarcRank[floor]; ok && rp < rf {
		return "p=" + p + " is below the floor " + floor
	}
	return ""
}

// onDomain: a is one address whose domain is exactly e.
func onDomain(a, e string) bool {
	m, err := mail.ParseAddress(a)
	if err != nil || m.Name != "" || m.Address != a {
		return false
	}
	i := strings.LastIndexByte(a, '@')
	return i > 0 && strings.EqualFold(a[i+1:], e)
}
