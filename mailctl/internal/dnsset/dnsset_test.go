package dnsset

import (
	"encoding/json"
	"strings"
	"testing"
)

func lines(rs []Record) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(r.Name + " " + r.Type + " " + r.Value + "\n")
	}
	return b.String()
}

func TestWantedMatchesSpecTable(t *testing.T) {
	main := Input{Domain: "example.com", Hostname: "mail.example.com", Mail: "on", DMARC: "reject",
		DKIM:     []DKIMRecord{{"v1-rsa-20261115", "v=DKIM1; k=rsa; p=R"}, {"v1-ed25519-20261115", "v=DKIM1; k=ed25519; p=E"}},
		MTASTSID: "0123456789abcdef0123T1794700000"}
	want := `example.com MX 10 mail.example.com.
example.com TXT v=spf1 mx -all
v1-ed25519-20261115._domainkey.example.com TXT v=DKIM1; k=ed25519; p=E
v1-rsa-20261115._domainkey.example.com TXT v=DKIM1; k=rsa; p=R
_dmarc.example.com TXT v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:dmarc-reports@example.com
_mta-sts.example.com TXT v=STSv1; id=0123456789abcdef0123T1794700000
_smtp._tls.example.com TXT v=TLSRPTv1; rua=mailto:tls-reports@example.com
_submissions._tcp.example.com SRV 0 1 465 mail.example.com.
_imaps._tcp.example.com SRV 0 1 993 mail.example.com.
_submission._tcp.example.com SRV 0 1 587 mail.example.com.
_imap._tcp.example.com SRV 0 0 0 .
_pop3._tcp.example.com SRV 0 0 0 .
_pop3s._tcp.example.com SRV 0 0 0 .
`
	if got := lines(Wanted(main)); got != want {
		t.Fatalf("main:\n%s\nwant:\n%s", got, want)
	}
	added := main
	added.Domain, added.DMARC, added.SPFInclude, added.MTASTSID = "team-b.example.org", "none", "spf.relay.example", ""
	got := lines(Wanted(added))
	for _, w := range []string{"team-b.example.org TXT v=spf1 mx include:spf.relay.example -all", "p=none", "team-b.example.org MX 10 mail.example.com."} {
		if !strings.Contains(got, w) {
			t.Errorf("added domain lacks %q:\n%s", w, got)
		}
	}
	for _, no := range []string{"TLSA", "mail.example.com TXT", "_mta-sts", "CAA"} {
		if strings.Contains(got, no) {
			t.Errorf("added domain has %q:\n%s", no, got)
		}
	}
	for _, r := range Wanted(main) {
		if r.TTL != 3600 {
			t.Fatalf("TTL %d", r.TTL)
		}
	}
	b, _ := json.Marshal(Wanted(main)[0])
	if string(b) != `{"name":"example.com","type":"MX","ttl":3600,"value":"10 mail.example.com."}` {
		t.Fatalf("json %s", b)
	}
}

func TestDrainingAndOff(t *testing.T) {
	in := Input{Domain: "example.com", Hostname: "mail.example.com", Mail: "draining", DMARC: "reject", MTASTSID: "x"}
	if got := lines(Wanted(in)); got != "_mta-sts.example.com TXT v=STSv1; id=x\n" {
		t.Fatalf("draining: %s", got)
	}
	in.Mail = "off"
	if len(Wanted(in)) != 0 {
		t.Fatal("off: records")
	}
}

// A domain without a wildcard address record (the Hub asked with
// wildcard=false): the three CNAMEs; never while draining.
func TestCNAMEsWithoutWildcard(t *testing.T) {
	in := Input{Domain: "team-b.example.org", Hostname: "mail.example.com", Mail: "on", DMARC: "none", NoWildcard: true}
	n := 0
	for _, r := range Wanted(in) {
		if r.Type == "CNAME" {
			n++
			if r.Value != "mail.example.com." || !(r.Name == "mta-sts.team-b.example.org" || r.Name == "autoconfig.team-b.example.org" || r.Name == "autodiscover.team-b.example.org") {
				t.Fatalf("%+v", r)
			}
		}
	}
	if n != 3 {
		t.Fatalf("%d CNAMEs", n)
	}
	in.Mail = "draining"
	for _, r := range Wanted(in) {
		if r.Type == "CNAME" {
			t.Fatal("CNAME while draining")
		}
	}
}

// The provider's set never carries a record the contract keeps for core
// or mail-cert (§19.3, §19.7): no TLSA, no A / AAAA / CAA, and nothing at
// MAIL_HOSTNAME (its HELO SPF and address records are core's), on any
// domain, in any state, with or without a relay or the CNAMEs.
func TestDNSSetHasNoTLSAOrHELO(t *testing.T) {
	for _, mail := range []string{"on", "draining", "off"} {
		for _, wild := range []bool{false, true} {
			in := Input{Domain: "example.com", Hostname: "mail.example.com", Mail: mail, DMARC: "reject", SPFInclude: "_spf.relay.example",
				MTASTSID: "x", NoWildcard: wild, DKIM: []DKIMRecord{{"v1-ed25519-20261115", "v=DKIM1; k=ed25519; p=E"}}}
			for _, r := range Wanted(in) {
				switch {
				case r.Type == "TLSA" || r.Type == "A" || r.Type == "AAAA" || r.Type == "CAA":
					t.Errorf("%s %v: %+v", mail, wild, r)
				case r.Name == "mail.example.com" || strings.HasSuffix(r.Name, ".mail.example.com"):
					t.Errorf("%s %v: a record at MAIL_HOSTNAME %+v", mail, wild, r)
				}
			}
		}
	}
}
