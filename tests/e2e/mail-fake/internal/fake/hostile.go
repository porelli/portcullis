package fake

import "github.com/portcullis/mail-fake/internal/mailprovider"

// Modes: honest serves the contract; hostile serves what the Hub must
// contain (core e2e-mail 12 hostile_provider_contained).
const (
	ModeHonest  = "honest"
	ModeHostile = "hostile"
)

// SetMode switches the fake (false: an unknown mode, nothing changed).
func (s *Server) SetMode(mode string) bool {
	switch mode {
	case ModeHonest, ModeHostile:
	default:
		return false
	}
	s.Lock(func(s *Server) { s.Hostile = mode == ModeHostile })
	return true
}

// hostileSet is the forbidden set for d: an A record, a foreign MX, an
// include: nobody asked for, DMARC below any floor, a CAA. The Hub's
// shared rules refuse each one (mail_records_wrong names them).
func hostileSet(d, host string) mailprovider.DNSSet {
	return mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{
		{Name: d, Type: "A", TTL: 3600, Value: "192.0.2.66"},
		{Name: d, Type: "MX", TTL: 3600, Value: "10 mx.attacker.example."},
		{Name: d, Type: "TXT", TTL: 3600, Value: "v=spf1 mx include:_spf.attacker.example -all"},
		{Name: "_dmarc." + d, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none"},
		{Name: d, Type: "CAA", TTL: 3600, Value: `0 issue "attacker-ca.example"`},
		{Name: d, Type: "MX", TTL: 3600, Value: "20 " + host + "."},
	}}
}

// honestSet is a set the Hub's shared rules accept for d: the MX on the
// mail host, SPF mx, DMARC reject with reports on d, MTA-STS, TLS-RPT and
// one DKIM key (selector "fake").
// HonestSet is honest mode's set for domain d (mail host host): every
// record one the shared DNS rules accept (domains/internal/dnsplan's
// TestMailFakeHonestSets judges testdata/honest_sets.json).
func HonestSet(d, host string) mailprovider.DNSSet { return honestSet(d, host) }

func honestSet(d, host string) mailprovider.DNSSet {
	return mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{
		{Name: d, Type: "MX", TTL: 3600, Value: "10 " + host + "."},
		{Name: d, Type: "TXT", TTL: 3600, Value: "v=spf1 mx -all"},
		{Name: "_dmarc." + d, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=reject; rua=mailto:dmarc-reports@" + d},
		{Name: "_mta-sts." + d, Type: "TXT", TTL: 3600, Value: "v=STSv1; id=fake1"},
		{Name: "_smtp._tls." + d, Type: "TXT", TTL: 3600, Value: "v=TLSRPTv1; rua=mailto:tls-reports@" + d},
		{Name: "fake._domainkey." + d, Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="},
	}}
}
