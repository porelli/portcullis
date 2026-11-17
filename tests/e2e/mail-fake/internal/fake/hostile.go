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
