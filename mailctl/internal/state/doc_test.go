package state

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func vector(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/mailstate_v2.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MailState v2: the contract's vector (a byte copy of the Hub's) decodes,
// and encodes back to the same values.
func TestMailStateV2Vector(t *testing.T) {
	b := vector(t)
	d, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Generation != 12 || d.PrimaryDomain != "example.com" || len(d.Accounts) != 3 || d.Lists[0].Posting != "members" || d.Spam.DNSBL.Barracuda != true ||
		d.MailHostname != "mail.example.com" || d.Rewritten() || d.SPFInclude() != "_spf.relay.example.net" || d.Relay.Port != 465 ||
		Period(d.DKIMRotate) != 4320*time.Hour || Period(d.FormerRetention) != 720*time.Hour || len(d.TLS.SPKISHA256) != 1 ||
		d.Domains[1].DMARCFloor != "none" {
		t.Fatalf("decoded %+v", d)
	}
	// relay null: deliver directly.
	nd, err := Parse([]byte(strings.Replace(string(b), `"relay":{"host":"smtp.relay.example.net","port":465,"username":"portcullis","spf_include":"_spf.relay.example.net"}`, `"relay":null`, 1)))
	if err != nil || nd.Relay != nil || nd.SPFInclude() != "" {
		t.Fatalf("relay null: %v", err)
	}
	out, _ := json.Marshal(d)
	var a, z any
	json.Unmarshal(b, &a)
	json.Unmarshal(out, &z)
	ab, _ := json.Marshal(a)
	zb, _ := json.Marshal(z)
	if string(ab) != string(zb) {
		t.Fatalf("round trip differs:\n%s\n%s", ab, zb)
	}
}

func TestParseRefuses(t *testing.T) {
	base := string(vector(t))
	rep := func(old, new string) string {
		if !strings.Contains(base, old) {
			t.Fatalf("vector lacks %q", old)
		}
		return strings.Replace(base, old, new, 1)
	}
	cases := map[string]string{
		"another version":               rep(`"version":2`, `"version":1`),
		"bad hostname":                  rep(`"mail_hostname":"mail.example.com"`, `"mail_hostname":"mail"`),
		"bad client_ip":                 rep(`"client_ip":"preserved"`, `"client_ip":"nat"`),
		"lan only not bool":             rep(`"submission_lan_only":false`, `"submission_lan_only":"no"`),
		"rotate too short":              rep(`"dkim_rotate":"4320h"`, `"dkim_rotate":"23h"`),
		"retention too long":            rep(`"former_retention":"720h"`, `"former_retention":"8761h"`),
		"retention not a duration":      rep(`"former_retention":"720h"`, `"former_retention":"30d"`),
		"relay port":                    rep(`"port":465`, `"port":0`),
		"relay host":                    rep(`"host":"smtp.relay.example.net"`, `"host":"not a host"`),
		"relay missing key":             rep(`,"spf_include":"_spf.relay.example.net"`, ``),
		"relay bad include":             rep(`"spf_include":"_spf.relay.example.net"`, `"spf_include":"a b"`),
		"tls null":                      rep(`"tls":{"spki_sha256":["99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"]}`, `"tls":null`),
		"no spki":                       rep(`"spki_sha256":["99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"]`, `"spki_sha256":[]`),
		"three spki":                    rep(`"spki_sha256":["99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"]`, `"spki_sha256":["99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6","99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6","99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"]`),
		"uppercase spki":                rep(`"99ad5d8130ef75b24fa9a72e9ca7d0db45cee16a25405bdaa9d317a6d9dac9c6"`, `"99AD5D8130EF75B24FA9A72E9CA7D0DB45CEE16A25405BDAA9D317A6D9DAC9C6"`),
		"bad floor":                     rep(`"dmarc_floor":"reject"`, `"dmarc_floor":"strict"`),
		"missing floor":                 rep(`"dmarc_floor":"none",`, ``),
		"unknown key":                   rep(`"confirm_mass_removal":false`, `"confirm_mass_removal":false,"extra":1`),
		"duplicate key":                 rep(`"confirm_mass_removal":false`, `"confirm_mass_removal":false,"confirm_mass_removal":true`),
		"duplicate nested key":          rep(`"username":"bob",`, `"username":"bob","username":"bob",`),
		"missing key":                   rep(`"confirm_mass_removal":false,`, ``),
		"missing nested key":            rep(`"dnssec":"secure"`, `"dnssec":"secure","x":1`),
		"missing nested key 2":          rep(`,"dnssec":"secure"`, ``),
		"null list":                     rep(`"postmaster":["root"]`, `"postmaster":null`),
		"trailing data":                 base + `{}`,
		"address on another domain":     rep(`"bob@example.com"]`, `"bob@example.com","bob@other.example"]`),
		"address twice":                 rep(`"address":"sales@example.com"`, `"address":"alice@team-b.example.org"`),
		"alias = a list":                rep(`"address":"sales@example.com"`, `"address":"team@example.com"`),
		"reserved local part":           rep(`"address":"sales@example.com"`, `"address":"postmaster@example.com"`),
		"reserved list":                 rep(`"address":"team@example.com"`, `"address":"abuse@example.com"`),
		"bad username":                  rep(`"username":"bob"`, `"username":"Bob B"`),
		"bad uuid":                      rep(`"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"`, `"0b9d8c7a"`),
		"uuid twice":                    rep(`"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"`, `"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"`),
		"negative quota":                rep(`"quota_bytes":10737418240}],`, `"quota_bytes":-1}],`),
		"limits too high":               rep(`"recipients_per_day":1000`, `"recipients_per_day":100001`),
		"limits zero":                   rep(`"recipients_per_hour":300`, `"recipients_per_hour":0`),
		"junk >= reject":                rep(`"junk_score":5`, `"junk_score":15`),
		"reject > 100":                  rep(`"reject_score":15`, `"reject_score":101`),
		"list member not an account":    rep(`"members":["alice","bob"]`, `"members":["alice","carol"]`),
		"postmaster not an account":     rep(`"postmaster":["root"]`, `"postmaster":["carol"]`),
		"primary not first":             rep(`"addresses":["alice@example.com","alice@team-b.example.org"]`, `"addresses":["alice@team-b.example.org","alice@example.com"]`),
		"primary domain not in domains": rep(`"primary_domain":"example.com"`, `"primary_domain":"example.net"`),
		"parking domain":                rep(`{"name":"team-b.example.org"`, `{"name":"portcullis-former.internal"`),
		"bad mail state":                rep(`"mail":"on","dnssec":"unsigned"`, `"mail":"paused","dnssec":"unsigned"`),
		"bad local network":             rep(`"10.0.0.0/8"`, `"10.0.0.1/8"`),
		"anywhere v4":                   rep(`"10.0.0.0/8"`, `"0.0.0.0/0"`),
		"anywhere v6":                   rep(`"10.0.0.0/8"`, `"::/0"`),
		"half the internet":             rep(`"10.0.0.0/8"`, `"0.0.0.0/1","128.0.0.0/1"`),
		"public /8":                     rep(`"10.0.0.0/8"`, `"11.0.0.0/8"`),
		"public v6 /16":                 rep(`"10.0.0.0/8"`, `"2001::/16"`),
		"mapped IPv4":                   rep(`"10.0.0.0/8"`, `"::ffff:0.0.0.0/96"`),
		"NAT64":                         rep(`"10.0.0.0/8"`, `"64:ff9b::/96"`),
		"bad allow entry":               rep(`"allow":["example.org"]`, `"allow":["not a domain"]`),
		"uppercase address":             rep(`"bob@example.com"]`, `"bob@example.com","Bob2@example.com"]`),
		"generation zero":               rep(`"generation":12`, `"generation":0`),
		"bad posting":                   rep(`"posting":"members"`, `"posting":"open"`),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := Parse(vector(t))
	if err := s.Update(func(p *Persistent) error { p.Doc, p.Generation = d, d.Generation; return nil }); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dir + "/state.json")
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	s2, err := Open(dir)
	if err != nil || s2.Get().Generation != 12 || s2.Get().Doc.PrimaryDomain != "example.com" {
		t.Fatalf("reopen: %v %+v", err, s2.Get())
	}
}

// The local_networks ruling: an IPv6 network overlapping a range that
// names IPv4 space is refused whatever its start, and one outside ULA,
// link-local and global unicast; the minimum widths stay.
func TestLocalNetworkOK(t *testing.T) {
	refused := []string{
		"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "11.0.0.0/8", "8.0.0.0/15",
		"::ffff:0:0/96", "::ffff:10.0.0.0/104", "::ffff:0:0/95", "::/64", "::/96", "::1/128", "::/127",
		"64:ff9b::/96", "64:ff9b::/64", "64:ff9b:1::/48", "64:ff9b:1:2::/64", "64:ff9b::/32",
		"2001::/16", "2000::/3", "2000::/31", "ff02::/16", "100::/64", "3fff::/20",
	}
	for _, n := range refused {
		if err := LocalNetworkOK(netip.MustParsePrefix(n)); err == nil {
			t.Errorf("%s accepted", n)
		}
	}
	accepted := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24", "100.64.0.0/10", "203.0.113.0/24", "198.51.0.0/16",
		"fd00::/8", "fc00::/7", "fe80::/10", "2001:db8::/32", "2001:db8:1::/48", "2a01:4f8:1:2::/64",
	}
	for _, n := range accepted {
		if err := LocalNetworkOK(netip.MustParsePrefix(n)); err != nil {
			t.Errorf("%s refused: %v", n, err)
		}
	}
}

func sendersVector(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/mailstate_v2_senders.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The contract's MailState v2 vector with senders (§19.5, §19.14; a byte
// copy of the contract's block) decodes and encodes back to the same
// values.
func TestMailStateV2SendersVector(t *testing.T) {
	b := sendersVector(t)
	d, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !d.SendersPresent() || len(d.SenderList()) != 2 || d.SenderList()[0].Username != "portcullis-hub-mail" ||
		d.SenderList()[1].Address != "portcullis-app-firefox-sync-fxa@example.com" || d.SenderList()[1].UUID != "7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e" {
		t.Fatalf("senders %+v", d.SenderList())
	}
	out, _ := json.Marshal(d)
	var a, z any
	json.Unmarshal(b, &a)
	json.Unmarshal(out, &z)
	ab, _ := json.Marshal(a)
	zb, _ := json.Marshal(z)
	if string(ab) != string(zb) {
		t.Fatalf("round trip differs:\n%s\n%s", ab, zb)
	}
	// The vector without senders is the older Hub's document, byte for
	// byte (testdata/mailstate_v2.json, the Hub's current copy).
	old := strings.Replace(string(b), ` "senders":[{"username":"portcullis-hub-mail","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-hub-mail@example.com"},
            {"username":"portcullis-app-firefox-sync-fxa","uuid":"7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e","address":"portcullis-app-firefox-sync-fxa@example.com"}],
`, "", 1)
	if old != string(vector(t)) {
		t.Fatal("mailstate_v2_senders.json minus its senders isn't mailstate_v2.json")
	}
}

// senders is optional (ruling C1): absent = an older Hub (existing
// senders left untouched), present and empty = remove every sender. Both
// survive the store's round trip as they are.
func TestSendersAbsentOrEmpty(t *testing.T) {
	d, err := Parse(vector(t))
	if err != nil {
		t.Fatalf("absent: %v", err)
	}
	if d.SendersPresent() || d.Senders != nil {
		t.Fatalf("absent senders read as present: %+v", d.Senders)
	}
	empty := strings.Replace(string(vector(t)), `"aliases":`, `"senders":[],"aliases":`, 1)
	e, err := Parse([]byte(empty))
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if !e.SendersPresent() || len(e.SenderList()) != 0 {
		t.Fatalf("empty senders read as %+v (present %v)", e.SenderList(), e.SendersPresent())
	}
	dir := t.TempDir()
	for name, doc := range map[string]*Doc{"absent": d, "empty": e} {
		st, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Update(func(p *Persistent) error { p.Doc = doc; return nil }); err != nil {
			t.Fatal(err)
		}
		re, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := re.Get().Doc; got.SendersPresent() != doc.SendersPresent() || len(got.SenderList()) != len(doc.SenderList()) {
			t.Errorf("%s: after the store's round trip present=%v len=%d", name, got.SendersPresent(), len(got.SenderList()))
		}
	}
}

// A malformed senders entry refuses the whole document (contract §19.5).
func TestParseRefusesSenders(t *testing.T) {
	base := string(sendersVector(t))
	rep := func(old, new string) string {
		if !strings.Contains(base, old) {
			t.Fatalf("vector lacks %q", old)
		}
		return strings.Replace(base, old, new, 1)
	}
	hub := `{"username":"portcullis-hub-mail","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-hub-mail@example.com"}`
	cases := map[string]string{
		"senders null":            strings.Replace(string(vector(t)), `"aliases":`, `"senders":null,"aliases":`, 1),
		"unknown key":             rep(hub, `{"username":"portcullis-hub-mail","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-hub-mail@example.com","label":"x"}`),
		"missing address":         rep(hub, `{"username":"portcullis-hub-mail","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"}`),
		"missing uuid":            rep(hub, `{"username":"portcullis-hub-mail","address":"portcullis-hub-mail@example.com"}`),
		"null username":           rep(hub, `{"username":null,"uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-hub-mail@example.com"}`),
		"duplicate key":           rep(hub, `{"username":"portcullis-hub-mail","username":"portcullis-hub-mail","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-hub-mail@example.com"}`),
		"not a list":              strings.Replace(string(vector(t)), `"aliases":`, `"senders":`+hub+`,"aliases":`, 1),
		"senders twice":           rep(`"aliases":`, `"senders":[],"aliases":`),
		"a person's username":     rep(hub, `{"username":"alice","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"alice@example.com"}`),
		"another form":            rep(hub, `{"username":"portcullis-mail","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-mail@example.com"}`),
		"uppercase":               rep(hub, `{"username":"portcullis-app-Fxa","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-app-Fxa@example.com"}`),
		"empty instance":          rep(hub, `{"username":"portcullis-app-","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-app-@example.com"}`),
		"instance too long":       rep(hub, `{"username":"portcullis-app-a234567890123456789012345678901234","uuid":"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d","address":"portcullis-app-a234567890123456789012345678901234@example.com"}`),
		"bad uuid":                rep(`"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`, `"1a2b3c4d"`),
		"uppercase uuid":          rep(`"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`, `"1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D"`),
		"address of another":      rep(`"address":"portcullis-hub-mail@example.com"`, `"address":"portcullis-app-firefox-sync-fxa@example.com"`),
		"address another local":   rep(`"address":"portcullis-hub-mail@example.com"`, `"address":"hub@example.com"`),
		"address another domain":  rep(`"address":"portcullis-hub-mail@example.com"`, `"address":"portcullis-hub-mail@team-b.example.org"`),
		"address on no domain":    rep(`"address":"portcullis-hub-mail@example.com"`, `"address":"portcullis-hub-mail@example.net"`),
		"address not an address":  rep(`"address":"portcullis-hub-mail@example.com"`, `"address":"portcullis-hub-mail"`),
		"username twice":          rep(`"username":"portcullis-app-firefox-sync-fxa","uuid":"7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e","address":"portcullis-app-firefox-sync-fxa@example.com"`, `"username":"portcullis-hub-mail","uuid":"7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e","address":"portcullis-hub-mail@example.com"`),
		"uuid twice":              rep(`"7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e"`, `"1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"`),
		"a person's uuid":         rep(`"7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e"`, `"6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"`),
		"a person named a sender": strings.Replace(rep(`"username":"bob","uuid":"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d","display_name":"Bob B.","addresses":["bob@example.com"]`, `"username":"portcullis-app-firefox-sync-fxa","uuid":"0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d","display_name":"Bob B.","addresses":["portcullis-app-firefox-sync-fxa@example.com"]`), `"members":["alice","bob"]`, `"members":["alice","portcullis-app-firefox-sync-fxa"]`, 1),
		"a person's alias":        rep(`"aliases":[{"address":"sales@example.com","username":"alice"}]`, `"aliases":[{"address":"portcullis-hub-mail@example.com","username":"alice"}]`),
		"a person's 2nd address":  rep(`"addresses":["bob@example.com"]`, `"addresses":["bob@example.com","portcullis-app-firefox-sync-fxa@example.com"]`),
		"a list's address":        rep(`"address":"team@example.com"`, `"address":"portcullis-hub-mail@example.com"`),
		"a sender as postmaster":  rep(`"postmaster":["root"]`, `"postmaster":["portcullis-hub-mail"]`),
		"a sender as list member": rep(`"members":["alice","bob"]`, `"members":["alice","portcullis-hub-mail"]`),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
