package state

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func vector(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/mailstate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The contract's vector (a byte copy of the Hub's) decodes, and encodes
// back to the same values.
func TestDocMatchesContractVector(t *testing.T) {
	b := vector(t)
	d, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Generation != 12 || d.PrimaryDomain != "example.com" || len(d.Accounts) != 3 || d.Lists[0].Posting != "members" || d.Spam.DNSBL.Barracuda != true {
		t.Fatalf("decoded %+v", d)
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
		"another version":               rep(`"version":1`, `"version":2`),
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
