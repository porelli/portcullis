package dnsplan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type ruleVectors struct {
	Context map[string]any `json:"context"`
	Cases   []struct {
		Name      string         `json:"name"`
		Context   map[string]any `json:"context"`
		Records   []MailRecord   `json:"records"`
		WantError string         `json:"want_error"`
	} `json:"cases"`
}

func ruleContext(t *testing.T, base, over map[string]any) RuleContext {
	t.Helper()
	m := map[string]any{}
	for k, v := range base {
		m[k] = v
	}
	for k, v := range over {
		m[k] = v
	}
	var c struct {
		Domain       string `json:"domain"`
		MailHostname string `json:"mail_hostname"`
		RelayInclude string `json:"relay_include"`
		DMARCFloor   string `json:"dmarc_floor"`
		Wildcard     bool   `json:"wildcard"`
		Draining     bool   `json:"draining"`
	}
	b, _ := json.Marshal(m)
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return RuleContext{Domain: c.Domain, MailHostname: c.MailHostname, RelayInclude: c.RelayInclude, DMARCFloor: c.DMARCFloor, Wildcard: c.Wildcard, Draining: c.Draining}
}

// The shared vectors (a byte copy of the Hub's; CI compares them): every
// case judged as the Hub judges it, with the same text.
func TestMailRuleVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/mail_dns_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v ruleVectors
	if err := json.Unmarshal(b, &v); err != nil || len(v.Cases) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for _, c := range v.Cases {
		err := ValidateMailSet(ruleContext(t, v.Context, c.Context), c.Records)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != c.WantError {
			t.Errorf("%s: got %q, want %q", c.Name, got, c.WantError)
		}
	}
}

// M5: a set the shared rules accept (any one-label selector, a TTL in
// the rules' 60–86400) passes the structural check too: the Hub and core
// agree.
func TestSharedRulesAndStructureAgree(t *testing.T) {
	c := RuleContext{Domain: "example.com", MailHostname: "mail.example.com", DMARCFloor: "none"}
	recs := []MailRecord{
		{Name: "default._domainkey.example.com", Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=rsa; p=AAAA"},
		{Name: "example.com", Type: "MX", TTL: 60, Value: "10 mail.example.com."},
	}
	if err := ValidateMailSet(c, recs); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMail("example.com", recs); err != nil {
		t.Fatalf("structural check refuses what the rules accept: %v", err)
	}
}

// The value-shape rules (the Hub's M12; core-local until the 76-case
// vectors arrive): each refusal's text, in the rules' order.
func TestMailSetValueShape(t *testing.T) {
	const e, h = "example.com", "mail.example.com"
	c := RuleContext{Domain: e, MailHostname: h, DMARCFloor: "none"}
	mx := MailRecord{Name: e, Type: "MX", TTL: 3600, Value: "10 " + h + "."}
	for want, r := range map[string]MailRecord{
		"mail set: example.com MX: ttl must be 60–86400":                                                  {Name: e, Type: "MX", TTL: 59, Value: "10 " + h + "."},
		"mail set: example.com MX: ttl must be 60–86400 ":                                                 {Name: e, Type: "MX", TTL: 86401, Value: "10 " + h + "."},
		"mail set: example.com TXT: the value must be printable ASCII":                                    {Name: e, Type: "TXT", TTL: 3600, Value: "v=spf1 mx\t-all"},
		"mail set: _dmarc.example.com TXT: the value is longer than 2048 characters":                      {Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none; " + strings.Repeat("x", 2040)},
		"mail set: example.com MX: the value is longer than 255 characters":                               {Name: e, Type: "MX", TTL: 3600, Value: "10 " + strings.Repeat("a", 260) + "."},
		"mail set: example.com MX: the priority must be 0–65535":                                          {Name: e, Type: "MX", TTL: 3600, Value: "70000 " + h + "."},
		"mail set: _submissions._tcp.example.com SRV: priority and weight must be 0–65535":                {Name: "_submissions._tcp." + e, Type: "SRV", TTL: 3600, Value: "0 99999 465 " + h + "."},
		"mail set: s1._domainkey.example.com TXT: the DKIM tags must be <name>=<value>, with p=<base64>":  {Name: "s1._domainkey." + e, Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=rsa"},
		"mail set: s1._domainkey.example.com TXT: the DKIM tags must be <name>=<value>, with p=<base64> ": {Name: "s1._domainkey." + e, Type: "TXT", TTL: 3600, Value: "v=DKIM1; p=AA; p=BB"},
		"mail set: _dmarc.example.com TXT: adkim must be r or s":                                          {Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none; adkim=x"},
		"mail set: _dmarc.example.com TXT: aspf must be r or s":                                           {Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none; aspf=relaxed"},
		"mail set: _dmarc.example.com TXT: fo must be 0, 1, d or s, colon-separated":                      {Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none; fo=1:x"},
		"mail set: _dmarc.example.com TXT: rf must be afrf":                                               {Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none; rf=iodef"},
		"mail set: _dmarc.example.com TXT: ri must be a whole number of seconds":                          {Name: "_dmarc." + e, Type: "TXT", TTL: 3600, Value: "v=DMARC1; p=none; ri=1h"},
	} {
		recs := []MailRecord{r}
		if r.Name != e || r.Type != "MX" {
			recs = append([]MailRecord{mx}, r)
		}
		err := ValidateMailSet(c, recs)
		if err == nil || err.Error() != strings.TrimSpace(want) {
			t.Errorf("%v: got %v, want %q", r, err, strings.TrimSpace(want))
		}
	}
	ok := []MailRecord{mx,
		{Name: "s1._domainkey." + e, Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=rsa; p="},
		{Name: "_dmarc." + e, Type: "TXT", TTL: 86400, Value: "v=DMARC1; p=none; adkim=s; aspf=r; fo=0:1:d:s; rf=afrf; ri=86400"},
		{Name: "_submissions._tcp." + e, Type: "SRV", TTL: 60, Value: "0 65535 465 " + h + "."},
	}
	if err := ValidateMailSet(c, ok); err != nil {
		t.Fatalf("a well-shaped set refused: %v", err)
	}
}
