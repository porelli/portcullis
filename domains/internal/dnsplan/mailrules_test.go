package dnsplan

import (
	"encoding/json"
	"os"
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

// M5: a set the shared rules accept (any one-label selector, any TTL ≥ 1)
// passes the structural check too: the Hub and core agree.
func TestSharedRulesAndStructureAgree(t *testing.T) {
	c := RuleContext{Domain: "example.com", MailHostname: "mail.example.com", DMARCFloor: "none"}
	recs := []MailRecord{
		{Name: "default._domainkey.example.com", Type: "TXT", TTL: 3600, Value: "v=DKIM1; k=rsa; p=AAAA"},
		{Name: "example.com", Type: "MX", TTL: 30, Value: "10 mail.example.com."},
	}
	if err := ValidateMailSet(c, recs); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMail("example.com", recs); err != nil {
		t.Fatalf("structural check refuses what the rules accept: %v", err)
	}
}
