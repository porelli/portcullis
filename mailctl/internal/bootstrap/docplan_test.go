package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

// MailState v2 carries the relay, the host name and the client address
// mode: the adapter converges them from the document, idempotently.
func TestApplyDocFollowsDocument(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	b, _ := os.ReadFile("../state/testdata/mailstate_v2.json")
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if ch, err := ApplyDoc(context.Background(), c, doc); err != nil || !ch {
		t.Fatalf("first: %v %v", ch, err)
	}
	routes := func() string {
		var n []string
		for _, r := range f.Objects("MtaRoute", "") {
			n = append(n, r["name"].(string))
		}
		return strings.Join(n, ",")
	}
	if !strings.Contains(routes(), "relay") {
		t.Fatalf("no relay route: %s", routes())
	}
	ss, _ := json.Marshal(f.Get("SystemSettings", "", "singleton"))
	ob, _ := json.Marshal(f.Get("MtaOutboundStrategy", "", "singleton"))
	if !strings.Contains(string(ss), `"defaultHostname":"mail.example.com"`) || !strings.Contains(string(ob), `'relay'`) {
		t.Fatalf("%s %s", ss, ob)
	}
	f.ResetCalls()
	if ch, err := ApplyDoc(context.Background(), c, doc); err != nil || ch || f.Count("x:Action") != 0 {
		t.Fatalf("second pass wrote: %v %v %v", ch, err, f.Calls)
	}
	doc.Relay = nil
	doc.ClientIP = state.ClientIPRewritten
	if _, err := ApplyDoc(context.Background(), c, doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(routes(), "relay") {
		t.Fatalf("relay route kept: %s", routes())
	}
	sa, _ := json.Marshal(f.Get("SenderAuth", "", "singleton"))
	if !strings.Contains(string(sa), `"spfFromVerify":{"else":"disable"`) {
		t.Fatalf("degraded sender auth %s", sa)
	}
	sec, _ := json.Marshal(f.Get("Security", "", "singleton"))
	if !strings.Contains(string(sec), `"authBanRate":null`) {
		t.Fatalf("degraded security %s", sec)
	}
	// Back to preserved: the bans come back (explicit non-null rates).
	doc.ClientIP = state.ClientIPPreserved
	if _, err := ApplyDoc(context.Background(), c, doc); err != nil {
		t.Fatal(err)
	}
	sec, _ = json.Marshal(f.Get("Security", "", "singleton"))
	for _, k := range []string{`"authBanRate":{"count":100`, `"abuseBanRate":{"count":35`, `"loiterBanRate":{"count":150`, `"scanBanRate":{"count":30`} {
		if !strings.Contains(string(sec), k) {
			t.Fatalf("normal security lacks %s: %s", k, sec)
		}
	}
}

// ApplyDoc only creates missing TLS strategies and tightens existing ones:
// an entry stricter than wanted stays, dane is never touched (the DANE
// machine's), and a new strategy follows DANE being off.
func TestApplyDocTightensTLSStrategiesOnly(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	f.Put("MtaTlsStrategy", "", map[string]any{"name": "default", "dane": "disable", "mtaSts": "require", "startTls": "require", "allowInvalidCerts": false})
	b, _ := os.ReadFile("../state/testdata/mailstate_v2.json")
	doc, _ := state.Parse(b)
	if _, err := ApplyDoc(context.Background(), c, doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, o := range f.Objects("MtaTlsStrategy", "") {
		got[o["name"].(string)] = o
	}
	if d := got["default"]; d["dane"] != "disable" || d["mtaSts"] != "require" || d["startTls"] != "require" {
		t.Fatalf("default loosened: %v", d)
	}
	if r := got["relay-strict"]; r == nil || r["dane"] != "disable" || r["startTls"] != "require" {
		t.Fatalf("relay-strict %v", r)
	}
	// A looser existing entry is tightened.
	f.Put("MtaTlsStrategy", "", map[string]any{"id": got["relay-strict"]["id"], "name": "relay-strict", "dane": "disable", "mtaSts": "optional", "startTls": "optional", "allowInvalidCerts": true})
	if _, err := ApplyDoc(context.Background(), c, doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range f.Objects("MtaTlsStrategy", "") {
		if o["name"] == "relay-strict" && (o["startTls"] != "require" || o["allowInvalidCerts"] != false || o["dane"] != "disable") {
			t.Fatalf("not tightened: %v", o)
		}
	}
}

// Ruling T17-d: the document-less plan is valid on Stalwart 1.1 (a
// placeholder host on the parking domain, the parking domain as the
// default); ApplyDoc moves both to the document's.
func TestDocumentlessPlanPlaceholders(t *testing.T) {
	p := Params{}
	for _, s := range p.Singletons() {
		if s.Object == "SystemSettings" && s.Patch["defaultHostname"] != "mail.portcullis-former.internal" {
			t.Fatalf("defaultHostname %v", s.Patch["defaultHostname"])
		}
	}
	f := fake.New()
	t.Cleanup(f.Close)
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	prim := f.Put("Domain", "", map[string]any{"name": "example.com"})
	b, _ := os.ReadFile("../state/testdata/mailstate_v2.json")
	doc, _ := state.Parse(b)
	if _, err := ApplyDoc(context.Background(), c, doc); err != nil {
		t.Fatal(err)
	}
	ss, _ := json.Marshal(f.Get("SystemSettings", "", "singleton"))
	if !strings.Contains(string(ss), `"defaultDomainId":"`+prim+`"`) || !strings.Contains(string(ss), `"defaultHostname":"mail.example.com"`) {
		t.Fatalf("%s", ss)
	}
}
