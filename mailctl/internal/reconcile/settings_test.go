package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
)

func dnsbl(e *env, typ, name, zone string, enable bool) string {
	return e.f.Put("SpamDnsblServer", "", map[string]any{"@type": typ, "name": name, "enable": enable,
		"zone": map[string]any{"match": map[string]any{}, "else": zone}})
}

func zoneOf(e *env, id string) string {
	b, _ := json.Marshal(e.f.Get("SpamDnsblServer", "", id)["zone"])
	return string(b)
}

func TestSettings(t *testing.T) {
	e := newEnv(t)
	d := baseDoc(t)
	zen := dnsbl(e, "Ip", "STWT_RBL_SPAMHAUS_IP", "ip_reverse + '.zen.spamhaus.org'", true)
	dbl := dnsbl(e, "Domain", "STWT_DBL_SPAMHAUS_DOMAIN", "value + '.dbl.spamhaus.org'", true)
	cop := dnsbl(e, "Ip", "STWT_RBL_SPAMCOP_IP", "ip_reverse + '.bl.spamcop.net'", true)
	other := dnsbl(e, "Ip", "STWT_RBL_MAILSPIKE_IP", "ip_reverse + '.rep.mailspike.net'", true)
	d.Spam.DNSBL.Spamcop = false
	d.Spam.RejectScore, d.Spam.JunkScore = 12, 4
	ctx := context.Background()
	if err := Settings(ctx, e.c, d, SettingsOpts{}); err != nil {
		t.Fatal(err)
	}
	ss := e.f.Get("SpamSettings", "", "singleton")
	if ss["scoreSpam"] != float64(4) || ss["scoreReject"] != float64(12) {
		t.Fatalf("scores %v", ss)
	}
	if e.f.Get("SpamDnsblServer", "", cop)["enable"] != false || e.f.Get("SpamDnsblServer", "", zen)["enable"] != true || e.f.Get("SpamDnsblServer", "", other)["enable"] != true {
		t.Fatal("dnsbl switches")
	}
	// Allow / block in mailctl's namespaces.
	keys := map[string]bool{}
	for _, k := range e.f.Objects("MemoryLookupKey", "") {
		keys[k["namespace"].(string)+" "+k["key"].(string)] = true
	}
	if !keys["portcullis-allow example.org"] || !keys["portcullis-block spam@example.net"] {
		t.Fatalf("lists %v", keys)
	}
	// Outbound limits keyed on the sender.
	ths := e.f.Objects("MtaOutboundThrottle", "")
	if len(ths) != 2 {
		t.Fatalf("throttles %v", ths)
	}
	for _, th := range ths {
		if b, _ := json.Marshal(th["key"]); string(b) != `{"sender":true}` {
			t.Fatalf("key %s", b)
		}
	}
	// Idempotent: a second pass changes nothing.
	e.f.ResetCalls()
	if err := Settings(ctx, e.c, d, SettingsOpts{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range e.f.Calls {
		if strings.Contains(c, "/set") {
			t.Fatalf("second pass wrote: %v", e.f.Calls)
		}
	}
	// A removed allow entry goes.
	d.Spam.Allow = nil
	if err := Settings(ctx, e.c, d, SettingsOpts{}); err != nil {
		t.Fatal(err)
	}
	for _, k := range e.f.Objects("MemoryLookupKey", "") {
		if k["namespace"] == NSSpamAllow {
			t.Fatal("stale allow entry kept")
		}
	}
	// DQS: the Spamhaus zones move to the key's, and back without it.
	dir := t.TempDir()
	kf := filepath.Join(dir, "dqs-key")
	os.WriteFile(kf, []byte("abcdef0123456789\n"), 0o600)
	if err := Settings(ctx, e.c, d, SettingsOpts{DQSKeyFile: kf}); err != nil {
		t.Fatal(err)
	}
	if z := zoneOf(e, zen); !strings.Contains(z, ".abcdef0123456789.zen.dq.spamhaus.net") {
		t.Fatalf("zen %s", z)
	}
	if z := zoneOf(e, dbl); !strings.Contains(z, ".abcdef0123456789.dbl.dq.spamhaus.net") {
		t.Fatalf("dbl %s", z)
	}
	if z := zoneOf(e, cop); strings.Contains(z, "dq") {
		t.Fatalf("spamcop touched %s", z)
	}
	os.WriteFile(kf, nil, 0o600)
	if err := Settings(ctx, e.c, d, SettingsOpts{DQSKeyFile: kf}); err != nil {
		t.Fatal(err)
	}
	if z := zoneOf(e, zen); !strings.Contains(z, ".zen.spamhaus.org") || strings.Contains(z, "dq") {
		t.Fatalf("zen back %s", z)
	}
	// A malformed key (it goes into an expression) is refused, zones kept.
	os.WriteFile(kf, []byte("bad' + 'x"), 0o600)
	if err := Settings(ctx, e.c, d, SettingsOpts{DQSKeyFile: kf}); err == nil {
		t.Fatal("malformed key accepted")
	}
	if z := zoneOf(e, zen); strings.Contains(z, "bad") {
		t.Fatalf("zone %s", z)
	}
	// Rewritten client addresses: every IP list off, domain lists stay.
	if err := Settings(ctx, e.c, d, SettingsOpts{Rewritten: true}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{zen, cop, other} {
		if e.f.Get("SpamDnsblServer", "", id)["enable"] != false {
			t.Fatalf("ip list %s on in degraded mode", id)
		}
	}
	if e.f.Get("SpamDnsblServer", "", dbl)["enable"] != true {
		t.Fatal("domain list off in degraded mode")
	}
}

// TestDQSKeyNeverReachesViewer (security review N4, data flow): the DQS
// key, mailctl's secret source for the spam settings, is written only
// where the admin view's viewer can't read it.
func TestDQSKeyNeverReachesViewer(t *testing.T) {
	e := newEnv(t)
	d := baseDoc(t)
	dnsbl(e, "Ip", "STWT_RBL_SPAMHAUS_IP", "ip_reverse + '.zen.spamhaus.org'", true)
	dnsbl(e, "Domain", "STWT_DBL_SPAMHAUS_DOMAIN", "value + '.dbl.spamhaus.org'", true)
	kf := filepath.Join(t.TempDir(), "dqs-key")
	const key = "sentinelkey0123456789"
	os.WriteFile(kf, []byte(key+"\n"), 0o600)
	if err := Settings(context.Background(), e.c, d, SettingsOpts{DQSKeyFile: kf}); err != nil {
		t.Fatal(err)
	}
	assertNoViewerLeak(t, e.f, key)
}

// assertNoViewerLeak fails when secret reaches a field the viewer reads,
// in any write the fake received or anything it stores; it also fails when
// secret was written nowhere (a vacuous check).
func assertNoViewerLeak(t *testing.T, f *fake.Server, secret string) {
	t.Helper()
	schema, err := os.ReadFile("../stalwart/testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	ty, err := stalwart.ParseTypes(schema)
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, w := range f.Written {
		if b, _ := json.Marshal(w.Fields); strings.Contains(string(b), secret) {
			seen = true
		}
		if l := stalwart.ViewerSecretLeaks(ty, w.Object, w.Fields, secret); len(l) > 0 {
			t.Errorf("a secret reaches the viewer: %v", l)
		}
	}
	for st, objs := range f.Stores() {
		obj, _, _ := strings.Cut(st, "@")
		for _, o := range objs {
			if l := stalwart.ViewerSecretLeaks(ty, obj, o, secret); len(l) > 0 {
				t.Errorf("a stored secret reaches the viewer: %v", l)
			}
		}
	}
	if !seen {
		t.Fatal("the secret was never written: the check proves nothing")
	}
}
