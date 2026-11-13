package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/dnsplan"
	"github.com/portcullis/domains/internal/fakedns"
)

const toolToken = "tool-Tk9vZXJ5U2VjcmV0VG9rZW4xMjM0"

type toolFixture struct {
	zone      *fakedns.Zone
	resolvers []string
	hook      func(op string, recs []libdns.Record) error
}

// newToolFixture: zone example.test on a fake DNS server and provider
// "fake-tool" writing into it.
func newToolFixture(t *testing.T) *toolFixture {
	t.Helper()
	f := &toolFixture{zone: fakedns.NewZone()}
	f.zone.SetSOA("example.test")
	srv, err := fakedns.Serve(f.zone, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	f.resolvers = []string{srv.Addr}
	providers["fake-tool"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		return &fakedns.Provider{Zone: f.zone, Token: c["api_token"], ZoneName: "example.test",
			Hook: func(op string, recs []libdns.Record) error {
				if f.hook != nil {
					return f.hook(op, recs)
				}
				return nil
			}}, nil
	}}
	t.Cleanup(func() { delete(providers, "fake-tool") })
	return f
}

func toolJSON(mod func(m map[string]any)) string {
	m := map[string]any{"name": "portcullis.example.test", "provider": "fake-tool", "credentials": map[string]string{"api_token": toolToken},
		"ipv4": "203.0.113.10", "ipv6": "", "ca_server": "https://acme-v02.api.letsencrypt.org/directory",
		"caa":    map[string]any{"enabled": true, "issuer": "", "account_uri": "https://acme-v02.api.letsencrypt.org/acme/acct/1", "iodef": ""},
		"nomail": false, "sets": []string{"address", "caa"}, "mail_from": ""}
	if mod != nil {
		mod(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (f *toolFixture) run(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runDNSTool(args, toolEnv{stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb, resolvers: f.resolvers})
	return code, out.String(), errb.String()
}

func readOnly(m map[string]any) { m["provider"] = ""; delete(m, "credentials") }

func TestToolPlanFake(t *testing.T) {
	f := newToolFixture(t)
	code, out, errs := f.run([]string{"plan"}, toolJSON(nil))
	var pl dnsplan.Plan
	if code != 0 || json.Unmarshal([]byte(out), &pl) != nil || !pl.CanWrite || pl.Name != "portcullis.example.test" || len(pl.Items) == 0 {
		t.Fatalf("plan = %d %s %s", code, out, errs)
	}
	// Without a provider: read-only, manual steps.
	code, out, _ = f.run([]string{"plan"}, toolJSON(readOnly))
	json.Unmarshal([]byte(out), &pl)
	if code != 0 || pl.CanWrite || pl.Items[0].Fix != dnsplan.FixManual {
		t.Fatalf("read-only plan = %d %s", code, out)
	}
}

func TestToolCheckRefusesCredentials(t *testing.T) {
	f := newToolFixture(t)
	if code, _, errs := f.run([]string{"check"}, toolJSON(nil)); code != exitUsage || !strings.Contains(errs, "check takes no credentials") {
		t.Fatalf("= %d %s", code, errs)
	}
	if code, _, _ := f.run([]string{"apply"}, toolJSON(readOnly)); code != exitUsage {
		t.Fatalf("apply without a provider = %d", code)
	}
}

func TestToolApplyWait(t *testing.T) {
	f := newToolFixture(t)
	old := toolPollEvery
	toolPollEvery = 50 * time.Millisecond
	t.Cleanup(func() { toolPollEvery = old })
	code, out, errs := f.run([]string{"apply", "--wait", "5s"}, toolJSON(nil))
	var pl dnsplan.Plan
	if code != 0 || json.Unmarshal([]byte(out), &pl) != nil || !pl.CanWrite {
		t.Fatalf("apply = %d %s %s (the final plan is built with the provider: can_write)", code, out, errs)
	}
	for _, it := range pl.Items {
		if (it.Set == dnsplan.SetAddress || it.Set == dnsplan.SetCAA) && it.Status != dnsplan.StatusOK {
			t.Errorf("item %+v", it)
		}
	}
	if !pl.CAA.WouldIssue || len(f.zone.Records("portcullis.example.test")) != 3 { // A + issue + issuewild
		t.Fatalf("caa %+v records %v", pl.CAA, f.zone.Records("portcullis.example.test"))
	}
	// Records that never become visible (the resolvers answer from an
	// empty zone): exit 1 at the deadline.
	empty, err := fakedns.Serve(fakedns.NewZone(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	f.resolvers = []string{empty.Addr}
	if code, _, _ := f.run([]string{"apply", "--wait", "200ms"}, toolJSON(nil)); code != exitProblem {
		t.Fatalf("apply --wait not visible = %d", code)
	}
}

func TestToolCheckExit1OnProblem(t *testing.T) {
	f := newToolFixture(t)
	other := dnsplan.CAAValue("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/999")
	f.zone.Set("portcullis.example.test", libdns.RR{Name: "portcullis", Type: "A", Data: "203.0.113.10"},
		libdns.CAA{Name: "portcullis", Tag: "issue", Value: other}.RR(), libdns.CAA{Name: "portcullis", Tag: "issuewild", Value: other}.RR())
	f.zone.Set("*.portcullis.example.test", libdns.RR{Name: "*.portcullis", Type: "A", Data: "203.0.113.10"})
	code, out, _ := f.run([]string{"check"}, toolJSON(readOnly))
	if code != exitProblem || !strings.Contains(out, `"would_issue":false`) {
		t.Fatalf("check = %d %s", code, out)
	}
	// The right pin: exit 0.
	code, out, _ = f.run([]string{"check"}, toolJSON(func(m map[string]any) {
		readOnly(m)
		m["caa"].(map[string]any)["account_uri"] = "https://acme-v02.api.letsencrypt.org/acme/acct/999"
	}))
	if code != exitOK {
		t.Fatalf("check with the right pin = %d %s", code, out)
	}
}

func TestToolStdinOnly(t *testing.T) {
	f := newToolFixture(t)
	if code, _, _ := f.run([]string{"plan"}, toolJSON(func(m map[string]any) { m["extra"] = 1 })); code != exitUsage {
		t.Fatalf("unknown field = %d", code)
	}
	big := toolJSON(func(m map[string]any) { m["mail_from"] = strings.Repeat("a", toolInputMax) })
	if code, _, _ := f.run([]string{"plan"}, big); code != exitUsage {
		t.Fatalf("> 64 KiB = %d", code)
	}
	if code, _, _ := f.run([]string{"plan"}, toolJSON(nil)+"{}"); code != exitUsage {
		t.Fatalf("two objects = %d", code)
	}
	if code, _, _ := f.run([]string{"plan", "--wait", "1s"}, toolJSON(nil)); code != exitUsage {
		t.Fatalf("plan --wait = %d", code)
	}
}

func TestToolInputKeys(t *testing.T) {
	raw := `{"name":"d.test","provider":"cloudflare","credentials":{"api_token":"x"},"ipv4":"203.0.113.1","ipv6":"2001:db8::1",
		"ca_server":"https://ca/dir","caa":{"enabled":true,"issuer":"pebble.test","account_uri":"https://ca/acct/1","iodef":"mailto:a@b"},
		"nomail":true,"sets":["caa"],"mail_from":"alerts@d.test"}`
	in, err := readToolInput(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "d.test" || in.Provider != "cloudflare" || in.Credentials["api_token"] != "x" || in.IPv4 != "203.0.113.1" || in.IPv6 != "2001:db8::1" ||
		in.CAServer != "https://ca/dir" || !in.CAA.Enabled || in.CAA.Issuer != "pebble.test" || in.CAA.AccountURI != "https://ca/acct/1" ||
		in.CAA.IODEF != "mailto:a@b" || !in.NoMail || strings.Join(in.Sets, ",") != "caa" || in.MailFrom != "alerts@d.test" {
		t.Fatalf("%+v", in)
	}
	if _, err := readToolInput(strings.NewReader(`{"caa":{"AccountURI":"x"}}`)); err == nil {
		t.Fatal("AccountURI accepted")
	}
	f := newToolFixture(t)
	if code, _, _ := f.run([]string{"plan"}, `{"name":"portcullis.example.test","caa":{"AccountURI":"https://x/acct"}}`); code != exitUsage {
		t.Fatalf("camel-case key = %d", code)
	}
}

func TestToolErrorsRedacted(t *testing.T) {
	f := newToolFixture(t)
	f.hook = func(op string, _ []libdns.Record) error {
		return fmt.Errorf("provider said: %s refused for token=%s", op, toolToken)
	}
	code, out, errs := f.run([]string{"apply"}, toolJSON(nil))
	if code != exitFailure || strings.Contains(errs+out, toolToken) || strings.Contains(errs, toolToken[:len(toolToken)/2]) || !strings.Contains(errs, "[redacted]") {
		t.Fatalf("= %d %q %q", code, out, errs)
	}
	f.hook = nil
	// A bad input never echoes the credentials either.
	_, _, errs = f.run([]string{"plan"}, strings.Replace(toolJSON(nil), `"nomail":false`, `"nomail":"x"`, 1))
	if strings.Contains(errs, toolToken) {
		t.Fatalf("input error quotes the token: %s", errs)
	}
}

func TestTraefikAccountURI(t *testing.T) {
	dir := t.TempDir()
	const uri = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123"
	good := filepath.Join(dir, "acme.json")
	os.WriteFile(good, []byte(`{"letsencrypt":{"Account":{"Email":"a@b","Registration":{"body":{},"uri":"`+uri+`"},"PrivateKey":"SECRETKEY"},"Certificates":[{"key":"CERTKEY"}]}}`), 0o600)
	var out, errb bytes.Buffer
	if code := runTraefikAccountURI([]string{good}, &out, &errb); code != 0 || out.String() != uri+"\n" || strings.Contains(out.String()+errb.String(), "SECRETKEY") {
		t.Fatalf("= %d %q %q", code, out.String(), errb.String())
	}
	for name, body := range map[string]string{"none.json": `{"letsencrypt":{"Certificates":null}}`, "bad.json": `{"letsencrypt": SECRETKEY`,
		"empty.json": ``, "http.json": `{"letsencrypt":{"Account":{"Registration":{"uri":"http://x/acct"},"PrivateKey":"SECRETKEY"}}}`} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		out.Reset()
		errb.Reset()
		if code := runTraefikAccountURI([]string{p}, &out, &errb); code != exitFailure || out.Len() != 0 ||
			errb.String() != "no Traefik ACME account in "+p+"\n" {
			t.Errorf("%s: = %d %q %q", name, code, out.String(), errb.String())
		}
	}
	if code := runTraefikAccountURI([]string{filepath.Join(dir, "missing")}, &out, &errb); code != exitFailure {
		t.Fatalf("missing file = %d", code)
	}
}

func TestReportShape(t *testing.T) {
	e := newEnv(t, false)
	e.do("PUT", "/domains/team-rp.example.org", creds(goodToken), true)
	e.waitState("team-rp.example.org", StateReady, 60*time.Second)
	srv := httptest.NewServer(e.api)
	defer srv.Close()
	var out, errb bytes.Buffer
	if code := runReport([]string{"--main", "--json"}, srv.URL, testSecret, &out, &errb); code != 0 {
		t.Fatalf("= %d %s", code, errb.String())
	}
	var r struct {
		Main    dnsplan.Plan            `json:"main"`
		Domains map[string]dnsplan.Plan `json:"domains"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Main.Name != testMain || r.Domains["team-rp.example.org"].Name != "team-rp.example.org" || len(r.Domains) != 1 {
		t.Fatalf("%v %s", err, out.String())
	}
	if code := runReport([]string{"--main", "--json"}, srv.URL, "wrong-secret-wrong-secret-wrong-secret", &out, &errb); code != exitFailure {
		t.Fatalf("wrong secret = %d", code)
	}
	if code := runReport(nil, srv.URL, testSecret, &out, &errb); code != exitUsage {
		t.Fatalf("no flags = %d", code)
	}
	// --refresh: POST /main/dns/refresh, nothing printed.
	e.svc.mu.Lock()
	gen := e.svc.mainGen
	e.svc.mu.Unlock()
	out.Reset()
	if code := runReport([]string{"--main", "--refresh"}, srv.URL, testSecret, &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("--refresh = %d %q %s", code, out.String(), errb.String())
	}
	e.svc.mu.Lock()
	after := e.svc.mainGen
	e.svc.mu.Unlock()
	if after != gen+1 {
		t.Fatalf("--refresh: main plan generation %d → %d", gen, after)
	}
	if code := runReport([]string{"--main", "--refresh"}, srv.URL, "wrong-secret-wrong-secret-wrong-secret", &out, &errb); code != exitFailure {
		t.Fatalf("--refresh, wrong secret = %d", code)
	}
}
