package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	// deleteMode: the fake provider's DeleteMode ("porkbun": its 600 s TTL
	// floor and delete-by-name/type, as libdns/porkbun v1.1.0).
	deleteMode string
	// storedTTL, if set, is the TTL the provider's API reports for every
	// record (Cloudflare's 1 = "auto", Hetzner's 0 = the zone default),
	// whatever the zone serves.
	storedTTL *time.Duration
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
	// The fake server is also the zone's authoritative server.
	oldAuth := toolAuthServers
	toolAuthServers = func(context.Context, []string, string) []string { return []string{srv.Addr} }
	t.Cleanup(func() { toolAuthServers = oldAuth })
	providers["fake-tool"] = providerSpec{required: []string{"api_token"}, build: func(c map[string]string) (dnsProvider, error) {
		raw := &fakedns.Provider{Zone: f.zone, Token: c["api_token"], ZoneName: "example.test", DeleteMode: f.deleteMode,
			Hook: func(op string, recs []libdns.Record) error {
				if f.hook != nil {
					return f.hook(op, recs)
				}
				return nil
			}}
		if f.deleteMode == "porkbun" { // wrapped as buildProvider wraps the real one
			return zoneKnown{newPorkbunProvider(raw, fakeIDs{raw}), "example.test."}, nil
		}
		if f.storedTTL != nil {
			return zoneKnown{ttlReport{raw, *f.storedTTL}, "example.test."}, nil
		}
		return raw, nil
	}}
	t.Cleanup(func() { delete(providers, "fake-tool") })
	return f
}

// ttlReport: a provider whose API reports ttl for every record.
type ttlReport struct {
	dnsProvider
	ttl time.Duration
}

func (p ttlReport) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	recs, err := p.dnsProvider.GetRecords(ctx, zone)
	for i, r := range recs {
		rr := r.RR()
		rr.TTL = p.ttl
		recs[i] = rr
	}
	return recs, err
}

// DeleteRecords matches on data, not on the TTL it reported.
func (p ttlReport) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	for i, r := range recs {
		rr := r.RR()
		rr.TTL = 0
		recs[i] = rr
	}
	return p.dnsProvider.DeleteRecords(ctx, zone, recs)
}

// zoneKnown: a wrapped fake that still names its zone (no SOA lookup).
type zoneKnown struct {
	dnsProvider
	zone string
}

func (z zoneKnown) FindZone(string) (string, error) { return z.zone, nil }

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
	old, oldSpan := toolPollEvery, toolStableSpan
	toolPollEvery, toolStableSpan = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { toolPollEvery, toolStableSpan = old, oldSpan })
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

// TestReportFresh (deploy finding A): `domains report --main --json
// --fresh` asks for a main plan rebuilt unless one is under 30 s old
// (GET /main/dns?refresh=1, the service's throttle), so status sees a CAA
// changed outside Portcullis; when that doesn't answer in time it falls
// back to the cached plan and says so (main_fresh false).
func TestReportFresh(t *testing.T) {
	e := newEnv(t, false)
	srv := httptest.NewServer(e.api)
	defer srv.Close()
	var out, errb bytes.Buffer
	report := func(args ...string) (int, map[string]json.RawMessage) {
		out.Reset()
		errb.Reset()
		code := runReport(append([]string{"--main", "--json"}, args...), srv.URL, testSecret, &out, &errb)
		var r map[string]json.RawMessage
		json.Unmarshal(out.Bytes(), &r)
		return code, r
	}
	if code, r := report(); code != 0 || string(r["main_fresh"]) != "false" {
		t.Fatalf("--json alone = %d main_fresh %s", code, r["main_fresh"])
	}
	// A CAA written outside Portcullis: --fresh shows it at once.
	e.clock.advance(time.Minute) // past the 30 s throttle
	v := dnsplan.CAAValue("pebble.test", "https://elsewhere.test/acct/9")
	e.zone.Set(testMain, libdns.CAA{Name: "@", TTL: dnsplan.TTLCAA, Tag: "issue", Value: v}.RR())
	code, r := report("--fresh")
	var pl dnsplan.Plan
	json.Unmarshal(r["main"], &pl)
	if code != 0 || string(r["main_fresh"]) != "true" {
		t.Fatalf("--fresh = %d %s %s", code, out.String(), errb.String())
	}
	live := false
	for _, it := range pl.Items {
		if it.Set == dnsplan.SetCAA && len(it.Live) > 0 && strings.Contains(it.Live[0], "acct/9") {
			live = true
		}
	}
	if !live {
		t.Fatalf("--fresh plan doesn't show the outside CAA: %+v", pl.Items)
	}
	// The rebuild doesn't answer in time: the cached plan, main_fresh false.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("refresh") == "1" {
			time.Sleep(2 * time.Second)
		}
		e.api.ServeHTTP(w, r)
	}))
	defer slow.Close()
	old := reportFreshTimeout
	reportFreshTimeout = 200 * time.Millisecond
	t.Cleanup(func() { reportFreshTimeout = old })
	out.Reset()
	if code := runReport([]string{"--main", "--json", "--fresh"}, slow.URL, testSecret, &out, &errb); code != 0 ||
		!strings.Contains(out.String(), `"main_fresh":false`) || !strings.Contains(out.String(), `"main":{`) {
		t.Fatalf("slow --fresh = %d %s %s", code, out.String(), errb.String())
	}
	if code := runReport([]string{"--main", "--refresh", "--fresh"}, srv.URL, testSecret, &out, &errb); code != exitUsage {
		t.Fatalf("--refresh --fresh = %d", code)
	}
}

// A main-plan build cut short (the client gave up) never replaces the
// cached plan with failed lookups (M9: it goes on, detached from the
// request, and stores its plan when it finishes, so the 30 s throttle
// engages for the next status).
func TestMainPlanCanceledNotStored(t *testing.T) {
	e := newEnv(t, false)
	cachedAt := func() (time.Time, dnsplan.Plan, bool) {
		e.svc.mu.Lock()
		defer e.svc.mu.Unlock()
		c, ok := e.svc.plans[mainPlanKey]
		return c.at, c.plan, ok
	}
	e.waitFor("the worker's first main plan", 10*time.Second, func() bool { _, _, ok := cachedAt(); return ok })
	before, _, _ := cachedAt()
	e.clock.advance(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = e.svc.mainPlan(ctx, true)
	e.waitFor("the detached build stored", 10*time.Second, func() bool { at, _, _ := cachedAt(); return at.After(before) })
	_, pl, _ := cachedAt()
	for _, it := range pl.Items {
		if it.Status == dnsplan.StatusUnknown && it.Severity == dnsplan.SevWarning {
			t.Fatalf("a canceled request's lookups were stored: %+v", it)
		}
	}
}

// M17: a main-plan request that gives up with nothing cached answers 503
// (unavailable), never an empty 200 that could read as clean.
func TestMainPlanGivesUpNothingCached(t *testing.T) {
	e := newEnv(t, false)
	e.svc.mu.Lock()
	e.svc.mainGen++
	delete(e.svc.plans, mainPlanKey)
	e.svc.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.svc.mainPlan(ctx, false); err == nil {
		t.Fatal("a request that gave up with nothing cached got a plan")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/main/dns", nil).WithContext(ctx)
	e.svc.handleMainPlan(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /main/dns, gave up, nothing cached = %d %s", rec.Code, rec.Body.String())
	}
}

// M23: when the CA wouldn't issue, check says how long caches may hold the
// CAA at the name (the TTL its authoritative servers serve), so the
// flip's refusal can say how long to wait after removing a pin by hand.
func TestToolCheckCAATTL(t *testing.T) {
	f := newToolFixture(t)
	other := dnsplan.CAAValue("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/999")
	f.zone.Set("portcullis.example.test", libdns.RR{Name: "portcullis", Type: "A", Data: "203.0.113.10"},
		libdns.CAA{Name: "portcullis", TTL: 1800 * time.Second, Tag: "issue", Value: other}.RR(),
		libdns.CAA{Name: "portcullis", TTL: 1800 * time.Second, Tag: "issuewild", Value: other}.RR())
	caOnly := func(m map[string]any) {
		readOnly(m)
		m["sets"] = []string{"caa"}
		m["caa"].(map[string]any)["account_uri"] = ""
	}
	var r struct {
		WouldIssue struct {
			V bool `json:"would_issue"`
		} `json:"caa"`
		TTL *int `json:"caa_ttl"`
	}
	code, out, _ := f.run([]string{"check"}, toolJSON(caOnly))
	if code != exitProblem || json.Unmarshal([]byte(out), &r) != nil || r.WouldIssue.V || r.TTL == nil || *r.TTL != 1800 {
		t.Fatalf("check, a live pin = %d %s: want would_issue false, caa_ttl 1800", code, out)
	}
	// It would issue: no caa_ttl.
	f.zone.Set("portcullis.example.test", libdns.RR{Name: "portcullis", Type: "A", Data: "203.0.113.10"})
	r.TTL = nil
	if _, out, _ = f.run([]string{"check"}, toolJSON(caOnly)); json.Unmarshal([]byte(out), &r) != nil || r.TTL != nil {
		t.Fatalf("check, no pin: %s", out)
	}
}
