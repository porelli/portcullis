package machines

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/dkim"
	"github.com/portcullis/mailctl/internal/mtasts"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

type env struct {
	f   *fake.Server
	m   *Machines
	st  *state.Store
	now time.Time
	vis map[string]bool // name|value → visible
}

func newEnv(t *testing.T, mutate func(*state.Doc)) *env {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	f.Put("Domain", "", map[string]any{"name": "example.com"})
	f.Put("Domain", "", map[string]any{"name": "team-b.example.org"})
	b, err := os.ReadFile("../state/testdata/mailstate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(doc)
	}
	st, _ := state.Open(t.TempDir())
	st.Update(func(p *state.Persistent) error { p.Doc, p.Generation = doc, doc.Generation; return nil })
	e := &env{f: f, st: st, now: t0, vis: map[string]bool{}}
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	e.m = New(c, st, Config{MainDomain: "example.com", Hostname: "mail.example.com", RotateEvery: 180 * 24 * time.Hour, Reachable: true}, t.Logf)
	e.m.Now = func() time.Time { return e.now }
	e.m.Visible = func(_ context.Context, name, value string) bool { return e.vis[name+"|"+value] }
	return e
}

func (e *env) step(t *testing.T) {
	t.Helper()
	if err := e.m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (e *env) keys(domain string) []dkim.Key {
	var out []dkim.Key
	for _, k := range read[dkim.State](e.st.Get(), extDKIM).Keys {
		if k.Domain == domain {
			out = append(out, k)
		}
	}
	return out
}

func records(t *testing.T, e *env, domain string) map[string][]string {
	t.Helper()
	s, err := e.m.Set(domain)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, r := range s.Records {
		out[r.Type+" "+r.Name] = append(out[r.Type+" "+r.Name], r.Value)
	}
	return out
}

// DKIM: both keys created pending in Stalwart (the private key sent once,
// never kept), published, active once both resolvers serve the TXT, with
// InvalidateCaches after the stage change.
func TestDKIMThroughStalwart(t *testing.T) {
	e := newEnv(t, nil)
	e.step(t)
	ks := e.keys("example.com")
	if len(ks) != 2 || len(e.f.Objects("DkimSignature", "")) != 4 {
		t.Fatalf("keys %+v, stalwart %d", ks, len(e.f.Objects("DkimSignature", "")))
	}
	for _, k := range ks {
		if k.Stage != dkim.Pending || k.ID == "" || k.PublicKey == "" {
			t.Fatalf("key %+v", k)
		}
		o := e.f.Get("DkimSignature", "", k.ID)
		if o["stage"] != "pending" || o["selector"] != k.Selector {
			t.Fatalf("stalwart %v", o)
		}
		if pk, _ := o["privateKey"].(map[string]any); pk["secret"] != nil {
			t.Fatal("the fake kept the secret")
		}
	}
	raw := string(e.st.Get().Ext[extDKIM])
	if strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("a private key in state.json")
	}
	rec := records(t, e, "example.com")
	if len(rec["TXT v1-ed25519-20261115._domainkey.example.com"]) != 1 || len(rec["TXT v1-rsa-20261115._domainkey.example.com"]) != 1 {
		t.Fatalf("dkim records %v", rec)
	}
	// Visible: active, caches invalidated.
	for _, k := range ks {
		e.vis[dkim.Name(k)+"|"+dkim.TXT(k)] = true
	}
	e.f.ResetCalls()
	e.now = t0.Add(time.Hour)
	e.step(t)
	for _, k := range e.keys("example.com") {
		if k.Stage != dkim.Active || e.f.Get("DkimSignature", "", k.ID)["stage"] != "active" {
			t.Fatalf("not active %+v", k)
		}
	}
	if !strings.Contains(strings.Join(e.f.Calls, "\n"), "InvalidateCaches") {
		t.Fatalf("no InvalidateCaches: %v", e.f.Calls)
	}
	// dkim-rotate: a new pending pair, the actives stay until it's visible.
	if err := e.m.DKIMRotate(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	e.now = t0.Add(2 * time.Hour)
	e.step(t)
	if n := len(e.keys("example.com")); n != 4 {
		t.Fatalf("after rotate %d keys", n)
	}
	var nothing ErrNothingToDo
	if err := e.m.DKIMRotate(context.Background(), "example.com"); !errors.As(err, &nothing) {
		t.Fatalf("rotate while pending: %v", err)
	}
	if err := e.m.DKIMRotate(context.Background(), "nope.example"); !errors.Is(err, ErrNotMailDomain) {
		t.Fatalf("unknown domain: %v", err)
	}
}

// A Stalwart failure on create leaves the key without an id; the next
// pass creates it again with the same selector.
func TestDKIMCreateRetried(t *testing.T) {
	e := newEnv(t, nil)
	e.f.Refuse("DkimSignature", "nope")
	if err := e.m.Step(context.Background()); err == nil {
		t.Fatal("no error")
	}
	if ks := e.keys("example.com"); len(ks) != 2 || ks[0].ID != "" {
		t.Fatalf("%+v", ks)
	}
	e.f.Refuse("DkimSignature", "")
	e.step(t)
	for _, k := range e.keys("example.com") {
		if k.ID == "" || !strings.HasSuffix(k.Selector, "20261115") {
			t.Fatalf("%+v", k)
		}
	}
}

// TLSA only while the main zone is secure (mailctl rotate's state wins over
// the document's), with the rollover's switch_key answer.
func TestRotateTLSA(t *testing.T) {
	e := newEnv(t, nil)
	in := RotateIn{DNSSECState: "insecure"}
	in.SPKI.Current = "AA"
	out, err := e.m.Rotate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if out.TLSA != "withheld: dnssec insecure" || out.SwitchKey || out.NextKey {
		t.Fatalf("%+v", out)
	}
	for _, r := range out.Records {
		if r.Type == "TLSA" {
			t.Fatal("TLSA while insecure")
		}
	}
	if e.st.Get().TimerSeenAt == nil {
		t.Fatal("timer_seen_at not recorded")
	}
	in.DNSSECState = "secure"
	in.SPKI.Next = "BB"
	out, _ = e.m.Rotate(context.Background(), in)
	rec := map[string][]string{}
	for _, r := range out.Records {
		rec[r.Type+" "+r.Name] = append(rec[r.Type+" "+r.Name], r.Value)
	}
	if strings.Join(rec["TLSA _25._tcp.mail.example.com"], ",") != "3 1 1 aa,3 1 1 bb" || out.TLSA != "published" {
		t.Fatalf("%v %s", rec, out.TLSA)
	}
	e.now = t0.Add(2*time.Hour + 24*time.Hour)
	out, _ = e.m.Rotate(context.Background(), in)
	if !out.SwitchKey {
		t.Fatal("no switch_key after 2×TTL + 1 day")
	}
	// An added domain never gets TLSA.
	if s, _ := e.m.Set("team-b.example.org"); !strings.HasPrefix(s.TLSA, "withheld") {
		t.Fatalf("added domain %s", s.TLSA)
	}
	// Without a fresh rotate state the document's dnssec counts.
	e.now = t0.Add(80 * time.Hour)
	e.st.Update(func(p *state.Persistent) error { p.Doc.Domains[0].DNSSEC = "bogus"; return nil })
	if s, _ := e.m.Set("example.com"); s.TLSA != "withheld: dnssec bogus" {
		t.Fatalf("stale rotate state: %s", s.TLSA)
	}
}

func modeOf(t *testing.T, e *env, domain string) string {
	t.Helper()
	st, err := e.m.Status(context.Background(), true, "preserved")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range st.MTASTS {
		if m.Domain == domain {
			return m.Mode
		}
	}
	t.Fatalf("%s not in status", domain)
	return ""
}

// The controller's pin: status says "off" exactly when the drain is done
// (the full max_age of the last published policy), "none" before.
func TestStatusOffExactlyWhenDrainDone(t *testing.T) {
	e := newEnv(t, nil)
	e.step(t)
	if m := modeOf(t, e, "team-b.example.org"); m != mtasts.Testing {
		t.Fatalf("start %s", m)
	}
	e.st.Update(func(p *state.Persistent) error { p.Doc.Domains[1].Mail = state.MailDraining; return nil })
	e.now = t0.Add(time.Hour)
	drainAt := e.now
	e.step(t)
	if m := modeOf(t, e, "team-b.example.org"); m != mtasts.None {
		t.Fatalf("draining %s", m)
	}
	rec := records(t, e, "team-b.example.org")
	if len(rec) != 1 || len(rec["TXT _mta-sts.team-b.example.org"]) != 1 {
		t.Fatalf("draining set %v", rec)
	}
	e.now = drainAt.Add(mtasts.MaxAgeTesting*time.Second - time.Second)
	e.step(t)
	if m := modeOf(t, e, "team-b.example.org"); m != mtasts.None {
		t.Fatalf("off before max_age: %s", m)
	}
	e.now = drainAt.Add(mtasts.MaxAgeTesting * time.Second)
	e.step(t)
	if m := modeOf(t, e, "team-b.example.org"); m != mtasts.Off {
		t.Fatalf("not off at max_age: %s", m)
	}
	if rec := records(t, e, "team-b.example.org"); len(rec) != 0 {
		t.Fatalf("set after the drain %v", rec)
	}
	if m := modeOf(t, e, "example.com"); m != mtasts.Testing {
		t.Fatalf("the other domain %s", m)
	}
}

// VPN-only: no _mta-sts, no policy served, mode off.
func TestUnreachableNoMTASTS(t *testing.T) {
	e := newEnv(t, nil)
	e.m.Cfg.Reachable = false
	e.step(t)
	if rec := records(t, e, "example.com"); len(rec["TXT _mta-sts.example.com"]) != 0 {
		t.Fatalf("%v", rec)
	}
	if e.m.Policy("example.com") != "" || modeOf(t, e, "example.com") != mtasts.Off {
		t.Fatal("policy while unreachable")
	}
}

func TestActions(t *testing.T) {
	e := newEnv(t, nil)
	e.step(t)
	var nothing ErrNothingToDo
	if err := e.m.MTASTSEnforce(context.Background(), "example.com"); !errors.As(err, &nothing) {
		t.Fatalf("enforce at once: %v", err)
	}
	if err := e.m.DMARCPromote("example.com"); !errors.As(err, &nothing) {
		t.Fatalf("promote reject: %v", err)
	}
	if err := e.m.DMARCPromote("nope.example"); !errors.Is(err, ErrNotMailDomain) {
		t.Fatalf("%v", err)
	}
	e.now = t0.Add(8 * 24 * time.Hour)
	if err := e.m.MTASTSEnforce(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.m.Policy("example.com"), "mode: enforce") {
		t.Fatal(e.m.Policy("example.com"))
	}
	// A TLS-RPT failure since → back to testing at the next pass.
	e.f.Put("TlsExternalReport", "", map[string]any{"report": map[string]any{
		"dateRangeEnd": e.now.Add(time.Hour).Format(time.RFC3339),
		"policies":     map[string]any{"0": map[string]any{"policyDomain": "example.com", "totalFailedSessions": 3}}}})
	e.now = e.now.Add(2 * time.Hour)
	e.step(t)
	if m := modeOf(t, e, "example.com"); m != mtasts.Testing {
		t.Fatalf("after a failure %s", m)
	}
}

// DMARC p=none → quarantine proposed after 14 clean days of reports.
func TestDMARCProposal(t *testing.T) {
	e := newEnv(t, nil)
	e.step(t)
	st, _ := e.m.Status(context.Background(), true, "preserved")
	if st.DMARC[1].Policy != "none" || st.DMARC[1].Proposed != nil {
		t.Fatalf("%+v", st.DMARC[1])
	}
	e.f.Put("DmarcExternalReport", "", map[string]any{"report": map[string]any{
		"policyDomain": "team-b.example.org", "dateRangeEnd": t0.Add(15 * 24 * time.Hour).Format(time.RFC3339),
		"records": map[string]any{"0": map[string]any{"evaluatedDkim": "pass", "evaluatedSpf": "fail"}}}})
	e.now = t0.Add(15 * 24 * time.Hour)
	e.step(t)
	st, _ = e.m.Status(context.Background(), true, "preserved")
	if st.DMARC[1].Proposed == nil || *st.DMARC[1].Proposed != "quarantine" {
		t.Fatalf("%+v", st.DMARC[1])
	}
	if err := e.m.DMARCPromote("team-b.example.org"); err != nil {
		t.Fatal(err)
	}
	if rec := records(t, e, "team-b.example.org"); !strings.Contains(rec["TXT _dmarc.team-b.example.org"][0], "p=quarantine") {
		t.Fatalf("%v", rec)
	}
}

func TestStatusCertQueueFormer(t *testing.T) {
	e := newEnv(t, nil)
	e.f.Put("Certificate", "", map[string]any{"notValidAfter": "2027-02-01T00:00:00Z", "subjectAlternativeNames": map[string]any{"mail.example.com": true}})
	e.f.Put("Certificate", "", map[string]any{"notValidAfter": "2028-02-01T00:00:00Z", "subjectAlternativeNames": map[string]any{"other.example.com": true}})
	e.f.Put("QueuedMessage", "", map[string]any{"recipients": map[string]any{"a@x.org": map[string]any{"retryCount": 0}}})
	e.f.Put("QueuedMessage", "", map[string]any{"recipients": map[string]any{"a@x.org": map[string]any{"retryCount": 2}}})
	e.st.Update(func(p *state.Persistent) error {
		p.Former["6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"] = state.Former{Username: "alice", Since: t0}
		return nil
	})
	st, err := e.m.Status(context.Background(), true, "rewritten")
	if err != nil {
		t.Fatal(err)
	}
	if st.Cert == nil || st.Cert.NotAfter.Year() != 2027 || st.Cert.SANs[0] != "mail.example.com" {
		t.Fatalf("cert %+v", st.Cert)
	}
	if st.Queue.Messages != 2 || st.Queue.Deferred != 1 || st.ClientIP != "rewritten" || st.StalwartVersion != "1.1.0" {
		t.Fatalf("%+v", st)
	}
	if len(st.Former) != 1 || st.Former[0].ID != "former-6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b" {
		t.Fatalf("%+v", st.Former)
	}
	e.f.Fail("x:QueuedMessage", 1)
	if _, err := e.m.Status(context.Background(), true, "preserved"); err == nil {
		t.Fatal("a Stalwart failure isn't an error")
	}
}
