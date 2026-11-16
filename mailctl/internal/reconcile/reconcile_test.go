package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

const (
	uAlice  = "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"
	uBob    = "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"
	uRoot   = "3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e"
	uAlice2 = "11111111-2222-4333-8444-555555555555"
)

// env is a fake Stalwart after the bootstrap (parking + primary domain,
// mailctl's account) and a runner on a temp store.
type env struct {
	t   *testing.T
	f   *fake.Server
	c   *stalwart.Client
	st  *state.Store
	r   *Runner
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	park := f.Put("Domain", "", map[string]any{"name": state.ParkingDomain})
	f.Put("Domain", "", map[string]any{"name": "example.com"})
	f.Put("Account", "", map[string]any{"@type": "User", "name": MailctlAccount, "domainId": park, "description": "Portcullis mailctl"})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := stalwart.New(f.URL(), stalwart.Bearer("API_test"))
	e := &env{t: t, f: f, c: c, st: st, now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	e.r = NewRunner(c, st, 720*time.Hour, false, nil)
	e.r.Now = func() time.Time { return e.now }
	return e
}

func baseDoc(t *testing.T) *state.Doc {
	t.Helper()
	b, err := os.ReadFile("../state/testdata/mailstate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// apply stores the document and runs passes until one succeeds (at most n).
func (e *env) apply(d *state.Doc) error {
	e.t.Helper()
	if err := e.st.Update(func(p *state.Persistent) error { p.Doc, p.Generation = d, d.Generation; return nil }); err != nil {
		e.t.Fatal(err)
	}
	return e.r.Once(context.Background())
}

func (e *env) mustApply(d *state.Doc) {
	e.t.Helper()
	if err := e.apply(d); err != nil {
		e.t.Fatalf("apply: %v", err)
	}
}

func (e *env) account(name string) map[string]any {
	for _, a := range e.f.Objects("Account", "") {
		if a["name"] == name {
			return a
		}
	}
	return nil
}

func dropAccount(d *state.Doc, user string) {
	var keep []state.Account
	for _, a := range d.Accounts {
		if a.Username != user {
			keep = append(keep, a)
		}
	}
	d.Accounts = keep
	var al []state.Alias
	for _, a := range d.Aliases {
		if a.Username != user {
			al = append(al, a)
		}
	}
	d.Aliases = al
	for i := range d.Lists {
		var m []string
		for _, x := range d.Lists[i].Members {
			if x != user {
				m = append(m, x)
			}
		}
		d.Lists[i].Members = m
	}
}

func TestFirstApply(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	for _, addr := range []string{"alice@example.com", "alice@team-b.example.org", "sales@example.com", "bob@example.com", "root@example.com"} {
		if !strings.HasPrefix(e.f.Resolve(addr), "account ") {
			t.Errorf("%s doesn't resolve to an account", addr)
		}
	}
	for _, addr := range []string{"team@example.com", "postmaster@example.com", "abuse@team-b.example.org"} {
		if !strings.HasPrefix(e.f.Resolve(addr), "list ") {
			t.Errorf("%s isn't a list", addr)
		}
	}
	if e.f.Resolve("dmarc-reports@team-b.example.org") != "account "+e.account(MailctlAccount)["id"].(string) {
		t.Error("dmarc-reports@ isn't mailctl's")
	}
	if a := e.account("alice"); a["description"] != DescPrefix+uAlice || a["quotas"].(map[string]any)["maxDiskQuota"] != float64(10737418240) {
		t.Errorf("alice %v", a)
	}
	if p := e.st.Get(); p.AppliedGeneration != 12 || len(p.Errors) != 0 {
		t.Fatalf("state %+v", p)
	}
	if len(e.f.Objects("MtaInboundThrottle", "")) != 2 {
		t.Fatal("limits not made")
	}
	// A second pass changes nothing.
	e.f.ResetCalls()
	e.mustApply(baseDoc(t))
	for _, c := range e.f.Calls {
		if strings.Contains(c, "/set") {
			t.Errorf("second pass wrote: %s", c)
		}
	}
}

// M10: members-only list entries; anyone lists have none.
func TestListMembersOnlyLookup(t *testing.T) {
	e := newEnv(t)
	d := baseDoc(t)
	d.Lists = append(d.Lists, state.List{Address: "open@example.com", Members: []string{"alice"}, Posting: "anyone"})
	e.mustApply(d)
	keys := map[string]bool{}
	for _, k := range e.f.Objects("MemoryLookupKey", "") {
		if ns := k["namespace"].(string); ns != NSSpamAllow && ns != NSSpamBlock {
			keys[ns+" "+k["key"].(string)] = true
		}
	}
	want := []string{NSMembersOnly + " team@example.com", NSPosters + " team@example.com|alice@example.com", NSPosters + " team@example.com|bob@example.com"}
	if len(keys) != len(want) {
		t.Fatalf("keys %v", keys)
	}
	for _, w := range want {
		if !keys[w] {
			t.Errorf("missing %s", w)
		}
	}
	if e.f.Count("x:Action/set ReloadLookupStores") < 1 {
		t.Error("no ReloadLookupStores after the lookup change")
	}
	// bob leaves the list: his poster entry goes.
	d.Lists[0].Members = []string{"alice"}
	d.Generation++
	e.mustApply(d)
	for _, k := range e.f.Objects("MemoryLookupKey", "") {
		if strings.Contains(k["key"].(string), "bob") {
			t.Error("bob can still post")
		}
	}
}

func TestPostmasterToAdmins(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	for _, l := range e.f.Objects("MailingList", "") {
		if l["name"] == "postmaster" || l["name"] == "abuse" {
			rec := l["recipients"].(map[string]any)
			if len(rec) != 1 || rec["root@example.com"] != true {
				t.Errorf("%v@ → %v", l["name"], rec)
			}
		}
	}
	if n := len(e.f.Objects("MailingList", "")); n != 5 {
		t.Errorf("%d lists, want team + postmaster/abuse × 2 domains", n)
	}
}

// Review Focus 3: a removal parks the account; its old address is gone,
// its app passwords went first, InvalidateCaches last.
func TestRemovalRenamesToParkingDomain(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	bob := e.account("bob")["id"].(string)
	e.f.Put("AppPassword", bob, map[string]any{"description": "phone"})
	e.f.ResetCalls()
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	e.mustApply(d)
	if e.f.Resolve("bob@example.com") != "" {
		t.Error("bob@example.com still exists")
	}
	a := e.f.Get("Account", "", bob)
	if a["name"] != FormerPrefix+uBob || len(a["aliases"].(map[string]any)) != 0 {
		t.Fatalf("bob not parked: %v", a)
	}
	dis := a["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)
	if dis["authenticate"] != true || dis["emailSend"] != true || dis["emailReceive"] != true {
		t.Fatalf("permissions %v", a["permissions"])
	}
	if len(e.f.Objects("AppPassword", bob)) != 0 {
		t.Fatal("bob's app password survived")
	}
	i, j, k := -1, -1, -1
	for n, c := range e.f.Calls {
		switch {
		case strings.HasPrefix(c, "x:AppPassword/set destroy") && i < 0:
			i = n
		case c == "x:Account/set update" && j < 0:
			j = n
		case c == "x:Action/set InvalidateCaches" && k < 0:
			k = n
		}
	}
	if !(i >= 0 && i < j && j < k) {
		t.Fatalf("order %d %d %d: %v", i, j, k, e.f.Calls)
	}
	if f := e.st.Get().Former[uBob]; f.Username != "bob" || !f.Since.Equal(e.now) {
		t.Fatalf("former record %+v", f)
	}
}

// Review Focus 5: the same username with a new uuid gets a fresh account;
// the old one goes to former-<old uuid>.
func TestUUIDChangeMovesToFormer(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	old := e.account("alice")["id"].(string)
	d := baseDoc(t)
	d.Generation = 13
	d.Accounts[0].UUID = uAlice2
	e.mustApply(d)
	if a := e.f.Get("Account", "", old); a["name"] != FormerPrefix+uAlice {
		t.Fatalf("old alice %v", a)
	}
	n := e.account("alice")
	if n == nil || n["id"] == old || n["description"] != DescPrefix+uAlice2 {
		t.Fatalf("new alice %v", n)
	}
}

func TestRejoinSameUUIDRenamesBack(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	bob := e.account("bob")["id"].(string)
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	e.mustApply(d)
	back := baseDoc(t)
	back.Generation = 14
	e.mustApply(back)
	a := e.f.Get("Account", "", bob)
	if a["name"] != "bob" || a["permissions"].(map[string]any)["@type"] != "Inherit" {
		t.Fatalf("bob not back: %v", a)
	}
	if e.f.Resolve("bob@example.com") != "account "+bob {
		t.Fatal("bob@example.com doesn't reach bob's old mailbox")
	}
	if _, ok := e.st.Get().Former[uBob]; ok {
		t.Fatal("the former record stayed")
	}
}

func TestMassRemovalRefused(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	dropAccount(d, "root")
	d.Postmaster = []string{"alice"}
	if err := e.apply(d); !errors.Is(err, ErrMassRemoval) {
		t.Fatalf("2 of 3 removed: %v", err)
	}
	if e.account("bob") == nil {
		t.Fatal("removed anyway")
	}
	d.ConfirmMassRemoval = true
	e.mustApply(d)
	if e.account("bob") != nil {
		t.Fatal("confirmed removal not applied")
	}
}

func TestRemovalRetriedUntilDone(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	e.f.Fail("x:Account/set", 2)
	if err := e.apply(d); err == nil {
		t.Fatal("first pass succeeded with a failing Stalwart")
	}
	if p := e.st.Get(); p.AppliedGeneration != 12 || len(p.Errors) != 1 {
		t.Fatalf("state after a failure %+v", p)
	}
	_ = e.r.Once(context.Background())
	if err := e.r.Once(context.Background()); err != nil {
		t.Fatalf("third pass: %v", err)
	}
	if e.account("bob") != nil || e.st.Get().AppliedGeneration != 13 {
		t.Fatal("bob not removed after the retries")
	}
}

func TestFormerDestroyedAfterRetention(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	bob := e.account("bob")["id"].(string)
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	e.mustApply(d)
	e.now = e.now.Add(719 * time.Hour)
	e.mustApply(d)
	if e.f.Get("Account", "", bob) == nil {
		t.Fatal("destroyed before the retention")
	}
	e.now = e.now.Add(2 * time.Hour)
	e.mustApply(d)
	if e.f.Get("Account", "", bob) != nil {
		t.Fatal("still there after the retention")
	}
	if _, ok := e.st.Get().Former[uBob]; ok {
		t.Fatal("former record kept after the purge")
	}
}

func TestLANOnlySASLAndRestrict(t *testing.T) {
	e := newEnv(t)
	e.r.LANOnly = true
	e.mustApply(baseDoc(t))
	auth := e.f.Get("MtaStageAuth", "", "singleton")
	cond := auth["saslMechanisms"].(map[string]any)["match"].(map[string]any)["0"].(map[string]any)["if"].(string)
	if !strings.Contains(cond, "is_ip_in_cidr(remote_ip, '10.0.0.0/8')") || !strings.Contains(cond, "local_port != 10025 && is_tls") {
		t.Fatalf("sasl rule %q", cond)
	}
	alice := e.account("alice")["id"].(string)
	e.f.Put("AppPassword", alice, map[string]any{"description": "old phone"})
	e.mustApply(baseDoc(t))
	for _, p := range e.f.Objects("AppPassword", alice) {
		ips := p["allowedIps"].(map[string]any)
		if len(ips) != 1 || ips["10.0.0.0/8"] != true {
			t.Fatalf("existing password not restricted: %v", ips)
		}
	}
	e.f.ResetCalls()
	e.mustApply(baseDoc(t))
	if e.f.Count("x:MtaStageAuth/set") != 0 {
		t.Fatal("the SASL rule is rewritten on every pass")
	}
	// A bootstrap run (mail enable, upgrade) wrote the rule without the
	// Local networks: the next pass compares the live rule and puts the
	// LAN-only one back (final review M1).
	if _, err := e.r.C.Set(context.Background(), "MtaStageAuth", nil, map[string]map[string]any{"singleton": {
		"saslMechanisms": SASLExpression(false, nil)}}, nil); err != nil {
		t.Fatal(err)
	}
	e.mustApply(baseDoc(t))
	cond = e.f.Get("MtaStageAuth", "", "singleton")["saslMechanisms"].(map[string]any)["match"].(map[string]any)["0"].(map[string]any)["if"].(string)
	if !strings.Contains(cond, "is_ip_in_cidr(remote_ip, '10.0.0.0/8')") {
		t.Fatalf("the LAN-only rule wasn't restored after the overwrite: %q", cond)
	}
}

// A parked account whose permissions were lifted (an export that died) is
// disabled again on the next pass.
func TestParkedReDisabled(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	bob := e.account("bob")["id"].(string)
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	e.mustApply(d)
	// Lift as an export would.
	c := e.c
	if _, err := c.Set(context.Background(), "Account", nil, map[string]map[string]any{bob: {"permissions": map[string]any{"@type": "Merge",
		"enabledPermissions": map[string]bool{}, "disabledPermissions": map[string]bool{"emailSend": true, "emailReceive": true}}}}, nil); err != nil {
		t.Fatal(err)
	}
	e.f.ResetCalls()
	e.mustApply(d)
	dis := e.f.Get("Account", "", bob)["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)
	if dis["authenticate"] != true {
		t.Fatalf("not disabled again: %v", dis)
	}
	if e.f.Count("x:Action/set InvalidateCaches") != 1 {
		t.Fatal("no InvalidateCaches after re-disabling")
	}
}

// LAN-only is applied on its own path even when the plan's Apply fails.
func TestLANOnlyEvenWhenApplyFails(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	alice := e.account("alice")["id"].(string)
	e.f.Put("AppPassword", alice, map[string]any{"description": "phone"})
	e.r.LANOnly = true
	d := baseDoc(t)
	d.Generation = 13
	d.Accounts[1].QuotaBytes = 1 // forces an account update, which fails
	e.f.Fail("x:Account/set", 5)
	if err := e.apply(d); err == nil {
		t.Fatal("apply succeeded with a failing Account/set")
	}
	if e.f.Get("MtaStageAuth", "", "singleton") == nil {
		t.Fatal("the LAN-only SASL rule wasn't written")
	}
	ips, _ := e.f.Objects("AppPassword", alice)[0]["allowedIps"].(map[string]any)
	if ips["10.0.0.0/8"] != true {
		t.Fatalf("passwords not restricted: %v", ips)
	}
}

// Rewritten client addresses: LAN-only admits loopback only.
func TestLANOnlyRewrittenLoopbackOnly(t *testing.T) {
	e := newEnv(t)
	e.r.LANOnly, e.r.Rewritten = true, true
	e.mustApply(baseDoc(t))
	cond := e.f.Get("MtaStageAuth", "", "singleton")["saslMechanisms"].(map[string]any)["match"].(map[string]any)["0"].(map[string]any)["if"].(string)
	if strings.Contains(cond, "10.0.0.0/8") || !strings.Contains(cond, "127.0.0.1/32") {
		t.Fatalf("rewritten LAN-only rule %q", cond)
	}
}

// Every account / alias / list change ends with InvalidateCaches.
func TestInvalidateCachesOnEveryChange(t *testing.T) {
	for name, mut := range map[string]func(d *state.Doc){
		"alias": func(d *state.Doc) {
			d.Aliases = append(d.Aliases, state.Alias{Address: "info@example.com", Username: "bob"})
		},
		"address": func(d *state.Doc) {
			d.Accounts[1].Addresses = append(d.Accounts[1].Addresses, "bob@team-b.example.org")
		},
		"list member": func(d *state.Doc) { d.Lists[0].Members = []string{"alice"} },
		"new list": func(d *state.Doc) {
			d.Lists = append(d.Lists, state.List{Address: "ops@example.com", Members: []string{"root"}, Posting: "anyone"})
		},
		"domain off": func(d *state.Doc) {
			d.Domains[1].Mail = state.MailOff
			d.Accounts[0].Addresses = d.Accounts[0].Addresses[:1]
		},
		"primary": func(d *state.Doc) { d.PrimaryDomain = "team-b.example.org"; fixPrimary(d) },
	} {
		e := newEnv(t)
		e.mustApply(baseDoc(t))
		d := baseDoc(t)
		d.Generation = 13
		mut(d)
		if _, err := state.Parse(mustJSON(t, d)); err != nil {
			t.Fatalf("%s: the test document is invalid: %v", name, err)
		}
		e.f.ResetCalls()
		e.mustApply(d)
		if e.f.Count("x:Action/set InvalidateCaches") < 1 {
			t.Errorf("%s: no InvalidateCaches", name)
		}
	}
}

func fixPrimary(d *state.Doc) {
	for i := range d.Accounts {
		a := &d.Accounts[i]
		var rest []string
		for _, x := range a.Addresses {
			if x != a.Username+"@example.com" && x != a.Username+"@team-b.example.org" {
				rest = append(rest, x)
			}
		}
		a.Addresses = append([]string{a.Username + "@team-b.example.org"}, rest...)
	}
}

func mustJSON(t *testing.T, d *state.Doc) []byte {
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A rejoin (the same uuid back) destroys whatever password the parked
// account still holds before its permissions come back (final review M2).
func TestRejoinDestroysPasswords(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	bob := e.account("bob")["id"].(string)
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	e.mustApply(d)
	e.f.Put("AppPassword", bob, map[string]any{"description": "made in a race with the park"})
	back := baseDoc(t)
	back.Generation = 14
	e.mustApply(back)
	if n := len(e.f.Objects("AppPassword", bob)); n != 0 {
		t.Fatalf("%d password(s) survived the rejoin", n)
	}
	if p, _ := e.f.Get("Account", "", bob)["permissions"].(map[string]any); p["@type"] != "Inherit" {
		t.Fatalf("permissions after the rejoin: %v", p)
	}
}

// TestBrokenPagingChangesNothing: a live read that doesn't add up to the
// total stops the pass before any decision or write (no mass-removal
// verdict, no deletes).
func TestBrokenPagingChangesNothing(t *testing.T) {
	old := stalwart.QueryPage
	stalwart.QueryPage = 1
	t.Cleanup(func() { stalwart.QueryPage = old })
	e := newEnv(t)
	e.mustApply(baseDoc(t))
	d := baseDoc(t)
	d.Generation = 13
	dropAccount(d, "bob")
	for _, mode := range []string{"short", "no-total", "ignore-position"} {
		e.f.QueryMode = mode
		e.f.Calls = nil
		err := e.apply(d)
		if err == nil || errors.Is(err, ErrMassRemoval) {
			t.Fatalf("%s: %v", mode, err)
		}
		for _, call := range e.f.Calls {
			if strings.Contains(call, "/set") {
				t.Fatalf("%s: wrote %s on a broken read", mode, call)
			}
		}
		if e.account("bob") == nil {
			t.Fatalf("%s: bob removed", mode)
		}
	}
	e.f.QueryMode = ""
	e.mustApply(d)
	if e.account("bob") != nil {
		t.Fatal("bob not removed once the reads add up")
	}
}
