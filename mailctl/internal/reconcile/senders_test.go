package reconcile

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

const (
	uHubSender = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"
	uAppSender = "7b8c9d0e-1f2a-3b4c-5d6e-7f8a9b0c1d2e"
	hubSender  = "portcullis-hub-mail"
	appSender  = "portcullis-app-firefox-sync-fxa"
)

// sendersDoc is the contract's vector with senders (§19.5, §19.14).
func sendersDoc(t *testing.T) *state.Doc {
	t.Helper()
	b, err := os.ReadFile("../state/testdata/mailstate_v2_senders.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func withSenders(d *state.Doc, s ...state.Sender) *state.Doc {
	l := append([]state.Sender{}, s...)
	d.Senders = &l
	d.Generation++
	return d
}

func (e *env) senderKeys() map[string]bool {
	out := map[string]bool{}
	for _, k := range e.f.Objects("MemoryLookupKey", "") {
		if k["namespace"] == bootstrap.NSSenders {
			out[k["key"].(string)] = true
		}
	}
	return out
}

func permSet(v any) map[string]bool {
	out := map[string]bool{}
	m, _ := v.(map[string]any)
	for k, x := range m {
		if x == true {
			out[k] = true
		}
	}
	return out
}

// A sender is a submission-only account (§19.14): its login is its one
// address on the primary domain, its permissions replace every inherited
// one with authenticate + emailSend (no IMAP, JMAP, POP3, DAV, Sieve or
// emailReceive: no mailbox access), and it is never one of the people's
// accounts (Live.Accounts, the mass-removal count, the credentials of a
// person).
func TestSenderAccountCreated(t *testing.T) {
	e := newEnv(t)
	e.mustApply(sendersDoc(t))
	primary := ""
	for _, d := range e.f.Objects("Domain", "") {
		if d["name"] == "example.com" {
			primary = d["id"].(string)
		}
	}
	for name, uuid := range map[string]string{hubSender: uHubSender, appSender: uAppSender} {
		a := e.account(name)
		if a == nil {
			t.Fatalf("%s: no account", name)
		}
		if a["description"] != DescSenderPrefix+uuid || a["domainId"] != primary || a["@type"] != "User" {
			t.Errorf("%s: %v", name, a)
		}
		p, _ := a["permissions"].(map[string]any)
		if p["@type"] != "Replace" || len(permSet(p["disabledPermissions"])) != 0 {
			t.Errorf("%s: permissions %v", name, p)
		}
		got := permSet(p["enabledPermissions"])
		if len(got) != 2 || !got["authenticate"] || !got["emailSend"] {
			t.Errorf("%s: enabled permissions %v (want exactly authenticate, emailSend)", name, got)
		}
		if al, _ := a["aliases"].(map[string]any); len(al) != 0 {
			t.Errorf("%s: aliases %v", name, al)
		}
		if !strings.HasPrefix(e.f.Resolve(name+"@example.com"), "account ") {
			t.Errorf("%s@example.com doesn't resolve to the sender", name)
		}
	}
	l, err := Read(context.Background(), e.c)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Accounts) != 3 || len(l.Senders) != 2 {
		t.Fatalf("live: %d people, %d senders (want 3, 2)", len(l.Accounts), len(l.Senders))
	}
	// Idempotent: a second pass changes nothing.
	e.f.ResetCalls()
	d := sendersDoc(t)
	d.Generation = 13
	e.mustApply(d)
	for _, c := range e.f.Calls {
		if strings.Contains(c, "/set") {
			t.Errorf("second pass wrote: %s", c)
		}
	}
	// Drift is put back: a hand edit giving the sender more permissions,
	// another role or a domain other than the primary.
	id := e.account(appSender)["id"].(string)
	if _, err := e.c.Set(context.Background(), "Account", nil, map[string]map[string]any{id: {
		"permissions": map[string]any{"@type": "Inherit"}, "roles": map[string]any{"@type": "Admin"}}}, nil); err != nil {
		t.Fatal(err)
	}
	d.Generation = 14
	e.mustApply(d)
	a := e.account(appSender)
	if p := a["permissions"].(map[string]any); p["@type"] != "Replace" || len(permSet(p["enabledPermissions"])) != 2 {
		t.Errorf("drifted permissions kept: %v", p)
	}
	if r := a["roles"].(map[string]any); r["@type"] != "User" {
		t.Errorf("drifted role kept: %v", r)
	}
}

// The sending address is the sender's only one (§19.14: MAIL FROM and
// From: = address only). Submission's mustMatchSender ties the envelope
// sender to the login's addresses and the DATA script (from-check) the
// From: header to the envelope sender, for every authenticated session,
// so an alias (a hand edit) is removed again: another From: is refused at
// DATA.
func TestSenderFromRestricted(t *testing.T) {
	e := newEnv(t)
	e.mustApply(sendersDoc(t))
	id := e.account(appSender)["id"].(string)
	primary := e.account(appSender)["domainId"]
	if _, err := e.c.Set(context.Background(), "Account", nil, map[string]map[string]any{id: {
		"aliases": map[string]any{"0": map[string]any{"name": "boss", "domainId": primary, "enable": true}}}}, nil); err != nil {
		t.Fatal(err)
	}
	if e.f.Resolve("boss@example.com") == "" {
		t.Fatal("the hand-made alias isn't there")
	}
	d := sendersDoc(t)
	d.Generation = 13
	e.mustApply(d)
	if al, _ := e.account(appSender)["aliases"].(map[string]any); len(al) != 0 {
		t.Fatalf("the sender kept an alias: %v", al)
	}
	if e.f.Resolve("boss@example.com") != "" {
		t.Fatal("boss@example.com still resolves")
	}
	// The base plan's half (every authenticated session, senders
	// included): mustMatchSender on, from-check at DATA.
	var auth, data map[string]any
	for _, s := range (bootstrap.Params{}).Singletons() {
		switch s.Object {
		case "MtaStageAuth":
			auth = s.Patch
		case "MtaStageData":
			data = s.Patch
		}
	}
	if m := auth["mustMatchSender"].(map[string]any); m["else"] != "true" || len(m["match"].(map[string]any)) != 0 {
		t.Errorf("mustMatchSender %v", m)
	}
	ds := data["script"].(map[string]any)["match"].(map[string]any)["0"].(map[string]any)
	if ds["if"] != "!is_empty(authenticated_as)" || ds["then"] != "'"+bootstrap.ScriptFrom+"'" {
		t.Errorf("DATA script %v", ds)
	}
	if !strings.Contains(bootstrap.FromCheckSieve, `reject "550 5.7.1 the From: header must be your own address"`) {
		t.Error("from-check doesn't refuse another From:")
	}
}

// Inbound mail to a sender's address is refused at RCPT with 550 5.1.1
// (§19.14): its address is a key of the senders' lookup namespace, which
// the RCPT stage's script expression sends to the parked-reject script
// before anything else.
func TestSenderInboundRefused(t *testing.T) {
	e := newEnv(t)
	e.mustApply(sendersDoc(t))
	keys := e.senderKeys()
	if len(keys) != 2 || !keys[hubSender+"@example.com"] || !keys[appSender+"@example.com"] {
		t.Fatalf("sender keys %v", keys)
	}
	// The keys are in place before the account exists (no window where
	// the address takes mail), and the lookup stores reloaded.
	keyAt, acctAt, reloadAt := -1, -1, -1
	for i, c := range e.f.Calls {
		switch {
		case c == "x:MemoryLookupKey/set create" && keyAt < 0:
			keyAt = i
		case c == "x:Account/set create" && acctAt < 0 && i > keyAt && keyAt >= 0:
			acctAt = i
		case c == "x:Action/set ReloadLookupStores" && reloadAt < 0 && keyAt >= 0:
			reloadAt = i
		}
	}
	if keyAt < 0 || reloadAt < keyAt || acctAt < reloadAt {
		t.Errorf("order: keys %d, reload %d, sender account %d: %v", keyAt, reloadAt, acctAt, e.f.Calls)
	}
	var rcpt map[string]any
	for _, s := range (bootstrap.Params{}).Singletons() {
		if s.Object == "MtaStageRcpt" {
			rcpt = s.Patch["script"].(map[string]any)
		}
	}
	first := rcpt["match"].(map[string]any)["0"].(map[string]any)
	if first["if"] != "key_exists('"+bootstrap.NSSenders+"', rcpt)" || first["then"] != "'"+bootstrap.ScriptParked+"'" {
		t.Fatalf("the RCPT script's first rule %v", first)
	}
	if !strings.Contains(bootstrap.ParkedRejectSieve, `reject "550 5.1.1`) {
		t.Fatal("parked-reject isn't 550 5.1.1")
	}
}

// A sender missing from a present list is removed (§19.14): its mail
// passwords destroyed first, then the account and its lookup key; an
// empty list removes every sender; an absent list (an older Hub) leaves
// them all untouched.
func TestSenderRemovedWithInstance(t *testing.T) {
	e := newEnv(t)
	d := sendersDoc(t)
	e.mustApply(d)
	app := e.account(appSender)["id"].(string)
	hubID := e.account(hubSender)["id"].(string)
	e.f.Put("AppPassword", app, map[string]any{"description": "fxa"})
	e.f.Put("AppPassword", hubID, map[string]any{"description": "hub"})

	// Absent: untouched (accounts, passwords, keys).
	absent := baseDoc(t)
	absent.Generation = 13
	e.f.ResetCalls()
	e.mustApply(absent)
	if e.account(appSender) == nil || e.account(hubSender) == nil || len(e.f.Objects("AppPassword", app)) != 1 || len(e.senderKeys()) != 2 {
		t.Fatal("an absent senders list touched the senders")
	}
	for _, c := range e.f.Calls {
		if strings.HasPrefix(c, "x:Account/set") || strings.HasPrefix(c, "x:AppPassword/set") || strings.HasPrefix(c, "x:MemoryLookupKey/set") {
			t.Errorf("absent senders: %s", c)
		}
	}

	// The instance's sender gone from the list.
	hubOnly := withSenders(sendersDoc(t), d.SenderList()[0])
	hubOnly.Generation = 14
	e.f.ResetCalls()
	e.mustApply(hubOnly)
	if e.account(appSender) != nil {
		t.Fatal("the removed instance's sender is still there")
	}
	if len(e.f.Objects("AppPassword", app)) != 0 {
		t.Fatal("its mail password survived")
	}
	if keys := e.senderKeys(); len(keys) != 1 || !keys[hubSender+"@example.com"] {
		t.Fatalf("keys after the removal %v", keys)
	}
	if e.account(hubSender) == nil || len(e.f.Objects("AppPassword", hubID)) != 1 {
		t.Fatal("the remaining sender was touched")
	}
	pwAt, acctAt := -1, -1
	for i, c := range e.f.Calls {
		if strings.HasPrefix(c, "x:AppPassword/set destroy") && pwAt < 0 {
			pwAt = i
		}
		if c == "x:Account/set destroy "+app {
			acctAt = i
		}
	}
	if pwAt < 0 || acctAt < pwAt {
		t.Errorf("order: passwords %d, account %d: %v", pwAt, acctAt, e.f.Calls)
	}

	// A sender whose uuid the Hub replaced (a void): the old account goes,
	// a new one is made under the same name.
	re := withSenders(sendersDoc(t), state.Sender{Username: hubSender, UUID: uAlice2, Address: hubSender + "@example.com"})
	re.Generation = 15
	e.mustApply(re)
	if a := e.account(hubSender); a == nil || a["description"] != DescSenderPrefix+uAlice2 || a["id"] == hubID {
		t.Fatalf("replaced uuid: %v", a)
	}

	// Empty: every sender and key removed; the people stay.
	empty := withSenders(sendersDoc(t))
	empty.Generation = 16
	e.mustApply(empty)
	if e.account(hubSender) != nil || len(e.senderKeys()) != 0 {
		t.Fatal("an empty senders list kept a sender")
	}
	if e.account("alice") == nil || e.account("bob") == nil || e.account("root") == nil {
		t.Fatal("removing the senders touched the people")
	}
}

// Senders follow their instance and are excluded from the 50 % rule
// (§19.5): removing every sender is never a mass removal, senders don't
// count towards the live accounts it is judged against, and a refused
// mass removal of people still reconciles the senders.
func TestSenderNotMassRemoval(t *testing.T) {
	e := newEnv(t)
	e.mustApply(sendersDoc(t))
	empty := withSenders(sendersDoc(t))
	empty.Generation = 13
	if err := e.apply(empty); err != nil {
		t.Fatalf("removing every sender: %v", err)
	}
	if e.account(hubSender) != nil || e.account(appSender) != nil {
		t.Fatal("the senders weren't removed")
	}

	// 3 people + 2 senders; removing 2 people is more than half of the 3
	// people (the senders don't dilute it): refused. The senders' change
	// in the same document still applies.
	back := sendersDoc(t)
	back.Generation = 14
	e.mustApply(back)
	d := withSenders(sendersDoc(t), back.SenderList()[0])
	d.Generation = 15
	dropAccount(d, "bob")
	dropAccount(d, "root")
	d.Postmaster = []string{"alice"}
	l, err := Read(context.Background(), e.c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Plan(l, d, nil, e.now, 1<<62, nil); !errors.Is(err, ErrMassRemoval) {
		t.Fatalf("plan: %v (want the mass removal)", err)
	}
	if err := e.apply(d); !errors.Is(err, ErrMassRemoval) {
		t.Fatalf("apply: %v (want the mass removal)", err)
	}
	if e.account("bob") == nil || !strings.HasPrefix(e.account("bob")["name"].(string), "bob") {
		t.Fatal("a refused mass removal parked bob")
	}
	if e.account(appSender) != nil {
		t.Fatal("the senders weren't reconciled next to the refused removal")
	}
	if e.account(hubSender) == nil {
		t.Fatal("the listed sender went")
	}
}

// The senders' permission lists are Stalwart v1.1.0's (schema snapshot,
// stalwart.Used) and mailctl's role can grant them.
func TestSenderPermissionsGrantable(t *testing.T) {
	role := map[string]bool{}
	for _, p := range stalwart.MailctlRolePermissions {
		role[p] = true
	}
	for _, p := range stalwart.SenderPermissions {
		if !role[p] {
			t.Errorf("mailctl's role can't grant %s", p)
		}
	}
	if len(stalwart.SenderPermissions) != 2 {
		t.Errorf("SenderPermissions %v (want authenticate, emailSend)", stalwart.SenderPermissions)
	}
}

// Each sender is rate-limited (§19.14): 10 messages a minute and 60 an
// hour, keyed on the login, matching only the senders' logins (the
// NSSenders keys); made on the first pass whatever the list (absent
// included), put back after drift, a duplicate removed.
func TestSenderRateLimit(t *testing.T) {
	e := newEnv(t)
	e.mustApply(baseDoc(t)) // senders absent: the limits are made anyway
	limits := func() map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, th := range e.f.Objects("MtaInboundThrottle", "") {
			if d := th["description"].(string); d == DescSenderMinute || d == DescSenderHour {
				if out[d] != nil {
					t.Fatalf("%s twice", d)
				}
				out[d] = th
			}
		}
		return out
	}
	want := map[string][2]float64{DescSenderMinute: {10, 60000}, DescSenderHour: {60, 3600000}}
	check := func(when string) {
		t.Helper()
		got := limits()
		if len(got) != 2 {
			t.Fatalf("%s: sender limits %v", when, got)
		}
		for d, w := range want {
			th := got[d]
			r := th["rate"].(map[string]any)
			m := th["match"].(map[string]any)
			k := permSet(th["key"])
			if r["count"] != w[0] || r["period"] != w[1] || th["enable"] != true || m["else"] != "key_exists('"+bootstrap.NSSenders+"', authenticated_as)" ||
				len(m["match"].(map[string]any)) != 0 || len(k) != 1 || !k["authenticatedAs"] {
				t.Errorf("%s: %s = %v", when, d, th)
			}
		}
	}
	check("first pass")
	reload := false
	for _, c := range e.f.Calls {
		if c == "x:Action/set ReloadSettings" {
			reload = true
		}
	}
	if !reload {
		t.Error("no ReloadSettings after the limits were made")
	}
	// Drift: a raised count, a widened match, a disabled limit, a duplicate.
	got := limits()
	if _, err := e.c.Set(context.Background(), "MtaInboundThrottle", map[string]any{"dup": senderThrottleFields(SenderLimits[1])},
		map[string]map[string]any{
			got[DescSenderMinute]["id"].(string): {"rate": map[string]any{"count": 1000, "period": 60000}, "match": map[string]any{"match": map[string]any{}, "else": "true"}},
			got[DescSenderHour]["id"].(string):   {"enable": false},
		}, nil); err != nil {
		t.Fatal(err)
	}
	d := sendersDoc(t)
	d.Generation = 13
	e.mustApply(d)
	check("after drift")
	// Steady: nothing written.
	e.f.ResetCalls()
	d.Generation = 14
	e.mustApply(d)
	for _, c := range e.f.Calls {
		if strings.HasPrefix(c, "x:MtaInboundThrottle/set") {
			t.Errorf("steady pass wrote %s", c)
		}
	}
}
