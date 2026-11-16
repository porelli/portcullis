package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

func spamEnv(t *testing.T) (*fake.Server, *stalwart.Client, *state.Store) {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	st, _ := state.Open(t.TempDir())
	old := [3]time.Duration{spamTaskEvery, spamTaskWait, spamTaskPoll}
	spamTaskWait, spamTaskPoll = 200*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { spamTaskEvery, spamTaskWait, spamTaskPoll = old[0], old[1], old[2] })
	return f, stalwart.New(f.URL(), stalwart.Bearer("API_k")), st
}

func putAllRules(f *fake.Server) {
	names, _ := spamrules.RuleNames()
	for _, n := range names {
		f.Put("SpamRule", "", map[string]any{"@type": "Any", "name": n})
	}
}

// The vendored rules: an import task while they aren't in Stalwart (one
// per 5 min, never per call), the sha recorded only once every vendored
// rule name is there, nothing asked after that; another sha asks again.
func TestEnsureSpamRules(t *testing.T) {
	f, c, st := spamEnv(t)
	ctx, now := context.Background(), time.Unix(1_800_000_000, 0)
	tasks := func() int { return len(f.Objects("Task", "")) }
	ok, req, err := EnsureSpamRules(ctx, c, st, now)
	if ok || !req || err == nil || tasks() != 1 {
		t.Fatalf("no rules: ok %v req %v err %v tasks %d", ok, req, err, tasks())
	}
	for _, o := range f.Objects("Task", "") {
		if o["@type"] != "SpamFilterMaintenance" || o["maintenanceType"] != "updateRules" {
			t.Fatalf("task %v", o)
		}
	}
	if s := ReadSpamRules(st.Get()); s.Imported != "" || s.Error == "" {
		t.Fatalf("recorded before the proof: %+v", s)
	}
	if _, req, _ := EnsureSpamRules(ctx, c, st, now.Add(time.Minute)); req || tasks() != 1 {
		t.Fatalf("a task per call: %d", tasks())
	}
	if _, req, _ := EnsureSpamRules(ctx, c, st, now.Add(6*time.Minute)); !req || tasks() != 2 {
		t.Fatalf("no new task after 5 min: %d", tasks())
	}
	names, _ := spamrules.RuleNames()
	for _, n := range names[:len(names)-1] {
		f.Put("SpamRule", "", map[string]any{"@type": "Any", "name": n})
	}
	if ok, _, _ := EnsureSpamRules(ctx, c, st, now.Add(7*time.Minute)); ok {
		t.Fatal("verified with a rule missing")
	}
	f.Put("SpamRule", "", map[string]any{"@type": "Any", "name": names[len(names)-1]})
	if ok, _, err := EnsureSpamRules(ctx, c, st, now.Add(8*time.Minute)); !ok || err != nil {
		t.Fatalf("every rule there: %v %v", ok, err)
	}
	if s := ReadSpamRules(st.Get()); s.Imported != spamrules.SHA256 || s.ImportedAt == nil || s.Error != "" {
		t.Fatalf("recorded %+v", s)
	}
	f.ResetCalls()
	if ok, _, _ := EnsureSpamRules(ctx, c, st, now.Add(time.Hour)); !ok || len(f.Calls) != 0 {
		t.Fatalf("after the import: ok %v, calls %v", ok, f.Calls)
	}
	put(st, SpamRulesState{Imported: "older"})
	if ok, _, _ := EnsureSpamRules(ctx, c, st, now.Add(2*time.Hour)); !ok {
		t.Fatal("re-verified rules not recorded")
	}
}

// A task finishing late (it turns the lookups on when it lands): the pass
// waits for it, then verifies, then turns the lookups off; a lookup
// switched on an hour later is turned off by the next 15-minute pass; a
// lookup that can't be turned off is recorded (the external_lookups
// Problem).
func TestSpamRulesPassLateTaskAndReenabledLookup(t *testing.T) {
	f, c, st := spamEnv(t)
	spamTaskWait = 3 * time.Second
	ctx, start := context.Background(), time.Now()
	go func() {
		// The import lands after the request: the task goes, the rules and
		// their (enabled) feeds appear.
		for len(f.Objects("Task", "")) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond)
		var ids []string
		var tasks []struct {
			ID string `json:"id"`
		}
		_ = c.Get(ctx, "Task", nil, []string{"id"}, &tasks)
		for _, tk := range tasks {
			ids = append(ids, tk.ID)
		}
		putAllRules(f)
		f.Put("HttpLookup", "", map[string]any{"namespace": "openphish", "enable": true})
		_, _ = c.Set(ctx, "Task", nil, nil, ids)
	}()
	var logs []string
	logf := func(format string, a ...any) { logs = append(logs, format) }
	last, wait := SpamRulesPass(ctx, c, st, start, start, logf)
	if s := ReadSpamRules(st.Get()); s.Imported != spamrules.SHA256 {
		t.Fatalf("the late import wasn't waited for: %+v %v", s, logs)
	}
	for _, l := range f.Objects("HttpLookup", "") {
		if l["enable"] != false {
			t.Fatalf("a lookup left on after the late import: %v", l)
		}
	}
	if wait != time.Minute || !last.Equal(start) {
		t.Fatalf("after an import request: wait %v, last %v", wait, last)
	}
	// An hour later a lookup is on again: the 15-minute pass turns it off.
	f.Put("HttpLookup", "", map[string]any{"namespace": "phishtank", "enable": true})
	_, wait = SpamRulesPass(ctx, c, st, start.Add(time.Hour), last, logf)
	if wait != 15*time.Minute {
		t.Fatalf("an hour after the request: wait %v", wait)
	}
	for _, l := range f.Objects("HttpLookup", "") {
		if l["enable"] != false {
			t.Fatalf("a re-enabled lookup left on: %v", l)
		}
	}
	if s := ReadLookups(st.Get()); s.Error != "" || s.Disabled != 1 || s.CheckedAt == nil {
		t.Fatalf("lookups state %+v", s)
	}
	// Can't be turned off: recorded, and the next pass comes in a minute.
	f.Put("HttpLookup", "", map[string]any{"namespace": "x", "enable": true})
	f.Fail("x:HttpLookup/set", 1)
	_, wait = SpamRulesPass(ctx, c, st, start.Add(2*time.Hour), last, logf)
	if s := ReadLookups(st.Get()); s.Error == "" || wait != time.Minute {
		t.Fatalf("a failed turn-off: %+v, wait %v", s, wait)
	}
	if !strings.Contains(strings.Join(logs, "|"), "couldn't be turned off") {
		t.Fatalf("not logged: %v", logs)
	}
}
