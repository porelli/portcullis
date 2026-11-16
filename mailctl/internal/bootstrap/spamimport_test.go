package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

// The vendored rules: an import task while they aren't in Stalwart (one
// per 5 min, never per call), the sha recorded only once every vendored
// rule name is there, nothing asked after that; an image update (another
// sha) asks again.
func TestEnsureSpamRules(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	st, _ := state.Open(t.TempDir())
	ctx, now := context.Background(), time.Unix(1_800_000_000, 0)
	tasks := func() int { return len(f.Objects("Task", "")) }

	ok, err := EnsureSpamRules(ctx, c, st, now)
	if ok || err == nil || tasks() != 1 {
		t.Fatalf("no rules: ok %v err %v tasks %d", ok, err, tasks())
	}
	for _, o := range f.Objects("Task", "") {
		if o["@type"] != "SpamFilterMaintenance" || o["maintenanceType"] != "updateRules" {
			t.Fatalf("task %v", o)
		}
	}
	if s := ReadSpamRules(st.Get()); s.Imported != "" || s.Error == "" {
		t.Fatalf("recorded before the proof: %+v", s)
	}
	if ok, _ := EnsureSpamRules(ctx, c, st, now.Add(time.Minute)); ok || tasks() != 1 {
		t.Fatalf("a task per call: %d", tasks())
	}
	if _, _ = EnsureSpamRules(ctx, c, st, now.Add(6*time.Minute)); tasks() != 2 {
		t.Fatalf("no new task after 5 min: %d", tasks())
	}
	names, _ := spamrules.RuleNames()
	for _, n := range names[:len(names)-1] {
		f.Put("SpamRule", "", map[string]any{"@type": "Any", "name": n})
	}
	if ok, _ := EnsureSpamRules(ctx, c, st, now.Add(7*time.Minute)); ok {
		t.Fatal("verified with a rule missing")
	}
	f.Put("SpamRule", "", map[string]any{"@type": "Any", "name": names[len(names)-1]})
	if ok, err := EnsureSpamRules(ctx, c, st, now.Add(8*time.Minute)); !ok || err != nil {
		t.Fatalf("every rule there: %v %v", ok, err)
	}
	if s := ReadSpamRules(st.Get()); s.Imported != spamrules.SHA256 || s.ImportedAt == nil || s.Error != "" {
		t.Fatalf("recorded %+v", s)
	}
	f.ResetCalls()
	if ok, _ := EnsureSpamRules(ctx, c, st, now.Add(time.Hour)); !ok || len(f.Calls) != 0 {
		t.Fatalf("after the import: ok %v, calls %v", ok, f.Calls)
	}
	// Another vendored file (an image update): checked again.
	put(st, SpamRulesState{Imported: "older"})
	if ok, _ := EnsureSpamRules(ctx, c, st, now.Add(2*time.Hour)); !ok {
		t.Fatal("re-verified rules not recorded")
	}
}
