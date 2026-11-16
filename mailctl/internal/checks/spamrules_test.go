package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/state"
)

// spam_rules: a Problem until the vendored sha is imported, ok after.
func TestSpamRulesCheck(t *testing.T) {
	p := state.Persistent{Ext: map[string]json.RawMessage{}}
	if c := spamRulesCheck(p); c.Severity != Problem || !strings.Contains(c.Detail, "no spam rules") {
		t.Fatalf("none: %+v", c)
	}
	b, _ := json.Marshal(bootstrap.SpamRulesState{Imported: "older", Error: "3 of 66 vendored rules not in Stalwart yet (import requested)"})
	p.Ext[bootstrap.ExtSpamRules] = b
	if c := spamRulesCheck(p); c.Severity != Problem || !strings.Contains(c.Detail, "3 of 66") {
		t.Fatalf("an older import: %+v", c)
	}
	b, _ = json.Marshal(bootstrap.SpamRulesState{Imported: spamrules.SHA256})
	p.Ext[bootstrap.ExtSpamRules] = b
	if c := spamRulesCheck(p); c.Severity != OK {
		t.Fatalf("imported: %+v", c)
	}
}

// external_lookups: a Problem when lookups were found on and couldn't be
// turned off.
func TestLookupsCheck(t *testing.T) {
	p := state.Persistent{Ext: map[string]json.RawMessage{}}
	if c := lookupsCheck(p); c.Severity != Info {
		t.Fatalf("never checked: %+v", c)
	}
	now := time.Now()
	b, _ := json.Marshal(bootstrap.LookupsState{CheckedAt: &now, Error: "x:HttpLookup/set: stalwart: HTTP 500"})
	p.Ext[bootstrap.ExtLookups] = b
	if c := lookupsCheck(p); c.Severity != Problem || !strings.Contains(c.Detail, "couldn't be turned off") {
		t.Fatalf("on and stuck: %+v", c)
	}
	b, _ = json.Marshal(bootstrap.LookupsState{CheckedAt: &now})
	p.Ext[bootstrap.ExtLookups] = b
	if c := lookupsCheck(p); c.Severity != OK {
		t.Fatalf("off: %+v", c)
	}
}
