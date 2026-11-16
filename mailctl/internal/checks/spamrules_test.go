package checks

import (
	"encoding/json"
	"strings"
	"testing"

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
