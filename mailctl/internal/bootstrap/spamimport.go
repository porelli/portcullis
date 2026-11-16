package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/portcullis/mailctl/internal/spamrules"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// ExtSpamRules is state.json's ext key for the spam rules import.
const ExtSpamRules = "spam_rules"

// SpamRulesState: the vendored file's sha256 last imported and verified
// (Imported), when, and the last import task's request (TaskAt) and error.
type SpamRulesState struct {
	Imported   string     `json:"imported"`
	ImportedAt *time.Time `json:"imported_at"`
	TaskAt     *time.Time `json:"task_at"`
	Error      string     `json:"error"`
}

// ReadSpamRules is the recorded import state.
func ReadSpamRules(p state.Persistent) SpamRulesState {
	var s SpamRulesState
	_ = json.Unmarshal(p.Ext[ExtSpamRules], &s)
	return s
}

// spamTaskEvery: a new import task while the rules aren't there yet.
const spamTaskEvery = 5 * time.Minute

// EnsureSpamRules imports the vendored spam rules into Stalwart (contract
// §19.8): whenever the vendored file's sha256 isn't the one last imported
// and verified (the first start, an image update), it asks for Stalwart's
// SpamFilterMaintenance task updateRules — Stalwart downloads from
// SpamSettings.spamFilterRulesUrl, which is mailctl's own copy (no
// network) — and records the sha only once every vendored rule name is in
// Stalwart. Until then each call checks again (a new task every 5 min);
// the spam_rules check is a Problem meanwhile. Returns whether the rules
// are in place.
func EnsureSpamRules(ctx context.Context, c *stalwart.Client, st *state.Store, now time.Time) (bool, error) {
	cur := ReadSpamRules(st.Get())
	if cur.Imported == spamrules.SHA256 {
		return true, nil
	}
	names, err := spamrules.RuleNames()
	if err != nil {
		return false, err
	}
	have, err := getAll(ctx, c, "SpamRule")
	if err != nil {
		return false, record(st, cur, err)
	}
	got := map[string]bool{}
	for _, r := range have {
		got[str(r, "name")] = true
	}
	missing := 0
	for _, n := range names {
		if !got[n] {
			missing++
		}
	}
	if missing == 0 && len(names) > 0 {
		t := now.UTC()
		cur.Imported, cur.ImportedAt, cur.Error = spamrules.SHA256, &t, ""
		return true, put(st, cur)
	}
	if cur.TaskAt == nil || now.Sub(*cur.TaskAt) >= spamTaskEvery {
		r, err := c.Set(ctx, "Task", map[string]any{"t": map[string]any{
			"@type": "SpamFilterMaintenance", "maintenanceType": "updateRules"}}, nil, nil)
		if err := checkSet("Task", r, err); err != nil {
			return false, record(st, cur, err)
		}
		t := now.UTC()
		cur.TaskAt = &t
	}
	cur.Error = fmt.Sprintf("%d of %d vendored rules not in Stalwart yet (import requested)", missing, len(names))
	return false, record(st, cur, errors.New(cur.Error))
}

func put(st *state.Store, s SpamRulesState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.Update(func(p *state.Persistent) error {
		if p.Ext == nil {
			p.Ext = map[string]json.RawMessage{}
		}
		p.Ext[ExtSpamRules] = b
		return nil
	})
}

// record saves cur with err's text and returns err.
func record(st *state.Store, cur SpamRulesState, err error) error {
	cur.Error = err.Error()
	if perr := put(st, cur); perr != nil {
		return errors.Join(err, perr)
	}
	return err
}

func init() {
	stalwart.Used = append(stalwart.Used,
		stalwart.Use{Object: "x:Task", Variant: "SpamFilterMaintenance", Field: "maintenanceType"},
		stalwart.Use{Enum: "TaskSpamFilterMaintenanceType", Value: "updateRules"},
		stalwart.Use{Object: "x:SpamRule", Variant: "Any", Field: "name"},
	)
}
