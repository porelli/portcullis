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

// spamTaskEvery: a new import task while the rules aren't there yet;
// spamTaskWait / spamTaskPoll: how long a requested task is waited for.
var (
	spamTaskEvery = 5 * time.Minute
	spamTaskWait  = 2 * time.Minute
	spamTaskPoll  = 2 * time.Second
)

// EnsureSpamRules imports the vendored spam rules into Stalwart (contract
// §19.8): whenever the vendored file's sha256 isn't the one last imported
// and verified (the first start, an image update), it asks for Stalwart's
// SpamFilterMaintenance task updateRules — Stalwart downloads from
// SpamSettings.spamFilterRulesUrl, which is mailctl's own copy (no
// network) —, waits for that task to finish (at most spamTaskWait), and
// records the sha only once every vendored rule name is in Stalwart.
// Until then each call checks again (a new task every 5 min); the
// spam_rules check is a Problem meanwhile. ok: the rules are in place;
// requested: a task was asked for (the import turns the rules' external
// lookups on: the caller turns them off after it).
func EnsureSpamRules(ctx context.Context, c *stalwart.Client, st *state.Store, now time.Time) (ok, requested bool, err error) {
	cur := ReadSpamRules(st.Get())
	if cur.Imported == spamrules.SHA256 {
		return true, false, nil
	}
	names, err := spamrules.RuleNames()
	if err != nil {
		return false, false, err
	}
	missing, err := missingRules(ctx, c, names)
	if err != nil {
		return false, false, record(st, cur, err)
	}
	if missing > 0 && (cur.TaskAt == nil || now.Sub(*cur.TaskAt) >= spamTaskEvery) {
		r, err := c.Set(ctx, "Task", map[string]any{"t": map[string]any{
			"@type": "SpamFilterMaintenance", "maintenanceType": "updateRules"}}, nil, nil)
		if err := checkSet("Task", r, err); err != nil {
			return false, false, record(st, cur, err)
		}
		t := now.UTC()
		cur.TaskAt, requested = &t, true
		if err := waitTask(ctx, c, r.CreatedID("t")); err != nil {
			return false, true, record(st, cur, err)
		}
		if missing, err = missingRules(ctx, c, names); err != nil {
			return false, true, record(st, cur, err)
		}
	}
	if missing == 0 && len(names) > 0 {
		t := now.UTC()
		cur.Imported, cur.ImportedAt, cur.Error = spamrules.SHA256, &t, ""
		return true, requested, put(st, cur)
	}
	cur.Error = fmt.Sprintf("%d of %d vendored rules not in Stalwart yet (import requested)", missing, len(names))
	return false, requested, record(st, cur, errors.New(cur.Error))
}

func missingRules(ctx context.Context, c *stalwart.Client, names []string) (int, error) {
	have, err := getAll(ctx, c, "SpamRule")
	if err != nil {
		return 0, err
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
	return missing, nil
}

// waitTask polls the task until it is gone (done) or failed, at most
// spamTaskWait (then the next pass verifies again).
func waitTask(ctx context.Context, c *stalwart.Client, id string) error {
	if id == "" {
		return errors.New("the import task has no id")
	}
	deadline := time.Now().Add(spamTaskWait)
	for {
		var ts []struct {
			Status struct {
				Type   string `json:"@type"`
				Reason string `json:"failureReason"`
			} `json:"status"`
		}
		if err := c.Get(ctx, "Task", []string{id}, []string{"status"}, &ts); err != nil {
			return fmt.Errorf("the import task: %w", err)
		}
		switch {
		case len(ts) == 0:
			return nil
		case ts[0].Status.Type == "Failed":
			return fmt.Errorf("the import task failed: %s", ts[0].Status.Reason)
		}
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(spamTaskPoll):
		}
	}
}

// ExtLookups is state.json's ext key for the external lookups' check.
const ExtLookups = "external_lookups"

// LookupsState: the last lookups-off check (an error = lookups on that
// couldn't be turned off), and the last time it turned some off.
type LookupsState struct {
	CheckedAt  *time.Time `json:"checked_at"`
	Error      string     `json:"error"`
	DisabledAt *time.Time `json:"disabled_at"`
	Disabled   int        `json:"disabled"`
}

// ReadLookups is the recorded lookups-off check.
func ReadLookups(p state.Persistent) LookupsState {
	var s LookupsState
	_ = json.Unmarshal(p.Ext[ExtLookups], &s)
	return s
}

// Pass timing: every minute for lookupsFastFor after a start or an import
// request (an import finishing late turns the lookups on), else every
// lookupsSlowEvery — forever (one query).
const (
	lookupsFastFor   = 30 * time.Minute
	lookupsSlowEvery = 15 * time.Minute
)

// SpamRulesPass is `mailctl serve`'s spam rules loop body: the import
// (EnsureSpamRules, its own minute), then always the lookups-off check
// (its own minute, never skipped), recorded. lastFast is the start or the
// last import request; it returns the new one and the wait until the next
// pass. Log lines go to logf.
func SpamRulesPass(ctx context.Context, c *stalwart.Client, st *state.Store, now, lastFast time.Time, logf func(string, ...any)) (time.Time, time.Duration) {
	ictx, cancel := context.WithTimeout(ctx, time.Minute+spamTaskWait)
	ok, requested, err := EnsureSpamRules(ictx, c, st, now)
	cancel()
	if err != nil {
		logf("spam rules: %v", err)
	}
	if requested {
		lastFast = now
	}
	dctx, dcancel := context.WithTimeout(ctx, time.Minute)
	n, derr := DisableExternalLookups(dctx, c)
	dcancel()
	t := time.Now().UTC()
	ls := ReadLookups(st.Get())
	ls.CheckedAt, ls.Error = &t, ""
	switch {
	case derr != nil:
		ls.Error = derr.Error()
		logf("spam rules: external lookups may be on and couldn't be turned off: %v", derr)
	case n > 0:
		ls.DisabledAt, ls.Disabled = &t, n
		logf("spam rules: disabled %d external lookups", n)
	}
	if b, err := json.Marshal(ls); err == nil {
		_ = st.Update(func(p *state.Persistent) error {
			if p.Ext == nil {
				p.Ext = map[string]json.RawMessage{}
			}
			p.Ext[ExtLookups] = b
			return nil
		})
	}
	wait := lookupsSlowEvery
	if !ok || derr != nil || now.Sub(lastFast) < lookupsFastFor {
		wait = time.Minute
	}
	return lastFast, wait
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
		stalwart.Use{Object: "x:Task", Variant: "SpamFilterMaintenance", Field: "status"},
		stalwart.Use{Object: "x:TaskStatus", Variant: "Failed"},
		stalwart.Use{Object: "x:TaskStatusFailed", Field: "failureReason"},
	)
}
