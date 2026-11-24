package bootstrap

import (
	"context"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// A store bootstrapped before app mail senders (contract §19.14) has the
// RCPT script without its first rule. The marked-store job puts the base
// plan's rule first, keeps every other rule in its order, and never
// writes a script of any other shape.

// adminRule is a rule an admin added by hand after the plan's.
var adminRule = map[string]any{"if": "rcpt == 'nobody@example.com'", "then": "'list-reject'"}

func rcptRules() map[string]any {
	return normalize(rcptScript()["match"]).(map[string]any)
}

// preSenders gives the store the script it had before app mail senders:
// the plan's rules 1 and 2 as rules 0 and 1, then the admin's rule.
func preSenders(f *fakeStalwart) map[string]any {
	r := rcptRules()
	s := normalize(map[string]any{"else": "false", "match": map[string]any{"0": r["1"], "1": r["2"], "2": adminRule}}).(map[string]any)
	f.objs["MtaStageRcpt"]["singleton"]["script"] = s
	return s
}

func rcptOf(f *fakeStalwart) any { return normalize(f.objs["MtaStageRcpt"]["singleton"]["script"]) }

func ensureSenderRcpt(t *testing.T, f *fakeStalwart) SenderRcptHeal {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	h, err := EnsureSenderRcpt(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")))
	if err != nil {
		t.Fatalf("EnsureSenderRcpt: %v", err)
	}
	return h
}

// changedBut lists the objects changed besides MtaStageRcpt and Actions.
func changedBut(f *fakeStalwart, before map[string]any) []string {
	var out []string
	for _, c := range changedBesides(before, snapshot(f), "", "") {
		if c != "MtaStageRcpt/singleton" && !strings.HasPrefix(c, "Action/") {
			out = append(out, c)
		}
	}
	return out
}

func TestSenderRcptAddedFirstOthersKept(t *testing.T) {
	f := bootstrapped(t)
	old := preSenders(f)
	before := snapshot(f)
	h := ensureSenderRcpt(t, f)
	if !h.Added || h.Odd != "" {
		t.Fatalf("heal %+v", h)
	}
	if got := strings.Join(setCalls(f), ","); got != "x:MtaStageRcpt/set update,x:Action/set create" {
		t.Fatalf("sets %s", got)
	}
	if a := fmt.Sprint(f.writes[len(f.writes)-1].fields); !strings.Contains(a, "ReloadSettings") {
		t.Fatalf("last write %s, want ReloadSettings", a)
	}
	got := rcptOf(f).(map[string]any)
	m := got["match"].(map[string]any)
	om := old["match"].(map[string]any)
	if len(m) != 4 || !reflect.DeepEqual(m["0"], rcptRules()["0"]) || !reflect.DeepEqual(m["1"], om["0"]) ||
		!reflect.DeepEqual(m["2"], om["1"]) || !reflect.DeepEqual(m["3"], normalize(adminRule)) || got["else"] != "false" {
		t.Fatalf("script %v", got)
	}
	// The update is the script alone.
	for _, w := range f.writes {
		if w.obj == "MtaStageRcpt" && len(w.fields) != 1 {
			t.Fatalf("MtaStageRcpt patch %v", w.fields)
		}
	}
	if ch := changedBut(f, before); len(ch) > 0 {
		t.Fatalf("other objects changed: %v", ch)
	}
	// Idempotent: the next run writes nothing.
	f.calls = nil
	if h := ensureSenderRcpt(t, f); h.Added || h.Odd != "" || len(setCalls(f)) > 0 {
		t.Fatalf("second run %+v sets %v", h, setCalls(f))
	}
}

// Without the admin's rule the result is exactly the base plan's script.
func TestSenderRcptPlanShape(t *testing.T) {
	f := bootstrapped(t)
	r := rcptRules()
	f.objs["MtaStageRcpt"]["singleton"]["script"] = normalize(map[string]any{"else": "false", "match": map[string]any{"0": r["1"], "1": r["2"]}})
	if h := ensureSenderRcpt(t, f); !h.Added {
		t.Fatalf("heal %+v", h)
	}
	if !reflect.DeepEqual(rcptOf(f), normalize(rcptScript())) {
		t.Fatalf("script %v", rcptOf(f))
	}
}

func TestSenderRcptInPlaceUntouched(t *testing.T) {
	f := bootstrapped(t)
	// The plan's script, and the plan's with an admin's rule after it.
	withAdmin := normalize(rcptScript()).(map[string]any)
	withAdmin["match"].(map[string]any)["3"] = normalize(adminRule)
	for _, s := range []any{normalize(rcptScript()), withAdmin} {
		f.objs["MtaStageRcpt"]["singleton"]["script"] = s
		f.calls = nil
		if h := ensureSenderRcpt(t, f); h.Added || h.Odd != "" || len(setCalls(f)) > 0 {
			t.Fatalf("heal %+v sets %v", h, setCalls(f))
		}
		if !reflect.DeepEqual(rcptOf(f), s) {
			t.Fatalf("script changed: %v", rcptOf(f))
		}
	}
}

func TestSenderRcptOddShapeLeftAlone(t *testing.T) {
	r := rcptRules()
	differ := map[string]any{"if": "key_exists('" + NSSenders + "', rcpt)", "then": "'list-reject'"}
	for name, s := range map[string]any{
		"a string":            "false",
		"no else":             map[string]any{"match": map[string]any{"0": r["1"]}},
		"an extra key":        map[string]any{"else": "false", "match": map[string]any{"0": r["1"]}, "x": 1},
		"match a list":        map[string]any{"else": "false", "match": []any{r["1"]}},
		"a gap":               map[string]any{"else": "false", "match": map[string]any{"0": r["1"], "2": r["2"]}},
		"a rule with a key":   map[string]any{"else": "false", "match": map[string]any{"0": map[string]any{"if": "true", "then": "'x'", "z": 1}}},
		"a non-string rule":   map[string]any{"else": "false", "match": map[string]any{"0": map[string]any{"if": true, "then": "'x'"}}},
		"rule 0 differs":      map[string]any{"else": "false", "match": map[string]any{"0": differ, "1": r["1"], "2": r["2"]}},
		"the rule not first":  map[string]any{"else": "false", "match": map[string]any{"0": r["1"], "1": r["0"], "2": r["2"]}},
		"senders in its then": map[string]any{"else": "false", "match": map[string]any{"0": map[string]any{"if": "true", "then": "'" + NSSenders + "'"}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := bootstrapped(t)
			f.objs["MtaStageRcpt"]["singleton"]["script"] = normalize(s)
			before := snapshot(f)
			h := ensureSenderRcpt(t, f)
			if h.Added || h.Odd == "" || len(setCalls(f)) > 0 {
				t.Fatalf("heal %+v sets %v", h, setCalls(f))
			}
			if !reflect.DeepEqual(before, snapshot(f)) {
				t.Fatal("the store changed")
			}
		})
	}
	// No script at all, no settings at all.
	f := bootstrapped(t)
	delete(f.objs["MtaStageRcpt"]["singleton"], "script")
	if h := ensureSenderRcpt(t, f); h.Added || h.Odd == "" || len(setCalls(f)) > 0 {
		t.Fatalf("no script: %+v %v", h, setCalls(f))
	}
	delete(f.objs, "MtaStageRcpt")
	if h := ensureSenderRcpt(t, f); h.Added || h.Odd == "" || len(setCalls(f)) > 0 {
		t.Fatalf("no settings: %+v %v", h, setCalls(f))
	}
}

// The job on a marked store from before app mail senders: the rule put
// first with its log line (not "nothing to do"); the next start: nothing
// to do. An odd script: a warning, nothing written, "nothing to do".
func TestBootstrapJobSenderRcpt(t *testing.T) {
	s := &jobServer{f: newFake()}
	seedDefaults(s.f)
	j := newJob(t, s)
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	runJob := func() string {
		t.Helper()
		s.f.calls, s.f.writes = nil, nil
		var logs []string
		j.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
		if err := j.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		return strings.Join(logs, "\n")
	}
	if got := runJob(); !strings.Contains(got, "its API key is in place; nothing to do") || len(setCalls(s.f)) > 0 {
		t.Fatalf("a current store: logged %q, sets %v", got, setCalls(s.f))
	}
	preSenders(s.f)
	got := runJob()
	if !strings.Contains(got, "bootstrap: the RCPT script had no rule refusing mail to app mail senders: put it first (every other rule kept, in its order)") ||
		!strings.Contains(got, "its API key is in place; only the missing or differing pieces (above)") || strings.Contains(got, "nothing to do") {
		t.Fatalf("logged %q", got)
	}
	if sets := strings.Join(setCalls(s.f), ","); sets != "x:MtaStageRcpt/set update,x:Action/set create" {
		t.Fatalf("sets %s", sets)
	}
	if m := rcptOf(s.f).(map[string]any)["match"].(map[string]any); !reflect.DeepEqual(m["0"], rcptRules()["0"]) || len(m) != 4 {
		t.Fatalf("script %v", m)
	}
	if got := runJob(); !strings.Contains(got, "its API key is in place; nothing to do") || len(setCalls(s.f)) > 0 {
		t.Fatalf("next start logged %q, sets %v", got, setCalls(s.f))
	}
	s.f.objs["MtaStageRcpt"]["singleton"]["script"] = "false"
	got = runJob()
	if !strings.Contains(got, "bootstrap: warning: the RCPT script isn't the expected shape") || !strings.Contains(got, "nothing to do") || len(setCalls(s.f)) > 0 {
		t.Fatalf("odd script logged %q, sets %v", got, setCalls(s.f))
	}
	if s.f.objs["MtaStageRcpt"]["singleton"]["script"] != "false" {
		t.Fatal("the odd script was written")
	}
}
