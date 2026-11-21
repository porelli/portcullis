package viewer

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// startJSHarness is a tiny DOM for startJS under node: the page's html
// element (data-hub-origin), the wait message and the form, window's
// message listeners, a captured setTimeout, and ports that record what
// the page sends and answer "ready" with the case's reply (none: a port
// that never answers).
const startJSHarness = `
const out = { readies: 0, submitted: null, timeoutMs: null };
const wait = { hidden: true };
const form = { elements: { t: { value: '' } }, submit() { out.submitted = form.elements.t.value; } };
const listeners = [];
let timer = null;
global.document = {
  documentElement: { getAttribute: (n) => (n === 'data-hub-origin' ? HUB : null) },
  getElementById: (id) => (id === 'portcullis-wait' ? wait : id === 'portcullis-open' ? form : null),
};
global.window = { addEventListener: (t, f) => { if (t === 'message') listeners.push(f); } };
global.setTimeout = (f, ms) => { timer = f; out.timeoutMs = ms; };
function port(reply) {
  const p = {
    onmessage: null,
    postMessage(m) {
      if (m && m.type === 'portcullis-mail-admin-ready') {
        out.readies++;
        if (reply !== undefined && p.onmessage) p.onmessage({ data: reply });
      }
    },
    close() {},
  };
  return p;
}
function hello(origin, data, ports) { listeners.forEach((f) => f({ origin, data, ports })); }
const H = { type: 'portcullis-mail-admin-hello' };
const GOOD = { type: 'portcullis-mail-admin-ticket', ticket: 'v1.eyJ1IjoiYSJ9.c2ln' };
`

// TestStartJS runs the start page's script (review M2): only the first
// hello counts, and only from exactly the Hub's origin with one port; the
// ticket must come typed and well-formed on that port; 15 s without a
// posted ticket shows the message for good (nit1, nit2).
func TestStartJS(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI for the start page's script test")
		}
		t.Skip("no node")
	}
	type result struct {
		Readies   int
		Submitted *string
		TimeoutMs int
		Wait      bool
	}
	run := func(hub, steps string) result {
		t.Helper()
		js := "const HUB = " + strings.TrimSpace(hub) + ";\n" + startJSHarness + startJS + steps +
			"\nprocess.stdout.write(JSON.stringify({ readies: out.readies, submitted: out.submitted, timeoutMs: out.timeoutMs, wait: !wait.hidden }));"
		b, err := exec.Command("node", "-e", js).CombinedOutput()
		if err != nil {
			t.Fatalf("node: %v: %s", err, b)
		}
		var r result
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%v: %s", err, b)
		}
		return r
	}
	const hub = `'https://hub.example.org'`
	good := "v1.eyJ1IjoiYSJ9.c2ln"
	for name, c := range map[string]struct {
		hub, steps   string
		readies      int
		submit, wait bool
	}{
		"the Hub":                   {hub, `hello('https://hub.example.org', H, [port(GOOD)]);`, 1, true, false},
		"an app of the same site":   {hub, `hello('https://app.example.org', H, [port(GOOD)]);`, 0, false, false},
		"another site":              {hub, `hello('https://evil.test', H, [port(GOOD)]);`, 0, false, false},
		"the Hub over http":         {hub, `hello('http://hub.example.org', H, [port(GOOD)]);`, 0, false, false},
		"no port":                   {hub, `hello('https://hub.example.org', H, []); hello('https://hub.example.org', H, undefined);`, 0, false, false},
		"two ports":                 {hub, `hello('https://hub.example.org', H, [port(GOOD), port(GOOD)]);`, 0, false, false},
		"not a hello":               {hub, `hello('https://hub.example.org', { type: 'x' }, [port(GOOD)]); hello('https://hub.example.org', null, [port(GOOD)]);`, 0, false, false},
		"a malformed ticket":        {hub, `hello('https://hub.example.org', H, [port({ type: 'portcullis-mail-admin-ticket', ticket: 'v1.a b.c' })]);`, 1, false, true},
		"an untyped ticket":         {hub, `hello('https://hub.example.org', H, [port({ ticket: GOOD.ticket })]);`, 1, false, true},
		"a second hello":            {hub, `hello('https://hub.example.org', H, [port()]); hello('https://hub.example.org', H, [port(GOOD)]);`, 1, false, false},
		"stalled after ready":       {hub, `hello('https://hub.example.org', H, [port()]); timer();`, 1, false, true},
		"no offer in time":          {hub, `timer();`, 0, false, true},
		"a hello after giving up":   {hub, `timer(); hello('https://hub.example.org', H, [port(GOOD)]);`, 0, false, true},
		"no Hub origin on the page": {`''`, `hello('', H, [port(GOOD)]); hello('null', H, [port(GOOD)]);`, 0, false, false},
	} {
		r := run(c.hub, c.steps)
		if r.Readies != c.readies || (r.Submitted != nil) != c.submit || r.Wait != c.wait || r.TimeoutMs != 15000 {
			t.Errorf("%s: %+v", name, r)
		}
		if c.submit && *r.Submitted != good {
			t.Errorf("%s: submitted %q", name, *r.Submitted)
		}
	}
}
