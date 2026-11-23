package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// A store from before the admin view (contract §19.13) lacks its whole
// server side: the viewer role and account, the admin-view listener, the
// access rule's entry and the web admin's settings. The marked-store job
// makes or corrects exactly those, on every start, and nothing else.

func viewParams() Params {
	p := params()
	p.ViewerIP = netip.MustParseAddr("172.31.255.5")
	return p
}

// stockApp is a WebUI as Stalwart makes it at a start (not the plan's).
var stockApp = map[string]any{"enable": true, "description": "WebUI", "urlPrefix": map[string]any{"/": true}, "resourceUrl": "https://github.com/stalwartlabs/webui/releases/latest/download/webui.zip"}

// preAdminView turns a bootstrapped store into one made before the admin
// view: no viewer role / account, no admin-view listener, the access rule
// without its entry, the stock web admin.
func preAdminView(f *fakeStalwart) {
	dropViewer(f, true, true)
	for id, l := range f.objs["NetworkListener"] {
		if l["name"] == AdminViewListener {
			delete(f.objs["NetworkListener"], id)
		}
	}
	f.objs["Http"]["singleton"]["allowedEndpoints"] = normalize(params().AllowedEndpoints())
	for id := range f.objs["Application"] {
		f.objs["Application"][id] = normalize(stockApp).(map[string]any)
	}
}

func listenerID(f *fakeStalwart) string {
	for id, l := range f.objs["NetworkListener"] {
		if l["name"] == AdminViewListener {
			return id
		}
	}
	return ""
}

// changedOutside lists the objects ("Obj/id") added, removed or changed
// other than the admin view's own: the viewer role and account, the
// admin-view listener, the Http singleton, the Applications.
func changedOutside(f *fakeStalwart, before map[string]any) []string {
	role, acct := viewerIDs(f)
	var out []string
	for _, c := range changedBesides(before, snapshot(f), role, acct) {
		if c == "NetworkListener/"+listenerID(f) || c == "Http/singleton" || strings.HasPrefix(c, "Application/") {
			continue
		}
		out = append(out, c)
	}
	return out
}

func checkAdminView(t *testing.T, f *fakeStalwart, p Params) {
	t.Helper()
	id := listenerID(f)
	if id == "" {
		t.Fatal("no admin-view listener")
	}
	l := map[string]any{}
	for k, v := range f.objs["NetworkListener"][id] {
		l[k] = v
	}
	if !reflect.DeepEqual(l, normalize(adminViewListener())) {
		t.Fatalf("admin-view listener %v", l)
	}
	n := 0
	for _, o := range f.objs["NetworkListener"] {
		if o["name"] == AdminViewListener {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d admin-view listeners", n)
	}
	if got := f.objs["Http"]["singleton"]["allowedEndpoints"]; !reflect.DeepEqual(got, normalize(p.AllowedEndpoints())) {
		t.Fatalf("access rule %v", got)
	}
	if !strings.Contains(fmt.Sprint(f.objs["Http"]["singleton"]["allowedEndpoints"]), "listener == 'admin-view' && remote_ip == '172.31.255.5'") {
		t.Fatal("no admin-view entry in the access rule")
	}
	for id, a := range f.objs["Application"] {
		if len(differs(objectOf(a), WebUIApplication(), nil)) > 0 {
			t.Fatalf("Application %s %v", id, a)
		}
	}
}

func objectOf(m map[string]any) object {
	o := object{}
	for k, v := range m {
		b, _ := json.Marshal(v)
		o[k] = b
	}
	return o
}

func ensureAdminView(t *testing.T, f *fakeStalwart, p Params) AdminViewSetup {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	s, err := EnsureAdminView(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")), p)
	if err != nil {
		t.Fatalf("EnsureAdminView: %v", err)
	}
	return s
}

func sortedSets(f *fakeStalwart) string {
	s := setCalls(f)
	sort.Strings(s)
	return strings.Join(s, ",")
}

func TestEnsureAdminViewPreAdminViewStore(t *testing.T) {
	p := viewParams()
	f := newFake()
	seedDefaults(f)
	run(t, f, p, false)
	preAdminView(f)
	f.calls, f.writes = nil, nil
	before := snapshot(f)
	s := ensureAdminView(t, f, p)
	if !s.MadeListener || s.FixedListener || !s.SetRule || !s.FixedApp || s.NoApp {
		t.Fatalf("EnsureAdminView %+v", s)
	}
	if got := sortedSets(f); got != "x:Application/set update,x:Http/set update,x:NetworkListener/set create" {
		t.Fatalf("sets %s", got)
	}
	checkAdminView(t, f, p)
	if ch := changedOutside(f, before); len(ch) > 0 {
		t.Fatalf("other objects changed: %v", ch)
	}
	// The Http write is the access rule alone.
	for _, w := range f.writes {
		if w.obj == "Http" {
			if _, ok := w.fields["allowedEndpoints"]; !ok || len(w.fields) != 1 {
				t.Fatalf("Http patch %v", w.fields)
			}
		}
	}
	// Idempotent: a second run writes nothing.
	f.calls = nil
	if s := ensureAdminView(t, f, p); s.Changed() || len(setCalls(f)) > 0 {
		t.Fatalf("second run %+v sets %v", s, setCalls(f))
	}
}

// A listener that differs (another port, no TLS) is corrected; the other
// listeners are neither changed nor destroyed.
func TestEnsureAdminViewFixesListener(t *testing.T) {
	p := viewParams()
	f := newFake()
	seedDefaults(f)
	run(t, f, p, false)
	id := listenerID(f)
	f.objs["NetworkListener"][id]["bind"] = map[string]any{"[::]:9443": true}
	f.objs["NetworkListener"][id]["useTls"] = false
	f.put("NetworkListener", map[string]any{"name": "someone-elses", "protocol": "http", "bind": map[string]any{"[::]:9999": true}})
	f.calls, f.writes = nil, nil
	before := snapshot(f)
	s := ensureAdminView(t, f, p)
	if s.MadeListener || !s.FixedListener || s.SetRule || s.FixedApp {
		t.Fatalf("EnsureAdminView %+v", s)
	}
	if got := sortedSets(f); got != "x:NetworkListener/set update" {
		t.Fatalf("sets %s", got)
	}
	if listenerID(f) != id {
		t.Fatal("the listener was replaced, not corrected")
	}
	checkAdminView(t, f, p)
	if ch := changedOutside(f, before); len(ch) > 0 {
		t.Fatalf("other objects changed: %v", ch)
	}
}

// Without a ViewerIP the access rule isn't touched; without an
// Application none is made (Stalwart makes the WebUI at a start).
func TestEnsureAdminViewNoViewerIPNoApp(t *testing.T) {
	f := newFake()
	seedDefaults(f)
	run(t, f, viewParams(), false)
	preAdminView(f)
	for id := range f.objs["Application"] {
		delete(f.objs["Application"], id)
	}
	f.calls = nil
	rule := normalize(f.objs["Http"]["singleton"]["allowedEndpoints"])
	s := ensureAdminView(t, f, params())
	if !s.MadeListener || s.SetRule || s.FixedApp || !s.NoApp {
		t.Fatalf("EnsureAdminView %+v", s)
	}
	if got := sortedSets(f); got != "x:NetworkListener/set create" {
		t.Fatalf("sets %s", got)
	}
	if !reflect.DeepEqual(rule, normalize(f.objs["Http"]["singleton"]["allowedEndpoints"])) {
		t.Fatal("the access rule changed without a ViewerIP")
	}
	if len(f.objs["Application"]) != 0 {
		t.Fatal("an Application was made")
	}
}

// The job on a marked store made before the admin view: every piece made
// or set, the password written, the key and every other object kept; a
// later start with the file in place writes nothing ("nothing to do").
// With the file in place but the listener gone (the test server's case),
// only the listener is made and the password stays.
func TestBootstrapJobPreAdminViewStore(t *testing.T) {
	s := &jobServer{f: newFake()}
	seedDefaults(s.f)
	j := newJob(t, s)
	j.Params = viewParams()
	j.ViewerFile = filepath.Join(t.TempDir(), "viewer-password")
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(j.keyFile())
	preAdminView(s.f)
	os.Remove(j.ViewerFile)
	before := snapshot(s.f)
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
	got := runJob()
	for _, line := range []string{
		"bootstrap: the store had no admin view listener: made it (that listener only)",
		"bootstrap: the management access rule differed from the base plan's",
		"bootstrap: the web admin's settings differed from the base plan's",
		"bootstrap: the store had no admin view account: made it (the viewer role and account only)",
		"its API key is in place",
	} {
		if !strings.Contains(got, line) {
			t.Fatalf("no %q in %q", line, got)
		}
	}
	if strings.Contains(got, "nothing to do") {
		t.Fatalf("logged %q", got)
	}
	if sets := sortedSets(s.f); sets != "x:Account/set create,x:Application/set update,x:Http/set update,x:NetworkListener/set create,x:Role/set create" {
		t.Fatalf("sets %s", sets)
	}
	checkAdminView(t, s.f, j.Params)
	checkViewer(t, s.f)
	if ch := changedOutside(s.f, before); len(ch) > 0 {
		t.Fatalf("other objects changed: %v", ch)
	}
	pw, _ := os.ReadFile(j.ViewerFile)
	if len(pw) < 40 || strings.Contains(got, string(pw)) {
		t.Fatalf("viewer password %d bytes, logged %v", len(pw), strings.Contains(got, string(pw)))
	}
	if k, _ := os.ReadFile(j.keyFile()); string(k) != string(key) {
		t.Fatal("the API key changed")
	}

	// The next start: nothing to do, nothing written.
	if got := runJob(); !strings.Contains(got, "its API key is in place; nothing to do") || len(setCalls(s.f)) > 0 {
		t.Fatalf("third run logged %q, sets %v", got, setCalls(s.f))
	}

	// The file in place, the listener gone: that listener only.
	for id, l := range s.f.objs["NetworkListener"] {
		if l["name"] == AdminViewListener {
			delete(s.f.objs["NetworkListener"], id)
		}
	}
	got = runJob()
	if !strings.Contains(got, "made it (that listener only)") || strings.Contains(got, "nothing to do") {
		t.Fatalf("listener-only run logged %q", got)
	}
	if sets := sortedSets(s.f); sets != "x:NetworkListener/set create" {
		t.Fatalf("listener-only run sets %s", sets)
	}
	if b, _ := os.ReadFile(j.ViewerFile); string(b) != string(pw) {
		t.Fatal("the viewer password changed with the file in place")
	}
}
