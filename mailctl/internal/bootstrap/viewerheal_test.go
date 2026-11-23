package bootstrap

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// A store from before the admin view (contract §19.13): ResetViewer makes
// exactly what is missing — the viewer role from the base plan's
// definition, the viewer account on the parking domain with that role
// alone — corrects a drifted viewer role's permissions, and changes no
// other object. Without the parking domain it writes nothing.

// bootstrapped is a store after the base plan.
func bootstrapped(t *testing.T) *fakeStalwart {
	t.Helper()
	f := newFake()
	seedDefaults(f)
	run(t, f, params(), false)
	f.calls, f.writes = nil, nil
	return f
}

// viewerIDs is the viewer role's and the viewer account's ids ("" when
// missing).
func viewerIDs(f *fakeStalwart) (role, acct string) {
	for id, r := range f.objs["Role"] {
		if r["description"] == ViewerRole {
			role = id
		}
	}
	for id, a := range f.objs["Account"] {
		if a["name"] == ViewerAccount {
			acct = id
		}
	}
	return role, acct
}

// dropViewer removes the viewer role and/or account (a store made before
// the admin view existed).
func dropViewer(f *fakeStalwart, role, acct bool) {
	r, a := viewerIDs(f)
	if role {
		delete(f.objs["Role"], r)
	}
	if acct {
		delete(f.objs["Account"], a)
	}
}

func snapshot(f *fakeStalwart) map[string]any {
	return normalize(f.objs).(map[string]any)
}

// changedBesides lists the objects ("Obj/id") added, removed or changed
// between before and after, other than the viewer role and account.
func changedBesides(before, after map[string]any, role, acct string) []string {
	var out []string
	objs := map[string]bool{}
	for o := range before {
		objs[o] = true
	}
	for o := range after {
		objs[o] = true
	}
	for o := range objs {
		b, _ := before[o].(map[string]any)
		a, _ := after[o].(map[string]any)
		ids := map[string]bool{}
		for id := range b {
			ids[id] = true
		}
		for id := range a {
			ids[id] = true
		}
		for id := range ids {
			if (o == "Role" && id == role) || (o == "Account" && id == acct) {
				continue
			}
			if !reflect.DeepEqual(b[id], a[id]) {
				out = append(out, o+"/"+id)
			}
		}
	}
	sort.Strings(out)
	return out
}

func resetViewer(t *testing.T, f *fakeStalwart) ViewerReset {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	v, err := ResetViewer(context.Background(), stalwart.New(srv.URL, stalwart.Basic("r", "p")))
	if err != nil {
		t.Fatalf("ResetViewer: %v", err)
	}
	return v
}

// checkViewer: the viewer role holds exactly the plan's permissions and
// extends nothing; the account sits on the parking domain with that role
// alone and inherits nothing else.
func checkViewer(t *testing.T, f *fakeStalwart) {
	t.Helper()
	roleID, acctID := viewerIDs(f)
	if roleID == "" || acctID == "" {
		t.Fatalf("viewer role %q account %q", roleID, acctID)
	}
	r := f.objs["Role"][roleID]
	if !reflect.DeepEqual(r["enabledPermissions"], normalize(viewerRole()["enabledPermissions"])) {
		t.Fatalf("viewer role permissions %v", r["enabledPermissions"])
	}
	if ext, _ := r["roleIds"].(map[string]any); len(ext) > 0 {
		t.Fatalf("viewer role extends %v", ext)
	}
	var parking string
	for id, d := range f.objs["Domain"] {
		if d["name"] == ParkingDomain {
			parking = id
		}
	}
	a := f.objs["Account"][acctID]
	roles, _ := a["roles"].(map[string]any)
	ids, _ := roles["roleIds"].(map[string]any)
	perms, _ := a["permissions"].(map[string]any)
	if a["domainId"] != parking || roles["@type"] != "Custom" || len(ids) != 1 || ids[roleID] != true || perms["@type"] != "Inherit" {
		t.Fatalf("viewer account %v", a)
	}
}

func TestResetViewerMakesRoleAndAccount(t *testing.T) {
	f := bootstrapped(t)
	dropViewer(f, true, true)
	before := snapshot(f)
	v := resetViewer(t, f)
	if len(v.Password) < 40 || !v.MadeRole || !v.MadeAccount || v.FixedRole {
		t.Fatalf("ResetViewer: made role %v account %v fixed %v, %d-byte password", v.MadeRole, v.MadeAccount, v.FixedRole, len(v.Password))
	}
	if got := strings.Join(setCalls(f), ","); got != "x:Role/set create,x:Account/set create" {
		t.Fatalf("sets %s", got)
	}
	checkViewer(t, f)
	role, acct := viewerIDs(f)
	if ch := changedBesides(before, snapshot(f), role, acct); len(ch) > 0 {
		t.Fatalf("other objects changed: %v", ch)
	}
	// The role create is the plan's definition, nothing more.
	for _, w := range f.writes {
		if w.obj == "Role" && !reflect.DeepEqual(normalize(w.fields), normalize(viewerRole())) {
			t.Fatalf("role create %v", w.fields)
		}
	}
	// A second loss: a new password only.
	f.calls = nil
	v2 := resetViewer(t, f)
	if v2.MadeRole || v2.MadeAccount || v2.FixedRole || v2.Password == v.Password {
		t.Fatalf("second ResetViewer %+v", v2.MadeRole || v2.MadeAccount || v2.FixedRole)
	}
	if got := strings.Join(setCalls(f), ","); got != "x:Account/set update" {
		t.Fatalf("second run sets %s", got)
	}
}

func TestResetViewerMakesAccountOnly(t *testing.T) {
	f := bootstrapped(t)
	dropViewer(f, false, true)
	role, _ := viewerIDs(f)
	before := snapshot(f)
	v := resetViewer(t, f)
	if len(v.Password) < 40 || v.MadeRole || !v.MadeAccount || v.FixedRole {
		t.Fatalf("ResetViewer: made role %v account %v fixed %v", v.MadeRole, v.MadeAccount, v.FixedRole)
	}
	if got := strings.Join(setCalls(f), ","); got != "x:Account/set create" {
		t.Fatalf("sets %s", got)
	}
	checkViewer(t, f)
	if r, _ := viewerIDs(f); r != role {
		t.Fatalf("viewer role %s, was %s", r, role)
	}
	_, acct := viewerIDs(f)
	// The role is in the snapshot's comparison: untouched.
	if ch := changedBesides(before, snapshot(f), "", acct); len(ch) > 0 {
		t.Fatalf("other objects changed: %v", ch)
	}
}

// A viewer role whose permissions drifted (a write added, a read gone,
// another role extended): only that role's permissions are set back to
// the plan's; its description and every other role stay.
func TestResetViewerFixesDriftedRole(t *testing.T) {
	for _, acctMissing := range []bool{false, true} {
		t.Run(fmt.Sprintf("account missing %v", acctMissing), func(t *testing.T) {
			f := bootstrapped(t)
			dropViewer(f, false, acctMissing)
			role, _ := viewerIDs(f)
			var other string
			for id, r := range f.objs["Role"] {
				if r["description"] == MailctlRole {
					other = id
				}
			}
			perms := f.objs["Role"][role]["enabledPermissions"].(map[string]any)
			delete(perms, stalwart.ViewerRolePermissions[0])
			perms["sysAccountUpdate"] = true
			f.objs["Role"][role]["roleIds"] = map[string]any{other: true}
			before := snapshot(f)
			v := resetViewer(t, f)
			if len(v.Password) < 40 || v.MadeRole || v.MadeAccount != acctMissing || !v.FixedRole {
				t.Fatalf("ResetViewer: made role %v account %v fixed %v", v.MadeRole, v.MadeAccount, v.FixedRole)
			}
			want := "x:Role/set update,x:Account/set update"
			if acctMissing {
				want = "x:Role/set update,x:Account/set create"
			}
			if got := strings.Join(setCalls(f), ","); got != want {
				t.Fatalf("sets %s", got)
			}
			checkViewer(t, f)
			for _, w := range f.writes {
				if w.obj != "Role" {
					continue
				}
				keys := []string{}
				for k := range w.fields {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				if strings.Join(keys, ",") != "enabledPermissions,roleIds" {
					t.Fatalf("role patch %v", w.fields)
				}
			}
			if f.objs["Role"][role]["description"] != ViewerRole {
				t.Fatal("the viewer role's description changed")
			}
			_, acct := viewerIDs(f)
			if ch := changedBesides(before, snapshot(f), role, acct); len(ch) > 0 {
				t.Fatalf("other objects changed: %v", ch)
			}
		})
	}
}

// Without the parking domain the view stays unavailable: no domain, role
// or account is made, nothing is written.
func TestResetViewerWithoutParkingDomain(t *testing.T) {
	f := bootstrapped(t)
	dropViewer(f, true, true)
	for id, d := range f.objs["Domain"] {
		if d["name"] == ParkingDomain {
			delete(f.objs["Domain"], id)
		}
	}
	before := snapshot(f)
	v := resetViewer(t, f)
	if v != (ViewerReset{}) {
		t.Fatalf("ResetViewer %+v", v.MadeRole || v.MadeAccount || v.FixedRole || v.Password != "")
	}
	if sets := setCalls(f); len(sets) > 0 {
		t.Fatalf("wrote %v", sets)
	}
	if !reflect.DeepEqual(before, snapshot(f)) {
		t.Fatal("the store changed")
	}
}

// The job on a marked store from before the admin view, its viewer file
// missing or empty: the viewer role and account made, the password
// written 0640 and never logged, the key and every other object kept,
// and the CI's "API key is in place" line.
func TestBootstrapJobMakesMissingViewer(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty file %v", empty), func(t *testing.T) {
			s := &jobServer{f: newFake()}
			j := newJob(t, s)
			j.ViewerFile = filepath.Join(t.TempDir(), "viewer-password")
			if err := j.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			key, _ := os.ReadFile(j.keyFile())
			dropViewer(s.f, true, true)
			if empty {
				os.WriteFile(j.ViewerFile, nil, 0o640)
			} else {
				os.Remove(j.ViewerFile)
			}
			before := snapshot(s.f)
			s.f.calls = nil
			var logs []string
			j.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
			if err := j.Run(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := strings.Join(logs, "\n")
			if !strings.Contains(got, "bootstrap: the store had no admin view account: made it (the viewer role and account only)") ||
				!strings.Contains(got, "its API key is in place") || strings.Contains(got, "nothing to do") || strings.Contains(got, "stays unavailable") {
				t.Fatalf("logged %q", got)
			}
			if sets := strings.Join(setCalls(s.f), ","); sets != "x:Role/set create,x:Account/set create" {
				t.Fatalf("sets %s", sets)
			}
			checkViewer(t, s.f)
			role, acct := viewerIDs(s.f)
			if ch := changedBesides(before, snapshot(s.f), role, acct); len(ch) > 0 {
				t.Fatalf("other objects changed: %v", ch)
			}
			pw, _ := os.ReadFile(j.ViewerFile)
			fi, err := os.Stat(j.ViewerFile)
			if err != nil || fi.Mode().Perm() != 0o640 || len(pw) < 40 {
				t.Fatalf("viewer file %v %v %d bytes", err, fi, len(pw))
			}
			if strings.Contains(got, string(pw)) {
				t.Fatal("the viewer password was logged")
			}
			if k, _ := os.ReadFile(j.keyFile()); string(k) != string(key) {
				t.Fatal("the API key changed")
			}
			// The account's credential is the written password.
			creds, _ := s.f.objs["Account"][acct]["credentials"].(map[string]any)
			if !strings.Contains(fmt.Sprint(creds), string(pw)) {
				t.Fatal("the account doesn't hold the written password")
			}
		})
	}
}

// A marked store without the parking domain: today's behaviour (the view
// logged unavailable, nothing written; the key check then refuses the
// store, which has no mailctl account either).
func TestBootstrapJobViewerWithoutParkingDomain(t *testing.T) {
	s := &jobServer{f: newFake()}
	j := newJob(t, s)
	j.ViewerFile = filepath.Join(t.TempDir(), "viewer-password")
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	dropViewer(s.f, true, true)
	for id, d := range s.f.objs["Domain"] {
		if d["name"] == ParkingDomain {
			delete(s.f.objs["Domain"], id)
		}
	}
	os.Remove(j.ViewerFile)
	s.f.calls = nil
	var logs []string
	j.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	if err := j.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "no mailctl account") {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(logs, "\n"); !strings.Contains(got, "the read-only admin view stays unavailable") {
		t.Fatalf("logged %q", got)
	}
	if sets := setCalls(s.f); len(sets) > 0 {
		t.Fatalf("wrote %v", sets)
	}
	if _, err := os.Stat(j.ViewerFile); err == nil {
		t.Fatal("a viewer file was written")
	}
}
