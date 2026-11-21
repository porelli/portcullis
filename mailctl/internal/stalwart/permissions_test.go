package stalwart

import (
	"sort"
	"strings"
	"testing"
)

// P52: MailPasswordPermissions is exactly authenticate, emailSend,
// emailReceive and every imap* permission of the schema snapshot.
func TestMailPasswordPermissionsExact(t *testing.T) {
	s := loadSnapshot(t)
	want := []string{"authenticate", "emailSend", "emailReceive"}
	for _, v := range s.Enums["Permission"] {
		if strings.HasPrefix(v.Name, "imap") {
			want = append(want, v.Name)
		}
	}
	got := append([]string(nil), MailPasswordPermissions...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("MailPasswordPermissions\n got %v\nwant %v", got, want)
	}
	if len(got) != 34 {
		t.Fatalf("%d permissions, want 34", len(got))
	}
}

// The role can't widen itself and never reads mail over other protocols.
func TestMailctlRoleHasNoSelfWidening(t *testing.T) {
	for _, p := range MailctlRolePermissions {
		for _, bad := range []string{"sysApiKey", "sysRole", "jmap", "dav", "sieve", "pop3", "sysNetworkListener", "sysAuthentication"} {
			if strings.HasPrefix(p, bad) {
				t.Errorf("role holds %s", p)
			}
		}
	}
	has := map[string]bool{}
	for _, p := range MailctlRolePermissions {
		has[p] = true
	}
	for _, p := range append(append([]string{"actionReloadLookupStores", "sysHttpLookupUpdate", "sysSpamDnsblServerUpdate", "sysSenderAuthUpdate", "impersonate", "sysAppPasswordCreate"}, MailPasswordPermissions...), ExportPermissions...) {
		if !has[p] {
			t.Errorf("role lacks %s", p)
		}
	}
}

// The built-in User role every account is created with holds the passkey
// set on Stalwart 1.1; Stalwart refuses to grant what the caller lacks, so
// mailctl's role must hold it (core CI: every account create was refused).
func TestMailctlRoleCanGrantUserRole(t *testing.T) {
	have := map[string]bool{}
	for _, p := range MailctlRolePermissions {
		have[p] = true
	}
	for _, p := range []string{"sysPasskeyGet", "sysPasskeyCreate", "sysPasskeyUpdate", "sysPasskeyDestroy", "sysPasskeyQuery"} {
		if !have[p] {
			t.Errorf("mailctl's role lacks %s (the User role it grants holds it)", p)
		}
	}
}

// The viewer role (contract §19.13) is exactly authenticate plus every
// sys<Object>Get / sys<Object>Query of the schema snapshot whose object
// isn't in ViewerDenied: no write, action, task, live, protocol or blob
// permission ever, and every allowed read present (a schema bump that adds
// an object fails here until it is judged).
func TestViewerRoleReadOnlyExact(t *testing.T) {
	s := loadSnapshot(t)
	denied := map[string]bool{}
	for _, o := range ViewerDenied {
		denied[o] = true
	}
	want := []string{"authenticate"}
	for _, v := range s.Enums["Permission"] {
		n := v.Name
		if !strings.HasPrefix(n, "sys") {
			continue
		}
		obj, ok := strings.CutSuffix(n, "Get")
		if !ok {
			obj, ok = strings.CutSuffix(n, "Query")
		}
		if ok && !denied[strings.TrimPrefix(obj, "sys")] {
			want = append(want, n)
		}
	}
	got := append([]string(nil), ViewerRolePermissions...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ViewerRolePermissions\n got %v\nwant %v", got, want)
	}
	for _, p := range got {
		if p == "authenticate" {
			continue
		}
		for _, bad := range []string{"Create", "Update", "Destroy"} {
			if strings.HasSuffix(p, bad) {
				t.Errorf("viewer holds the write %s", p)
			}
		}
		if !strings.HasPrefix(p, "sys") {
			t.Errorf("viewer holds the non-management %s", p)
		}
	}
	seen := map[string]bool{}
	for _, p := range ViewerRolePermissions {
		if seen[p] {
			t.Errorf("duplicate %s", p)
		}
		seen[p] = true
	}
}

// Messages and their envelopes stay out of the viewer's reach (security
// review): the queue and every received or sent report is denied in the
// role, and ViewerDeniedObject (the admin view proxy's second layer)
// refuses exactly the denied objects and their kin, never an allowed one.
func TestViewerNoMessagesOrEnvelopes(t *testing.T) {
	has := map[string]bool{}
	for _, p := range ViewerRolePermissions {
		has[p] = true
	}
	for _, o := range []string{"QueuedMessage", "ArfExternalReport", "DmarcExternalReport", "DmarcInternalReport", "TlsExternalReport", "TlsInternalReport",
		"SpamTrainingSample", "ArchivedItem", "MaskedEmail", "SieveUserScript", "ApiKey", "AppPassword", "AccountPassword", "Log", "Trace"} {
		for _, v := range []string{"Get", "Query"} {
			if has["sys"+o+v] {
				t.Errorf("viewer holds sys%s%s", o, v)
			}
		}
		for _, m := range []string{"x:" + o + "/get", "x:" + o + "/query", "x:" + o + "/changes"} {
			if !ViewerDeniedObject(m) {
				t.Errorf("proxy allows %s", m)
			}
		}
	}
	for _, p := range ViewerRolePermissions {
		obj, ok := strings.CutSuffix(strings.TrimPrefix(p, "sys"), "Get")
		if !ok {
			continue
		}
		if ViewerDeniedObject("x:" + obj + "/get") {
			t.Errorf("the proxy refuses x:%s/get, which the role allows", obj)
		}
	}
	for _, m := range []string{"x:QueuedMessageV2/get", "x:FooReport/get", "Email/get", "Mailbox/query", "x:SomeSecret/get", "x:queuedmessage/get"} {
		if !ViewerDeniedObject(m) {
			t.Errorf("proxy allows the new kin %s", m)
		}
	}
}
