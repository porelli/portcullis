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
