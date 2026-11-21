package stalwart

import (
	"encoding/json"
	"os"
	"regexp"
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

// Messages, envelopes and secret-capable objects stay out of the viewer's
// reach (security review): denied in the role, and the admin view proxy's
// allowlist (ViewerMethodAllowed, derived from the role) refuses them.
func TestViewerNoMessagesOrEnvelopes(t *testing.T) {
	has := map[string]bool{}
	for _, p := range ViewerRolePermissions {
		has[p] = true
	}
	for _, o := range []string{"QueuedMessage", "ArfExternalReport", "DmarcExternalReport", "DmarcInternalReport", "TlsExternalReport", "TlsInternalReport",
		"SpamTrainingSample", "ArchivedItem", "MaskedEmail", "SieveUserScript", "ApiKey", "AppPassword", "AccountPassword", "Log", "Trace",
		"SpamDnsblServer", "SpamDnsblSettings", "DnsServer", "Directory", "WebHook", "HttpLookup", "AiModel", "Tracer", "Metrics", "Bootstrap", "OAuthGrant"} {
		for _, v := range []string{"Get", "Query"} {
			if has["sys"+o+v] {
				t.Errorf("viewer holds sys%s%s", o, v)
			}
		}
		for _, m := range []string{"x:" + o + "/get", "x:" + o + "/query", "x:" + o + "/changes", "X:" + o + "/get"} {
			if ViewerMethodAllowed(m) {
				t.Errorf("proxy allows %s", m)
			}
		}
	}
}

// The proxy's allowlist is exactly the role's reads as x:<Obj>/get and
// /query: every other method of the schema, every non-management method
// and every case variant is refused.
func TestViewerMethods(t *testing.T) {
	s := loadSnapshot(t)
	n := 0
	for _, p := range ViewerRolePermissions {
		obj, isGet := strings.CutSuffix(strings.TrimPrefix(p, "sys"), "Get")
		if !isGet {
			obj, _ = strings.CutSuffix(strings.TrimPrefix(p, "sys"), "Query")
		}
		if p == "authenticate" {
			continue
		}
		if _, ok := s.Schemas["x:"+obj]; !ok {
			t.Errorf("%s names no schema object x:%s", p, obj)
		}
		m := "x:" + obj + "/query"
		if isGet {
			m = "x:" + obj + "/get"
		}
		if !ViewerMethodAllowed(m) {
			t.Errorf("%s: %s refused", p, m)
		}
		n++
	}
	if len(viewerMethods) != n {
		t.Fatalf("%d methods for %d permissions", len(viewerMethods), n)
	}
	for _, m := range []string{"SearchSnippet/get", "Thread/get", "SieveScript/get", "Identity/get", "Principal/get", "Email/get", "Mailbox/query",
		"Core/echo", "X:Bootstrap/get", "X:OAuthGrant/get", "X:SieveUserScript/get", "x:SpamDnsblServer/get", "X:Account/get", "x:account/get",
		"x:Account/GET", "x:Account/changes", "x:Account/queryChanges", "x:Account/set", "x:Account/get ", " x:Account/get", "x:Account/get/get"} {
		if ViewerMethodAllowed(m) {
			t.Errorf("allowed %q", m)
		}
	}
	if !ViewerMethodAllowed("x:Account/get") || !ViewerMethodAllowed("x:Domain/query") {
		t.Fatal("the web admin's own reads refused")
	}
}

// viewerReviewedFields are the plain fields of objects the viewer reads
// whose names look secret-capable, each judged: not a secret, or masked
// by the server.
var viewerReviewedFields = map[string]string{
	"Account.credentials.otpUrl":             "masked by Stalwart (MASKED_PASSWORD) like the secret",
	"Account.credentials.publicKey":          "a passkey's public key",
	"AcmeProvider.accountUri":                "the ACME account's URL (not a credential; Portcullis has no ACME in Stalwart)",
	"Application.resourceUrl":                "file:// path of the pinned bundle",
	"Application.urlPrefix":                  "URL prefixes",
	"CalendarScheduling.httpRsvpUrl":         "the public RSVP URL",
	"DkimSignature.headers":                  "signed header names",
	"DkimSignature.publicKey":                "the DKIM public key (published in DNS)",
	"Domain.dnsZoneFile":                     "the domain's public zone text",
	"Domain.reportAddressUri":                "a report mailto: URI",
	"ExternalPublicKey.key":                  "a public key",
	"ExternalPublicKey.nextKey":              "a public key",
	"PublicKey.key":                          "a public key",
	"MemoryLookupKey.key":                    "a lookup entry (allow / block list domains)",
	"MemoryLookupKeyValue.key":               "a lookup entry",
	"MtaExtensions.dsn":                      "the DSN extension switch (an expression)",
	"MtaInboundThrottle.key":                 "rate-limit key names",
	"MtaOutboundThrottle.key":                "rate-limit key names",
	"MtaQueueQuota.key":                      "quota key names",
	"MtaRoute.authUsername":                  "the relay's username (its password is a masked secret)",
	"MtaStageData.addAuthResultsHeader":      "a header switch (an expression)",
	"MtaStageData.addDateHeader":             "a header switch",
	"MtaStageData.addMessageIdHeader":        "a header switch",
	"MtaStageData.addReceivedHeader":         "a header switch",
	"MtaStageData.addReceivedSpfHeader":      "a header switch",
	"MtaStageData.addReturnPathHeader":       "a header switch",
	"MtaStageData.maxReceivedHeaders":        "a header count",
	"OAuthClient.postLogoutRedirectUris":     "redirect URIs",
	"OAuthClient.redirectUris":               "redirect URIs",
	"SieveUserInterpreter.allowedNotifyUris": "notify URI schemes",
	"SieveUserInterpreter.protectedHeaders":  "header names",
	"SpamSettings.spamFilterRulesUrl":        "the adapter's internal rules URL",
	"Account.quotas":                         "quota sizes",
	"Tenant.quotas":                          "quota sizes",
	"Email.defaultFolders":                   "default folder names",
	"SystemSettings.services":                "advertised service hostnames",
	"SystemSettings.providerInfo":            "autoconfig provider display info",
}

// TestViewerSecretFreeFields (security review I1) walks every object the
// viewer reads, embedded objects included (references are other objects,
// judged on their own): a plain field (not Stalwart's secret types) that
// could hold a secret — a string map (headers), or a URL, username, key,
// token, zone, header or endpoint field — must be judged in
// viewerReviewedFields, else its object belongs in ViewerDenied.
func TestViewerSecretFreeFields(t *testing.T) {
	raw := loadSnapshotRaw(t)
	var sc struct {
		Schemas map[string]struct {
			Type       string `json:"type"`
			SchemaName string `json:"schemaName"`
			Variants   []struct {
				SchemaName string `json:"schemaName"`
			} `json:"variants"`
		} `json:"schemas"`
		Fields map[string]struct {
			Properties map[string]struct {
				Type struct {
					Type       string `json:"type"`
					Format     string `json:"format"`
					ObjectName string `json:"objectName"`
					Class      *struct {
						Type       string `json:"type"`
						Format     string `json:"format"`
						ObjectName string `json:"objectName"`
					} `json:"class"`
				} `json:"type"`
			} `json:"properties"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatal(err)
	}
	schemasOf := func(name string) []string {
		d, ok := sc.Schemas[name]
		if !ok {
			if _, f := sc.Fields[name]; f {
				return []string{name}
			}
			return nil
		}
		if d.Type == "single" {
			return []string{d.SchemaName}
		}
		var out []string
		for _, v := range d.Variants {
			if v.SchemaName != "" {
				out = append(out, v.SchemaName)
			}
		}
		return out
	}
	secretTypes := map[string]bool{"x:SecretKey": true, "x:SecretText": true, "x:SecretKeyOptional": true, "x:SecretTextOptional": true}
	words := regexp.MustCompile(`(?i)header|url|uri|zone|token|apikey|applicationkey|key$|username|dsn|endpoint|secret|password`)
	seen := map[string]bool{}
	var walk func(schema, path string, visiting map[string]bool)
	walk = func(schema, path string, visiting map[string]bool) {
		if visiting[schema] {
			return
		}
		visiting[schema] = true
		defer delete(visiting, schema)
		for f, d := range sc.Fields[schema].Properties {
			ty := d.Type
			p := path + "." + f
			if ty.Format == "secret" || ty.Format == "secretText" || secretTypes[ty.ObjectName] || ty.Type == "objectId" {
				continue
			}
			flag := false
			if ty.Type == "map" && (ty.Class == nil || ty.Class.Type == "string" || strings.Contains(strings.ToLower(f), "header")) {
				flag = true
			} else if (ty.Type == "string" || ty.Type == "set" || ty.Type == "object") && words.MatchString(f) && ty.ObjectName != "x:Rate" {
				flag = true
			}
			if flag && !seen[p] {
				seen[p] = true
				if viewerReviewedFields[p] == "" {
					t.Errorf("the viewer reads %s, which could hold a secret: judge it in viewerReviewedFields or deny its object", p)
				}
			}
			on := ""
			if ty.Type == "object" || ty.Type == "objectList" {
				on = ty.ObjectName
			} else if ty.Class != nil && ty.Class.Type == "object" {
				on = ty.Class.ObjectName
			}
			if on != "" {
				for _, sub := range schemasOf(on) {
					walk(sub, p, visiting)
				}
			}
		}
	}
	for _, p := range ViewerRolePermissions {
		obj, ok := strings.CutSuffix(strings.TrimPrefix(p, "sys"), "Get")
		if !ok {
			continue
		}
		for _, sn := range schemasOf("x:" + obj) {
			walk(sn, obj, map[string]bool{})
		}
	}
	for p := range viewerReviewedFields {
		if !seen[p] {
			t.Errorf("viewerReviewedFields judges %s, which the viewer doesn't read (stale)", p)
		}
	}
}

func loadSnapshotRaw(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
