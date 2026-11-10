package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func vector(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// G47 / contract §15.4: the shared vector decodes strictly and re-encodes
// byte for byte (the Hub commits the same bytes and runs the same test).
func TestVectorRoundTrip(t *testing.T) {
	gate := vector(t, "mcp-gate.json")
	f, err := DecodeFile(gate)
	if err != nil {
		t.Fatalf("mcp-gate.json: %v", err)
	}
	out, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, gate) {
		t.Errorf("mcp-gate.json re-encoded differs:\n%s", out)
	}
	creds := vector(t, "mcp-credentials.json")
	cf, err := DecodeCredFile(creds)
	if err != nil {
		t.Fatalf("mcp-credentials.json: %v", err)
	}
	out, err = cf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, creds) {
		t.Errorf("mcp-credentials.json re-encoded differs:\n%s", out)
	}
}

// Every way a file can be outside its rule refuses the whole file (§4.2).
func TestStrictDecodeRefuses(t *testing.T) {
	gate := string(vector(t, "mcp-gate.json"))
	for name, mut := range map[string][2]string{
		"unknown field":            {`"version": 2,`, `"version": 2, "extra": true,`},
		"case-variant key":         {`"version": 2,`, `"Version": 2,`},
		"duplicate key":            {`"version": 2,`, `"version": 2, "version": 2,`},
		"missing field":            {`"main_domain": "example.com",`, ``},
		"missing resource field":   {`"label": "Gitea",`, ``},
		"null list":                {`"allowed_origins": [],`, `"allowed_origins": null,`},
		"other version":            {`"version": 2,`, `"version": 3,`},
		"issuer not auth.<d>":      {`"issuer": "https://auth.example.com/realms/portcullis"`, `"issuer": "https://evil.example/realms/portcullis"`},
		"forward-auth client":      {"\"portcullis-ai-generic\"\n  ],", "\"portcullis-ai-generic\", \"portcullis-forward-auth\"\n  ],"},
		"client not top-level":     {`"clients": [` + "\n        \"portcullis-ai-claude\",", `"clients": [` + "\n        \"gitea\", \"portcullis-ai-claude\","},
		"companion on a core host": {"    \"example.com\",\n", "    \"example.com\",\n    \"gitea.example.com\",\n"},
		"core_hosts without hub":   {"    \"hub.example.com\",\n    \"mcp.example.com\",\n", "    \"mcp.example.com\",\n"},
		"core_hosts without apex":  {"    \"example.com\",\n    \"hub.example.com\",\n", "    \"hub.example.com\",\n"},
		"companion hosts core":     {"\"hosts\": [\n        \"gitea.example.com\"\n      ]", "\"hosts\": [\n        \"gitea.example.com\", \"hub.example.com\"\n      ]"},
		"bad upstream":             {`"upstream": "http://portcullis-mcp-gitea--gitea:8080/mcp"`, `"upstream": "http://169.254.169.254/latest"`},
		"fanout 5":                 {`"fanout": 4,`, `"fanout": 5,`},
		"bad scope":                {`"scope": "mcp:gitea.gitea",`, `"scope": "mcp:all",`},
		"unsupported protocol":     {"\"2026-07-28\",\n        \"2025-11-25\"", "\"2026-07-28\",\n        \"2025-03-26\""},
		"unsorted population":      {"\"population\": [\n        \"alice\",\n        \"bob\"\n      ],", "\"population\": [\n        \"bob\",\n        \"alice\"\n      ],"},
		"uppercase user":           {"\"population\": [\n        \"alice\",\n        \"bob\"\n      ],", "\"population\": [\n        \"Alice\",\n        \"bob\"\n      ],"},
		"Kelvin sign user":         {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"\u212aim\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"non-ASCII user":           {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"b\u00f6b\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user with @":              {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"b@b\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user with +":              {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"b+b\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user leading .":           {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \".bob\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user leading -":           {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"-bob\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"user 65 chars":            {"\"population\": [\n        \"alice\"\n      ],\n      \"expiring\": {},\n      \"people\"", "\"population\": [\n        \"alice\",\n        \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n      ],\n      \"expiring\": {},\n      \"people\""},
		"expiring not UTC":         {`"bob": "2027-03-31T23:59:59Z"`, `"bob": "2027-03-31T23:59:59+02:00"`},
		"expiring outside pop":     {`"bob": "2027-03-31T23:59:59Z"`, `"zed": "2027-03-31T23:59:59Z"`},
		"people on app_token":      {`"expiring": {` + "\n        \"bob\"", `"people": {}, "expiring": {` + "\n        \"bob\""},
		"identity header cookie":   {`"header": "Authorization",` + "\n        \"format\": \"token {credential}\"", `"header": "Cookie",` + "\n        \"format\": \"token {credential}\""},
		"secret_ref other":         {`"secret_ref": "grafana/grafana"`, `"secret_ref": "gitea/gitea"`},
		"fixed limit changed":      {`"upstream_timeout_s": 120`, `"upstream_timeout_s": 600`},
		"zero limit":               {`"resource_rpm": 120,`, `"resource_rpm": 0,`},
		"origin not https":         {`"allowed_origins": [],`, `"allowed_origins": ["http://claude.ai"],`},
		"trailing data":            {"\n}\n", "\n}\n{}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(gate, mut[0]) {
				t.Fatalf("mutation anchor %q not in the vector", mut[0])
			}
			b := strings.Replace(gate, mut[0], mut[1], 1)
			_, err := DecodeFile([]byte(b))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
	creds := string(vector(t, "mcp-credentials.json"))
	for name, mut := range map[string][2]string{
		"unknown field":      {`"state": "active",`, `"state": "active", "secret": "x",`},
		"revoking with age":  {`"state": "revoking",` + "\n      \"age\": \"\"", `"state": "revoking",` + "\n      \"age\": \"x\""},
		"active without age": {`"state": "active",` + "\n      \"age\": \"-----BEGIN AGE ENCRYPTED FILE-----\\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSBleGFtcGxl\\n-----END AGE ENCRYPTED FILE-----\\n\"", `"state": "active",` + "\n      \"age\": \"\""},
		"bad state":          {`"state": "active",`, `"state": "paused",`},
		"bad id":             {`"id": "7",`, `"id": "7 8",`},
		"unsorted":           {`"user": "carol",`, `"user": "aaron",`},
		"missing field":      {`"minted_at": "2026-11-05T09:30:00Z",`, ``},
	} {
		t.Run("creds/"+name, func(t *testing.T) {
			if !strings.Contains(creds, mut[0]) {
				t.Fatalf("mutation anchor %q not in the vector", mut[0])
			}
			b := strings.Replace(creds, mut[0], mut[1], 1)
			_, err := DecodeCredFile([]byte(b))
			if err == nil {
				t.Fatal("accepted")
			}
			t.Log(err)
		})
	}
}

// Final review M5: a companion never sits on a core host, even one the
// Hub left out of core_hosts.
func TestCompanionNeverOnFixedCoreHost(t *testing.T) {
	gate := string(vector(t, "mcp-gate.json"))
	for _, m := range [][2]string{
		{"    \"metrics.example.com\",\n", ""},
		{"\"hosts\": [\n        \"gitea.example.com\"\n      ]", "\"hosts\": [\n        \"gitea.example.com\", \"metrics.example.com\"\n      ]"},
	} {
		if !strings.Contains(gate, m[0]) {
			t.Fatalf("anchor %q not in the vector", m[0])
		}
		gate = strings.Replace(gate, m[0], m[1], 1)
	}
	if _, err := DecodeFile([]byte(gate)); err == nil || !strings.Contains(err.Error(), "core host") {
		t.Fatalf("companion on metrics.<d> (not in core_hosts): %v", err)
	}
}

func writeFile(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func openStore(t *testing.T, dir string, id age.Identity) *Store {
	t.Helper()
	s, err := Open(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Review Focus 5 / §4.2: missing = off; corrupt after good = every request
// refused, the last good configuration dropped; good again = served.
func TestConfigMissingVsCorrupt(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir, nil)
	sn := s.Snapshot()
	if !sn.Off || sn.Err != nil || sn.File != nil {
		t.Fatalf("missing file: Off=%v Err=%v File=%v", sn.Off, sn.Err, sn.File != nil)
	}
	good := vector(t, "mcp-gate.json")
	writeFile(t, dir, GateFile, good)
	s.poll()
	sn = s.Snapshot()
	if sn.Off || sn.Err != nil || sn.File == nil {
		t.Fatalf("good file: Off=%v Err=%v", sn.Off, sn.Err)
	}
	if _, ok := sn.Resource("gitea.example.com", "/mcp"); !ok {
		t.Fatal("gitea resource missing")
	}
	writeFile(t, dir, GateFile, good[:len(good)/2])
	s.poll()
	sn = s.Snapshot()
	if sn.Err == nil || sn.File != nil {
		t.Fatalf("truncated file: Err=%v File=%v", sn.Err, sn.File != nil)
	}
	if _, ok := sn.Resource("gitea.example.com", "/mcp"); ok {
		t.Fatal("a resource served from a corrupt file")
	}
	writeFile(t, dir, GateFile, good)
	s.poll()
	if sn = s.Snapshot(); sn.Err != nil || sn.File == nil {
		t.Fatalf("good again: Err=%v", sn.Err)
	}
	// enabled: false is off, like a missing file.
	writeFile(t, dir, GateFile, bytes.Replace(good, []byte(`"enabled": true`), []byte(`"enabled": false`), 1))
	s.poll()
	if sn = s.Snapshot(); !sn.Off || sn.Err != nil {
		t.Fatalf("enabled false: Off=%v Err=%v", sn.Off, sn.Err)
	}
	// An unreadable file is an error, not "off".
	if err := os.Remove(filepath.Join(dir, GateFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, GateFile), 0o750); err != nil {
		t.Fatal(err)
	}
	s.poll()
	if sn = s.Snapshot(); sn.Err == nil {
		t.Fatal("unreadable file: no error")
	}
}

// G21: a rename to a file of the same size and the same mtime is seen
// (the inode changed).
func TestReloadSameSizeSameSecond(t *testing.T) {
	dir := t.TempDir()
	good := vector(t, "mcp-gate.json")
	writeFile(t, dir, GateFile, good)
	s := openStore(t, dir, nil)
	r, _ := s.Snapshot().Resource("gitea.example.com", "/mcp")
	if r == nil || r.Label != "Gitea" {
		t.Fatalf("first load: %v", r)
	}
	st, err := os.Stat(filepath.Join(dir, GateFile))
	if err != nil {
		t.Fatal(err)
	}
	other := bytes.Replace(good, []byte(`"label": "Gitea"`), []byte(`"label": "Gitex"`), 1)
	if len(other) != len(good) {
		t.Fatal("not the same size")
	}
	tmp := filepath.Join(dir, ".next")
	if err := os.WriteFile(tmp, other, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, GateFile)); err != nil {
		t.Fatal(err)
	}
	s.poll()
	r, _ = s.Snapshot().Resource("gitea.example.com", "/mcp")
	if r == nil || r.Label != "Gitex" {
		t.Fatalf("same-size same-mtime rename missed: %v", r)
	}
}

// The background poll picks up a change by itself (every second).
func TestPollRuns(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir, nil)
	writeFile(t, dir, GateFile, vector(t, "mcp-gate.json"))
	deadline := time.Now().Add(5 * time.Second)
	for s.Snapshot().File == nil {
		if time.Now().After(deadline) {
			t.Fatal("not reloaded within 5 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func encrypt(t *testing.T, r age.Recipient, s string) string {
	t.Helper()
	var buf bytes.Buffer
	a := armor.NewWriter(&buf)
	w, err := age.Encrypt(a, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func credsFile(t *testing.T, creds []CredEntry, secrets []SecretEntry) []byte {
	t.Helper()
	if creds == nil {
		creds = []CredEntry{}
	}
	if secrets == nil {
		secrets = []SecretEntry{}
	}
	b, err := (&CredFile{Version: 1, Credentials: creds, CallerSecrets: secrets}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func minted(t *testing.T) Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, "2026-11-05T09:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return Time{tm}
}

func TestCredentialsDecrypted(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	writeFile(t, dir, GateFile, vector(t, "mcp-gate.json"))
	aliceCT := encrypt(t, id.Recipient(), "s3cr3t-alice")
	writeFile(t, dir, CredsFile, credsFile(t, []CredEntry{
		{Instance: "gitea", Companion: "gitea", User: "alice", ID: "7", MintedAt: minted(t), State: "active", Age: aliceCT},
		{Instance: "gitea", Companion: "gitea", User: "carol", ID: "4", MintedAt: minted(t), State: "revoking", Age: ""},
	}, []SecretEntry{{Ref: "grafana/grafana", Age: encrypt(t, id.Recipient(), "caller-secret")}}))
	s := openStore(t, dir, id)
	sn := s.Snapshot()
	if sn.Err != nil {
		t.Fatal(sn.Err)
	}
	c, ok := sn.Creds[CredKey{"gitea", "gitea", "alice"}]
	if !ok || c.Secret != "s3cr3t-alice" || c.ID != "7" {
		t.Fatalf("alice: %v %v", ok, c.ID)
	}
	if _, ok := sn.Creds[CredKey{"gitea", "gitea", "carol"}]; ok {
		t.Error("a revoking entry is usable")
	}
	if sn.Secrets["grafana/grafana"] != "caller-secret" {
		t.Error("caller secret not decrypted")
	}
	// Never printed: %v and %#v of a credential don't show the secret.
	if out := fmt.Sprintf("%v %+v %#v %s", c, c, c, c); strings.Contains(out, "s3cr3t") {
		t.Errorf("credential formatted with its secret: %s", out)
	}

	// An entry encrypted to another recipient refuses the file, the error
	// names the index, never the ciphertext.
	bobCT := encrypt(t, other.Recipient(), "s3cr3t-bob")
	writeFile(t, dir, CredsFile, credsFile(t, []CredEntry{
		{Instance: "gitea", Companion: "gitea", User: "alice", ID: "7", MintedAt: minted(t), State: "active", Age: aliceCT},
		{Instance: "gitea", Companion: "gitea", User: "bob", ID: "8", MintedAt: minted(t), State: "active", Age: bobCT},
	}, nil))
	s.poll()
	sn = s.Snapshot()
	if sn.Err == nil {
		t.Fatal("undecryptable entry accepted")
	}
	msg := sn.Err.Error()
	if !strings.Contains(msg, "credentials[1]") {
		t.Errorf("error doesn't name the entry: %s", msg)
	}
	for _, leak := range []string{"AGE ENCRYPTED", bobCT[40:60], "s3cr3t"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error leaks %q: %s", leak, msg)
		}
	}
	if sn.File != nil || len(sn.Creds) != 0 {
		t.Error("a refused credentials file still serves")
	}

	// A corrupt credentials file refuses everything too; a missing one is empty.
	writeFile(t, dir, CredsFile, []byte("{"))
	s.poll()
	if s.Snapshot().Err == nil {
		t.Error("corrupt credentials file accepted")
	}
	if err := os.Remove(filepath.Join(dir, CredsFile)); err != nil {
		t.Fatal(err)
	}
	s.poll()
	if sn = s.Snapshot(); sn.Err != nil || sn.File == nil || len(sn.Creds) != 0 {
		t.Errorf("missing credentials file: Err=%v", sn.Err)
	}
}

func TestCredentialForUnknownResourceIgnored(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	dir := t.TempDir()
	writeFile(t, dir, GateFile, vector(t, "mcp-gate.json"))
	writeFile(t, dir, CredsFile, credsFile(t, []CredEntry{
		{Instance: "gitea", Companion: "gitea", User: "alice", ID: "7", MintedAt: minted(t), State: "active", Age: encrypt(t, id.Recipient(), "a")},
		// No such resource: ignored, even though it can't be decrypted.
		{Instance: "nextcloud", Companion: "nextcloud", User: "alice", ID: "9", MintedAt: minted(t), State: "active", Age: encrypt(t, other.Recipient(), "b")},
	}, []SecretEntry{{Ref: "wiki/wiki", Age: encrypt(t, other.Recipient(), "c")}}))
	s := openStore(t, dir, id)
	sn := s.Snapshot()
	if sn.Err != nil {
		t.Fatal(sn.Err)
	}
	if _, ok := sn.Creds[CredKey{"nextcloud", "nextcloud", "alice"}]; ok {
		t.Error("entry for an unknown resource kept")
	}
	if len(sn.Creds) != 1 || len(sn.Secrets) != 0 {
		t.Errorf("creds %d secrets %d", len(sn.Creds), len(sn.Secrets))
	}
}

func TestResourceLookupNormalised(t *testing.T) {
	f, err := DecodeFile(vector(t, "mcp-gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	sn := &Snapshot{File: f}
	for _, c := range []struct {
		host, path, want string
	}{
		{"Gitea.Example.COM.:443", "/mcp", "https://gitea.example.com/mcp"},
		{"gitea.example.com", "/mcp", "https://gitea.example.com/mcp"},
		{"gitea.example.com:8443", "/mcp", "https://gitea.example.com/mcp"},
		{"mcp.example.com", "/mcp", "https://mcp.example.com/mcp"},
		{"gitea.example.com", "/mcp/", ""},
		{"gitea.example.com", "/MCP", ""},
		{"gitea.example.com", "/mcp/x", ""},
		{"gitea.example.com:x", "/mcp", ""},
		{"gitea.example.com:", "/mcp", ""},
		{"evil.example", "/mcp", ""},
		{"", "/mcp", ""},
	} {
		r, ok := sn.Resource(c.host, c.path)
		got := ""
		if ok {
			got = r.URL
		}
		if got != c.want {
			t.Errorf("%q %q → %q, want %q", c.host, c.path, got, c.want)
		}
	}
	if _, ok := (&Snapshot{}).Resource("gitea.example.com", "/mcp"); ok {
		t.Error("a snapshot without a file serves a resource")
	}
}

func TestResourceMembership(t *testing.T) {
	f, err := DecodeFile(vector(t, "mcp-gate.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, _ := (&Snapshot{File: f}).Resource("gitea.example.com", "/mcp")
	before := time.Date(2027, 3, 31, 23, 59, 58, 0, time.UTC)
	at := time.Date(2027, 3, 31, 23, 59, 59, 0, time.UTC)
	if !r.Member("alice", at) || !r.Member("bob", before) {
		t.Error("member refused")
	}
	if r.Member("bob", at) || r.Member("carol", before) || r.Member("Alice", before) {
		t.Error("non-member allowed")
	}
	if !r.AllowsClient("portcullis-ai-claude") || !r.AllowsClient("ai-chat-mcp") || r.AllowsClient("portcullis-forward-auth") || r.AllowsClient("gitea") || r.AllowsClient("AI-CHAT-MCP") {
		t.Error("clients")
	}
	// §15.4: the ai_client is on every resource but the admin one.
	for _, host := range []string{"grafana.example.com", "mcp.example.com", "people.example.com"} {
		if r, ok := (&Snapshot{File: f}).Resource(host, "/mcp"); !ok || !r.AllowsClient("ai-chat-mcp") {
			t.Errorf("%s: ai-chat-mcp refused", host)
		}
	}
	if a, ok := (&Snapshot{File: f}).Resource("hub.example.com", "/mcp"); !ok || a.AllowsClient("ai-chat-mcp") || !a.AllowsClient("portcullis-ai-claude") {
		t.Error("admin resource clients")
	}
}

func TestAttributes(t *testing.T) {
	doc := map[string]any{
		"version": 2,
		"fields":  map[string]string{"team": "Team", "cost_center": "Cost-Center", "Bad": "Bad"},
		"users": map[string]any{
			"alice": map[string][]string{"team": {"A, B", "100%"}, "cost_center": {"CC-1"}, "Bad": {"x"}},
		},
		"hosts": map[string]any{
			"grafana.example.com": map[string]any{
				"Grafana-Role": map[string]string{"Alice": "Admin"},
				"Team":         map[string]string{},
			},
		},
	}
	b, _ := json.Marshal(doc)
	a, err := ParseAttributes(b)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(a.Headers("grafana.example.com", "alice"))
	want := "[{X-Forwarded-Attr-Cost-Center CC-1} {X-Forwarded-Attr-Grafana-Role Admin}]"
	if got != want {
		t.Errorf("grafana: %s, want %s", got, want)
	}
	got = fmt.Sprint(a.Headers("gitea.example.com", "alice"))
	want = "[{X-Forwarded-Attr-Cost-Center CC-1} {X-Forwarded-Attr-Team A%2C B, 100%25}]"
	if got != want {
		t.Errorf("gitea: %s, want %s", got, want)
	}
	if h := a.Headers("gitea.example.com", "bob"); len(h) != 0 {
		t.Errorf("bob: %v", h)
	}
	if _, err := ParseAttributes([]byte(`{"version": 1}`)); err == nil {
		t.Error("version 1 accepted")
	}
	var none *Attributes
	if h := none.Headers("x", "alice"); len(h) != 0 {
		t.Error("nil attributes give headers")
	}

	// In the store: missing or corrupt means no headers, never an error.
	dir := t.TempDir()
	writeFile(t, dir, GateFile, vector(t, "mcp-gate.json"))
	writeFile(t, dir, AttrsFile, []byte("{"))
	s := openStore(t, dir, nil)
	if sn := s.Snapshot(); sn.Err != nil || sn.Attrs != nil {
		t.Errorf("corrupt attributes: Err=%v Attrs=%v", sn.Err, sn.Attrs)
	}
	writeFile(t, dir, AttrsFile, b)
	s.poll()
	if sn := s.Snapshot(); sn.Attrs == nil || len(sn.Attrs.Headers("gitea.example.com", "alice")) != 2 {
		t.Error("attributes not loaded")
	}
}

func TestValidUsernameMatchesHub(t *testing.T) {
	for u, want := range map[string]bool{
		"alice": true, "a.b-c_d": true, "0x": true, strings.Repeat("a", 64): true,
		strings.Repeat("a", 65): false, "a@b": false, "a+b": false, ".a": false, "-a": false, "_a": false, "Alice": false, "": false,
	} {
		if got := ValidUsername(u); got != want {
			t.Errorf("%q: %v, want %v", u, got, want)
		}
	}
}

// Gate file v2 (sign-in methods, contract §15.4): version 1, the v1 LoA
// keys and every rule outside the readers' limits refuse the whole file,
// exactly as the Hub's aigate validator does.
func TestConfigV2Strict(t *testing.T) {
	gate := string(vector(t, "mcp-gate.json"))
	// The first resource (gitea, a companion) is on Standard; the first
	// "op": "any" with security_key / yubikey_cert is the admin resource.
	std := "\"rule\": {\n        \"op\": \"any\",\n        \"items\": [\n          {\n            \"op\": \"any\",\n            \"items\": [\n              \"passkey_synced\",\n              \"passkey_device\",\n              \"security_key\"\n            ]\n          },\n          {\n            \"op\": \"any\",\n            \"items\": [\n              \"yubikey_cert\"\n            ]\n          }\n        ]\n      },"
	strong := "\"rule\": {\n        \"op\": \"any\",\n        \"items\": [\n          \"security_key\",\n          \"yubikey_cert\"\n        ]\n      },"
	rule := func(js string) [2]string { return [2]string{std, `"rule": ` + js + `,`} }
	nine := `{"op":"any","items":["passkey_synced","passkey_device","security_key","yubikey_cert","passkey_synced","passkey_device","security_key","yubikey_cert","security_key"]}`
	g7 := `{"op":"any","items":["security_key","security_key","security_key","security_key","security_key","security_key","security_key"]}`
	many := `{"op":"any","items":[` + strings.Repeat(g7+",", 7) + `{"op":"all","items":["security_key"]}]}`
	for name, mut := range map[string][2]string{
		"version 1":                     {`"version": 2,`, `"version": 1,`},
		"acr_loa key":                   {`"methods": [`, `"acr_loa": {"hwk": 2}, "methods": [`},
		"min_loa key":                   {std, std + ` "min_loa": 2,`},
		"min_loa instead of rule":       {std, `"min_loa": 2,`},
		"missing methods":               {"\"methods\": [\n    \"passkey_device\",\n    \"passkey_synced\",\n    \"security_key\",\n    \"yubikey_cert\"\n  ],", ``},
		"methods unsorted":              {"\"passkey_device\",\n    \"passkey_synced\",", "\"passkey_synced\",\n    \"passkey_device\","},
		"methods unknown":               {"\"methods\": [\n", "\"methods\": [\n    \"otp\",\n"},
		"methods amr value":             {"\"methods\": [\n", "\"methods\": [\n    \"hwk\",\n"},
		"methods family":                {"\"methods\": [\n", "\"methods\": [\n    \"family:passkey\",\n"},
		"leaf not in methods":           rule(`{"op":"any","items":["password","security_key"]}`),
		"browser_cert not in methods":   rule(`{"op":"any","items":["browser_cert","security_key"]}`),
		"family leaf":                   rule(`{"op":"any","items":["family:passkey"]}`),
		"amr leaf":                      rule(`{"op":"any","items":["hwk"]}`),
		"inv leaf":                      rule(`{"op":"any","items":["inv"]}`),
		"leaf at the top":               rule(`"security_key"`),
		"empty group":                   rule(`{"op":"any","items":["security_key",{"op":"all","items":[]}]}`),
		"group of 9":                    rule(nine),
		"depth 5":                       rule(`{"op":"any","items":[{"op":"all","items":[{"op":"any","items":[{"op":"all","items":[{"op":"any","items":["security_key"]}]}]}]}]}`),
		"more than 48 leaves":           rule(many),
		"unknown op":                    rule(`{"op":"none","items":["security_key"]}`),
		"unknown rule key":              rule(`{"op":"any","items":["security_key"],"min_loa":2}`),
		"duplicate op":                  rule(`{"op":"any","op":"all","items":["security_key"]}`),
		"missing items":                 rule(`{"op":"any"}`),
		"null rule":                     rule(`null`),
		"empty leaf":                    rule(`{"op":"any","items":[""]}`),
		"number leaf":                   rule(`{"op":"any","items":[2]}`),
		"companion needs a certificate": rule(`{"op":"all","items":["security_key","yubikey_cert"]}`),
		"companion certificate only":    rule(`{"op":"any","items":["yubikey_cert"]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(gate, mut[0]) {
				t.Fatalf("mutation anchor %q not in the vector", mut[0])
			}
			if _, err := DecodeFile([]byte(strings.Replace(gate, mut[0], mut[1], 1))); err == nil {
				t.Fatal("accepted")
			} else {
				t.Log(err)
			}
		})
	}
	// Accepted: nested rules within the limits, a group of exactly 8, and
	// a Portcullis resource whose rule needs a certificate (the residual
	// of §15.2: no token meets it, every request is refused).
	for name, mut := range map[string][2]string{
		"group of 8":            rule(`{"op":"any","items":["passkey_synced","passkey_device","security_key","yubikey_cert","passkey_synced","passkey_device","security_key","yubikey_cert"]}`),
		"depth 4":               rule(`{"op":"any","items":[{"op":"all","items":[{"op":"any","items":[{"op":"all","items":["security_key"]}]}]}]}`),
		"certificate or touch":  rule(`{"op":"any","items":["yubikey_cert","security_key"]}`),
		"admin needs a cert":    {strong, `"rule": {"op":"all","items":["security_key","yubikey_cert"]},`},
		"passkey and touch all": rule(`{"op":"all","items":["passkey_device","security_key"]}`),
	} {
		t.Run("ok/"+name, func(t *testing.T) {
			if !strings.Contains(gate, mut[0]) {
				t.Fatalf("mutation anchor %q not in the vector", mut[0])
			}
			if _, err := DecodeFile([]byte(strings.Replace(gate, mut[0], mut[1], 1))); err != nil {
				t.Fatal(err)
			}
		})
	}
}
