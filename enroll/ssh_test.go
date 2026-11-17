package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ── shared vectors (the Hub's internal/cliapi/testdata/vectors.json) ──

type sshVectors struct {
	Principals []struct {
		In string `json:"in"`
		OK bool   `json:"ok"`
	} `json:"principals"`
	HostGroupIDs []struct {
		In       string `json:"in"`
		OK       bool   `json:"ok"`
		Reserved bool   `json:"reserved"`
	} `json:"host_group_ids"`
	Usernames []struct {
		In string `json:"in"`
		OK bool   `json:"ok"`
	} `json:"usernames"`
	KeyIDs []struct {
		In        string `json:"in"`
		OK        bool   `json:"ok"`
		User      string `json:"user"`
		HostGroup string `json:"host_group"`
	} `json:"key_ids"`
	Extensions []struct {
		Value string `json:"value"`
	} `json:"extensions"`
	RoleTTLs []struct {
		In  int  `json:"in"`
		Out int  `json:"out"`
		OK  bool `json:"ok"`
	} `json:"role_ttls"`
	Roles []struct {
		Name      string          `json:"name"`
		HostGroup string          `json:"host_group"`
		Spec      sshRoleSpec     `json:"spec"`
		Body      string          `json:"body"`
		Vault     json.RawMessage `json:"vault"`
	} `json:"roles"`
	HostPatterns []struct {
		In   string `json:"in"`
		Name bool   `json:"name"`
	} `json:"host_patterns"`
	KeyTypes []struct {
		Type     string `json:"type"`
		Accepted bool   `json:"accepted"`
	} `json:"key_types"`
}

func loadSSHVectors(t *testing.T) *sshVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/ssh_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v sshVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestSSHVectors(t *testing.T) {
	v := loadSSHVectors(t)
	for _, c := range v.Principals {
		if got := sshPrincipalRE.MatchString(c.In); got != c.OK {
			t.Errorf("principal %q: %v", c.In, got)
		}
	}
	for _, c := range v.HostGroupIDs {
		if got := sshHostGroupRE.MatchString(c.In); got != c.OK {
			t.Errorf("host group %q: %v", c.In, got)
		}
		if c.OK && validSSHHostGroup(c.In) == c.Reserved {
			t.Errorf("host group %q reserved=%v", c.In, c.Reserved)
		}
	}
	for _, c := range v.Usernames {
		if got := usernameRe.MatchString(c.In); got != c.OK {
			t.Errorf("username %q: %v", c.In, got)
		}
	}
	for _, c := range v.KeyIDs {
		m := sshKeyIDRE.FindStringSubmatch(c.In)
		if (m != nil) != c.OK || (m != nil && (m[1] != c.User || m[2] != c.HostGroup)) {
			t.Errorf("key id %q: %v", c.In, m)
		}
	}
	if len(v.Extensions) != len(sshExtensionSets) {
		t.Errorf("%d extension vectors, %d sets", len(v.Extensions), len(sshExtensionSets))
	}
	for _, c := range v.Extensions {
		if !validSSHExtensions(c.Value) {
			t.Errorf("extensions %q refused", c.Value)
		}
	}
	for _, c := range v.RoleTTLs {
		got, ok := sshRoundRoleTTL(c.In)
		if ok != c.OK || (ok && got != c.Out) {
			t.Errorf("ttl %d: %d %v", c.In, got, ok)
		}
	}
	for _, c := range v.HostPatterns {
		if got := validSSHHostPrincipal(c.In); got != c.Name {
			t.Errorf("host name %q: %v", c.In, got)
		}
	}
	for _, c := range v.KeyTypes {
		if _, ok := sshUserKeyLengths[c.Type]; ok != c.Accepted {
			t.Errorf("key type %s accepted=%v", c.Type, ok)
		}
	}
	// Roles: the body decodes to the spec, checkRole keeps it, and the
	// Vault write is exactly the vector's map.
	for _, c := range v.Roles {
		var spec sshRoleSpec
		if err := json.Unmarshal([]byte(c.Body), &spec); err != nil || !reflect.DeepEqual(spec, c.Spec) {
			t.Errorf("%s: body %v %v", c.Name, spec, err)
		}
		if err := checkRole(c.HostGroup, &spec); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		got, _ := json.Marshal(sshRoleWrite(spec))
		var a, b any
		json.Unmarshal(got, &a)
		json.Unmarshal(c.Vault, &b)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: vault write\n%s\nwant\n%s", c.Name, got, c.Vault)
		}
	}
}

// ── fake backend for the HTTP checks ──

type fakeSSH struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (f *fakeSSH) rec(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}
func (f *fakeSSH) n() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }
func (f *fakeSSH) putSSHRole(_ context.Context, hg string, s sshRoleSpec) (*sshRoleSpec, error) {
	f.rec("put " + hg)
	return &s, f.err
}
func (f *fakeSSH) deleteSSHRole(_ context.Context, hg string) error {
	f.rec("delete " + hg)
	return f.err
}
func (f *fakeSSH) listSSHRoles(context.Context) ([]string, error) {
	f.rec("list")
	return []string{"hg-web"}, f.err
}
func (f *fakeSSH) signSSHUser(_ context.Context, r sshUserSign, _ ssh.PublicKey, _ string) (*sshSigned, error) {
	f.rec("sign " + r.User)
	return &sshSigned{Certificate: "ssh-ed25519-cert-v01@openssh.com AAAA", Serial: "7", ValidBefore: "2026-11-17T20:00:00Z"}, f.err
}
func (f *fakeSSH) signSSHHost(_ context.Context, r sshHostSign, _ ssh.PublicKey, _ string) (*sshSigned, error) {
	f.rec("host " + r.HostID)
	return &sshSigned{Certificate: "x", Serial: "8", ValidBefore: "2026-11-17T20:00:00Z"}, f.err
}
func (f *fakeSSH) sshCA(context.Context) (*sshCAView, error) {
	f.rec("ca")
	return &sshCAView{UserCAs: []string{}, HostCAs: []string{}, Problems: []string{}}, f.err
}

func sshTestService(t *testing.T) (*inviteService, *fakeSSH) {
	t.Helper()
	s, _ := testInvites(t)
	f := &fakeSSH{}
	s.ssh = f
	s.sshUserExists = func(u string) error {
		switch u {
		case "alice", "bob":
			return nil
		case "ldapdown":
			return errors.New("ldap dial: refused")
		}
		return refuse(404, "no such user")
	}
	return s, f
}

func sshDo(s *inviteService, method, path, body string) *httptest.ResponseRecorder {
	return do(s.apiHandler(false), method, path, body, map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + testAPISecret})
}

func testKey(t *testing.T) (ssh.PublicKey, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), priv
}

func TestSSHRoutesNeedBearer(t *testing.T) {
	s, f := sshTestService(t)
	for _, r := range []struct{ m, p string }{{"PUT", "/internal/ssh-roles/web"}, {"DELETE", "/internal/ssh-roles/web"}, {"GET", "/internal/ssh-roles"},
		{"POST", "/internal/ssh-certificates"}, {"POST", "/internal/ssh-host-certificates"}, {"GET", "/internal/ssh-ca"}} {
		if w := do(s.apiHandler(false), r.m, r.p, "{}", map[string]string{"Authorization": "Bearer wrong"}); w.Code != 401 {
			t.Errorf("%s %s: %d", r.m, r.p, w.Code)
		}
		if w := do(s.apiHandler(true), r.m, r.p, "{}", nil); w.Code != 404 && w.Code != 405 {
			t.Errorf("%s %s on the loopback listener: %d", r.m, r.p, w.Code)
		}
	}
	if f.n() != 0 {
		t.Errorf("calls without the bearer: %v", f.calls)
	}
	s.ssh = nil
	if w := sshDo(s, "GET", "/internal/ssh-ca", ""); w.Code != 503 {
		t.Errorf("unwired: %d", w.Code)
	}
}

func roleBody(principals []string, ext string, cidrs []string, ttl int) string {
	b, _ := json.Marshal(sshRoleSpec{Principals: principals, Extensions: ext, SourceAddress: cidrs, MaxTTLSeconds: ttl})
	return string(b)
}

func TestSSHRoleBodyChecks(t *testing.T) {
	s, f := sshTestService(t)
	many := make([]string, 4097)
	for i := range many {
		many[i] = fmt.Sprintf("u:a%d@web", i)
	}
	cidrs := make([]string, 17)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("192.0.2.%d/32", i)
	}
	bad := map[string]struct{ path, body string }{
		"id grammar":            {"/internal/ssh-roles/Web", roleBody([]string{"u:alice@Web"}, "permit-pty", nil, 3600)},
		"reserved id":           {"/internal/ssh-roles/portcullis-servers", roleBody([]string{"u:alice@portcullis-servers"}, "permit-pty", nil, 3600)},
		"principal grammar":     {"/internal/ssh-roles/web", roleBody([]string{"alice@web"}, "permit-pty", nil, 3600)},
		"principal other group": {"/internal/ssh-roles/web", roleBody([]string{"u:alice@all"}, "permit-pty", nil, 3600)},
		"principal twice":       {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web", "u:alice@web"}, "permit-pty", nil, 3600)},
		"4097 principals":       {"/internal/ssh-roles/web", roleBody(many, "permit-pty", nil, 3600)},
		"extension set":         {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "permit-pty,permit-X11-forwarding", nil, 3600)},
		"extension order":       {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "permit-port-forwarding,permit-pty", nil, 3600)},
		"no pty":                {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "", nil, 3600)},
		"17 CIDRs":              {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "permit-pty", cidrs, 3600)},
		"bad CIDR":              {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "permit-pty", []string{"192.0.2.1/24"}, 3600)},
		"43201 s":               {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "permit-pty", nil, 43201)},
		"0 s":                   {"/internal/ssh-roles/web", roleBody([]string{"u:alice@web"}, "permit-pty", nil, 0)},
		"unknown field":         {"/internal/ssh-roles/web", `{"principals":[],"extensions":"permit-pty","source_address":[],"max_ttl_s":3600,"ttl":"99h"}`},
	}
	for name, c := range bad {
		if w := sshDo(s, "PUT", c.path, c.body); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if f.n() != 0 {
		t.Fatalf("Vault called on a refused role: %v", f.calls)
	}
	w := sshDo(s, "PUT", "/internal/ssh-roles/web", roleBody([]string{"s:deploy@web", "u:alice@web"}, "permit-pty", []string{"192.0.2.0/24"}, 3601))
	var back sshRoleSpec
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &back) != nil || back.MaxTTLSeconds != 7200 {
		t.Errorf("good role: %d %s", w.Code, w.Body)
	}
	if w := sshDo(s, "DELETE", "/internal/ssh-roles/Web", ""); w.Code != 400 {
		t.Errorf("delete bad id: %d", w.Code)
	}
	if w := sshDo(s, "DELETE", "/internal/ssh-roles/web", ""); w.Code != 204 {
		t.Errorf("delete: %d", w.Code)
	}
	if w := sshDo(s, "GET", "/internal/ssh-roles", ""); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"roles":["hg-web"]}` {
		t.Errorf("list: %d %s", w.Code, w.Body)
	}
}

func signBody(t *testing.T, mut func(*sshUserSign)) string {
	t.Helper()
	_, line, _ := testKey(t)
	r := sshUserSign{User: "alice", HostGroup: "web", PublicKey: line, Principals: []string{"u:alice@web", "s:deploy@web"},
		ValidSeconds: 28800, Extensions: []string{"permit-pty"}, KeyID: "pc:alice:web:0123456789abcdef"}
	if mut != nil {
		mut(&r)
	}
	b, _ := json.Marshal(r)
	return string(b)
}

func TestSSHSignRefusals(t *testing.T) {
	s, f := sshTestService(t)
	rsa := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7"
	cases := map[string]struct {
		mut  func(*sshUserSign)
		want int
	}{
		"protected admin": {func(r *sshUserSign) {
			r.User = "admin"
			r.Principals = []string{"s:deploy@web"}
			r.KeyID = "pc:admin:web:0123456789abcdef"
		}, 409},
		"protected hub":    {func(r *sshUserSign) { r.User = "portcullis-hub" }, 409},
		"protected prefix": {func(r *sshUserSign) { r.User = "Portcullis-x" }, 409},
		"not in LLDAP": {func(r *sshUserSign) {
			r.User = "carol"
			r.Principals = []string{"u:carol@web"}
			r.KeyID = "pc:carol:web:0123456789abcdef"
		}, 409},
		"user grammar":          {func(r *sshUserSign) { r.User = "Al ice" }, 400},
		"rsa key":               {func(r *sshUserSign) { r.PublicKey = rsa }, 400},
		"two lines":             {func(r *sshUserSign) { r.PublicKey += "\nssh-ed25519 AAAA" }, 400},
		"options":               {func(r *sshUserSign) { r.PublicKey = `command="x" ` + r.PublicKey }, 400},
		"principal grammar":     {func(r *sshUserSign) { r.Principals = []string{"alice@web"} }, 400},
		"principal other group": {func(r *sshUserSign) { r.Principals = []string{"u:alice@all"} }, 400},
		"another person":        {func(r *sshUserSign) { r.Principals = []string{"u:bob@web"} }, 400},
		"no principals":         {func(r *sshUserSign) { r.Principals = nil }, 400},
		"299 s":                 {func(r *sshUserSign) { r.ValidSeconds = 299 }, 400},
		"43201 s":               {func(r *sshUserSign) { r.ValidSeconds = 43201 }, 400},
		"extension":             {func(r *sshUserSign) { r.Extensions = []string{"permit-pty", "permit-user-rc"} }, 400},
		"no extensions":         {func(r *sshUserSign) { r.Extensions = nil }, 400},
		"key id form":           {func(r *sshUserSign) { r.KeyID = "pc:alice:web:0123" }, 400},
		"key id other user":     {func(r *sshUserSign) { r.KeyID = "pc:bob:web:0123456789abcdef" }, 400},
		"key id other group":    {func(r *sshUserSign) { r.KeyID = "pc:alice:all:0123456789abcdef" }, 400},
		"reserved group": {func(r *sshUserSign) {
			r.HostGroup = "portcullis-servers"
			r.Principals = []string{"u:alice@portcullis-servers"}
		}, 400},
		"ldap down": {func(r *sshUserSign) {
			r.User = "ldapdown"
			r.Principals = []string{"s:deploy@web"}
			r.KeyID = "pc:ldapdown:web:0123456789abcdef"
		}, 503},
	}
	for name, c := range cases {
		if w := sshDo(s, "POST", "/internal/ssh-certificates", signBody(t, c.mut)); w.Code != c.want {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	if f.n() != 0 {
		t.Fatalf("Vault called on a refused sign: %v", f.calls)
	}
	if w := sshDo(s, "POST", "/internal/ssh-certificates", signBody(t, nil)); w.Code != 201 {
		t.Errorf("good sign: %d %s", w.Code, w.Body)
	}
	// Host certificates: ed25519 only, 1–64 names, DNS names or IPs.
	_, line, _ := testKey(t)
	host := func(mut func(*sshHostSign)) string {
		r := sshHostSign{PublicKey: line, Principals: []string{"web-1.example.com", "192.0.2.11"}, HostGroup: "web", HostID: "web-1"}
		if mut != nil {
			mut(&r)
		}
		b, _ := json.Marshal(r)
		return string(b)
	}
	names := make([]string, 65)
	for i := range names {
		names[i] = fmt.Sprintf("h%d.example.com", i)
	}
	for name, mut := range map[string]func(*sshHostSign){
		"ecdsa key": func(r *sshHostSign) {
			r.PublicKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEm"
		},
		"no names": func(r *sshHostSign) { r.Principals = nil },
		"65 names": func(r *sshHostSign) { r.Principals = names },
		"wildcard": func(r *sshHostSign) { r.Principals = []string{"*.example.com"} },
		"zone":     func(r *sshHostSign) { r.Principals = []string{"fe80::1%eth0"} },
		"host id":  func(r *sshHostSign) { r.HostID = "Web 1" },
	} {
		if w := sshDo(s, "POST", "/internal/ssh-host-certificates", host(mut)); w.Code != 400 {
			t.Errorf("host %s: %d", name, w.Code)
		}
	}
	if w := sshDo(s, "POST", "/internal/ssh-host-certificates", host(nil)); w.Code != 201 {
		t.Errorf("good host sign: %d %s", w.Code, w.Body)
	}
}

// ── fake Vault for the Vault-side tests ──

type fakeSSHVault struct {
	t      *testing.T
	mu     sync.Mutex
	writes map[string]map[string]any
	ca     ssh.Signer
	// mutate changes the signed certificate (a Vault answering wrong).
	mutate func(*ssh.Certificate)
	// read answers for GET paths (nil = 404).
	reads map[string]map[string]any
}

func newFakeSSHVault(t *testing.T) (*fakeSSHVault, *Config) {
	t.Helper()
	_, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(caPriv)
	fv := &fakeSSHVault{t: t, writes: map[string]map[string]any{}, ca: ca, reads: map[string]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(fv.serve))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "role-id"), []byte("role"), 0o600)
	os.WriteFile(filepath.Join(dir, "secret-id"), []byte("secret"), 0o600)
	cfg := &Config{VaultAddr: srv.URL, vault: newVaultAuth(srv.URL, "approle", filepath.Join(dir, "role-id"), filepath.Join(dir, "secret-id"))}
	return fv, cfg
}

func (fv *fakeSSHVault) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if path == "auth/approle/login" {
		json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok", "lease_duration": 3600, "renewable": true}})
		return
	}
	fv.mu.Lock()
	defer fv.mu.Unlock()
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		fv.writes[path] = body
		switch {
		case strings.HasPrefix(path, "ssh_user/roles/"):
			// Vault's read-back shape (spike S4): ints and maps.
			ttl := 0
			fmt.Sscan(body["max_ttl"].(string), &ttl)
			fv.reads[path] = map[string]any{"key_type": "ca", "allow_host_certificates": false, "allowed_users": body["allowed_users"],
				"allowed_extensions": body["allowed_extensions"], "default_critical_options": body["default_critical_options"], "max_ttl": ttl, "ttl": ttl}
			w.WriteHeader(204)
		case strings.Contains(path, "/sign/"):
			fv.sign(w, path, body)
		default:
			w.WriteHeader(204)
		}
	case http.MethodDelete:
		delete(fv.reads, path)
		w.WriteHeader(204)
	case "LIST":
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": []string{"hg-web", "hg-all", "other", "hg-Bad"}}})
	case http.MethodGet:
		if r.URL.Query().Get("list") == "true" {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": []string{"hg-web", "hg-all", "other", "hg-Bad"}}})
			return
		}
		d, ok := fv.reads[path]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte(`{"errors":[]}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"data": d})
	}
}

func (fv *fakeSSHVault) sign(w http.ResponseWriter, path string, body map[string]any) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body["public_key"].(string)))
	if err != nil {
		w.WriteHeader(400)
		return
	}
	c := &ssh.Certificate{Key: pk, Serial: 1234567890123, KeyId: fmt.Sprint(body["key_id"]),
		ValidPrincipals: strings.Split(body["valid_principals"].(string), ","),
		ValidAfter:      uint64(time.Now().Add(-30 * time.Second).Unix())}
	if strings.HasPrefix(path, "ssh_host/") {
		c.CertType = ssh.HostCert
		if body["cert_type"] != "host" {
			c.CertType = ssh.UserCert // Vault's default
		}
		c.ValidBefore = uint64(time.Now().Add(2160 * time.Hour).Unix())
	} else {
		c.CertType = ssh.UserCert
		var secs int
		fmt.Sscanf(body["ttl"].(string), "%ds", &secs)
		c.ValidBefore = uint64(time.Now().Add(time.Duration(secs) * time.Second).Unix())
		c.Permissions.Extensions = map[string]string{}
		for k := range body["extensions"].(map[string]any) {
			c.Permissions.Extensions[k] = ""
		}
	}
	if fv.mutate != nil {
		fv.mutate(c)
	}
	if err := c.SignCert(rand.Reader, fv.ca); err != nil {
		fv.t.Fatal(err)
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"signed_key": string(ssh.MarshalAuthorizedKey(c)), "serial_number": "11f71fb0447"}})
}

// TestSSHRoleStringEncoding: every scalar of the role write is a string
// (C15, spike S4); the three maps are maps; the read-back is normalised.
func TestSSHRoleStringEncoding(t *testing.T) {
	fv, cfg := newFakeSSHVault(t)
	spec := sshRoleSpec{Principals: []string{"s:deploy@web", "u:alice@web"}, Extensions: "permit-pty,permit-port-forwarding", SourceAddress: []string{"192.0.2.0/24"}, MaxTTLSeconds: 14400}
	back, err := cfg.putSSHRole(context.Background(), "web", spec)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*back, spec) {
		t.Errorf("read-back %+v", back)
	}
	body := fv.writes["ssh_user/roles/hg-web"]
	for k, v := range body {
		switch k {
		case "default_extensions", "default_critical_options", "allowed_user_key_lengths":
			if _, ok := v.(map[string]any); !ok {
				t.Errorf("%s = %T", k, v)
			}
		default:
			if _, ok := v.(string); !ok {
				t.Errorf("%s = %T %v: not a string", k, v, v)
			}
		}
	}
	if body["ttl"] != "14400" || body["max_ttl"] != "14400" || body["allowed_critical_options"] != "source-address" {
		t.Errorf("write %v", body)
	}
	roles, err := cfg.listSSHRoles(context.Background())
	if err != nil || !reflect.DeepEqual(roles, []string{"hg-all", "hg-web"}) {
		t.Errorf("list %v %v", roles, err)
	}
	if err := cfg.deleteSSHRole(context.Background(), "web"); err != nil {
		t.Error(err)
	}
}

func TestSSHUserSignChecksVaultsAnswer(t *testing.T) {
	fv, cfg := newFakeSSHVault(t)
	k, line, _ := testKey(t)
	r := sshUserSign{User: "alice", HostGroup: "web", PublicKey: line, Principals: []string{"u:alice@web"}, ValidSeconds: 3600, Extensions: []string{"permit-pty"}, KeyID: "pc:alice:web:0123456789abcdef"}
	got, err := cfg.signSSHUser(context.Background(), r, k, line)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != "1234567890123" || !strings.HasPrefix(got.Certificate, "ssh-ed25519-cert-v01@openssh.com ") {
		t.Errorf("answer %+v", got)
	}
	body := fv.writes["ssh_user/sign/hg-web"]
	if _, ok := body["cert_type"]; ok {
		t.Error("cert_type sent on a user sign")
	}
	if _, ok := body["critical_options"]; ok {
		t.Error("critical_options sent on a user sign")
	}
	if ext, ok := body["extensions"].(map[string]any); !ok || len(ext) != 1 || ext["permit-pty"] != "" {
		t.Errorf("extensions %v (a map with permit-pty)", body["extensions"])
	}
	for name, mut := range map[string]func(*ssh.Certificate){
		"other principal": func(c *ssh.Certificate) { c.ValidPrincipals = []string{"u:bob@web"} },
		"host type":       func(c *ssh.Certificate) { c.CertType = ssh.HostCert },
		"other key id":    func(c *ssh.Certificate) { c.KeyId = "vault-approle-x" },
		"extra extension": func(c *ssh.Certificate) { c.Permissions.Extensions["permit-user-rc"] = "" },
		"force-command":   func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "sh"} },
		"too long":        func(c *ssh.Certificate) { c.ValidBefore += 3600 },
		"other key": func(c *ssh.Certificate) {
			k2, _, _ := testKey(t)
			c.Key = k2
		},
	} {
		fv.mutate = mut
		if _, err := cfg.signSSHUser(context.Background(), r, k, line); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSSHHostSignCertType: the host sign sends cert_type=host and key_id
// pc-host:<id> (spike S4b) and refuses a user certificate back.
func TestSSHHostSignCertType(t *testing.T) {
	fv, cfg := newFakeSSHVault(t)
	k, line, _ := testKey(t)
	r := sshHostSign{PublicKey: line, Principals: []string{"web-1.example.com"}, HostGroup: "web", HostID: "web-1"}
	if _, err := cfg.signSSHHost(context.Background(), r, k, line); err != nil {
		t.Fatal(err)
	}
	b := fv.writes["ssh_host/sign/host"]
	if b["cert_type"] != "host" || b["key_id"] != "pc-host:web-1" || b["valid_principals"] != "web-1.example.com" {
		t.Errorf("host sign body %v", b)
	}
	if _, ok := b["ttl"]; ok {
		t.Error("ttl sent on a host sign (the role's 2160h)")
	}
	fv.mutate = func(c *ssh.Certificate) { c.CertType = ssh.UserCert }
	if _, err := cfg.signSSHHost(context.Background(), r, k, line); err == nil {
		t.Error("a user certificate accepted as a host certificate")
	}
}

func TestSSHCAProblems(t *testing.T) {
	fv, cfg := newFakeSSHVault(t)
	edPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(fv.ca.PublicKey())))
	good := func() {
		fv.reads = map[string]map[string]any{
			"sys/mounts/ssh_user/tune": {"max_lease_ttl": 43200},
			"sys/mounts/ssh_host/tune": {"max_lease_ttl": 7776000},
			"ssh_user/config/ca":       {"public_key": edPub + "\n"},
			"ssh_host/config/ca":       {"public_key": edPub + "\n"},
			"ssh_host/roles/host":      {"key_type": "ca", "allow_host_certificates": true, "allow_user_certificates": false, "allow_user_key_ids": true},
		}
	}
	good()
	v, err := cfg.sshCA(context.Background())
	if err != nil || len(v.Problems) != 0 || len(v.UserCAs) != 1 || v.UserCAs[0] != edPub || len(v.HostCAs) != 1 {
		t.Fatalf("good: %+v %v", v, err)
	}
	cases := map[string]struct {
		mut  func()
		want string
	}{
		"user cap": {func() { fv.reads["sys/mounts/ssh_user/tune"]["max_lease_ttl"] = 86400 }, "ssh_user: max_lease_ttl is 86400 s, not 12h"},
		"host cap": {func() { fv.reads["sys/mounts/ssh_host/tune"]["max_lease_ttl"] = 2764800 }, "ssh_host: max_lease_ttl"},
		"no mount": {func() { delete(fv.reads, "sys/mounts/ssh_user/tune") }, "ssh_user: the mount is missing"},
		"no CA":    {func() { delete(fv.reads, "ssh_host/config/ca") }, "ssh_host: no CA"},
		"rsa CA": {func() {
			fv.reads["ssh_user/config/ca"]["public_key"] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDMaQ7b2jbNpk1VbLM84Tv0J5vQKX7XpZxS1lkQHkE+2W8BMbZqFSaNzV8jC1Cr+Sb3K0Md7m0Ae4p1eGBQqTGEGl8V/4s4OaLP0Gf3eoRwhETc7Oge2JxzVQc4mRh+o5KTgUJjWbRxrH4PGh9Y2ZTA5LLZWuRZ3A7AnMP2AO6AnQ=="
		}, "ssh_user: the CA key is ssh-rsa, not ed25519"},
		"host role allows users": {func() { fv.reads["ssh_host/roles/host"]["allow_user_certificates"] = true }, "allow_user_certificates isn't false"},
		"host role no host":      {func() { fv.reads["ssh_host/roles/host"]["allow_host_certificates"] = false }, "allow_host_certificates isn't true"},
		"no host role":           {func() { delete(fv.reads, "ssh_host/roles/host") }, "ssh_host/roles/host: missing"},
		"host role no key ids":   {func() { fv.reads["ssh_host/roles/host"]["allow_user_key_ids"] = false }, "allow_user_key_ids isn't true"},
	}
	for name, c := range cases {
		good()
		c.mut()
		v, err := cfg.sshCA(context.Background())
		if err != nil || !strings.Contains(strings.Join(v.Problems, "\n"), c.want) {
			t.Errorf("%s: %v %v", name, v.Problems, err)
		}
	}
}

// TestSSHSignLogsNoKey: the sign logs name the user, host group,
// principals, serial and fingerprint — never the key or certificate.
func TestSSHSignLogsNoKey(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	s, _ := sshTestService(t)
	_, cfg := newFakeSSHVault(t)
	s.ssh = cfg
	k, line, _ := testKey(t)
	body, _ := json.Marshal(sshUserSign{User: "alice", HostGroup: "web", PublicKey: line, Principals: []string{"u:alice@web"}, ValidSeconds: 3600, Extensions: []string{"permit-pty"}, KeyID: "pc:alice:web:0123456789abcdef"})
	w := sshDo(s, "POST", "/internal/ssh-certificates", string(body))
	if w.Code != 201 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var ans sshSigned
	json.Unmarshal(w.Body.Bytes(), &ans)
	// A refused sign logs no key either.
	bad, _ := json.Marshal(sshUserSign{User: "alice", HostGroup: "web", PublicKey: line, Principals: []string{"u:bob@web"}, ValidSeconds: 3600, Extensions: []string{"permit-pty"}, KeyID: "pc:alice:web:0123456789abcdef"})
	sshDo(s, "POST", "/internal/ssh-certificates", string(bad))
	out := buf.String()
	b64 := strings.Fields(line)[1]
	certB64 := strings.Fields(ans.Certificate)[1]
	if strings.Contains(out, b64) || strings.Contains(out, certB64) {
		t.Errorf("a key reached the log:\n%s", out)
	}
	if !strings.Contains(out, ssh.FingerprintSHA256(k)) || !strings.Contains(out, "alice") || !strings.Contains(out, ans.Serial) {
		t.Errorf("the log lacks fingerprint / user / serial:\n%s", out)
	}
	if strings.Contains(w.Body.String(), b64) {
		t.Error("the answer echoes the public key")
	}
}
