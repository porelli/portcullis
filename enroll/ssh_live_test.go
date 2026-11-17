package main

// TestLiveSSHVault: spike S1 and S4 as a permanent, opt-in test against a
// real Vault (2.2.1, dev mode is fine) with the real vault/policies/enroll.hcl.
//
//	PORTCULLIS_VAULT_LIVE_ADDR=http://127.0.0.1:8200 PORTCULLIS_VAULT_LIVE_TOKEN=<root> go test -run TestLiveSSHVault -v
//
// It sets the mounts up like ssh_setup, attaches the policy to an AppRole
// and then works as enroll: every refusal of the spike, the four key
// types, the host sign's cert_type, and the endpoints' own Vault paths.
// It changes the Vault it is pointed at: use a throwaway one.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
)

// skKey builds an authorized_keys line of a security-key type (Vault
// signs the public key only; no device needed).
func skKey(t *testing.T, ecdsaKind bool) (ssh.PublicKey, string) {
	t.Helper()
	var blob []byte
	if ecdsaKind {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pt := elliptic.Marshal(elliptic.P256(), k.X, k.Y) //nolint:staticcheck // the SSH wire form
		blob = ssh.Marshal(struct{ Type, Curve, Point, App string }{"sk-ecdsa-sha2-nistp256@openssh.com", "nistp256", string(pt), "ssh:"})
	} else {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		blob = ssh.Marshal(struct{ Type, Key, App string }{"sk-ssh-ed25519@openssh.com", string(pub), "ssh:"})
	}
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	return k, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func TestLiveSSHVault(t *testing.T) {
	addr, tok := os.Getenv("PORTCULLIS_VAULT_LIVE_ADDR"), os.Getenv("PORTCULLIS_VAULT_LIVE_TOKEN")
	if addr == "" || tok == "" {
		t.Skip("PORTCULLIS_VAULT_LIVE_ADDR / PORTCULLIS_VAULT_LIVE_TOKEN not set")
	}
	ctx := context.Background()
	rc, err := vault.NewClient(&vault.Config{Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	rc.SetToken(tok)
	must := func(err error, what string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	sys := rc.Sys()
	mounts, err := sys.ListMounts()
	must(err, "list mounts")
	for _, m := range []struct{ path, ttl string }{{"ssh_user", "12h"}, {"ssh_host", "2160h"}} {
		if _, ok := mounts[m.path+"/"]; !ok {
			must(sys.Mount(m.path, &vault.MountInput{Type: "ssh"}), "mount "+m.path)
			must(sys.TuneMount(m.path, vault.MountConfigInput{MaxLeaseTTL: m.ttl}), "tune "+m.path)
			_, err := rc.Logical().Write(m.path+"/config/ca", map[string]any{"generate_signing_key": true, "key_type": "ed25519"})
			must(err, "CA "+m.path)
		}
	}
	_, err = rc.Logical().Write("ssh_host/roles/host", map[string]any{"key_type": "ca", "allow_host_certificates": true, "allow_user_certificates": false,
		"allow_user_key_ids": true, "allowed_domains": "*", "allow_subdomains": true, "allow_bare_domains": true, "ttl": "2160h", "max_ttl": "2160h"})
	must(err, "host role")
	pol, err := os.ReadFile("../vault/policies/enroll.hcl")
	must(err, "policy file")
	must(sys.PutPolicy("portcullis-enroll-live", string(pol)), "policy")
	if auths, _ := sys.ListAuth(); auths["approle/"] == nil {
		must(sys.EnableAuthWithOptions("approle", &vault.EnableAuthOptions{Type: "approle"}), "approle")
	}
	_, err = rc.Logical().Write("auth/approle/role/enroll-live", map[string]any{"token_policies": "portcullis-enroll-live", "token_ttl": "1h"})
	must(err, "approle role")
	rid, err := rc.Logical().Read("auth/approle/role/enroll-live/role-id")
	must(err, "role id")
	sid, err := rc.Logical().Write("auth/approle/role/enroll-live/secret-id", nil)
	must(err, "secret id")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "role-id"), []byte(rid.Data["role_id"].(string)), 0o600)
	os.WriteFile(filepath.Join(dir, "secret-id"), []byte(sid.Data["secret_id"].(string)), 0o600)
	cfg := &Config{VaultAddr: addr, vault: newVaultAuth(addr, "approle", filepath.Join(dir, "role-id"), filepath.Join(dir, "secret-id"))}
	ec, err := cfg.vault.client(true)
	must(err, "enroll login")
	refused := func(name, path string, body map[string]any) {
		t.Helper()
		if _, err := ec.Logical().WriteWithContext(ctx, path, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// The role through enroll's own code: written, read back equal.
	spec := sshRoleSpec{Principals: []string{"s:deploy@live", "u:alice@live"}, Extensions: "permit-pty", SourceAddress: []string{}, MaxTTLSeconds: 14400}
	back, err := cfg.putSSHRole(ctx, "live", spec)
	must(err, "put role")
	if back.MaxTTLSeconds != 14400 || strings.Join(back.Principals, ",") != "s:deploy@live,u:alice@live" || back.Extensions != "permit-pty" {
		t.Errorf("read-back %+v", back)
	}
	roles, err := cfg.listSSHRoles(ctx)
	must(err, "list roles")
	if !strings.Contains(strings.Join(roles, ","), "hg-live") {
		t.Errorf("list %v", roles)
	}

	// S4 / S4c: the policy refuses every role shape outside §18.7.
	base := sshRoleWrite(spec)
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	refused("role max_ttl 86400 (S4c: no role above 12 h)", "ssh_user/roles/hg-live", with("max_ttl", "86400"))
	refused("role ttl 86400", "ssh_user/roles/hg-live", with("ttl", "86400"))
	refused("role ttl 1800 (not a whole hour)", "ssh_user/roles/hg-live", with("ttl", "1800"))
	refused("role allow_host_certificates", "ssh_user/roles/hg-live", with("allow_host_certificates", "true"))
	refused("role JSON boolean (S4)", "ssh_user/roles/hg-live", with("allow_user_certificates", true))
	refused("role X11", "ssh_user/roles/hg-live", with("allowed_extensions", "permit-pty,permit-X11-forwarding"))
	refused("role user-rc", "ssh_user/roles/hg-live", with("allowed_extensions", "permit-pty,permit-user-rc"))
	refused("role force-command", "ssh_user/roles/hg-live", with("allowed_critical_options", "force-command"))
	refused("role key_type otp", "ssh_user/roles/hg-live", with("key_type", "otp"))
	refused("a role outside hg-*", "ssh_user/roles/web", base)
	// Security review: no wildcard principal, no default extension.
	refused("role allowed_users *", "ssh_user/roles/hg-live", with("allowed_users", "*"))
	refused("role allowed_users * with a permit-pty default", "ssh_user/roles/hg-live", func() map[string]any {
		m := with("allowed_users", "*")
		m["default_extensions"] = map[string]any{"permit-pty": ""}
		return m
	}())
	refused("role default_extensions permit-pty", "ssh_user/roles/hg-live", with("default_extensions", map[string]any{"permit-pty": ""}))
	refused("role default_extensions X11", "ssh_user/roles/hg-live", with("default_extensions", map[string]any{"permit-X11-forwarding": ""}))
	refused("role allowed_users_template", "ssh_user/roles/hg-live", with("allowed_users_template", "true"))
	refused("role allowed_users not s:/u:", "ssh_user/roles/hg-live", with("allowed_users", "root"))
	refused("the host role", "ssh_host/roles/host", map[string]any{"key_type": "ca", "allow_user_certificates": "true"})
	refused("a new user CA", "ssh_user/config/ca", map[string]any{"generate_signing_key": "true"})
	if back, err := ec.Logical().ReadWithContext(ctx, "ssh_user/roles/hg-live"); err != nil || back == nil {
		t.Errorf("role read: %v", err)
	} else if n, _ := numberOf(back.Data["max_ttl"]); n != 14400 {
		t.Errorf("a refused write changed the role: max_ttl %v", back.Data["max_ttl"])
	}

	// S1: the four key types sign; RSA doesn't.
	edK, edLine, _ := testKey(t)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecK, _ := ssh.NewPublicKey(&ecPriv.PublicKey)
	ecLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ecK)))
	skEdK, skEdLine := skKey(t, false)
	skEcK, skEcLine := skKey(t, true)
	req := sshUserSign{User: "alice", HostGroup: "live", Principals: []string{"u:alice@live"}, ValidSeconds: 3600, Extensions: []string{"permit-pty"}, KeyID: "pc:alice:live:0123456789abcdef"}
	for name, k := range map[string]struct {
		k    ssh.PublicKey
		line string
	}{"ed25519": {edK, edLine}, "ecdsa p256": {ecK, ecLine}, "sk ed25519": {skEdK, skEdLine}, "sk ecdsa": {skEcK, skEcLine}} {
		r := req
		r.PublicKey = k.line
		got, err := cfg.signSSHUser(ctx, r, k.k, k.line)
		if err != nil {
			t.Errorf("S1 %s: %v", name, err)
			continue
		}
		c, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(got.Certificate))
		cert := c.(*ssh.Certificate)
		if cert.KeyId != req.KeyID || cert.Permissions.Extensions["permit-pty"] != "" || len(cert.Permissions.Extensions) != 1 {
			t.Errorf("S1 %s: certificate %+v", name, cert)
		}
		if life := time.Unix(int64(cert.ValidBefore), 0).Sub(time.Now()); life > time.Hour+time.Minute {
			t.Errorf("S1 %s: lives %v", name, life)
		}
	}
	rsaPub := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDMaQ7b2jbNpk1VbLM84Tv0J5vQKX7XpZxS1lkQHkE+2W8BMbZqFSaNzV8jC1Cr+Sb3K0Md7m0Ae4p1eGBQqTGEGl8V/4s4OaLP0Gf3eoRwhETc7Oge2JxzVQc4mRh+o5KTgUJjWbRxrH4PGh9Y2ZTA5LLZWuRZ3A7AnMP2AO6AnQ=="
	signBody := func(k string, v any) map[string]any {
		m := map[string]any{"public_key": edLine, "valid_principals": "u:alice@live", "ttl": "3600s", "extensions": map[string]any{"permit-pty": ""}, "key_id": req.KeyID}
		if k != "" {
			m[k] = v
		}
		return m
	}
	refused("RSA key", "ssh_user/sign/hg-live", signBody("public_key", rsaPub))
	refused("user sign with cert_type", "ssh_user/sign/hg-live", signBody("cert_type", "user"))
	refused("user sign as host", "ssh_user/sign/hg-live", signBody("cert_type", "host"))
	refused("user sign with critical_options", "ssh_user/sign/hg-live", signBody("critical_options", map[string]any{"force-command": "sh"}))
	refused("ttl over the role", "ssh_user/sign/hg-live", signBody("ttl", "43200s"))
	refused("a principal outside the role", "ssh_user/sign/hg-live", signBody("valid_principals", "u:bob@live"))
	refused("an extension outside the role", "ssh_user/sign/hg-live", signBody("extensions", map[string]any{"permit-pty": "", "permit-port-forwarding": ""}))
	refused("a role without hg-", "ssh_user/sign/web", signBody("", nil))

	// An embedded "*" passes the policy (s:/u: prefix) but is no wildcard
	// in Vault, and an exact entry is no glob.
	_, err = ec.Logical().WriteWithContext(ctx, "ssh_user/roles/hg-star", func() map[string]any {
		m := sshRoleWrite(sshRoleSpec{Principals: []string{"u:alice@star", "*"}, Extensions: "permit-pty", SourceAddress: []string{}, MaxTTLSeconds: 3600})
		return m
	}())
	if err == nil {
		refused("the embedded * signs root", "ssh_user/sign/hg-star", signBody("valid_principals", "root"))
		refused("the embedded * signs u:bob", "ssh_user/sign/hg-star", signBody("valid_principals", "u:bob@star"))
		_, _ = ec.Logical().DeleteWithContext(ctx, "ssh_user/roles/hg-star")
	}
	_, err = ec.Logical().WriteWithContext(ctx, "ssh_user/roles/hg-glob", sshRoleWrite(sshRoleSpec{Principals: []string{"u:*"}, Extensions: "permit-pty", SourceAddress: []string{}, MaxTTLSeconds: 3600}))
	must(err, "glob role (passes the policy)")
	refused("u:* isn't a glob in Vault", "ssh_user/sign/hg-glob", signBody("valid_principals", "u:bob@glob"))
	_, _ = ec.Logical().DeleteWithContext(ctx, "ssh_user/roles/hg-glob")

	// An empty principal list signs nothing.
	_, err = cfg.putSSHRole(ctx, "empty", sshRoleSpec{Principals: []string{}, Extensions: "permit-pty", SourceAddress: []string{}, MaxTTLSeconds: 3600})
	must(err, "empty role")
	refused("a role with no principals", "ssh_user/sign/hg-empty", signBody("", nil))
	refused("a role with no principals, none asked", "ssh_user/sign/hg-empty", signBody("valid_principals", ""))
	must(cfg.deleteSSHRole(ctx, "empty"), "delete empty role")

	// source-address comes from the role.
	_, err = cfg.putSSHRole(ctx, "vpn", sshRoleSpec{Principals: []string{"u:alice@vpn"}, Extensions: "permit-pty", SourceAddress: []string{"192.0.2.0/24"}, MaxTTLSeconds: 3600})
	must(err, "vpn role")
	r := req
	r.HostGroup, r.Principals, r.KeyID, r.PublicKey = "vpn", []string{"u:alice@vpn"}, "pc:alice:vpn:0123456789abcdef", edLine
	got, err := cfg.signSSHUser(ctx, r, edK, edLine)
	must(err, "vpn sign")
	c, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(got.Certificate))
	if c.(*ssh.Certificate).CriticalOptions["source-address"] != "192.0.2.0/24" {
		t.Errorf("source-address %v", c.(*ssh.Certificate).CriticalOptions)
	}
	must(cfg.deleteSSHRole(ctx, "vpn"), "delete vpn role")

	// S4b: host certificates only with cert_type=host.
	refused("host sign without cert_type", "ssh_host/sign/host", map[string]any{"public_key": edLine, "valid_principals": "web-1.example.com"})
	refused("host sign as user", "ssh_host/sign/host", map[string]any{"public_key": edLine, "valid_principals": "web-1.example.com", "cert_type": "user"})
	hs, err := cfg.signSSHHost(ctx, sshHostSign{PublicKey: edLine, Principals: []string{"web-1.example.com", "192.0.2.11"}, HostGroup: "live", HostID: "web-1"}, edK, edLine)
	must(err, "host sign")
	hc, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(hs.Certificate))
	if hc.(*ssh.Certificate).CertType != ssh.HostCert || hc.(*ssh.Certificate).KeyId != "pc-host:web-1" {
		t.Errorf("host certificate %+v", hc)
	}

	// S4d–S4f: the CA keys and checks without sudo.
	ca, err := cfg.sshCA(ctx)
	must(err, "ssh CA")
	if len(ca.Problems) != 0 || len(ca.UserCAs) != 1 || len(ca.HostCAs) != 1 || !strings.HasPrefix(ca.UserCAs[0], "ssh-ed25519 ") {
		t.Errorf("CA view %+v", ca)
	}
	must(cfg.deleteSSHRole(ctx, "live"), "delete live role")
}
