package main

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/config"
	"github.com/portcullis/mailctl/internal/gate"
	"github.com/portcullis/mailctl/internal/stalwart"
)

// startCfg is a wired adapter's slot: the gate open, the secrets and the
// API key in place.
func startCfg(t *testing.T) config.Config {
	t.Helper()
	slot, data := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(slot, ".present"), []byte(gate.Sentinel+"\n"), 0o640)
	os.WriteFile(filepath.Join(slot, "api-secret"), []byte(hub), 0o640)
	os.WriteFile(filepath.Join(slot, "metrics-secret"), []byte("m3tr1cs-0123456789abcdef0123456789abcdef"), 0o640)
	os.WriteFile(filepath.Join(data, "api-key"), []byte("API_x"), 0o600)
	return config.Config{SlotDir: slot, DataDir: data, APIKeyFile: filepath.Join(data, "api-key"), APISubnet: netip.MustParsePrefix("172.31.255.16/28")}
}

func addrs(ips ...string) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		var out []net.Addr
		for _, s := range ips {
			_, n, _ := net.ParseCIDR(s)
			ip, _, _ := net.ParseCIDR(s)
			out = append(out, &net.IPNet{IP: ip, Mask: n.Mask})
		}
		return out, nil
	}
}

const (
	hub    = "0123456789abcdef0123456789abcdef0123456789abcdef"
	inside = "172.31.255.19/28"
)

func TestStartRefusedWithoutPresent(t *testing.T) {
	c := startCfg(t)
	if err := checkStart(c, addrs(inside)); err != nil {
		t.Fatalf("wired: %v", err)
	}
	os.Remove(filepath.Join(c.SlotDir, ".present"))
	if err := checkStart(c, addrs(inside)); err == nil || !strings.Contains(err.Error(), "mail gate") {
		t.Fatalf("no .present: %v", err)
	}
	os.WriteFile(filepath.Join(c.SlotDir, ".present"), []byte("open"), 0o640)
	if err := checkStart(c, addrs(inside)); err == nil {
		t.Fatal("wrong .present accepted")
	}
	// A void owed: .present doesn't count.
	os.WriteFile(filepath.Join(c.SlotDir, ".present"), []byte(gate.Sentinel), 0o640)
	os.WriteFile(filepath.Join(c.SlotDir, "void-pending"), nil, 0o640)
	if err := checkStart(c, addrs(inside)); err == nil {
		t.Fatal("void-pending with .present accepted")
	}
}

func TestStartVoidSessionNonce(t *testing.T) {
	c := startCfg(t)
	os.Remove(filepath.Join(c.SlotDir, ".present"))
	os.WriteFile(filepath.Join(c.SlotDir, "void-pending"), nil, 0o640)
	os.WriteFile(filepath.Join(c.SlotDir, "void-session"), []byte("9f86d081884c7d65"), 0o640)
	for _, s := range []string{"", "9f86d081884c7d6", "9f86d081884c7d65 "} {
		c.VoidSession = s
		if err := checkStart(c, addrs(inside)); err == nil {
			t.Errorf("session %q accepted", s)
		}
	}
	c.VoidSession = "9f86d081884c7d65"
	if err := checkStart(c, addrs(inside)); err != nil {
		t.Fatalf("void mode: %v", err)
	}
}

func TestStartRefusesSecrets(t *testing.T) {
	for _, f := range []string{"api-secret", "metrics-secret"} {
		for _, v := range []string{"", "short"} {
			c := startCfg(t)
			os.WriteFile(filepath.Join(c.SlotDir, f), []byte(v), 0o640)
			if err := checkStart(c, addrs(inside)); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ReplaceAll(f, "-", " ")) {
				t.Errorf("%s %q: %v", f, v, err)
			}
		}
		c := startCfg(t)
		os.Remove(filepath.Join(c.SlotDir, f))
		if err := checkStart(c, addrs(inside)); err == nil {
			t.Errorf("%s missing: accepted", f)
		}
	}
	c := startCfg(t)
	os.WriteFile(c.APIKeyFile, []byte(" \n"), 0o600)
	if err := checkStart(c, addrs(inside)); err == nil || !strings.Contains(err.Error(), "API key") {
		t.Errorf("empty API key: %v", err)
	}
}

func TestStartRefusedOutsideSubnet(t *testing.T) {
	c := startCfg(t)
	if err := checkStart(c, addrs("127.0.0.1/8", "172.31.255.3/28", "172.31.250.4/24")); err == nil || !strings.Contains(err.Error(), "PORTCULLIS_MAIL_API_SUBNET") {
		t.Fatalf("outside: %v", err)
	}
	if err := checkStart(c, addrs("127.0.0.1/8", inside)); err != nil {
		t.Fatalf("inside: %v", err)
	}
	// An unparsable subnet never gets this far: serve refuses at Load.
	var out, errb bytes.Buffer
	env := map[string]string{"PORTCULLIS_MAIL_API_SUBNET": "172.31.255.16", "MAILCTL_LOCAL_RESOLVER": "172.31.255.4:5353"}
	if rc := run([]string{"serve"}, func(k string) string { return env[k] }, &out, &errb); rc != 1 ||
		!strings.Contains(errb.String(), "PORTCULLIS_MAIL_API_SUBNET") || strings.Count(strings.TrimSpace(errb.String()), "\n") != 0 {
		t.Fatalf("bad subnet: %d %q", rc, errb.String())
	}
}

// The control socket is gone: the CLI talks to the Hub, the Hub to the
// provider API. No source of the adapter listens on a unix socket.
func TestNoControlSocket(t *testing.T) {
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, bad := range []string{`"unix"`, "mailctl.sock", "internal/admin"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s: %s", p, bad)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("internal/admin"); !os.IsNotExist(err) {
		t.Error("internal/admin exists")
	}
}

// Stalwart reads the relay's password (and the metrics password) from the
// Hub's slot files, which the override mounts at the contract's path.
func TestRelayPasswordFromSlot(t *testing.T) {
	c, err := config.Load(func(k string) string {
		return map[string]string{"PORTCULLIS_MAIL_API_SUBNET": "172.31.255.16/28", "MAILCTL_LOCAL_RESOLVER": "172.31.255.4:5353"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.RelaySecret != c.RelayPasswordFile() || bootstrap.MetricsSecret != c.MetricsSecretFile() {
		t.Fatalf("%s %s vs %s %s", bootstrap.RelaySecret, bootstrap.MetricsSecret, c.RelayPasswordFile(), c.MetricsSecretFile())
	}
	p := bootstrap.Params{Relay: &bootstrap.Relay{Host: "smtp.relay.example", Port: 465, Username: "u"}}
	for _, n := range p.Collections() {
		if n.Object != "MtaRoute" {
			continue
		}
		for _, w := range n.Want {
			if w["name"] == "relay" {
				if fp, _ := w["authSecret"].(map[string]any)["filePath"].(string); fp != "/run/portcullis/mail/slot/relay-password" {
					t.Fatalf("relay secret %v", w["authSecret"])
				}
				return
			}
		}
	}
	t.Fatal("no relay route")
}

func TestSubcommands(t *testing.T) {
	var out, errb bytes.Buffer
	env := func(string) string { return "" }
	if rc := run([]string{"nope"}, env, &out, &errb); rc != 2 {
		t.Errorf("unknown: %d", rc)
	}
	if rc := run([]string{"--help"}, env, &out, &errb); rc != 0 || !strings.Contains(out.String(), "usage") {
		t.Errorf("help: %d", rc)
	}
	if rc := run([]string{"serve"}, env, &out, &errb); rc != 1 || !strings.Contains(errb.String(), "PORTCULLIS_MAIL_API_SUBNET is required") {
		t.Errorf("serve without config: %d %s", rc, errb.String())
	}
}

// M13 over every package mailctl links: each object, field, variant and
// enum value sent is in the v1.1.0 schema snapshot.
func TestEveryUsedFieldInSchema(t *testing.T) {
	raw, err := os.ReadFile("internal/stalwart/testdata/schema-v1.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := stalwart.ParseSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bad := s.Check(stalwart.Used); len(bad) > 0 {
		t.Fatalf("not in the schema:\n%s", strings.Join(bad, "\n"))
	}
}
