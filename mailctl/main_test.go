package main

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/portcullis/mailctl/internal/config"
	"github.com/portcullis/mailctl/internal/stalwart"
)

func startCfg(t *testing.T, key, hub string) config.Config {
	t.Helper()
	d := t.TempDir()
	kf, hf := filepath.Join(d, "api-key"), filepath.Join(d, "hub-secret")
	os.WriteFile(kf, []byte(key), 0o600)
	os.WriteFile(hf, []byte(hub), 0o600)
	return config.Config{APIKeyFile: kf, HubSecretFile: hf, APISubnet: netip.MustParsePrefix("172.31.255.16/28")}
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

const hub = "0123456789abcdef0123456789abcdef0123"

func TestStartRefusesEmptyAPIKey(t *testing.T) {
	for _, key := range []string{"", " \n"} {
		err := checkStart(startCfg(t, key, hub), addrs("172.31.255.19/28"))
		if err == nil || !strings.Contains(err.Error(), "API key") {
			t.Errorf("key %q: %v", key, err)
		}
	}
	c := startCfg(t, "API_x", hub)
	os.Remove(c.APIKeyFile)
	if err := checkStart(c, addrs("172.31.255.19/28")); err == nil {
		t.Error("missing key file accepted")
	}
}

func TestStartRefusesHubSecret(t *testing.T) {
	for _, s := range []string{"", "short"} {
		if err := checkStart(startCfg(t, "API_x", s), addrs("172.31.255.19/28")); err == nil || !strings.Contains(err.Error(), "Hub secret") {
			t.Errorf("secret %q: %v", s, err)
		}
	}
}

func TestStartRefusesAddressOutsideSubnet(t *testing.T) {
	c := startCfg(t, "API_x", hub)
	if err := checkStart(c, addrs("127.0.0.1/8", "172.31.255.3/28", "172.31.250.4/24")); err == nil || !strings.Contains(err.Error(), "MAILCTL_API_SUBNET") {
		t.Fatalf("outside: %v", err)
	}
	if err := checkStart(c, addrs("127.0.0.1/8", "172.31.255.19/28")); err != nil {
		t.Fatalf("inside: %v", err)
	}
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
	if rc := run([]string{"serve"}, env, &out, &errb); rc != 1 || !strings.Contains(errb.String(), "MAILCTL_API_SUBNET is required") {
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
