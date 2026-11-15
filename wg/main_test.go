package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/portcullis/wg/internal/status"
	"github.com/portcullis/wg/internal/tunnel"
	"github.com/portcullis/wg/internal/vpndoc"
)

func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli(args, strings.NewReader(stdin), &out, &errb, func(string) string { return "" })
	return code, out.String(), errb.String()
}

func TestMainUsage(t *testing.T) {
	for _, a := range [][]string{{"--help"}, {"-h"}, {"help"}} {
		if code, out, _ := runCLI(t, "", a...); code != 0 || !strings.Contains(out, "genkey") {
			t.Fatalf("%v: %d %q", a, code, out)
		}
	}
	for _, a := range [][]string{{}, {"bogus"}, {"genkey"}, {"genkey", "a", "b"}, {"keypair", "x"}, {"run", "x"}, {"qr", "x"}} {
		if code, _, _ := runCLI(t, "", a...); code != 2 {
			t.Fatalf("%v: exit %d, want 2", a, code)
		}
	}

	code, out, _ := runCLI(t, "", "keypair")
	if code != 0 {
		t.Fatalf("keypair exit %d", code)
	}
	var kp struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kp); err != nil {
		t.Fatalf("keypair output: %v", err)
	}
	priv, err := vpndoc.ParseKey(kp.PrivateKey)
	if err != nil || tunnel.KeyString(tunnel.PublicKeyOf(priv)) != kp.PublicKey {
		t.Fatal("keypair: public key doesn't match")
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "people.key")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ino := inode(t, p)
	code, out, errOut := runCLI(t, "", "genkey", p)
	if code != 0 || out != "" {
		t.Fatalf("genkey: exit %d, stdout %q", code, out)
	}
	b, _ := os.ReadFile(p)
	k, err := vpndoc.ParseKey(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("genkey wrote no key: %v", err)
	}
	if strings.Contains(errOut, strings.TrimSpace(string(b))) {
		t.Fatal("genkey printed the key")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("genkey mode %v", fi.Mode().Perm())
	}
	if inode(t, p) != ino {
		t.Fatal("genkey replaced the file (a single-file bind would keep the old inode)")
	}
	_ = k

	code, out, _ = runCLI(t, "[Interface]\nPrivateKey = x\n", "qr")
	if code != 0 || !strings.Contains(out, "█") {
		t.Fatalf("qr: %d %q", code, out)
	}
	if code, _, _ := runCLI(t, strings.Repeat("x", 5000), "qr"); code != 2 {
		t.Fatalf("qr of 5000 bytes: exit %d", code)
	}
}

func TestHealthcheckAndStatus(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "status.json")
	env := func(k string) string {
		if k == "WG_STATUS_FILE" {
			return p
		}
		return ""
	}
	run := func(args ...string) (int, string) {
		var out, e bytes.Buffer
		c := cli(args, strings.NewReader(""), &out, &e, env)
		return c, out.String()
	}
	if c, _ := run("healthcheck"); c != 1 {
		t.Fatalf("healthcheck without a file: %d", c)
	}
	if err := status.Write(p, status.Doc{Mode: "apps", Edge: status.Role{OK: true}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if c, _ := run("healthcheck"); c != 0 {
		t.Fatalf("healthcheck fresh: %d", c)
	}
	if c, out := run("status"); c != 0 || !strings.Contains(out, `"version":1`) {
		t.Fatalf("status: %d %q", c, out)
	}
	if err := status.Write(p, status.Doc{Mode: "apps", Edge: status.Role{OK: true}}, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if c, _ := run("healthcheck"); c != 1 {
		t.Fatalf("healthcheck stale: %d", c)
	}
}

func TestLoadConfig(t *testing.T) {
	base := map[string]string{
		"WG_VPN_ADDR": "172.31.254.3", "WG_EDGE_ADDR": "172.31.254.67", "WG_TRAEFIK": "172.31.254.66:8443", "WG_DOMAIN": "example.org",
	}
	get := func(over map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return base[k]
		}
	}
	c, err := loadConfig(get(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.People || c.Port != 51820 || c.Subnet != netip.MustParsePrefix("10.213.0.0/22") || c.Mode != "apps" ||
		c.VPNFile != "/vpn-doc/vpn.json" || c.EdgeAddr != netip.MustParseAddr("172.31.254.67") || c.StatusFile != "/data/status.json" || c.PeopleKey != "/run/portcullis/wg/people.key" ||
		len(c.Upstreams) != 2 || c.Metrics != "wg-metrics:9100" ||
		c.MaxPerProvider != 1024 || c.MaxPerUser != 128 || c.MaxPerClient != 32 || c.PressurePercent != 90 || c.PressureIdle != 2*time.Minute {
		t.Fatalf("defaults %+v", c)
	}
	c, err = loadConfig(get(map[string]string{"WG_EDGE_MAX_PER_PROVIDER": "2048", "WG_EDGE_MAX_PER_USER": "64",
		"WG_EDGE_MAX_PER_CLIENT": "16", "WG_EDGE_PRESSURE_PERCENT": "80", "WG_EDGE_PRESSURE_IDLE": "5m"}))
	if err != nil || c.MaxPerProvider != 2048 || c.MaxPerUser != 64 || c.MaxPerClient != 16 || c.PressurePercent != 80 || c.PressureIdle != 5*time.Minute {
		t.Fatalf("caps from env: %+v %v", c, err)
	}
	for name, over := range map[string]map[string]string{
		"people bogus":    {"WG_PEOPLE": "yes"},
		"port":            {"WG_PORT": "0"},
		"port text":       {"WG_PORT": "x"},
		"subnet v6":       {"WG_SUBNET": "fd00::/64"},
		"subnet unmasked": {"WG_SUBNET": "10.213.0.1/22"},
		"subnet /31":      {"WG_SUBNET": "10.213.0.0/31"},
		"vpn addr":        {"WG_VPN_ADDR": ""},
		"edge addr":       {"WG_EDGE_ADDR": ""},
		"edge = vpn addr": {"WG_EDGE_ADDR": "172.31.254.3"},
		"traefik":         {"WG_TRAEFIK": "traefik:8443"},
		"mode":            {"WG_MODE": "everything"},
		"upstream":        {"WG_DNS_UPSTREAM": "dns.google"},
		"domain":          {"WG_PEOPLE": "on", "WG_DOMAIN": ""},
		"metrics":         {"WG_METRICS": "9100"},
		"core subnets":    {"WG_CORE_SUBNETS": "172.31.250.0/24 nonsense"},
		"provider cap 0":  {"WG_EDGE_MAX_PER_PROVIDER": "0"},
		"user cap text":   {"WG_EDGE_MAX_PER_USER": "lots"},
		"client > user":   {"WG_EDGE_MAX_PER_CLIENT": "200"},
		"user > provider": {"WG_EDGE_MAX_PER_USER": "2000"},
		"percent 0":       {"WG_EDGE_PRESSURE_PERCENT": "0"},
		"percent 101":     {"WG_EDGE_PRESSURE_PERCENT": "101"},
		"idle text":       {"WG_EDGE_PRESSURE_IDLE": "soon"},
		"idle under 1 s":  {"WG_EDGE_PRESSURE_IDLE": "500ms"},
	} {
		if _, err := loadConfig(get(over)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c, err = loadConfig(get(map[string]string{"WG_PEOPLE": "on", "WG_MODE": "server", "WG_METRICS": "off"}))
	if err != nil || !c.People || c.Mode != "server" || c.Metrics != "" {
		t.Fatalf("%+v %v", c, err)
	}
	if c, err := loadConfig(get(map[string]string{"WG_ADDR_MODE": "docker"})); err != nil || c.AddrMode != "docker" {
		t.Fatalf("WG_ADDR_MODE=docker: %+v %v", c, err)
	}
}

// TestLoadConfigPodMode (K7): on Kubernetes every role shares the pod's one
// address (isolation is the NetworkPolicies'): WG_ADDR_MODE=pod accepts
// WG_VPN_ADDR = WG_EDGE_ADDR, requires them equal, and any other mode but
// docker refuses the start; docker keeps every separate-address check.
func TestLoadConfigPodMode(t *testing.T) {
	pod := map[string]string{
		"WG_ADDR_MODE": "pod", "WG_VPN_ADDR": "10.42.0.17", "WG_EDGE_ADDR": "10.42.0.17",
		"WG_TRAEFIK": "10.43.0.21:8444", "WG_DOMAIN": "example.org", "WG_METRICS": "10.42.0.17:9100",
	}
	get := func(over map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return pod[k]
		}
	}
	c, err := loadConfig(get(nil))
	if err != nil || c.AddrMode != "pod" || c.VPNAddr != c.EdgeAddr || c.VPNAddr != netip.MustParseAddr("10.42.0.17") || c.Metrics != "10.42.0.17:9100" {
		t.Fatalf("pod mode: %+v %v", c, err)
	}
	for name, over := range map[string]map[string]string{
		"pod: addresses differ": {"WG_EDGE_ADDR": "10.42.0.18"},
		"pod: no address":       {"WG_VPN_ADDR": "", "WG_EDGE_ADDR": ""},
		"pod: v6 address":       {"WG_VPN_ADDR": "fd00::1", "WG_EDGE_ADDR": "fd00::1"},
		"unknown mode":          {"WG_ADDR_MODE": "host"},
		"empty-ish mode":        {"WG_ADDR_MODE": "Pod"},
		"docker: one address":   {"WG_ADDR_MODE": "docker"},
	} {
		if _, err := loadConfig(get(over)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Metrics on the pod address: allowed in pod mode only.
	ip := netip.MustParseAddr("10.42.0.17")
	local := []netip.Addr{netip.MustParseAddr("127.0.0.1"), ip}
	look := func(string) ([]netip.Addr, error) { return []netip.Addr{ip}, nil }
	if a, err := metricsAddr("10.42.0.17:9100", look, local, metricsNever(c)...); err != nil || a.String() != "10.42.0.17:9100" {
		t.Fatalf("pod metrics: %v %v", a, err)
	}
	d := &config{AddrMode: "docker", VPNAddr: ip, EdgeAddr: netip.MustParseAddr("10.42.0.18")}
	if _, err := metricsAddr("10.42.0.17:9100", look, local, metricsNever(d)...); err == nil {
		t.Fatal("docker mode: metrics on the VPN address accepted")
	}
}

// TestMetricsAddr (V23): metrics bind to the address the portcullis-only
// alias resolves to, which must be one of the container's own addresses
// and never the portcullis-vpn one.
func TestMetricsAddr(t *testing.T) {
	vpn := netip.MustParseAddr("172.31.254.3")
	edgeA := netip.MustParseAddr("172.31.254.67")
	local := []netip.Addr{netip.MustParseAddr("127.0.0.1"), vpn, edgeA, netip.MustParseAddr("172.18.0.5"), netip.MustParseAddr("172.19.0.7")}
	look := func(ips ...string) func(string) ([]netip.Addr, error) {
		return func(string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, s := range ips {
				out = append(out, netip.MustParseAddr(s))
			}
			return out, nil
		}
	}
	got, err := metricsAddr("wg-metrics:9100", look("172.18.0.5"), local, vpn, edgeA)
	if err != nil || got != netip.MustParseAddrPort("172.18.0.5:9100") {
		t.Fatalf("%v %v", got, err)
	}
	for name, l := range map[string]func(string) ([]netip.Addr, error){
		"vpn address":  look("172.31.254.3"),
		"edge address": look("172.31.254.67"),
		"not local":    look("10.1.1.1"),
		"two answers":  look("172.18.0.5", "172.19.0.7"),
		"no answer":    look(),
		"ipv6 answer":  look("fd00::5"),
		"loopback too": look("127.0.0.1"),
	} {
		if _, err := metricsAddr("wg-metrics:9100", l, local, vpn, edgeA); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func inode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func TestLoadConfigLink(t *testing.T) {
	base := map[string]string{
		"WG_VPN_ADDR": "172.31.254.3", "WG_EDGE_ADDR": "172.31.254.67", "WG_TRAEFIK": "172.31.254.66:8443",
		"WG_LINK": "on", "WG_LINK_CONTROL_ADDR": "172.31.254.83:3128", "WG_LINK_DATA_ADDR": "172.31.254.130:3129",
	}
	get := func(over map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return base[k]
		}
	}
	c, err := loadConfig(get(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Link || c.LinkPort != 51821 || c.LinkKey != "/run/portcullis/wg/link.key" || c.LinkFile != "/link-doc/link.json" ||
		c.LinkControl != netip.MustParseAddrPort("172.31.254.83:3128") || c.LinkData != netip.MustParseAddrPort("172.31.254.130:3129") ||
		c.LinkTLSKey != defaultLinkTLSKey || c.LinkTLSCert != defaultLinkTLSCert || c.LinkCAFile != defaultLinkCA {
		t.Fatalf("link defaults %+v", c)
	}
	if c, err := loadConfig(get(map[string]string{"WG_LINK": ""})); err != nil || c.Link {
		t.Fatalf("link off by default: %+v %v", c, err)
	}
	for name, over := range map[string]map[string]string{
		"link bogus":            {"WG_LINK": "yes"},
		"port":                  {"WG_LINK_PORT": "0"},
		"port = people port":    {"WG_PEOPLE": "on", "WG_DOMAIN": "example.org", "WG_LINK_PORT": "51820"},
		"no control addr":       {"WG_LINK_CONTROL_ADDR": ""},
		"no data addr":          {"WG_LINK_DATA_ADDR": ""},
		"control hostname":      {"WG_LINK_CONTROL_ADDR": "wg:3128"},
		"control loopback":      {"WG_LINK_CONTROL_ADDR": "127.0.0.1:3128"},
		"control any":           {"WG_LINK_CONTROL_ADDR": "0.0.0.0:3128"},
		"data v6":               {"WG_LINK_DATA_ADDR": "[fd00::1]:3129"},
		"control = data":        {"WG_LINK_DATA_ADDR": "172.31.254.83:3129"},
		"control on vpn net":    {"WG_LINK_CONTROL_ADDR": "172.31.254.3:3128"},
		"data on edge net":      {"WG_LINK_DATA_ADDR": "172.31.254.67:3129"},
		"pod mode (Kubernetes)": {"WG_ADDR_MODE": "pod", "WG_EDGE_ADDR": "172.31.254.3", "WG_METRICS": "off"},
	} {
		if _, err := loadConfig(get(over)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenkeyTLSAndLinkCSR(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "link-tls.key")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ino := inode(t, p)
	code, out, errOut := runCLI(t, "", "genkey-tls", p)
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("genkey-tls: %d %q %q", code, out, errOut)
	}
	if inode(t, p) != ino {
		t.Fatal("genkey-tls replaced the file")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if code, _, _ := runCLI(t, "", "genkey-tls"); code != 2 {
		t.Fatal("genkey-tls without a path")
	}
	var o, e bytes.Buffer
	code = cli([]string{"link-csr"}, strings.NewReader(""), &o, &e, func(k string) string {
		if k == "WG_LINK_TLS_KEY" {
			return p
		}
		return ""
	})
	if code != 0 {
		t.Fatalf("link-csr: %d %s", code, e.String())
	}
	key, _ := os.ReadFile(p)
	if strings.Contains(o.String(), "PRIVATE KEY") || bytes.Contains(o.Bytes(), bytes.TrimSpace(key)) {
		t.Fatal("link-csr printed the key")
	}
	blk, _ := pem.Decode(o.Bytes())
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("no CSR: %q", o.String())
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "link.control" || len(csr.DNSNames)+len(csr.IPAddresses) != 0 {
		t.Fatalf("csr %+v %v", csr, err)
	}
	if pk, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || pk.Curve != elliptic.P256() {
		t.Fatal("not a P-256 key")
	}
	// A WireGuard key (or nothing) is refused.
	os.WriteFile(p, []byte("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"), 0o640)
	if code := cli([]string{"link-csr"}, strings.NewReader(""), &o, &e, func(k string) string {
		if k == "WG_LINK_TLS_KEY" {
			return p
		}
		return ""
	}); code != 1 {
		t.Fatalf("link-csr of a non-TLS key: %d", code)
	}
}

// TestLinkRoleStatus: the status block follows the key and the document;
// absent while the role is off.
func TestLinkRoleStatus(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "link.key")
	os.WriteFile(keyPath, nil, 0o640)
	docPath := filepath.Join(dir, "link.json")
	cfg := &config{Link: true, LinkKey: keyPath, LinkFile: docPath, LinkPort: udpPort(t),
		LinkControl: netip.MustParseAddrPort("127.0.0.1:0"), LinkData: netip.MustParseAddrPort("127.0.0.1:0")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if r := startLink(ctx, cfg, prometheus.NewRegistry()); r.status().OK || !strings.Contains(r.status().Error, "link init") {
		t.Fatalf("no key: %+v", r.status())
	}
	if r := startLink(ctx, &config{}, prometheus.NewRegistry()); r != nil {
		t.Fatal("role started while off")
	}
	k, _ := tunnel.GenerateKey()
	os.WriteFile(keyPath, []byte(tunnel.KeyString(k)+"\n"), 0o640)
	r := startLink(ctx, cfg, prometheus.NewRegistry())
	wait := func(cond func(*status.Link) bool) *status.Link {
		for i := 0; i < 100; i++ {
			if st := r.status(); cond(st) {
				return st
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("status never matched: %+v", r.status())
		return nil
	}
	wait(func(s *status.Link) bool { return !s.OK && strings.Contains(s.Error, "missing") })
	peer, _ := tunnel.GenerateKey()
	doc := `{"version":1,"written_at":"2026-11-15T10:00:00Z","subnet":"10.214.0.0/24","peers":[{"id":"w1","public_key":"` +
		tunnel.KeyString(tunnel.PublicKeyOf(peer)) + `","ip":"10.214.0.10","state":"enrolling"}],"relays":[]}`
	os.WriteFile(docPath, []byte(doc), 0o640)
	st := wait(func(s *status.Link) bool { return s.OK && len(s.Peers) == 1 })
	if st.Peers[0].ID != "w1" || st.Peers[0].IP != "10.214.0.10" || st.Peers[0].Handshake != nil {
		t.Fatalf("peers %+v", st.Peers)
	}
	os.WriteFile(docPath, []byte(`{"version":1}`), 0o640)
	wait(func(s *status.Link) bool { return !s.OK && len(s.Peers) == 0 })

	// status.json: "link" omitted when the role is off (temporary: until Hub
	// knows about the field; contract §17.2 wants null, not omitted).
	p := filepath.Join(dir, "status.json")
	status.Write(p, status.Doc{Mode: "apps"}, time.Now())
	if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(`"link"`)) {
		t.Fatalf("link key while off: %s", b)
	}
	status.Write(p, status.Doc{Mode: "apps", Link: &status.Link{}}, time.Now())
	if b, _ := os.ReadFile(p); !bytes.Contains(b, []byte(`"link":{"ok":false,"error":"","public_key":"","port":0,"peers":[]}`)) {
		t.Fatalf("link block: %s", b)
	}
}
