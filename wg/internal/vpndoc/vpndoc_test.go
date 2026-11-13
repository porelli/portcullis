package vpndoc

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// vector is one case of the shared vpn.json reader vectors (a byte copy
// of the Hub's internal/vpn/testdata/vpn_json_vectors.json; CI compares
// them). want is "ok" or a substring of the error the reference reader
// gives; this reader only has to refuse, so a refusal is all it checks.
type vector struct {
	Name  string          `json:"name"`
	Doc   json.RawMessage `json:"doc"`
	Raw   string          `json:"raw"`
	Now   time.Time       `json:"now"`
	Want  string          `json:"want"`
	Peers []string        `json:"peers"`
	Allow []struct {
		IP, Provider, User string
	} `json:"allow"`
	Deny []struct {
		IP, Provider string
	} `json:"deny"`
}

func TestVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vpn_json_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	if len(vs) < 8 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			raw := []byte(v.Doc)
			if v.Raw != "" {
				raw = []byte(v.Raw)
			}
			d, err := Parse(raw)
			if v.Want != "ok" {
				if err == nil {
					t.Fatalf("parsed; want a refusal (%s)", v.Want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			for _, a := range v.Allow {
				dev := d.Device(a.Provider, netip.MustParseAddr(a.IP), v.Now)
				if dev == nil || dev.User != a.User {
					t.Errorf("%s via %s: got %+v, want user %s", a.IP, a.Provider, dev, a.User)
				}
			}
			for _, x := range v.Deny {
				if dev := d.Device(x.Provider, netip.MustParseAddr(x.IP), v.Now); dev != nil {
					t.Errorf("%s via %s: allowed (%+v), want deny", x.IP, x.Provider, dev)
				}
			}
			if v.Peers != nil {
				var got []string
				for _, p := range d.BuiltinPeers(v.Now) {
					got = append(got, p.IP.String())
				}
				if strings.Join(got, ",") != strings.Join(v.Peers, ",") {
					t.Errorf("peers %v, want %v", got, v.Peers)
				}
			}
		})
	}
}

const docOK = `{"version":2,
 "builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":["example.org"],
  "peers":[{"ip":"10.213.0.5","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d1","expires":null}]},
 "providers":[{"id":"builtin","ranges":["10.213.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false},
  {"id":"hs","label":"t","ranges":["100.64.0.0/10"],"edge_port":9001,"gateway_ip":"172.31.254.16",
   "refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],
 "devices":[{"ip":"100.64.0.7","provider":"hs","user":"alice","device_id":"hs:1","name":"a","expires":null}]}`

func TestProviderOf(t *testing.T) {
	d, err := Parse([]byte(docOK))
	if err != nil {
		t.Fatal(err)
	}
	if p := d.ProviderOf(netip.MustParseAddr("100.64.3.3")); p == nil || p.ID != "hs" {
		t.Fatalf("ProviderOf tailnet = %+v", p)
	}
	if p := d.ProviderOf(netip.MustParseAddr("10.213.1.1")); p == nil || p.ID != "builtin" {
		t.Fatalf("ProviderOf builtin = %+v", p)
	}
	if p := d.ProviderOf(netip.MustParseAddr("203.0.113.9")); p != nil {
		t.Fatalf("ProviderOf internet = %+v", p)
	}
	if p := d.ProviderByID("hs"); p == nil || p.EdgePort != 9001 || p.Gateway() != netip.MustParseAddr("172.31.254.16") {
		t.Fatalf("ProviderByID = %+v", p)
	}
	now := time.Date(2026, 11, 13, 10, 1, 0, 0, time.UTC)
	if !d.ProviderByID("hs").Fresh(now) || d.ProviderByID("hs").Fresh(now.Add(3*time.Minute)) {
		t.Fatal("Fresh by clock")
	}
}

func TestParseRefusals(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":            ``,
		"null":             `null`,
		"trailing":         `{"version":2,"providers":[],"devices":[]} {}`,
		"ipv6 range":       `{"version":2,"providers":[{"id":"a","ranges":["fd00::/64"],"edge_port":9001,"gateway_ip":"172.31.254.16","stale":false}],"devices":[]}`,
		"unmasked range":   `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.1/10"],"edge_port":9001,"gateway_ip":"172.31.254.16","stale":false}],"devices":[]}`,
		"dup provider":     `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.16","stale":false},{"id":"a","ranges":["100.65.0.0/16"],"edge_port":9002,"gateway_ip":"172.31.254.17","stale":false}],"devices":[]}`,
		"dup edge port":    `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.16","stale":false},{"id":"b","ranges":["100.65.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.17","stale":false}],"devices":[]}`,
		"bad edge port":    `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":80,"gateway_ip":"172.31.254.16","stale":false}],"devices":[]}`,
		"no gateway":       `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"","stale":false}],"devices":[]}`,
		"unknown provider": `{"version":2,"providers":[],"devices":[{"ip":"100.64.0.7","provider":"x","user":"a","device_id":"1","name":"a","expires":null}]}`,
		"no user":          `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.16","stale":false}],"devices":[{"ip":"100.64.0.7","provider":"a","user":"","device_id":"1","name":"a","expires":null}]}`,
		"bad peer key":     `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":[],"peers":[{"ip":"10.213.0.5","public_key":"short","device_id":"d","expires":null}]},"providers":[],"devices":[]}`,
		"peer outside":     `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":[],"peers":[{"ip":"10.9.0.5","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d","expires":null}]},"providers":[],"devices":[]}`,
		"peer is server":   `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":[],"peers":[{"ip":"10.213.0.1","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d","expires":null}]},"providers":[],"devices":[]}`,
		"dup peer key":     `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":[],"peers":[{"ip":"10.213.0.5","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d","expires":null},{"ip":"10.213.0.6","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"e","expires":null}]},"providers":[],"devices":[]}`,
		"case key":         `{"Version":2,"providers":[],"devices":[]}`,
		"builtin range":    `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":[],"peers":[]},"providers":[{"id":"builtin","ranges":["10.99.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false}],"devices":[]}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: parsed, want refusal", name)
		}
	}
}

func TestWatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.json")
	w := &Watcher{Path: path, Every: 20 * time.Millisecond}
	var mu sync.Mutex
	var calls []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, func(d *Doc, err error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err != nil:
			calls = append(calls, "err")
		case d != nil:
			calls = append(calls, "doc")
		}
	})
	wait := func(want string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(calls)
			last := ""
			if n > 0 {
				last = calls[n-1]
			}
			mu.Unlock()
			if last == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no %q call (calls %v)", want, calls)
	}
	wait("err") // missing file
	if err := os.WriteFile(path, []byte(docOK), 0o640); err != nil {
		t.Fatal(err)
	}
	wait("doc")
	if err := os.WriteFile(path, []byte(`{"version":3}`), 0o640); err != nil {
		t.Fatal(err)
	}
	wait("err")
}
