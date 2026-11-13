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
			var asString string
			if json.Unmarshal(v.Doc, &asString) == nil {
				raw = []byte(asString) // a vector whose document isn't JSON
			}
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
 "builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":["example.org"],
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
		"ipv6 range":       `{"version":2,"providers":[{"id":"a","ranges":["fd00::/64"],"edge_port":9001,"gateway_ip":"172.31.254.16","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],"devices":[]}`,
		"unmasked range":   `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.1/10"],"edge_port":9001,"gateway_ip":"172.31.254.16","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],"devices":[]}`,
		"dup provider":     `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.16","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false},{"id":"a","ranges":["100.65.0.0/16"],"edge_port":9002,"gateway_ip":"172.31.254.17","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],"devices":[]}`,
		"dup edge port":    `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.16","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false},{"id":"b","ranges":["100.65.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.17","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],"devices":[]}`,
		"bad edge port":    `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":80,"gateway_ip":"172.31.254.16","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],"devices":[]}`,
		"no gateway":       `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"","stale":false}],"devices":[]}`,
		"unknown provider": `{"version":2,"providers":[],"devices":[{"ip":"100.64.0.7","provider":"x","user":"a","device_id":"1","name":"a","expires":null}]}`,
		"no user":          `{"version":2,"providers":[{"id":"a","ranges":["100.64.0.0/16"],"edge_port":9001,"gateway_ip":"172.31.254.16","refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:03:00Z","stale":false}],"devices":[{"ip":"100.64.0.7","provider":"a","user":"","device_id":"1","name":"a","expires":null}]}`,
		"bad peer key":     `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":[],"peers":[{"ip":"10.213.0.5","public_key":"short","device_id":"d","expires":null}]},"providers":[],"devices":[]}`,
		"peer outside":     `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":[],"peers":[{"ip":"10.9.0.5","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d","expires":null}]},"providers":[],"devices":[]}`,
		"peer is server":   `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":[],"peers":[{"ip":"10.213.0.1","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d","expires":null}]},"providers":[],"devices":[]}`,
		"dup peer key":     `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":[],"peers":[{"ip":"10.213.0.5","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"d","expires":null},{"ip":"10.213.0.6","public_key":"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=","device_id":"e","expires":null}]},"providers":[],"devices":[]}`,
		"case key":         `{"Version":2,"providers":[],"devices":[]}`,
		"builtin range":    `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=","domains":[],"peers":[]},"providers":[{"id":"builtin","ranges":["10.99.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false}],"devices":[]}`,
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

// TestStaleAfterRules: a marketplace provider's map is only fresh before a
// stale_after the Hub must write, at most MaxStaleSpan after refreshed_at.
func TestStaleAfterRules(t *testing.T) {
	prov := func(extra string) string {
		return `{"version":2,"providers":[{"id":"hs","ranges":["100.64.0.0/10"],"edge_port":9001,"gateway_ip":"172.31.254.16",` +
			extra + `"stale":false}],"devices":[{"ip":"100.64.0.7","provider":"hs","user":"alice","device_id":"1","name":"a","expires":null}]}`
	}
	for name, extra := range map[string]string{
		"nil stale_after":            `"refreshed_at":"2026-11-13T10:00:00Z",`,
		"null stale_after":           `"refreshed_at":"2026-11-13T10:00:00Z","stale_after":null,`,
		"nil refreshed_at":           `"stale_after":"2026-11-13T10:03:00Z",`,
		"stale_after too far ahead":  `"refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:30:01Z",`,
		"stale_after a year ahead":   `"refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2027-11-13T10:00:00Z",`,
		"stale_after before refresh": `"refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T09:59:00Z",`,
	} {
		if _, err := Parse([]byte(prov(extra))); err == nil || !strings.Contains(err.Error(), "stale_after") && !strings.Contains(err.Error(), "refreshed_at") {
			t.Errorf("%s: err %v, want a stale_after refusal", name, err)
		}
	}
	d, err := Parse([]byte(prov(`"refreshed_at":"2026-11-13T10:00:00Z","stale_after":"2026-11-13T10:30:00Z",`)))
	if err != nil {
		t.Fatalf("30 min span refused: %v", err)
	}
	at := time.Date(2026, 11, 13, 10, 29, 59, 0, time.UTC)
	a := netip.MustParseAddr("100.64.0.7")
	if d.Device("hs", a, at) == nil {
		t.Fatal("fresh device denied")
	}
	if d.Device("hs", a, at.Add(time.Second)) != nil {
		t.Fatal("device allowed at stale_after")
	}
	// Belt and braces: a provider value with no stale_after is never fresh.
	p := &Provider{ID: "hs"}
	if p.Fresh(at) {
		t.Fatal("Fresh without stale_after")
	}
	if !(&Provider{ID: BuiltinID}).Fresh(at) || (&Provider{ID: BuiltinID, Stale: true}).Fresh(at) {
		t.Fatal("builtin freshness")
	}
}

// TestHubAlignedRules: the rules the Hub's reference reader (internal/vpn
// Parse / Lookup) has, which this reader must not be laxer than.
func TestHubAlignedRules(t *testing.T) {
	const key = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	const peerKey = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	bp := `{"id":"builtin","ranges":["10.213.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false}`
	for name, doc := range map[string]string{
		"empty server key": `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"","domains":[],"peers":[]},"providers":[` + bp + `],"devices":[]}`,
		"peer device_id":   `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"` + key + `","domains":[],"peers":[{"ip":"10.213.0.5","public_key":"` + peerKey + `","device_id":"","expires":null}]},"providers":[` + bp + `],"devices":[]}`,
		"device device_id": `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"` + key + `","domains":[],"peers":[]},"providers":[` + bp + `],"devices":[{"ip":"10.213.0.5","provider":"builtin","user":"a","device_id":"","name":"n","expires":null}]}`,
		"orphan builtin":   `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"` + key + `","domains":[],"peers":[]},"providers":[],"devices":[]}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// A built-in device needs its peer (same ip and device_id), unexpired.
	doc := `{"version":2,"builtin":{"subnet":"10.213.0.0/22","server_public_key":"` + key + `","domains":[],
	 "peers":[{"ip":"10.213.0.5","public_key":"` + peerKey + `","device_id":"d1","expires":"2026-11-13T12:00:00Z"}]},
	 "providers":[` + bp + `],
	 "devices":[{"ip":"10.213.0.5","provider":"builtin","user":"a","device_id":"d1","name":"n","expires":null},
	            {"ip":"10.213.0.6","provider":"builtin","user":"b","device_id":"d2","name":"n","expires":null}]}`
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC)
	if d.Device(BuiltinID, netip.MustParseAddr("10.213.0.5"), at) == nil {
		t.Fatal("device with its peer denied")
	}
	if d.Device(BuiltinID, netip.MustParseAddr("10.213.0.6"), at) != nil {
		t.Fatal("device without a peer allowed")
	}
	if d.Device(BuiltinID, netip.MustParseAddr("10.213.0.5"), at.Add(time.Hour)) != nil {
		t.Fatal("device allowed after its peer expired")
	}
}

// TestProviderFromIngress: the lookup is per provider (the ingress the
// connection came through): another provider's device address is denied
// even though it is a valid device of the file.
func TestProviderFromIngress(t *testing.T) {
	d, err := Parse([]byte(docOK))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 13, 10, 1, 0, 0, time.UTC)
	tail := netip.MustParseAddr("100.64.0.7")
	if d.Device("hs", tail, at) == nil {
		t.Fatal("own device denied")
	}
	for _, p := range []string{BuiltinID, "", "other"} {
		if d.Device(p, tail, at) != nil {
			t.Fatalf("hs's device allowed through %q", p)
		}
	}
}
