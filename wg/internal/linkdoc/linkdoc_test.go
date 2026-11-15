package linkdoc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vector is one case of the shared link.json reader vectors (a byte copy
// of the Hub's internal/linkdoc/testdata/link_json_vectors.json). error is
// a substring of the reference reader's error; this reader only has to
// refuse, so a refusal is all the vectors check (the reasons are pinned by
// TestReasons below).
type vector struct {
	Name  string          `json:"name"`
	Doc   json.RawMessage `json:"doc"`
	Valid bool            `json:"valid"`
	Error string          `json:"error"`
}

func TestLinkDocVectors(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "link_json_vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatalf("vectors: %v", err)
	}
	if len(vs) < 30 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			raw := []byte(v.Doc)
			var asString string
			if json.Unmarshal(v.Doc, &asString) == nil {
				raw = []byte(asString) // a vector whose document isn't a JSON value
			}
			d, err := Parse(raw)
			if !v.Valid {
				if err == nil {
					t.Fatalf("parsed; want a refusal (%s)", v.Error)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if d.Version != Version {
				t.Fatal("version not kept")
			}
		})
	}
}

func goodDoc() map[string]any {
	return map[string]any{
		"version": 1, "written_at": "2026-11-15T10:00:00Z", "subnet": "10.214.0.0/24",
		"peers": []any{
			map[string]any{"id": "w1", "public_key": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "ip": "10.214.0.10", "state": "ready"},
		},
		"relays": []any{},
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReasons(t *testing.T) {
	relays := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{"token_sha256": fmt.Sprintf("%064x", i), "instance": "gitea", "server": "w1"}
		}
		return out
	}
	cases := []struct {
		name string
		mod  func(d map[string]any)
		want string
	}{
		{"version", func(d map[string]any) { d["version"] = 2 }, "version 2"},
		{"subnet", func(d map[string]any) { d["subnet"] = "10.214.1.0/24" }, "subnet: must be 10.214.0.0/24"},
		{"ip", func(d map[string]any) { d["peers"].([]any)[0].(map[string]any)["ip"] = "10.214.0.2" }, "peers[0].ip"},
		{"state", func(d map[string]any) { d["peers"].([]any)[0].(map[string]any)["state"] = "offline" }, "peers[0].state"},
		{"id", func(d map[string]any) { d["peers"].([]any)[0].(map[string]any)["id"] = "primary" }, "peers[0].id"},
		{"unknown", func(d map[string]any) { d["x"] = 1 }, `unknown key "x"`},
		{"missing", func(d map[string]any) { delete(d, "relays") }, `missing key "relays"`},
		{"null", func(d map[string]any) { d["peers"] = nil }, "$.peers: null"},
		{"relay server", func(d map[string]any) {
			d["relays"] = []any{map[string]any{"token_sha256": strings.Repeat("a", 64), "instance": "x", "server": "nope"}}
		}, "relays[0].server"},
		{"relay cap", func(d map[string]any) { d["relays"] = relays(MaxRelays + 1) }, "relays: more than 4096"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := goodDoc()
			c.mod(d)
			_, err := Parse(mustJSON(t, d))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
	d := goodDoc()
	d["relays"] = relays(MaxRelays)
	if _, err := Parse(mustJSON(t, d)); err != nil {
		t.Fatalf("4096 relays refused: %v", err)
	}
	if _, err := Parse(make([]byte, MaxSize+1)); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized: %v", err)
	}
}

// Errors never quote values (keys, hashes or ids).
func TestErrorsCarryNoValues(t *testing.T) {
	d := goodDoc()
	d["peers"].([]any)[0].(map[string]any)["public_key"] = "c2VjcmV0LXZhbHVl"
	_, err := Parse(mustJSON(t, d))
	if err == nil || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Fatalf("err %v", err)
	}
}

func TestLookups(t *testing.T) {
	d := goodDoc()
	d["relays"] = []any{map[string]any{"token_sha256": strings.Repeat("a", 64), "instance": "gitea", "server": "w1"}}
	doc, err := Parse(mustJSON(t, d))
	if err != nil {
		t.Fatal(err)
	}
	p := doc.PeerByAddr(netip.MustParseAddr("10.214.0.10"))
	if p == nil || p.ID != "w1" || doc.PeerByID("w1") != p || p.Addr() != netip.MustParseAddr("10.214.0.10") {
		t.Fatal("peer lookup")
	}
	if r := doc.RelayByToken(strings.Repeat("a", 64)); r == nil || r.Instance != "gitea" {
		t.Fatal("relay lookup")
	}
	var nilDoc *Doc
	if nilDoc.PeerByID("w1") != nil || nilDoc.PeerByAddr(p.Addr()) != nil || nilDoc.RelayByToken("x") != nil {
		t.Fatal("nil doc lookups")
	}
	if PeerAddr(LinkAddr) || PeerAddr(netip.MustParseAddr("10.214.0.9")) || !PeerAddr(netip.MustParseAddr("10.214.0.250")) || PeerAddr(netip.MustParseAddr("10.214.0.251")) {
		t.Fatal("PeerAddr")
	}
}

func TestWatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "link.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type res struct {
		d   *Doc
		err error
	}
	ch := make(chan res, 16)
	go (&Watcher{Path: path, Every: 20 * time.Millisecond}).Run(ctx, func(d *Doc, err error) { ch <- res{d, err} })
	next := func() res {
		select {
		case r := <-ch:
			return r
		case <-time.After(5 * time.Second):
			t.Fatal("no callback")
		}
		return res{}
	}
	if r := next(); r.d != nil || r.err == nil || !strings.Contains(r.err.Error(), "missing") {
		t.Fatalf("missing: %+v", r)
	}
	if err := os.WriteFile(path, mustJSON(t, goodDoc()), 0o640); err != nil {
		t.Fatal(err)
	}
	if r := next(); r.d == nil || r.err != nil {
		t.Fatalf("valid: %+v", r)
	}
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if r := next(); r.d != nil || r.err == nil {
		t.Fatalf("invalid: %+v", r)
	}
}
