package status

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestStatusDocument: the contract §16 shape, people null when off,
// rewritten by Run every interval.
func TestStatusDocument(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	at := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	hs := at.Add(-time.Minute)
	on := Doc{Mode: "apps", Edge: Role{OK: true}, People: &People{
		Role: Role{OK: true}, PublicKey: "pk", Port: 51820, Subnet: "10.213.0.0/22", MTU: 1280,
		Peers: []Peer{{PublicKey: "a", LastHandshake: &hs}, {PublicKey: "b"}},
	}}
	if err := Write(path, on, at); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	var m map[string]any
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if got := keys(m); !reflect.DeepEqual(got, []string{"edge", "mode", "people", "version", "written"}) {
		t.Fatalf("top keys %v", got)
	}
	if m["version"].(float64) != 1 || m["written"] != "2026-11-13T10:00:00Z" {
		t.Fatalf("version / written: %v %v", m["version"], m["written"])
	}
	if got := keys(m["edge"].(map[string]any)); !reflect.DeepEqual(got, []string{"error", "ok"}) {
		t.Fatalf("edge keys %v", got)
	}
	p := m["people"].(map[string]any)
	if got := keys(p); !reflect.DeepEqual(got, []string{"error", "mtu", "ok", "peers", "port", "public_key", "subnet"}) {
		t.Fatalf("people keys %v", got)
	}
	peers := p["peers"].([]any)
	if got := keys(peers[0].(map[string]any)); !reflect.DeepEqual(got, []string{"last_handshake", "public_key"}) {
		t.Fatalf("peer keys %v", got)
	}
	if peers[1].(map[string]any)["last_handshake"] != nil {
		t.Fatal("no handshake must be null")
	}

	if err := Write(path, Doc{Mode: "server", Edge: Role{OK: false, Error: "vpn.json: missing"}}, at); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	json.Unmarshal(b, &m)
	if v, ok := m["people"]; !ok || v != nil {
		t.Fatalf("people must be null when off: %v", m["people"])
	}

	// Run writes at once and every interval.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var n atomic.Int32
	go Run(ctx, path, 30*time.Millisecond, func() Doc { n.Add(1); return on }, time.Now, func(error) {})
	time.Sleep(200 * time.Millisecond)
	cancel()
	if n.Load() < 3 {
		t.Fatalf("written %d times in 200 ms at 30 ms", n.Load())
	}
	if Interval != 10*time.Second {
		t.Fatal("interval")
	}
	got, err := Read(path)
	if err != nil || got.Mode != "apps" || got.People == nil {
		t.Fatalf("Read: %+v %v", got, err)
	}
}
