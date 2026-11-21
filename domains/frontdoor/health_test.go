package frontdoor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var snapAt = time.Date(2026, 11, 18, 10, 0, 5, 0, time.UTC)

const snap = `{"v": 1, "taken_at": "2026-11-18T10:00:00Z",
 "nodes": [
  {"name": "n1", "role": "server", "ready": true, "labels": {"portcullis.io/site": "main", "portcullis.io/ingress": "true"},
   "addresses": {"mesh": "10.215.0.1", "lan": ["192.0.2.10"], "public": ["198.51.100.7"]}, "traefik_ready": true},
  {"name": "n2", "role": "server", "ready": true, "labels": {"portcullis.io/ingress": "true"},
   "addresses": {"mesh": "10.215.0.2", "public": ["198.51.100.8"]}, "traefik_ready": false},
  {"name": "e1", "role": "agent", "ready": true, "labels": {"portcullis.io/site": "edge"},
   "addresses": {"mesh": "10.215.0.4", "public": []}, "traefik_ready": false}],
 "enrolling": [], "pods": []}`

func TestParseSnapshot(t *testing.T) {
	c, err := ParseSnapshot([]byte(snap), snapAt, docs)
	if err != nil {
		t.Fatal(err)
	}
	if n := c.Nodes["n2"]; n.Site != "main" || !n.Ingress || n.Public[0] != "198.51.100.8" {
		t.Errorf("n2 %+v", n)
	}
	if !c.Ready["n1"] || c.Ready["n2"] || !c.Ready["e1"] {
		t.Errorf("ready %v (n2's Traefik isn't Ready; e1 runs none)", c.Ready)
	}
	if c.Nodes["e1"].Ingress || c.Mesh["e1"] != "10.215.0.4" {
		t.Errorf("e1 %+v %v", c.Nodes["e1"], c.Mesh)
	}
	const at = `"taken_at": "2026-11-18T10:00:00Z"`
	for _, bad := range []string{
		`{"v": 2, ` + at + `, "nodes": []}`,
		`{"v": 1, ` + at + `, "nodes": [{"name": ""}]}`,
		`{"v": 1, ` + at + `, "nodes": [{"name": "n1"}, {"name": "n1"}]}`,
		`{"v": 1, ` + at + `, "nodes": [{"name": "n1", "addresses": {"public": ["10.0.0.1x"]}}]}`,
		`{"v": 1, "taken_at": "2026-11-18T09:59:40Z", "nodes": []}`,
		`{"v": 1, "taken_at": "2026-11-18T10:00:30Z", "nodes": []}`,
		`{"v": 1, "nodes": []}`,
		`not json`,
	} {
		if _, err := ParseSnapshot([]byte(bad), snapAt, docs); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	// A well-formed address that isn't public is left out, with a warning.
	c, err = ParseSnapshot([]byte(`{"v": 1, `+at+`, "nodes": [{"name": "n1", "ready": true, "traefik_ready": true, "labels": {"portcullis.io/ingress": "true"},
	  "addresses": {"public": ["127.0.0.1", "10.215.0.9", "198.51.100.7", "100.64.1.1"]}}]}`), snapAt,
		AddrPolicy{AllowDocumentation: true, Excluded: prefixes("10.215.0.0/24")})
	if err != nil || len(c.Nodes["n1"].Public) != 1 || c.Nodes["n1"].Public[0] != "198.51.100.7" || len(c.Warnings) != 3 {
		t.Errorf("%+v %v %v", c.Nodes["n1"], c.Warnings, err)
	}
	// Production refuses the documentation ranges.
	if c, _ := ParseSnapshot([]byte(snap), snapAt, AddrPolicy{}); len(c.Nodes["n1"].Public) != 0 {
		t.Errorf("a documentation address published in production: %v", c.Nodes["n1"].Public)
	}
}

func TestNewestRound(t *testing.T) {
	now := time.Date(2026, 11, 18, 10, 0, 25, 0, time.UTC)
	mk := func(rs ...ProbeRound) []byte {
		b, _ := json.Marshal(map[string]any{"rounds": rs})
		return b
	}
	r0 := ProbeRound{T: now.Add(-5 * time.Second), Prober: "n1", Site: "main", ReachedAny: true, EgressOK: true}
	r1 := r0
	r1.T = now.Add(-15 * time.Second)
	got, err := NewestRound(mk(r1, r0), "n1", "main", now)
	if err != nil || !got.T.Equal(r0.T) {
		t.Fatalf("%+v %v", got, err)
	}
	stale := r0
	stale.T = now.Add(-time.Minute)
	other := r0
	other.Prober = "n2"
	site := r0
	site.Site = "edge"
	for name, b := range map[string][]byte{"none": mk(), "stale": mk(stale), "another prober": mk(other), "another site": mk(site), "junk": []byte("{")} {
		if _, err := NewestRound(b, "n1", "main", now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBuildStatus(t *testing.T) {
	c, _ := ParseSnapshot([]byte(snap), snapAt, docs)
	e := NewEngine([]string{"example.org", "*.example.org"})
	pub := map[string][]string{"example.org": {"198.51.100.8", "198.51.100.7"}, "*.example.org": {"198.51.100.7"}}
	e.Step(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC), Inputs{Lease: true, Nodes: c.Nodes, Ready: c.Ready, Published: pub})
	st := BuildStatus(true, []string{"example.org", "*.example.org"}, pub, 600*time.Second, c, e.View())
	b, _ := json.Marshal(st)
	for _, want := range []string{`"v":1`, `"state":"leading"`, `"addresses":["198.51.100.7","198.51.100.8"]`, `"ttl":600`, `"worst_case_s":630`,
		`"pending":{"op":"remove","value":"198.51.100.8"`, `"n1":{"ok":true,"verdict":"healthy","internal_only":true,"blind":false}`, `"n2":{"ok":false,"verdict":"unhealthy"`, `"e1":{"ok":false,"verdict":"none"`, `"main":{"healthy":true,"ingress":["n1","n2"],"addresses":["198.51.100.7","198.51.100.8"],"blind_probers":0}`, `"edge":{"healthy":false,"ingress":[],"addresses":[],"blind_probers":0}`, `"last_change":null`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("status %s lacks %s", b, want)
		}
	}
}
