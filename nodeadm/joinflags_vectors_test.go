package main

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// The join answer's flags as shared vectors (plan Task 30 carry): the
// Hub's nodeagent allowlist (internal/nodeagent/host checkFlags, its byte
// copy internal/nodeagent/testdata/join_flags_vectors.json) must accept
// each vector's flags and allow nothing else for that role, so nodeadm's
// list and the nodeagent's allowlist match exactly. Regenerate with
// PORTCULLIS_UPDATE_VECTORS=1 go test -run TestJoinFlagsVectors.

const joinFlagsVectorsFile = "testdata/join_flags_vectors.json"

type joinFlagsVector struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Role        string   `json:"role"`
	MeshIP      string   `json:"mesh_ip"`
	ServerURL   string   `json:"server_url"`
	ClusterCIDR string   `json:"cluster_cidr"`
	Flags       []string `json:"flags"`
}

func joinFlagsVectors() []joinFlagsVector {
	in := []joinFlagsVector{
		{Name: "a server at main", ID: "n4", Role: "server", MeshIP: "10.215.0.4", ServerURL: "https://10.215.0.1:6443", ClusterCIDR: "10.42.0.0/16"},
		{Name: "an agent at main", ID: "n5", Role: "agent", MeshIP: "10.215.0.5", ServerURL: "https://10.215.0.1:6443", ClusterCIDR: "10.42.0.0/16"},
		{Name: "an agent at another site, another server, another cluster network", ID: "edge-1", Role: "agent", MeshIP: "10.215.0.17", ServerURL: "https://10.215.0.2:6443", ClusterCIDR: "10.60.0.0/16"},
		{Name: "a server, another cluster network", ID: "srv-3", Role: "server", MeshIP: "10.215.0.33", ServerURL: "https://10.215.0.2:6443", ClusterCIDR: "10.60.0.0/16"},
	}
	for i := range in {
		v := &in[i]
		v.Flags = joinFlags(&nodeRecord{Role: v.Role, MeshIP: v.MeshIP, Class: "home", Site: "main", Ingress: true, Storage: true}, v.ID, v.ServerURL, v.ClusterCIDR)
	}
	return in
}

func TestJoinFlagsVectors(t *testing.T) {
	want := joinFlagsVectors()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"vectors": want}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PORTCULLIS_UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(joinFlagsVectorsFile, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(joinFlagsVectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, buf.Bytes()) {
		t.Fatalf("%s isn't joinFlags' output: regenerate it (PORTCULLIS_UPDATE_VECTORS=1) and re-copy it into the Hub", joinFlagsVectorsFile)
	}
	for _, v := range want {
		for _, f := range []string{"--bind-address=" + v.MeshIP, "--node-taint=" + unlabelledTaint, "--node-ip=" + v.MeshIP, "--server=" + v.ServerURL} {
			if !slices.Contains(v.Flags, f) {
				t.Errorf("%s: no %s", v.Name, f)
			}
		}
	}
}

// TestAgentHealthTakesTheNodeagentsAnswer (found live, Task 30): the
// nodeagent's GET /v1/health carries "peers" (the Hub's WireGuard state,
// Hub internal/nodeagent Health); nodeadm's strict decode must take the
// real answer, or no join ever leaves mesh_pending. Unknown fields stay
// refused.
func TestAgentHealthTakesTheNodeagentsAnswer(t *testing.T) {
	base := `"id":"n2","version":"0.0.0-dev","mesh_ip":"10.215.0.2","mesh_pub":"bWVzaHB1Yg==","k3s":"running","time":"2026-11-22T07:00:00Z"`
	for _, b := range []string{
		`{` + base + `,"peers":{"node-1":{"latest_handshake":"2026-11-22T07:00:00Z","endpoint":"198.51.100.1:51830"},"n3":{"latest_handshake":null,"endpoint":null}}}`,
		`{` + base + `,"peers":{}}`,
		`{` + base + `,"peers":null}`,
		`{` + base + `}`,
	} {
		var h AgentHealth
		if err := strictJSON([]byte(b), &h); err != nil || h.ID != "n2" {
			t.Errorf("%s: %v", b, err)
		}
	}
	var h AgentHealth
	if strictJSON([]byte(`{`+base+`,"token":"x"}`), &h) == nil {
		t.Error("an unknown field was taken")
	}
}
