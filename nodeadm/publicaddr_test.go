package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

// TestPublicAddrVectors: the same tests/public_addr_vectors.json as the
// front door's (domains/frontdoor), so nodeadm's copy of AddrPolicy can't
// drift from it.
func TestPublicAddrVectors(t *testing.T) {
	b, err := os.ReadFile("../tests/public_addr_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs struct {
		V     int `json:"v"`
		Cases []struct {
			Name     string   `json:"name"`
			Address  string   `json:"address"`
			Excluded []string `json:"excluded"`
			Public   bool     `json:"public"`
			PubDocs  bool     `json:"public_with_documentation"`
		} `json:"cases"`
	}
	if err := strictVectors(b, &vs); err != nil || len(vs.Cases) < 20 {
		t.Fatalf("vectors: %v", err)
	}
	for _, c := range vs.Cases {
		var ex []netip.Prefix
		for _, e := range c.Excluded {
			ex = append(ex, netip.MustParsePrefix(e))
		}
		if got := (AddrPolicy{Excluded: ex}).Check(c.Address) == nil; got != c.Public {
			t.Errorf("%s: public %v, want %v", c.Name, got, c.Public)
		}
		if got := (AddrPolicy{Excluded: ex, AllowDocumentation: true}).Check(c.Address) == nil; got != c.PubDocs {
			t.Errorf("%s (documentation allowed): public %v, want %v", c.Name, got, c.PubDocs)
		}
	}
}

// TestNodeAddressVectors (review I4): nodeadm's LAN rule is the CLI's
// strict IPv4 rule (tests/node_address_vectors.json, also run by
// test_shell_libs against kube_doc_addresses); a non-IPv4 public endpoint
// is dropped from an annotation too.
func TestNodeAddressVectors(t *testing.T) {
	b, err := os.ReadFile("../tests/node_address_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Address string `json:"address"`
			Accept  bool   `json:"accept"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Vectors) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	h := newHarness(t)
	for _, v := range f.Vectors {
		if got := h.s.lanCheck(v.Address) == nil; got != v.Accept {
			t.Errorf("lanCheck(%q) accepts %v, want %v", v.Address, got, v.Accept)
		}
	}
	a := h.s.cleanAddrs(NodeAddresses{Mesh: "10.215.0.4", LAN: []string{"2001:db8::1", "192.0.2.44"}, Public: []string{"2001:4860::8888", "8.8.8.8"}})
	if len(a.LAN) != 1 || a.LAN[0] != "192.0.2.44" || len(a.Public) != 1 || a.Public[0] != "8.8.8.8" {
		t.Fatalf("cleanAddrs kept a non-IPv4 address: %+v", a)
	}
}
