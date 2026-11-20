package main

import (
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
