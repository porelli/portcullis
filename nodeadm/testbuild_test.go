//go:build testprovider

package main

import "testing"

// The testprovider build (e2e-ha-k3d) admits TEST-NET as public, and still
// nothing private.
func TestTestProviderBuildAdmitsDocumentationAddresses(t *testing.T) {
	p := AddrPolicy{AllowDocumentation: testProviderBuild}
	if err := p.Check("203.0.113.11"); err != nil {
		t.Fatalf("203.0.113.11: %v", err)
	}
	if p.Check("10.215.0.2") == nil {
		t.Fatal("a private address admitted")
	}
}
