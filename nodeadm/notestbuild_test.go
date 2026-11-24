//go:build !testprovider

package main

import "testing"

// The published build never admits a documentation address as public.
func TestProductionBuildRefusesDocumentationAddresses(t *testing.T) {
	if testProviderBuild {
		t.Fatal("testProviderBuild is true without the testprovider tag")
	}
	p := AddrPolicy{AllowDocumentation: testProviderBuild}
	if p.Check("203.0.113.11") == nil {
		t.Fatal("203.0.113.11 admitted as public by the production build")
	}
}
