//go:build !testprovider

package main

import (
	"io"
	"log"
	"os/exec"
	"strings"
	"testing"
)

// TestNoTestProviderInProduction: the production build has no provider
// "fake" and doesn't link the fake DNS package.
func TestNoTestProviderInProduction(t *testing.T) {
	if err := startTestProvider(log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
	if _, ok := providers["fake"]; ok {
		t.Fatal("provider fake registered in a build without the testprovider tag")
	}
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	if strings.Contains(string(out), "internal/fakedns") {
		t.Fatal("the production binary links internal/fakedns")
	}
}
