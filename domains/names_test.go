package main

import "testing"

func TestCheckNameCoreHosts(t *testing.T) {
	const main = "example.org"
	for _, name := range []string{
		"example.org", "org",
		"auth.example.org", "x.hub.example.org", "people.example.org",
		// AI support (contract §4): mcp.<main> is a core host.
		"mcp.example.org", "x.mcp.example.org",
	} {
		if err := checkName(name, main); err == nil {
			t.Errorf("checkName(%q) accepted a core / main-domain name", name)
		}
	}
	for _, name := range []string{"team-b.test", "mcp.team-b.test", "mcpx.example.org", "apps.example.org"} {
		if err := checkName(name, main); err != nil {
			t.Errorf("checkName(%q): %v", name, err)
		}
	}
}
