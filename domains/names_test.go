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
		if err := checkName(name, main, ""); err == nil {
			t.Errorf("checkName(%q) accepted a core / main-domain name", name)
		}
	}
	for _, name := range []string{"team-b.test", "mcp.team-b.test", "mcpx.example.org", "apps.example.org"} {
		if err := checkName(name, main, ""); err != nil {
			t.Errorf("checkName(%q): %v", name, err)
		}
	}
}

// TestCheckNameMailReserved: MAIL_HOSTNAME (and under it), the main
// domain's mail labels, and a domain whose own mail set would name
// MAIL_HOSTNAME are never added domains (their mail set would own the
// main mail set's records).
func TestCheckNameMailReserved(t *testing.T) {
	const main = "example.org"
	for host, names := range map[string][]string{
		"":               {"mail.example.org", "x.mail.example.org", "mta-sts.example.org", "autoconfig.example.org", "x.autodiscover.example.org"},
		"mx.team-b.test": {"mx.team-b.test", "a.mx.team-b.test", "mail.example.org"},
		// MAIL_HOSTNAME is a name team-c.test's mail set uses (its apex,
		// its mail CNAME): team-c.test can't be added.
		"team-c.test":         {"team-c.test"},
		"mta-sts.team-d.test": {"team-d.test", "mta-sts.team-d.test"},
	} {
		for _, n := range names {
			if err := checkName(n, main, host); err == nil {
				t.Errorf("MAIL_HOSTNAME %q: checkName(%q) accepted", host, n)
			}
		}
	}
	for host, names := range map[string][]string{
		"":               {"mailx.example.org", "team-b.test", "mail.team-b.test"},
		"mx.team-b.test": {"team-b.test", "team-c.test"},
	} {
		for _, n := range names {
			if err := checkName(n, main, host); err != nil {
				t.Errorf("MAIL_HOSTNAME %q: checkName(%q): %v", host, n, err)
			}
		}
	}
}
