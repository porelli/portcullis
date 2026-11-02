package main

import (
	"fmt"
	"regexp"
	"strings"
)

// hostnameRe is the contract's "valid hostname" (§4): lowercase, at least
// two labels, no port, no trailing dot, no wildcard; at most 253 chars.
var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// coreSubdomains are the core hosts <sub>.<main domain> (contract §4).
var coreSubdomains = []string{"auth", "traefik", "hub", "directory", "enroll", "people", "metrics"}

func validHostname(s string) bool { return len(s) <= 253 && hostnameRe.MatchString(s) }

// checkName applies contract §12.2's rule for {name}: a valid hostname,
// not the main domain, not a parent of it, not at or under a core
// subdomain host. Used on enroll and again on every certificate served.
func checkName(name, main string) error {
	if !validHostname(name) {
		return fmt.Errorf("%q is not a valid hostname", name)
	}
	if name == main {
		return fmt.Errorf("%s is the main domain", name)
	}
	if strings.HasSuffix(main, "."+name) {
		return fmt.Errorf("%s is a parent of the main domain", name)
	}
	for _, sub := range coreSubdomains {
		c := sub + "." + main
		if name == c || strings.HasSuffix(name, "."+c) {
			return fmt.Errorf("%s is at or under the core host %s", name, c)
		}
	}
	return nil
}
