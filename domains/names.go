package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/portcullis/domains/internal/dnsplan"
)

// hostnameRe is the contract's "valid hostname" (§4): lowercase, at least
// two labels, no port, no trailing dot, no wildcard; at most 253 chars.
var hostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// coreSubdomains are the core hosts <sub>.<main domain> (contract §4).
var coreSubdomains = []string{"auth", "traefik", "hub", "directory", "enroll", "people", "metrics", "mcp"}

func validHostname(s string) bool { return len(s) <= 253 && hostnameRe.MatchString(s) }

// mailLabels are the main domain's mail labels (contract §19: reserved
// on every mail domain; mail.<main> is MAIL_HOSTNAME's default).
var mailLabels = []string{"mail", "mta-sts", "autoconfig", "autodiscover"}

// checkName applies contract §12.2's rule for {name}: a valid hostname,
// not the main domain, not a parent of it, not at or under a core
// subdomain host, and — mail — not at or under MAIL_HOSTNAME (mailHost,
// "" = mail.<main>) or a main-domain mail label, and not a domain whose
// own mail set would name MAIL_HOSTNAME (an added domain's mail set never
// owns the main mail set's records). Used on enroll and again on every
// certificate served.
func checkName(name, main, mailHost string) error {
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
	if mailHost == "" {
		mailHost = "mail." + main
	}
	reserved := []string{mailHost}
	for _, l := range mailLabels {
		reserved = append(reserved, l+"."+main)
	}
	for _, r := range reserved {
		if name == r || strings.HasSuffix(name, "."+r) {
			return fmt.Errorf("%s is at or under %s, reserved for the main domain's mail", name, r)
		}
	}
	if dnsplan.MailNameOwned(name, mailHost) {
		return fmt.Errorf("MAIL_HOSTNAME %s is a name %s's own mail records would use", mailHost, name)
	}
	return nil
}
