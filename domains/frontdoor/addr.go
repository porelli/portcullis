package frontdoor

import (
	"fmt"
	"net/netip"
)

// AddrPolicy says which addresses may be published: only truly public
// unicast ones, never the cluster's own networks.
type AddrPolicy struct {
	// AllowDocumentation admits the documentation ranges (TEST-NET-1..3,
	// 2001:db8::/32, 3fff::/20) as public: the testprovider build only
	// (CI's fake zone and the vectors); production builds refuse them.
	AllowDocumentation bool
	// Excluded are the node mesh, the pod and the service CIDRs.
	Excluded []netip.Prefix
}

var (
	documentation = prefixes("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20")
	// notPublic: what IsGlobalUnicast admits but the internet doesn't
	// route to a host (RFC 6890 and the IANA special-purpose registries).
	notPublic = prefixes(
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15", "240.0.0.0/4",
		"64:ff9b:1::/48", "100::/64", "2001::/23", "2001:2::/48", "2002::/16", "fc00::/7", "fec0::/10",
	)
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Check is nil when value is an address the front door may publish.
func (p AddrPolicy) Check(value string) error {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" || ip.Is4In6() {
		return fmt.Errorf("%q is not an IPv4 or IPv6 address", value)
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%s is not a public address", ip)
	}
	for _, n := range notPublic {
		if n.Contains(ip) {
			return fmt.Errorf("%s is not a public address (%s)", ip, n)
		}
	}
	if !p.AllowDocumentation {
		for _, n := range documentation {
			if n.Contains(ip) {
				return fmt.Errorf("%s is a documentation address (%s)", ip, n)
			}
		}
	}
	for _, n := range p.Excluded {
		if n.Contains(ip) {
			return fmt.Errorf("%s is in the cluster's network %s", ip, n)
		}
	}
	return nil
}
