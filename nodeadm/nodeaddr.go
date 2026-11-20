package main

// The addresses a node reports of itself (its enrolment report, the
// portcullis.io/addresses annotation): a LAN address is a valid unicast
// address (private ranges included) outside loopback, link-local,
// multicast, unspecified and the mesh / cluster / service networks; a
// public address is truly public (AddrPolicy, the front door's rule). An
// enrolment with another one is refused; an annotation's are dropped.

import (
	"fmt"
	"net/netip"
)

// excludedNets: the mesh, the cluster and the service networks.
func (s *Server) excludedNets() []netip.Prefix {
	out := []netip.Prefix{meshPrefix}
	for _, c := range []string{s.cfg.ClusterCIDR, s.cfg.ServiceCIDR} {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func (s *Server) publicPolicy() AddrPolicy {
	return AddrPolicy{AllowDocumentation: s.cfg.AllowDocAddrs, Excluded: s.excludedNets()}
}

// lanCheck is nil for an address a node may report as its LAN address.
func (s *Server) lanCheck(value string) error {
	ip, err := netip.ParseAddr(value)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.String() != value {
		return fmt.Errorf("%q is not an IPv4 or IPv6 address", value)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() || (ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("%s is not a unicast LAN address", ip)
	}
	for _, n := range s.excludedNets() {
		if n.Contains(ip) {
			return fmt.Errorf("%s is in the cluster's network %s", ip, n)
		}
	}
	return nil
}

// cleanAddrs drops the LAN and public addresses the rules refuse.
func (s *Server) cleanAddrs(a NodeAddresses) NodeAddresses {
	out := NodeAddresses{Mesh: a.Mesh, LAN: []string{}, Public: []string{}}
	for _, l := range a.LAN {
		if s.lanCheck(l) == nil {
			out.LAN = append(out.LAN, l)
		}
	}
	pol := s.publicPolicy()
	for _, p := range a.Public {
		if pol.Check(p) == nil {
			out.Public = append(out.Public, p)
		}
	}
	return out
}

// checkReport validates and normalises an enrolment report: the LAN
// endpoint's address by lanCheck and held by no other node, the public
// endpoint's by the public rule (several nodes may share a NAT's public
// address), a non-zero port.
func (s *Server) checkReport(m MeshReport, id string, cl []clusterNode, st *nodeadmState) (MeshReport, error) {
	out := MeshReport{Pub: m.Pub}
	if m.LAN != nil {
		ap, err := netip.ParseAddrPort(*m.LAN)
		if err != nil || ap.Port() == 0 {
			return out, fmt.Errorf("the LAN endpoint isn't an address:port")
		}
		if err := s.lanCheck(ap.Addr().String()); err != nil {
			return out, fmt.Errorf("the LAN endpoint: %v", err)
		}
		a := ap.Addr().String()
		for _, c := range cl {
			if c.Name != id && (contains(c.Addresses.LAN, a) || contains(c.Addresses.Public, a) || c.Mesh == a) {
				return out, fmt.Errorf("the LAN address %s is node %s's", a, c.Name)
			}
		}
		for oid, r := range st.Nodes {
			if oid != id && !r.Removed && contains(reportAddrs(r).LAN, a) {
				return out, fmt.Errorf("the LAN address %s is node %s's", a, oid)
			}
		}
		v := ap.String()
		out.LAN = &v
	}
	if m.Public != nil {
		ap, err := netip.ParseAddrPort(*m.Public)
		if err != nil || ap.Port() == 0 {
			return out, fmt.Errorf("the public endpoint isn't an address:port")
		}
		if err := s.publicPolicy().Check(ap.Addr().String()); err != nil {
			return out, fmt.Errorf("the public endpoint: %v", err)
		}
		v := ap.String()
		out.Public = &v
	}
	return out, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
