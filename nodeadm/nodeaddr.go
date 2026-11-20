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
	if err != nil || !ip.Is4() || ip.String() != value {
		return fmt.Errorf("%q is not an IPv4 address (the cluster is IPv4 single-stack)", value)
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
		if ip, err := netip.ParseAddr(p); err == nil && ip.Is4() && pol.Check(p) == nil {
			out.Public = append(out.Public, p)
		}
	}
	return out
}

// lanHolders: every LAN address → the nodes holding it (live nodes' raw
// addresses, enrolment records that aren't removed).
func lanHolders(cl []clusterNode, st *nodeadmState) map[string]map[string]bool {
	h := map[string]map[string]bool{}
	add := func(a, id string) {
		if h[a] == nil {
			h[a] = map[string]bool{}
		}
		h[a][id] = true
	}
	for _, c := range cl {
		for _, a := range c.RawLAN {
			add(a, c.Name)
		}
	}
	if st != nil {
		for id, r := range st.Nodes {
			if !r.Removed {
				for _, a := range reportAddrs(r).LAN {
					add(a, id)
				}
			}
		}
	}
	return h
}

// lanTaken: another node than id holds a.
func lanTaken(h map[string]map[string]bool, a, id string) string {
	for o := range h[a] {
		if o != id {
			return o
		}
	}
	return ""
}

// dedupeLAN drops from every node a LAN address another node also holds
// (a self-reported address nobody can vouch for: dropped on both sides).
func dedupeLAN(cl []clusterNode, st *nodeadmState) {
	h := lanHolders(cl, st)
	for i := range cl {
		keep := []string{}
		for _, a := range cl[i].Addresses.LAN {
			if lanTaken(h, a, cl[i].Name) == "" {
				keep = append(keep, a)
			}
		}
		cl[i].Addresses.LAN = keep
	}
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
		if err := lanFree(a, id, cl, st); err != nil {
			return out, err
		}
		v := ap.String()
		out.LAN = &v
	}
	if m.Public != nil {
		ap, err := netip.ParseAddrPort(*m.Public)
		if err != nil || ap.Port() == 0 {
			return out, fmt.Errorf("the public endpoint isn't an address:port")
		}
		if !ap.Addr().Is4() {
			return out, fmt.Errorf("the public endpoint %s isn't IPv4 (the cluster is IPv4 single-stack)", ap.Addr())
		}
		if err := s.publicPolicy().Check(ap.Addr().String()); err != nil {
			return out, fmt.Errorf("the public endpoint: %v", err)
		}
		v := ap.String()
		out.Public = &v
	}
	return out, nil
}

// lanFree: no other node (live, its public or mesh address included, or a
// record that isn't removed) holds a.
func lanFree(a, id string, cl []clusterNode, st *nodeadmState) error {
	for _, c := range cl {
		if c.Name != id && (contains(c.Addresses.Public, a) || c.Mesh == a) {
			return fmt.Errorf("the LAN address %s is node %s's", a, c.Name)
		}
	}
	if o := lanTaken(lanHolders(cl, st), a, id); o != "" {
		return fmt.Errorf("the LAN address %s is node %s's", a, o)
	}
	return nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
