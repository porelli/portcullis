package dnsplan

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// TestHAAddressSet (contract §12.4, HA): with Spec.HA the address items
// want the front door's set per name (a multi-value A), the server's own
// IPv4 is ignored, an empty set is unknown, and Apply never writes the
// address set as a whole (the follower does, one change at a time).
func TestHAAddressSet(t *testing.T) {
	e := newPlanEnv(t)
	e.addr(pd, "198.51.100.1")
	e.addr(pd, "198.51.100.2")
	e.addr("*."+pd, "198.51.100.1")
	e.in.Spec.HA = &HAAddrs{Apex: []netip.Addr{netip.MustParseAddr("198.51.100.2"), netip.MustParseAddr("198.51.100.1")},
		Wild: []netip.Addr{netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")}}
	p := Build(context.Background(), e.in)
	if a := find(t, p, SetAddress, pd, "A", StatusOK); !slices.Equal(a.Want, []string{"198.51.100.1", "198.51.100.2"}) {
		t.Errorf("apex want %v", a.Want)
	}
	w := find(t, p, SetAddress, "*."+pd, "A", StatusWrong)
	if !slices.Equal(w.Want, []string{"198.51.100.1", "198.51.100.2"}) || len(w.Steps) == 0 || !strings.Contains(w.Steps[0], "add A *."+pd+" 198.51.100.2") {
		t.Errorf("wildcard %+v", w)
	}
	for _, it := range items(p, SetAddress) {
		if slices.Contains(it.Want, ipv4) {
			t.Errorf("the server's own IPv4 wanted in HA: %+v", it)
		}
	}
	if _, _, err := Apply(context.Background(), e.in, []string{SetAddress}); err == nil || !strings.Contains(err.Error(), "follows the front door") {
		t.Errorf("Apply of the address set in HA: %v", err)
	}
	if got := e.zone.Records("*." + pd); len(got) != 1 {
		t.Errorf("Apply wrote in HA: %v", got)
	}
	e.in.Spec.HA = &HAAddrs{}
	for _, it := range items(Build(context.Background(), e.in), SetAddress) {
		if it.Status != StatusUnknown || it.Severity != SevInfo || !strings.Contains(strings.Join(it.Steps, " "), "front door") {
			t.Errorf("empty HA set: %+v", it)
		}
	}
}
