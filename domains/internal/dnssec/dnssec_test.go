package dnssec

import (
	"context"
	"strings"
	"testing"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/portcullis/domains/internal/fakedns"
)

func setup(t *testing.T, f func(z *fakedns.Zone)) []string {
	t.Helper()
	z := fakedns.NewZone()
	z.SetSOA("team.test")
	z.Set("team.test", libdns.RR{Name: "@", Type: "A", Data: "203.0.113.10"})
	f(z)
	s, err := fakedns.ServeWith(z, "127.0.0.1:0", fakedns.Options{Validating: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return []string{s.Addr, s.Addr}
}

func sign(t *testing.T, z *fakedns.Zone) *dns.DNSKEY {
	t.Helper()
	k, err := z.Sign("team.test")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCheckSecure(t *testing.T) {
	r := Check(context.Background(), setup(t, func(z *fakedns.Zone) {
		z.PublishDS("team.test", sign(t, z).ToDS(dns.SHA256))
	}), "team.test")
	if r.State != Secure || r.Zone != "team.test." || len(r.DS) != 1 || len(r.ParentDS) != 1 || r.DS[0] != r.ParentDS[0] {
		t.Fatalf("%+v", r)
	}
	if r.DS[0].DigestType != 2 || r.DS[0].Algorithm != dns.ECDSAP256SHA256 {
		t.Fatalf("DS %+v", r.DS[0])
	}
}

func TestCheckUnsigned(t *testing.T) {
	if r := Check(context.Background(), setup(t, func(*fakedns.Zone) {}), "team.test"); r.State != Unsigned || len(r.DS) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestCheckDSMissing(t *testing.T) {
	var k *dns.DNSKEY
	r := Check(context.Background(), setup(t, func(z *fakedns.Zone) { k = sign(t, z) }), "team.test")
	want := k.ToDS(dns.SHA256)
	if r.State != DSMissing || len(r.DS) != 1 || r.DS[0].KeyTag != want.KeyTag || r.DS[0].Digest != strings.ToUpper(want.Digest) || r.DS[0].DigestType != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestCheckDSMismatch(t *testing.T) {
	r := Check(context.Background(), setup(t, func(z *fakedns.Zone) {
		bad := *sign(t, z).ToDS(dns.SHA256)
		bad.Digest = strings.Repeat("AB", 32)
		z.PublishDS("team.test", &bad)
	}), "team.test")
	if r.State != DSMismatch {
		t.Fatalf("%+v", r)
	}
}

func TestCheckBogus(t *testing.T) {
	r := Check(context.Background(), setup(t, func(z *fakedns.Zone) {
		z.PublishDS("team.test", sign(t, z).ToDS(dns.SHA256))
		z.SetBogus("team.test", true)
	}), "team.test")
	if r.State != Bogus || r.Err == "" {
		t.Fatalf("%+v", r)
	}
	// A DS without any DNSKEY is bogus too.
	r = Check(context.Background(), setup(t, func(z *fakedns.Zone) {
		z.PublishDS("team.test", &dns.DS{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: strings.Repeat("AB", 32)})
	}), "team.test")
	if r.State != Bogus {
		t.Fatalf("DS without DNSKEY: %+v", r)
	}
}

func TestCheckUnknown(t *testing.T) {
	if r := Check(context.Background(), []string{"127.0.0.1:1"}, "team.test"); r.State != Unknown || r.Err == "" {
		t.Fatalf("%+v", r)
	}
}

func TestFindZoneClimbs(t *testing.T) {
	z, err := FindZone(context.Background(), setup(t, func(*fakedns.Zone) {}), "a.b.team.test")
	if err != nil || z != "team.test." {
		t.Fatalf("%q %v", z, err)
	}
}
