package main

import (
	"net/netip"
	"strings"
	"testing"
)

const conf = `[Interface]
PrivateKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
Address = 10.213.0.5/32
DNS = 10.213.0.1
MTU = 1280

[Peer]
PublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=
Endpoint = portcullis.local:51820
AllowedIPs = 10.213.0.1/32
PersistentKeepalive = 25
`

func TestParseConf(t *testing.T) {
	c, err := parseConf(strings.NewReader(conf))
	if err != nil {
		t.Fatal(err)
	}
	if c.Address != netip.MustParseAddr("10.213.0.5") || c.DNS != netip.MustParseAddr("10.213.0.1") || c.MTU != 1280 {
		t.Fatalf("interface %+v", c)
	}
	if c.Endpoint != "portcullis.local:51820" || len(c.AllowedIPs) != 1 || c.AllowedIPs[0] != netip.MustParsePrefix("10.213.0.1/32") {
		t.Fatalf("peer %+v", c)
	}
	if c.Keepalive != 25 {
		t.Fatalf("keepalive %d", c.Keepalive)
	}
	for _, bad := range []string{
		"", "[Interface]\nAddress = 10.0.0.1/32\n", strings.Replace(conf, "PublicKey = HIgo", "PublicKey = xx", 1),
		strings.Replace(conf, "Address = 10.213.0.5/32", "Address = fd00::5/128", 1),
		conf + "\n[Peer]\nPublicKey = HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=\n",
	} {
		if _, err := parseConf(strings.NewReader(bad)); err == nil {
			t.Errorf("parsed: %q", bad)
		}
	}
}

func TestResolveFlag(t *testing.T) {
	r, err := parseResolve([]string{"echo-vpn.portcullis.local:443:10.213.0.1"})
	if err != nil || r["echo-vpn.portcullis.local:443"] != "10.213.0.1:443" {
		t.Fatalf("%v %v", r, err)
	}
	if _, err := parseResolve([]string{"x:443"}); err == nil {
		t.Fatal("bad --resolve accepted")
	}
}
