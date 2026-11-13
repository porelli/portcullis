package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"github.com/portcullis/wg/internal/status"
	"github.com/portcullis/wg/internal/tunnel"
)

func udpPort(t *testing.T) int {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// TestServeEndToEnd: a built-in device's TCP 443 through the people stack
// reaches "Traefik" with a PROXY v2 header naming the device; port 80
// redirects; an unknown device's key gets no session.
func TestServeEndToEnd(t *testing.T) {
	dir := t.TempDir()
	tr, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	got := make(chan string, 4)
	go func() {
		for {
			c, err := tr.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				h, err := proxyproto.Read(br)
				if err != nil {
					got <- "no header"
					return
				}
				got <- h.SourceAddr.(*net.TCPAddr).IP.String()
				c.Write([]byte("ok\n"))
			}()
		}
	}()

	srvKey, _ := tunnel.GenerateKey()
	cliKey, _ := tunnel.GenerateKey()
	keyFile := filepath.Join(dir, "people.key")
	os.WriteFile(keyFile, []byte(tunnel.KeyString(srvKey)+"\n"), 0o640)
	vpnFile := filepath.Join(dir, "vpn.json")
	os.WriteFile(vpnFile, []byte(fmt.Sprintf(`{"version":2,
 "builtin":{"subnet":"10.213.0.0/22","server_public_key":%q,"domains":[],
  "peers":[{"ip":"10.213.0.5","public_key":%q,"device_id":"d1","expires":null}]},
 "providers":[{"id":"builtin","source":"builtin","ranges":["10.213.0.0/22"],"edge_port":0,"gateway_ip":"","stale":false}],
 "devices":[{"ip":"10.213.0.5","provider":"builtin","user":"alice","device_id":"d1","name":"p","expires":null}]}`,
		tunnel.KeyString(tunnel.PublicKeyOf(srvKey)), tunnel.KeyString(tunnel.PublicKeyOf(cliKey)))), 0o640)
	statusFile := filepath.Join(dir, "status.json")
	port := udpPort(t)
	env := map[string]string{
		"WG_VPN_FILE": vpnFile, "WG_STATUS_FILE": statusFile, "WG_PEOPLE_KEY": keyFile, "WG_PEOPLE": "on",
		"WG_PORT": fmt.Sprint(port), "WG_VPN_ADDR": "127.0.0.3", "WG_EDGE_ADDR": "127.0.0.1", "WG_TRAEFIK": tr.Addr().String(),
		"WG_DNS_UPSTREAM": "127.0.0.1:1", "WG_DOMAIN": "example.org", "WG_METRICS": "off",
	}
	cfg, err := loadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serve(ctx, cfg)

	cli, err := tunnel.New(tunnel.Config{PrivateKey: cliKey, Address: netip.MustParseAddr("10.213.0.5"), MTU: 1280})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := cli.SyncPeers([]tunnel.PeerConfig{{PublicKey: tunnel.PublicKeyOf(srvKey), IP: netip.MustParseAddr("10.213.0.1"),
		Endpoint: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), Keepalive: 1}}); err != nil {
		t.Fatal(err)
	}
	var c net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		dctx, dc := context.WithTimeout(ctx, 2*time.Second)
		c, err = cli.DialTCP(dctx, netip.MustParseAddrPort("10.213.0.1:443"))
		dc()
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	c.Write([]byte("hello\n"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if src := <-got; src != "10.213.0.5" || line != "ok\n" {
		t.Fatalf("traefik saw %q, client got %q", src, line)
	}

	hc := &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return cli.DialTCP(ctx, netip.MustParseAddrPort("10.213.0.1:80"))
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       5 * time.Second,
	}
	resp, err := hc.Get("http://app.example.org/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 308 || resp.Header.Get("Location") != "https://app.example.org/x?y=1" {
		t.Fatalf("redirect %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d, err := status.Read(statusFile)
		if err == nil && d.People != nil && d.People.OK && d.Edge.OK && len(d.People.Peers) == 1 && d.People.Peers[0].LastHandshake != nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	b, _ := os.ReadFile(statusFile)
	t.Fatalf("status never showed the handshake: %s", b)
}
