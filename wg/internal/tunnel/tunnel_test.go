package tunnel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func newStack(t *testing.T, addr string) (*Stack, [32]byte, int) {
	t.Helper()
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	s, err := New(Config{PrivateKey: priv, ListenPort: port, Address: netip.MustParseAddr(addr), MTU: 1280})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(s.Close)
	return s, PublicKeyOf(priv), port
}

// peerWithEndpoint links a client stack to a server: the client knows the
// server's endpoint and routes the server's /32 there.
func peerWithEndpoint(t *testing.T, client *Stack, serverPub [32]byte, serverIP netip.Addr, serverPort int) {
	t.Helper()
	if err := client.SyncPeers([]PeerConfig{{
		PublicKey: serverPub, IP: serverIP,
		Endpoint:  netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(serverPort)),
		Keepalive: 1,
	}}); err != nil {
		t.Fatalf("client SyncPeers: %v", err)
	}
}

func echo(t *testing.T, s *Stack, port uint16) {
	t.Helper()
	ln, err := s.ListenTCP(port)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
}

func roundTrip(ctx context.Context, s *Stack, to netip.AddrPort) error {
	c, err := s.DialTCP(ctx, to)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return err
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	if string(b) != "ping" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestTunnelRoundTrip(t *testing.T) {
	srv, srvPub, srvPort := newStack(t, "10.77.0.1")
	cli, cliPub, _ := newStack(t, "10.77.0.2")
	if err := srv.SyncPeers([]PeerConfig{{PublicKey: cliPub, IP: netip.MustParseAddr("10.77.0.2")}}); err != nil {
		t.Fatal(err)
	}
	peerWithEndpoint(t, cli, srvPub, netip.MustParseAddr("10.77.0.1"), srvPort)
	echo(t, srv, 443)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := roundTrip(ctx, cli, netip.MustParseAddrPort("10.77.0.1:443")); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	hs, err := srv.Handshakes()
	if err != nil {
		t.Fatal(err)
	}
	if ts, ok := hs[KeyString(cliPub)]; !ok || ts.IsZero() {
		t.Fatalf("no handshake recorded for the client: %v", hs)
	}
	if srv.PublicKey() != KeyString(srvPub) {
		t.Fatal("PublicKey mismatch")
	}
}

func TestSyncPeersDiff(t *testing.T) {
	srv, srvPub, srvPort := newStack(t, "10.78.0.1")
	a, aPub, _ := newStack(t, "10.78.0.2")
	b, bPub, _ := newStack(t, "10.78.0.3")
	both := []PeerConfig{
		{PublicKey: aPub, IP: netip.MustParseAddr("10.78.0.2")},
		{PublicKey: bPub, IP: netip.MustParseAddr("10.78.0.3")},
	}
	if err := srv.SyncPeers(both); err != nil {
		t.Fatal(err)
	}
	peerWithEndpoint(t, a, srvPub, netip.MustParseAddr("10.78.0.1"), srvPort)
	peerWithEndpoint(t, b, srvPub, netip.MustParseAddr("10.78.0.1"), srvPort)
	echo(t, srv, 443)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	to := netip.MustParseAddrPort("10.78.0.1:443")
	if err := roundTrip(ctx, a, to); err != nil {
		t.Fatalf("a: %v", err)
	}
	if err := roundTrip(ctx, b, to); err != nil {
		t.Fatalf("b: %v", err)
	}
	before, _ := srv.Handshakes()
	hsA := before[KeyString(aPub)]
	if hsA.IsZero() {
		t.Fatal("a has no handshake")
	}
	// Drop b: a keeps its session (no re-handshake, same timestamp), b is gone.
	if err := srv.SyncPeers(both[:1]); err != nil {
		t.Fatal(err)
	}
	after, _ := srv.Handshakes()
	if _, ok := after[KeyString(bPub)]; ok {
		t.Fatal("b still a peer")
	}
	if !after[KeyString(aPub)].Equal(hsA) {
		t.Fatalf("a's handshake changed: %v → %v", hsA, after[KeyString(aPub)])
	}
	if err := roundTrip(ctx, a, to); err != nil {
		t.Fatalf("a after the diff: %v", err)
	}
	short, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	if err := roundTrip(short, b, to); err == nil {
		t.Fatal("b still reaches the server after removal")
	}
	// Re-adding with a new address replaces a's allowed IP.
	if err := srv.SyncPeers([]PeerConfig{{PublicKey: aPub, IP: netip.MustParseAddr("10.78.0.9")}}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := srv.dev.IpcGet()
	if want := "allowed_ip=10.78.0.9/32"; !contains(cfg, want) || contains(cfg, "allowed_ip=10.78.0.2/32") {
		t.Fatalf("allowed ips not replaced:\n%s", cfg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestTwoStacksIsolated is the role-separation proof: two stacks in one
// process on disjoint subnets share no route. A dial from stack A to an
// address of stack B's subnet never arrives (A has no peer for it, and
// nothing forwards between stacks), and a stack with no listener accepts
// nothing even from a peer that reaches it.
func TestTwoStacksIsolated(t *testing.T) {
	people, peoplePub, peoplePort := newStack(t, "10.213.0.1")
	link, linkPub, linkPort := newStack(t, "10.214.0.1")
	client, clientPub, _ := newStack(t, "10.213.0.5")
	worker, workerPub, _ := newStack(t, "10.214.0.5")

	if err := people.SyncPeers([]PeerConfig{{PublicKey: clientPub, IP: netip.MustParseAddr("10.213.0.5")}}); err != nil {
		t.Fatal(err)
	}
	if err := link.SyncPeers([]PeerConfig{{PublicKey: workerPub, IP: netip.MustParseAddr("10.214.0.5")}}); err != nil {
		t.Fatal(err)
	}
	peerWithEndpoint(t, client, peoplePub, netip.MustParseAddr("10.213.0.1"), peoplePort)
	peerWithEndpoint(t, worker, linkPub, netip.MustParseAddr("10.214.0.1"), linkPort)
	echo(t, people, 443)
	echo(t, worker, 443) // a worker service the link stack could dial

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := roundTrip(ctx, client, netip.MustParseAddrPort("10.213.0.1:443")); err != nil {
		t.Fatalf("people baseline: %v", err)
	}
	if err := roundTrip(ctx, link, netip.MustParseAddrPort("10.214.0.5:443")); err != nil {
		t.Fatalf("link baseline: %v", err)
	}
	short := func() context.Context {
		c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		t.Cleanup(cancel)
		return c
	}
	// The people stack can't dial a link address (or the link stack's own).
	if err := roundTrip(short(), people, netip.MustParseAddrPort("10.214.0.5:443")); err == nil {
		t.Fatal("people stack reached a link peer")
	}
	if err := roundTrip(short(), people, netip.MustParseAddrPort("10.214.0.1:443")); err == nil {
		t.Fatal("people stack reached the link stack")
	}
	// A people client can't reach the link side through the people stack.
	if err := roundTrip(short(), client, netip.MustParseAddrPort("10.214.0.5:443")); err == nil {
		t.Fatal("people client reached a link peer")
	}
	// The link stack has no listener: its own peer is refused.
	if err := roundTrip(short(), worker, netip.MustParseAddrPort("10.214.0.1:443")); err == nil {
		t.Fatal("link stack accepted a connection")
	}
}

func TestKeys(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if k[0]&7 != 0 || k[31]&128 != 0 || k[31]&64 == 0 {
		t.Fatal("not clamped")
	}
	s := KeyString(PublicKeyOf(k))
	if len(s) != 44 {
		t.Fatalf("public key %q", s)
	}
	if _, err := New(Config{PrivateKey: k, ListenPort: 0, Address: netip.MustParseAddr("fd00::1"), MTU: 1280}); err == nil {
		t.Fatal("IPv6 address accepted")
	}
}
