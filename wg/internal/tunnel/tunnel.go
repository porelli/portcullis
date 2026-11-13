// Package tunnel is one userspace WireGuard device on its own gVisor
// netstack (golang.zx2c4.com/wireguard + tun/netstack): no TUN device, no
// capability, an ordinary UDP socket. Each role of the wg service gets its
// own Stack, with its own key, port and subnet; nothing forwards between
// stacks, and a stack accepts only on the listeners its role opens.
package tunnel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Config of one stack. Address is the stack's own tunnel address.
type Config struct {
	PrivateKey [32]byte
	ListenPort int // 0 = no fixed port (a client)
	Address    netip.Addr
	MTU        int
}

// PeerConfig is one peer: its key and the single address it may use
// (allowed_ip <ip>/32). Endpoint and Keepalive are for client stacks that
// dial a server; a server learns endpoints from handshakes.
type PeerConfig struct {
	PublicKey [32]byte
	IP        netip.Addr
	Endpoint  netip.AddrPort
	Keepalive int
}

// Stack is a running device and its netstack.
type Stack struct {
	dev  *device.Device
	tnet *netstack.Net
	addr netip.Addr
	pub  [32]byte

	mu    sync.Mutex
	peers map[[32]byte]PeerConfig
}

// GenerateKey returns a new clamped X25519 private key.
func GenerateKey() ([32]byte, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// PublicKeyOf derives the public key.
func PublicKeyOf(priv [32]byte) [32]byte {
	var pub [32]byte
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err) // only for low-order points, which a clamped scalar never gives with the base point
	}
	copy(pub[:], p)
	return pub
}

// KeyString is the base64 form WireGuard configs use.
func KeyString(k [32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

// New creates and starts a stack. The private key goes to the device
// through UAPI in memory only.
func New(cfg Config) (*Stack, error) {
	if !cfg.Address.Is4() {
		return nil, errors.New("tunnel: address must be IPv4")
	}
	if cfg.MTU <= 0 {
		cfg.MTU = 1280
	}
	if cfg.ListenPort < 0 || cfg.ListenPort > 65535 {
		return nil, errors.New("tunnel: listen port out of range")
	}
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.Address}, nil, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("tunnel: netstack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, errors.New("tunnel: device configuration refused")
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: up: %w", err)
	}
	return &Stack{dev: dev, tnet: tnet, addr: cfg.Address, pub: PublicKeyOf(cfg.PrivateKey), peers: map[[32]byte]PeerConfig{}}, nil
}

// SyncPeers makes the device's peers exactly peers: gone peers are removed
// (remove=true), new ones added and changed ones updated with
// replace_allowed_ips=true. Unchanged peers aren't touched, so their
// sessions survive. Never replace_peers.
func (s *Stack) SyncPeers(peers []PeerConfig) error {
	want := map[[32]byte]PeerConfig{}
	ips := map[netip.Addr]bool{}
	for _, p := range peers {
		if !p.IP.Is4() {
			return errors.New("tunnel: peer address must be IPv4")
		}
		if _, dup := want[p.PublicKey]; dup || ips[p.IP] {
			return errors.New("tunnel: duplicate peer key or address")
		}
		if p.PublicKey == s.pub {
			return errors.New("tunnel: a peer has the stack's own key")
		}
		want[p.PublicKey] = p
		ips[p.IP] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for k := range s.peers {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", hex.EncodeToString(k[:]))
		}
	}
	keys := make([][32]byte, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return string(keys[i][:]) < string(keys[j][:]) })
	for _, k := range keys {
		p := want[k]
		if old, ok := s.peers[k]; ok && old == p {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(k[:]))
		if p.Endpoint.IsValid() {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
		fmt.Fprintf(&b, "replace_allowed_ips=true\nallowed_ip=%s/32\n", p.IP)
	}
	if b.Len() == 0 {
		return nil
	}
	if err := s.dev.IpcSet(b.String()); err != nil {
		// The device may hold a partial update: forget what we believe
		// and let the next sync rewrite every peer.
		s.resyncLocked()
		return errors.New("tunnel: peer update refused")
	}
	s.peers = want
	return nil
}

// resyncLocked reads the device's real peer set after a failed update so
// the next SyncPeers diffs against it.
func (s *Stack) resyncLocked() {
	s.peers = map[[32]byte]PeerConfig{}
	cfg, err := s.dev.IpcGet()
	if err != nil {
		return
	}
	for _, p := range parsePeers(cfg) {
		// Unknown allowed IP: an empty PeerConfig never equals a wanted one,
		// so every live peer is rewritten (or removed) next time.
		s.peers[p.key] = PeerConfig{PublicKey: p.key}
	}
}

type peerState struct {
	key       [32]byte
	sec, nsec int64
}

func (p peerState) handshake() time.Time {
	if p.sec == 0 && p.nsec == 0 {
		return time.Time{}
	}
	return time.Unix(p.sec, p.nsec)
}

func parsePeers(cfg string) []peerState {
	var out []peerState
	sc := bufio.NewScanner(strings.NewReader(cfg))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != 32 {
				continue
			}
			var pk [32]byte
			copy(pk[:], b)
			out = append(out, peerState{key: pk})
			continue
		}
		if len(out) == 0 {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			out[len(out)-1].sec = n
		case "last_handshake_time_nsec":
			out[len(out)-1].nsec = n
		}
	}
	return out
}

// Handshakes maps each peer's base64 public key to its last handshake
// (zero when it never had one).
func (s *Stack) Handshakes() (map[string]time.Time, error) {
	cfg, err := s.dev.IpcGet()
	if err != nil {
		return nil, errors.New("tunnel: device state unreadable")
	}
	out := map[string]time.Time{}
	for _, p := range parsePeers(cfg) {
		out[KeyString(p.key)] = p.handshake()
	}
	return out, nil
}

// ListenTCP listens on the stack's own address.
func (s *Stack) ListenTCP(port uint16) (net.Listener, error) {
	return s.tnet.ListenTCPAddrPort(netip.AddrPortFrom(s.addr, port))
}

// ListenUDP listens on the stack's own address.
func (s *Stack) ListenUDP(port uint16) (net.PacketConn, error) {
	return s.tnet.ListenUDPAddrPort(netip.AddrPortFrom(s.addr, port))
}

// DialTCP dials through the tunnel (clients and tests).
func (s *Stack) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return s.tnet.DialContextTCPAddrPort(ctx, addr)
}

// Net is the stack's netstack (clients: DNS and HTTP through the tunnel).
func (s *Stack) Net() *netstack.Net { return s.tnet }

// PublicKey is the stack's base64 public key.
func (s *Stack) PublicKey() string { return KeyString(s.pub) }

// Close stops the device.
func (s *Stack) Close() { s.dev.Close() }
