// Command vpn-client is the e2e-vpn / e2e-podman jobs' WireGuard client: a
// userspace WireGuard device (wireguard-go + gVisor netstack, no TUN, no
// capability) brought up from a wg-quick config on stdin, then one HTTPS
// request or one DNS query through the tunnel. It prints one JSON document
// and exits 0 when it got an answer, 3 when the tunnel or the connection
// failed (no handshake, dial / TLS error), 2 on a usage error. CI only.
//
//	vpn-client [--endpoint host:port] [--wait-handshake 20s] [--timeout 20s]
//	    (--get https://<host>/<path> [--resolve host:port:addr] [--ca-file f] [--header-file f]
//	     | --dns <name> [--type A|AAAA] [--server 10.213.0.1:53]) < wg.conf
//
// The config's private key and any header file are secrets: they are never
// printed. The answer's body is clipped.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wgConf struct {
	PrivateKey [32]byte
	Address    netip.Addr
	DNS        netip.Addr
	MTU        int
	PublicKey  [32]byte
	Endpoint   string
	AllowedIPs []netip.Prefix
	Keepalive  int
}

func key(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return k, errors.New("not a WireGuard key")
	}
	copy(k[:], b)
	return k, nil
}

// parseConf reads a wg-quick config with one [Interface] and one [Peer].
func parseConf(r io.Reader) (*wgConf, error) {
	c := &wgConf{MTU: 1280}
	sec, peers := "", 0
	var haveKey, havePeerKey bool
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			sec = strings.ToLower(strings.Trim(line, "[]"))
			if sec == "peer" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("config: a line without =")
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		var err error
		switch sec + "." + k {
		case "interface.privatekey":
			c.PrivateKey, err = key(v)
			haveKey = err == nil
		case "interface.address":
			var p netip.Prefix
			p, err = netip.ParsePrefix(v)
			if err == nil && !p.Addr().Is4() {
				err = errors.New("IPv4 only")
			}
			c.Address = p.Addr()
		case "interface.dns":
			c.DNS, err = netip.ParseAddr(v)
		case "interface.mtu":
			c.MTU, err = strconv.Atoi(v)
		case "peer.publickey":
			c.PublicKey, err = key(v)
			havePeerKey = err == nil
		case "peer.endpoint":
			c.Endpoint = v
		case "peer.allowedips":
			for _, f := range strings.Split(v, ",") {
				var p netip.Prefix
				if p, err = netip.ParsePrefix(strings.TrimSpace(f)); err != nil {
					break
				}
				c.AllowedIPs = append(c.AllowedIPs, p)
			}
		case "peer.persistentkeepalive":
			c.Keepalive, err = strconv.Atoi(v)
		default:
			return nil, fmt.Errorf("config: unknown key %s in [%s]", k, sec)
		}
		if err != nil {
			return nil, fmt.Errorf("config: %s: %v", k, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !haveKey || !havePeerKey || !c.Address.IsValid() || peers != 1 || len(c.AllowedIPs) == 0 {
		return nil, errors.New("config: needs PrivateKey, Address, exactly one [Peer] with PublicKey and AllowedIPs")
	}
	return c, nil
}

// parseResolve turns curl-style host:port:addr into host:port → addr:port.
func parseResolve(vals []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range vals {
		parts := strings.Split(v, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("--resolve %q: want host:port:addr", v)
		}
		out[parts[0]+":"+parts[1]] = net.JoinHostPort(parts[2], parts[1])
	}
	return out, nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type result struct {
	Handshake bool              `json:"handshake"`
	Status    int               `json:"status,omitempty"`
	Location  string            `json:"location,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      string            `json:"body,omitempty"`
	Answers   []string          `json:"answers,omitempty"`
	Rcode     string            `json:"rcode,omitempty"`
	AD        bool              `json:"ad,omitempty"`
	Error     string            `json:"error,omitempty"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("vpn-client", flag.ContinueOnError)
	fs.SetOutput(stderr)
	endpoint := fs.String("endpoint", "", "override the peer's Endpoint (host:port)")
	waitHS := fs.Duration("wait-handshake", 20*time.Second, "how long to wait for the handshake")
	timeout := fs.Duration("timeout", 20*time.Second, "the request's timeout")
	get := fs.String("get", "", "an https:// URL to GET through the tunnel")
	caFile := fs.String("ca-file", "", "PEM CA bundle to trust")
	headerFile := fs.String("header-file", "", "request headers, one 'Name: value' per line (secret)")
	dnsName := fs.String("dns", "", "a name to look up through the tunnel")
	dnsType := fs.String("type", "A", "A or AAAA")
	dnsServer := fs.String("server", "", "resolver (default: the config's DNS, port 53)")
	var resolve multi
	fs.Var(&resolve, "resolve", "host:port:addr (repeatable), like curl")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*get == "") == (*dnsName == "") || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "vpn-client: exactly one of --get and --dns")
		return 2
	}
	res, err := parseResolve(resolve)
	if err != nil {
		fmt.Fprintln(stderr, "vpn-client:", err)
		return 2
	}
	c, err := parseConf(io.LimitReader(stdin, 1<<16))
	if err != nil {
		fmt.Fprintln(stderr, "vpn-client:", err)
		return 2
	}
	if *endpoint != "" {
		c.Endpoint = *endpoint
	}
	out := result{}
	emit := func(code int) int {
		json.NewEncoder(stdout).Encode(out)
		return code
	}
	tnet, dev, err := up(c)
	if err != nil {
		out.Error = err.Error()
		return emit(3)
	}
	defer dev.Close()
	if !waitHandshake(dev, tnet, c.AllowedIPs[0].Addr(), *waitHS) {
		out.Error = "no handshake within " + waitHS.String()
		return emit(3)
	}
	out.Handshake = true
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *dnsName != "" {
		server := *dnsServer
		if server == "" {
			if !c.DNS.IsValid() {
				out.Error = "no DNS in the config and no --server"
				return emit(2)
			}
			server = netip.AddrPortFrom(c.DNS, 53).String()
		}
		if err := lookup(ctx, tnet, server, *dnsName, *dnsType, &out); err != nil {
			out.Error = err.Error()
			return emit(3)
		}
		return emit(0)
	}
	if err := fetch(ctx, tnet, *get, res, *caFile, *headerFile, &out); err != nil {
		out.Error = err.Error()
		return emit(3)
	}
	return emit(0)
}

func up(c *wgConf) (*netstack.Net, *device.Device, error) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{c.Address}, nil, c.MTU)
	if err != nil {
		return nil, nil, fmt.Errorf("netstack: %v", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wireguard: "))
	ep, err := net.ResolveUDPAddr("udp4", c.Endpoint)
	if err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("endpoint: %v", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\npublic_key=%s\nendpoint=%s\n", hex.EncodeToString(c.PrivateKey[:]), hex.EncodeToString(c.PublicKey[:]), ep)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", c.Keepalive)
	}
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p)
	}
	if err := dev.IpcSet(b.String()); err != nil {
		dev.Close()
		return nil, nil, errors.New("device configuration refused")
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, err
	}
	return tnet, dev, nil
}

// waitHandshake pokes the tunnel (a UDP packet to the first allowed
// address starts the handshake) and waits for last_handshake_time_sec.
func waitHandshake(dev *device.Device, tnet *netstack.Net, peer netip.Addr, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	poke := time.Time{}
	for time.Now().Before(deadline) {
		if time.Since(poke) > 2*time.Second {
			poke = time.Now()
			if u, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(peer, 9)); err == nil {
				u.Write([]byte{0})
				u.Close()
			}
		}
		st, err := dev.IpcGet()
		if err == nil {
			for _, l := range strings.Split(st, "\n") {
				if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok && v != "0" {
					return true
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func fetch(ctx context.Context, tnet *netstack.Net, url string, res map[string]string, caFile, headerFile string, out *result) error {
	if !strings.HasPrefix(url, "https://") {
		return errors.New("--get: an https:// URL")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return errors.New("--ca-file: no PEM certificates")
		}
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if to, ok := res[addr]; ok {
				addr = to
			}
			return tnet.DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: false,
	}
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if headerFile != "" {
		b, err := os.ReadFile(headerFile)
		if err != nil {
			return errors.New("--header-file: unreadable")
		}
		for _, l := range strings.Split(string(b), "\n") {
			if n, v, ok := strings.Cut(strings.TrimRight(l, "\r"), ":"); ok && strings.TrimSpace(n) != "" {
				req.Header.Add(strings.TrimSpace(n), strings.TrimSpace(v))
			}
		}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	out.Status = resp.StatusCode
	out.Location = resp.Header.Get("Location")
	out.Headers = map[string]string{}
	for _, h := range []string{"Content-Type", "X-Stepup-Url"} {
		if v := resp.Header.Get(h); v != "" {
			out.Headers[h] = v
		}
	}
	out.Body = string(body)
	return nil
}

func lookup(ctx context.Context, tnet *netstack.Net, server, name, typ string, out *result) error {
	qt, ok := map[string]uint16{"A": dns.TypeA, "AAAA": dns.TypeAAAA}[strings.ToUpper(typ)]
	if !ok {
		return errors.New("--type: A or AAAA")
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qt)
	q.SetEdns0(1232, true)
	c, err := tnet.DialContext(ctx, "udp", server)
	if err != nil {
		return err
	}
	defer c.Close()
	co := &dns.Conn{Conn: c}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if err := co.WriteMsg(q); err != nil {
		return err
	}
	in, err := co.ReadMsg()
	if err != nil {
		return err
	}
	out.Rcode = dns.RcodeToString[in.Rcode]
	out.AD = in.AuthenticatedData
	out.Answers = []string{}
	for _, a := range in.Answer {
		out.Answers = append(out.Answers, strings.Join(strings.Fields(a.String()), " "))
	}
	return nil
}
