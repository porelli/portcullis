// Command wg is Portcullis' VPN service (contract §16): the edge (the only
// PROXY v2 client of Traefik's vpnsecure entrypoint) and the built-in
// people VPN role, on userspace WireGuard (wireguard-go + gVisor
// netstack): no capability, no TUN device. It reads /vpn-doc/vpn.json (the
// vpn_doc volume; Hub-written, public data only) and writes wg_data/status.json.
//
//	wg run            the service
//	wg genkey <path>  write a new private key into <path> in place (0640); prints nothing
//	wg keypair        {"private_key","public_key"} on stdout (the host CLI only)
//	wg qr             stdin text → terminal QR code on stdout
//	wg healthcheck    exit 0 while status.json is fresh
//	wg status         print status.json
//	wg providers      a summary of vpn.json's providers (no keys)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/portcullis/wg/internal/edge"
	"github.com/portcullis/wg/internal/people"
	"github.com/portcullis/wg/internal/resolver"
	"github.com/portcullis/wg/internal/status"
	"github.com/portcullis/wg/internal/tunnel"
	"github.com/portcullis/wg/internal/vpndoc"
)

const usage = `usage: wg <command>

  run              run the service (environment WG_*)
  genkey <path>    write a new private key into <path> (0640); prints nothing
  keypair          print {"private_key","public_key"} (for the host CLI)
  qr               read text on stdin, print a terminal QR code
  healthcheck      exit 0 while the status file is fresh
  status           print the status file
  providers        print a summary of vpn.json's providers
`

const maxQR = 4096

func main() {
	os.Exit(cli(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

func cli(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	case "genkey":
		if len(rest) != 1 {
			fmt.Fprint(stderr, "usage: wg genkey <path>\n")
			return 2
		}
		if err := genkey(rest[0]); err != nil {
			fmt.Fprintf(stderr, "wg genkey: %v\n", err)
			return 1
		}
		return 0
	case "keypair":
		if len(rest) != 0 {
			fmt.Fprint(stderr, "usage: wg keypair\n")
			return 2
		}
		k, err := tunnel.GenerateKey()
		if err != nil {
			fmt.Fprintln(stderr, "wg keypair: no randomness")
			return 1
		}
		json.NewEncoder(stdout).Encode(map[string]string{
			"private_key": tunnel.KeyString(k),
			"public_key":  tunnel.KeyString(tunnel.PublicKeyOf(k)),
		})
		return 0
	case "qr":
		if len(rest) != 0 {
			fmt.Fprint(stderr, "usage: wg qr < text\n")
			return 2
		}
		b, err := io.ReadAll(io.LimitReader(stdin, maxQR+1))
		if err != nil {
			fmt.Fprintln(stderr, "wg qr: stdin unreadable")
			return 1
		}
		if len(b) > maxQR || len(b) == 0 {
			fmt.Fprintf(stderr, "wg qr: 1–%d bytes on stdin\n", maxQR)
			return 2
		}
		qrterminal.GenerateHalfBlock(string(b), qrterminal.L, stdout)
		return 0
	case "healthcheck", "status":
		if len(rest) != 0 {
			fmt.Fprintf(stderr, "usage: wg %s\n", cmd)
			return 2
		}
		path := envOr(getenv, "WG_STATUS_FILE", "/data/status.json")
		if cmd == "status" {
			b, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintln(stderr, "wg status: no status file (is wg running?)")
				return 1
			}
			stdout.Write(b)
			return 0
		}
		d, err := status.Read(path)
		if err != nil {
			fmt.Fprintln(stdout, "unhealthy: no status file")
			return 1
		}
		if age := time.Since(d.Written); age > status.MaxAge || age < -status.MaxAge {
			fmt.Fprintf(stdout, "unhealthy: status written %s ago\n", age.Round(time.Second))
			return 1
		}
		fmt.Fprintf(stdout, "ok (edge ok=%v)\n", d.Edge.OK)
		return 0
	case "providers":
		if len(rest) != 0 {
			fmt.Fprint(stderr, "usage: wg providers\n")
			return 2
		}
		return providers(envOr(getenv, "WG_VPN_FILE", "/vpn-doc/vpn.json"), stdout, stderr)
	case "run":
		if len(rest) != 0 {
			fmt.Fprint(stderr, "usage: wg run\n")
			return 2
		}
		cfg, err := loadConfig(getenv)
		if err != nil {
			fmt.Fprintf(stderr, "wg: %v\n", err)
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		if err := serve(ctx, cfg); err != nil {
			fmt.Fprintf(stderr, "wg: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stderr, "wg: unknown command %q\n%s", cmd, usage)
	return 2
}

func envOr(getenv func(string) string, k, def string) string {
	if v := getenv(k); v != "" {
		return v
	}
	return def
}

// genkey writes the key into the existing file in place (truncate +
// write): the compose bind of a single file pins its inode, so a rename
// would never reach a running wg (V4).
func genkey(path string) error {
	k, err := tunnel.GenerateKey()
	if err != nil {
		return errors.New("no randomness")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return errors.New("can't open the key file for writing")
	}
	if _, err := f.WriteString(tunnel.KeyString(k) + "\n"); err != nil {
		f.Close()
		return errors.New("writing the key failed")
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return errors.New("setting the key file's mode failed")
	}
	return f.Close()
}

func providers(path string, stdout, stderr io.Writer) int {
	d, err := vpndoc.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "wg providers: %v\n", err)
		return 1
	}
	now := time.Now()
	type row struct {
		ID          string     `json:"id"`
		Label       string     `json:"label"`
		Ranges      []string   `json:"ranges"`
		Devices     int        `json:"devices"`
		RefreshedAt *time.Time `json:"refreshed_at"`
		Fresh       bool       `json:"fresh"`
	}
	out := []row{}
	for i := range d.Providers {
		p := &d.Providers[i]
		n := 0
		for _, dv := range d.Devices {
			if dv.Provider == p.ID {
				n++
			}
		}
		out = append(out, row{p.ID, p.Label, p.Ranges, n, p.RefreshedAt, p.Fresh(now)})
	}
	json.NewEncoder(stdout).Encode(map[string]any{"providers": out})
	return 0
}

type config struct {
	VPNFile, StatusFile, PeopleKey string
	People                         bool
	Port                           int
	Subnet                         netip.Prefix
	AddrMode                       string     // docker (separate networks) | pod (Kubernetes: one pod address)
	VPNAddr                        netip.Addr // portcullis-vpn: the edge ports gateways connect to
	EdgeAddr                       netip.Addr // portcullis-vpn-edge: the only source Traefik trusts PROXY from
	Traefik                        netip.AddrPort
	Upstreams                      []string
	Domain                         string
	Mode                           string
	Metrics                        string // host:port, "" = off
	CoreSubnets                    []netip.Prefix
	// The edge's connection caps and pressure eviction (contract §16).
	MaxPerProvider, MaxPerUser, MaxPerClient, PressurePercent int
	PressureIdle                                              time.Duration
}

// edgeLimits reads WG_EDGE_MAX_PER_PROVIDER / _USER / _CLIENT,
// WG_EDGE_PRESSURE_PERCENT and WG_EDGE_PRESSURE_IDLE (defaults 1024, 128,
// 32, 90, 2m). Positive integers with client <= user <= provider, a
// percent 1–100, an idle of at least 1 s; anything else refuses the start.
func edgeLimits(getenv func(string) string, c *config) error {
	num := func(k string, def int) (int, error) {
		n, err := strconv.Atoi(envOr(getenv, k, strconv.Itoa(def)))
		if err != nil || n < 1 {
			return 0, fmt.Errorf("%s must be a positive integer", k)
		}
		return n, nil
	}
	var err error
	if c.MaxPerProvider, err = num("WG_EDGE_MAX_PER_PROVIDER", edge.DefaultMaxPerProvider); err != nil {
		return err
	}
	if c.MaxPerUser, err = num("WG_EDGE_MAX_PER_USER", edge.DefaultMaxPerUser); err != nil {
		return err
	}
	if c.MaxPerClient, err = num("WG_EDGE_MAX_PER_CLIENT", edge.DefaultMaxPerClient); err != nil {
		return err
	}
	if c.MaxPerClient > c.MaxPerUser || c.MaxPerUser > c.MaxPerProvider {
		return errors.New("WG_EDGE_MAX_PER_CLIENT <= WG_EDGE_MAX_PER_USER <= WG_EDGE_MAX_PER_PROVIDER")
	}
	if c.PressurePercent, err = num("WG_EDGE_PRESSURE_PERCENT", edge.DefaultPressurePercent); err != nil || c.PressurePercent > 100 {
		return errors.New("WG_EDGE_PRESSURE_PERCENT must be 1–100")
	}
	d, err := time.ParseDuration(envOr(getenv, "WG_EDGE_PRESSURE_IDLE", edge.DefaultPressureIdle.String()))
	if err != nil || d < time.Second {
		return errors.New("WG_EDGE_PRESSURE_IDLE must be a duration of at least 1s")
	}
	c.PressureIdle = d
	return nil
}

func loadConfig(getenv func(string) string) (*config, error) {
	c := &config{
		VPNFile:    envOr(getenv, "WG_VPN_FILE", "/vpn-doc/vpn.json"),
		StatusFile: envOr(getenv, "WG_STATUS_FILE", "/data/status.json"),
		PeopleKey:  envOr(getenv, "WG_PEOPLE_KEY", "/run/portcullis/wg/people.key"),
		Domain:     strings.ToLower(strings.TrimSpace(getenv("WG_DOMAIN"))),
	}
	switch v := envOr(getenv, "WG_PEOPLE", "off"); v {
	case "on":
		c.People = true
	case "off":
	default:
		return nil, errors.New("WG_PEOPLE must be on or off")
	}
	p, err := strconv.Atoi(envOr(getenv, "WG_PORT", "51820"))
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("WG_PORT must be a port number")
	}
	c.Port = p
	sn, err := netip.ParsePrefix(envOr(getenv, "WG_SUBNET", "10.213.0.0/22"))
	if err != nil || !sn.Addr().Is4() || sn.Masked() != sn || sn.Bits() < 8 || sn.Bits() > 30 {
		return nil, errors.New("WG_SUBNET must be an IPv4 network between /8 and /30")
	}
	c.Subnet = sn
	// WG_ADDR_MODE (K7): docker (the default) — the edge ports, the PROXY
	// source and the metrics each on their own network, so their addresses
	// must differ; pod (Kubernetes) — one pod address for every role, kept
	// apart by NetworkPolicies, so WG_VPN_ADDR and WG_EDGE_ADDR are both the
	// pod's IP and must be equal. Anything else refuses the start.
	switch m := envOr(getenv, "WG_ADDR_MODE", "docker"); m {
	case "docker", "pod":
		c.AddrMode = m
	default:
		return nil, errors.New("WG_ADDR_MODE must be docker or pod")
	}
	a, err := netip.ParseAddr(getenv("WG_VPN_ADDR"))
	if err != nil || !a.Is4() {
		if c.AddrMode == "pod" {
			return nil, errors.New("WG_VPN_ADDR must be the pod's IPv4 address (WG_ADDR_MODE=pod)")
		}
		return nil, errors.New("WG_VPN_ADDR must be wg's IPv4 address on portcullis-vpn")
	}
	c.VPNAddr = a
	ea, err := netip.ParseAddr(getenv("WG_EDGE_ADDR"))
	if c.AddrMode == "pod" {
		if err != nil || ea != a {
			return nil, errors.New("WG_EDGE_ADDR must be the pod's IPv4 address, = WG_VPN_ADDR (WG_ADDR_MODE=pod)")
		}
	} else if err != nil || !ea.Is4() || ea == a {
		return nil, errors.New("WG_EDGE_ADDR must be wg's IPv4 address on portcullis-vpn-edge (not its portcullis-vpn one)")
	}
	c.EdgeAddr = ea
	tr, err := netip.ParseAddrPort(getenv("WG_TRAEFIK"))
	if err != nil || !tr.Addr().Is4() {
		return nil, errors.New("WG_TRAEFIK must be Traefik's vpnsecure <ipv4>:<port> on portcullis-vpn-edge")
	}
	c.Traefik = tr
	ups, err := resolver.Upstreams(envOr(getenv, "WG_DNS_UPSTREAM", "1.1.1.1,9.9.9.9"))
	if err != nil {
		return nil, errors.New("WG_DNS_UPSTREAM must be a comma-separated list of IP addresses")
	}
	c.Upstreams = ups
	for _, f := range strings.Fields(getenv("WG_CORE_SUBNETS")) {
		pr, err := netip.ParsePrefix(f)
		if err != nil || !pr.Addr().Is4() {
			return nil, errors.New("WG_CORE_SUBNETS must be IPv4 networks, space-separated")
		}
		c.CoreSubnets = append(c.CoreSubnets, pr.Masked())
	}
	switch m := envOr(getenv, "WG_MODE", "apps"); m {
	case "apps", "admin", "server":
		c.Mode = m
	default:
		return nil, errors.New("WG_MODE must be apps, admin or server")
	}
	if c.People && c.Domain == "" {
		return nil, errors.New("WG_DOMAIN is required with WG_PEOPLE=on")
	}
	switch m := envOr(getenv, "WG_METRICS", "wg-metrics:9100"); m {
	case "off":
	default:
		h, port, err := net.SplitHostPort(m)
		if err != nil || h == "" {
			return nil, errors.New("WG_METRICS must be <host>:<port> or off")
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("WG_METRICS must be <host>:<port> or off")
		}
		c.Metrics = m
	}
	if err := edgeLimits(getenv, c); err != nil {
		return nil, err
	}
	return c, nil
}

// metricsAddr picks the metrics listen address: the one address the host
// part (the alias wg has on portcullis-metrics-wg, shared with Prometheus
// only) resolves to, which must be one of the container's own, never
// loopback and never one of never (the portcullis-vpn address, where
// gateways sit, and the edge one).
func metricsAddr(hostport string, lookup func(string) ([]netip.Addr, error), local []netip.Addr, never ...netip.Addr) (netip.AddrPort, error) {
	h, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.AddrPortFrom(netip.Addr{}, 0), err
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ips, err := lookup(h)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var v4 []netip.Addr
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			v4 = append(v4, ip.Unmap())
		}
	}
	if len(v4) != 1 {
		return netip.AddrPort{}, fmt.Errorf("%s resolves to %d IPv4 addresses, want 1", h, len(v4))
	}
	ip := v4[0]
	if ip.IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("%s resolves to an address metrics may not use", h)
	}
	for _, n := range never {
		if ip == n {
			return netip.AddrPort{}, fmt.Errorf("%s resolves to an address metrics may not use", h)
		}
	}
	for _, l := range local {
		if l == ip {
			return netip.AddrPortFrom(ip, uint16(n)), nil
		}
	}
	return netip.AddrPort{}, fmt.Errorf("%s isn't an address of this container", h)
}

// metricsNever — the addresses metrics may not bind to: the portcullis-vpn
// and edge ones under docker (gateways sit there); none under pod mode,
// where the pod has one address and only Prometheus may reach :9100 (its
// NetworkPolicy).
func metricsNever(cfg *config) []netip.Addr {
	if cfg.AddrMode == "pod" {
		return nil
	}
	return []netip.Addr{cfg.VPNAddr, cfg.EdgeAddr}
}

func localAddrs() []netip.Addr {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range as {
		if ipn, ok := a.(*net.IPNet); ok {
			if x, ok := netip.AddrFromSlice(ipn.IP); ok {
				out = append(out, x.Unmap())
			}
		}
	}
	return out
}

func lookupIPs(h string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", h)
}

// serve runs the roles until ctx ends.
func serve(ctx context.Context, cfg *config) error {
	// No provider may claim a core network's addresses (vpn.json refused).
	vpndoc.Reserve(cfg.CoreSubnets...)
	var doc atomic.Pointer[vpndoc.Doc]
	var docErr atomic.Value // string
	docErr.Store("vpn.json: not read yet")

	// Connections to Traefik leave from the edge network's address: the
	// only one vpnsecure trusts PROXY headers from (gateways can't reach
	// that network at all).
	e := edge.New(cfg.Traefik, cfg.EdgeAddr, doc.Load, time.Now)
	e.MaxPerProvider, e.MaxPerUser, e.MaxPerClient = cfg.MaxPerProvider, cfg.MaxPerUser, cfg.MaxPerClient
	e.PressurePercent, e.PressureIdle = cfg.PressurePercent, cfg.PressureIdle

	reg := prometheus.NewRegistry()
	reg.MustRegister(e.Collectors()...)
	staleG := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "wg_provider_stale", Help: "1 while a wired provider's device map is stale."}, []string{"provider"})
	roleUp := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "wg_role_up", Help: "1 while the role is up."}, []string{"role"})
	peersG := prometheus.NewGauge(prometheus.GaugeOpts{Name: "wg_people_peers", Help: "Configured built-in peers."})
	restricted := prometheus.NewGauge(prometheus.GaugeOpts{Name: "wg_mode_restricted", Help: "1 when the VPN mode isn't apps."})
	reg.MustRegister(staleG, roleUp, peersG, restricted)
	if cfg.Mode != "apps" {
		restricted.Set(1)
	}

	listeners := newEdgeListeners(ctx, e, cfg.VPNAddr)

	// The people role.
	var role *people.Role
	var peopleErr atomic.Value // string: a start failure
	peopleErr.Store("")
	var stack *tunnel.Stack
	peopleOn := false
	if cfg.People {
		key, on, err := people.LoadKey(cfg.PeopleKey)
		switch {
		case err != nil:
			peopleOn = true
			peopleErr.Store(err.Error())
		case on:
			peopleOn = true
			s, err := tunnel.New(tunnel.Config{PrivateKey: key, ListenPort: cfg.Port, Address: cfg.Subnet.Addr().Next(), MTU: 1280})
			if err != nil {
				peopleErr.Store(err.Error())
			} else {
				stack = s
				defer s.Close()
				role = people.NewRole(s, cfg.Subnet, time.Now)
			}
		}
	}

	onDoc := func(d *vpndoc.Doc, err error) {
		if err != nil {
			doc.Store(nil)
			docErr.Store(err.Error())
			log.Printf("wg: %v: every VPN connection is refused", err)
		} else {
			doc.Store(d)
			docErr.Store("")
		}
		listeners.sync(d)
		if role != nil {
			role.SetDoc(d, err)
		}
		// Admitted connections are re-checked against every reload (and
		// every 2 s by e.Run): a revoked, expired or stale device, or no
		// document at all, closes them.
		e.Revalidate()
	}
	w := &vpndoc.Watcher{Path: cfg.VPNFile, Every: 2 * time.Second}
	go w.Run(ctx, onDoc)
	go e.Run(ctx, 2*time.Second)

	if role != nil {
		go role.Run(ctx, time.Second)
		srv := &resolver.ServerAddrs{Apex: cfg.Domain, Upstreams: cfg.Upstreams}
		go srv.Run(ctx, func(err error) { log.Printf("wg: %v", err) })
		self := cfg.Subnet.Addr().Next()
		fw := &resolver.Forwarder{Upstreams: cfg.Upstreams, Rewriter: func() *resolver.Rewriter {
			domains := []string{cfg.Domain}
			if d := doc.Load(); d != nil && d.Builtin != nil {
				domains = append(domains, d.Builtin.Domains...)
			}
			return &resolver.Rewriter{Domains: domains, Server: srv.Get(), Self: self}
		}}
		go func() {
			if err := role.Serve(ctx, e, fw); err != nil {
				peopleErr.Store(err.Error())
				log.Printf("wg: %v", err)
			}
		}()
	}

	if cfg.Metrics != "" {
		go serveMetrics(ctx, cfg, reg)
	}

	build := func() status.Doc {
		d := doc.Load()
		now := time.Now()
		if d != nil && listeners.err() != "" {
			listeners.sync(d) // retry a failed bind
		}
		st := status.Doc{Mode: cfg.Mode}
		if d == nil {
			st.Edge = status.Role{OK: false, Error: docErr.Load().(string)}
		} else if !d.Valid(now) {
			st.Edge = status.Role{OK: false, Error: "vpn.json: past valid_until (the Hub hasn't republished it)"}
		} else if lerr := listeners.err(); lerr != "" {
			st.Edge = status.Role{OK: false, Error: lerr}
		} else {
			st.Edge = status.Role{OK: true}
		}
		staleG.Reset()
		if d != nil {
			for i := range d.Providers {
				p := &d.Providers[i]
				v := 0.0
				if !p.Fresh(now) {
					v = 1
				}
				staleG.WithLabelValues(p.ID).Set(v)
			}
		}
		roleUp.WithLabelValues("edge").Set(b2f(st.Edge.OK))
		if peopleOn {
			p := &status.People{Port: cfg.Port, Subnet: cfg.Subnet.String(), MTU: 1280}
			if stack != nil {
				p.PublicKey = stack.PublicKey()
			}
			if msg := peopleErr.Load().(string); msg != "" {
				p.Role = status.Role{OK: false, Error: msg}
			} else if role != nil {
				ok, msg := role.Status()
				p.Role = status.Role{OK: ok, Error: msg}
				p.Peers = role.Peers()
			}
			st.People = p
			roleUp.WithLabelValues("people").Set(b2f(p.OK))
			peersG.Set(float64(len(p.Peers)))
		}
		return st
	}
	if err := status.CheckDir(filepath.Dir(cfg.StatusFile)); err != nil {
		log.Printf("wg: %v", err)
	}
	status.Run(ctx, cfg.StatusFile, status.Interval, build, time.Now, func(err error) {
		log.Printf("wg: writing the status file failed: %v", err)
	})
	return nil
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func serveMetrics(ctx context.Context, cfg *config, reg *prometheus.Registry) {
	var addr netip.AddrPort
	var err error
	for i := 0; i < 30; i++ {
		addr, err = metricsAddr(cfg.Metrics, lookupIPs, localAddrs(), metricsNever(cfg)...)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		log.Printf("wg: metrics off: %v", err)
		return
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr.String(), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("wg: metrics: %v", err)
	}
}

// edgeListeners keeps one listener per wired provider on
// <vpn addr>:<edge_port>, re-bound when the document changes.
type edgeListeners struct {
	ctx  context.Context
	e    *edge.Edge
	addr netip.Addr

	mu     sync.Mutex
	open   map[string]*edgeListener // provider id
	errors map[string]string
}

type edgeListener struct {
	port   int
	cancel context.CancelFunc
}

func newEdgeListeners(ctx context.Context, e *edge.Edge, addr netip.Addr) *edgeListeners {
	return &edgeListeners{ctx: ctx, e: e, addr: addr, open: map[string]*edgeListener{}, errors: map[string]string{}}
}

func (l *edgeListeners) sync(d *vpndoc.Doc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	want := map[string]int{}
	if d != nil {
		for _, p := range d.Providers {
			if p.ID != vpndoc.BuiltinID {
				want[p.ID] = p.EdgePort
			}
		}
	} else {
		// No document: keep the listeners (they refuse with no_doc).
		return
	}
	for id, ol := range l.open {
		if port, ok := want[id]; !ok || port != ol.port {
			ol.cancel()
			delete(l.open, id)
		}
	}
	for id := range l.errors {
		if _, ok := want[id]; !ok {
			delete(l.errors, id)
		}
	}
	for id, port := range want {
		if _, ok := l.open[id]; ok {
			continue
		}
		ln, err := net.Listen("tcp4", netip.AddrPortFrom(l.addr, uint16(port)).String())
		if err != nil {
			l.errors[id] = fmt.Sprintf("edge: listening on port %d for %s failed", port, id)
			log.Printf("wg: %s", l.errors[id])
			continue
		}
		delete(l.errors, id)
		ctx, cancel := context.WithCancel(l.ctx)
		l.open[id] = &edgeListener{port: port, cancel: cancel}
		go l.e.ServeProvider(ctx, ln, id)
	}
}

func (l *edgeListeners) err() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.errors {
		return e
	}
	return ""
}
