// Package config reads the adapter's environment (integration contract §19.4).
// Every value is checked here: a missing required value or a bad one is an
// error naming the variable, and mailctl refuses to start (fail closed).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the adapter's whole environment. The PORTCULLIS_MAIL_* values
// come from the Hub's override of the wired instance (contract §19.4); the
// MAILCTL_* ones are the stalwart template's own wiring. Everything the
// Hub decides per server (the host name, LAN-only, the relay, the client
// address mode, the DKIM rotation, the former retention) is MailState v2.
type Config struct {
	APIAddr   string       // MAILCTL_API_ADDR: the provider API (":8080")
	APISubnet netip.Prefix // PORTCULLIS_MAIL_API_SUBNET: portcullis-mail-api
	HubIP     netip.Addr   // PORTCULLIS_MAIL_API_HUB_IP (optional; inside the subnet)
	// SlotDir is the provider slot (PORTCULLIS_MAIL_SLOT_DIR, core's mail_provider_slot volume): the
	// gate, api-secret, metrics-secret, relay-password.
	SlotDir string
	TLSDir  string // PORTCULLIS_MAIL_TLS_DIR: fullchain.pem, privkey.pem
	// VoidSession is PORTCULLIS_MAIL_VOID_SESSION, byte for byte (void mode only).
	VoidSession string

	// APIKeyFile is Stalwart's API key (MAILCTL_API_KEY_FILE, default
	// <data>/api-key; Ruling T17-d): the bootstrap job writes it 0640, the
	// adapter reads it.
	APIKeyFile string
	DQSKeyFile string // STALWART_DQS_KEY_FILE: the template's dqs_key setting ("" = none)

	StalwartURL    string // MAILCTL_STALWART_URL: the management listener
	WellKnownAddr  string // MAILCTL_WELLKNOWN_ADDR (":8081", behind the Hub's router)
	WellKnownEntry []string
	RulesAddr      string     // MAILCTL_RULES_ADDR: the spam rules, on the template's internal network
	MailIP         netip.Addr // the adapter's internal address (RulesAddr's host)
	MetricsAddr    string     // MAILCTL_METRICS_ADDR
	DataDir        string     // MAILCTL_DATA
	LocalResolver  string     // MAILCTL_LOCAL_RESOLVER: the template's resolver, ip:port
	Resolvers      []string   // MAILCTL_RESOLVERS: the public resolvers, ip:port

	PublicIPv4 netip.Addr // PORTCULLIS_MAIL_PUBLIC_IPV4: core's detected address, passed by the Hub (empty: the address checks are unknown)
	PublicIPv6 netip.Addr // PORTCULLIS_MAIL_PUBLIC_IPV6

	// The read-only admin view (contract §19.13), the bootstrap job only
	// (LoadJob): where the viewer's password goes (MAILCTL_VIEWER_SECRET_FILE,
	// "" = no admin view) and the admin-view proxy's internal address
	// (MAILCTL_ADMINVIEW_IP), the only client of the admin-view listener.
	ViewerSecretFile string
	ViewerIP         netip.Addr

	JobSessionFile string // the bootstrap job only (LoadJob)
	// JobLocalURL is how the bootstrap job reaches the server it runs in
	// its own container: loopback only (MAILCTL_JOB_LOCAL_URL, Ruling
	// T17-b); the job never dials StalwartURL.
	JobLocalURL string
	// StoreDir is the server's store volume in the job (MAILCTL_STORE_DIR,
	// required): the base plan's marker and the job's lock (Ruling T17-c).
	StoreDir    string
	ServerImage string // the bootstrap job only (LoadJob)
}

// The slot's files (contract §19.1).
func (c Config) APISecretFile() string     { return filepath.Join(c.SlotDir, "api-secret") }
func (c Config) MetricsSecretFile() string { return filepath.Join(c.SlotDir, "metrics-secret") }
func (c Config) RelayPasswordFile() string { return filepath.Join(c.SlotDir, "relay-password") }

func get(env func(string) string, k, def string) string {
	if v := strings.TrimSpace(env(k)); v != "" {
		return v
	}
	return def
}

func required(env func(string) string, k string) (string, error) {
	v := strings.TrimSpace(env(k))
	if v == "" {
		return "", fmt.Errorf("%s is required", k)
	}
	return v, nil
}

// hostPort checks an "ip:port" (host an IP literal, port 1-65535).
func hostPort(k, v string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(v)
	if err != nil || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s=%q is not an ip:port", k, v)
	}
	return ap, nil
}

// listenAddr checks a listen address "[host]:port" (host optional, a name
// allowed: the metrics alias resolves to its network's address).
func listenAddr(k, v string) error {
	h, p, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("%s=%q is not a [host]:port", k, v)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s=%q has no valid port", k, v)
	}
	if h != "" && !validHostname(h) {
		if _, err := netip.ParseAddr(h); err != nil {
			return fmt.Errorf("%s=%q has an invalid host", k, v)
		}
	}
	return nil
}

func validHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func publicIP(env func(string) string, k string, want4 bool) (netip.Addr, error) {
	v := strings.TrimSpace(env(k))
	if v == "" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(v)
	if err != nil || ip.Is4() != want4 || ip.Is4In6() || ip.Zone() != "" {
		fam := "6"
		if want4 {
			fam = "4"
		}
		return netip.Addr{}, fmt.Errorf("%s=%q is not an IPv%s address", k, v, fam)
	}
	return ip, nil
}

// Load reads and checks the environment.
func Load(env func(string) string) (Config, error) {
	var c Config
	var err error

	c.APIAddr = get(env, "MAILCTL_API_ADDR", ":8080")
	if err := listenAddr("MAILCTL_API_ADDR", c.APIAddr); err != nil {
		return c, err
	}
	sub, err := required(env, "PORTCULLIS_MAIL_API_SUBNET")
	if err != nil {
		return c, err
	}
	c.APISubnet, err = netip.ParsePrefix(sub)
	if err != nil || !c.APISubnet.Addr().Is4() || c.APISubnet.Masked() != c.APISubnet {
		return c, fmt.Errorf("PORTCULLIS_MAIL_API_SUBNET=%q is not an IPv4 network (e.g. 172.31.255.16/28)", sub)
	}
	if h := strings.TrimSpace(env("PORTCULLIS_MAIL_API_HUB_IP")); h != "" {
		if c.HubIP, err = netip.ParseAddr(h); err != nil || !c.APISubnet.Contains(c.HubIP) {
			return c, fmt.Errorf("PORTCULLIS_MAIL_API_HUB_IP=%q is not an address inside %s", h, c.APISubnet)
		}
	}
	for _, d := range []struct {
		k, def string
		dst    *string
	}{{"PORTCULLIS_MAIL_SLOT_DIR", "/run/portcullis/mail/slot", &c.SlotDir}, {"PORTCULLIS_MAIL_TLS_DIR", "/run/portcullis/mail/tls", &c.TLSDir}} {
		*d.dst = get(env, d.k, d.def)
		if !filepath.IsAbs(*d.dst) {
			return c, fmt.Errorf("%s=%q is not an absolute path", d.k, *d.dst)
		}
	}
	c.VoidSession = env("PORTCULLIS_MAIL_VOID_SESSION")
	for _, e := range strings.Split(get(env, "PORTCULLIS_MAIL_WELLKNOWN_ENTRYPOINTS", ""), ",") {
		if e = strings.TrimSpace(e); e != "" {
			c.WellKnownEntry = append(c.WellKnownEntry, e)
		}
	}
	c.DQSKeyFile = strings.TrimSpace(env("STALWART_DQS_KEY_FILE"))
	if c.DQSKeyFile != "" && !filepath.IsAbs(c.DQSKeyFile) {
		return c, fmt.Errorf("STALWART_DQS_KEY_FILE=%q is not an absolute path", c.DQSKeyFile)
	}

	if err := loadOwn(env, &c); err != nil {
		return c, err
	}
	return c, nil
}

// LoadJob reads the bootstrap job's environment: the template's own
// wiring only (the job isn't one of the mail: block's services, so it gets
// no PORTCULLIS_MAIL_* value), plus MAILCTL_JOB_SESSION_FILE (a job-only
// tmpfs path) and MAILCTL_SERVER_IMAGE (the pinned server image).
func LoadJob(env func(string) string) (Config, error) {
	var c Config
	if err := loadOwn(env, &c); err != nil {
		return c, err
	}
	c.JobSessionFile = strings.TrimSpace(env("MAILCTL_JOB_SESSION_FILE"))
	if c.JobSessionFile != "" && !filepath.IsAbs(c.JobSessionFile) {
		return c, fmt.Errorf("MAILCTL_JOB_SESSION_FILE=%q is not an absolute path", c.JobSessionFile)
	}
	c.StoreDir = strings.TrimSpace(env("MAILCTL_STORE_DIR"))
	if c.StoreDir == "" {
		return c, errors.New("MAILCTL_STORE_DIR is required (the server's store volume in the job)")
	}
	if !filepath.IsAbs(c.StoreDir) || filepath.Clean(c.StoreDir) != c.StoreDir || c.StoreDir == "/" {
		return c, fmt.Errorf("MAILCTL_STORE_DIR=%q is not a clean absolute directory", c.StoreDir)
	}
	c.JobLocalURL = get(env, "MAILCTL_JOB_LOCAL_URL", "http://127.0.0.1:8080")
	if !plainHTTPURL(c.JobLocalURL, true) {
		return c, fmt.Errorf("MAILCTL_JOB_LOCAL_URL=%q is not http://<loopback ip>:<port>", c.JobLocalURL)
	}
	c.ViewerSecretFile = strings.TrimSpace(env("MAILCTL_VIEWER_SECRET_FILE"))
	if c.ViewerSecretFile != "" {
		if !filepath.IsAbs(c.ViewerSecretFile) || filepath.Clean(c.ViewerSecretFile) != c.ViewerSecretFile {
			return c, fmt.Errorf("MAILCTL_VIEWER_SECRET_FILE=%q is not a clean absolute file path", c.ViewerSecretFile)
		}
		v := get(env, "MAILCTL_ADMINVIEW_IP", "172.31.255.5")
		ip, err := netip.ParseAddr(v)
		if err != nil || !ip.Is4() {
			return c, fmt.Errorf("MAILCTL_ADMINVIEW_IP=%q is not an IPv4 address", v)
		}
		if ip == c.MailIP {
			return c, fmt.Errorf("MAILCTL_ADMINVIEW_IP=%q is the adapter's own address: the admin view has its own", v)
		}
		c.ViewerIP = ip
	}
	c.ServerImage = strings.TrimSpace(env("MAILCTL_SERVER_IMAGE"))
	if strings.ContainsAny(c.ServerImage, " \t\n") {
		return c, fmt.Errorf("MAILCTL_SERVER_IMAGE=%q is not an image reference", c.ServerImage)
	}
	return c, nil
}

// loadOwn reads the MAILCTL_* part.
func loadOwn(env func(string) string, c *Config) error {
	var err error
	c.StalwartURL = strings.TrimSuffix(get(env, "MAILCTL_STALWART_URL", "http://172.31.255.2:8080"), "/")
	if !plainHTTPURL(c.StalwartURL, false) {
		return fmt.Errorf("MAILCTL_STALWART_URL=%q is not http://<ip>:<port>", c.StalwartURL)
	}
	c.WellKnownAddr = get(env, "MAILCTL_WELLKNOWN_ADDR", ":8081")
	if err := listenAddr("MAILCTL_WELLKNOWN_ADDR", c.WellKnownAddr); err != nil {
		return err
	}
	c.RulesAddr = get(env, "MAILCTL_RULES_ADDR", "172.31.255.3:8082")
	rules, err := hostPort("MAILCTL_RULES_ADDR", c.RulesAddr)
	if err != nil || !rules.Addr().Is4() {
		return fmt.Errorf("MAILCTL_RULES_ADDR=%q is not the adapter's internal IPv4 ip:port", c.RulesAddr)
	}
	c.MailIP = rules.Addr()
	c.MetricsAddr = get(env, "MAILCTL_METRICS_ADDR", "mail-provider-metrics:9100")
	if err := listenAddr("MAILCTL_METRICS_ADDR", c.MetricsAddr); err != nil {
		return err
	}
	c.DataDir = get(env, "MAILCTL_DATA", "/data")
	if !filepath.IsAbs(c.DataDir) || filepath.Clean(c.DataDir) != c.DataDir {
		return fmt.Errorf("MAILCTL_DATA=%q is not a clean absolute path", c.DataDir)
	}
	c.APIKeyFile = get(env, "MAILCTL_API_KEY_FILE", filepath.Join(c.DataDir, "api-key"))
	if !filepath.IsAbs(c.APIKeyFile) || filepath.Clean(c.APIKeyFile) != c.APIKeyFile || strings.HasSuffix(env("MAILCTL_API_KEY_FILE"), "/") {
		return fmt.Errorf("MAILCTL_API_KEY_FILE=%q is not a clean absolute file path", c.APIKeyFile)
	}
	lr, err := required(env, "MAILCTL_LOCAL_RESOLVER")
	if err != nil {
		return err
	}
	if _, err := hostPort("MAILCTL_LOCAL_RESOLVER", lr); err != nil {
		return err
	}
	c.LocalResolver = lr
	for _, r := range strings.Fields(get(env, "MAILCTL_RESOLVERS", "1.1.1.1:53 8.8.8.8:53")) {
		if _, err := hostPort("MAILCTL_RESOLVERS", r); err != nil {
			return err
		}
		c.Resolvers = append(c.Resolvers, r)
	}
	if c.PublicIPv4, err = publicIP(env, "PORTCULLIS_MAIL_PUBLIC_IPV4", true); err != nil {
		return err
	}
	if c.PublicIPv6, err = publicIP(env, "PORTCULLIS_MAIL_PUBLIC_IPV6", false); err != nil {
		return err
	}
	return nil
}

// plainHTTPURL: exactly http://<ip literal>:<port> (lowercase scheme, no
// userinfo, path, query or fragment — the API key is sent there);
// loopback: the address must be a loopback one.
func plainHTTPURL(raw string, loopback bool) bool {
	if !strings.HasPrefix(raw, "http://") || strings.ContainsAny(raw, " \t\n?#@") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	ap, err := netip.ParseAddrPort(u.Host)
	return err == nil && ap.Port() != 0 && (!loopback || ap.Addr().IsLoopback())
}

// AdminView is `mailctl admin-view`'s configuration (contract §19.13):
// the read-only mail admin view's proxy, a service of its own.
type AdminView struct {
	Addr       string // MAILCTL_ADMINVIEW_ADDR: where Traefik reaches it (":8090")
	Upstream   string // MAILCTL_ADMINVIEW_UPSTREAM: Stalwart's admin-view listener (https://<ip>:<port>)
	Host       string // PORTCULLIS_MAIL_ADMIN_HOST: the admin view's hostname (the Hub's override)
	SecretFile string // MAILCTL_VIEWER_SECRET_FILE: the viewer's password
	// SPKIs: PORTCULLIS_MAIL_TLS_SPKI, the mail certificate's SPKI SHA-256
	// values (comma-separated hex, the Hub's override): the hop to
	// Stalwart is pinned to them.
	SPKIs []string
	// TraefikIP (PORTCULLIS_MAIL_ADMIN_TRAEFIK_IP) and RouteKey
	// (PORTCULLIS_MAIL_ADMIN_ROUTE_KEY), from the Hub's override: the only
	// client and the per-install key its router sets.
	TraefikIP netip.Addr
	RouteKey  string
}

// LoadAdminView reads the admin view's configuration; every value is
// checked (fail closed).
func LoadAdminView(env func(string) string) (AdminView, error) {
	var a AdminView
	a.Addr = get(env, "MAILCTL_ADMINVIEW_ADDR", ":8090")
	if err := listenAddr("MAILCTL_ADMINVIEW_ADDR", a.Addr); err != nil {
		return a, err
	}
	a.Upstream = strings.TrimSuffix(get(env, "MAILCTL_ADMINVIEW_UPSTREAM", "https://172.31.255.2:8443"), "/")
	u, err := url.Parse(a.Upstream)
	if err != nil || u.Scheme != "https" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Port() == "" {
		return a, fmt.Errorf("MAILCTL_ADMINVIEW_UPSTREAM=%q is not https://<ip>:<port>", a.Upstream)
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err != nil || !ip.Is4() {
		return a, fmt.Errorf("MAILCTL_ADMINVIEW_UPSTREAM=%q is not https://<ip>:<port>", a.Upstream)
	}
	a.Host = strings.ToLower(strings.TrimSpace(env("PORTCULLIS_MAIL_ADMIN_HOST")))
	if a.Host == "" {
		return a, errors.New("PORTCULLIS_MAIL_ADMIN_HOST is required (the Hub's override sets it on the wired provider)")
	}
	if !validHostname(a.Host) || !strings.Contains(a.Host, ".") {
		return a, fmt.Errorf("PORTCULLIS_MAIL_ADMIN_HOST=%q is not a hostname", a.Host)
	}
	a.SecretFile = get(env, "MAILCTL_VIEWER_SECRET_FILE", "")
	if a.SecretFile == "" || !filepath.IsAbs(a.SecretFile) || filepath.Clean(a.SecretFile) != a.SecretFile {
		return a, fmt.Errorf("MAILCTL_VIEWER_SECRET_FILE=%q is not a clean absolute file path", a.SecretFile)
	}
	for _, p := range strings.Split(env("PORTCULLIS_MAIL_TLS_SPKI"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			a.SPKIs = append(a.SPKIs, p)
		}
	}
	if len(a.SPKIs) == 0 {
		return a, errors.New("PORTCULLIS_MAIL_TLS_SPKI is required (the Hub's override sets the mail certificate's SPKI): the hop to the mail server is pinned to it")
	}
	tip := strings.TrimSpace(env("PORTCULLIS_MAIL_ADMIN_TRAEFIK_IP"))
	if a.TraefikIP, err = netip.ParseAddr(tip); err != nil || !a.TraefikIP.Is4() {
		return a, fmt.Errorf("PORTCULLIS_MAIL_ADMIN_TRAEFIK_IP=%q is not Traefik's IPv4 address (the Hub's override sets it)", tip)
	}
	a.RouteKey = strings.TrimSpace(env("PORTCULLIS_MAIL_ADMIN_ROUTE_KEY"))
	if len(a.RouteKey) < 32 || strings.Trim(a.RouteKey, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") != "" {
		return a, errors.New("PORTCULLIS_MAIL_ADMIN_ROUTE_KEY is required: 32+ letters and digits (the Hub's override sets it)")
	}
	return a, nil
}
