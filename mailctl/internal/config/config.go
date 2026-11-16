// Package config reads mailctl's environment (integration contract §19).
// Every value is checked here: a missing required value or a bad one is an
// error naming the variable, and mailctl refuses to start (fail closed).
package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Client address modes (MAILCTL_CLIENT_IP, contract §19.8).
const (
	ClientIPPreserved = "preserved"
	ClientIPRewritten = "rewritten"
)

// Relay is the optional smarthost (MAIL_RELAY_*). Its password is a file
// only `mail` reads (secrets/mail/relay-password); mailctl never holds it.
type Relay struct {
	Host       string
	Port       int
	Username   string
	SPFInclude string
}

// Config is mailctl's whole environment.
type Config struct {
	APIAddr       string       // MAILCTL_API_ADDR: the Hub API (":8080")
	APISubnet     netip.Prefix // MAILCTL_API_SUBNET: the portcullis-mailctl subnet
	HubSecretFile string       // MAILCTL_HUB_SECRET_FILE
	// MetricsSecretFile is the metrics scrape password (Basic auth,
	// user prometheus): MAILCTL_METRICS_SECRET_FILE.
	MetricsSecretFile string
	APIKeyFile        string // MAILCTL_API_KEY_FILE: Stalwart's API key
	DQSKeyFile        string // MAILCTL_DQS_KEY_FILE (empty file = no DQS key)

	StalwartURL    string // MAILCTL_STALWART_URL: the management listener
	WellKnownAddr  string // MAILCTL_WELLKNOWN_ADDR (":8081", behind Traefik)
	WellKnownEntry []string
	RulesAddr      string     // MAILCTL_RULES_ADDR: the spam rules, on portcullis-mail only
	MailIP         netip.Addr // mailctl's portcullis-mail address (RulesAddr's host)
	MetricsAddr    string     // MAILCTL_METRICS_ADDR
	DataDir        string     // MAILCTL_DATA
	LocalResolver  string     // MAILCTL_LOCAL_RESOLVER: mail-resolver, ip:port
	Resolvers      []string   // MAILCTL_RESOLVERS: the public resolvers, ip:port

	ClientIP     string // MAILCTL_CLIENT_IP: preserved | rewritten
	Hostname     string // MAIL_HOSTNAME
	MainDomain   string // PORTCULLIS_DOMAIN
	DKIMRotate   time.Duration
	FormerRetain time.Duration
	LANOnly      bool // MAIL_SUBMISSION_LAN_ONLY

	Relay *Relay // nil without MAIL_RELAY_HOST

	PublicIPv4 netip.Addr // MAILCTL_PUBLIC_IPV4, else DOMAINS_PUBLIC_IPV4 (may be unset)
	PublicIPv6 netip.Addr // MAILCTL_PUBLIC_IPV6, else DOMAINS_PUBLIC_IPV6 (may be unset)
}

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

func duration(env func(string) string, k, def string) (time.Duration, error) {
	v := get(env, k, def)
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s=%q is not a positive duration (e.g. 720h)", k, v)
	}
	return d, nil
}

func boolTF(env func(string) string, k string) (bool, error) {
	switch v := get(env, k, "false"); v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q must be true or false", k, v)
	}
}

func onOff(env func(string) string, k string) (bool, error) {
	switch v := get(env, k, "off"); v {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s=%q must be on or off", k, v)
	}
}

func publicIP(env func(string) string, own, domains string, want4 bool) (netip.Addr, error) {
	k, v := own, strings.TrimSpace(env(own))
	if v == "" {
		k, v = domains, strings.TrimSpace(env(domains))
	}
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
	sub, err := required(env, "MAILCTL_API_SUBNET")
	if err != nil {
		return c, err
	}
	c.APISubnet, err = netip.ParsePrefix(sub)
	if err != nil || !c.APISubnet.Addr().Is4() || c.APISubnet.Masked() != c.APISubnet {
		return c, fmt.Errorf("MAILCTL_API_SUBNET=%q is not an IPv4 network (e.g. 172.31.255.16/28)", sub)
	}
	c.HubSecretFile = get(env, "MAILCTL_HUB_SECRET_FILE", "/run/portcullis/mail/hub-secret")
	c.MetricsSecretFile = get(env, "MAILCTL_METRICS_SECRET_FILE", "/run/portcullis/mail/metrics-secret")
	c.APIKeyFile = get(env, "MAILCTL_API_KEY_FILE", "/run/portcullis/mail/api-key")
	c.DQSKeyFile = get(env, "MAILCTL_DQS_KEY_FILE", "/run/portcullis/mail/dqs-key")

	c.StalwartURL = get(env, "MAILCTL_STALWART_URL", "http://172.31.255.2:8080")
	if !strings.HasPrefix(c.StalwartURL, "http://") || strings.ContainsAny(c.StalwartURL, " \t\n") {
		return c, fmt.Errorf("MAILCTL_STALWART_URL=%q is not an http:// URL", c.StalwartURL)
	}
	c.StalwartURL = strings.TrimSuffix(c.StalwartURL, "/")
	c.WellKnownAddr = get(env, "MAILCTL_WELLKNOWN_ADDR", ":8081")
	if err := listenAddr("MAILCTL_WELLKNOWN_ADDR", c.WellKnownAddr); err != nil {
		return c, err
	}
	for _, e := range strings.Split(get(env, "MAILCTL_WELLKNOWN_ENTRYPOINTS", "websecure,vpnsecure"), ",") {
		if e = strings.TrimSpace(e); e != "" {
			c.WellKnownEntry = append(c.WellKnownEntry, e)
		}
	}
	c.RulesAddr = get(env, "MAILCTL_RULES_ADDR", "172.31.255.3:8082")
	rules, err := hostPort("MAILCTL_RULES_ADDR", c.RulesAddr)
	if err != nil || !rules.Addr().Is4() {
		return c, fmt.Errorf("MAILCTL_RULES_ADDR=%q is not mailctl's portcullis-mail IPv4 ip:port", c.RulesAddr)
	}
	c.MailIP = rules.Addr()
	c.MetricsAddr = get(env, "MAILCTL_METRICS_ADDR", "mailctl-metrics:9100")
	if err := listenAddr("MAILCTL_METRICS_ADDR", c.MetricsAddr); err != nil {
		return c, err
	}
	c.DataDir = get(env, "MAILCTL_DATA", "/data")
	lr, err := required(env, "MAILCTL_LOCAL_RESOLVER")
	if err != nil {
		return c, err
	}
	if _, err := hostPort("MAILCTL_LOCAL_RESOLVER", lr); err != nil {
		return c, err
	}
	c.LocalResolver = lr
	for _, r := range strings.Fields(get(env, "MAILCTL_RESOLVERS", "1.1.1.1:53 8.8.8.8:53")) {
		if _, err := hostPort("MAILCTL_RESOLVERS", r); err != nil {
			return c, err
		}
		c.Resolvers = append(c.Resolvers, r)
	}

	if c.ClientIP, err = required(env, "MAILCTL_CLIENT_IP"); err != nil {
		return c, err
	}
	if c.ClientIP != ClientIPPreserved && c.ClientIP != ClientIPRewritten {
		return c, fmt.Errorf("MAILCTL_CLIENT_IP=%q must be preserved or rewritten", c.ClientIP)
	}
	main, err := required(env, "PORTCULLIS_DOMAIN")
	if err != nil {
		return c, err
	}
	c.MainDomain = strings.ToLower(strings.TrimSuffix(main, "."))
	if !validHostname(c.MainDomain) {
		return c, fmt.Errorf("PORTCULLIS_DOMAIN=%q is not a valid domain", main)
	}
	host, err := required(env, "MAIL_HOSTNAME")
	if err != nil {
		return c, err
	}
	c.Hostname = strings.ToLower(strings.TrimSuffix(host, "."))
	if !validHostname(c.Hostname) || !strings.Contains(c.Hostname, ".") {
		return c, fmt.Errorf("MAIL_HOSTNAME=%q is not a valid host name", host)
	}
	if c.DKIMRotate, err = duration(env, "MAIL_DKIM_ROTATE", "4320h"); err != nil {
		return c, err
	}
	if c.FormerRetain, err = duration(env, "MAIL_FORMER_RETENTION", "720h"); err != nil {
		return c, err
	}
	if c.LANOnly, err = boolTF(env, "MAIL_SUBMISSION_LAN_ONLY"); err != nil {
		return c, err
	}
	// IPv6 for mail isn't supported yet (published [::] ports go through
	// docker-proxy, which rewrites client addresses): refused, not ignored.
	if strings.TrimSpace(env("MAIL_IPV6")) != "" {
		return c, fmt.Errorf("MAIL_IPV6 isn't supported yet")
	}

	if h := strings.TrimSpace(env("MAIL_RELAY_HOST")); h != "" {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if !validHostname(h) {
			if _, err := netip.ParseAddr(h); err != nil {
				return c, fmt.Errorf("MAIL_RELAY_HOST=%q is not a host name or an address", h)
			}
		}
		r := &Relay{Host: h, Username: strings.TrimSpace(env("MAIL_RELAY_USERNAME")), SPFInclude: strings.TrimSpace(env("MAIL_RELAY_SPF_INCLUDE"))}
		p := get(env, "MAIL_RELAY_PORT", "465")
		if r.Port, err = strconv.Atoi(p); err != nil || r.Port < 1 || r.Port > 65535 {
			return c, fmt.Errorf("MAIL_RELAY_PORT=%q is not a port", p)
		}
		if r.SPFInclude != "" && !validHostname(strings.ToLower(r.SPFInclude)) {
			return c, fmt.Errorf("MAIL_RELAY_SPF_INCLUDE=%q is not a domain", r.SPFInclude)
		}
		c.Relay = r
	} else {
		for _, k := range []string{"MAIL_RELAY_PORT", "MAIL_RELAY_USERNAME", "MAIL_RELAY_SPF_INCLUDE"} {
			if strings.TrimSpace(env(k)) != "" {
				return c, fmt.Errorf("%s is set but MAIL_RELAY_HOST isn't", k)
			}
		}
	}

	if c.PublicIPv4, err = publicIP(env, "MAILCTL_PUBLIC_IPV4", "DOMAINS_PUBLIC_IPV4", true); err != nil {
		return c, err
	}
	if c.PublicIPv6, err = publicIP(env, "MAILCTL_PUBLIC_IPV6", "DOMAINS_PUBLIC_IPV6", false); err != nil {
		return c, err
	}
	return c, nil
}
