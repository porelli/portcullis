package config

import (
	"strings"
	"testing"
	"time"
)

func base() map[string]string {
	return map[string]string{
		"MAILCTL_API_SUBNET":     "172.31.255.16/28",
		"MAILCTL_LOCAL_RESOLVER": "172.31.255.4:5353",
		"MAILCTL_CLIENT_IP":      "preserved",
		"MAIL_HOSTNAME":          "mail.example.com",
		"PORTCULLIS_DOMAIN":      "example.com",
	}
}

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(envOf(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.APIAddr != ":8080" || c.WellKnownAddr != ":8081" || c.RulesAddr != "172.31.255.3:8082" ||
		c.MetricsAddr != "mailctl-metrics:9100" || c.DataDir != "/data" || c.StalwartURL != "http://172.31.255.2:8080" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.MailIP.String() != "172.31.255.3" {
		t.Fatalf("mail ip %v", c.MailIP)
	}
	if strings.Join(c.Resolvers, " ") != "1.1.1.1:53 8.8.8.8:53" {
		t.Fatalf("resolvers %v", c.Resolvers)
	}
	if c.DKIMRotate != 4320*time.Hour || c.FormerRetain != 720*time.Hour || c.LANOnly || c.IPv6 || c.Relay != nil {
		t.Fatalf("defaults: %+v", c)
	}
	if strings.Join(c.WellKnownEntry, ",") != "websecure,vpnsecure" {
		t.Fatalf("entrypoints %v", c.WellKnownEntry)
	}
	if c.HubSecretFile != "/run/portcullis/mail/hub-secret" || c.APIKeyFile != "/run/portcullis/mail/api-key" || c.DQSKeyFile != "/run/portcullis/mail/dqs-key" {
		t.Fatalf("files %+v", c)
	}
}

func TestLoadRefusesMissing(t *testing.T) {
	for _, k := range []string{"MAILCTL_API_SUBNET", "MAILCTL_LOCAL_RESOLVER", "MAILCTL_CLIENT_IP", "MAIL_HOSTNAME", "PORTCULLIS_DOMAIN"} {
		m := base()
		delete(m, k)
		_, err := Load(envOf(m))
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("without %s: %v", k, err)
		}
	}
}

func TestLoadRefusesBad(t *testing.T) {
	cases := map[string]string{
		"MAILCTL_API_SUBNET":       "172.31.255.17/28",
		"MAILCTL_LOCAL_RESOLVER":   "mail-resolver:5353",
		"MAILCTL_RULES_ADDR":       "[::1]:8082",
		"MAILCTL_STALWART_URL":     "https://172.31.255.2:8080",
		"MAILCTL_RESOLVERS":        "1.1.1.1",
		"MAIL_HOSTNAME":            "mail_host",
		"PORTCULLIS_DOMAIN":        "exa mple.com",
		"MAIL_DKIM_ROTATE":         "180d",
		"MAIL_FORMER_RETENTION":    "-1h",
		"MAIL_SUBMISSION_LAN_ONLY": "yes",
		"MAIL_IPV6":                "true",
		"MAILCTL_PUBLIC_IPV4":      "2001:db8::1",
		"DOMAINS_PUBLIC_IPV6":      "192.0.2.1",
		"MAIL_RELAY_PORT":          "465",
		"MAILCTL_API_ADDR":         ":99999",
	}
	for k, v := range cases {
		m := base()
		m[k] = v
		_, err := Load(envOf(m))
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q: %v", k, v, err)
		}
	}
}

func TestClientIPMode(t *testing.T) {
	for _, v := range []string{"preserved", "rewritten"} {
		m := base()
		m["MAILCTL_CLIENT_IP"] = v
		c, err := Load(envOf(m))
		if err != nil || c.ClientIP != v {
			t.Errorf("%s: %v %v", v, c.ClientIP, err)
		}
	}
	for _, v := range []string{"Preserved", "auto", "on"} {
		m := base()
		m["MAILCTL_CLIENT_IP"] = v
		if _, err := Load(envOf(m)); err == nil || !strings.Contains(err.Error(), "MAILCTL_CLIENT_IP") {
			t.Errorf("%s accepted: %v", v, err)
		}
	}
}

func TestPublicIPsAndRelay(t *testing.T) {
	m := base()
	m["DOMAINS_PUBLIC_IPV4"] = "198.51.100.7"
	m["DOMAINS_PUBLIC_IPV6"] = "2001:db8::7"
	m["MAILCTL_PUBLIC_IPV4"] = "203.0.113.5"
	m["MAIL_RELAY_HOST"] = "smtp.relay.example"
	m["MAIL_RELAY_PORT"] = "587"
	m["MAIL_RELAY_USERNAME"] = "u"
	m["MAIL_RELAY_SPF_INCLUDE"] = "spf.relay.example"
	c, err := Load(envOf(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicIPv4.String() != "203.0.113.5" || c.PublicIPv6.String() != "2001:db8::7" {
		t.Fatalf("ips %v %v", c.PublicIPv4, c.PublicIPv6)
	}
	if c.Relay == nil || c.Relay.Host != "smtp.relay.example" || c.Relay.Port != 587 || c.Relay.Username != "u" || c.Relay.SPFInclude != "spf.relay.example" {
		t.Fatalf("relay %+v", c.Relay)
	}
}
