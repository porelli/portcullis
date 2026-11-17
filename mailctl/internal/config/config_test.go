package config

import (
	"strings"
	"testing"
)

func base() map[string]string {
	return map[string]string{
		"PORTCULLIS_MAIL_API_SUBNET": "172.31.255.16/28",
		"MAILCTL_LOCAL_RESOLVER":     "172.31.255.4:5353",
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
		c.MetricsAddr != "mail-provider-metrics:9100" || c.DataDir != "/data" || c.StalwartURL != "http://172.31.255.2:8080" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.MailIP.String() != "172.31.255.3" || strings.Join(c.Resolvers, " ") != "1.1.1.1:53 8.8.8.8:53" {
		t.Fatalf("%v %v", c.MailIP, c.Resolvers)
	}
	// No entrypoints given: the well-known router isn't public (MTA-STS off).
	if len(c.WellKnownEntry) != 0 || c.HubIP.IsValid() || c.VoidSession != "" || c.DQSKeyFile != "" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.SlotDir != "/run/portcullis/mail/slot" || c.TLSDir != "/run/portcullis/mail/tls" || c.APIKeyFile != "/data/api-key" ||
		c.APISecretFile() != "/run/portcullis/mail/slot/api-secret" || c.MetricsSecretFile() != "/run/portcullis/mail/slot/metrics-secret" ||
		c.RelayPasswordFile() != "/run/portcullis/mail/slot/relay-password" {
		t.Fatalf("files %+v", c)
	}
}

func TestLoadSlotEnvironment(t *testing.T) {
	m := base()
	m["PORTCULLIS_MAIL_API_HUB_IP"] = "172.31.255.18"
	m["PORTCULLIS_MAIL_SLOT_DIR"] = "/slot"
	m["PORTCULLIS_MAIL_TLS_DIR"] = "/tls"
	m["PORTCULLIS_MAIL_VOID_SESSION"] = "abc "
	m["PORTCULLIS_MAIL_WELLKNOWN_ENTRYPOINTS"] = "websecure, vpnsecure"
	m["STALWART_DQS_KEY_FILE"] = "/run/secrets/dqs"
	m["MAILCTL_PUBLIC_IPV4"] = "203.0.113.5"
	c, err := Load(envOf(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.HubIP.String() != "172.31.255.18" || c.APISecretFile() != "/slot/api-secret" || c.TLSDir != "/tls" || c.VoidSession != "abc " ||
		strings.Join(c.WellKnownEntry, ",") != "websecure,vpnsecure" || c.DQSKeyFile != "/run/secrets/dqs" || c.PublicIPv4.String() != "203.0.113.5" {
		t.Fatalf("%+v", c)
	}
}

func TestLoadRefusesMissing(t *testing.T) {
	for _, k := range []string{"PORTCULLIS_MAIL_API_SUBNET", "MAILCTL_LOCAL_RESOLVER"} {
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
		"PORTCULLIS_MAIL_API_SUBNET": "172.31.255.17/28",
		"PORTCULLIS_MAIL_API_HUB_IP": "172.31.250.18",
		"PORTCULLIS_MAIL_SLOT_DIR":   "slot",
		"PORTCULLIS_MAIL_TLS_DIR":    "../tls",
		"STALWART_DQS_KEY_FILE":      "dqs",
		"MAILCTL_LOCAL_RESOLVER":     "resolver:5353",
		"MAILCTL_RULES_ADDR":         "[::1]:8082",
		"MAILCTL_STALWART_URL":       "https://172.31.255.2:8080",
		"MAILCTL_RESOLVERS":          "1.1.1.1",
		"MAILCTL_PUBLIC_IPV4":        "2001:db8::1",
		"MAILCTL_PUBLIC_IPV6":        "192.0.2.1",
		"MAILCTL_API_ADDR":           ":99999",
	}
	for k, v := range cases {
		m := base()
		m[k] = v
		_, err := Load(envOf(m))
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%q: %v", k, v, err)
		}
	}
	// The removed core-era keys are simply not read (no legacy hint).
	m := base()
	for _, k := range []string{"MAILCTL_API_SUBNET", "MAIL_HOSTNAME", "MAIL_RELAY_HOST", "MAILCTL_CLIENT_IP", "MAIL_DKIM_ROTATE"} {
		m[k] = "x y"
	}
	if _, err := Load(envOf(m)); err != nil {
		t.Fatalf("an old key was read: %v", err)
	}
}
