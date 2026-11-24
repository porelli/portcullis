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
	m["PORTCULLIS_MAIL_PUBLIC_IPV4"] = "203.0.113.5"
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
		"PORTCULLIS_MAIL_API_SUBNET":  "172.31.255.17/28",
		"PORTCULLIS_MAIL_API_HUB_IP":  "172.31.250.18",
		"PORTCULLIS_MAIL_SLOT_DIR":    "slot",
		"PORTCULLIS_MAIL_TLS_DIR":     "../tls",
		"STALWART_DQS_KEY_FILE":       "dqs",
		"MAILCTL_LOCAL_RESOLVER":      "resolver:5353",
		"MAILCTL_RULES_ADDR":          "[::1]:8082",
		"MAILCTL_STALWART_URL":        "https://172.31.255.2:8080",
		"MAILCTL_RESOLVERS":           "1.1.1.1",
		"PORTCULLIS_MAIL_PUBLIC_IPV4": "2001:db8::1",
		"PORTCULLIS_MAIL_PUBLIC_IPV6": "192.0.2.1",
		"MAILCTL_API_ADDR":            ":99999",
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

// Ruling T17-d / T17-c: MAILCTL_API_KEY_FILE (both the job and the
// adapter), MAILCTL_STORE_DIR (the job, required), each a clean absolute path.
func TestKeyFileAndStoreDir(t *testing.T) {
	m := base()
	m["MAILCTL_API_KEY_FILE"] = "/run/adapter/api-key"
	if c, err := Load(envOf(m)); err != nil || c.APIKeyFile != "/run/adapter/api-key" {
		t.Fatalf("%v %v", c.APIKeyFile, err)
	}
	for _, bad := range []string{"api-key", "/run/../etc/key", "/run/adapter/", "/run//key"} {
		m["MAILCTL_API_KEY_FILE"] = bad
		if _, err := Load(envOf(m)); err == nil || !strings.Contains(err.Error(), "MAILCTL_API_KEY_FILE") {
			t.Errorf("%s: %v", bad, err)
		}
	}
	j := map[string]string{"MAILCTL_LOCAL_RESOLVER": "172.31.255.4:5353"}
	if _, err := LoadJob(envOf(j)); err == nil || !strings.Contains(err.Error(), "MAILCTL_STORE_DIR is required") {
		t.Fatalf("no store: %v", err)
	}
	for _, bad := range []string{"store", "/", "/var/lib/../x"} {
		j["MAILCTL_STORE_DIR"] = bad
		if _, err := LoadJob(envOf(j)); err == nil {
			t.Errorf("store %s accepted", bad)
		}
	}
	j["MAILCTL_STORE_DIR"] = "/var/lib/stalwart"
	j["MAILCTL_API_KEY_FILE"] = "/data/key"
	if c, err := LoadJob(envOf(j)); err != nil || c.StoreDir != "/var/lib/stalwart" || c.APIKeyFile != "/data/key" {
		t.Fatalf("%+v %v", c, err)
	}
}

// L5: both server URLs are exactly http://<ip>:<port> (the key is sent
// there): no userinfo, path, query, fragment, name or other scheme.
func TestServerURLsStrict(t *testing.T) {
	for _, bad := range []string{"http://u:p@172.31.255.2:8080", "http://172.31.255.2:8080/x", "http://172.31.255.2:8080?", "http://172.31.255.2:8080#",
		"HTTP://172.31.255.2:8080", "http://stalwart:8080", "http://172.31.255.2", "https://172.31.255.2:8080"} {
		m := base()
		m["MAILCTL_STALWART_URL"] = bad
		if _, err := Load(envOf(m)); err == nil {
			t.Errorf("STALWART_URL %s accepted", bad)
		}
		j := map[string]string{"MAILCTL_LOCAL_RESOLVER": "172.31.255.4:5353", "MAILCTL_STORE_DIR": "/s", "MAILCTL_JOB_LOCAL_URL": strings.Replace(bad, "172.31.255.2", "127.0.0.1", 1)}
		if _, err := LoadJob(envOf(j)); err == nil {
			t.Errorf("JOB_LOCAL_URL %s accepted", j["MAILCTL_JOB_LOCAL_URL"])
		}
	}
	m := base()
	m["MAILCTL_STALWART_URL"] = "http://172.31.255.2:8080/"
	if c, err := Load(envOf(m)); err != nil || c.StalwartURL != "http://172.31.255.2:8080" {
		t.Fatalf("%v %v", c.StalwartURL, err)
	}
}

// The admin view's proxy (contract §19.13) refuses to start on any bad
// or missing value: the host, the secret file, the pinned SPKI and an
// upstream that isn't https to an IPv4 address.
func TestLoadAdminView(t *testing.T) {
	good := map[string]string{"PORTCULLIS_MAIL_ADMIN_HOST": "mail-admin.example.org", "MAILCTL_VIEWER_SECRET_FILE": "/run/portcullis/viewer-key/viewer-password",
		"PORTCULLIS_MAIL_TLS_SPKI": strings.Repeat("ab", 32), "PORTCULLIS_MAIL_ADMIN_TRAEFIK_IP": "172.31.250.2",
		"PORTCULLIS_MAIL_ADMIN_ROUTE_KEY": strings.Repeat("aB3", 16), "PORTCULLIS_MAIL_ADMIN_GROUP": "lldap_admin"}
	a, err := LoadAdminView(func(k string) string { return good[k] })
	if err != nil || a.Addr != ":8090" || a.Upstream != "https://172.31.255.2:8443" || len(a.SPKIs) != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	for k, v := range map[string]string{"PORTCULLIS_MAIL_ADMIN_HOST": "", "MAILCTL_VIEWER_SECRET_FILE": "rel/path", "PORTCULLIS_MAIL_TLS_SPKI": " ",
		"MAILCTL_ADMINVIEW_UPSTREAM": "http://172.31.255.2:8443", "MAILCTL_ADMINVIEW_ADDR": "nope",
		"PORTCULLIS_MAIL_ADMIN_TRAEFIK_IP": "", "PORTCULLIS_MAIL_ADMIN_ROUTE_KEY": "short", "PORTCULLIS_MAIL_ADMIN_GROUP": ""} {
		env := map[string]string{}
		for kk, vv := range good {
			env[kk] = vv
		}
		env[k] = v
		if _, err := LoadAdminView(func(x string) string { return env[x] }); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
	for _, u := range []string{"https://stalwart:8443", "https://172.31.255.2", "https://172.31.255.2:8443/x", "https://u@172.31.255.2:8443"} {
		env := map[string]string{"MAILCTL_ADMINVIEW_UPSTREAM": u}
		for kk, vv := range good {
			env[kk] = vv
		}
		if _, err := LoadAdminView(func(x string) string { return env[x] }); err == nil {
			t.Errorf("upstream %q accepted", u)
		}
	}
}
