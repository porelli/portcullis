package checks

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/portcullis/mailctl/internal/dkim"
	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

const (
	pub1 = "1.1.1.1:53"
	pub2 = "8.8.8.8:53"
	loc  = "172.31.255.4:5353"
)

// fakeDNS answers from a table: "server|name|type" → message builder.
type fakeDNS map[string]func(*dns.Msg)

func (f fakeDNS) q(_ context.Context, server, name string, qtype uint16, _ bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	fn, ok := f[server+"|"+strings.TrimSuffix(name, ".")+"|"+dns.TypeToString[qtype]]
	if !ok {
		fn, ok = f["*|"+strings.TrimSuffix(name, ".")+"|"+dns.TypeToString[qtype]]
	}
	if !ok {
		m.Rcode = dns.RcodeNameError
		return m, nil
	}
	fn(m)
	return m, nil
}

func rr(s string) func(*dns.Msg) {
	return func(m *dns.Msg) {
		r, err := dns.NewRR(s)
		if err != nil {
			panic(err)
		}
		m.Answer = append(m.Answer, r)
	}
}

type env struct {
	f   *fake.Server
	st  *state.Store
	m   *machines.Machines
	d   Deps
	dns fakeDNS
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	f.Put("Domain", "", map[string]any{"name": "example.com"})
	f.Put("Domain", "", map[string]any{"name": "team-b.example.org"})
	b, _ := os.ReadFile("../state/testdata/mailstate_v1.json")
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := state.Open(t.TempDir())
	st.Update(func(p *state.Persistent) error { p.Doc, p.Generation = doc, doc.Generation; return nil })
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	e := &env{f: f, st: st, dns: fakeDNS{}, now: t0}
	e.m = machines.New(c, st, machines.Config{MainDomain: "example.com", Hostname: "mail.example.com", RotateEvery: 180 * 24 * time.Hour, Reachable: true}, t.Logf)
	e.m.Now = func() time.Time { return e.now }
	e.m.Visible = func(context.Context, string, string) bool { return false }
	e.d = Deps{C: c, M: e.m, Store: st, Now: func() time.Time { return e.now }, DNS: e.dns.q, Logf: t.Logf,
		Cfg: Config{Hostname: "mail.example.com", MainDomain: "example.com", PublicIPv4: netip.MustParseAddr("203.0.113.5"),
			Resolvers: []string{pub1, pub2}, LocalResolver: loc, ClientIP: "preserved", MailIP: "172.31.255.2"},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasSuffix(addr, ":25") {
				t.Fatalf("dialled port 25: %s", addr)
			}
			return nil, errors.New("no listener in this test")
		}}
	return e
}

func find(t *testing.T, cs []Check, id string) Check {
	t.Helper()
	for _, c := range cs {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %s in %+v", id, cs)
	return Check{}
}

func queue(e *env, rcpt, typ, errType, host string, retries int) {
	st := map[string]any{"@type": typ}
	if errType != "" {
		st["errorType"], st["responseHostname"] = errType, host
	}
	e.f.Put("QueuedMessage", "", map[string]any{"createdAt": e.now.Add(-time.Hour).Format(time.RFC3339), "returnPath": "alice@example.com",
		"recipients": map[string]any{rcpt: map[string]any{"retryCount": retries, "status": st}}})
}

// P3: from the queue only; the dial stub fails the test on any port 25.
func TestPort25FromQueueOnly(t *testing.T) {
	e := newEnv(t)
	p := e.st.Get()
	c := port25(e.d, nil, nil, p)
	if c.Severity != Info || c.Detail != "no outbound delivery yet: not known" {
		t.Fatalf("empty queue %+v", c)
	}
	queue(e, "a@gmail.com", "TemporaryFailure", "connectionError", "gmail-smtp-in.l.google.com", 2)
	q, _ := readQueue(context.Background(), e.d)
	if c := port25(e.d, q, nil, p); c.Severity != Info {
		t.Fatalf("one host %+v", c)
	}
	queue(e, "b@outlook.com", "TemporaryFailure", "connectionError", "outlook-com.olc.protection.outlook.com", 1)
	queue(e, "local@example.com", "Completed", "", "", 0) // local: not port 25
	q, _ = readQueue(context.Background(), e.d)
	c = port25(e.d, q, nil, p)
	if c.Severity != Problem || !strings.Contains(c.Detail, "2 MX hosts") || len(c.Steps) < 5 {
		t.Fatalf("blocked %+v", c)
	}
	queue(e, "c@yahoo.com", "Completed", "", "", 0)
	q, _ = readQueue(context.Background(), e.d)
	if c := port25(e.d, q, nil, p); c.Severity != OK {
		t.Fatalf("a delivery %+v", c)
	}
	// Remembered: an empty queue later is ok, not "not known".
	if c := port25(e.d, nil, nil, e.st.Get()); c.Severity != OK {
		t.Fatalf("after a delivery %+v", c)
	}
	// The whole run never dials port 25 (the dial stub).
	_ = Run(context.Background(), e.d)
}

func TestFCrDNSMismatch(t *testing.T) {
	e := newEnv(t)
	e.dns["*|5.113.0.203.in-addr.arpa|PTR"] = rr("5.113.0.203.in-addr.arpa. 300 IN PTR static.5.113.0.203.clients.your-server.de.")
	e.dns["*|static.5.113.0.203.clients.your-server.de|A"] = rr("static.5.113.0.203.clients.your-server.de. 300 IN A 198.51.100.9")
	c := fcrdns(context.Background(), e.d, e.d.Cfg.PublicIPv4, false)
	if c.Severity != Problem || c.Reason != "mismatch" {
		t.Fatalf("%+v", c)
	}
	e.dns["*|static.5.113.0.203.clients.your-server.de|A"] = rr("static.5.113.0.203.clients.your-server.de. 300 IN A 203.0.113.5")
	c = fcrdns(context.Background(), e.d, e.d.Cfg.PublicIPv4, false)
	if c.Severity != OK || c.Reason != "" || !strings.Contains(c.Detail, "not mail.example.com") {
		t.Fatalf("ok %+v", c)
	}
	delete(e.dns, "*|static.5.113.0.203.clients.your-server.de|A")
	if c := fcrdns(context.Background(), e.d, e.d.Cfg.PublicIPv4, false); c.Reason != "missing" {
		t.Fatalf("name doesn't resolve %+v", c)
	}
	delete(e.dns, "*|5.113.0.203.in-addr.arpa|PTR")
	if c := fcrdns(context.Background(), e.d, e.d.Cfg.PublicIPv4, false); c.Reason != "missing" || c.Severity != Problem {
		t.Fatalf("no PTR %+v", c)
	}
	// IPv6 failing is Info (outbound v4 only); no IPv6 address is ok.
	if c := fcrdns(context.Background(), e.d, netip.MustParseAddr("2001:db8::5"), true); c.Severity != Info || c.Reason != "missing" || c.ID != "fcrdns_v6" {
		t.Fatalf("v6 %+v", c)
	}
	if c := fcrdns(context.Background(), e.d, netip.Addr{}, true); c.Severity != OK {
		t.Fatalf("no v6 %+v", c)
	}
}

func TestFCrDNSLightsailSteps(t *testing.T) {
	e := newEnv(t)
	c := fcrdns(context.Background(), e.d, e.d.Cfg.PublicIPv4, false)
	joined := strings.Join(c.Steps, "\n")
	for _, w := range []string{"Hetzner:", "DigitalOcean:", "AWS EC2:", "AWS Lightsail: submit the \"Request to remove email sending limitations\" form for the static IP with the reverse DNS name.", "OVH:", "Elsewhere:", "203.0.113.5 to mail.example.com"} {
		if !strings.Contains(joined, w) {
			t.Errorf("steps lack %q:\n%s", w, joined)
		}
	}
}

func TestBlocklistPBL(t *testing.T) {
	e := newEnv(t)
	e.dns[loc+"|5.113.0.203.zen.spamhaus.org|A"] = rr("5.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.11")
	c := blocklist(context.Background(), e.d, e.st.Get().Doc)
	if c.Severity != Problem || !strings.Contains(c.Detail, "residential range: use a relay") {
		t.Fatalf("%+v", c)
	}
	e.dns[loc+"|5.113.0.203.zen.spamhaus.org|A"] = rr("5.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.2")
	if c := blocklist(context.Background(), e.d, e.st.Get().Doc); c.Severity != Problem || !strings.Contains(c.Detail, "listed by Spamhaus ZEN") {
		t.Fatalf("SBL %+v", c)
	}
	delete(e.dns, loc+"|5.113.0.203.zen.spamhaus.org|A")
	if c := blocklist(context.Background(), e.d, e.st.Get().Doc); c.Severity != OK {
		t.Fatalf("clean %+v", c)
	}
}

func TestBlocklistRefusedIsWarning(t *testing.T) {
	e := newEnv(t)
	e.dns[loc+"|5.113.0.203.zen.spamhaus.org|A"] = rr("5.113.0.203.zen.spamhaus.org. 300 IN A 127.255.255.254")
	c := blocklist(context.Background(), e.d, e.st.Get().Doc)
	if c.Severity != Warning || !strings.Contains(c.Detail, "DNSBL refused the query") || !strings.Contains(strings.Join(c.Steps, " "), "DQS") {
		t.Fatalf("%+v", c)
	}
	// With a DQS key the key's zone is asked, and the key never shows.
	kf := t.TempDir() + "/dqs"
	os.WriteFile(kf, []byte("k3y0123456789abc"), 0o600)
	e.d.Cfg.DQSKeyFile = kf
	e.dns[loc+"|5.113.0.203.k3y0123456789abc.zen.dq.spamhaus.net|A"] = rr("x. 300 IN A 127.0.0.4")
	c = blocklist(context.Background(), e.d, e.st.Get().Doc)
	if c.Severity != Problem || strings.Contains(c.Detail, "k3y0123456789abc") || !strings.Contains(c.Detail, "Spamhaus ZEN (DQS)") {
		t.Fatalf("dqs %+v", c)
	}
}

// listener is a TLS (or STARTTLS SMTP) server for one port.
func listener(t *testing.T, cert tls.Certificate, starttls bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if !starttls {
					tls.Server(c, cfg).Handshake()
					return
				}
				var conn net.Conn = c
				w := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
				fmt.Fprint(w, "220 mail.example.com ESMTP\r\n")
				w.Flush()
				for {
					line, err := w.ReadString('\n')
					if err != nil || len(strings.Fields(line)) == 0 {
						return
					}
					switch strings.ToUpper(strings.Fields(line)[0]) {
					case "EHLO":
						fmt.Fprint(w, "250-mail.example.com\r\n250 STARTTLS\r\n")
					case "STARTTLS":
						fmt.Fprint(w, "220 go ahead\r\n")
						w.Flush()
						tc := tls.Server(conn, cfg)
						if tc.Handshake() != nil {
							return
						}
						conn = tc
						w = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
						continue
					case "QUIT":
						fmt.Fprint(w, "221 bye\r\n")
						w.Flush()
						return
					default:
						fmt.Fprint(w, "250 ok\r\n")
					}
					w.Flush()
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func selfSigned(t *testing.T, host string, notAfter time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: t0.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, leaf
}

func withListeners(t *testing.T, e *env, cert tls.Certificate) {
	addrs := map[string]string{}
	for _, p := range certPorts {
		addrs[fmt.Sprintf("172.31.255.2:%d", p.Port)] = listener(t, cert, p.StartTLS)
	}
	e.d.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":25") {
			t.Fatalf("dialled port 25: %s", addr)
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addrs[addr])
	}
}

func TestCertTLSAMismatch(t *testing.T) {
	e := newEnv(t)
	cert, leaf := selfSigned(t, "mail.example.com", t0.Add(60*24*time.Hour))
	withListeners(t, e, cert)
	if c := certCheck(context.Background(), e.d); c.Severity != OK || !strings.Contains(c.Detail, "valid until") {
		t.Fatalf("ok %+v", c)
	}
	// TLSA published (secure) with another SPKI → Problem on every port.
	in := machines.RotateIn{DNSSECState: "secure"}
	in.SPKI.Current = strings.Repeat("ab", 32)
	if _, err := e.m.Rotate(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	c := certCheck(context.Background(), e.d)
	if c.Severity != Problem || strings.Count(c.Detail, "doesn't match the published TLSA") != 4 {
		t.Fatalf("mismatch %+v", c)
	}
	in.SPKI.Current = SPKI(leaf)
	e.m.Rotate(context.Background(), in)
	e.now = t0.Add(3 * 24 * time.Hour) // the old record dropped after 2×TTL
	e.m.Rotate(context.Background(), in)
	if c := certCheck(context.Background(), e.d); c.Severity != OK || !strings.Contains(c.Detail, "matching TLSA") {
		t.Fatalf("match %+v", c)
	}
	// Expiring soon → Warning; another name → Problem.
	e2 := newEnv(t)
	cert2, _ := selfSigned(t, "mail.example.com", t0.Add(5*24*time.Hour))
	withListeners(t, e2, cert2)
	if c := certCheck(context.Background(), e2.d); c.Severity != Warning {
		t.Fatalf("expiring %+v", c)
	}
	e3 := newEnv(t)
	cert3, _ := selfSigned(t, "other.example.com", t0.Add(60*24*time.Hour))
	withListeners(t, e3, cert3)
	if c := certCheck(context.Background(), e3.d); c.Severity != Problem || !strings.Contains(c.Detail, "isn't for mail.example.com") {
		t.Fatalf("name %+v", c)
	}
}

func TestSelftestFailsOnWrongDNSKey(t *testing.T) {
	e := newEnv(t)
	e.now = t0
	if err := e.m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.m.Visible = func(context.Context, string, string) bool { return true }
	e.now = t0.Add(time.Hour)
	if err := e.m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	var active []dkim.Key
	for _, k := range e.m.Keys() {
		if k.Domain == "example.com" && k.Stage == dkim.Active {
			active = append(active, k)
		}
	}
	if len(active) != 2 {
		t.Fatalf("%+v", e.m.Keys())
	}
	for _, k := range active {
		txt := dkim.TXT(k)
		e.dns["*|"+dkim.Name(k)+"|TXT"] = rr(fmt.Sprintf("%s. 300 IN TXT %q", dkim.Name(k), txt))
	}
	c := selftest(context.Background(), e.d, dkim.State{Keys: e.m.Keys()}, "example.com")
	if c.Severity != OK {
		t.Fatalf("ok %+v", c)
	}
	k := active[0]
	_, other, _ := dkim.Generate(k.Algorithm)
	e.dns[pub2+"|"+dkim.Name(k)+"|TXT"] = rr(fmt.Sprintf("%s. 300 IN TXT %q", dkim.Name(k), "v=DKIM1; k="+k.Algorithm+"; p="+other[0]))
	c = selftest(context.Background(), e.d, dkim.State{Keys: e.m.Keys()}, "example.com")
	if c.Severity != Problem || !strings.Contains(c.Detail, k.Selector+" (8.8.8.8:53 serves another key)") {
		t.Fatalf("wrong key %+v", c)
	}
}

// Review Focus 1 (exact plan values) lives in bootstrap; here the check.
func TestClientIPRewrittenWarning(t *testing.T) {
	e := newEnv(t)
	if c := clientIP(e.d); c.Severity != OK {
		t.Fatal(c)
	}
	e.d.Cfg.ClientIP = "rewritten"
	if c := clientIP(e.d); c.Severity != Warning || !strings.Contains(c.Detail, "SPF, iprev and the IP blocklists are off") {
		t.Fatal(c)
	}
}

func TestRefreshCoalesced(t *testing.T) {
	e := newEnv(t)
	var runs atomic.Int32
	r := &Runner{D: e.d, OnResult: func(Result) { runs.Add(1) }}
	r.Get(context.Background(), false)
	r.Get(context.Background(), false)
	r.Get(context.Background(), true) // within 60 s: the last result
	if runs.Load() != 1 {
		t.Fatalf("%d runs", runs.Load())
	}
	e.now = e.now.Add(RefreshWithin)
	r.Get(context.Background(), true)
	if runs.Load() != 2 {
		t.Fatalf("%d runs after 60 s", runs.Load())
	}
	r.Get(context.Background(), false)
	if runs.Load() != 2 {
		t.Fatal("a plain GET ran again")
	}
	// A new document: a refresh runs even within 60 s.
	e.st.Update(func(p *state.Persistent) error { p.Generation++; return nil })
	r.Get(context.Background(), true)
	if runs.Load() != 3 {
		t.Fatal("a refresh after a new document didn't run")
	}
	if _, ok := r.Last("client_ip"); !ok {
		t.Fatal("Last")
	}
}

// Ruling: authenticated reports from independent reporters raise a
// doctor Problem and change no policy; unauthenticated ones are shown
// as Info only.
func TestReportsProblemNoPolicyChange(t *testing.T) {
	e := newEnv(t)
	if err := e.m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := e.m.Policy("example.com")
	rep := func(from, org string) {
		e.f.Put("TlsExternalReport", "", map[string]any{"from": from, "to": map[string]any{"tls-reports@example.com": true},
			"report": map[string]any{"organizationName": org, "dateRangeEnd": t0.Add(time.Hour).Format(time.RFC3339),
				"policies": map[string]any{"0": map[string]any{"policyDomain": "example.com", "totalFailedSessions": 2}}}})
	}
	rep("tlsrpt@google.com", "Google")
	rep("tlsrpt@microsoft.com", "Microsoft")
	e.now = t0.Add(2 * time.Hour)
	c := find(t, reportChecks(context.Background(), e.d, e.st.Get().Doc), "tlsrpt_reports")
	if c.Severity != Info || !strings.Contains(c.Detail, "never acted on") {
		t.Fatalf("unauthenticated %+v", c)
	}
	e.m.Verify = func(_ context.Context, r machines.Report) (string, bool) { return r.From, true }
	c = find(t, reportChecks(context.Background(), e.d, e.st.Get().Doc), "tlsrpt_reports")
	if c.Severity != Problem || !strings.Contains(c.Detail, "google.com") || !strings.Contains(c.Detail, "microsoft.com") ||
		!strings.Contains(strings.Join(c.Steps, " "), "nothing was changed automatically") {
		t.Fatalf("authenticated %+v", c)
	}
	if err := e.m.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.m.Policy("example.com") != before {
		t.Fatal("the policy changed")
	}
}

func TestDANESwitch(t *testing.T) {
	e := newEnv(t)
	id := e.f.Put("MtaTlsStrategy", "", map[string]any{"name": "default", "dane": "optional"})
	e.dns[loc+"|dnssec.works|A"] = func(m *dns.Msg) { m.AuthenticatedData = true; rr("dnssec.works. 300 IN A 5.45.107.88")(m) }
	e.dns[loc+"|fail01.dnssec.works|A"] = func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }
	if c := dane(context.Background(), e.d); c.Severity != OK || e.f.Get("MtaTlsStrategy", "", id)["dane"] != "optional" {
		t.Fatalf("validating %+v", c)
	}
	// No AD bit: DANE off, then on again once it validates.
	e.dns[loc+"|dnssec.works|A"] = rr("dnssec.works. 300 IN A 5.45.107.88")
	c := dane(context.Background(), e.d)
	if c.Severity != Info || c.Detail != "DANE is off: the resolver can't validate DNSSEC" || e.f.Get("MtaTlsStrategy", "", id)["dane"] != "disable" {
		t.Fatalf("not validating %+v %v", c, e.f.Get("MtaTlsStrategy", "", id))
	}
	e.dns[loc+"|dnssec.works|A"] = func(m *dns.Msg) { m.AuthenticatedData = true; rr("dnssec.works. 300 IN A 5.45.107.88")(m) }
	dane(context.Background(), e.d)
	if e.f.Get("MtaTlsStrategy", "", id)["dane"] != "optional" {
		t.Fatal("DANE not switched back on")
	}
}

func TestRateHeld(t *testing.T) {
	e := newEnv(t)
	e.f.Put("QueuedMessage", "", map[string]any{"createdAt": t0.Format(time.RFC3339), "returnPath": "Alice@Example.com",
		"recipients": map[string]any{"x@gmail.com": map[string]any{"retryCount": 1, "status": map[string]any{"@type": "TemporaryFailure", "errorType": "rateLimited"}}}})
	q, _ := readQueue(context.Background(), e.d)
	cs := rateHeld(e.d, q, nil, e.st.Get().Doc)
	if len(cs) != 1 || cs[0].ID != "rate_held:alice" || cs[0].Severity != Warning {
		t.Fatalf("%+v", cs)
	}
}

func TestRunShape(t *testing.T) {
	e := newEnv(t)
	res := Run(context.Background(), e.d)
	ids := map[string]bool{}
	for _, c := range res.Checks {
		ids[strings.SplitN(c.ID, ":", 2)[0]] = true
		if c.Steps == nil {
			t.Fatalf("%s: steps null", c.ID)
		}
		if (c.ID == "fcrdns_v4" || c.ID == "fcrdns_v6") && c.Severity != OK && c.Reason == "" {
			t.Fatalf("%s without a reason", c.ID)
		}
	}
	for _, w := range []string{"port25", "fcrdns_v4", "fcrdns_v6", "blocklist", "cert", "dkim_stuck", "dkim_selftest", "dmarc_reports", "tlsrpt_reports", "client_ip", "dane"} {
		if !ids[w] {
			t.Errorf("no %s", w)
		}
	}
}
