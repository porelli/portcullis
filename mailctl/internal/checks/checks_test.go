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
	"sync"
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
	b, _ := os.ReadFile("../state/testdata/mailstate_v2.json")
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := state.Open(t.TempDir())
	st.Update(func(p *state.Persistent) error { p.Doc, p.Generation = doc, doc.Generation; return nil })
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	e := &env{f: f, st: st, dns: fakeDNS{}, now: t0}
	e.m = machines.New(c, st, machines.Config{Reachable: true}, t.Logf)
	e.m.Now = func() time.Time { return e.now }
	e.m.Visible = func(context.Context, string, string) bool { return false }
	e.d = Deps{C: c, M: e.m, Store: st, Now: func() time.Time { return e.now }, DNS: e.dns.q, Logf: t.Logf,
		Cfg: Config{Hostname: "mail.example.com", PublicIPv4: netip.MustParseAddr("203.0.113.5"),
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

// The cert check judges the served key against the document's
// tls.spki_sha256 (core's current and next key), never a DNS lookup.
func TestCertSPKIFromDocument(t *testing.T) {
	e := newEnv(t)
	cert, leaf := selfSigned(t, "mail.example.com", t0.Add(60*24*time.Hour))
	withListeners(t, e, cert)
	other := strings.Repeat("ab", 32)
	if c := certCheck(context.Background(), e.d, []string{other, SPKI(leaf)}); c.Severity != OK || c.outcome != "pass" || !strings.Contains(c.Detail, "valid until") {
		t.Fatalf("ok %+v", c)
	}
	c := certCheck(context.Background(), e.d, []string{other})
	if c.Severity != Problem || c.outcome != "fail" || strings.Count(c.Detail, "the key isn't the mail certificate's") != 4 {
		t.Fatalf("mismatch %+v", c)
	}
	// No keys known (no document yet): unknown, never a failure.
	if c := certCheck(context.Background(), e.d, nil); c.Severity != Info || c.outcome != "unknown" {
		t.Fatalf("no keys %+v", c)
	}
	// Run takes the keys from the document.
	e.st.Update(func(p *state.Persistent) error { p.Doc.TLS.SPKISHA256 = []string{SPKI(leaf)}; return nil })
	if c := find(t, Run(context.Background(), e.d).Checks, "cert"); c.Severity != OK {
		t.Fatalf("run %+v", c)
	}
	// A listener that can't be reached: unknown.
	e.d.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("i/o timeout") }
	if c := certCheck(context.Background(), e.d, []string{SPKI(leaf)}); c.Severity != Info || c.outcome != "unknown" {
		t.Fatalf("timeout: %+v", c)
	}
	// Expiring soon → Warning; another name → Problem.
	e2 := newEnv(t)
	cert2, leaf2 := selfSigned(t, "mail.example.com", t0.Add(5*24*time.Hour))
	withListeners(t, e2, cert2)
	if c := certCheck(context.Background(), e2.d, []string{SPKI(leaf2)}); c.Severity != Warning {
		t.Fatalf("expiring %+v", c)
	}
	e3 := newEnv(t)
	cert3, leaf3 := selfSigned(t, "other.example.com", t0.Add(60*24*time.Hour))
	withListeners(t, e3, cert3)
	if c := certCheck(context.Background(), e3.d, []string{SPKI(leaf3)}); c.Severity != Problem || !strings.Contains(c.Detail, "isn't for mail.example.com") {
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
	// Final review L11: one lookup per key and resolver.
	asked := map[string]int{}
	e.d.DNS = func(ctx context.Context, server, name string, qtype uint16, do bool) (*dns.Msg, error) {
		asked[server+"|"+name]++
		return e.dns.q(ctx, server, name, qtype, do)
	}
	c := selftest(context.Background(), e.d, dkim.State{Keys: e.m.Keys()}, "example.com")
	if c.Severity != OK {
		t.Fatalf("ok %+v", c)
	}
	for q, n := range asked {
		if n != 1 {
			t.Fatalf("%s asked %d times", q, n)
		}
	}
	if len(asked) != 2*len(active) {
		t.Fatalf("lookups %v", asked)
	}
	e.d.DNS = e.dns.q
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
	daneOf := func() any { return e.f.Get("MtaTlsStrategy", "", id)["dane"] }
	valid := func() {
		e.dns[loc+"||DNSKEY"] = func(m *dns.Msg) { m.AuthenticatedData = true; rr(". 300 IN DNSKEY 257 3 8 AwEAAa==")(m) }
		e.dns[loc+"|fail01.dnssec.works|A"] = func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }
	}
	invalid := func() {
		e.dns[loc+"||DNSKEY"] = rr(". 300 IN DNSKEY 257 3 8 AwEAAa==")
		e.dns[loc+"|fail01.dnssec.works|A"] = rr("fail01.dnssec.works. 300 IN A 192.0.2.1")
	}
	valid()
	if c := dane(context.Background(), e.d); c.Severity != OK || daneOf() != "optional" {
		t.Fatalf("validating %+v", c)
	}
	// Unknown shapes change nothing: SERVFAIL on the good probe, a
	// timeout, AD on the good probe but the broken one answering.
	for name, set := range map[string]func(){
		"servfail on good": func() {
			e.dns[loc+"||DNSKEY"] = func(m *dns.Msg) { m.Rcode = dns.RcodeServerFailure }
		},
		"timeout": func() {
			delete(e.dns, loc+"||DNSKEY")
			e.d.DNS = func(context.Context, string, string, uint16, bool) (*dns.Msg, error) {
				return nil, errors.New("i/o timeout")
			}
		},
		"mixed": func() {
			e.dns[loc+"||DNSKEY"] = func(m *dns.Msg) { m.AuthenticatedData = true }
			e.dns[loc+"|fail01.dnssec.works|A"] = rr("fail01.dnssec.works. 300 IN A 192.0.2.1")
		},
	} {
		e.d.DNS = e.dns.q
		set()
		for i := 0; i < 5; i++ {
			e.now = e.now.Add(time.Hour)
			if c := dane(context.Background(), e.d); c.Severity != Info || daneOf() != "optional" {
				t.Fatalf("%s: %+v %v", name, c, daneOf())
			}
		}
		e.d.DNS = e.dns.q
	}
	// Definite not-validating: off only after 3 in a row over ≥ 30 min.
	invalid()
	e.now = t0.Add(48 * time.Hour)
	for i := 0; i < 3; i++ {
		c := dane(context.Background(), e.d)
		if c.Severity != Warning || daneOf() != "optional" {
			t.Fatalf("invalid #%d (within 30 min): %+v", i+1, c)
		}
		e.now = e.now.Add(10 * time.Minute)
	}
	c := dane(context.Background(), e.d) // the 4th, 30 min after the first
	if c.Severity != Problem || c.Detail != "DANE is off: the resolver can't validate DNSSEC" || daneOf() != "disable" {
		t.Fatalf("off: %+v %v", c, daneOf())
	}
	// Still a Problem while off; an unknown result keeps it off.
	e.d.DNS = func(context.Context, string, string, uint16, bool) (*dns.Msg, error) {
		return nil, errors.New("timeout")
	}
	if c := dane(context.Background(), e.d); c.Severity != Problem || daneOf() != "disable" {
		t.Fatalf("unknown while off: %+v", c)
	}
	e.d.DNS = e.dns.q
	// The first definite validating verdict switches it back on.
	valid()
	if c := dane(context.Background(), e.d); c.Severity != OK || daneOf() != "optional" {
		t.Fatalf("back on: %+v %v", c, daneOf())
	}
	// A valid verdict resets the streak.
	invalid()
	e.now = e.now.Add(time.Hour)
	dane(context.Background(), e.d)
	e.now = e.now.Add(time.Hour)
	if c := dane(context.Background(), e.d); daneOf() != "optional" || c.Severity != Warning {
		t.Fatalf("streak not reset: %+v", c)
	}
}

// Security ruling: a cert failure from a timeout, a cancelled request or
// an unreachable listener is unknown and never moves MTA-STS back; one
// definite failure doesn't either; two definite failures ≥ 15 min apart do.
func TestCertStateConfirmed(t *testing.T) {
	e := newEnv(t)
	r := &Runner{D: e.d}
	// Unreachable listeners (the default dial stub): unknown.
	res := r.Get(context.Background(), false)
	c := find(t, res.Checks, "cert")
	if c.Severity != Info || !strings.Contains(c.Detail, "couldn't be checked") {
		t.Fatalf("unreachable %+v", c)
	}
	if ok, known := r.CertState(); ok || known {
		t.Fatal("unknown reported as known")
	}
	// A cancelled request: the run doesn't inherit the cancellation.
	cert, leaf := selfSigned(t, "mail.example.com", t0.Add(60*24*time.Hour))
	e.st.Update(func(p *state.Persistent) error { p.Doc.TLS.SPKISHA256 = []string{SPKI(leaf)}; return nil })
	withListeners(t, e, cert)
	r.D = e.d
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.now = e.now.Add(2 * time.Minute)
	// The cancelled caller gets the last result at once; the run goes on
	// and the next caller waits for it (single flight).
	if res = r.Get(ctx, true); find(t, res.Checks, "cert").Severity != Info {
		t.Fatalf("cancelled request didn't get the last result: %+v", find(t, res.Checks, "cert"))
	}
	res = r.Get(context.Background(), false)
	if c := find(t, res.Checks, "cert"); c.Severity != OK {
		t.Fatalf("cancelled request %+v", c)
	}
	if ok, known := r.CertState(); !ok || !known {
		t.Fatal("pass not known")
	}
	// A definite failure (another name): once → no downgrade.
	bad, _ := selfSigned(t, "other.example.com", t0.Add(60*24*time.Hour))
	withListeners(t, e, bad)
	r.D = e.d
	e.now = e.now.Add(2 * time.Minute)
	r.Get(context.Background(), true)
	if ok, known := r.CertState(); ok || known {
		t.Fatal("one failure confirmed")
	}
	// Again 10 min later: still not 15 min apart.
	e.now = e.now.Add(10 * time.Minute)
	r.Get(context.Background(), true)
	if _, known := r.CertState(); known {
		t.Fatal("confirmed before 15 min")
	}
	// An unknown in between keeps the streak; a failure 15 min after the
	// first confirms it.
	keep := r.D.Dial
	r.D.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("i/o timeout") }
	e.now = e.now.Add(2 * time.Minute)
	r.Get(context.Background(), true)
	if _, known := r.CertState(); known {
		t.Fatal("an unknown result confirmed a failure")
	}
	r.D.Dial = keep
	e.now = e.now.Add(3 * time.Minute)
	r.Get(context.Background(), true)
	if ok, known := r.CertState(); ok || !known {
		t.Fatal("two definite failures ≥ 15 min apart not confirmed")
	}
	// The MTA-STS machine: enforce → testing only now.
	if c := find(t, r.last.Checks, "cert"); c.Severity != Problem {
		t.Fatalf("no Problem %+v", c)
	}
}

// The machine side: unknown or unconfirmed cert state never moves enforce
// back; the confirmed one does.
func TestCertDowngradeOnlyConfirmed(t *testing.T) {
	e := newEnv(t)
	e.m.Step(context.Background())
	e.now = t0.Add(8 * 24 * time.Hour)
	if err := e.m.MTASTSEnforce(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	for _, st := range [][2]bool{{false, false}, {false, false}} {
		e.m.CertOK = func() (bool, bool) { return st[0], st[1] }
		e.now = e.now.Add(time.Hour)
		e.m.Step(context.Background())
		if s, _ := e.m.Status(context.Background(), true); s.MTASTS[0].Mode != "enforce" {
			t.Fatalf("downgraded on %v", st)
		}
	}
	e.m.CertOK = func() (bool, bool) { return false, true }
	e.now = e.now.Add(time.Hour)
	e.m.Step(context.Background())
	if s, _ := e.m.Status(context.Background(), true); s.MTASTS[0].Mode != "testing" {
		t.Fatalf("confirmed failure didn't downgrade: %+v", s.MTASTS)
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

// Final review L7: concurrent refreshes share one run.
func TestChecksSingleFlight(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	runs := 0
	r := &Runner{D: e.d, OnResult: func(Result) { mu.Lock(); runs++; mu.Unlock() }}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.Get(context.Background(), true) }()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if runs != 1 {
		t.Fatalf("%d runs for 5 concurrent refreshes", runs)
	}
}

// Every id a run reports is in the contract's catalog (or x-), and the
// provider's own are x- with a title; the list GET /v1/provider sends
// covers every reported id.
func TestCheckIDsInCatalog(t *testing.T) {
	e := newEnv(t)
	res := Run(context.Background(), e.d)
	if len(res.Checks) == 0 {
		t.Fatal("no checks")
	}
	listed := func(id string) bool {
		for _, c := range Catalog {
			if c == id || (strings.HasSuffix(c, ":") && strings.HasPrefix(id, c)) {
				return true
			}
		}
		return false
	}
	for _, c := range res.Checks {
		if !InCatalog(c.ID) || !listed(c.ID) {
			t.Errorf("%s: not in the catalog", c.ID)
		}
		if strings.HasPrefix(c.ID, "x-") != (c.Title != "") {
			t.Errorf("%s: title %q (only x- checks have one)", c.ID, c.Title)
		}
	}
	for _, id := range []string{IDSpamRules, IDExternalLookups} {
		find(t, res.Checks, id)
	}
	for _, id := range Catalog {
		if strings.HasSuffix(id, ":") {
			id += "example.com"
		}
		if !InCatalog(id) {
			t.Errorf("Catalog lists %s", id)
		}
	}
	for _, bad := range []string{"spam_rules", "external_lookups", "x-", "x-Upper", "dkim_stuck:", "records", "tlsa", "x-" + strings.Repeat("a", 41)} {
		if InCatalog(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
