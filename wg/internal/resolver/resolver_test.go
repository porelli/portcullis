package resolver

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var (
	server  = netip.MustParseAddr("203.0.113.10")
	server6 = netip.MustParseAddr("2001:db8::10")
	self    = netip.MustParseAddr("10.213.0.1")
)

func rw() *Rewriter {
	return &Rewriter{Domains: []string{"example.org", "team-b.test"}, Server: []netip.Addr{server, server6}, Self: self}
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func query(name string, qt uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.SetEdns0(1232, true)
	return m
}

func reply(t *testing.T, q *dns.Msg, ans ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.AuthenticatedData = true
	for _, a := range ans {
		m.Answer = append(m.Answer, rr(t, a))
	}
	m.Ns = append(m.Ns, rr(t, "example.org. 300 IN RRSIG SOA 13 2 300 20261201000000 20261101000000 12345 example.org. AAAA"))
	return m
}

func answers(m *dns.Msg) []string {
	var out []string
	for _, a := range m.Answer {
		out = append(out, strings.Join(strings.Fields(a.String()), " "))
	}
	return out
}

func noRRSIG(t *testing.T, m *dns.Msg) {
	t.Helper()
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range sec {
			if r.Header().Rrtype == dns.TypeRRSIG {
				t.Fatalf("RRSIG left: %v", r)
			}
		}
	}
}

func TestRewriteTable(t *testing.T) {
	r := rw()
	cases := []struct {
		name    string
		qname   string
		qt      uint16
		ans     []string
		want    []string
		rewrote bool
	}{
		{"apex", "example.org", dns.TypeA,
			[]string{"example.org. 300 IN A 203.0.113.10", "example.org. 300 IN RRSIG A 13 2 300 20261201000000 20261101000000 1 example.org. AAAA"},
			[]string{"example.org. 300 IN A 10.213.0.1"}, true},
		{"app host", "app.example.org", dns.TypeA,
			[]string{"app.example.org. 300 IN A 203.0.113.10"},
			[]string{"app.example.org. 300 IN A 10.213.0.1"}, true},
		{"case folded", "APP.Example.ORG", dns.TypeA,
			[]string{"APP.Example.ORG. 300 IN A 203.0.113.10"},
			[]string{"APP.Example.ORG. 300 IN A 10.213.0.1"}, true},
		{"enrolled domain", "x.team-b.test", dns.TypeA,
			[]string{"x.team-b.test. 60 IN A 203.0.113.10"},
			[]string{"x.team-b.test. 60 IN A 10.213.0.1"}, true},
		{"aaaa nodata", "app.example.org", dns.TypeAAAA,
			[]string{"app.example.org. 300 IN AAAA 2001:db8::10"},
			nil, true},
		{"foreign a untouched", "nas.example.org", dns.TypeA,
			[]string{"nas.example.org. 300 IN A 198.51.100.4"},
			[]string{"nas.example.org. 300 IN A 198.51.100.4"}, false},
		{"foreign aaaa untouched", "nas.example.org", dns.TypeAAAA,
			[]string{"nas.example.org. 300 IN AAAA 2001:db8::99"},
			[]string{"nas.example.org. 300 IN AAAA 2001:db8::99"}, false},
		{"not portcullis", "www.example.com", dns.TypeA,
			[]string{"www.example.com. 300 IN A 203.0.113.10"},
			[]string{"www.example.com. 300 IN A 203.0.113.10"}, false},
		{"suffix lookalike", "badexample.org", dns.TypeA,
			[]string{"badexample.org. 300 IN A 203.0.113.10"},
			[]string{"badexample.org. 300 IN A 203.0.113.10"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := query(tc.qname, tc.qt)
			up := reply(t, q, tc.ans...)
			got := r.Rewrite(q, up)
			if strings.Join(answers(got), "|") != strings.Join(tc.want, "|") {
				t.Fatalf("answers %v, want %v", answers(got), tc.want)
			}
			if got.Rcode != dns.RcodeSuccess || got.Id != q.Id {
				t.Fatalf("rcode %d id %d", got.Rcode, got.Id)
			}
			if inScope := tc.name != "not portcullis" && tc.name != "suffix lookalike"; inScope {
				if got.AuthenticatedData {
					t.Fatal("AD set on a Portcullis name")
				}
				noRRSIG(t, got)
			} else if !got.AuthenticatedData {
				t.Fatal("a foreign answer was modified (AD cleared)")
			}
		})
	}
}

func TestRewriteCNAMEChain(t *testing.T) {
	r := rw()
	q := query("app.example.org", dns.TypeA)
	up := reply(t, q,
		"app.example.org. 300 IN CNAME example.org.",
		"app.example.org. 300 IN RRSIG CNAME 13 3 300 20261201000000 20261101000000 1 example.org. AAAA",
		"example.org. 300 IN A 203.0.113.10",
		"example.org. 300 IN RRSIG A 13 2 300 20261201000000 20261101000000 1 example.org. AAAA")
	got := r.Rewrite(q, up)
	want := []string{"app.example.org. 300 IN CNAME example.org.", "example.org. 300 IN A 10.213.0.1"}
	if strings.Join(answers(got), "|") != strings.Join(want, "|") {
		t.Fatalf("answers %v", answers(got))
	}
	noRRSIG(t, got)
	if got.AuthenticatedData {
		t.Fatal("AD set")
	}

	q = query("docs.example.org", dns.TypeA)
	up = reply(t, q,
		"docs.example.org. 300 IN CNAME pages.hoster.example.",
		"pages.hoster.example. 60 IN A 192.0.2.80")
	got = r.Rewrite(q, up)
	want = []string{"docs.example.org. 300 IN CNAME pages.hoster.example.", "pages.hoster.example. 60 IN A 192.0.2.80"}
	if strings.Join(answers(got), "|") != strings.Join(want, "|") {
		t.Fatalf("foreign chain changed: %v", answers(got))
	}

	// A foreign chain landing on a host that resolves to this server's
	// address is still pointing at this server: rewritten.
	q = query("alias.example.org", dns.TypeAAAA)
	up = reply(t, q, "alias.example.org. 300 IN CNAME example.org.", "example.org. 300 IN AAAA 2001:db8::10")
	got = r.Rewrite(q, up)
	if want := []string{"alias.example.org. 300 IN CNAME example.org."}; strings.Join(answers(got), "|") != strings.Join(want, "|") {
		t.Fatalf("aaaa through cname: %v", answers(got))
	}
}

func TestRewriteNilUpstream(t *testing.T) {
	q := query("app.example.org", dns.TypeA)
	got := rw().Rewrite(q, nil)
	if got.Rcode != dns.RcodeServerFailure || got.Id != q.Id {
		t.Fatalf("rcode %d", got.Rcode)
	}
}

// TestForwarder runs the handler against a fake upstream over UDP.
func TestForwarder(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = append(m.Answer, rr(t, q.Question[0].Name+" 60 IN A 203.0.113.10"))
		w.WriteMsg(m)
	})}
	go up.ActivateAndServe()
	defer up.Shutdown()
	f := &Forwarder{Upstreams: []string{pc.LocalAddr().String()}, Rewriter: func() *Rewriter { return rw() }, Timeout: 2 * time.Second}
	got, err := f.Exchange(context.Background(), query("app.example.org", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if a := answers(got); len(a) != 1 || !strings.HasSuffix(a[0], "10.213.0.1") {
		t.Fatalf("answers %v", a)
	}
	f2 := &Forwarder{Upstreams: []string{"127.0.0.1:1"}, Rewriter: func() *Rewriter { return rw() }, Timeout: 300 * time.Millisecond}
	got, _ = f2.Exchange(context.Background(), query("app.example.org", dns.TypeA))
	if got == nil || got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("dead upstream: %+v", got)
	}
}
