package resolve

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func server(t *testing.T, recs map[string][]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, s := range recs[r.Question[0].Name] {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: splitN(s, 255)})
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func splitN(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

func TestVisibleAllJoinsLongTXT(t *testing.T) {
	long := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 400)
	a := server(t, map[string][]string{"s._domainkey.example.com.": {long}})
	b := server(t, map[string][]string{"s._domainkey.example.com.": {"other"}})
	ctx := context.Background()
	if !VisibleAll(ctx, []string{a}, "s._domainkey.example.com", long) {
		t.Fatal("a split 400-byte TXT isn't seen whole")
	}
	if VisibleAll(ctx, []string{a, b}, "s._domainkey.example.com", long) {
		t.Fatal("visible though one resolver serves another value")
	}
	if VisibleAll(ctx, []string{a, "127.0.0.1:1"}, "s._domainkey.example.com", long) {
		t.Fatal("a failed lookup counted as visible")
	}
}
