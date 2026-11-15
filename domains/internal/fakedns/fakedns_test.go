package fakedns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"
)

func serve(t *testing.T, z *Zone, o Options) *Server {
	t.Helper()
	s, err := ServeWith(z, "127.0.0.1:0", o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func ask(t *testing.T, s *Server, name string, qt uint16, cd bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	m.CheckingDisabled = cd
	m.SetEdns0(4096, true)
	in, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestServesCAAMXTXTCNAME(t *testing.T) {
	z := NewZone()
	z.Set("d.test",
		libdns.CAA{Name: "@", TTL: 300 * time.Second, Flags: 0, Tag: "issue", Value: "letsencrypt.org; validationmethods=dns-01"}.RR(),
		libdns.MX{Name: "@", TTL: time.Hour, Preference: 0, Target: "."}.RR(),
		libdns.TXT{Name: "@", TTL: time.Hour, Text: "v=spf1 -all"}.RR())
	z.Set("www.d.test", libdns.CNAME{Name: "www", TTL: time.Minute, Target: "d.test."}.RR())
	z.Set("d.test", append(z.Records("d.test"), libdns.RR{Name: "@", Type: "A", Data: "203.0.113.10", TTL: time.Minute})...)
	s := serve(t, z, Options{})

	in := ask(t, s, "d.test", dns.TypeCAA, false)
	if len(in.Answer) != 1 {
		t.Fatalf("CAA answer %v", in.Answer)
	}
	caa := in.Answer[0].(*dns.CAA)
	if caa.Flag != 0 || caa.Tag != "issue" || caa.Value != "letsencrypt.org; validationmethods=dns-01" || caa.Hdr.Ttl != 300 {
		t.Fatalf("CAA %v", caa)
	}
	in = ask(t, s, "d.test", dns.TypeMX, false)
	if mx := in.Answer[0].(*dns.MX); mx.Preference != 0 || mx.Mx != "." {
		t.Fatalf("MX %v", mx)
	}
	in = ask(t, s, "d.test", dns.TypeTXT, false)
	if txt := in.Answer[0].(*dns.TXT); strings.Join(txt.Txt, "") != "v=spf1 -all" {
		t.Fatalf("TXT %v", txt)
	}
	in = ask(t, s, "www.d.test", dns.TypeCNAME, false)
	if c := in.Answer[0].(*dns.CNAME); c.Target != "d.test." {
		t.Fatalf("CNAME %v", c)
	}
	// An A query at the alias follows it.
	in = ask(t, s, "www.d.test", dns.TypeA, false)
	if len(in.Answer) != 2 || in.Answer[1].(*dns.A).A.String() != "203.0.113.10" {
		t.Fatalf("A via CNAME %v", in.Answer)
	}
}

func TestNXDOMAIN(t *testing.T) {
	z := NewZone()
	z.SetSOA("d.test")
	z.Set("a.b.d.test", libdns.RR{Name: "a.b", Type: "A", Data: "203.0.113.1"})
	s := serve(t, z, Options{})
	if in := ask(t, s, "nope.d.test", dns.TypeA, false); in.Rcode != dns.RcodeNameError || len(in.Ns) != 1 {
		t.Fatalf("nope: rcode %d ns %v", in.Rcode, in.Ns)
	}
	// An empty non-terminal exists (NOERROR, no answer).
	if in := ask(t, s, "b.d.test", dns.TypeA, false); in.Rcode != dns.RcodeSuccess || len(in.Answer) != 0 {
		t.Fatalf("ENT: rcode %d %v", in.Rcode, in.Answer)
	}
	if in := ask(t, s, "d.test", dns.TypeSOA, false); len(in.Answer) != 1 {
		t.Fatalf("SOA %v", in.Answer)
	}
}

func TestValidatingAD(t *testing.T) {
	z := NewZone()
	k, err := z.Sign("d.test")
	if err != nil {
		t.Fatal(err)
	}
	z.Set("d.test", libdns.RR{Name: "@", Type: "A", Data: "203.0.113.1"})
	z.PublishDS("d.test", k.ToDS(dns.SHA256))
	s := serve(t, z, Options{Validating: true})
	if in := ask(t, s, "d.test", dns.TypeA, false); !in.AuthenticatedData || in.Rcode != dns.RcodeSuccess {
		t.Fatalf("secure: AD %v rcode %d", in.AuthenticatedData, in.Rcode)
	}
	in := ask(t, s, "d.test", dns.TypeDNSKEY, false)
	if len(in.Answer) != 2 {
		t.Fatalf("DNSKEY answer %v", in.Answer)
	}
	if err := in.Answer[1].(*dns.RRSIG).Verify(in.Answer[0].(*dns.DNSKEY), in.Answer[:1]); err != nil {
		t.Fatalf("RRSIG doesn't verify: %v", err)
	}
	bad := *k.ToDS(dns.SHA256)
	bad.Digest = strings.Repeat("00", 32)
	z.PublishDS("d.test", &bad)
	if in := ask(t, s, "d.test", dns.TypeA, false); in.Rcode != dns.RcodeServerFailure {
		t.Fatalf("mismatch: rcode %d", in.Rcode)
	}
	if in := ask(t, s, "d.test", dns.TypeA, true); in.Rcode != dns.RcodeSuccess || in.AuthenticatedData || len(in.Answer) != 1 {
		t.Fatalf("mismatch with CD: rcode %d AD %v %v", in.Rcode, in.AuthenticatedData, in.Answer)
	}
	// Signed without DS: insecure, answers without AD.
	z.PublishDS("d.test")
	if in := ask(t, s, "d.test", dns.TypeA, false); in.AuthenticatedData || in.Rcode != dns.RcodeSuccess {
		t.Fatalf("no DS: AD %v rcode %d", in.AuthenticatedData, in.Rcode)
	}
	// Non-validating servers never set AD.
	z.PublishDS("d.test", k.ToDS(dns.SHA256))
	plain := serve(t, z, Options{})
	if in := ask(t, plain, "d.test", dns.TypeA, false); in.AuthenticatedData {
		t.Fatal("AD from a non-validating server")
	}
}

func TestQueriesLogged(t *testing.T) {
	z := NewZone()
	s := serve(t, z, Options{})
	ask(t, s, "D.test", dns.TypeCAA, false)
	ask(t, s, "x.d.test", dns.TypeA, false)
	if got := strings.Join(s.Queries(), "|"); got != "CAA d.test|A x.d.test" {
		t.Fatalf("queries %q", got)
	}
}

// libdns/porkbun v1.1.0's porkbunRecordPayload raises a TTL under 600 s to
// 600 for every write, appends and SetRecords' edits alike.
func TestPorkbunTTLFloor(t *testing.T) {
	z := NewZone()
	p := &Provider{Zone: z, DeleteMode: "porkbun", SetMode: "porkbun"}
	ctx := context.Background()
	if _, err := p.AppendRecords(ctx, "example.test.", []libdns.Record{libdns.RR{Name: "a", Type: "TXT", TTL: 300 * time.Second, Data: "x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SetRecords(ctx, "example.test.", []libdns.Record{libdns.RR{Name: "b", Type: "TXT", TTL: 60 * time.Second, Data: "y"},
		libdns.RR{Name: "a", Type: "TXT", TTL: 120 * time.Second, Data: "z"}}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"a.example.test", "b.example.test"} {
		for _, rr := range z.Records(n) {
			if rr.TTL != 600*time.Second {
				t.Errorf("%s stored TTL %s, want porkbun's 600 s floor", n, rr.TTL)
			}
		}
	}
	// 900 s stays 900 s.
	if _, err := p.AppendRecords(ctx, "example.test.", []libdns.Record{libdns.RR{Name: "c", Type: "TXT", TTL: 900 * time.Second, Data: "x"}}); err != nil {
		t.Fatal(err)
	}
	if rr := z.Records("c.example.test"); len(rr) != 1 || rr[0].TTL != 900*time.Second {
		t.Fatalf("c = %v", rr)
	}
}

// TestServesSRVTLSAAndLongTXT: SRV and TLSA answers; a long TXT stored
// split (TXTSplit255) or whole is served as ≤ 255-byte strings, and too
// large for a plain UDP answer it is truncated (TC).
func TestServesSRVTLSAAndLongTXT(t *testing.T) {
	long := strings.Repeat("a", 300) + strings.Repeat("b", 300)
	for _, split := range []bool{true, false} {
		z := NewZone()
		p := &Provider{Zone: z, TXTSplit255: split, RefuseTypes: []string{"HINFO"}}
		ctx := context.Background()
		if _, err := p.AppendRecords(ctx, "d.test.", []libdns.Record{
			libdns.TXT{Name: "k._domainkey", TTL: time.Hour, Text: long},
			libdns.SRV{Service: "imaps", Transport: "tcp", Name: "@", TTL: time.Hour, Priority: 0, Weight: 1, Port: 993, Target: "mail.d.test."},
			libdns.RR{Name: "_25._tcp.mail", Type: "TLSA", TTL: time.Hour, Data: "3 1 1 abcd"},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := p.AppendRecords(ctx, "d.test.", []libdns.Record{libdns.RR{Name: "x", Type: "HINFO", Data: "a b"}}); err == nil {
			t.Fatal("a refused type was written")
		}
		stored := z.Records("k._domainkey.d.test")[0].Data
		if split != strings.HasPrefix(stored, `"`) || txtJoined(stored) != long {
			t.Fatalf("split=%v stored %q", split, stored)
		}
		s := serve(t, z, Options{})
		txt := ask(t, s, "k._domainkey.d.test", dns.TypeTXT, false).Answer[0].(*dns.TXT).Txt
		if len(txt) != 3 || len(txt[0]) != 255 || strings.Join(txt, "") != long {
			t.Fatalf("served %q", txt)
		}
		srv := ask(t, s, "_imaps._tcp.d.test", dns.TypeSRV, false).Answer[0].(*dns.SRV)
		if srv.Port != 993 || srv.Target != "mail.d.test." {
			t.Fatalf("SRV %v", srv)
		}
		tlsa := ask(t, s, "_25._tcp.mail.d.test", dns.TypeTLSA, false).Answer[0].(*dns.TLSA)
		if tlsa.Usage != 3 || tlsa.Certificate != "abcd" {
			t.Fatalf("TLSA %v", tlsa)
		}
		m := new(dns.Msg)
		m.SetQuestion("k._domainkey.d.test.", dns.TypeTXT)
		in, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, s.Addr)
		if err != nil || !in.Truncated {
			t.Fatalf("plain UDP: %v %v", in, err)
		}
		// Deleting by the joined value removes the split record.
		if del, err := p.DeleteRecords(ctx, "d.test.", []libdns.Record{libdns.TXT{Name: "k._domainkey", Text: long}}); err != nil || len(del) != 1 {
			t.Fatalf("delete %v %v", del, err)
		}
	}
}
