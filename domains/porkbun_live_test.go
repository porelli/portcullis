//go:build pblive

package main

// A live check of porkbunProvider against Porkbun, by hand only (build tag
// pblive; never in CI): PB_ENV names an .env with PORKBUN_API_KEY /
// PORKBUN_SECRET_API_KEY, PB_DOMAIN the Porkbun domain, PB_SCRATCH a
// scratch label under it (every record goes below it and is deleted).

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestPorkbunLive(t *testing.T) {
	keys := map[string]string{}
	f, err := os.Open(os.Getenv("PB_ENV"))
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if ok && (k == "PORKBUN_API_KEY" || k == "PORKBUN_SECRET_API_KEY") {
			keys[k] = strings.Trim(v, `"'`)
		}
	}
	f.Close()
	dom, scratch := os.Getenv("PB_DOMAIN"), os.Getenv("PB_SCRATCH")
	if keys["PORKBUN_API_KEY"] == "" || dom == "" || !strings.HasPrefix(scratch, "_pc-test.") {
		t.Fatal("PB_ENV / PB_DOMAIN / PB_SCRATCH (a _pc-test.* label)")
	}
	p := newPorkbunProvider(newPorkbunAPI(keys["PORKBUN_API_KEY"], keys["PORKBUN_SECRET_API_KEY"]))
	ctx, zone := context.Background(), dom+"."
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 13)
	recs := []libdns.Record{
		libdns.RR{Name: scratch, Type: "MX", TTL: time.Hour, Data: "10 mail." + scratch + "." + dom + "."},
		libdns.RR{Name: "n." + scratch, Type: "MX", TTL: time.Hour, Data: "0 ."},
		libdns.RR{Name: "_submissions._tcp." + scratch, Type: "SRV", TTL: time.Hour, Data: "0 1 465 mail." + scratch + "." + dom + "."},
		libdns.RR{Name: "_imap._tcp." + scratch, Type: "SRV", TTL: time.Hour, Data: "0 0 0 ."},
		libdns.RR{Name: "_25._tcp.mail." + scratch, Type: "TLSA", TTL: time.Hour, Data: "3 1 1 " + strings.Repeat("ab", 32)},
		libdns.TXT{Name: "v1._domainkey." + scratch, TTL: time.Hour, Text: dkim},
		libdns.TXT{Name: scratch, TTL: time.Hour, Text: "v=spf1 mx -all"},
		libdns.CAA{Name: scratch, TTL: time.Hour, Tag: "issue", Value: "letsencrypt.org; validationmethods=dns-01"},
	}
	made, err := p.AppendRecords(ctx, zone, recs)
	defer func() {
		if _, derr := p.DeleteRecords(ctx, zone, made); derr != nil {
			t.Errorf("cleanup: %v", derr)
		}
		left, _ := p.GetRecords(ctx, zone)
		for _, r := range left {
			if strings.Contains(r.RR().Name, "_pc-test") {
				t.Errorf("left behind: %+v", r.RR())
			}
		}
	}()
	if err != nil {
		t.Fatalf("append (%d made): %v", len(made), err)
	}
	got, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range got {
		rr := r.RR()
		seen[rr.Type+" "+rr.Name+" "+rr.Data] = true
	}
	for _, r := range recs {
		rr := r.RR()
		if !seen[rr.Type+" "+rr.Name+" "+rr.Data] {
			t.Errorf("not read back as written: %s %s %q", rr.Type, rr.Name, rr.Data)
		}
	}
}
