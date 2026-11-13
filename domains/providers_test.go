package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/dnssec"
)

const cfToken = "cf-Tk9vZXJ5U2VjcmV0VG9rZW4xMjM0"

// cfFake is Cloudflare's zones + dnssec API; it records every request.
type cfFake struct {
	mu     sync.Mutex
	bodies []string
	auth   []string
	status string // the zone's dnssec status
	forbid bool   // PATCH answers 403
	echo   bool   // errors echo the Authorization header
}

func (f *cfFake) handler() http.Handler {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, result any) {
		json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "result": result})
	}
	mux.HandleFunc("GET /zones", func(w http.ResponseWriter, r *http.Request) {
		if f.echo {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"success":false,"errors":[{"code":6003,"message":"bad header %s"}]}`, r.Header.Get("Authorization"))
			return
		}
		ok(w, []map[string]string{{"id": "zid-1", "name": r.URL.Query().Get("name")}})
	})
	mux.HandleFunc("GET /zones/zid-1/dnssec", func(w http.ResponseWriter, _ *http.Request) {
		ok(w, map[string]any{"status": f.status, "ds": "example.org. 3600 IN DS 2371 13 2 1F98…", "key_tag": 2371, "algorithm": "13", "digest_type": "2",
			"digest": "1f987cc6583e92df0890718c42"})
	})
	mux.HandleFunc("PATCH /zones/zid-1/dnssec", func(w http.ResponseWriter, _ *http.Request) {
		if f.forbid {
			w.WriteHeader(403)
			io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
			return
		}
		f.status = "pending"
		ok(w, map[string]any{"status": "pending"})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, r.Method+" "+r.URL.Path+" "+string(b))
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		mux.ServeHTTP(w, r)
	})
}

func newCF(t *testing.T, f *cfFake) *cloudflareDNSSEC {
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return &cloudflareDNSSEC{token: cfToken, base: srv.URL, hc: srv.Client()}
}

func TestCloudflareDNSSECStatus(t *testing.T) {
	c := newCF(t, &cfFake{status: "active"})
	st, ds, err := c.DNSSECStatus(context.Background(), "example.org.")
	if err != nil || st != "active" || len(ds) != 1 {
		t.Fatalf("%q %v %v", st, ds, err)
	}
	if want := (dnssec.DS{KeyTag: 2371, Algorithm: 13, DigestType: 2, Digest: "1F987CC6583E92DF0890718C42"}); ds[0] != want {
		t.Fatalf("ds %+v", ds[0])
	}
}

func TestCloudflareEnableDNSSEC(t *testing.T) {
	f := &cfFake{status: "disabled"}
	c := newCF(t, f)
	if err := c.EnableDNSSEC(context.Background(), "example.org"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	last := f.bodies[len(f.bodies)-1]
	if last != `PATCH /zones/zid-1/dnssec {"status":"active"}` {
		t.Fatalf("request %q", last)
	}
	for _, a := range f.auth {
		if a != "Bearer "+cfToken {
			t.Fatalf("auth %q", a)
		}
	}
}

func TestCloudflareEnable403NamesPermission(t *testing.T) {
	c := newCF(t, &cfFake{status: "disabled", forbid: true})
	err := c.EnableDNSSEC(context.Background(), "example.org")
	if err == nil || !strings.Contains(err.Error(), "Zone › DNS Settings › Edit") {
		t.Fatalf("%v", err)
	}
}

// TestCloudflareNeverDisables: no request of any exported path asks for
// "disabled" (there is no such path).
func TestCloudflareNeverDisables(t *testing.T) {
	f := &cfFake{status: "active"}
	c := newCF(t, f)
	c.DNSSECStatus(context.Background(), "example.org")
	c.EnableDNSSEC(context.Background(), "example.org")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.bodies {
		if strings.Contains(b, "disabled") {
			t.Fatalf("request %q", b)
		}
	}
	var s dnssec.Signer = c
	_ = s
}

const r53GetDNSSEC = `<?xml version="1.0"?>
<GetDNSSECResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<Status><ServeSignature>SIGNING</ServeSignature></Status>
<KeySigningKeys><member><Name>ksk1</Name><Status>ACTIVE</Status><KeyTag>4711</KeyTag><Flag>257</Flag>
<SigningAlgorithmType>13</SigningAlgorithmType><DigestAlgorithmType>2</DigestAlgorithmType><DigestValue>abcdef0123</DigestValue></member></KeySigningKeys>
</GetDNSSECResponse>`

func TestRoute53GetDNSSEC(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/hostedzonesbyname"):
			io.WriteString(w, `<?xml version="1.0"?><ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/Z123</Id><Name>example.org.</Name><CallerReference>x</CallerReference></HostedZone></HostedZones><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems></ListHostedZonesByNameResponse>`)
		case r.URL.Path == "/2013-04-01/hostedzone/Z123/dnssec":
			io.WriteString(w, r53GetDNSSEC)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	r := newRoute53DNSSEC(map[string]string{"access_key_id": "AKIAEXAMPLE0", "secret_access_key": "secret-0123456789"}, srv.URL)
	st, ds, err := r.DNSSECStatus(context.Background(), "example.org.")
	if err != nil || st != "SIGNING" || len(ds) != 1 || ds[0] != (dnssec.DS{KeyTag: 4711, Algorithm: 13, DigestType: 2, Digest: "ABCDEF0123"}) {
		t.Fatalf("%q %+v %v (paths %v)", st, ds, err, paths)
	}
	if _, isSigner := any(r).(dnssec.Signer); isSigner {
		t.Fatal("route53 must not be a Signer")
	}
}

func TestRoute53AccessDeniedFallsBack(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `<?xml version="1.0"?><ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>`)
	}))
	defer srv.Close()
	r := newRoute53DNSSEC(map[string]string{"access_key_id": "AKIAEXAMPLE0", "secret_access_key": "secret-0123456789", "hosted_zone_id": "Z123"}, srv.URL)
	if _, _, err := r.DNSSECStatus(context.Background(), "example.org."); !errors.Is(err, errNoProviderData) {
		t.Fatalf("%v", err)
	}
}

// doFake is DigitalOcean's records API.
type doFake struct {
	mu     sync.Mutex
	nextID int
	recs   map[int]map[string]any
	posts  []string
	dels   []int
	ops    []string
}

func (f *doFake) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		const base = "/v2/domains/example.org/records"
		switch {
		case r.Method == "GET" && r.URL.Path == base:
			list := []map[string]any{}
			for id := 1; id <= f.nextID; id++ {
				if rec, ok := f.recs[id]; ok {
					list = append(list, rec)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"domain_records": list, "links": map[string]any{}, "meta": map[string]any{"total": len(list)}})
		case r.Method == "POST" && r.URL.Path == base:
			b, _ := io.ReadAll(r.Body)
			f.posts = append(f.posts, string(b))
			f.ops = append(f.ops, "post")
			var rec map[string]any
			json.Unmarshal(b, &rec)
			f.nextID++
			rec["id"] = f.nextID
			f.recs[f.nextID] = rec
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"domain_record": rec})
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, base+"/"):
			var id int
			fmt.Sscanf(strings.TrimPrefix(r.URL.Path, base+"/"), "%d", &id)
			f.dels = append(f.dels, id)
			f.ops = append(f.ops, "del")
			delete(f.recs, id)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	})
}

func newDO(t *testing.T) (*doFake, *doProvider) {
	f := &doFake{recs: map[int]map[string]any{}}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	p, err := newDOProviderAt(srv.Client(), srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	return f, p
}

func TestDigitalOceanCAASendsFlagsTag(t *testing.T) {
	f, p := newDO(t)
	v := "letsencrypt.org; validationmethods=dns-01"
	_, err := p.SetRecords(context.Background(), "example.org.", []libdns.Record{
		libdns.CAA{Name: "team", TTL: 300 * time.Second, Tag: "issue", Value: v},
		libdns.CAA{Name: "team", TTL: 300 * time.Second, Tag: "issuewild", Value: v},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.posts) != 2 || !strings.Contains(f.posts[0], `"flags":0`) || !strings.Contains(f.posts[0], `"tag":"issue"`) ||
		!strings.Contains(f.posts[1], `"tag":"issuewild"`) || !strings.Contains(f.posts[0], `"data":"`+v+`"`) || !strings.Contains(f.posts[0], `"ttl":300`) {
		t.Fatalf("posts %v", f.posts)
	}
	// Read back as typed CAA records; a second Set changes nothing.
	recs, err := p.GetRecords(context.Background(), "example.org.")
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %v", recs, err)
	}
	if c, ok := recs[0].(libdns.CAA); !ok || c.Tag != "issue" || c.Value != v {
		t.Fatalf("%#v", recs[0])
	}
	p.SetRecords(context.Background(), "example.org.", []libdns.Record{libdns.CAA{Name: "team", TTL: 300 * time.Second, Tag: "issue", Value: v}, libdns.CAA{Name: "team", TTL: 300 * time.Second, Tag: "issuewild", Value: v}})
	if len(f.posts) != 2 || len(f.dels) != 0 {
		t.Fatalf("churn: posts %d dels %v", len(f.posts), f.dels)
	}
	// Deleting exactly one entry leaves the other.
	if _, err := p.DeleteRecords(context.Background(), "example.org.", []libdns.Record{libdns.CAA{Name: "team", Tag: "issuewild", Value: v}}); err != nil || len(f.recs) != 1 {
		t.Fatalf("%v %v", err, f.recs)
	}
}

func TestDigitalOceanNonCAAPassesThrough(t *testing.T) {
	f, p := newDO(t)
	ctx := context.Background()
	p.AppendRecords(ctx, "example.org.", []libdns.Record{libdns.RR{Name: "team", Type: "A", Data: "198.51.100.1", TTL: time.Hour}})
	_, err := p.SetRecords(ctx, "example.org.", []libdns.Record{
		libdns.Address{Name: "team", TTL: 300 * time.Second, IP: mustAddr("203.0.113.10")},
		libdns.MX{Name: "team", TTL: time.Hour, Preference: 0, Target: "."},
		libdns.TXT{Name: "_acme-challenge.team", TTL: time.Minute, Text: "tok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.dels) != 1 || f.dels[0] != 1 {
		t.Fatalf("the old A wasn't replaced: dels %v", f.dels)
	}
	// Create before delete per RRset (review I2): the new A, then the old one goes.
	if strings.Join(f.ops, ",") != "post,post,del,post,post" {
		t.Fatalf("ops %v", f.ops)
	}
	all := strings.Join(f.posts, "\n")
	for _, want := range []string{`"type":"A","name":"team","data":"203.0.113.10"`, `"type":"MX","name":"team","data":".","priority":0`, `"type":"TXT","name":"_acme-challenge.team","data":"tok"`} {
		if !strings.Contains(all, want) {
			t.Errorf("no %s in\n%s", want, all)
		}
	}
	// libdns delete semantics: type only matches every value.
	if _, err := p.DeleteRecords(ctx, "example.org.", []libdns.Record{libdns.RR{Name: "team", Type: "A"}}); err != nil {
		t.Fatal(err)
	}
	for _, r := range f.recs {
		if r["type"] == "A" {
			t.Fatalf("A left: %v", f.recs)
		}
	}
}

func TestHetznerCloudValidateCredentials(t *testing.T) {
	if err := validateCredentials("hetzner-cloud", map[string]string{"api_token": "hcloud-0123456789"}); err != nil {
		t.Fatal(err)
	}
	if err := validateCredentials("hetzner-cloud", map[string]string{"api_token": "hcloud-0123456789", "api_key": "x-0123456789"}); err == nil {
		t.Fatal("an unknown key accepted")
	}
	if _, err := buildProvider(&Domain{Provider: "hetzner-cloud", Credentials: map[string]string{"api_token": "hcloud-0123456789"}}); err != nil {
		t.Fatal(err)
	}
	if r, can, err := buildDNSSEC(&Domain{Provider: "hetzner-cloud", Credentials: map[string]string{"api_token": "hcloud-0123456789"}}); r != nil || can || err != nil {
		t.Fatalf("hetzner-cloud dnssec %v %v %v", r, can, err)
	}
}

func TestDNSSECErrorsRedacted(t *testing.T) {
	f := &cfFake{echo: true}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	providers["cf-test"] = providerSpec{required: []string{"api_token"}, build: providers["cloudflare"].build,
		dnssec: func(c map[string]string) (dnssec.StatusReader, error) {
			return &cloudflareDNSSEC{token: c["api_token"], base: srv.URL, hc: srv.Client()}, nil
		}}
	defer delete(providers, "cf-test")
	r, can, err := buildDNSSEC(&Domain{Provider: "cf-test", Credentials: map[string]string{"api_token": cfToken}})
	if err != nil || !can {
		t.Fatalf("%v %v", can, err)
	}
	_, _, err = r.DNSSECStatus(context.Background(), "example.org")
	if err == nil || strings.Contains(err.Error(), cfToken) || strings.Contains(err.Error(), cfToken[:len(cfToken)/2]) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("%v", err)
	}
	if err := r.(dnssec.Signer).EnableDNSSEC(context.Background(), "example.org"); err == nil || strings.Contains(err.Error(), cfToken) {
		t.Fatalf("%v", err)
	}
	// cloudflare signs, route53 only reads, the others have nothing.
	for p, want := range map[string]bool{"cloudflare": true, "route53": false} {
		c := map[string]string{"api_token": cfToken, "access_key_id": "AKIAEXAMPLE0", "secret_access_key": "secret-0123456789"}
		r, can, err := buildDNSSEC(&Domain{Provider: p, Credentials: c})
		if err != nil || r == nil || can != want {
			t.Errorf("%s: %v %v %v", p, r, can, err)
		}
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
