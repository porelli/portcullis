package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/dnsplan"
	"github.com/portcullis/domains/internal/fakedns"
)

// The final-review C1 cases: libdns/porkbun v1.1.0 deletes every record
// with the name and type, libdns/hetzner v1.0.0 the first one. Through the
// provider the service builds for them (fakedns DeleteMode playing the
// library), a partial delete must remove exactly the stale entries.

const (
	bzone = "example.net."
	bname = "portcullis.example.net"
)

func deleteModes() []string { return []string{"porkbun", "hetzner"} }

// modeProvider is the fake zone behind the library's delete semantics,
// wrapped as buildProvider wraps the real library.
func modeProvider(z *fakedns.Zone, mode string) dnsProvider {
	raw := &fakedns.Provider{Zone: z, ZoneName: bzone, DeleteMode: mode}
	return newByIDDelete(raw, fakeIDs{raw})
}

func sortedRRs(z *fakedns.Zone, name, typ string) []string {
	var out []string
	for _, rr := range z.Records(name) {
		if rr.Type == typ {
			out = append(out, rr.Data)
		}
	}
	sort.Strings(out)
	return out
}

func bspec(acct string) dnsplan.Spec {
	return dnsplan.Spec{Name: bname, IPv4: netip.MustParseAddr("203.0.113.10"), CAA: true, Issuer: "letsencrypt.org", AccountURI: acct}
}

func TestDeleteModeAccountSwitchKeepsCAA(t *testing.T) {
	const old, cur = "https://acme-v02.api.letsencrypt.org/acme/acct/123", "https://acme-v02.api.letsencrypt.org/acme/acct/456"
	for _, mode := range deleteModes() {
		t.Run(mode, func(t *testing.T) {
			z := fakedns.NewZone()
			ov := dnsplan.CAAValue("letsencrypt.org", old)
			z.Set(bname, libdns.CAA{Name: "portcullis", TTL: time.Hour, Tag: "issue", Value: "digicert.com"}.RR(),
				libdns.CAA{Name: "portcullis", TTL: dnsplan.TTLCAA, Tag: "issue", Value: ov}.RR(),
				libdns.CAA{Name: "portcullis", TTL: dnsplan.TTLCAA, Tag: "issuewild", Value: ov}.RR())
			in := dnsplan.Input{Spec: bspec(cur), Zone: bzone, Provider: modeProvider(z, mode)}
			if _, _, err := dnsplan.Apply(context.Background(), in, []string{dnsplan.SetCAA}); err != nil {
				t.Fatal(err)
			}
			nv := dnsplan.CAAValue("letsencrypt.org", cur)
			want := []string{`0 issue "digicert.com"`, `0 issue "` + nv + `"`, `0 issuewild "` + nv + `"`}
			sort.Strings(want)
			if got := sortedRRs(z, bname, "CAA"); strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("CAA after the switch %v, want %v", got, want)
			}
		})
	}
}

func TestDeleteModeIPChangeKeepsA(t *testing.T) {
	for _, mode := range deleteModes() {
		t.Run(mode, func(t *testing.T) {
			z := fakedns.NewZone()
			z.Set(bname, libdns.RR{Name: "portcullis", Type: "A", TTL: dnsplan.TTLAddress, Data: "198.51.100.1"})
			z.Set("*."+bname, libdns.RR{Name: "*.portcullis", Type: "A", TTL: dnsplan.TTLAddress, Data: "198.51.100.1"})
			in := dnsplan.Input{Spec: bspec(""), Zone: bzone, Provider: modeProvider(z, mode)}
			in.Spec.CAA = false
			if _, _, err := dnsplan.Apply(context.Background(), in, []string{dnsplan.SetAddress}); err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{bname, "*." + bname} {
				if got := sortedRRs(z, n, "A"); strings.Join(got, "|") != "203.0.113.10" {
					t.Fatalf("%s A %v", n, got)
				}
			}
		})
	}
}

func TestDeleteModeNoMailKeepsUserTXT(t *testing.T) {
	for _, mode := range deleteModes() {
		t.Run(mode, func(t *testing.T) {
			z := fakedns.NewZone()
			z.Set(bname, libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "google-site-verification=abc"}.RR(),
				libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "v=spf1 include:mail.test -all"}.RR())
			in := dnsplan.Input{Spec: bspec(""), Zone: bzone, Provider: modeProvider(z, mode)}
			in.Spec.CAA, in.Spec.NoMail = false, true
			if _, _, err := dnsplan.Apply(context.Background(), in, []string{dnsplan.SetNoMail}); err != nil {
				t.Fatal(err)
			}
			if got := sortedRRs(z, bname, "TXT"); strings.Join(got, "|") != "google-site-verification=abc|v=spf1 -all" {
				t.Fatalf("TXT %v", got)
			}
		})
	}
}

func TestDeleteModeDeleteLeavesUserRecords(t *testing.T) {
	for _, mode := range deleteModes() {
		t.Run(mode, func(t *testing.T) {
			z := fakedns.NewZone()
			v := dnsplan.CAAValue("letsencrypt.org", "https://acme-v02.api.letsencrypt.org/acme/acct/123")
			ours := []libdns.Record{
				libdns.CAA{Name: "portcullis", TTL: dnsplan.TTLCAA, Tag: "issue", Value: v},
				libdns.CAA{Name: "portcullis", TTL: dnsplan.TTLCAA, Tag: "issuewild", Value: v},
				libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "v=spf1 -all"},
			}
			// The user's records first: hetzner v1 deletes the first match.
			rrs := []libdns.RR{libdns.CAA{Name: "portcullis", TTL: time.Hour, Tag: "issue", Value: "digicert.com"}.RR(),
				libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "google-site-verification=abc"}.RR()}
			var refs []RecordRef
			for _, r := range ours {
				rrs = append(rrs, r.RR())
				rr := r.RR()
				refs = append(refs, RecordRef{Name: rr.Name, Type: rr.Type, Value: rr.Data})
			}
			z.Set(bname, rrs...)
			if err := deleteRecords(context.Background(), modeProvider(z, mode), bzone, refs); err != nil {
				t.Fatal(err)
			}
			if got := sortedRRs(z, bname, "CAA"); strings.Join(got, "|") != `0 issue "digicert.com"` {
				t.Fatalf("CAA after DELETE %v", got)
			}
			if got := sortedRRs(z, bname, "TXT"); strings.Join(got, "|") != "google-site-verification=abc" {
				t.Fatalf("TXT after DELETE %v", got)
			}
		})
	}
}

// fakeIDs is the fake zone's record-ID API (what porkbunAPI / hetznerAPI
// are for the real providers).
type fakeIDs struct{ p *fakedns.Provider }

func (f fakeIDs) listIDs(ctx context.Context, zone string) ([]idRecord, error) {
	recs, err := f.p.ListIDs(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]idRecord, 0, len(recs))
	for _, r := range recs {
		out = append(out, idRecord{id: r.ID, rr: r.RR})
	}
	return out, nil
}

func (f fakeIDs) deleteID(ctx context.Context, zone, id string) error {
	return f.p.DeleteID(ctx, zone, id)
}

// TestByIDWiring: buildProvider wraps porkbun and hetzner (and only they
// need it) so their deletes go by record ID.
func TestByIDWiring(t *testing.T) {
	for name, c := range map[string]map[string]string{
		"porkbun": {"api_key": "pk1_aaaaaaaa", "secret_api_key": "sk1_bbbbbbbb"},
		"hetzner": {"api_token": "tok-cccccccc"},
	} {
		p, err := buildProvider(&Domain{Name: "x.example.net", Provider: name, Credentials: c})
		if err != nil {
			t.Fatal(err)
		}
		inner, _ := unwrap(p)
		b, ok := inner.(byIDDelete)
		if !ok {
			t.Fatalf("%s: provider %T, want byIDDelete", name, inner)
		}
		switch api := b.api.(type) {
		case porkbunAPI:
			if name != "porkbun" || api.base != porkbunBase || api.key != c["api_key"] || api.secret != c["secret_api_key"] || api.hc.Timeout != providerTimeout {
				t.Fatalf("%s: api %+v", name, api)
			}
		case hetznerAPI:
			if name != "hetzner" || api.base != hetznerBase || api.token != c["api_token"] || api.hc.Timeout != providerTimeout {
				t.Fatalf("%s: api %+v", name, api)
			}
		default:
			t.Fatalf("%s: api %T", name, b.api)
		}
	}
}

func TestByIDRefusesWholeRRset(t *testing.T) {
	z := fakedns.NewZone()
	z.Set(bname, libdns.TXT{Name: "portcullis", Text: "keep"}.RR())
	p := modeProvider(z, "porkbun")
	for _, r := range []libdns.Record{libdns.RR{Name: "portcullis", Type: "TXT"}, libdns.RR{Name: "portcullis", Data: "keep"}} {
		if _, err := p.DeleteRecords(context.Background(), bzone, []libdns.Record{r}); err == nil {
			t.Fatalf("%+v accepted", r)
		}
	}
	if got := sortedRRs(z, bname, "TXT"); len(got) != 1 {
		t.Fatalf("TXT %v", got)
	}
}

// TestPorkbunAPIDeletesByID: retrieve's IDs, /dns/delete/<domain>/<id>
// for exactly the matching record (CAA quoted or not, MX with prio),
// never deleteByNameType; the credentials only in the body.
func TestPorkbunAPIDeletesByID(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if r.Method != http.MethodPost || body["apikey"] != "pk1_aaaaaaaa" || body["secretapikey"] != "sk1_bbbbbbbb" || strings.Contains(r.URL.String(), "aaaaaaaa") {
			w.WriteHeader(400)
			return
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/dns/retrieve/example.net":
			io.WriteString(w, `{"status":"SUCCESS","records":[
				{"id":"11","name":"portcullis.example.net","type":"CAA","content":"0 issue \"digicert.com\"","ttl":"600","prio":"0"},
				{"id":"12","name":"portcullis.example.net","type":"CAA","content":"0 issue letsencrypt.org","ttl":"600","prio":"0"},
				{"id":13,"name":"portcullis.example.net","type":"MX","content":"mx.mail.test","ttl":"600","prio":"10"},
				{"id":"14","name":"portcullis.example.net","type":"MX","content":"mx2.mail.test","ttl":"600","prio":"20"},
				{"id":"15","name":"example.net","type":"CAA","content":"0 issue \"letsencrypt.org\"","ttl":"600","prio":"0"}]}`)
		case "/dns/delete/example.net/12", "/dns/delete/example.net/13":
			io.WriteString(w, `{"status":"SUCCESS"}`)
		default:
			io.WriteString(w, `{"status":"ERROR","message":"unexpected"}`)
		}
	}))
	defer srv.Close()
	api := newPorkbunAPI("pk1_aaaaaaaa", "sk1_bbbbbbbb")
	api.base = srv.URL
	p := newByIDDelete(nil, api)
	del, err := p.DeleteRecords(context.Background(), bzone, []libdns.Record{
		libdns.CAA{Name: "portcullis", Tag: "issue", Value: "letsencrypt.org"},
		libdns.MX{Name: "portcullis", Preference: 10, Target: "mx.mail.test."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, " ") != "/dns/retrieve/example.net /dns/delete/example.net/12 /dns/delete/example.net/13" || len(del) != 2 {
		t.Fatalf("calls %v, deleted %v", paths, del)
	}
}

// TestHetznerAPIDeletesByID: the zone's ID, its records, DELETE of
// exactly the matching record's ID (not the first same name/type).
func TestHetznerAPIDeletesByID(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-API-Token") != "tok-cccccccc" {
			w.WriteHeader(401)
			return
		}
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch {
		case r.Method == "GET" && r.URL.Path == "/zones" && r.URL.Query().Get("name") == "example.net":
			io.WriteString(w, `{"zones":[{"id":"z1","name":"example.net"}]}`)
		case r.Method == "GET" && r.URL.Path == "/records" && r.URL.Query().Get("zone_id") == "z1":
			io.WriteString(w, `{"records":[
				{"id":"a","type":"TXT","name":"portcullis","value":"google-site-verification=abc","ttl":3600},
				{"id":"b","type":"TXT","name":"portcullis","value":"\"v=spf1 -all\"","ttl":3600},
				{"id":"c","type":"TXT","name":"other","value":"v=spf1 -all","ttl":3600}]}`)
		case r.Method == "DELETE" && r.URL.Path == "/records/b":
			io.WriteString(w, `{}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	api := newHetznerAPI("tok-cccccccc")
	api.base = srv.URL
	p := newByIDDelete(nil, api)
	if _, err := p.DeleteRecords(context.Background(), bzone, []libdns.Record{libdns.TXT{Name: "portcullis", Text: "v=spf1 -all"}}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls, " | ") != "GET /zones?name=example.net | GET /records?zone_id=z1 | DELETE /records/b" {
		t.Fatalf("calls %v", calls)
	}
	// An ambiguous or missing zone fails closed (the library would index
	// past an empty list).
	api.base = srv.URL + "/nope"
	if _, err := newByIDDelete(nil, api).DeleteRecords(context.Background(), bzone, []libdns.Record{libdns.TXT{Name: "portcullis", Text: "x"}}); err == nil {
		t.Fatal("no error without the zone")
	}
}
