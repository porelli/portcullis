package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/fakedns"
)

// fakePorkbun is Porkbun's DNS API v3 over a fake zone, with the rules
// Porkbun applied live (test server, 2026-11-16, scratch names under
// _pc-test.portcullis.imbu.ca): MX and SRV need "prio", and a content that
// still starts with the priority is refused with Porkbun's own answer;
// SRV content is "weight port target"; names are relative to the domain
// ("" at the apex); every call carries both keys. Every create body is
// logged for the request-shape tests.
type fakePorkbun struct {
	mu      sync.Mutex
	creates []map[string]string
	nextID  int
}

const fakePBKey, fakePBSecret = "pk1_test-aaaaaaaa", "sk1_test-bbbbbbbb"

func newFakePorkbun(t testing.TB, raw *fakedns.Provider) (porkbunAPI, *fakePorkbun) {
	t.Helper()
	f := &fakePorkbun{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.serve(w, r, raw) }))
	t.Cleanup(srv.Close)
	return porkbunAPI{base: srv.URL, key: fakePBKey, secret: fakePBSecret, hc: srv.Client()}, f
}

func pbAnswer(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

func pbError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	pbAnswer(w, map[string]string{"status": "ERROR", "message": msg})
}

func (f *fakePorkbun) serve(w http.ResponseWriter, r *http.Request, raw *fakedns.Provider) {
	ctx := context.Background()
	b, _ := io.ReadAll(r.Body)
	var body map[string]any
	if json.Unmarshal(b, &body) != nil || body["apikey"] != fakePBKey || body["secretapikey"] != fakePBSecret {
		pbError(w, "Invalid API key.")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/") // dns, op, domain[, id]
	for i, seg := range parts {
		parts[i], _ = url.PathUnescape(seg)
	}
	if len(parts) < 3 || parts[0] != "dns" {
		pbError(w, "unknown endpoint")
		return
	}
	zone := parts[2] + "."
	str := func(k string) string {
		switch v := body[k].(type) {
		case string:
			return v
		case float64:
			return strconv.Itoa(int(v))
		}
		return ""
	}
	switch parts[1] {
	case "create":
		rec := map[string]string{}
		for k := range body {
			if k != "apikey" && k != "secretapikey" {
				rec[k] = str(k)
			}
		}
		f.mu.Lock()
		f.creates = append(f.creates, rec)
		f.mu.Unlock()
		typ, content, prio := str("type"), str("content"), str("prio")
		data := content
		switch typ {
		case "MX", "SRV":
			first := strings.Fields(content)
			_, numFirst := strconv.Atoi(first[0])
			if prio == "" || (typ == "MX" && numFirst == nil && len(first) > 1) || (typ == "SRV" && len(first) != 3) {
				pbError(w, "Create error: We were unable to create the DNS record.")
				return
			}
			data = prio + " " + content
		}
		ttl, _ := strconv.Atoi(str("ttl"))
		name := str("name")
		if name == "" {
			name = "@"
		}
		if _, err := raw.AppendRecords(ctx, zone, []libdns.Record{libdns.RR{Name: name, Type: typ, TTL: time.Duration(ttl) * time.Second, Data: data}}); err != nil {
			pbError(w, err.Error())
			return
		}
		f.mu.Lock()
		f.nextID++
		id := f.nextID
		f.mu.Unlock()
		pbAnswer(w, map[string]any{"status": "SUCCESS", "id": id})
	case "retrieve":
		recs, err := raw.ListIDs(ctx, zone)
		if err != nil {
			pbError(w, err.Error())
			return
		}
		var out []map[string]string
		for _, rr := range recs {
			n := strings.TrimSuffix(libdns.AbsoluteName(rr.RR.Name, zone), ".")
			content, prio := rr.RR.Data, "0"
			if rr.RR.Type == "MX" || rr.RR.Type == "SRV" {
				p, rest, _ := strings.Cut(rr.RR.Data, " ")
				prio, content = p, rest
			}
			out = append(out, map[string]string{"id": rr.ID, "name": n, "type": rr.RR.Type, "content": content,
				"ttl": strconv.Itoa(int(rr.RR.TTL / time.Second)), "prio": prio})
		}
		pbAnswer(w, map[string]any{"status": "SUCCESS", "records": out})
	case "delete":
		if len(parts) != 4 {
			pbError(w, "no id")
			return
		}
		if err := raw.DeleteID(ctx, zone, parts[3]); err != nil {
			pbError(w, err.Error())
			return
		}
		pbAnswer(w, map[string]string{"status": "SUCCESS"})
	default:
		pbError(w, "unknown endpoint")
	}
}

// TestPorkbunRequestShapes pins the create body for every type the sets
// write (found on the test server: libdns/porkbun sent MX / SRV with the
// priority inside content and no prio, and Porkbun refused them).
func TestPorkbunRequestShapes(t *testing.T) {
	z := fakedns.NewZone()
	raw := &fakedns.Provider{Zone: z, ZoneName: "imbu.ca"}
	api, f := newFakePorkbun(t, raw)
	p := newPorkbunProvider(api)
	const zone = "imbu.ca."
	dkim := "v=DKIM1; k=rsa; p=" + strings.Repeat("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", 13)
	recs := []libdns.Record{
		libdns.RR{Name: "portcullis", Type: "MX", TTL: time.Hour, Data: "10 mail.portcullis.imbu.ca."},
		libdns.RR{Name: "nomail", Type: "MX", TTL: time.Hour, Data: "0 ."},
		libdns.RR{Name: "_submissions._tcp.portcullis", Type: "SRV", TTL: time.Hour, Data: "0 1 465 mail.portcullis.imbu.ca."},
		libdns.RR{Name: "_imap._tcp.portcullis", Type: "SRV", TTL: time.Hour, Data: "0 0 0 ."},
		libdns.RR{Name: "_25._tcp.mail.portcullis", Type: "TLSA", TTL: time.Hour, Data: "3 1 1 " + strings.Repeat("ab", 32)},
		libdns.TXT{Name: "v1-rsa._domainkey.portcullis", TTL: time.Hour, Text: dkim},
		libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "v=spf1 mx -all"},
		libdns.CAA{Name: "portcullis", TTL: time.Hour, Tag: "issue", Value: "letsencrypt.org; accounturi=https://x/acct/1"},
		libdns.Address{Name: "@", TTL: 5 * time.Minute, IP: mustAddr("203.0.113.10")},
	}
	if _, err := p.AppendRecords(context.Background(), zone, recs); err != nil {
		t.Fatal(err)
	}
	want := []map[string]string{
		{"name": "portcullis", "type": "MX", "content": "mail.portcullis.imbu.ca.", "prio": "10", "ttl": "3600"},
		{"name": "nomail", "type": "MX", "content": ".", "prio": "0", "ttl": "3600"},
		{"name": "_submissions._tcp.portcullis", "type": "SRV", "content": "1 465 mail.portcullis.imbu.ca.", "prio": "0", "ttl": "3600"},
		{"name": "_imap._tcp.portcullis", "type": "SRV", "content": "0 0 .", "prio": "0", "ttl": "3600"},
		{"name": "_25._tcp.mail.portcullis", "type": "TLSA", "content": "3 1 1 " + strings.Repeat("ab", 32), "ttl": "3600"},
		{"name": "v1-rsa._domainkey.portcullis", "type": "TXT", "content": dkim, "ttl": "3600"},
		{"name": "portcullis", "type": "TXT", "content": "v=spf1 mx -all", "ttl": "3600"},
		{"name": "portcullis", "type": "CAA", "content": `0 issue "letsencrypt.org; accounturi=https://x/acct/1"`, "ttl": "3600"},
		{"name": "", "type": "A", "content": "203.0.113.10", "ttl": "600"}, // raised to Porkbun's minimum
	}
	if len(f.creates) != len(want) {
		t.Fatalf("%d creates: %v", len(f.creates), f.creates)
	}
	for i, w := range want {
		if fmt.Sprint(f.creates[i]) != fmt.Sprint(w) {
			t.Errorf("create %d:\n got %v\nwant %v", i, f.creates[i], w)
		}
	}
	// Read back: every type, MX / SRV with their priority again, CAA
	// unquoted, names relative to the zone.
	got, err := p.GetRecords(context.Background(), zone)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range got {
		rr := r.RR()
		seen[rr.Type+" "+rr.Name+" "+rr.Data] = true
		if c, ok := r.(libdns.CAA); ok && strings.HasPrefix(c.Value, `"`) {
			t.Fatalf("CAA read quoted: %q", c.Value)
		}
	}
	for _, k := range []string{
		"MX portcullis 10 mail.portcullis.imbu.ca.", "MX nomail 0 .",
		"SRV _submissions._tcp.portcullis 0 1 465 mail.portcullis.imbu.ca.", "SRV _imap._tcp.portcullis 0 0 0 .",
		"TLSA _25._tcp.mail.portcullis 3 1 1 " + strings.Repeat("ab", 32),
	} {
		if !seen[k] {
			t.Errorf("not read back: %s (read %v)", k, seen)
		}
	}
	// A record without its priority first is refused before any call.
	if _, err := p.AppendRecords(context.Background(), zone, []libdns.Record{libdns.RR{Name: "x", Type: "MX", Data: "mail.example."}}); err == nil {
		t.Fatal("an MX without a priority was sent")
	}
	// The library's shape is what Porkbun refuses (the deploy's error).
	n := len(f.creates)
	if err := api.create(context.Background(), zone, porkbunCreate{Name: "x", Type: "MX", Content: "10 mail.example.", TTL: "600"}); err == nil ||
		!strings.Contains(err.Error(), "unable to create") || len(f.creates) != n+1 {
		t.Fatalf("the fake accepted libdns/porkbun's MX shape: %v", err)
	}
}

// TestPorkbunDeleteByIDAndSet: deletes go by ID and match the data;
// SetRecords leaves the other records of the name alone.
func TestPorkbunDeleteByIDAndSet(t *testing.T) {
	z := fakedns.NewZone()
	raw := &fakedns.Provider{Zone: z, ZoneName: "imbu.ca"}
	api, _ := newFakePorkbun(t, raw)
	p := newPorkbunProvider(api)
	ctx, zone := context.Background(), "imbu.ca."
	if _, err := p.AppendRecords(ctx, zone, []libdns.Record{
		libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "keep"},
		libdns.TXT{Name: "portcullis", TTL: time.Hour, Text: "go"},
		libdns.RR{Name: "portcullis", Type: "MX", TTL: time.Hour, Data: "10 a.example."},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteRecords(ctx, zone, []libdns.Record{libdns.TXT{Name: "portcullis", Text: "go"}}); err != nil {
		t.Fatal(err)
	}
	if got := sortedRRs(z, "portcullis.imbu.ca", "TXT"); fmt.Sprint(got) != "[keep]" {
		t.Fatalf("TXT after the delete %v", got)
	}
	if _, err := p.SetRecords(ctx, zone, []libdns.Record{libdns.RR{Name: "portcullis", Type: "MX", TTL: time.Hour, Data: "20 b.example."}}); err != nil {
		t.Fatal(err)
	}
	if got := sortedRRs(z, "portcullis.imbu.ca", "MX"); fmt.Sprint(got) != "[20 b.example.]" {
		t.Fatalf("MX after the set %v", got)
	}
	if got := sortedRRs(z, "portcullis.imbu.ca", "TXT"); fmt.Sprint(got) != "[keep]" {
		t.Fatalf("SetRecords touched the TXT: %v", got)
	}
}

// fakePorkbunAPI is newFakePorkbun's client alone.
func fakePorkbunAPI(t testing.TB, raw *fakedns.Provider) porkbunAPI {
	api, _ := newFakePorkbun(t, raw)
	return api
}
