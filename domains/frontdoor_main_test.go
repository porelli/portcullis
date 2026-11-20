package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/frontdoor"
)

// leakProvider is a provider that echoes its credentials into every
// error (raw, base64 and URL-encoded), as a careless API or library
// might.
type leakProvider struct {
	mu        sync.Mutex
	creds     map[string]string
	recs      []libdns.RR
	failReads int
}

func (p *leakProvider) leak(op string) error {
	var parts []string
	for _, v := range p.creds {
		parts = append(parts, v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
			url.QueryEscape(v), fmt.Sprintf("%q", v))
	}
	return fmt.Errorf("%s: HTTP 500, request {\"apikey\": %s}", op, strings.Join(parts, " "))
}

func (p *leakProvider) FindZone(string) (string, error) { return "example.org.", nil }

func (p *leakProvider) GetRecords(context.Context, string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failReads > 0 {
		p.failReads--
		return nil, p.leak("retrieve")
	}
	var out []libdns.Record
	for _, r := range p.recs {
		out = append(out, r)
	}
	return out, nil
}

func (p *leakProvider) AppendRecords(_ context.Context, _ string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range recs {
		p.recs = append(p.recs, r.RR())
	}
	return recs, nil
}

func (p *leakProvider) SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, p.leak("set")
}

func (p *leakProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, p.leak("delete")
}

// vectorSource feeds one vector's rounds.
type vectorSource struct {
	v fdVector
	i int
}

func (s *vectorSource) Cluster(context.Context) (frontdoor.Cluster, error) {
	c := frontdoor.Cluster{Nodes: map[string]frontdoor.Node{}, Ready: s.v.Rounds[s.i].Ready}
	for id, n := range s.v.Nodes {
		c.Nodes[id] = frontdoor.Node{Site: n.Site, Ingress: n.Ingress, Public: n.Public}
	}
	return c, nil
}

func (s *vectorSource) Probes(context.Context, frontdoor.Cluster, time.Time) ([]frontdoor.ProbeRound, []error) {
	var out []frontdoor.ProbeRound
	for _, p := range s.v.Rounds[s.i].Probes {
		r := frontdoor.ProbeRound{T: p.T, Prober: p.Prober, Site: p.Site, ReachedAny: p.ReachedAny, EgressOK: p.EgressOK, Results: map[string]frontdoor.ProbeResult{}}
		for k, x := range p.Results {
			r.Results[k] = frontdoor.ProbeResult{OK: x.OK, Class: x.Class}
		}
		out = append(out, r)
	}
	return out, []error{errors.New("node e9: unreachable")}
}

type recordSink struct{ docs []string }

func (s *recordSink) Write(_ context.Context, b []byte) error {
	s.docs = append(s.docs, string(b))
	return nil
}

// TestFrontDoorCredentialsNeverLogged (X2): over a full vector run with
// every delete failing and a failed read (both errors echoing the
// credentials), and the credential file's own refusals, no credential
// value — raw, base64 or URL-encoded — appears in any log line, returned
// error or status write.
func TestFrontDoorCredentialsNeverLogged(t *testing.T) {
	secrets := map[string]string{"api_token": "fd-TOKEN-0a1b2c3d4e5f6a7b", "api_secret": "fd-SECRET/+=9z8y7x6w5v"}
	var lp *leakProvider
	providers["fdleak"] = providerSpec{required: []string{"api_token", "api_secret"}, build: func(c map[string]string) (dnsProvider, error) {
		return lp, nil
	}}
	t.Cleanup(func() { delete(providers, "fdleak") })

	b, err := os.ReadFile("testdata/frontdoor_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []fdVector
	if err := strictVectors(b, &vs); err != nil {
		t.Fatal(err)
	}
	var v fdVector
	for _, x := range vs {
		if strings.HasPrefix(x.Name, "a whole site down: its addresses go") {
			v = x
		}
	}
	if len(v.Want.Changes) == 0 {
		t.Fatal("vector not found")
	}
	lp = &leakProvider{creds: secrets, failReads: 1}
	for name, as := range v.Initial {
		for _, a := range as {
			lp.recs = append(lp.recs, libdns.RR{Name: libdns.RelativeName(name+".", "example.org."), Type: "A", Data: a, TTL: time.Minute})
		}
	}

	var logs bytes.Buffer
	var errs []string
	leading := true
	w, clean, err := newFrontdoorWriter("example.org", frontdoorCreds{Provider: "fdleak", Credentials: secrets}, func() bool { return leading }, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordSink{}
	src := &vectorSource{v: v}
	r := &frontdoor.Runner{Engine: frontdoor.NewEngine(w.Names()), Writer: w, Source: src, Leading: func() bool { return leading },
		Status: sink, Metrics: frontdoor.NewMetrics(), Log: log.New(&logs, "", 0), Redact: clean}
	for i, round := range v.Rounds {
		src.i = i
		r.Step(context.Background(), round.T)
	}
	// A direct Apply's error too (the provider's delete refusal).
	if err := w.Apply(context.Background(), frontdoor.Change{Name: "example.org", Op: "remove", Value: "198.51.100.1", Type: "A"}); err != nil {
		errs = append(errs, err.Error())
	} else {
		t.Error("the delete didn't fail")
	}
	// The credential file's refusals name keys, never values.
	dir := t.TempDir()
	for i, body := range []string{
		`{"provider": "fdleak", "credentials": {"api_token": "` + secrets["api_token"] + `", "api_secret": "` + secrets["api_secret"] + `", "extra": "` + secrets["api_token"] + `"}}`,
		`{"provider": "fdleak", "credentials": {"api_token": "` + secrets["api_token"] + `"}}`,
		`{"provider": "nope-` + secrets["api_token"][:4] + `", "credentials": {}}`,
		`{"provider": "fdleak", "credentials": {"api_token": "` + secrets["api_token"] + `", "api_secret": "` + secrets["api_secret"] + `"}, "more": 1}`,
		`not json ` + secrets["api_token"],
	} {
		p := filepath.Join(dir, fmt.Sprintf("c%d.json", i))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadFrontdoorCreds(p); err == nil {
			t.Errorf("credentials %d accepted", i)
		} else {
			errs = append(errs, err.Error())
		}
	}

	if !strings.Contains(logs.String(), "[redacted]") || !strings.Contains(logs.String(), "remove") {
		t.Fatalf("the run logged no redacted provider failure:\n%s", logs.String())
	}
	all := logs.String() + "\n" + strings.Join(sink.docs, "\n") + "\n" + strings.Join(errs, "\n")
	for k, v := range secrets {
		for form, s := range map[string]string{
			"raw": v, "base64": base64.StdEncoding.EncodeToString([]byte(v)), "base64url": base64.RawURLEncoding.EncodeToString([]byte(v)),
			"url-encoded": url.QueryEscape(v), "path-encoded": url.PathEscape(v),
		} {
			if strings.Contains(all, s) {
				t.Errorf("%s (%s) appears in the logs, errors or status", k, form)
			}
		}
	}
	if len(sink.docs) != len(v.Rounds) {
		t.Errorf("%d status writes over %d rounds", len(sink.docs), len(v.Rounds))
	}
}
