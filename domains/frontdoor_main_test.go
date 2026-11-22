package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
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
	failZone  bool
}

// leakText echoes every credential in every form a careless API might:
// raw, quoted, query- and path-encoded, base64 (std, url), and inside
// basic-auth headers (key:value, value:value).
func leakText(creds map[string]string, op string) string {
	var parts []string
	for k, v := range creds {
		parts = append(parts, v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
			url.QueryEscape(v), url.PathEscape(v), fmt.Sprintf("%q", v),
			"Basic "+base64.StdEncoding.EncodeToString([]byte(k+":"+v)))
		for _, w := range creds {
			parts = append(parts, "Basic "+base64.StdEncoding.EncodeToString([]byte(v+":"+w)))
		}
	}
	return fmt.Sprintf("%s: HTTP 500, request {\"apikey\": %s}", op, strings.Join(parts, " "))
}

func (p *leakProvider) leak(op string) error { return errors.New(leakText(p.creds, op)) }

func (p *leakProvider) FindZone(string) (string, error) {
	if p.failZone {
		return "", p.leak("zone")
	}
	return "example.org.", nil
}

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

func (p *leakProvider) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, p.leak("create")
}

func (p *leakProvider) SetRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, p.leak("set")
}

func (p *leakProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, p.leak("delete")
}

// vectorSource feeds one vector's rounds; every third snapshot fails and
// every probe error echoes the credentials.
type vectorSource struct {
	v     fdVector
	i     int
	creds map[string]string
}

func (s *vectorSource) Cluster(context.Context) (frontdoor.Cluster, error) {
	if s.i%3 == 2 {
		return frontdoor.Cluster{}, errors.New(leakText(s.creds, "nodeadm"))
	}
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
	return out, []error{errors.New(leakText(s.creds, "node e9"))}
}

// recordSink keeps every status write; every other one fails, echoing
// the credentials.
type recordSink struct {
	docs  []string
	creds map[string]string
}

func (s *recordSink) Write(_ context.Context, b []byte) error {
	s.docs = append(s.docs, string(b))
	if len(s.docs)%2 == 0 {
		return errors.New(leakText(s.creds, "configmap"))
	}
	return nil
}

type alwaysFence struct{}

func (alwaysFence) Leading() bool { return true }

func (alwaysFence) WriteContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	c, cancel := context.WithTimeout(ctx, frontdoor.WriteMargin)
	return c, cancel, nil
}

// TestFrontDoorCredentialsNeverLogged (X2): over full vector runs (a
// removal case and an addition case) where every append and delete
// fails, a read, every third snapshot, every probe and every other status
// write fail — every error echoing the credentials in every form
// (leakText) —, plus the zone lookup's failure through runFrontdoor's own
// logger and the credential file's refusals, no credential value (raw,
// base64, base64url, query- or path-encoded, or inside a basic-auth
// header) appears in any log line, returned error or status write.
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
	var logs bytes.Buffer
	var errs, statuses []string
	pol := frontdoor.AddrPolicy{AllowDocumentation: true}
	ran := 0
	for _, v := range vs {
		if !strings.HasPrefix(v.Name, "a whole site down: its addresses go") && !strings.HasPrefix(v.Name, "a whole site down holding the last address") {
			continue
		}
		ran++
		lp = &leakProvider{creds: secrets, failReads: 1}
		for name, as := range v.Initial {
			for _, a := range as {
				lp.recs = append(lp.recs, libdns.RR{Name: libdns.RelativeName(name+".", "example.org."), Type: "A", Data: a, TTL: time.Minute})
			}
		}
		w, clean, err := newFrontdoorWriter("example.org", frontdoorCreds{Provider: "fdleak", Credentials: secrets}, pol, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.Fence = alwaysFence{}
		sink := &recordSink{creds: secrets}
		src := &vectorSource{v: v, creds: secrets}
		r := &frontdoor.Runner{Engine: frontdoor.NewEngine(w.Names()), Writer: w, Source: src,
			Status: sink, Metrics: frontdoor.NewMetrics(), Log: log.New(&logs, "", 0), Redact: clean}
		for i, round := range v.Rounds {
			src.i = i
			r.Step(context.Background(), round.T)
		}
		statuses = append(statuses, sink.docs...)
		for _, c := range []frontdoor.Change{
			{Name: "example.org", Op: "remove", Value: "198.51.100.1", Type: "A"},
			{Name: "example.org", Op: "add", Value: "198.51.100.77", Type: "A"},
		} {
			lp.recs = append(lp.recs, libdns.RR{Name: "@", Type: "A", Data: "198.51.100.1"}, libdns.RR{Name: "@", Type: "A", Data: "198.51.100.2"})
			if err := w.Apply(context.Background(), c); err != nil {
				errs = append(errs, err.Error())
			} else {
				t.Errorf("%s didn't fail", c.Op)
			}
		}
	}
	if ran != 2 {
		t.Fatalf("%d vectors run", ran)
	}
	for _, want := range []string{"create:", "delete:", "retrieve:", "nodeadm:", "node e9:", "configmap:"} {
		if !strings.Contains(logs.String()+strings.Join(errs, "\n"), want) {
			t.Errorf("no %q failure was logged or returned: the path isn't covered", want)
		}
	}
	// The zone lookup's failure, through newFrontdoorWriter and through
	// runFrontdoor's own stderr logger (which refuses to start there).
	lp = &leakProvider{creds: secrets, failZone: true}
	if _, _, err := newFrontdoorWriter("example.org", frontdoorCreds{Provider: "fdleak", Credentials: secrets}, pol, nil); err == nil {
		t.Error("the zone failure didn't fail")
	} else {
		errs = append(errs, err.Error())
	}
	dir := t.TempDir()
	cf := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(cf, []byte(`{"provider": "fdleak", "credentials": {"api_token": "`+secrets["api_token"]+`", "api_secret": "`+strings.ReplaceAll(secrets["api_secret"], "/", "\\/")+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"PORTCULLIS_DOMAIN": "example.org", "POD_NAME": "frontdoor-0", "POD_NAMESPACE": "portcullis",
		"FRONTDOOR_EXCLUDED_CIDRS": "10.215.0.0/24 10.42.0.0/16 10.43.0.0/16", "FRONTDOOR_CREDENTIALS_FILE": cf,
		"DOMAINS_FAKEDNS_ADDR": "127.0.0.1:0"} {
		t.Setenv(k, v)
	}
	// runFrontdoor sets the process's HTTP defaults: put them back.
	tr, to := http.DefaultTransport, http.DefaultClient.Timeout
	t.Cleanup(func() { http.DefaultTransport, http.DefaultClient.Timeout = tr, to })
	var stderr bytes.Buffer
	if code := runFrontdoor(nil, io.Discard, &stderr); code == 0 {
		t.Error("runFrontdoor started with a failing zone lookup")
	}
	if !strings.Contains(stderr.String(), "finding the DNS zone") {
		t.Errorf("runFrontdoor's log: %s", stderr.String())
	}
	errs = append(errs, stderr.String())
	// The credential file's refusals name keys, never values.
	for i, body := range []string{
		`{"provider": "fdleak", "credentials": {"api_token": "` + secrets["api_token"] + `", "api_secret": "x` + secrets["api_token"] + `", "extra": "` + secrets["api_token"] + `"}}`,
		`{"provider": "fdleak", "credentials": {"api_token": "` + secrets["api_token"] + `"}}`,
		`{"provider": "nope-` + secrets["api_token"][:4] + `", "credentials": {}}`,
		`{"provider": "fdleak", "credentials": {"api_token": "` + secrets["api_token"] + `", "api_secret": "x` + secrets["api_token"] + `"}, "more": 1}`,
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

	if !strings.Contains(logs.String(), "[redacted]") {
		t.Fatalf("the run logged no redacted provider failure:\n%s", logs.String())
	}
	all := logs.String() + "\n" + strings.Join(statuses, "\n") + "\n" + strings.Join(errs, "\n")
	for k, v := range secrets {
		forms := map[string]string{
			"raw": v, "base64": base64.StdEncoding.EncodeToString([]byte(v)), "base64url": base64.RawURLEncoding.EncodeToString([]byte(v)),
			"url-encoded": url.QueryEscape(v), "path-encoded": url.PathEscape(v),
			"basic auth key:value": base64.StdEncoding.EncodeToString([]byte(k + ":" + v)),
		}
		for _, w := range secrets {
			forms["basic auth "+v[:6]+":"+w[:6]] = base64.StdEncoding.EncodeToString([]byte(v + ":" + w))
		}
		for form, s := range forms {
			if strings.Contains(all, s) {
				t.Errorf("%s (%s) appears in the logs, errors or status", k, form)
			}
		}
	}
}
