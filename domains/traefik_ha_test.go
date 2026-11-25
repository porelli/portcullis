package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestServableHAIncludesMain: in HA the main domain's certificate from
// the front door's store is served, exactly {<main>, *.<main>}; anything
// else under that name is dropped.
func TestServableHAIncludesMain(t *testing.T) {
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(60*24*time.Hour)
	good, gk := mkCert(t, []string{testMain, "*." + testMain}, nil, nb, na)
	if err := servableHA(good, gk, testMain, "", now); err != nil {
		t.Fatalf("main certificate refused: %v", err)
	}
	added, ak := mkCert(t, []string{"good.example.org", "*.good.example.org"}, nil, nb, na)
	domains := map[string]*Domain{"good.example.org": {Name: "good.example.org", CertPEM: added, KeyPEM: ak, CertNotAfter: &na}}
	doc, dropped := buildDynamic(domains, &mainCert{CertPEM: good, KeyPEM: gk}, testMain, "", now)
	if len(doc.TLS.Certificates) != 2 || len(dropped) != 0 {
		t.Fatalf("served %d (want main + the added domain), dropped %v", len(doc.TLS.Certificates), dropped)
	}
	if doc.TLS.Certificates[0].CertFile != good {
		t.Error("the main certificate isn't served first")
	}
	// The document's routers are exactly the two reviewed ones, with an
	// added domain too (Task 33a review M8: core's k8s_hardening pins
	// their fields; this pins the set).
	var routers []string
	if doc.HTTP != nil {
		for k := range doc.HTTP.Routers {
			routers = append(routers, k)
		}
	}
	sort.Strings(routers)
	if strings.Join(routers, ",") != IngressHealthRouter+","+MainCertReadyRouter {
		t.Errorf("the document's routers %v, want only %s and %s", routers, MainCertReadyRouter, IngressHealthRouter)
	}
	_, otherKey := mkCert(t, []string{testMain, "*." + testMain}, nil, nb, na)
	for name, c := range map[string][2]string{
		"auth host added": pair(t, []string{testMain, "*." + testMain, "auth." + testMain}, nil, nb, na),
		"core host only":  pair(t, []string{"auth." + testMain, "*.auth." + testMain}, nil, nb, na),
		"apex only":       pair(t, []string{testMain}, nil, nb, na),
		"an IP SAN":       pair(t, []string{testMain, "*." + testMain}, []net.IP{net.ParseIP("203.0.113.1")}, nb, na),
		"expired":         pair(t, []string{testMain, "*." + testMain}, nil, now.Add(-48*time.Hour), now.Add(-time.Hour)),
		"another key":     {good, otherKey},
		"no key":          {good, ""},
	} {
		if err := servableHA(c[0], c[1], testMain, "", now); err == nil {
			t.Errorf("%s: served", name)
		}
		doc, dropped := buildDynamic(nil, &mainCert{CertPEM: c[0], KeyPEM: c[1]}, testMain, "", now)
		if len(doc.TLS.Certificates) != 0 || len(dropped) != 1 {
			t.Errorf("%s: served %d, dropped %v", name, len(doc.TLS.Certificates), dropped)
		}
	}
}

// TestServableHAExcludesMailHost: never the mail provider's name.
func TestServableHAExcludesMailHost(t *testing.T) {
	now := time.Now()
	c := pair(t, []string{testMain, "*." + testMain}, nil, now.Add(-time.Hour), now.Add(time.Hour))
	if err := servableHA(c[0], c[1], testMain, testMain+".", now); err == nil {
		t.Fatal("served with MAIL_HOSTNAME = the main domain")
	}
	if err := servableHA(c[0], c[1], testMain, "mail."+testMain, now); err != nil {
		t.Fatalf("a mail host under the main domain refused the main certificate: %v", err)
	}
	m := pair(t, []string{"mail." + testMain, "*.mail." + testMain}, nil, now.Add(-time.Hour), now.Add(time.Hour))
	if err := servableHA(m[0], m[1], testMain, "mail."+testMain, now); err == nil {
		t.Fatal("served the mail host's certificate as the main domain's")
	}
}

// TestServableNonHAUnchanged: without HA (no front-door certificate) the
// rule is "only added-domain names": the main domain is never served,
// even stored as an added domain.
func TestServableNonHAUnchanged(t *testing.T) {
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(60*24*time.Hour)
	c := pair(t, []string{testMain, "*." + testMain}, nil, nb, na)
	if err := servable(&Domain{Name: testMain, CertPEM: c[0], KeyPEM: c[1]}, testMain, "", now); err == nil {
		t.Fatal("servable admitted the main domain")
	}
	doc, dropped := buildDynamic(map[string]*Domain{testMain: {Name: testMain, CertPEM: c[0], KeyPEM: c[1], CertNotAfter: &na}}, nil, testMain, "", now)
	if len(doc.TLS.Certificates) != 0 || len(dropped) != 1 {
		t.Fatalf("served %d, dropped %v", len(doc.TLS.Certificates), dropped)
	}
	// A Service without HA never reads the front door's certificate.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "tls.crt"), c[0])
	writeFile(t, filepath.Join(dir, "tls.key"), c[1])
	e := newEnvWith(t, false, func(c *Config) { c.FrontdoorCertDir = dir })
	if e.svc.cfg.HA {
		t.Fatal("HA on")
	}
	_, served := e.dynamic()
	if len(served.TLS.Certificates) != 0 {
		t.Fatalf("served %d", len(served.TLS.Certificates))
	}
}

// TestHAServesFrontdoorCert: the domains service in HA serves the mounted
// frontdoor-cert, picks up a replaced one, and keeps the last good pair
// while a read is broken (the kubelet's swap between the two files, an
// emptied Secret), so Traefik never loses the main certificate.
func TestHAServesFrontdoorCert(t *testing.T) {
	e, _ := newHAEnv(t)
	dir := t.TempDir()
	e.svc.cfg.FrontdoorCertDir = dir
	now := time.Now()
	served := func() []string {
		_, doc := e.dynamic()
		var out []string
		for _, c := range doc.TLS.Certificates {
			out = append(out, c.CertFile)
		}
		return out
	}
	if got := served(); len(got) != 0 {
		t.Fatalf("served %d with no certificate mounted", len(got))
	}
	a := pair(t, []string{testMain, "*." + testMain}, nil, now.Add(-time.Hour), now.Add(48*time.Hour))
	writeFile(t, filepath.Join(dir, "tls.crt"), a[0])
	writeFile(t, filepath.Join(dir, "tls.key"), a[1])
	if got := served(); len(got) != 1 || got[0] != a[0] {
		t.Fatalf("served %d, want the mounted one", len(got))
	}
	b := pair(t, []string{testMain, "*." + testMain}, nil, now.Add(-time.Hour), now.Add(72*time.Hour))
	writeFile(t, filepath.Join(dir, "tls.crt"), b[0]) // the key still a's: a torn read
	if got := served(); len(got) != 1 || got[0] != a[0] {
		t.Fatal("a torn read didn't keep the last good pair")
	}
	writeFile(t, filepath.Join(dir, "tls.key"), b[1])
	if got := served(); len(got) != 1 || got[0] != b[0] {
		t.Fatal("the replaced certificate isn't served")
	}
	writeFile(t, filepath.Join(dir, "tls.crt"), "")
	if got := served(); len(got) != 1 || got[0] != b[0] {
		t.Fatal("an emptied Secret dropped the last good pair")
	}
}

func pair(t *testing.T, sans []string, ips []net.IP, nb, na time.Time) [2]string {
	t.Helper()
	c, k := mkCert(t, sans, ips, nb, na)
	return [2]string{c, k}
}

// TestMainCertReadyRoute (Task 31 fix round 1, M3): the HA Traefik's
// readiness route rides in the same document as the main certificate and
// only with it: none without a front-door certificate, none when it isn't
// servable, none without HA (no main certificate passed).
func TestMainCertReadyRoute(t *testing.T) {
	now := time.Now()
	nb, na := now.Add(-time.Hour), now.Add(60*24*time.Hour)
	good, gk := mkCert(t, []string{testMain, "*." + testMain}, nil, nb, na)
	doc, _ := buildDynamic(nil, &mainCert{CertPEM: good, KeyPEM: gk}, testMain, "", now)
	if doc.HTTP == nil || len(doc.HTTP.Routers) != 2 {
		t.Fatalf("no readiness route with the main certificate: %+v", doc.HTTP)
	}
	r := doc.HTTP.Routers[MainCertReadyRouter]
	if r.Rule != "Path(`/portcullis-main-cert`)" || r.Service != "ping@internal" || len(r.EntryPoints) != 1 || r.EntryPoints[0] != "traefik" {
		t.Errorf("route %+v", r)
	}
	h := doc.HTTP.Routers[IngressHealthRouter]
	if h.Rule != "Host(`auth."+testMain+"`) && Path(`/healthz`) && (Method(`GET`) || Method(`HEAD`))" || h.Service != "ping@internal" ||
		len(h.EntryPoints) != 1 || h.EntryPoints[0] != "websecure" || h.TLS == nil || h.Priority != 10002 ||
		strings.Join(h.Middlewares, ",") != "rate-limit-auth@file,security-headers@file" {
		t.Errorf("ingress health route %+v", h)
	}
	b, err := json.Marshal(doc)
	if err != nil || !strings.Contains(string(b), `"portcullis-main-cert-ready":{"entryPoints":["traefik"],"rule":"Path(`+"`/portcullis-main-cert`"+`)","service":"ping@internal"}`) ||
		!strings.Contains(string(b), `"portcullis-ingress-health":{"entryPoints":["websecure"],`) || !strings.Contains(string(b), `"tls":{}`) {
		t.Errorf("document %s (%v)", b, err)
	}
	expired := pair(t, []string{testMain, "*." + testMain}, nil, now.Add(-48*time.Hour), now.Add(-time.Hour))
	for name, mc := range map[string]*mainCert{"none": nil, "expired": {CertPEM: expired[0], KeyPEM: expired[1]}} {
		doc, _ := buildDynamic(nil, mc, testMain, "", now)
		if doc.HTTP != nil {
			t.Errorf("%s: a readiness route without a served main certificate", name)
		}
		if b, _ := json.Marshal(doc); strings.Contains(string(b), `"http"`) {
			t.Errorf("%s: %s", name, b)
		}
	}
}
