package wellknown

import (
	"net/http/httptest"
	"strings"
	"testing"
)

type src struct{}

func (src) MailDomain(d string) bool { return d == "example.com" }
func (src) Policy(d string) string {
	return "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 86400\n"
}
func (src) Hostname() string { return "mail.example.com" }

func do(method, host, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	w := httptest.NewRecorder()
	Handler(src{}).ServeHTTP(w, r)
	return w
}

func TestWellKnownExactPaths(t *testing.T) {
	w := do("GET", "mta-sts.example.com", "/.well-known/mta-sts.txt", "")
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/plain" || w.Header().Get("Cache-Control") != "max-age=300" || !strings.HasPrefix(w.Body.String(), "version: STSv1") {
		t.Fatalf("policy: %d %v %q", w.Code, w.Header(), w.Body)
	}
	for _, c := range []struct{ m, h, p string }{
		{"GET", "mta-sts.example.com", "/.well-known/mta-sts.txt.bak"},
		{"GET", "mta-sts.example.com", "/.well-known/MTA-STS.txt"},
		{"POST", "mta-sts.example.com", "/.well-known/mta-sts.txt"},
		{"GET", "mta-sts.other.example", "/.well-known/mta-sts.txt"},
		{"GET", "autoconfig.example.com", "/.well-known/mta-sts.txt"},
		{"GET", "mta-sts.example.com", "/mail/config-v1.1.xml"},
		{"GET", "www.example.com", "/"},
		{"GET", "autodiscover.example.com", "/autodiscover/autodiscover.xml"},
	} {
		if w := do(c.m, c.h, c.p, ""); w.Code != 404 {
			t.Errorf("%s %s%s: %d", c.m, c.h, c.p, w.Code)
		}
	}
	for _, p := range []string{"/mail/config-v1.1.xml", "/.well-known/autoconfig/mail/config-v1.1.xml"} {
		w := do("GET", "autoconfig.example.com:443", p, "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), "<hostname>mail.example.com</hostname>") || !strings.Contains(w.Body.String(), "<port>993</port>") || !strings.Contains(w.Body.String(), "%EMAILADDRESS%") {
			t.Fatalf("autoconfig %s: %d %s", p, w.Code, w.Body)
		}
	}
}

func TestAutodiscoverRefusesForeignAddress(t *testing.T) {
	req := func(a string) string {
		return `<Autodiscover><Request><EMailAddress>` + a + `</EMailAddress></Request></Autodiscover>`
	}
	w := do("POST", "autodiscover.example.com", "/autodiscover/autodiscover.xml", req("alice@example.com"))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<LoginName>alice@example.com</LoginName>") {
		t.Fatalf("own: %d %s", w.Code, w.Body)
	}
	for _, a := range []string{"mallory@evil.example", "&lt;script&gt;@example.com", "nobody"} {
		w := do("POST", "autodiscover.example.com", "/autodiscover/autodiscover.xml", req(a))
		if w.Code != 200 || strings.Contains(w.Body.String(), "LoginName") {
			t.Errorf("%s echoed: %s", a, w.Body)
		}
	}
}
