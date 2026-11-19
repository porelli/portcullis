package metrics

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetricNames(t *testing.T) {
	m := New()
	m.Check.WithLabelValues("port25").Set(1)
	m.DKIMStage.WithLabelValues("example.com", "active").Set(1)
	secret := filepath.Join(t.TempDir(), "metrics-secret")
	os.WriteFile(secret, []byte("0123456789abcdef0123456789abcdef0123456789\n"), 0o600)
	srv := httptest.NewServer(m.Handler(secret, readSecret, t.Logf))
	defer srv.Close()
	get := func(user, pw string) *http.Response {
		req, _ := http.NewRequest("GET", srv.URL+"/metrics", nil)
		if user != "" || pw != "" {
			req.SetBasicAuth(user, pw)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	// Final review I1: Basic auth as for mail; anything else 401.
	for _, c := range [][2]string{{"", ""}, {"prometheus", "wrong"}, {"other", "0123456789abcdef0123456789abcdef0123456789"}} {
		if r := get(c[0], c[1]); r.StatusCode != 401 {
			t.Errorf("%q: %d", c, r.StatusCode)
		}
	}
	resp := get("prometheus", "0123456789abcdef0123456789abcdef0123456789")
	if resp.StatusCode != 200 {
		t.Fatalf("scrape: %d", resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	for _, want := range []string{`portcullis_mail_check{check="port25"} 1`, `portcullis_mail_dkim_stage{domain="example.com",stage="active"} 1`,
		"portcullis_mail_queue_messages", "portcullis_mail_queue_deferred_ratio"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s", want)
		}
	}
	// The certificate's expiry is core's own textfile metric now.
	if strings.Contains(string(b), "portcullis_mail_cert_expiry_seconds") {
		t.Error("the adapter exposes the certificate expiry")
	}
	if strings.Contains(string(b), "go_goroutines") {
		t.Error("runtime collectors exposed")
	}
	if r, _ := srv.Client().Get(srv.URL + "/"); r.StatusCode != 404 {
		t.Errorf("/ answered %d", r.StatusCode)
	}
	// A short or unreadable secret refuses every scrape.
	os.WriteFile(secret, []byte("short"), 0o600)
	if r := get("prometheus", "short"); r.StatusCode != 503 {
		t.Errorf("short secret: %d", r.StatusCode)
	}
	os.Remove(secret)
	if r := get("prometheus", "0123456789abcdef0123456789abcdef0123456789"); r.StatusCode != 503 {
		t.Errorf("no secret: %d", r.StatusCode)
	}
}

func readSecret(path string, min int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if len(s) < min {
		return "", errors.New("short")
	}
	return s, nil
}
