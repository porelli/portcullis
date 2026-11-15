package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricNames(t *testing.T) {
	m := New()
	m.Check.WithLabelValues("port25").Set(1)
	m.DKIMStage.WithLabelValues("example.com", "active").Set(1)
	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	for _, want := range []string{`portcullis_mail_check{check="port25"} 1`, `portcullis_mail_dkim_stage{domain="example.com",stage="active"} 1`,
		"portcullis_mail_cert_expiry_seconds", "portcullis_mail_queue_messages", "portcullis_mail_queue_deferred_ratio"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(string(b), "go_goroutines") {
		t.Error("runtime collectors exposed")
	}
	if r, _ := srv.Client().Get(srv.URL + "/"); r.StatusCode != 404 {
		t.Errorf("/ answered %d", r.StatusCode)
	}
}
