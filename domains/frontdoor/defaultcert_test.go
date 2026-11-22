package frontdoor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestDefaultCertMirror (Task 31 fix round 2, M3): the served pair reaches
// the ingress namespace's traefik-default-cert as the file-provider
// document, only from the leader, only when servable, only when it
// differs; a refused pair keeps the last good one; nothing logged carries
// the key.
func TestDefaultCertMirror(t *testing.T) {
	ctx := context.Background()
	st := newStore()
	ingress := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: DefaultCertSecret, Namespace: "portcullis-ingress"}})
	lead := true
	var logs []string
	servable := true
	m := &DefaultCertMirror{Client: ingress, Namespace: "portcullis-ingress", Store: st, Fence: testFence{&lead}, Now: func() time.Time { return t0 },
		Log: func(s string) { logs = append(logs, s) },
		Check: func(c, k string, _ time.Time) error {
			if !servable {
				return errors.New("names wrong")
			}
			return nil
		}}
	doc := func() string {
		s, err := ingress.CoreV1().Secrets("portcullis-ingress").Get(ctx, DefaultCertSecret, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return string(s.Data[DefaultCertKey])
	}
	if err := st.SaveCert(ctx, "slot", Cert{ChainPEM: "CHAIN-1", KeyPEM: "KEY-SECRET-1"}, true); err != nil {
		t.Fatal(err)
	}
	if w, err := m.Sync(ctx); !w || err != nil {
		t.Fatalf("Sync: %v %v", w, err)
	}
	want := `{"tls":{"stores":{"default":{"defaultCertificate":{"certFile":"CHAIN-1","keyFile":"KEY-SECRET-1"}}}}}`
	if got := doc(); got != want {
		t.Fatalf("document %s, want %s", got, want)
	}
	if w, _ := m.Sync(ctx); w {
		t.Fatal("rewritten although equal")
	}
	// A standby never writes.
	lead = false
	_ = st.SaveCert(ctx, "slot", Cert{ChainPEM: "CHAIN-2", KeyPEM: "KEY-SECRET-2"}, true)
	if w, err := m.Sync(ctx); w || err != nil || !strings.Contains(doc(), "CHAIN-1") {
		t.Fatalf("standby wrote: %v %v %s", w, err, doc())
	}
	lead = true
	// A pair the domains service wouldn't serve is never written: the last
	// good one stays; said once.
	servable = false
	for range 2 {
		if w, err := m.Sync(ctx); w || err != nil {
			t.Fatalf("unservable: %v %v", w, err)
		}
	}
	if !strings.Contains(doc(), "CHAIN-1") {
		t.Fatal("an unservable pair replaced the good one")
	}
	kept := 0
	for _, l := range logs {
		if strings.Contains(l, "is kept") {
			kept++
		}
	}
	if kept != 1 {
		t.Fatalf("the refusal logged %d times: %q", kept, logs)
	}
	servable = true
	if w, err := m.Sync(ctx); !w || err != nil || !strings.Contains(doc(), "CHAIN-2") {
		t.Fatalf("renewed pair: %v %v %s", w, err, doc())
	}
	for _, l := range logs {
		if strings.Contains(l, "KEY-SECRET") || strings.Contains(l, "CHAIN-") {
			t.Fatalf("a log line carries certificate material: %q", l)
		}
	}
	// No Secret (the CLI creates it): an error naming it, nothing created.
	m.Client = fake.NewClientset()
	if _, err := m.Sync(ctx); !errors.Is(err, ErrNoDefaultCertSecret) {
		t.Fatalf("no Secret: %v", err)
	}
}

// TestDefaultCertDocRoundTrip: the document's pair reads back; anything
// else holds none.
func TestDefaultCertDocRoundTrip(t *testing.T) {
	d, err := DefaultCertDoc("C\n", "K\n")
	if err != nil {
		t.Fatal(err)
	}
	if c, k := defaultCertOf(d); c != "C\n" || k != "K\n" {
		t.Fatalf("%q %q", c, k)
	}
	for _, bad := range []string{"", "{", `{"tls":{}}`} {
		if c, k := defaultCertOf([]byte(bad)); c != "" || k != "" {
			t.Fatalf("%q: %q %q", bad, c, k)
		}
	}
}
