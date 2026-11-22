package frontdoor

import (
	"context"
	"errors"
	"fmt"
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
	ingress := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: DefaultCertSecret, Namespace: "portcullis-ingress"}, Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.crt": []byte("OLD"), "tls.key": []byte("OLD"), "extra.yml": []byte("tls: {}")}})
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
		if s.Type != corev1.SecretTypeTLS {
			t.Fatalf("type %s", s.Type)
		}
		return fmt.Sprintf("%d|%s|%s", len(s.Data), s.Data["tls.crt"], s.Data["tls.key"])
	}
	if err := st.SaveCert(ctx, "slot", Cert{ChainPEM: "CHAIN-1", KeyPEM: "KEY-SECRET-1"}, true); err != nil {
		t.Fatal(err)
	}
	if w, err := m.Sync(ctx); !w || err != nil {
		t.Fatalf("Sync: %v %v", w, err)
	}
	// Exactly the pair: a stray key is dropped.
	if got := doc(); got != "2|CHAIN-1|KEY-SECRET-1" {
		t.Fatalf("Secret %s", got)
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

// TestDefaultCertMirrorRefusesOtherType: a Secret that isn't
// kubernetes.io/tls is never written (the CLI recreates it).
func TestDefaultCertMirrorRefusesOtherType(t *testing.T) {
	ctx := context.Background()
	st := newStore()
	_ = st.SaveCert(ctx, "slot", Cert{ChainPEM: "C", KeyPEM: "K"}, true)
	ingress := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: DefaultCertSecret, Namespace: "portcullis-ingress"}, Type: corev1.SecretTypeOpaque})
	lead := true
	m := &DefaultCertMirror{Client: ingress, Namespace: "portcullis-ingress", Store: st, Fence: testFence{&lead}, Now: func() time.Time { return t0 },
		Check: func(string, string, time.Time) error { return nil }}
	if w, err := m.Sync(ctx); w || err == nil || !strings.Contains(err.Error(), "not kubernetes.io/tls") {
		t.Fatalf("Sync: %v %v", w, err)
	}
	s, _ := ingress.CoreV1().Secrets("portcullis-ingress").Get(ctx, DefaultCertSecret, metav1.GetOptions{})
	if len(s.Data) != 0 {
		t.Fatalf("written: %v", s.Data)
	}
}
