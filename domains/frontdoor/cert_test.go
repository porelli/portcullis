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

// TestChallengeOnlyAcmeName: the front door writes challenge TXT only at
// _acme-challenge.<d>, only while leading; any other name (a CNAME'd
// challenge lego would follow, another domain, a core host) is refused
// before the provider is called.
func TestChallengeOnlyAcmeName(t *testing.T) {
	p := newFake(t, []string{"198.51.100.1"})
	lead := true
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: time.Minute, Fence: testFence{&lead}}
	ctx := context.Background()
	for _, n := range []string{"_acme-challenge.other.example.", "_acme-challenge.auth.example.org.", "example.org.", "x._acme-challenge.example.org", "_acme-challenge.example.org.evil."} {
		if err := w.PresentTXT(ctx, n, "v1"); err == nil {
			t.Errorf("TXT at %s written", n)
		}
	}
	if err := w.PresentTXT(ctx, "_acme-challenge.example.org.", `a"b`); err == nil {
		t.Error("a TXT value with a quote written")
	}
	if len(p.calls) != 0 {
		t.Fatalf("provider called: %v", p.calls)
	}
	lead = false
	if err := w.PresentTXT(ctx, "_acme-challenge.example.org.", "v1"); !errors.Is(err, ErrStandingBy) {
		t.Fatalf("standing by: %v", err)
	}
	lead = true
	if err := w.PresentTXT(ctx, "_acme-challenge.example.org.", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := w.CleanUpTXT(ctx, "_acme-challenge.example.org", "v1"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.calls, ",") != "append _acme-challenge v1,delete _acme-challenge v1" {
		t.Fatalf("calls %v", p.calls)
	}
}

type fakeACME struct {
	uri      string
	regs     int
	obtains  int
	obtainEr error
	chain    string
}

func (a *fakeACME) CAServer() string { return "https://ca.example/dir" }

func (a *fakeACME) CurrentURI(acct []byte) string {
	if string(acct) == "acct:"+a.uri {
		return a.uri
	}
	return ""
}
func (a *fakeACME) Register(context.Context) ([]byte, string, error) {
	a.regs++
	return []byte("acct:" + a.uri), a.uri, nil
}
func (a *fakeACME) Obtain(context.Context, []byte, string, DNS01) (string, string, error) {
	a.obtains++
	return a.chain, "key", a.obtainEr
}

func newStore() SecretStore {
	mk := func(n string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: n, Namespace: "portcullis"}}
	}
	return SecretStore{Client: fake.NewClientset(mk(AccountSecret), mk(CertSecret)), Namespace: "portcullis"}
}

// TestIssueRefusesUncheckedCert: a chain the check refuses is never
// stored; a failed renewal backs off.
func TestIssueRefusesUncheckedCert(t *testing.T) {
	st := newStore()
	lead := true
	now := t0
	a := &fakeACME{uri: "https://ca.example/acct/1", chain: "x"}
	c := &Certs{Domain: "example.org", Store: st, ACME: a, Fence: testFence{&lead}, Now: func() time.Time { return now },
		Check: func(string, string, time.Time) error { return errors.New("names wrong") }}
	ctx := context.Background()
	if err := c.IssueMain(ctx); err == nil || !strings.Contains(err.Error(), "nothing stored") {
		t.Fatalf("IssueMain: %v", err)
	}
	if got, _ := st.LoadCert(ctx, AccountKeyFor("https://ca.example/dir")); got.ChainPEM != "" {
		t.Fatal("a refused chain was stored")
	}
	if a.regs != 1 {
		t.Fatalf("%d registrations", a.regs)
	}
	// A stored certificate of this account that doesn't parse is due;
	// the failed renewal waits 10 min before the next try.
	if err := st.SaveCert(ctx, AccountKeyFor("https://ca.example/dir"), Cert{ChainPEM: "garbage", KeyPEM: "k", AccountURI: a.uri}, true); err != nil {
		t.Fatal(err)
	}
	if ordered, err := c.Renew(ctx); !ordered || err == nil {
		t.Fatalf("Renew: %v %v", ordered, err)
	}
	now = now.Add(9 * time.Minute)
	if ordered, _ := c.Renew(ctx); ordered {
		t.Fatal("no backoff after a failed renewal")
	}
	now = now.Add(2 * time.Minute)
	if ordered, _ := c.Renew(ctx); !ordered {
		t.Fatal("no retry after the backoff")
	}
	if a.obtains != 3 {
		t.Fatalf("%d orders", a.obtains)
	}
	if got, _ := st.LoadCert(ctx, AccountKeyFor("https://ca.example/dir")); got.ChainPEM != "garbage" {
		t.Fatal("the stored certificate changed")
	}
}

// TestNotDueReasonLoggedOnce (fix round 1, M1): a certificate that isn't
// renewed on its own says why, once per change of reason.
func TestNotDueReasonLoggedOnce(t *testing.T) {
	st := newStore()
	lead := true
	var logs []string
	a := &fakeACME{uri: "https://ca.example/acct/1"}
	c := &Certs{Domain: "example.org", Store: st, ACME: a, Fence: testFence{&lead}, Now: func() time.Time { return t0 },
		Log: func(m string) { logs = append(logs, m) }, Check: func(string, string, time.Time) error { return nil }}
	ctx := context.Background()
	for range 3 {
		if _, err := c.Renew(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SaveCert(ctx, AccountKeyFor("https://ca.example/dir"), Cert{ChainPEM: "x", KeyPEM: "k", AccountURI: "https://old.example/acct/2"}, true); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := c.Renew(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(logs) != 2 || !strings.Contains(logs[0], "no certificate of this CA yet") || !strings.Contains(logs[1], "old.example") {
		t.Fatalf("logs %q", logs)
	}
	if a.obtains != 0 {
		t.Fatal("ordered")
	}
}
