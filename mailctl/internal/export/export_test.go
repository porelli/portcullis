package export

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

const uuid = "0b9d8c7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"

func setup(t *testing.T) (*fake.Server, *Exporter, string, string) {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	park := f.Put("Domain", "", map[string]any{"name": state.ParkingDomain})
	dom := f.Put("Domain", "", map[string]any{"name": "example.com"})
	former := f.Put("Account", "", map[string]any{"@type": "User", "name": "former-" + uuid, "domainId": park,
		"description": reconcile.DescPrefix + uuid, "permissions": reconcile.Disabled})
	active := f.Put("Account", "", map[string]any{"@type": "User", "name": "alice", "domainId": dom,
		"description": reconcile.DescPrefix + "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b"})
	_ = active
	e := &Exporter{C: stalwart.New(f.URL(), stalwart.Bearer("API_k")), IMAPAddr: "127.0.0.1:1", ServerName: "mail.example.com",
		MailctlIP: netip.MustParseAddr("172.31.255.3"), SPKI: []string{"00"}, Now: func() time.Time { return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC) }}
	return f, e, former, active
}

func TestExportRefusesActiveAccount(t *testing.T) {
	_, e, _, _ := setup(t)
	for _, id := range []string{"alice", "former-6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b", "former-x", "../etc"} {
		if _, err := e.Export(context.Background(), id, &bytes.Buffer{}); !errors.Is(err, ErrNotFormer) {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestExportRestoresDisabledOnError(t *testing.T) {
	f, e, former, _ := setup(t)
	e.Dial = func(string, *tls.Config) (*imapclient.Client, error) { return nil, errors.New("no route") }
	if _, err := e.Export(context.Background(), "former-"+uuid, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("err %v", err)
	}
	if n := len(f.Objects("AppPassword", former)); n != 0 {
		t.Fatalf("%d export passwords left", n)
	}
	a := f.Get("Account", "", former)
	dis := a["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)
	if dis["authenticate"] != true || dis["emailSend"] != true || dis["emailReceive"] != true {
		t.Fatalf("not disabled again: %v", a["permissions"])
	}
	if f.Count("x:AppPassword/set create") != 1 {
		t.Fatal("no export password was made")
	}
}

func TestExportStreamsMbox(t *testing.T) {
	f, e, former, _ := setup(t)
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("former-"+uuid+"@"+state.ParkingDomain, fmt.Sprintf("app_%036d", 1))
	mem.AddUser(user)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	user.Create("Archive", nil)
	for box, msg := range map[string]string{
		"INBOX":   "From: a@example.org\r\nSubject: one\r\n\r\nFrom the start\r\nbody\r\n",
		"Archive": "From: b@example.org\r\nSubject: two\r\n\r\nsecond\r\n",
	} {
		if _, err := user.Append(box, literal(msg), &imap.AppendOptions{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
	}
	srv := imapserver.New(&imapserver.Options{NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
		return mem.NewSession(), nil, nil
	}, Caps: imap.CapSet{imap.CapIMAP4rev1: {}}, InsecureAuth: true})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	e.Dial = func(string, *tls.Config) (*imapclient.Client, error) {
		return imapclient.DialInsecure(ln.Addr().String(), nil)
	}
	var out bytes.Buffer
	n, err := e.Export(context.Background(), "former-"+uuid, &out)
	if err != nil || n != 2 {
		t.Fatalf("export: %d %v", n, err)
	}
	s := out.String()
	if strings.Count(s, "\nFrom MAILER-DAEMON ")+boolInt(strings.HasPrefix(s, "From MAILER-DAEMON ")) != 2 || !strings.Contains(s, ">From the start") || strings.Contains(s, "\r") {
		t.Fatalf("mbox:\n%s", s)
	}
	// The password used is gone and the account disabled again.
	if len(f.Objects("AppPassword", former)) != 0 {
		t.Fatal("export password left")
	}
	created := f.Count("x:AppPassword/set create")
	if created != 1 {
		t.Fatalf("%d passwords made", created)
	}
}

func TestExportPasswordShape(t *testing.T) {
	f, e, former, _ := setup(t)
	var seen map[string]any
	e.Dial = func(string, *tls.Config) (*imapclient.Client, error) {
		ps := f.Objects("AppPassword", former)
		if len(ps) == 1 {
			seen = ps[0]
		}
		a := f.Get("Account", "", former)
		if a["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)["authenticate"] == true {
			t.Error("authenticate not lifted during the export")
		}
		return nil, errors.New("stop")
	}
	e.Export(context.Background(), "former-"+uuid, &bytes.Buffer{})
	ips := seen["allowedIps"].(map[string]any)
	if len(ips) != 1 || ips["172.31.255.3/32"] != true || seen["expiresAt"] != "2026-11-15T13:00:00Z" {
		t.Fatalf("password %v", seen)
	}
	perms := seen["permissions"].(map[string]any)["permissions"].(map[string]any)
	if len(perms) != len(stalwart.ExportPermissions) || perms["imapStore"] != nil {
		t.Fatalf("permissions %v", perms)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type lit struct {
	*strings.Reader
	n int64
}

func (l lit) Size() int64 { return l.n }

func literal(s string) imap.LiteralReader { return lit{strings.NewReader(s), int64(len(s))} }

// A step failing mid-export (the password can't be made) still leaves
// the account disabled.
func TestExportFailingMidwayDisablesAgain(t *testing.T) {
	f, e, former, _ := setup(t)
	f.Refuse("AppPassword", "no")
	if _, err := e.Export(context.Background(), "former-"+uuid, &bytes.Buffer{}); err == nil {
		t.Fatal("export succeeded")
	}
	dis := f.Get("Account", "", former)["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)
	if dis["authenticate"] != true {
		t.Fatalf("authenticate left lifted: %v", dis)
	}
}

func TestExportRefusesWithoutPin(t *testing.T) {
	f, e, former, _ := setup(t)
	e.SPKI = nil
	if _, err := e.Export(context.Background(), "former-"+uuid, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "key isn't known") {
		t.Fatalf("no pin: %v", err)
	}
	if f.Count("x:AppPassword/set create") != 0 {
		t.Fatal("a password was made without a pin")
	}
	if a := f.Get("Account", "", former); a["permissions"].(map[string]any)["disabledPermissions"].(map[string]any)["authenticate"] != true {
		t.Fatal("not disabled")
	}
}

// The leaf must be the mail certificate's key: another self-signed
// certificate for the same host name is refused.
func TestExportTLSPin(t *testing.T) {
	good, goodSPKI := selfSigned(t, "mail.example.com")
	bad, _ := selfSigned(t, "mail.example.com")
	for _, tc := range []struct {
		cert tls.Certificate
		ok   bool
	}{{good, true}, {bad, false}} {
		f, e, _, _ := setup(t)
		_ = f
		mem := imapmemserver.New()
		user := imapmemserver.NewUser("former-"+uuid+"@"+state.ParkingDomain, fmt.Sprintf("app_%036d", 1))
		mem.AddUser(user)
		user.Create("INBOX", nil)
		srv := imapserver.New(&imapserver.Options{NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		}, Caps: imap.CapSet{imap.CapIMAP4rev1: {}}})
		ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{tc.cert}})
		go srv.Serve(ln)
		e.IMAPAddr, e.SPKI, e.Dial = ln.Addr().String(), []string{goodSPKI}, nil
		e.Now = time.Now
		_, err := e.Export(context.Background(), "former-"+uuid, &bytes.Buffer{})
		srv.Close()
		if tc.ok && err != nil {
			t.Fatalf("pinned certificate refused: %v", err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "SPKI")) {
			t.Fatalf("another certificate accepted: %v", err)
		}
	}
}

func selfSigned(t *testing.T, host string) (tls.Certificate, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, hex.EncodeToString(sum[:])
}
