package mailtest

import (
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
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/portcullis/mailctl/internal/export"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

type backend struct {
	mu       sync.Mutex
	user, pw string
	from, to string
	data     string
}

type session struct{ b *backend }

func (b *backend) NewSession(*smtp.Conn) (smtp.Session, error) { return &session{b}, nil }
func (s *session) AuthMechanisms() []string                    { return []string{sasl.Plain} }
func (s *session) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, u, p string) error {
		s.b.mu.Lock()
		s.b.user, s.b.pw = u, p
		s.b.mu.Unlock()
		return nil
	}), nil
}
func (s *session) Mail(f string, _ *smtp.MailOptions) error { s.b.from = f; return nil }
func (s *session) Rcpt(t string, _ *smtp.RcptOptions) error { s.b.to = t; return nil }
func (s *session) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	s.b.mu.Lock()
	s.b.data = string(b)
	s.b.mu.Unlock()
	return nil
}
func (s *session) Reset()        {}
func (s *session) Logout() error { return nil }

func selfSigned(t *testing.T, host string) (tls.Certificate, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, hex.EncodeToString(sum[:])
}

func TestSendSignedTestAndDestroyPassword(t *testing.T) {
	f := fake.New()
	t.Cleanup(f.Close)
	dom := f.Put("Domain", "", map[string]any{"name": "example.com"})
	acct := f.Put("Account", "", map[string]any{"@type": "User", "name": "root", "domainId": dom, "description": "portcullis:3e5a7c9b-1d2f-4a6b-8c0e-2f4a6b8c0d1e"})
	b, _ := os.ReadFile("../state/testdata/mailstate_v2.json")
	doc, err := state.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	cert, spki := selfSigned(t, "mail.example.com")
	be := &backend{}
	srv := smtp.NewServer(be)
	srv.Domain, srv.TLSConfig, srv.AllowInsecureAuth = "mail.example.com", &tls.Config{Certificates: []tls.Certificate{cert}}, false
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	s := &Sender{C: stalwart.New(f.URL(), stalwart.Bearer("API_k")), Doc: doc, SubmitAddr: ln.Addr().String(),
		MailctlIP: netip.MustParseAddr("172.31.255.3"), TLS: func(now time.Time) *tls.Config { return export.PinnedTLS("mail.example.com", []string{spki}, now) }}
	res, err := s.Send(context.Background(), "someone@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "root@example.com" || be.user != "root@example.com" || be.from != "root@example.com" || be.to != "someone@example.org" {
		t.Fatalf("%+v %+v", res, be)
	}
	if !strings.Contains(be.data, "Message-ID: <"+res.MessageID+">") || !strings.Contains(be.data, "Authentication-Results") {
		t.Fatalf("data %q", be.data)
	}
	if n := len(f.Objects("AppPassword", acct)); n != 0 {
		t.Fatalf("%d test passwords left", n)
	}
	// A wrong certificate key: refused, and the password still destroyed.
	s.TLS = func(now time.Time) *tls.Config {
		return export.PinnedTLS("mail.example.com", []string{strings.Repeat("00", 32)}, now)
	}
	if _, err := s.Send(context.Background(), "someone@example.org"); err == nil || !strings.Contains(err.Error(), "SPKI pin") {
		t.Fatalf("pin: %v", err)
	}
	if n := len(f.Objects("AppPassword", acct)); n != 0 {
		t.Fatalf("%d test passwords left after a failure", n)
	}
	// No postmaster.
	doc.Postmaster = nil
	if _, err := s.Send(context.Background(), "x@example.org"); !errors.Is(err, ErrNoPostmaster) {
		t.Fatal(err)
	}
}
