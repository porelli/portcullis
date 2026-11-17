package tlsprobe

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
	"math/big"
	"net"
	"testing"
	"time"
)

// L7: the leaf an implicit-TLS listener presents, its SPKI; a refused
// connection is an error.
func TestLeafImplicitTLS(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.example.com"}, DNSNames: []string{"mail.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); time.Sleep(100 * time.Millisecond); c.Close() }()
		}
	}()
	leaf, err := Leaf(context.Background(), nil, ln.Addr().String(), "mail.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if SPKI(leaf) != hex.EncodeToString(sum[:]) || leaf.DNSNames[0] != "mail.example.com" {
		t.Fatalf("%v", leaf.DNSNames)
	}
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l2.Addr().String()
	l2.Close()
	if _, err := Leaf(context.Background(), nil, addr, "mail.example.com", false); err == nil {
		t.Fatal("a closed port answered")
	}
}
