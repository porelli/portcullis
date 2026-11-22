package main

import (
	"bytes"
	"strings"
	"testing"

	"filippo.io/age"
)

// TestSealUnseal: the backup's frontdoor.age round-trips with the domains
// key only; another key or garbage refuses; no plaintext in the sealed file.
func TestSealUnseal(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	plain := `{"v":1,"secrets":[{"name":"frontdoor-acme","data":{"frontdoor-x":"S0VZLVNFQ1JFVA=="}}]}`
	var sealed, errb bytes.Buffer
	if code := runSeal([]string{id.Recipient().String()}, strings.NewReader(plain), &sealed, &errb); code != exitOK {
		t.Fatalf("seal: %d %s", code, errb.String())
	}
	if strings.Contains(sealed.String(), "S0VZLVNFQ1JFVA") || !strings.HasPrefix(sealed.String(), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatal("the sealed file isn't an armored age file without the plaintext")
	}
	var out bytes.Buffer
	in := "# created: now\n# public key: x\n" + id.String() + "\n" + sealed.String()
	if code := runUnseal(nil, strings.NewReader(in), &out, &errb); code != exitOK || out.String() != plain {
		t.Fatalf("unseal: %d %q %s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := runUnseal(nil, strings.NewReader(other.String()+"\n"+sealed.String()), &out, &errb); code != exitProblem || out.Len() != 0 {
		t.Fatalf("unseal with another key: %d %q", code, out.String())
	}
	if code := runSeal([]string{"notakey"}, strings.NewReader(plain), &out, &errb); code != exitUsage {
		t.Fatal("seal with a bad recipient")
	}
	if code := runSeal([]string{id.Recipient().String()}, strings.NewReader(""), &out, &errb); code != exitUsage {
		t.Fatal("seal of nothing")
	}
}
