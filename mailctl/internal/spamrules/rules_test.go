package spamrules

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"testing"
)

func TestEmbeddedRulesDigest(t *testing.T) {
	sum := sha256.Sum256(Rules())
	if got := hex.EncodeToString(sum[:]); got != SHA256 {
		t.Fatalf("spam-filter-rules.json.gz sha256 %s, want %s (v3.0.4)", got, SHA256)
	}
}

func TestHandlerServesOnlyThePath(t *testing.T) {
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + Path)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	b, _ := io.ReadAll(resp.Body)
	if len(b) != len(Rules()) {
		t.Fatalf("served %d bytes", len(b))
	}
	for _, p := range []string{"/", "/spam-filter-rules.json", "/x" + Path} {
		if r, _ := srv.Client().Get(srv.URL + p); r.StatusCode != 404 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
}

func TestHTTPLookups(t *testing.T) {
	ls, err := HTTPLookups()
	if err != nil || len(ls) != 4 {
		t.Fatalf("%d lookups, %v", len(ls), err)
	}
	for _, l := range ls {
		if l["namespace"] == "" || l["url"] == "" {
			t.Fatalf("lookup without namespace / url: %v", l)
		}
	}
}
