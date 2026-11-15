package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
	"github.com/portcullis/mailctl/internal/state"
)

type v1env struct {
	f   *fake.Server
	v   *V1
	s   *Server
	log *bytes.Buffer
}

func newV1(t *testing.T) *v1env {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	park := f.Put("Domain", "", map[string]any{"name": state.ParkingDomain})
	f.Put("Domain", "", map[string]any{"name": "example.com"})
	f.Put("Account", "", map[string]any{"@type": "User", "name": reconcile.MailctlAccount, "domainId": park})
	st, _ := state.Open(t.TempDir())
	c := stalwart.New(f.URL(), stalwart.Bearer("API_k"))
	var buf bytes.Buffer
	lg := logx.New(&buf)
	r := reconcile.NewRunner(c, st, time.Hour, false, lg.Printf)
	v := &V1{Store: st, C: c, Runner: r, Logf: lg.Printf}
	srv, _ := newServer(t, "172.31.255.16/28")
	srv.Handler = v.Handler()
	return &v1env{f: f, v: v, s: srv, log: &buf}
}

func (e *v1env) do(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("172.31.255.19")}))
	r.Header.Set("Authorization", "Bearer "+secretA)
	w := httptest.NewRecorder()
	e.s.ServeHTTP(w, r)
	return w
}

func vec(t *testing.T, gen int) string {
	b, err := os.ReadFile("../state/testdata/mailstate_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Replace(string(b), `"generation":12`, `"generation":`+itoa(gen), 1)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestStaleGeneration409(t *testing.T) {
	e := newV1(t)
	if w := e.do("PUT", "/v1/state", vec(t, 12)); w.Code != 202 || !strings.Contains(w.Body.String(), `"generation":12`) {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	for _, g := range []int{12, 11} {
		if w := e.do("PUT", "/v1/state", vec(t, g)); w.Code != 409 {
			t.Errorf("generation %d: %d", g, w.Code)
		}
	}
	if w := e.do("PUT", "/v1/state", `{"version":2}`); w.Code != 400 || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("bad doc: %d %s", w.Code, w.Body)
	}
	if e.v.Store.Get().Generation != 12 {
		t.Fatal("a refused document replaced the accepted one")
	}
	_ = e.v.Runner.Once(context.Background())
	w := e.do("GET", "/v1/state", "")
	var st map[string]any
	json.Unmarshal(w.Body.Bytes(), &st)
	if st["generation"] != float64(12) || st["applied_generation"] != float64(12) || st["bootstrap"] != true || len(st["errors"].([]any)) != 0 {
		t.Fatalf("GET /v1/state %s", w.Body)
	}
}

func TestMassRemoval409AtPut(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	var m map[string]any
	json.Unmarshal([]byte(vec(t, 13)), &m)
	m["accounts"] = m["accounts"].([]any)[:1]
	m["lists"].([]any)[0].(map[string]any)["members"] = []string{"alice"}
	m["postmaster"] = []string{"alice"}
	b, _ := json.Marshal(m)
	doc := string(b)
	if w := e.do("PUT", "/v1/state", doc); w.Code != 409 || !strings.Contains(w.Body.String(), "50 %") {
		t.Fatalf("mass removal: %d %s", w.Code, w.Body)
	}
}

func TestCredentialsRoutes(t *testing.T) {
	e := newV1(t)
	e.do("PUT", "/v1/state", vec(t, 12))
	_ = e.v.Runner.Once(context.Background())
	w := e.do("POST", "/v1/credentials", `{"username":"alice","label":"phone","expires_at":null}`)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var cr map[string]any
	json.Unmarshal(w.Body.Bytes(), &cr)
	secret, _ := cr["secret"].(string)
	if !strings.HasPrefix(secret, "app_") || cr["id"] == "" || cr["created_at"] == nil {
		t.Fatalf("created %s", w.Body)
	}
	// TestSecretNeverLogged: the secret is in the answer only.
	if strings.Contains(e.log.String(), secret) {
		t.Fatal("the secret was logged")
	}
	w = e.do("GET", "/v1/credentials?user=alice", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), `"label":"phone"`) || !strings.Contains(w.Body.String(), `"last_used":null`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	for body, code := range map[string]int{
		`{"username":"carol","label":"x","expires_at":null}`:                   404,
		`{"username":"alice","label":"","expires_at":null}`:                    400,
		`{"username":"alice","label":"x","expires_at":"2020-01-01T00:00:00Z"}`: 400,
		`{"username":"alice","label":"x"}`:                                     400,
		`{"username":"alice","label":"x","expires_at":null,"extra":1}`:         400,
		`{"username":"alice","label":"x","label":"y","expires_at":null}`:       400,
	} {
		if w := e.do("POST", "/v1/credentials", body); w.Code != code {
			t.Errorf("%s: %d, want %d", body, w.Code, code)
		}
	}
	if w := e.do("GET", "/v1/credentials?user=carol", ""); w.Code != 404 {
		t.Errorf("unknown user: %d", w.Code)
	}
	id := cr["id"].(string)
	if w := e.do("DELETE", "/v1/credentials/"+id+"?user=alice", ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if w := e.do("DELETE", "/v1/credentials/"+id+"?user=alice", ""); w.Code != 204 {
		t.Fatalf("delete again: %d", w.Code)
	}
	for i := 0; i < 5; i++ {
		e.do("POST", "/v1/credentials", `{"username":"alice","label":"p","expires_at":null}`)
	}
	if w := e.do("POST", "/v1/credentials", `{"username":"alice","label":"p","expires_at":null}`); w.Code != 409 {
		t.Fatalf("sixth: %d", w.Code)
	}
	e.f.Fail("x:AppPassword", 1)
	if w := e.do("GET", "/v1/credentials?user=alice", ""); w.Code != 503 || !strings.Contains(w.Body.String(), "mail server unreachable") {
		t.Fatalf("stalwart down: %d %s", w.Code, w.Body)
	}
}
