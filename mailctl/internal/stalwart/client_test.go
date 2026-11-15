package stalwart

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

type fixture struct {
	Request  json.RawMessage `json:"request"`
	Status   int             `json:"status"`
	Response json.RawMessage `json:"response"`
}

func readFixture(t *testing.T, name string) fixture {
	t.Helper()
	b, err := os.ReadFile("testdata/jmap/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// replay answers one recorded triple and checks the request is the
// recorded one (as JSON values) and carries the auth.
func replay(t *testing.T, f fixture, wantAuth string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/jmap" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("Authorization %q, want %q", got, wantAuth)
		}
		body, _ := io.ReadAll(r.Body)
		var got, want any
		json.Unmarshal(body, &got)
		json.Unmarshal(f.Request, &want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("request\n got %s\nwant %s", body, f.Request)
		}
		w.WriteHeader(f.Status)
		w.Write(f.Response)
	}))
}

func TestActionReloadSettings(t *testing.T) {
	f := readFixture(t, "action-reload-settings")
	srv := replay(t, f, "Bearer API_test")
	defer srv.Close()
	if err := New(srv.URL, Bearer("API_test")).Action(context.Background(), "ReloadSettings"); err != nil {
		t.Fatal(err)
	}
}

func TestSetNotCreated(t *testing.T) {
	f := readFixture(t, "domain-create-invalid-tld-refused")
	srv := replay(t, f, "Basic cmVjb3Zlcnk6cHc=")
	defer srv.Close()
	r, err := New(srv.URL, Basic("recovery", "pw")).Set(context.Background(), "Domain", map[string]any{
		"d3": map[string]any{
			"name":                  "portcullis-former.invalid",
			"dkimManagement":        map[string]any{"@type": "Manual"},
			"certificateManagement": map[string]any{"@type": "Manual"},
			"dnsManagement":         map[string]any{"@type": "Manual"},
		},
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := r.Failed()
	if e == nil || !strings.Contains(e.Error(), "Invalid domain name") || r.NotCreated["d3"].Type != "invalidPatch" {
		t.Fatalf("refusal not reported: %v %+v", e, r)
	}
	if r.CreatedID("d3") != "" {
		t.Fatal("an id for a refused create")
	}
}

func TestMethodErrorAndHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer bad" {
			w.WriteHeader(401)
			w.Write([]byte(`{"detail":"echo of a secret must never surface"}`))
			return
		}
		w.Write([]byte(`{"methodResponses":[["error",{"type":"forbidden","description":"no"},"0"]],"sessionState":"x"}`))
	}))
	defer srv.Close()
	err := New(srv.URL, Bearer("ok")).Call(context.Background(), "x:Domain/get", nil, nil)
	var me *MethodError
	if !asMethodError(err, &me) || me.Type != "forbidden" {
		t.Fatalf("method error: %v", err)
	}
	err = New(srv.URL, Bearer("bad")).Call(context.Background(), "x:Domain/get", nil, nil)
	if !IsUnauthorized(err) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("401: %v", err)
	}
}

func asMethodError(err error, out **MethodError) bool {
	m, ok := err.(*MethodError)
	*out = m
	return ok
}

func TestQueryPagesAndGetChunks(t *testing.T) {
	ids := make([]string, 600)
	for i := range ids {
		ids[i] = "k" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req struct {
			MethodCalls [][3]json.RawMessage `json:"methodCalls"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var method string
		json.Unmarshal(req.MethodCalls[0][0], &method)
		var args map[string]json.RawMessage
		json.Unmarshal(req.MethodCalls[0][1], &args)
		var out any
		switch method {
		case "x:MemoryLookupKey/query":
			var pos int
			json.Unmarshal(args["position"], &pos)
			end := min(pos+250, len(ids))
			out = map[string]any{"ids": ids[pos:end], "position": pos}
		case "x:MemoryLookupKey/get":
			var want []string
			json.Unmarshal(args["ids"], &want)
			if len(want) > getChunk {
				t.Errorf("get of %d ids", len(want))
			}
			var list []map[string]string
			for _, id := range want {
				list = append(list, map[string]string{"id": id})
			}
			out = map[string]any{"list": list, "notFound": []string{}}
		}
		json.NewEncoder(w).Encode(map[string]any{"methodResponses": []any{[]any{method, out, "0"}}})
	}))
	defer srv.Close()
	c := New(srv.URL, Bearer("k"))
	got, err := c.Query(context.Background(), "MemoryLookupKey", map[string]string{"namespace": "x"})
	if err != nil || len(got) != 600 {
		t.Fatalf("query: %d %v", len(got), err)
	}
	var objs []struct{ ID string }
	if err := c.Get(context.Background(), "MemoryLookupKey", got, nil, &objs); err != nil || len(objs) != 600 {
		t.Fatalf("get: %d %v", len(objs), err)
	}
}
