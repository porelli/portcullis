package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mcp-gate/internal/accesslog"
)

// TestAccessLogEndpoint: the log port (contract §20.10) serves the access
// log's lines as written, oldest first, from / limit, at most 4 MiB, GET
// only; nothing but whole valid lines.
func TestAccessLogEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.jsonl")
	l, err := accesslog.OpenWith(path, accesslog.Options{Group: -1, Secrets: func() []string { return []string{"s3cret-value"} }})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	for i := 0; i < 5; i++ {
		if err := l.Write(accesslog.Line{Time: base.Add(time.Duration(i) * time.Second), User: "alice", Client: "c",
			Resource: "https://mcp.example.com/mcp", Via: "direct", Method: "tools/call", Tool: "t-s3cret-value",
			Decision: "allow", UpstreamStatus: 200}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	h := newLogHandler(path)
	do := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
		return w
	}
	times := func(w *httptest.ResponseRecorder) []string {
		t.Helper()
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" {
			t.Fatalf("answer %d %q: %s", w.Code, w.Header().Get("Content-Type"), w.Body)
		}
		var out []string
		for _, ln := range strings.Split(strings.TrimSuffix(w.Body.String(), "\n"), "\n") {
			if ln == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Fatalf("line %q: %v", ln, err)
			}
			out = append(out, m["time"].(string))
		}
		return out
	}
	ts := func(i int) string { return base.Add(time.Duration(i) * time.Second).Format(time.RFC3339) }

	disk, _ := os.ReadFile(path)
	if w := do("GET", "/v1/log"); !bytes.Equal(w.Body.Bytes(), disk) {
		t.Fatalf("answer != the file:\n%s\n%s", w.Body, disk)
	}
	if strings.Contains(string(disk), "s3cret-value") {
		t.Fatal("the log carries a secret")
	}
	if got := times(do("GET", "/v1/log?limit=2")); len(got) != 2 || got[0] != ts(0) {
		t.Fatalf("limit=2: %v", got)
	}
	if got := times(do("GET", "/v1/log?from="+url.QueryEscape(ts(3)))); len(got) != 2 || got[0] != ts(3) {
		t.Fatalf("from: %v", got)
	}
	// An offset form of the same instant.
	plus := base.Add(3 * time.Second).In(time.FixedZone("x", 3600)).Format(time.RFC3339)
	if got := times(do("GET", "/v1/log?from="+url.QueryEscape(plus)+"&limit=1")); len(got) != 1 || got[0] != ts(3) {
		t.Fatalf("from with offset: %v", got)
	}

	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "FOO"} {
		if w := do(m, "/v1/log"); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
			t.Errorf("%s: %d", m, w.Code)
		}
	}
	for _, q := range []string{"limit=0", "limit=10001", "limit=-1", "limit=+5", "limit=", "limit=x", "from=2026-11-18",
		"from=2026-11-18T10:00:00", "from=", "from=x&from=y", "limit=1&limit=2", "since=x", "%zz"} {
		if w := do("GET", "/v1/log?"+q); w.Code != http.StatusBadRequest {
			t.Errorf("?%s: %d", q, w.Code)
		}
	}
	if w := do("GET", "/v1/log?limit=10000"); w.Code != 200 {
		t.Errorf("limit=10000: %d", w.Code)
	}
	for _, p := range []string{"/", "/v1/log/", "/v1/logs", "/healthz", "/v1/%6cog"} {
		if w := do("GET", p); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}

	// Out of order, torn, malformed and unknown-key lines: sorted, skipped.
	line := func(i int) string {
		var b bytes.Buffer
		_ = json.NewEncoder(&b).Encode(map[string]any{"time": ts(i), "user": "", "client": "", "resource": "r", "instance": "",
			"companion": "", "via": "direct", "method": "m", "tool": "", "args_sha256": "", "decision": "allow",
			"upstream_status": 0, "duration_ms": 0})
		return b.String()
	}
	odd := line(7) + line(6) + "not json\n" + `{"time":"` + ts(8) + `","extra":1}` + "\n" + strings.TrimSuffix(line(9), "\n")
	if err := os.WriteFile(path, []byte(odd), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := times(do("GET", "/v1/log")); strings.Join(got, ",") != ts(6)+","+ts(7) {
		t.Fatalf("odd lines: %v", got)
	}

	// At most 4 MiB, whole lines: 1 KiB lines, more than 4 MiB of them.
	long := strings.Replace(line(1), `"resource":"r"`, `"resource":"`+strings.Repeat("r", 1000)+`"`, 1)
	n := logAnswerMax/len(long) + 50
	if err := os.WriteFile(path, []byte(strings.Repeat(long, n)), 0o640); err != nil {
		t.Fatal(err)
	}
	w := do("GET", "/v1/log?limit=10000")
	if want := (logAnswerMax / len(long)) * len(long); w.Code != 200 || w.Body.Len() != want {
		t.Fatalf("4 MiB cap: %d, %d bytes, want %d", w.Code, w.Body.Len(), want)
	}

	// A symlinked log is never followed; a missing one is empty.
	secret := filepath.Join(dir, "other.jsonl")
	_ = os.WriteFile(secret, []byte(line(2)), 0o640)
	_ = os.Remove(path)
	if err := os.Symlink(secret, path); err != nil {
		t.Fatal(err)
	}
	if w := do("GET", "/v1/log"); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), ts(2)) {
		t.Fatalf("symlink: %d %s", w.Code, w.Body)
	}
	_ = os.Remove(path)
	if w := do("GET", "/v1/log"); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("missing log: %d %q", w.Code, w.Body)
	}
}
