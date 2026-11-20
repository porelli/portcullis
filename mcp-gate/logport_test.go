package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
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
	l, err := accesslog.OpenWith(path, accesslog.Options{Group: -1, Generation: true, Secrets: func() []string { return []string{"s3cret-value"} }})
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
	w2 := do("GET", "/v1/log?limit=2")
	if got := times(w2); len(got) != 2 || got[0] != ts(0) || w2.Header().Get("X-Portcullis-Truncated") != "true" {
		t.Fatalf("limit=2: %v %v", got, w2.Header())
	}
	// The cursor continues right after it, to the end (not truncated).
	w3 := do("GET", "/v1/log?cursor="+w2.Header().Get("X-Portcullis-Next")+"&limit=3")
	if got := times(w3); strings.Join(got, ",") != ts(2)+","+ts(3)+","+ts(4) || w3.Header().Get("X-Portcullis-Truncated") != "false" {
		t.Fatalf("cursor page: %v %v", got, w3.Header())
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
		"from=2026-11-18T10:00:00", "from=", "from=x&from=y", "limit=1&limit=2", "since=x", "%zz", "limit=01",
		"from=0001-01-01T00:00:00Z", "cursor=", "cursor=***", "cursor=x&cursor=y",
		"cursor=" + accesslog.Cursor{Off: 1}.String() + "&from=" + url.QueryEscape(ts(1))} {
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

	// Out of order, torn, malformed and unknown-key lines: file order, skipped.
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
	if got := times(do("GET", "/v1/log")); strings.Join(got, ",") != ts(7)+","+ts(6) {
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
	// A cursor of a log that is gone: 410 cursor_expired.
	gone := accesslog.Cursor{Gen: "0123456789abcdef0123456789abcdef", Off: 10}.String()
	if w := do("GET", "/v1/log?cursor="+gone); w.Code != http.StatusGone || strings.TrimSpace(w.Body.String()) != "cursor_expired" {
		t.Fatalf("expired cursor: %d %q", w.Code, w.Body)
	}
	if w := do("GET", "/v1/log"); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("X-Portcullis-Next") == "" ||
		w.Header().Get("X-Portcullis-Truncated") != "false" {
		t.Fatalf("missing log: %d %q %v", w.Code, w.Body, w.Header())
	}
}

// TestLogPortBounds: at most logMaxConns connections (a further one waits
// for a free slot), each cut off at its deadline however slowly it
// trickles; the read slot is held until the answer is written.
func TestLogPortBounds(t *testing.T) {
	old := logDeadline
	logDeadline = time.Second
	defer func() { logDeadline = old }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newLogServer(ln.Addr().String(), filepath.Join(t.TempDir(), "access.jsonl"))
	bl := newBoundedListener(ln, logMaxConns, func() time.Duration { return logDeadline })
	go func() { _ = srv.Serve(bl) }()
	defer srv.Close()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	// Four idle connections: a fifth request isn't answered until they
	// are cut off at their deadline.
	for i := 0; i < logMaxConns; i++ {
		dial()
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	c := dial()
	_, _ = c.Write([]byte("GET /v1/log HTTP/1.1\r\nHost: x\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	b := make([]byte, 64)
	n, _ := c.Read(b)
	if !strings.HasPrefix(string(b[:n]), "HTTP/1.1 200") {
		t.Fatalf("fifth: %q", b[:n])
	}
	if el := time.Since(start); el < 700*time.Millisecond {
		t.Fatalf("the fifth connection was served at once (%s): no cap", el)
	}
	// A trickling client is cut off at the deadline.
	tr := dial()
	start = time.Now()
	cut := false
	for _, ch := range []byte("GET /v1/log HTTP/1.1\r\nHost: x\r\nX-A: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		if _, err := tr.Write([]byte{ch}); err != nil {
			cut = true
			break
		}
		_ = tr.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := tr.Read(b); err != nil && !os.IsTimeout(err) {
			cut = true
			break
		}
	}
	if !cut || time.Since(start) > 5*time.Second {
		t.Fatalf("trickling client not cut off (cut %v after %s)", cut, time.Since(start))
	}
}

// TestLogSlotHeldUntilWritten: a second read waits while the first one's
// answer is still being written.
func TestLogSlotHeldUntilWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	_ = os.WriteFile(path, nil, 0o640)
	h := newLogHandler(path)
	release := make(chan struct{})
	first := &blockingWriter{ResponseRecorder: httptest.NewRecorder(), release: release, started: make(chan struct{})}
	go h.ServeHTTP(first, httptest.NewRequest("GET", "/v1/log", nil))
	<-first.started
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/log", nil))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the second read ran while the first answer was being written")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the second read never ran")
	}
}

type blockingWriter struct {
	*httptest.ResponseRecorder
	release, started chan struct{}
}

func (b *blockingWriter) WriteHeader(code int) {
	close(b.started)
	<-b.release
	b.ResponseRecorder.WriteHeader(code)
}
