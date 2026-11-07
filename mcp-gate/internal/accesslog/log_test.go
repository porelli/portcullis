package accesslog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}
func (c *clock) add(d time.Duration) { c.set(c.now().Add(d)) }

func open(t *testing.T, o Options) (*Log, string, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 11, 5, 10, 16, 2, 0, time.UTC)}
	if o.Now == nil {
		o.Now = c.now
	}
	if o.Group == 0 {
		o.Group = os.Getgid()
	}
	path := filepath.Join(t.TempDir(), "data", "access.jsonl")
	l, err := OpenWith(path, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path, c
}

func flush(t *testing.T, l *Log) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not a JSON line: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

var full = Line{
	Time: time.Date(2026, 11, 5, 10, 16, 2, 0, time.UTC), User: "alice", Client: "portcullis-ai-claude",
	Resource: "https://gitea.example.com/mcp", Instance: "gitea", Companion: "gitea", Via: "direct",
	Method: "tools/call", Tool: "list_issues", ArgsSHA256: strings.Repeat("ab", 32), Decision: "allow",
	UpstreamStatus: 200, DurationMS: 184,
}

// TestAccessLogLine: every §15.8 key, in the contract's order, exactly.
func TestAccessLogLine(t *testing.T) {
	l, path, _ := open(t, Options{})
	if err := l.Write(full); err != nil {
		t.Fatal(err)
	}
	// Every key is present even when empty.
	if err := l.Write(Line{Time: full.Time, Method: "initialize", Decision: "deny:token"}); err != nil {
		t.Fatal(err)
	}
	flush(t, l)
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	want := `{"time":"2026-11-05T10:16:02Z","user":"alice","client":"portcullis-ai-claude","resource":"https://gitea.example.com/mcp","instance":"gitea","companion":"gitea","via":"direct","method":"tools/call","tool":"list_issues","args_sha256":"` + strings.Repeat("ab", 32) + `","decision":"allow","upstream_status":200,"duration_ms":184}`
	if len(lines) != 2 || lines[0] != want {
		t.Fatalf("got\n%s\nwant\n%s", b, want)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(lines[1]), &m)
	keys := []string{"time", "user", "client", "resource", "instance", "companion", "via", "method", "tool", "args_sha256", "decision", "upstream_status", "duration_ms"}
	if len(m) != len(keys) {
		t.Errorf("keys %v", m)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("key %s missing", k)
		}
	}
	// Parse round-trips.
	got, err := ParseLine([]byte(lines[0]))
	if err != nil || !reflect.DeepEqual(got, full) {
		t.Errorf("ParseLine: %+v %v", got, err)
	}
}

// G29: the file is 0640 with group 10001; the directory 0750.
func TestFileMode(t *testing.T) {
	var gids []int
	old := chown
	chown = func(path string, gid int) error { gids = append(gids, gid); return nil }
	defer func() { chown = old }()
	dir := filepath.Join(t.TempDir(), "d")
	path := filepath.Join(dir, "access.jsonl")
	old2 := syscall.Umask(0o077)
	defer syscall.Umask(old2)
	l, err := Open(path, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("file mode %v %v", fi.Mode().Perm(), err)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o750 {
		t.Errorf("dir mode %v", di.Mode().Perm())
	}
	if len(gids) < 2 || gids[0] != 10001 || gids[1] != 10001 {
		t.Errorf("chown groups %v, want 10001 for the directory and the file", gids)
	}
	// An existing file with a wider mode is narrowed at open.
	l.Close()
	_ = os.Chmod(path, 0o666)
	l2, err := Open(path, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("reopened mode %v", fi.Mode().Perm())
	}
	// A chown failure is an error: the log must be readable by the Hub.
	chown = func(string, int) error { return errors.New("EPERM") }
	if _, err := Open(filepath.Join(t.TempDir(), "x.jsonl"), time.Hour); err == nil {
		t.Error("open succeeded without the group")
	}
}

// Redact, then clip: no secret survives in any field, and long values
// are clipped on a rune boundary.
func TestRedactThenClip(t *testing.T) {
	const cred = "s3cr3t-credential-XYZ"
	l, path, _ := open(t, Options{Secrets: func() []string { return []string{cred, ""} }})
	long := strings.Repeat("é", 300) + cred
	_ = l.Write(Line{Time: full.Time, Tool: "x" + cred + "y", Method: cred, Client: long, Decision: "allow"})
	// A secret straddling the clip boundary must not leave a prefix that
	// was cut out of a redacted value: redaction runs first.
	_ = l.Write(Line{Time: full.Time, Tool: strings.Repeat("a", maxField-12) + cred, Decision: "allow"})
	flush(t, l)
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), cred) || strings.Contains(string(b), cred[:10]) {
		t.Fatalf("secret in the log: %s", b)
	}
	for _, m := range readLines(t, path) {
		for k, v := range m {
			if s, ok := v.(string); ok && len(s) > maxField {
				t.Errorf("%s: %d bytes", k, len(s))
			}
		}
	}
	if !strings.Contains(string(b), `"tool":"x[redacted]y"`) {
		t.Errorf("redaction marker missing: %s", b)
	}
}

// Lines older than the retention are removed by an atomic rewrite with
// the same mode; a torn last line is dropped; writing continues.
func TestPrune(t *testing.T) {
	l, path, c := open(t, Options{Retention: 90 * 24 * time.Hour})
	base := c.now()
	for i, age := range []int{120, 91, 89, 1} {
		ln := full
		ln.Time = base.Add(-time.Duration(age) * 24 * time.Hour)
		ln.DurationMS = int64(i)
		_ = l.Write(ln)
	}
	flush(t, l)
	// A torn line in the middle (a crash mid-write) and at the end.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.WriteString(`{"time":"2026-11-0` + "\n")
	_ = f.Close()
	ln := full
	_ = l.Write(ln)
	flush(t, l)
	f, _ = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	_, _ = f.WriteString(`{"time":"2026-11-05T10:1`)
	_ = f.Close()
	before, _ := os.Stat(path)
	if err := l.Prune(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Mode().Perm() != 0o640 {
		t.Fatalf("mode after prune %v %v", after.Mode().Perm(), err)
	}
	if os.SameFile(before, after) {
		t.Error("not rewritten (same inode)")
	}
	got := readLines(t, path)
	if len(got) != 3 || got[0]["duration_ms"].(float64) != 2 || got[1]["duration_ms"].(float64) != 3 {
		t.Fatalf("after prune: %v", got)
	}
	// Writes go to the new file.
	ln.Decision = "rate_limited"
	_ = l.Write(ln)
	flush(t, l)
	got = readLines(t, path)
	if len(got) != 4 || got[3]["decision"] != "rate_limited" {
		t.Errorf("after prune + write: %v", got)
	}
	// Nothing old: no rewrite.
	before, _ = os.Stat(path)
	_ = l.Prune()
	after, _ = os.Stat(path)
	if !os.SameFile(before, after) {
		t.Error("rewritten with nothing to prune")
	}
	// No temp files left.
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Errorf("dir entries %v", ents)
	}
}

// G28: a writer failing for more than 30 s makes the log unhealthy; a
// success makes it healthy again; the failed line is retried, not lost.
func TestUnhealthyAfterFailing(t *testing.T) {
	l, path, c := open(t, Options{})
	var fail atomic.Bool
	l.writeHook = func() error {
		if fail.Load() {
			return errors.New("ENOSPC")
		}
		return nil
	}
	if !l.Healthy() {
		t.Fatal("unhealthy at start")
	}
	fail.Store(true)
	_ = l.Write(full)
	waitFor(t, func() bool { return l.Errors() > 0 })
	if !l.Healthy() {
		t.Error("unhealthy before 30 s")
	}
	c.add(31 * time.Second)
	if l.Healthy() {
		t.Error("healthy after failing for 31 s")
	}
	fail.Store(false)
	waitFor(t, func() bool { return l.Healthy() })
	flush(t, l)
	if got := readLines(t, path); len(got) != 1 {
		t.Errorf("the failed line was lost: %v", got)
	}
}

// G28: a full queue makes the log unhealthy, and Write never blocks a
// request for more than about 50 ms.
func TestQueueFull(t *testing.T) {
	l, _, _ := open(t, Options{QueueSize: 4})
	release := make(chan struct{})
	l.writeHook = func() error { <-release; return nil }
	defer close(release)
	var err error
	for i := 0; i < 10 && err == nil; i++ {
		err = l.Write(full)
	}
	start := time.Now()
	if err == nil {
		err = l.Write(full)
	}
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("write to a full queue: %v", err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("Write blocked %v", d)
	}
	if l.Healthy() {
		t.Error("healthy with a full queue")
	}
	if l.Dropped() == 0 {
		t.Error("drop not counted")
	}
}

// Low-priority lines (refusals without a valid token) never take the
// last half of the queue, so they can't make tools/call unloggable.
func TestLowPriorityKeepsRoom(t *testing.T) {
	l, _, _ := open(t, Options{QueueSize: 8})
	release := make(chan struct{})
	l.writeHook = func() error { <-release; return nil }
	defer close(release)
	for i := 0; i < 100; i++ {
		_ = l.WriteLow(full)
	}
	if !l.Healthy() {
		t.Error("low-priority lines filled the queue")
	}
	if err := l.Write(full); err != nil {
		t.Errorf("a normal line has no room: %v", err)
	}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition never met")
}

// §15.8: confirmation_id is the one optional key — last, present only
// when set, and parsed back.
func TestConfirmationIDKey(t *testing.T) {
	l, path, _ := open(t, Options{})
	with := full
	with.ConfirmationID = "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"
	if err := l.Write(with); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(full); err != nil {
		t.Fatal(err)
	}
	flush(t, l)
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], `"duration_ms":184,"confirmation_id":"ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ"}`) {
		t.Fatalf("with: %s", b)
	}
	if strings.Contains(lines[1], "confirmation_id") {
		t.Errorf("without: %s", lines[1])
	}
	got, err := ParseLine([]byte(lines[0]))
	if err != nil || !reflect.DeepEqual(got, with) {
		t.Errorf("ParseLine: %+v %v", got, err)
	}
}

// G28 (final review I2): a reserved line is never dropped. With the
// writer stalled and the queue then filled by normal lines (list
// fan-outs, other people's calls), every reserved line still lands;
// with no slot left, Reserve refuses.
func TestReservationNeverDropped(t *testing.T) {
	l, path, _ := open(t, Options{QueueSize: 8})
	release := make(chan struct{})
	l.writeHook = func() error { <-release; return nil }
	_ = l.Write(full) // the writer takes it and stalls
	waitFor(t, func() bool { return l.writingSince.Load() != 0 })
	var res []*Reservation
	for i := 0; i < 3; i++ {
		r, err := l.Reserve()
		if err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
		res = append(res, r)
	}
	for l.Write(full) == nil {
	}
	if _, err := l.Reserve(); !errors.Is(err, ErrQueueFull) {
		t.Errorf("reserve with no slot: %v", err)
	}
	call := full
	call.Method, call.Tool = "tools/call", "delete_repo"
	for _, r := range res {
		if err := r.Write(call); err != nil {
			t.Fatalf("reserved write: %v", err)
		}
	}
	close(release)
	flush(t, l)
	n := 0
	for _, ln := range readLines(t, path) {
		if ln["tool"] == "delete_repo" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d of 3 reserved lines written", n)
	}
	// Release gives an unused slot back; a used one is not given twice.
	r, err := l.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	before := len(l.slots)
	r.Release()
	r.Release()
	if len(l.slots) != before-1 {
		t.Errorf("slots %d → %d", before, len(l.slots))
	}
}

// G28 (I2): no reservation while the writer is failing at all (not only
// after 30 s) or stuck on one write for stallAfter.
func TestReserveRefusedWhileWriterFailsOrStalls(t *testing.T) {
	l, _, c := open(t, Options{})
	var fail atomic.Bool
	block := make(chan struct{})
	var blocking atomic.Bool
	l.writeHook = func() error {
		if blocking.Load() {
			<-block
		}
		if fail.Load() {
			return errors.New("ENOSPC")
		}
		return nil
	}
	if r, err := l.Reserve(); err != nil {
		t.Fatalf("healthy log: %v", err)
	} else {
		r.Release()
	}
	fail.Store(true)
	_ = l.Write(full)
	waitFor(t, func() bool { return l.Errors() > 0 })
	if _, err := l.Reserve(); !errors.Is(err, ErrUnloggable) {
		t.Errorf("failing writer: %v", err)
	}
	fail.Store(false)
	waitFor(t, func() bool { return l.failingSince.Load() == 0 })
	blocking.Store(true)
	_ = l.Write(full)
	waitFor(t, func() bool { return l.writingSince.Load() != 0 })
	if r, err := l.Reserve(); err != nil {
		t.Errorf("writer busy for 0 s: %v", err)
	} else {
		r.Release()
	}
	c.add(stallAfter)
	if _, err := l.Reserve(); !errors.Is(err, ErrUnloggable) {
		t.Errorf("writer stuck for %v: %v", stallAfter, err)
	}
	blocking.Store(false)
	close(block)
}
