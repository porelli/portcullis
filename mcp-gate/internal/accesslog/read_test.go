package accesslog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func testLine(t time.Time, res string) []byte {
	b, _ := json.Marshal(wire{Time: t.UTC().Format(time.RFC3339), Resource: res, Via: "direct", Method: "m", Decision: "allow"})
	return append(b, '\n')
}

type countingReaderAt struct {
	r io.ReaderAt
	n atomic.Int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n.Add(int64(n))
	return n, err
}

// TestSeekTimeIsLogarithmic: the start of a from page is found by a
// binary search (a few searchWindows read, not the file), right also
// with many lines per second and a few seconds' skew.
func TestSeekTimeIsLogarithmic(t *testing.T) {
	base := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	var starts []int64
	var times []time.Time
	for i := 0; i < 60000; i++ {
		ts := base.Add(time.Duration(i/20) * time.Second) // 20 lines per second
		if i%97 == 5 {
			ts = ts.Add(-2 * time.Second) // skew
		}
		starts = append(starts, int64(b.Len()))
		times = append(times, ts)
		b.Write(testLine(ts, fmt.Sprintf("https://r%d.example.com/mcp", i)))
	}
	data := b.Bytes()
	for _, sec := range []int{0, 1, 777, 1500, 2999, 3000} {
		key := base.Add(time.Duration(sec) * time.Second)
		cr := &countingReaderAt{r: bytes.NewReader(data)}
		got, err := seekTime(cr, int64(len(data)), key)
		if err != nil {
			t.Fatal(err)
		}
		// The first line at or after key, skipping skewed earlier ones.
		want := int64(len(data))
		for i, st := range starts {
			if !times[i].Before(key) && (i%97 != 5) {
				want = st
				break
			}
		}
		if sec*20 < len(starts) && got > want {
			t.Errorf("second %d: offset %d, want ≤ %d", sec, got, want)
		}
		if got < want {
			// Only a skewed line (time ≥ key) may come first.
			ln, _ := ParseLine(bytes.TrimSuffix(data[got:got+int64(bytes.IndexByte(data[got:], '\n'))+1], []byte("\n")))
			if ln.Time.Before(key) {
				t.Errorf("second %d: starts at a line of %s", sec, ln.Time)
			}
		}
		if n := cr.n.Load(); n > 40*searchWindow {
			t.Errorf("second %d: read %d bytes of %d", sec, n, len(data))
		}
	}
}

// TestReadPagesAndCursor: every line once through the cursor with many
// lines in one second; truncated until the last page; a cut at maxBytes;
// a cursor of a rewritten file (prune) restarts at its time.
func TestReadPagesAndCursor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.jsonl")
	base := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	for i := 0; i < 2500; i++ {
		b.Write(testLine(base, fmt.Sprintf("r%d", i)))
	}
	b.Write(testLine(base.Add(time.Second), "last"))
	if err := os.WriteFile(path, b.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeGen(path, -1); err != nil {
		t.Fatal(err)
	}
	page := func(cur *Cursor, from time.Time, limit, max int) Page {
		t.Helper()
		pg, err := Read(path, cur, from, limit, max)
		if err != nil {
			t.Fatal(err)
		}
		return pg
	}
	all := func(first Page, limit, max int) ([]byte, []bool) {
		out, flags := append([]byte(nil), first.Body...), []bool{first.Truncated}
		pg := first
		for pg.Truncated {
			c := pg.Next
			pg = page(&c, time.Time{}, limit, max)
			out = append(out, pg.Body...)
			flags = append(flags, pg.Truncated)
		}
		return out, flags
	}
	got, flags := all(page(nil, time.Time{}, 1000, 4<<20), 1000, 4<<20)
	if !bytes.Equal(got, b.Bytes()) || fmt.Sprint(flags) != "[true true false]" {
		t.Fatalf("paging by limit: %d bytes of %d, %v", len(got), b.Len(), flags)
	}
	got, flags = all(page(nil, base, 999, 4<<20), 999, 4<<20)
	if !bytes.Equal(got, b.Bytes()) || fmt.Sprint(flags) != "[true true false]" {
		t.Fatalf("paging from: %d bytes, %v", len(got), flags)
	}
	// The byte cut: whole lines, truncated, continued.
	ll := len(testLine(base, "r0"))
	got, flags = all(page(nil, time.Time{}, 10000, 10*ll+5), 10000, 10*ll+5)
	if !bytes.Equal(got, b.Bytes()) || flags[0] != true || flags[len(flags)-1] != false {
		t.Fatalf("paging by bytes: %d bytes, %d pages", len(got), len(flags))
	}
	if pg := page(nil, time.Time{}, 10000, 10*ll+5); len(pg.Body) != 10*ll {
		t.Fatalf("byte cut: %d bytes", len(pg.Body))
	}
	// Exactly limit lines left: not truncated; the end: the same position.
	end := page(nil, base.Add(time.Second), 1, 4<<20)
	if string(bytes.TrimSpace(end.Body)) != string(bytes.TrimSpace(testLine(base.Add(time.Second), "last"))) || end.Truncated {
		t.Fatalf("last line: %q %v", end.Body, end.Truncated)
	}
	if again := page(&end.Next, time.Time{}, 10, 4<<20); len(again.Body) != 0 || again.Next != end.Next || again.Truncated {
		t.Fatalf("at the end: %+v", again)
	}
	// A cursor mid-line: expired.
	bad := page(nil, time.Time{}, 1, 4<<20).Next
	bad.Off -= 3
	if _, err := Read(path, &bad, time.Time{}, 1, 4<<20); err != ErrCursorExpired {
		t.Fatalf("mid-line cursor: %v", err)
	}
}

// TestCursorExpiresOnEveryRewrite: the generation token changes at every
// rewrite — by rename (Prune) and in place on the same inode (what inode
// reuse looks like) — and a cursor of an older generation is expired even
// where its offset would still fall on a line start.
func TestCursorExpiresOnEveryRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.jsonl")
	base := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	for i := 0; i < 10; i++ {
		b.Write(testLine(base, "r")) // equal lengths: every old offset is a line start
	}
	_ = os.WriteFile(path, b.Bytes(), 0o640)
	if err := writeGen(path, -1); err != nil {
		t.Fatal(err)
	}
	read := func(cur *Cursor) (Page, error) { return Read(path, cur, time.Time{}, 3, 4<<20) }
	pg, err := read(nil)
	if err != nil {
		t.Fatal(err)
	}
	c1 := pg.Next
	if _, err := read(&c1); err != nil {
		t.Fatalf("the same generation: %v", err)
	}
	// Rewrite 1: a new file renamed over it (Prune's way).
	tmp := path + ".new"
	_ = os.WriteFile(tmp, b.Bytes(), 0o640)
	_ = os.Rename(tmp, path)
	if _, err := read(&c1); err != ErrGenUnknown {
		t.Fatalf("before the generation is written: %v (want unknown: 503)", err)
	}
	_ = writeGen(path, -1)
	if _, err := read(&c1); err != ErrCursorExpired {
		t.Fatalf("after rewrite 1: %v", err)
	}
	pg, _ = read(nil)
	c2 := pg.Next
	// Rewrite 2: in place, the same inode.
	_ = os.WriteFile(path, b.Bytes(), 0o640)
	_ = writeGen(path, -1)
	for _, c := range []Cursor{c1, c2} {
		if _, err := read(&c); err != ErrCursorExpired {
			t.Fatalf("after rewrite 2, cursor %+v: %v", c, err)
		}
	}
	if pg, err := read(nil); err != nil || pg.Next.Gen == c2.Gen || pg.Next.Gen == c1.Gen {
		t.Fatalf("a fresh start: %+v %v", pg.Next, err)
	}
}

// TestPruneRenewsTheGeneration: the Log keeps the generation file (with
// Generation on): created with the log, renewed by a Prune that
// rewrites, untouched by one that doesn't, absent with Generation off.
func TestPruneRenewsTheGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.jsonl")
	now := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	l, err := OpenWith(path, Options{Group: -1, Generation: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	g0, err := ReadGen(path)
	if err != nil {
		t.Fatalf("no generation at creation: %v", err)
	}
	_ = l.Write(Line{Time: now.Add(-100 * 24 * time.Hour), Resource: "old"})
	_ = l.Write(Line{Time: now, Resource: "new"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = l.Flush(ctx)
	pg, _ := Read(path, nil, time.Time{}, 1, 4<<20)
	if pg.Next.Gen != g0 {
		t.Fatalf("cursor generation %q, want %q", pg.Next.Gen, g0)
	}
	if err := l.Prune(); err != nil {
		t.Fatal(err)
	}
	g1, _ := ReadGen(path)
	if g1 == "" || g1 == g0 {
		t.Fatalf("the rewrite kept the generation (%q → %q)", g0, g1)
	}
	if _, err := Read(path, &pg.Next, time.Time{}, 1, 4<<20); err != ErrCursorExpired {
		t.Fatalf("a cursor from before the prune: %v", err)
	}
	if err := l.Prune(); err != nil { // nothing to remove: no rewrite
		t.Fatal(err)
	}
	if g2, _ := ReadGen(path); g2 != g1 {
		t.Fatalf("a prune without a rewrite renewed the generation")
	}
	_ = l.Close()
	off := filepath.Join(t.TempDir(), "access.jsonl")
	l2, err := OpenWith(off, Options{Group: -1})
	if err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	if _, err := os.Stat(GenPath(off)); !os.IsNotExist(err) {
		t.Fatalf("a generation file with Generation off: %v", err)
	}
}

func TestParseCursor(t *testing.T) {
	c := Cursor{Gen: "0123456789abcdef0123456789abcdef", Off: 1234, Time: 1790000000}
	for _, ok := range []Cursor{c, {Off: 0}} {
		if got, err := ParseCursor(ok.String()); err != nil || got != ok {
			t.Fatalf("round trip %+v: %+v %v", ok, got, err)
		}
	}
	enc := func(s string) string { return base64RawURL(s) }
	for _, s := range []string{"", "***", c.String() + "A", c.String() + "=", enc("mg2|" + c.Gen + "|1234"),
		enc("mg1|" + c.Gen + "|1|5"), enc("mg2|42|1|5"), enc("mg2|" + c.Gen + "|-1|5"), enc("mg2|" + c.Gen + "|01|5"),
		enc("mg2|ABCDEF0123456789ABCDEF0123456789|1|5"), enc("mg2|" + c.Gen + "|1|999999999999")} {
		if _, err := ParseCursor(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func base64RawURL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
