package accesslog

import (
	"bytes"
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
	// Rewritten (a new inode, as prune does): restart at the cursor's time.
	mid := page(nil, time.Time{}, 1, 4<<20).Next
	tmp := path + ".new"
	_ = os.WriteFile(tmp, append(testLine(base.Add(-time.Hour), "old"), b.Bytes()...), 0o640)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	pg := page(&mid, time.Time{}, 1, 4<<20)
	if ln, err := ParseLine(bytes.TrimSuffix(pg.Body, []byte("\n"))); err != nil || ln.Time != base {
		t.Fatalf("rewritten file: %q", pg.Body)
	}
	// A cursor mid-line (same inode): restart at its time too.
	bad := pg.Next
	bad.Off -= 3
	if pg := page(&bad, time.Time{}, 1, 4<<20); len(pg.Body) == 0 {
		t.Fatal("mid-line cursor: nothing")
	}
}

func TestParseCursor(t *testing.T) {
	c := Cursor{Ino: 42, Off: 1234, Time: 1790000000}
	if got, err := ParseCursor(c.String()); err != nil || got != c {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	enc := func(s string) string { return base64RawURL(s) }
	for _, s := range []string{"", "***", c.String() + "A", c.String() + "=", enc("mg1|42|1234"), enc("gg1|42|1234|5"),
		enc("mg1|42|-1|5"), enc("mg1|42|01|5"), enc("mg1|x|1|5"), enc("mg1|42|1|999999999999")} {
		if _, err := ParseCursor(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func base64RawURL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
