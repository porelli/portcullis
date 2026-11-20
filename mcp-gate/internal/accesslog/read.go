package accesslog

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxLine bounds one line on read: a line is at most 13 fields of
// maxField bytes, JSON-escaped (×6), plus its keys. Longer is not a line
// the gate wrote: skipped.
const maxLine = 64 << 10

// searchWindow: the binary search for a time stops once its range is this
// small, then scans it.
const searchWindow = 64 << 10

// Cursor is a position in the log (contract §20.10): right after the last
// line served (exclusive). Ino is the file's inode (prune rewrites the
// file: a cursor of another inode no longer holds), Off the byte offset,
// Time the last line's time (unix seconds), where a cursor that no longer
// holds restarts.
type Cursor struct {
	Ino  uint64
	Off  int64
	Time int64
}

const cursorTag = "mg1"

// String is the opaque form (X-Portcullis-Next).
func (c Cursor) String() string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%d|%d|%d", cursorTag, c.Ino, c.Off, c.Time)))
}

// ParseCursor reads String's form strictly.
func ParseCursor(s string) (Cursor, error) {
	bad := errors.New("malformed cursor")
	if s == "" || len(s) > 128 {
		return Cursor{}, bad
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return Cursor{}, bad
	}
	p := strings.Split(string(b), "|")
	if len(p) != 4 || p[0] != cursorTag {
		return Cursor{}, bad
	}
	ino, e1 := strconv.ParseUint(p[1], 10, 64)
	off, e2 := strconv.ParseInt(p[2], 10, 64)
	t, e3 := strconv.ParseInt(p[3], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || off < 0 || t < 0 || t > 253402300799 {
		return Cursor{}, bad
	}
	c := Cursor{Ino: ino, Off: off, Time: t}
	if c.String() != s {
		return Cursor{}, bad // only the canonical form
	}
	return c, nil
}

// Page is one log port answer.
type Page struct {
	Body      []byte
	Next      Cursor
	Truncated bool // a cut stopped it while another line was there
}

// Read is the log port's answer (contract §20.10). It starts at cur
// (exclusive; one that no longer holds restarts at its time), else at the
// first line whose time is at or after from (found by a binary search on
// the lines' time prefixes: lines are appended in time order up to a few
// seconds' skew; the zero time = the start). Lines in file order, each
// exactly as it is on disk, only complete lines that ParseLine accepts
// (nothing is served that the gate didn't write), at most limit lines and
// maxBytes bytes. A missing log is an empty page; a log that isn't a
// regular file (a symlink included: never followed) is an error.
func Read(path string, cur *Cursor, from time.Time, limit, maxBytes int) (Page, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		pg := Page{}
		if cur != nil {
			pg.Next = *cur
		} else if !from.IsZero() {
			pg.Next.Time = from.Unix()
		}
		return pg, nil
	}
	if err != nil {
		return Page{}, fmt.Errorf("access log: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Page{}, fmt.Errorf("access log: %w", err)
	}
	if !st.Mode().IsRegular() {
		return Page{}, errors.New("access log: not a regular file")
	}
	var ino uint64
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = uint64(sys.Ino)
	}
	size := st.Size()
	var start int64
	var t int64
	switch {
	case cur != nil:
		t = cur.Time
		if cur.Ino == ino && holds(f, cur.Off, size) {
			start = cur.Off
		} else if start, err = seekTime(f, size, time.Unix(cur.Time, 0)); err != nil {
			return Page{}, err
		}
	case !from.IsZero():
		if from.Nanosecond() != 0 {
			from = from.Truncate(time.Second).Add(time.Second)
		}
		t = from.Unix()
		if start, err = seekTime(f, size, from); err != nil {
			return Page{}, err
		}
	}
	pg := Page{Next: Cursor{Ino: ino, Off: start, Time: t}}
	var b bytes.Buffer
	n := 0
	pos := start
	r := bufio.NewReaderSize(io.NewSectionReader(f, start, size-start), maxLine)
	for {
		raw, used, err := readLine(r)
		if err == io.EOF {
			break // a final line without '\n' is torn: never served
		}
		if err != nil {
			return Page{}, fmt.Errorf("access log: %w", err)
		}
		pos += used
		ln, perr := ParseLine(raw)
		if raw == nil || perr != nil {
			pg.Next.Off = pos
			continue
		}
		if n >= limit || b.Len()+len(raw)+1 > maxBytes {
			pg.Truncated = true
			break
		}
		b.Write(raw)
		b.WriteByte('\n')
		n++
		pg.Next = Cursor{Ino: ino, Off: pos, Time: ln.Time.Unix()}
	}
	pg.Body = b.Bytes()
	return pg, nil
}

// holds: off is inside the file and right after a newline (or 0).
func holds(f io.ReaderAt, off, size int64) bool {
	if off == 0 {
		return true
	}
	if off > size {
		return false
	}
	var one [1]byte
	n, err := f.ReadAt(one[:], off-1)
	return n == 1 && err == nil && one[0] == '\n'
}

// timePrefix: a line's time from its `{"time":"<RFC 3339 UTC>"` prefix
// (encode writes it first), without decoding the line.
func timePrefix(line []byte) (string, bool) {
	const head = `{"time":"`
	const n = len(head) + len("2006-01-02T15:04:05Z")
	if len(line) < n+1 || !bytes.HasPrefix(line, []byte(head)) || line[n] != '"' || line[n-1] != 'Z' {
		return "", false
	}
	return string(line[len(head):n]), true
}

// lineAfter: the first line starting after off-1 that has a time prefix,
// looking at most searchWindow bytes on: (its start, its time).
func lineAfter(f io.ReaderAt, off, size int64) (int64, string, bool) {
	r := bufio.NewReaderSize(io.NewSectionReader(f, off, min(size-off, 2*searchWindow+maxLine)), maxLine)
	pos := off
	if off > 0 {
		// The line under off-1 is cut: skip to the next newline.
		var one [1]byte
		if n, _ := f.ReadAt(one[:], off-1); n != 1 || one[0] != '\n' {
			_, used, err := readLine(r)
			if err != nil {
				return 0, "", false
			}
			pos += used
		}
	}
	for pos-off <= searchWindow {
		raw, used, err := readLine(r)
		if err != nil {
			return 0, "", false
		}
		if ts, ok := timePrefix(raw); ok {
			return pos, ts, true
		}
		pos += used
	}
	return 0, "", false
}

// seekTime: the offset of the first line whose time is at or after t (a
// binary search down to searchWindow, then a scan; both compare the
// lines' time prefixes), else the end of the complete lines.
func seekTime(f io.ReaderAt, size int64, t time.Time) (int64, error) {
	key := t.UTC().Format(time.RFC3339)
	lo, hi := int64(0), size // lo: a line start; the answer is in [lo, hi]
	for hi-lo > searchWindow {
		mid := lo + (hi-lo)/2
		p, ts, ok := lineAfter(f, mid, size)
		if !ok || p >= hi {
			hi = mid
			continue
		}
		if ts >= key {
			hi = p
		} else {
			lo = p
		}
	}
	r := bufio.NewReaderSize(io.NewSectionReader(f, lo, size-lo), maxLine)
	pos := lo
	for {
		raw, used, err := readLine(r)
		if err == io.EOF {
			return pos, nil
		}
		if err != nil {
			return 0, fmt.Errorf("access log: %w", err)
		}
		if ts, ok := timePrefix(raw); ok && ts >= key {
			return pos, nil
		}
		pos += used
	}
}

// readLine reads one '\n'-terminated line (without it, copied) and the
// bytes it used. A line longer than the reader's buffer is consumed and
// returned as nil; a final line without '\n' is io.EOF.
func readLine(r *bufio.Reader) ([]byte, int64, error) {
	long := false
	var used int64
	for {
		b, err := r.ReadSlice('\n')
		used += int64(len(b))
		switch {
		case err == nil:
			if long {
				return nil, used, nil
			}
			return bytes.Clone(b[:len(b)-1]), used, nil
		case errors.Is(err, bufio.ErrBufferFull):
			long = true
		default:
			return nil, used, err
		}
	}
}
