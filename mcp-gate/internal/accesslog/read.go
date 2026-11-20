package accesslog

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"syscall"
	"time"
)

// maxLine bounds one line on read: a line is at most 13 fields of
// maxField bytes, JSON-escaped (×6), plus its keys. Longer is not a line
// the gate wrote: skipped.
const maxLine = 64 << 10

// Read is the log port's answer (contract §20.10): the lines of the log at
// path whose time is not before from (the zero time: all), oldest first,
// at most limit lines and maxBytes bytes, each exactly as it is on disk.
// Only complete lines that ParseLine accepts are served (a torn or
// malformed line is skipped), so nothing is served that the gate didn't
// write. Lines are appended in time order, so the file is read once from
// its start and the answer is sorted by time (stable) before it is cut. A
// missing log is an empty answer; a log that isn't a regular file (a
// symlink included: never followed) is an error.
func Read(path string, from time.Time, limit, maxBytes int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("access log: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("access log: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("access log: not a regular file")
	}
	type kept struct {
		t   time.Time
		raw []byte
	}
	var out []kept
	size := 0
	r := bufio.NewReaderSize(io.LimitReader(f, st.Size()), maxLine)
	for len(out) < limit {
		raw, err := readLine(r)
		if err == io.EOF {
			break // a final line without '\n' is torn: never served
		}
		if err != nil {
			return nil, fmt.Errorf("access log: %w", err)
		}
		if raw == nil {
			continue // too long
		}
		ln, perr := ParseLine(raw)
		if perr != nil || ln.Time.Before(from) {
			continue
		}
		if size+len(raw)+1 > maxBytes {
			break
		}
		out = append(out, kept{ln.Time, append(raw[:len(raw):len(raw)], '\n')})
		size += len(raw) + 1
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].t.Before(out[j].t) })
	var b bytes.Buffer
	b.Grow(size)
	for _, k := range out {
		b.Write(k.raw)
	}
	return b.Bytes(), nil
}

// readLine reads one '\n'-terminated line (without it, copied). A line
// longer than the reader's buffer is consumed and returned as nil; a final
// line without '\n' is io.EOF.
func readLine(r *bufio.Reader) ([]byte, error) {
	long := false
	for {
		b, err := r.ReadSlice('\n')
		switch {
		case err == nil:
			if long {
				return nil, nil
			}
			return bytes.Clone(b[:len(b)-1]), nil
		case errors.Is(err, bufio.ErrBufferFull):
			long = true
		default:
			return nil, err
		}
	}
}
