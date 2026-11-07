// Package accesslog is the gate's access log (integration contract §15.8):
// one JSON line per MCP request in mcp_gate_data/access.jsonl, 0640 with
// group 10001 so the Hub can read it through its read-only mount (G29),
// lines older than the retention (90 days) pruned by an atomic rewrite.
//
// Write never blocks a request for more than 50 ms: lines go through a
// queue to one writer goroutine, which retries a failed line until it is
// written. Healthy reports false while the writer has been failing for
// more than 30 s or the queue is full. A tools/call is admitted only with
// a Reservation (G28, final review I2): a queue slot taken before the
// call is forwarded, refused while the writer is failing or stuck on one
// write, so the line of an admitted call can never be dropped. Every string field is redacted (the gate's known secrets), then
// clipped. A line never carries arguments, results, tokens or credentials:
// callers pass only the §15.8 fields.
package accesslog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

// Defaults (G28, G29, §15.8).
const (
	DefaultRetention = 90 * 24 * time.Hour
	DefaultGroup     = 10001
	DefaultQueue     = 4096
	DefaultFailAfter = 30 * time.Second
	writeWait        = 50 * time.Millisecond
	fileMode         = 0o640
	dirMode          = 0o750
	// maxField bounds every string field (bytes, after redaction).
	maxField = 512
	redacted = "[redacted]"
	// lowPerSecond bounds lines of refused requests without a valid token.
	lowPerSecond = 50
	// stallAfter: a writer stuck this long on one line refuses new
	// reservations (a hung disk would otherwise pile admitted calls'
	// lines up in memory).
	stallAfter = 5 * time.Second
)

// ErrQueueFull: the line was dropped (counted); the log is unhealthy.
var ErrQueueFull = errors.New("access log queue full")

// ErrUnloggable: no reservation, the writer is failing or stuck.
var ErrUnloggable = errors.New("access log writer failing")

// ErrClosed: the log is closed.
var ErrClosed = errors.New("access log closed")

// Line is one access-log line (§15.8). Every key is always written.
type Line struct {
	Time                                                                       time.Time
	User, Client, Resource, Instance, Companion, Via, Method, Tool, ArgsSHA256 string
	Decision                                                                   string
	UpstreamStatus                                                             int
	DurationMS                                                                 int64
	// ConfirmationID (§15.8, optional): on a tools/call that consumed a
	// confirmation, or continued after one, its id; "" = the key is absent.
	ConfirmationID string
}

// wire is the JSON form, in the contract's key order.
type wire struct {
	Time           string `json:"time"`
	User           string `json:"user"`
	Client         string `json:"client"`
	Resource       string `json:"resource"`
	Instance       string `json:"instance"`
	Companion      string `json:"companion"`
	Via            string `json:"via"`
	Method         string `json:"method"`
	Tool           string `json:"tool"`
	ArgsSHA256     string `json:"args_sha256"`
	Decision       string `json:"decision"`
	UpstreamStatus int    `json:"upstream_status"`
	DurationMS     int64  `json:"duration_ms"`
	ConfirmationID string `json:"confirmation_id,omitempty"`
}

// ParseLine decodes one line strictly (every key, no other).
func ParseLine(b []byte) (Line, error) {
	var w wire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return Line{}, err
	}
	if dec.More() {
		return Line{}, errors.New("trailing data")
	}
	t, err := time.Parse(time.RFC3339, w.Time)
	if err != nil {
		return Line{}, err
	}
	return Line{
		Time: t.UTC(), User: w.User, Client: w.Client, Resource: w.Resource, Instance: w.Instance,
		Companion: w.Companion, Via: w.Via, Method: w.Method, Tool: w.Tool, ArgsSHA256: w.ArgsSHA256,
		Decision: w.Decision, UpstreamStatus: w.UpstreamStatus, DurationMS: w.DurationMS, ConfirmationID: w.ConfirmationID,
	}, nil
}

// Options configure a Log; zero values are the defaults.
type Options struct {
	Retention time.Duration
	// Group owns the file and the directory (G29); < 0 leaves them alone.
	Group     int
	QueueSize int
	FailAfter time.Duration
	// Secrets are redacted from every field (credentials, caller secrets,
	// the hub secret). Called per line; keep it cheap.
	Secrets func() []string
	Now     func() time.Time
	// WriteHook (tests only) runs before each write, under the file lock;
	// an error fails that write, blocking stalls the writer.
	WriteHook func() error
}

// Log is the access log. Safe for concurrent use.
type Log struct {
	path string
	o    Options

	mu    sync.Mutex // the file
	f     *os.File
	torn  bool // a failed write may have left a partial line
	stale bool // the file was replaced but reopening it failed

	q chan []byte
	// slots: one token per line queued or reserved and not yet taken by
	// the writer (cap = the queue's): a send to q always has its slot, so
	// it never blocks, and a reserved line always has room.
	slots        chan struct{}
	writingSince atomic.Int64 // unix ns (o.Now) of the write in progress; 0 = none
	lastDropLog  atomic.Int64
	pending      atomic.Int64
	failingSince atomic.Int64 // unix ns of the first failure in a row; 0 = fine
	errs         atomic.Int64
	dropped      atomic.Int64
	low          *rate.Limiter
	closed       atomic.Bool
	stop         chan struct{}
	wg           sync.WaitGroup
	lastErrLog   atomic.Int64

	writeHook func() error // tests: fails or blocks a write
}

// chown sets the group of path (tests replace it).
var chown = func(path string, gid int) error { return os.Chown(path, -1, gid) }

// Open opens (creating) the log at path with the defaults: group 10001,
// file 0640, directory 0750.
func Open(path string, retention time.Duration) (*Log, error) {
	return OpenWith(path, Options{Retention: retention})
}

// OpenWith opens the log with options. It enforces the file's and the
// directory's mode and group (an error if it can't: the Hub must be able
// to read the log), prunes once, and starts the writer and the hourly
// prune.
func OpenWith(path string, o Options) (*Log, error) {
	if o.Retention <= 0 {
		o.Retention = DefaultRetention
	}
	if o.Group == 0 {
		o.Group = DefaultGroup
	}
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueue
	}
	if o.FailAfter <= 0 {
		o.FailAfter = DefaultFailAfter
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("access log directory: %w", err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("access log directory mode: %w", err)
	}
	if o.Group >= 0 {
		if err := chown(dir, o.Group); err != nil {
			return nil, fmt.Errorf("access log directory group %d: %w", o.Group, err)
		}
	}
	l := &Log{
		path: path, o: o,
		q:     make(chan []byte, o.QueueSize),
		slots: make(chan struct{}, o.QueueSize),
		low:   rate.NewLimiter(lowPerSecond, lowPerSecond),
		stop:  make(chan struct{}),

		writeHook: o.WriteHook,
	}
	f, err := l.openFile()
	if err != nil {
		return nil, err
	}
	l.f = f
	if err := l.Prune(); err != nil {
		log.Printf("mcp-gate: access log prune: %v", err)
	}
	l.wg.Add(2)
	go l.writer()
	go l.pruner()
	return l, nil
}

func (l *Log) openFile() (*os.File, error) {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, fileMode)
	if err != nil {
		return nil, fmt.Errorf("access log: %w", err)
	}
	if err := l.setMode(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (l *Log) setMode(path string) error {
	if err := os.Chmod(path, fileMode); err != nil {
		return fmt.Errorf("access log mode: %w", err)
	}
	if l.o.Group >= 0 {
		if err := chown(path, l.o.Group); err != nil {
			return fmt.Errorf("access log group %d: %w", l.o.Group, err)
		}
	}
	return nil
}

// clip cuts s to n bytes on a rune boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// clean redacts every secret, then clips.
func clean(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			s = strings.ReplaceAll(s, sec, redacted)
		}
	}
	return clip(s, maxField)
}

func (l *Log) encode(ln Line) []byte {
	var secrets []string
	if l.o.Secrets != nil {
		secrets = l.o.Secrets()
	}
	t := ln.Time
	if t.IsZero() {
		t = l.o.Now()
	}
	w := wire{
		Time: t.UTC().Format(time.RFC3339),
		User: clean(ln.User, secrets), Client: clean(ln.Client, secrets), Resource: clean(ln.Resource, secrets),
		Instance: clean(ln.Instance, secrets), Companion: clean(ln.Companion, secrets), Via: clean(ln.Via, secrets),
		Method: clean(ln.Method, secrets), Tool: clean(ln.Tool, secrets), ArgsSHA256: clean(ln.ArgsSHA256, secrets),
		Decision: clean(ln.Decision, secrets), UpstreamStatus: ln.UpstreamStatus, DurationMS: ln.DurationMS,
		ConfirmationID: clean(ln.ConfirmationID, secrets),
	}
	b, _ := json.Marshal(w) // only strings and ints: never fails
	return append(b, '\n')
}

// Write queues a line; it waits at most 50 ms for room, else drops the
// line (counted) and returns ErrQueueFull.
func (l *Log) Write(ln Line) error {
	if l.closed.Load() {
		return ErrClosed
	}
	b := l.encode(ln)
	select {
	case l.slots <- struct{}{}:
	default:
		t := time.NewTimer(writeWait)
		defer t.Stop()
		select {
		case l.slots <- struct{}{}:
		case <-t.C:
			l.dropped.Add(1)
			l.logDrop()
			return ErrQueueFull
		}
	}
	l.enqueue(b)
	return nil
}

// enqueue sends a line whose slot is held: never blocks.
func (l *Log) enqueue(b []byte) {
	l.pending.Add(1)
	l.q <- b
}

// logDrop: a dropped line of a request that was let through is loud (at
// most one log line per 10 s).
func (l *Log) logDrop() {
	if last := l.lastDropLog.Load(); time.Since(time.Unix(0, last)) > 10*time.Second && l.lastDropLog.CompareAndSwap(last, time.Now().UnixNano()) {
		log.Printf("mcp-gate: ACCESS LOG QUEUE FULL: a line of an allowed request was dropped (%d dropped so far)", l.dropped.Load())
	}
}

// Reservation is a queue slot taken before a tools/call is forwarded
// (G28): its line goes into the slot and is never dropped. Write or
// Release it exactly once; a second Write is a plain Write.
type Reservation struct {
	l    *Log
	used atomic.Bool
}

// Reserve takes a slot for the line of a call about to be forwarded. It
// fails (ErrUnloggable) while the writer is failing at all — not only
// after FailAfter, so no admitted line waits on a failing disk — or has
// been stuck on one write for stallAfter, and (ErrQueueFull) when no slot
// is free. It never waits.
func (l *Log) Reserve() (*Reservation, error) {
	if l.closed.Load() {
		return nil, ErrClosed
	}
	if !l.writerOK() {
		return nil, ErrUnloggable
	}
	select {
	case l.slots <- struct{}{}:
		return &Reservation{l: l}, nil
	default:
		return nil, ErrQueueFull
	}
}

func (l *Log) writerOK() bool {
	if l.failingSince.Load() != 0 {
		return false
	}
	ws := l.writingSince.Load()
	return ws == 0 || l.o.Now().Sub(time.Unix(0, ws)) < stallAfter
}

// Write queues the line into the reserved slot (never dropped).
func (r *Reservation) Write(ln Line) error {
	if r.used.Swap(true) {
		return r.l.Write(ln)
	}
	r.l.enqueue(r.l.encode(ln))
	return nil
}

// Release gives an unused slot back.
func (r *Reservation) Release() {
	if r != nil && !r.used.Swap(true) {
		<-r.l.slots
	}
}

// WriteLow queues the line of a refused request (signed in or not): at
// most 50 per second and never into the second half of the queue, so
// a flood of refusals can't make tools/call unloggable. It never
// waits.
func (l *Log) WriteLow(ln Line) error {
	if l.closed.Load() {
		return ErrClosed
	}
	if len(l.slots) >= cap(l.slots)/2 || !l.low.Allow() {
		l.dropped.Add(1)
		return ErrQueueFull
	}
	b := l.encode(ln)
	select {
	case l.slots <- struct{}{}:
		l.enqueue(b)
		return nil
	default:
		l.dropped.Add(1)
		return ErrQueueFull
	}
}

// Healthy: false while the writer has failed for longer than FailAfter
// (30 s), or the queue is full (G28).
func (l *Log) Healthy() bool {
	if l.closed.Load() {
		return false
	}
	if fs := l.failingSince.Load(); fs != 0 && l.o.Now().Sub(time.Unix(0, fs)) > l.o.FailAfter {
		return false
	}
	return len(l.slots) < cap(l.slots)
}

// Errors counts failed writes; Dropped counts lines never queued.
func (l *Log) Errors() int64  { return l.errs.Load() }
func (l *Log) Dropped() int64 { return l.dropped.Load() }

// Flush waits until every queued line is written (tests, Close).
func (l *Log) Flush(ctx context.Context) error {
	for l.pending.Load() > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}

// Close writes what is queued (up to 2 s), then closes the file.
func (l *Log) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = l.Flush(ctx)
	cancel()
	close(l.stop)
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func (l *Log) writer() {
	defer l.wg.Done()
	for {
		var b []byte
		select {
		case <-l.stop:
			return
		case b = <-l.q:
		}
		<-l.slots // the line is the writer's now
		backoff := 50 * time.Millisecond
		for {
			l.writingSince.Store(l.o.Now().UnixNano())
			err := l.writeLine(b)
			l.writingSince.Store(0)
			if err == nil {
				l.failingSince.Store(0)
				l.pending.Add(-1)
				break
			}
			l.errs.Add(1)
			l.failingSince.CompareAndSwap(0, l.o.Now().UnixNano())
			if last := l.lastErrLog.Load(); time.Since(time.Unix(0, last)) > 10*time.Second && l.lastErrLog.CompareAndSwap(last, time.Now().UnixNano()) {
				log.Printf("mcp-gate: access log write failed (%d failures, %d dropped): %v", l.errs.Load(), l.dropped.Load(), err)
			}
			select {
			case <-l.stop:
				l.pending.Add(-1)
				return
			case <-time.After(backoff):
			}
			if backoff < time.Second {
				backoff *= 2
			}
		}
	}
}

func (l *Log) writeLine(b []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writeHook != nil {
		if err := l.writeHook(); err != nil {
			return err
		}
	}
	if l.stale {
		f, err := l.openFile()
		if err != nil {
			return err
		}
		l.f.Close()
		l.f, l.stale = f, false
	}
	if l.torn {
		// End the partial line so the next one stands on its own.
		if _, err := l.f.Write([]byte{'\n'}); err != nil {
			return err
		}
		l.torn = false
	}
	n, err := l.f.Write(b)
	if err != nil && n > 0 {
		l.torn = true
	}
	return err
}

func (l *Log) pruner() {
	defer l.wg.Done()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			if err := l.Prune(); err != nil {
				log.Printf("mcp-gate: access log prune: %v", err)
			}
		}
	}
}

// Prune removes lines older than the retention (and torn or malformed
// lines) by rewriting the file atomically with the same mode and group.
// Lines are filtered without holding the writer; only the tail written
// meanwhile is copied under the lock. Nothing to remove: no rewrite.
func (l *Log) Prune() error {
	cut := l.o.Now().Add(-l.o.Retention)
	l.mu.Lock()
	st, err := l.f.Stat()
	l.mu.Unlock()
	if err != nil {
		return err
	}
	size := st.Size()
	src, err := os.Open(l.path)
	if err != nil {
		return err
	}
	defer src.Close()
	// Quick check: a first line inside the retention means nothing to do
	// (lines are appended in time order).
	first, ferr := bufio.NewReader(io.LimitReader(src, size)).ReadBytes('\n')
	if size == 0 || (ferr == nil && fresh(first, cut)) {
		return nil
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(l.path), ".access-*.tmp")
	if err != nil {
		return err
	}
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := l.setMode(tmp.Name()); err != nil {
		return err
	}
	bw := bufio.NewWriter(tmp)
	r := bufio.NewReader(io.LimitReader(src, size))
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			break // a final line without '\n' is torn: dropped
		}
		if err != nil {
			return err
		}
		if fresh(line, cut) {
			if _, err := bw.Write(line); err != nil {
				return err
			}
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// The tail written since the stat, as is.
	if _, err := src.Seek(size, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), l.path); err != nil {
		return err
	}
	done = true
	if d, err := os.Open(filepath.Dir(l.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	f, err := l.openFile()
	if err != nil {
		l.stale = true // the writer retries the open (and fails until then)
		return err
	}
	l.f.Close()
	l.f = f
	return nil
}

// fresh: a complete, valid line not older than cut.
func fresh(line []byte, cut time.Time) bool {
	ln, err := ParseLine(bytes.TrimSuffix(line, []byte{'\n'}))
	return err == nil && !ln.Time.Before(cut)
}
