// Package logx is mailctl's logger: every line goes through Redact, which
// blanks every registered secret value and every Stalwart API key or app
// password shape (global constraint: secrets never in logs).
package logx

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
)

var (
	mu      sync.RWMutex
	secrets []string
	// API_… keys and app_… passwords (Task 2: "API_" + 38, "app_" + 36).
	shapes = regexp.MustCompile(`\b(API|app)_[A-Za-z0-9+/=_-]{16,}`)
)

// AddSecret registers a value Redact blanks (values under 6 characters are
// ignored: they would blank ordinary words).
func AddSecret(s string) {
	s = strings.TrimSpace(s)
	if len(s) < 6 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, x := range secrets {
		if x == s {
			return
		}
	}
	secrets = append(secrets, s)
}

// Redact blanks every known secret and secret-shaped token in s.
func Redact(s string) string {
	mu.RLock()
	for _, x := range secrets {
		s = strings.ReplaceAll(s, x, "[redacted]")
	}
	mu.RUnlock()
	return shapes.ReplaceAllString(s, "[redacted]")
}

// Logger writes redacted lines.
type Logger struct{ l *log.Logger }

// New logs to w with the standard date prefix.
func New(w io.Writer) *Logger { return &Logger{l: log.New(w, "", log.LstdFlags)} }

// Printf logs one redacted line.
func (l *Logger) Printf(format string, a ...any) { l.l.Print(Redact(fmt.Sprintf(format, a...))) }

// RedactingWriter writes w's input line by line through Redact (Ruling
// R2-LOG): a line is held until its newline and redacted whole. A line
// longer than redactMax is never cut: it is dropped whole and replaced by
// one marker line. Close does the same with the last partial line.
type RedactingWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
	// over: the current line passed redactMax; it is being dropped.
	over bool
}

// redactMax bounds one log line.
const redactMax = 64 << 10

// lineDropped replaces a line over redactMax.
const lineDropped = "[log line over 64 KiB dropped]"

// NewRedactingWriter wraps w.
func NewRedactingWriter(w io.Writer) *RedactingWriter { return &RedactingWriter{w: w} }

func (r *RedactingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if !r.over {
				r.buf = append(r.buf, p...)
				if len(r.buf) > redactMax {
					r.buf, r.over = nil, true
				}
			}
			return n, nil
		}
		line := p[:i+1]
		p = p[i+1:]
		var out string
		if r.over || len(r.buf)+len(line) > redactMax+1 {
			out = lineDropped + "\n"
		} else {
			out = Redact(string(append(r.buf, line...)))
		}
		r.buf, r.over = nil, false
		if _, err := io.WriteString(r.w, out); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Close writes the last partial line the same way (the child exited).
func (r *RedactingWriter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	switch {
	case r.over:
		_, err = io.WriteString(r.w, lineDropped)
	case len(r.buf) > 0:
		_, err = io.WriteString(r.w, Redact(string(r.buf)))
	}
	r.buf, r.over = nil, false
	return err
}
