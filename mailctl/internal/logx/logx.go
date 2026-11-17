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

// RedactingWriter writes w's input line by line through Redact (a line
// split across writes is held until its newline; the rest on Close-less
// streams flushes with the next line).
type RedactingWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
}

// NewRedactingWriter wraps w.
func NewRedactingWriter(w io.Writer) *RedactingWriter { return &RedactingWriter{w: w} }

func (r *RedactingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			break
		}
		if _, err := io.WriteString(r.w, Redact(string(r.buf[:i+1]))); err != nil {
			return len(p), err
		}
		r.buf = r.buf[i+1:]
	}
	if len(r.buf) > 64<<10 {
		_, _ = io.WriteString(r.w, Redact(string(r.buf)))
		r.buf = nil
	}
	return len(p), nil
}
