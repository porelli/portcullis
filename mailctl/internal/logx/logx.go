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

// RedactingWriter writes w's input line by line through Redact. A line
// split across writes is held until its newline. A line longer than
// redactMax is flushed in parts, each cut where no secret (or secret
// shape) can straddle it: the last tailKeep bytes, and any match crossing
// the cut, stay for the next part. Close redacts and writes the rest.
type RedactingWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte
	// inToken: a secret-shaped token was flushed whole while it still ran
	// on; its continuation is dropped until the first non-token byte.
	inToken bool
}

// tokenByte: a byte a secret-shaped token may continue with.
func tokenByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("+/=_-", c) >= 0
}

const (
	redactMax = 64 << 10
	// shapeMax bounds a secret-shaped token the cut keeps whole (API keys
	// are 42 bytes, app passwords 40).
	shapeMax = 256
)

// NewRedactingWriter wraps w.
func NewRedactingWriter(w io.Writer) *RedactingWriter { return &RedactingWriter{w: w} }

func (r *RedactingWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	if r.inToken {
		i := 0
		for i < len(p) && tokenByte(p[i]) {
			i++
		}
		if i == len(p) {
			return n, nil
		}
		p, r.inToken = p[i:], false
	}
	r.buf = append(r.buf, p...)
	for {
		i := bytes.IndexByte(r.buf, '\n')
		if i < 0 {
			break
		}
		if _, err := io.WriteString(r.w, Redact(string(r.buf[:i+1]))); err != nil {
			return n, err
		}
		r.buf = r.buf[i+1:]
	}
	if len(r.buf) > redactMax {
		cut := safeCut(string(r.buf))
		// No safe cut (one secret-shaped token fills the buffer): past
		// twice the bound, the whole buffer goes out redacted (L-c), never
		// an unbounded hold.
		forced := false
		if cut == 0 && len(r.buf) > 2*redactMax {
			cut, forced = len(r.buf), true
		}
		if _, err := io.WriteString(r.w, Redact(string(r.buf[:cut]))); err != nil {
			return n, err
		}
		r.buf = append([]byte(nil), r.buf[cut:]...)
		r.inToken = forced
	}
	return n, nil
}

// Close redacts and writes what is left (the child exited).
func (r *RedactingWriter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return nil
	}
	_, err := io.WriteString(r.w, Redact(string(r.buf)))
	r.buf = nil
	return err
}

// safeCut: where s may be cut: len(s) minus the longest secret (or
// shapeMax) less one, moved back to the start of any secret or shape
// match crossing it.
func safeCut(s string) int {
	keep := shapeMax
	mu.RLock()
	for _, x := range secrets {
		if len(x) > keep {
			keep = len(x)
		}
	}
	cut := len(s) - (keep - 1)
	for moved := true; moved && cut > 0; {
		moved = false
		for _, x := range secrets {
			from := cut - len(x) + 1
			if from < 0 {
				from = 0
			}
			if j := strings.Index(s[from:min(len(s), cut+len(x)-1)], x); j >= 0 && from+j < cut {
				cut, moved = from+j, true
			}
		}
		// The whole buffer: a shape match longer than shapeMax may cross
		// the cut from far before it.
		for _, m := range shapes.FindAllStringIndex(s, -1) {
			if m[0] < cut && m[1] > cut {
				cut, moved = m[0], true
			}
		}
	}
	mu.RUnlock()
	if cut < 0 {
		cut = 0
	}
	return cut
}
