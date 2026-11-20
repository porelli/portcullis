package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/portcullis/mcp-gate/internal/accesslog"
)

// The log port (contract §20.10): GET /v1/log?cursor=<c>|from=<RFC 3339>
// &limit=<n> answers the access log's lines as they are on disk (JSONL,
// file order, at most limit lines — 1–10000, default 1000 — and 4 MiB)
// with X-Portcullis-Next (the exclusive cursor of the next page) and
// X-Portcullis-Truncated; a cursor of another generation of the log (it was
// rewritten by its pruning) is 410 cursor_expired; every other method is 405. At most 4
// connections, each within 30 s of its accept, one read at a time held
// until its answer is written. No auth of its own: only the Hub pod may
// reach it (NetworkPolicy, a stated delta in hardening.md). The gate's own
// listener never serves it.
const (
	logPath         = "/v1/log"
	logAnswerMax    = 4 << 20
	logLimitDefault = 1000
	logLimitMax     = 10000
	logMaxConns     = 4
)

// logDeadline bounds a whole connection (tests shorten it).
var logDeadline = 30 * time.Second

// newLogServer: the log port's server (serve it on boundedListener).
func newLogServer(addr, logFile string) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           newLogHandler(logFile),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}

// boundedListener admits at most n connections at once (Accept waits for
// a free one) and gives each a deadline for its whole life.
type boundedListener struct {
	net.Listener
	slots    chan struct{}
	done     chan struct{}
	once     sync.Once
	deadline func() time.Duration
}

func newBoundedListener(ln net.Listener, n int, deadline func() time.Duration) *boundedListener {
	return &boundedListener{Listener: ln, slots: make(chan struct{}, n), done: make(chan struct{}), deadline: deadline}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	sc := &slotConn{Conn: c, end: time.Now().Add(l.deadline()), release: sync.OnceFunc(func() { <-l.slots })}
	_ = sc.SetDeadline(time.Time{})
	return sc, nil
}

func (l *boundedListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// slotConn: a connection holding a slot, whose deadlines never pass its
// end (http.Server sets its own read / write deadlines per request: they
// are clamped, so the whole connection ends by then).
type slotConn struct {
	net.Conn
	end     time.Time
	release func()
}

func (c *slotConn) clamp(t time.Time) time.Time {
	if t.IsZero() || t.After(c.end) {
		return c.end
	}
	return t
}

func (c *slotConn) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(c.clamp(t)) }
func (c *slotConn) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(c.clamp(t)) }
func (c *slotConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.clamp(t)) }

func (c *slotConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

func newLogHandler(logFile string) http.Handler {
	one := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != logPath || r.URL.RawPath != "" {
			http.NotFound(w, r)
			return
		}
		cur, from, limit, err := logQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case one <- struct{}{}:
		case <-r.Context().Done():
			return
		}
		defer func() { <-one }() // held until the answer is written
		pg, err := accesslog.Read(logFile, cur, from, limit, logAnswerMax)
		switch {
		case errors.Is(err, accesslog.ErrCursorExpired):
			http.Error(w, "cursor_expired", http.StatusGone)
			return
		case errors.Is(err, accesslog.ErrGenUnknown):
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		case err != nil:
			http.Error(w, "the access log can't be read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Length", strconv.Itoa(len(pg.Body)))
		w.Header().Set("X-Portcullis-Next", pg.Next.String())
		w.Header().Set("X-Portcullis-Truncated", strconv.FormatBool(pg.Truncated))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pg.Body)
	})
}

// logQuery reads cursor or from, and limit; anything else (an unknown or
// repeated parameter, both cursor and from, a bad cursor, a from that
// isn't RFC 3339, a limit outside 1–10000 or not in canonical decimal) is
// an error, the 400's text.
func logQuery(raw string) (*accesslog.Cursor, time.Time, int, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return nil, time.Time{}, 0, errors.New("malformed query")
	}
	for k, v := range q {
		if k != "from" && k != "cursor" && k != "limit" {
			return nil, time.Time{}, 0, fmt.Errorf("unknown parameter %q", k)
		}
		if len(v) != 1 {
			return nil, time.Time{}, 0, fmt.Errorf("%s given twice", k)
		}
	}
	if q.Has("from") && q.Has("cursor") {
		return nil, time.Time{}, 0, errors.New("from and cursor together")
	}
	var from time.Time
	if q.Has("from") {
		if from, err = time.Parse(time.RFC3339Nano, q.Get("from")); err != nil || from.IsZero() {
			return nil, time.Time{}, 0, errors.New("from must be an RFC 3339 timestamp")
		}
	}
	var cur *accesslog.Cursor
	if q.Has("cursor") {
		c, err := accesslog.ParseCursor(q.Get("cursor"))
		if err != nil {
			return nil, time.Time{}, 0, err
		}
		cur = &c
	}
	limit := logLimitDefault
	if q.Has("limit") {
		n, err := strconv.Atoi(q.Get("limit"))
		if err != nil || n < 1 || n > logLimitMax || strconv.Itoa(n) != q.Get("limit") {
			return nil, time.Time{}, 0, fmt.Errorf("limit must be 1-%d", logLimitMax)
		}
		limit = n
	}
	return cur, from, limit, nil
}
