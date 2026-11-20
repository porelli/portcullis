package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// The status port (contract §20.10, Kubernetes HA): GET /v1/status answers
// status.json exactly as wg last wrote it — the document the Hub reads from
// HUB_VPN_STATUS_FILE on Docker —, every other method 405. No auth of its
// own: only the Hub pod may reach it (NetworkPolicy, a stated delta in
// hardening.md). At most 4 connections, each within 30 s.
const (
	statusPath = "/v1/status"
	statusMax  = 4 << 20
)

// statusMaxConns / statusDeadline: at most 4 connections, each within
// 30 s of its accept (contract §20.10's bounds; tests shorten it).
const statusMaxConns = 4

var statusDeadline = 30 * time.Second

func newStatusServer(file string) *http.Server {
	srv := &http.Server{
		Handler:           statusHandler(file),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}

func serveStatusPort(ctx context.Context, addr, file string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("wg: status port: %v", err)
		return
	}
	srv := newStatusServer(file)
	go func() { <-ctx.Done(); srv.Close() }()
	log.Printf("wg: status port on %s (GET %s)", addr, statusPath)
	err = srv.Serve(newBoundedListener(ln, statusMaxConns, func() time.Duration { return statusDeadline }))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("wg: status port: %v", err)
	}
}

// boundedListener admits at most n connections at once (Accept waits for
// a free one) and ends each by its deadline.
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
// end (http.Server's own per-request deadlines are clamped).
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

func statusHandler(file string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != statusPath || r.URL.RawPath != "" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		b, err := readStatus(file)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			http.Error(w, "no status yet", http.StatusServiceUnavailable)
			return
		case err != nil:
			http.Error(w, "the status can't be read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})
}

// readStatus: the file's bytes, never through a symlink, a regular file of
// at most statusMax bytes.
func readStatus(file string) ([]byte, error) {
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("status: not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, statusMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > statusMax {
		return nil, errors.New("status: larger than 4 MiB")
	}
	return b, nil
}
