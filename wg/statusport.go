package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"
)

// The status port (contract §20.10, Kubernetes HA): GET /v1/status answers
// status.json exactly as wg last wrote it — the document the Hub reads from
// HUB_VPN_STATUS_FILE on Docker —, every other method 405. No auth of its
// own: only the Hub pod may reach it (NetworkPolicy, a stated delta in
// hardening.md).
const (
	statusPath = "/v1/status"
	statusMax  = 4 << 20
)

func serveStatusPort(ctx context.Context, addr, file string) {
	srv := &http.Server{
		Addr: addr, Handler: statusHandler(file),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	go func() { <-ctx.Done(); srv.Close() }()
	log.Printf("wg: status port on %s (GET %s)", addr, statusPath)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("wg: status port: %v", err)
	}
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
