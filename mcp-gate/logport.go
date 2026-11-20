package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/portcullis/mcp-gate/internal/accesslog"
)

// The log port (contract §20.10): GET /v1/log?from=<RFC 3339>&limit=<n>
// answers the access log's lines as they are on disk (JSONL, oldest
// first, at most limit lines — 1–10000, default 1000 — and 4 MiB); every
// other method is 405. It has no auth of its own: only the Hub pod may
// reach it (NetworkPolicy, a stated delta in hardening.md). The gate's
// own listener never serves it.
const (
	logPath         = "/v1/log"
	logAnswerMax    = 4 << 20
	logLimitDefault = 1000
	logLimitMax     = 10000
)

// newLogServer: the log port's server; reads are one at a time (an answer
// holds at most 4 MiB), so its memory stays bounded however often it is
// asked.
func newLogServer(addr, logFile string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           newLogHandler(logFile),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
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
		from, limit, err := logQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case one <- struct{}{}:
		case <-r.Context().Done():
			return
		}
		b, err := accesslog.Read(logFile, from, limit, logAnswerMax)
		<-one
		if err != nil {
			http.Error(w, "the access log can't be read", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})
}

// logQuery reads from and limit; anything else (an unknown or repeated
// parameter, a from that isn't RFC 3339, a limit outside 1–10000) is an
// error, the 400's text.
func logQuery(raw string) (time.Time, int, error) {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return time.Time{}, 0, fmt.Errorf("malformed query")
	}
	for k, v := range q {
		if k != "from" && k != "limit" {
			return time.Time{}, 0, fmt.Errorf("unknown parameter %q", k)
		}
		if len(v) != 1 {
			return time.Time{}, 0, fmt.Errorf("%s given twice", k)
		}
	}
	var from time.Time
	if v, ok := q["from"]; ok {
		if from, err = time.Parse(time.RFC3339Nano, v[0]); err != nil {
			return time.Time{}, 0, fmt.Errorf("from must be an RFC 3339 timestamp")
		}
	}
	limit := logLimitDefault
	if v, ok := q["limit"]; ok {
		n, err := strconv.Atoi(v[0])
		if err != nil || n < 1 || n > logLimitMax || strconv.Itoa(n) != v[0] {
			return time.Time{}, 0, fmt.Errorf("limit must be 1-%d", logLimitMax)
		}
		limit = n
	}
	return from, limit, nil
}
