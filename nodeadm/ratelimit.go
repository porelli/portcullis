package main

// The public paths' in-process rate limit (review I5): a second layer under
// the router's rate-limit@file. Every POST /node/v1/{nonce,enrol,join} takes
// a token from its source IP's bucket and from the global one; an empty
// bucket answers 429 and does no work. The source is the rightmost
// X-Forwarded-For entry (the one the edge router appended: the public port
// accepts only the edge, NetworkPolicy), else the connection's peer.

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	perSourceRate  = rate.Limit(1) // one a second sustained
	perSourceBurst = 10
	globalRate     = rate.Limit(20)
	globalBurst    = 60
	maxSources     = 4096
	sourceIdle     = 10 * time.Minute
)

type limiter struct {
	mu       sync.Mutex
	global   *rate.Limiter
	sources  map[netip.Addr]*sourceBucket
	now      func() time.Time
	srcRate  rate.Limit
	srcBurst int
}

type sourceBucket struct {
	l    *rate.Limiter
	seen time.Time
}

func newLimiter(srcRate rate.Limit, srcBurst int, gRate rate.Limit, gBurst int) *limiter {
	return &limiter{global: rate.NewLimiter(gRate, gBurst), sources: map[netip.Addr]*sourceBucket{}, now: time.Now,
		srcRate: srcRate, srcBurst: srcBurst}
}

// allow takes a token for src and one from the global bucket.
func (l *limiter) allow(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	b := l.sources[src]
	if b == nil {
		if len(l.sources) >= maxSources {
			for k, v := range l.sources {
				if t.Sub(v.seen) > sourceIdle {
					delete(l.sources, k)
				}
			}
		}
		if len(l.sources) >= maxSources {
			// Full of live sources: only the global bucket decides.
			return l.global.AllowN(t, 1)
		}
		b = &sourceBucket{l: rate.NewLimiter(l.srcRate, l.srcBurst)}
		l.sources[src] = b
	}
	b.seen = t
	if !b.l.AllowN(t, 1) {
		return false
	}
	return l.global.AllowN(t, 1)
}

// sourceIP: the rightmost X-Forwarded-For address, else the peer's.
func sourceIP(r *http.Request) netip.Addr {
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		parts := strings.Split(xff[len(xff)-1], ",")
		if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
			return a.Unmap()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
