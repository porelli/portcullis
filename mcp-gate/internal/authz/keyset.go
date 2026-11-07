package authz

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Refresh throttle (contract §15.2, preflight G20): an unknown kid
// refreshes the key set at most once per refreshEvery, gate-wide; until
// the first successful fetch, at most once per refreshEmpty (so a gate
// started before Keycloak recovers in seconds, not a minute).
const (
	refreshEvery = 60 * time.Second
	refreshEmpty = 5 * time.Second
	// keyMaxAge bounds how long a key set is used without a successful
	// fetch being tried again: a token whose kid is known re-fetches the
	// set first once the last success is older (still within the throttle
	// above), and the fetched set replaces the old one, so a key Keycloak
	// stopped publishing (rotated out, disabled, deleted) stops verifying
	// within keyMaxAge + refreshEvery. A failed fetch keeps the old set.
	keyMaxAge    = 10 * time.Minute
	jwksMaxBytes = 1 << 20
	jwksTimeout  = 10 * time.Second
)

// jwksClient is the JWKS fetcher's client: never a redirect (the answer
// must come from the configured URL), and, when the gate builds it, no
// proxy from the environment and bounded dials. A caller's client is
// copied, its CheckRedirect replaced.
func jwksClient(hc *http.Client) *http.Client {
	var c http.Client
	if hc != nil {
		c = *hc
	} else {
		c = http.Client{
			Timeout: jwksTimeout,
			Transport: &http.Transport{
				Proxy:                 nil,
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				TLSHandshakeTimeout:   5 * time.Second,
				ResponseHeaderTimeout: jwksTimeout,
				MaxIdleConns:          2,
				IdleConnTimeout:       90 * time.Second,
			},
		}
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

var signingAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// keySet is an oidc.KeySet over the realm's JWKS that never fetches more
// than the throttle allows. go-oidc's RemoteKeySet re-fetches on every
// unknown kid, so a flood of random kids would be a Keycloak fetch per
// request.
type keySet struct {
	url string
	hc  *http.Client
	now func() time.Time

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetched bool          // a fetch succeeded once
	last    time.Time     // last fetch attempt
	ok      time.Time     // last successful fetch
	flight  chan struct{} // closed when the fetch in flight ends; nil if none
}

// VerifySignature implements oidc.KeySet.
func (k *keySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, signingAlgs)
	if err != nil {
		return nil, errors.New("malformed or disallowed signature")
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("not exactly one signature")
	}
	hdr := jws.Signatures[0].Header
	if hdr.KeyID == "" {
		return nil, errors.New("no kid")
	}
	if key, ok := k.find(hdr.KeyID, hdr.Algorithm); ok && !k.stale() {
		return jws.Verify(key)
	}
	if done, mine := k.refreshSlot(); mine {
		k.refresh(ctx, done)
	} else if done != nil {
		// No new fetch, but wait for the one in flight (the first
		// requests after a start or a rotation).
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if key, ok := k.find(hdr.KeyID, hdr.Algorithm); ok {
		return jws.Verify(key)
	}
	return nil, errors.New("unknown kid")
}

// stale reports a key set whose last successful fetch is older than
// keyMaxAge (the known-kid path then re-fetches before verifying).
func (k *keySet) stale() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.fetched && k.now().Sub(k.ok) >= keyMaxAge
}

// find returns a public signing key with that kid usable for alg.
func (k *keySet) find(kid, alg string) (any, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, key := range k.keys {
		if key.KeyID != kid || (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != alg) {
			continue
		}
		switch pub := key.Key.(type) {
		case *rsa.PublicKey:
			if alg == string(jose.RS256) && pub.N.BitLen() >= 2048 {
				return pub, true
			}
		case *ecdsa.PublicKey:
			if alg == string(jose.ES256) && pub.Curve == elliptic.P256() {
				return pub, true
			}
		}
	}
	return nil, false
}

// refreshSlot takes the gate-wide refresh slot if the throttle allows
// (mine), else returns the fetch in flight, if any.
func (k *keySet) refreshSlot() (done chan struct{}, mine bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.flight != nil {
		return k.flight, false
	}
	every := refreshEvery
	if !k.fetched {
		every = refreshEmpty
	}
	now := k.now()
	if !k.last.IsZero() && now.Sub(k.last) < every {
		return nil, false
	}
	k.last = now
	k.flight = make(chan struct{})
	return k.flight, true
}

func (k *keySet) refresh(ctx context.Context, done chan struct{}) {
	keys, err := k.fetch(ctx)
	k.mu.Lock()
	if err == nil {
		// The fetched set replaces the old one: keys no longer
		// published are dropped.
		k.keys, k.fetched, k.ok = keys, true, k.now()
	}
	k.flight = nil
	k.mu.Unlock()
	close(done)
	if err != nil {
		// Never a token in here: only the JWKS endpoint's answer.
		logf("mcp-gate: JWKS fetch failed: %v", err)
	}
}

func (k *keySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	// A fetch outlives a cancelled request: other requests wait on it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jwksTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > jwksMaxBytes {
		return nil, errors.New("key set too large")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, errors.New("not a JWK set")
	}
	var keys []jose.JSONWebKey
	for _, key := range set.Keys {
		if key.IsPublic() && key.Valid() {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
