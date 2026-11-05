// Package hubapi is the gate's client of the Hub's internal MCP API
// (integration contract §15.7): mint a person's credential for a
// companion, create a confirmation, consume an approved one. Every request
// carries X-Portcullis-MCP-Secret.
//
// It fails closed (G26): a transport error, a timeout, a redirect, a 401
// (wrong secret), any 5xx other than the mint's 502 mint_failed, and any
// answer whose status or body is not exactly one the contract lists is
// ErrUnavailable, and the caller never calls the upstream. Errors carry
// neither the secret nor the Hub's body.
package hubapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Outcomes. Wrapped errors: test with errors.Is.
var (
	ErrUnavailable     = errors.New("hub unavailable")                         // fail closed
	ErrNoAccount       = errors.New("no_account")                              // mint 409: never signed in to the app
	ErrMintFailed      = errors.New("mint_failed")                             // mint 502
	ErrNotAllowed      = errors.New("not in the population")                   // 403
	ErrUnknownResource = errors.New("not a current companion resource")        // 404 on mint / create
	ErrNotConfirmable  = errors.New("the Hub refused to confirm this tool")    // create 400
	ErrTooMany         = errors.New("too many confirmations")                  // create 429 too_many
	errBadRequest      = errors.New("hubapi: request not sent: invalid field") // the gate's own bug
)

// Consume states.
const (
	StateConsumed = "consumed" // an approved match, now consumed: proceed
	StateNone     = "none"     // no match: create a new one
	StatePending  = "pending"
	StateDeclined = "declined"
)

// SecretHeader carries HUB_MCP_GATE_SECRET.
const SecretHeader = "X-Portcullis-MCP-Secret"

const (
	minSecret    = 32
	maxAnswer    = 64 << 10
	maxPreview   = 4 << 10
	defaultLimit = 25 * time.Second // > the 20 s mint wait; the caller's ctx usually ends first
)

var (
	credID    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`) // §15.4
	digestR   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	confirmR  = regexp.MustCompile(`^[A-Za-z2-7]{4}(-?[A-Za-z2-7]{1,4})*$`)
	printable = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Client talks to the Hub's MCP listener (HUB_MCP_ADDR).
type Client struct {
	base    *url.URL
	secret  string
	http    *http.Client
	timeout time.Duration
}

// New: baseURL is http(s)://host[:port] (MCP_GATE_HUB_URL); secret is
// HUB_MCP_GATE_SECRET (≥ 32 printable ASCII characters). The client
// never follows redirects and never uses a proxy.
func New(baseURL, secret string) (*Client, error) {
	if len(secret) < minSecret || !printable.MatchString(secret) {
		return nil, fmt.Errorf("hubapi: the hub secret must be at least %d printable ASCII characters", minSecret)
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("hubapi: the hub URL must be http(s)://host[:port]")
	}
	u.Path = ""
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: defaultLimit,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
	}
	return &Client{
		base:   u,
		secret: secret,
		http: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		timeout: defaultLimit,
	}, nil
}

// unavailable wraps a cause without its text when that could carry
// anything from the Hub.
func unavailable(what string) error { return fmt.Errorf("%w: %s", ErrUnavailable, what) }

// post sends body as JSON to path and returns the status and the answer
// (≤ 64 KiB). Any transport problem is ErrUnavailable.
func (c *Client) post(ctx context.Context, path string, body any) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, errBadRequest
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	u := *c.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(b))
	if err != nil {
		return 0, nil, unavailable("request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(SecretHeader, c.secret)
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, unavailable("timeout")
		}
		return 0, nil, unavailable("transport")
	}
	defer resp.Body.Close()
	ans, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return 0, nil, unavailable("reading the answer")
	}
	if len(ans) > maxAnswer {
		return 0, nil, unavailable("answer too large")
	}
	return resp.StatusCode, ans, nil
}

// strict decodes exactly one JSON object into v: no unknown, duplicate or
// case-variant keys, no trailing data, every listed key present.
func strict(b []byte, v any, keys ...string) bool {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&raw); err != nil || raw == nil || dec.More() {
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		return false
	}
	if len(raw) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := raw[k]; !ok {
			return false
		}
	}
	if dupKeys(b) {
		return false
	}
	d2 := json.NewDecoder(bytes.NewReader(b))
	d2.DisallowUnknownFields()
	return d2.Decode(v) == nil
}

// dupKeys reports a repeated top-level key (encoding/json keeps the last).
func dupKeys(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return true
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return true
		}
		k, _ := t.(string)
		if seen[k] {
			return true
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return true
		}
	}
	return false
}

func validUser(s string) bool { return s != "" && len(s) <= 64 && printable.MatchString(s) }

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && len(s) <= 2048
}

// MintAnswer: ID of the active entry (200), or the app's URL with
// ErrNoAccount (409).
type MintAnswer struct {
	ID     string
	AppURL string
}

// Mint: POST /internal/credentials {"resource", "user"} → 200 {"id"} (an
// active entry is in the file), 409 {"code": "no_account", "app_url"},
// 403, 404, 502 {"code": "mint_failed"}.
func (c *Client) Mint(ctx context.Context, resource, user string) (*MintAnswer, error) {
	if !validURL(resource) || !validUser(user) {
		return nil, errBadRequest
	}
	code, b, err := c.post(ctx, "/internal/credentials", struct {
		Resource string `json:"resource"`
		User     string `json:"user"`
	}{resource, user})
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusOK:
		var a struct {
			ID string `json:"id"`
		}
		if !strict(b, &a, "id") || !credID.MatchString(a.ID) {
			return nil, unavailable("malformed mint answer")
		}
		return &MintAnswer{ID: a.ID}, nil
	case http.StatusConflict:
		var a struct {
			Code   string `json:"code"`
			AppURL string `json:"app_url"`
		}
		if !strict(b, &a, "code", "app_url") || a.Code != "no_account" || !validURL(a.AppURL) {
			return nil, unavailable("malformed 409")
		}
		return &MintAnswer{AppURL: a.AppURL}, ErrNoAccount
	case http.StatusForbidden:
		return nil, ErrNotAllowed
	case http.StatusNotFound:
		return nil, ErrUnknownResource
	case http.StatusBadGateway:
		var a struct {
			Code string `json:"code"`
		}
		if strict(b, &a, "code") && a.Code == "mint_failed" {
			return nil, ErrMintFailed
		}
	}
	return nil, unavailable(fmt.Sprintf("status %d", code))
}

// ConfirmRequest is POST /internal/confirmations' body.
type ConfirmRequest struct {
	User        string `json:"user"`
	Client      string `json:"client"`
	Resource    string `json:"resource"`
	Tool        string `json:"tool"`
	ArgsSHA256  string `json:"args_sha256"`
	ArgsPreview string `json:"args_preview"`
	Reason      string `json:"reason"` // "confirm" or "destructive"
}

// Confirmation is a created confirmation.
type Confirmation struct {
	ID        string
	URL       string // https://people.<d>/confirm/<id>; the caller checks the host
	ExpiresAt time.Time
}

func validTool(s string) bool { return s != "" && len(s) <= 128 && printable.MatchString(s) }

// CreateConfirmation: → 201 {"id", "url", "expires_at"} | 403 | 404 |
// 400 (not a tool the Hub confirms) | 429 {"code": "too_many"}.
func (c *Client) CreateConfirmation(ctx context.Context, r ConfirmRequest) (*Confirmation, error) {
	if !validUser(r.User) || !validURL(r.Resource) || !validTool(r.Tool) || !digestR.MatchString(r.ArgsSHA256) ||
		len(r.ArgsPreview) > maxPreview || !utf8.ValidString(r.ArgsPreview) || (r.Reason != "confirm" && r.Reason != "destructive") ||
		len(r.Client) > 256 {
		return nil, errBadRequest
	}
	code, b, err := c.post(ctx, "/internal/confirmations", r)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusCreated:
		var a struct {
			ID        string `json:"id"`
			URL       string `json:"url"`
			ExpiresAt string `json:"expires_at"`
		}
		if !strict(b, &a, "id", "url", "expires_at") || !validConfirmID(a.ID) {
			return nil, unavailable("malformed confirmation")
		}
		u, err := url.Parse(a.URL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Host == "" || u.RawQuery != "" || u.ForceQuery ||
			u.Fragment != "" || u.RawPath != "" || u.Path != "/confirm/"+a.ID {
			return nil, unavailable("malformed confirmation URL")
		}
		exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
		if err != nil {
			return nil, unavailable("malformed expires_at")
		}
		return &Confirmation{ID: a.ID, URL: a.URL, ExpiresAt: exp}, nil
	case http.StatusForbidden:
		return nil, ErrNotAllowed
	case http.StatusNotFound:
		return nil, ErrUnknownResource
	case http.StatusBadRequest:
		return nil, ErrNotConfirmable
	case http.StatusTooManyRequests:
		var a struct {
			Code string `json:"code"`
		}
		if strict(b, &a, "code") && a.Code == "too_many" {
			return nil, ErrTooMany
		}
	}
	return nil, unavailable(fmt.Sprintf("status %d", code))
}

// validConfirmID: 128 bits in base32 (26 characters), plain or in the
// dashed display form (§15.6).
func validConfirmID(s string) bool {
	if !confirmR.MatchString(s) {
		return false
	}
	return len(strings.ReplaceAll(s, "-", "")) == 26
}

// ConsumeRequest is POST /internal/confirmations/consume's body.
type ConsumeRequest struct {
	User       string `json:"user"`
	Resource   string `json:"resource"`
	Tool       string `json:"tool"`
	ArgsSHA256 string `json:"args_sha256"`
}

// ConsumeConfirmation: → 200 {"id"} (StateConsumed: proceed) | 404
// (StateNone) | 409 {"state": "pending" | "declined"}. Anything else is
// an error (and state "").
func (c *Client) ConsumeConfirmation(ctx context.Context, r ConsumeRequest) (id string, state string, err error) {
	if !validUser(r.User) || !validURL(r.Resource) || !validTool(r.Tool) || !digestR.MatchString(r.ArgsSHA256) {
		return "", "", errBadRequest
	}
	code, b, err := c.post(ctx, "/internal/confirmations/consume", r)
	if err != nil {
		return "", "", err
	}
	switch code {
	case http.StatusOK:
		var a struct {
			ID string `json:"id"`
		}
		if strict(b, &a, "id") && validConfirmID(a.ID) {
			return a.ID, StateConsumed, nil
		}
		return "", "", unavailable("malformed consume answer")
	case http.StatusNotFound:
		return "", StateNone, nil
	case http.StatusConflict:
		var a struct {
			State string `json:"state"`
		}
		if strict(b, &a, "state") && (a.State == StatePending || a.State == StateDeclined) {
			return "", a.State, nil
		}
		return "", "", unavailable("malformed 409")
	}
	return "", "", unavailable(fmt.Sprintf("status %d", code))
}
