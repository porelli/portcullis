// Command mcpclient is the e2e-ai job's MCP client (plan 4 Task 30): a
// stand-in for Claude Code built on the official MCP Go SDK, so the CI
// drives mcp-gate exactly as a real client does — RFC 9728 discovery,
// Keycloak's authorization code flow with PKCE (S256) and the `resource`
// parameter, a loopback callback, then Streamable HTTP with the bearer
// token.
//
//	mcpclient login --client-id portcullis-ai-claude-code --callback-port 33418 \
//	    --resource <url> [--scope "<scope> ..."] --token-file <f> [--ca-file <pem>]
//
// prints the authorize URL on stdout (one line, flushed), serves
// http://127.0.0.1:<port>/callback, exchanges the code and writes the
// token JSON to --token-file (0600). The browser part (sign-in, consent)
// is the caller's: tests/e2e/e2e_ai.py opens the URL in Playwright.
//
//	mcpclient call --url <url> --token-file <f> --method tools/list|tools/call \
//	    [--tool <name> --args <json>] [--ca-file <pem>]
//
// prints one JSON document on stdout: {"result": …} or {"error": {code,
// message, data}} for a JSON-RPC answer (exit 0), {"http_status": N,
// "www_authenticate": "…"} when the HTTP layer refused (exit 2). Any other
// failure exits 1 with the reason on stderr.
//
// CI only: every host of the test stack resolves to 127.0.0.1, so the HTTP
// client dials itself (which opts out of the SDK's discovery SSRF checks
// for private addresses) and trusts --ca-file. Tokens never go on argv or
// in output; the token file is the only place they are written.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	code := 0
	switch os.Args[1] {
	case "login":
		err = login(os.Args[2:])
	case "call":
		code, err = call(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpclient:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mcpclient login|call [flags] (see the source header)")
	os.Exit(2)
}

// httpClient trusts caFile (plus the system roots) and dials the address
// it is given itself.
func httpClient(caFile string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificate", caFile)
		}
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Client{
		Timeout: 150 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         d.DialContext,
			TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}, nil
}

// tokenFile is what login writes and call reads.
type tokenFile struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
	Scope        string    `json:"scope,omitempty"`
	Resource     string    `json:"resource"`
	ClientID     string    `json:"client_id"`
}

func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	clientID := fs.String("client-id", "", "pre-registered public client id")
	port := fs.Int("callback-port", 33418, "loopback callback port (127.0.0.1)")
	resource := fs.String("resource", "", "the MCP resource URL")
	scope := fs.String("scope", "", "space-separated scopes to request (default: the resource's challenge)")
	out := fs.String("token-file", "", "where to write the token JSON")
	caFile := fs.String("ca-file", "", "extra CA certificates (PEM)")
	wait := fs.Duration("timeout", 5*time.Minute, "how long to wait for the callback")
	_ = fs.Parse(args)
	if *clientID == "" || *resource == "" || *out == "" {
		return errors.New("login needs --client-id, --resource and --token-file")
	}
	hc, err := httpClient(*caFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()

	redirect := "http://127.0.0.1:" + strconv.Itoa(*port) + "/callback"
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	results := make(chan *auth.AuthorizationResult, 1)
	var once sync.Once
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			fmt.Fprintf(os.Stderr, "mcpclient: authorization error %q: %s\n", e, q.Get("error_description"))
			http.Error(w, "authorization failed", http.StatusBadRequest)
			once.Do(func() { results <- nil })
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "mcpclient: signed in, you can close this tab\n")
		once.Do(func() {
			results <- &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}
		})
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cfg := &auth.AuthorizationCodeHandlerConfig{
		PreregisteredClient: &oauthex.ClientCredentials{ClientID: *clientID},
		RedirectURL:         redirect,
		Client:              hc,
		AuthorizationCodeFetcher: func(ctx context.Context, a *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			fmt.Println(a.URL)
			_ = os.Stdout.Sync()
			select {
			case res := <-results:
				if res == nil {
					return nil, errors.New("the authorization server answered with an error")
				}
				return res, nil
			case <-ctx.Done():
				return nil, fmt.Errorf("no callback: %w", ctx.Err())
			}
		},
	}
	if *scope != "" {
		want := strings.Fields(*scope)
		cfg.ScopeFilter = func([]string) []string { return want }
	}
	h, err := auth.NewAuthorizationCodeHandler(cfg)
	if err != nil {
		return err
	}

	// A real first request: the resource's 401 and its challenge start
	// the SDK's flow (RFC 9728 metadata, then the AS metadata).
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"portcullis-e2e","version":"1"}}}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *resource, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		resp.Body.Close()
		return fmt.Errorf("%s answered %d without a token (want 401)", *resource, resp.StatusCode)
	}
	if err := h.Authorize(ctx, req, resp); err != nil {
		return err
	}
	ts, err := h.TokenSource(ctx)
	if err != nil {
		return err
	}
	tok, err := ts.Token()
	if err != nil {
		return err
	}
	tf := tokenFile{AccessToken: tok.AccessToken, TokenType: tok.TokenType, RefreshToken: tok.RefreshToken,
		Expiry: tok.Expiry, Resource: *resource, ClientID: *clientID}
	if s, ok := tok.Extra("scope").(string); ok {
		tf.Scope = s
	}
	b, err := json.Marshal(tf)
	if err != nil {
		return err
	}
	tmp := *out + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, *out); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "mcpclient: token written, scope:", tf.Scope)
	return nil
}

// statusRecorder keeps the last refused HTTP answer of the transport.
type statusRecorder struct {
	base  http.RoundTripper
	token string
	mu    sync.Mutex
	code  int
	www   string
}

func (s *statusRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.base.RoundTrip(r)
	if err == nil && resp.StatusCode >= 400 {
		s.mu.Lock()
		s.code, s.www = resp.StatusCode, resp.Header.Get("WWW-Authenticate")
		s.mu.Unlock()
	}
	return resp, err
}

func call(args []string) (int, error) {
	fs := flag.NewFlagSet("call", flag.ExitOnError)
	endpoint := fs.String("url", "", "the MCP resource URL")
	tokFile := fs.String("token-file", "", "token JSON written by login")
	method := fs.String("method", "tools/list", "tools/list or tools/call")
	tool := fs.String("tool", "", "tool name (tools/call)")
	argJSON := fs.String("args", "{}", "tool arguments, a JSON object (tools/call)")
	caFile := fs.String("ca-file", "", "extra CA certificates (PEM)")
	_ = fs.Parse(args)
	if *endpoint == "" || *tokFile == "" {
		return 1, errors.New("call needs --url and --token-file")
	}
	if _, err := url.Parse(*endpoint); err != nil {
		return 1, err
	}
	raw, err := os.ReadFile(*tokFile)
	if err != nil {
		return 1, err
	}
	var tf tokenFile
	if err := json.Unmarshal(raw, &tf); err != nil || tf.AccessToken == "" {
		return 1, errors.New("token file: no access_token")
	}
	hc, err := httpClient(*caFile)
	if err != nil {
		return 1, err
	}
	rec := &statusRecorder{base: hc.Transport, token: tf.AccessToken}
	hc.Transport = rec

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "portcullis-e2e", Version: "1"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: *endpoint, HTTPClient: hc,
		MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return answer(rec, nil, err)
	}
	defer sess.Close()
	switch *method {
	case "tools/list":
		res, err := sess.ListTools(ctx, nil)
		return answer(rec, res, err)
	case "tools/call":
		if *tool == "" {
			return 1, errors.New("tools/call needs --tool")
		}
		var a map[string]any
		if err := json.Unmarshal([]byte(*argJSON), &a); err != nil {
			return 1, fmt.Errorf("--args: %v", err)
		}
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: *tool, Arguments: a})
		return answer(rec, res, err)
	default:
		return 1, fmt.Errorf("unknown --method %q", *method)
	}
}

// answer prints the one JSON document call promises.
func answer(rec *statusRecorder, res any, err error) (int, error) {
	enc := json.NewEncoder(os.Stdout)
	if err == nil {
		return 0, enc.Encode(map[string]any{"result": res})
	}
	// An HTTP refusal first: the SDK reports some of them (a 503, say) as
	// a JSON-RPC error of its own ("rejected by transport"), which the
	// server never sent.
	rec.mu.Lock()
	code, www := rec.code, rec.www
	rec.mu.Unlock()
	if code != 0 {
		if e := enc.Encode(map[string]any{"http_status": code, "www_authenticate": www}); e != nil {
			return 1, e
		}
		return 2, nil
	}
	var we *jsonrpc.Error
	if errors.As(err, &we) {
		return 0, enc.Encode(map[string]any{"error": we})
	}
	return 1, err
}
