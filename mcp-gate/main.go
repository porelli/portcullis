// Command mcp-gate is Portcullis' MCP gate (integration contract §15): it
// terminates every MCP request, checks the Keycloak access token for
// exactly the resource the request's Host and path name, checks that the
// person is in that resource's population right now, and serves each
// resource's RFC 9728 metadata. It reads the Hub's files in hub_data
// read-only (§4.2, §15.4).
//
//	mcp-gate [serve]      run the gate
//	mcp-gate keygen       print a new age X25519 identity (secrets/mcp-gate/age.key);
//	                      its recipient (age.pub) is the "# public key:" line
//	mcp-gate healthcheck  exit 0 if the gate answers /healthz (Docker HEALTHCHECK)
//
// Environment: MCP_GATE_LISTEN (:8080), MCP_GATE_HUB_DATA (/hub-data),
// MCP_GATE_DATA (/data), MCP_GATE_AGE_KEY_FILE, MCP_GATE_HUB_SECRET_FILE,
// MCP_GATE_JWKS_URL, MCP_GATE_HUB_URL (http://hub:8890).
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/portcullis/mcp-gate/internal/authz"
	"github.com/portcullis/mcp-gate/internal/config"
	"github.com/portcullis/mcp-gate/internal/meta"
)

const (
	defaultListen     = ":8080"
	defaultHubData    = "/hub-data"
	defaultData       = "/data"
	defaultAgeKey     = "/run/portcullis/mcp-gate/age.key"
	defaultHubSecret  = "/run/portcullis/mcp-gate/hub-secret"
	defaultJWKS       = "http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs"
	defaultHubURL     = "http://hub:8890"
	minHubSecretChars = 32
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "keygen":
		id, err := age.GenerateX25519Identity()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), id.Recipient(), id)
	case "healthcheck":
		os.Exit(healthcheck(env("MCP_GATE_LISTEN", defaultListen)))
	case "serve":
		if err := serve(); err != nil {
			log.Fatalf("mcp-gate: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: mcp-gate [serve|keygen|healthcheck]\n")
		os.Exit(2)
	}
}

func healthcheck(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func loadIdentity(path string) (age.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("age identity: %w", err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil || len(ids) != 1 {
		return nil, fmt.Errorf("age identity %s: not exactly one X25519 identity", path)
	}
	if _, ok := ids[0].(*age.X25519Identity); !ok {
		return nil, fmt.Errorf("age identity %s: not an X25519 identity", path)
	}
	return ids[0], nil
}

func loadHubSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("hub secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if len(s) < minHubSecretChars {
		return "", fmt.Errorf("hub secret %s: shorter than %d characters", path, minHubSecretChars)
	}
	return s, nil
}

func serve() error {
	ident, err := loadIdentity(env("MCP_GATE_AGE_KEY_FILE", defaultAgeKey))
	if err != nil {
		return err
	}
	// Checked at start; the Hub API client (mint, confirmations) uses it.
	if _, err := loadHubSecret(env("MCP_GATE_HUB_SECRET_FILE", defaultHubSecret)); err != nil {
		return err
	}
	store, err := config.Open(env("MCP_GATE_HUB_DATA", defaultHubData), ident)
	if err != nil {
		return err
	}
	defer store.Close()
	v := authz.NewVerifier("", env("MCP_GATE_JWKS_URL", defaultJWKS), nil)

	srv := &http.Server{
		Addr:              env("MCP_GATE_LISTEN", defaultListen),
		Handler:           newHandler(store.Snapshot, v),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("mcp-gate: listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newHandler: /healthz (loopback only), the metadata documents, and every
// other request through authz. Nothing here sets or reads a cookie.
func newHandler(snap func() *config.Snapshot, v *authz.Verifier) http.Handler {
	metaH := meta.Handler(snap)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && isLoopback(r.RemoteAddr) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		if strings.HasPrefix(r.URL.Path, meta.Prefix) {
			metaH.ServeHTTP(w, r)
			return
		}
		sn := snap()
		d := v.Check(r.Context(), sn, authz.FromHTTP(r, time.Now()))
		if !d.Allowed() {
			refuse(w, r, d)
			return
		}
		max := sn.File.Limits.MaxRequestBytes
		body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
		if err != nil {
			http.Error(w, "cannot read the request", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > max {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if _, perr := authz.CheckProtocol(r.Header, body); perr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(perr.Status)
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":null,"error":{"code":%d,"message":%q}}`, perr.Code, perr.Msg)
			return
		}
		// Forwarding to the resource's upstream comes with the bridge
		// (plan 4, tasks 3 and 5). Until then an allowed request is
		// refused: never answered without its upstream.
		log.Printf("mcp-gate: %s %s%s user=%s client=%s allow (no forwarding yet)", r.Method, d.Resource.Host, d.Resource.Path(), d.User, d.Client)
		http.Error(w, "MCP forwarding is not available in this build", http.StatusServiceUnavailable)
	})
}

func refuse(w http.ResponseWriter, r *http.Request, d authz.Decision) {
	if d.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", d.WWWAuthenticate)
	}
	// Never the Authorization header or the token.
	log.Printf("mcp-gate: %s %s%s %d deny:%s user=%s client=%s", r.Method, config.NormalizeHost(r.Host), r.URL.Path, d.Status, d.Reason, d.User, d.Client)
	http.Error(w, d.Message, d.Status)
}
