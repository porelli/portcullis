// Package meta serves each resource's OAuth protected resource metadata
// (RFC 9728, integration contract §15.1) at
// GET /.well-known/oauth-protected-resource<path> on the resource's own
// host: no authentication, no cookie.
package meta

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/portcullis/mcp-gate/internal/config"
)

// Prefix of every metadata path.
const Prefix = "/.well-known/oauth-protected-resource"

type document struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name"`
}

// Handler answers metadata requests from the current snapshot. The
// resource comes from r.Host and the path only (preflight G22).
func Handler(sn func() *config.Snapshot) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s := sn()
		if s == nil || s.Err != nil || s.Off || s.File == nil || !s.File.Enabled {
			http.Error(w, "AI support is off on this Portcullis", http.StatusServiceUnavailable)
			return
		}
		path, ok := strings.CutPrefix(r.URL.Path, Prefix)
		if !ok || path == "" {
			http.NotFound(w, r)
			return
		}
		res, ok := s.Resource(r.Host, path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := json.Marshal(document{
			Resource:               res.URL,
			AuthorizationServers:   []string{s.File.Issuer}, // https://auth.<main domain>/realms/portcullis (validated)
			ScopesSupported:        []string{res.Scope},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           res.Label + " on Portcullis",
		})
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
}
