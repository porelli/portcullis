// Package spamrules serves the vendored Stalwart spam filter rules
// (stalwartlabs/spam-filter v3.0.4, contract §19.8) to Stalwart over
// portcullis-mail, so the spam filter never downloads them from GitHub.
package spamrules

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// SHA256 pins the vendored file (the release asset's digest).
const SHA256 = "604cc4386b1574e95185d37cb9c194ac20d360cca3865960b6ed0edf70475562"

// Version is the vendored release (stalwartlabs/spam-filter).
const Version = "v3.0.4"

// Path is the one path served.
const Path = "/spam-filter-rules.json.gz"

//go:embed spam-filter-rules.json.gz
var rules []byte

// Rules returns the embedded file.
func Rules() []byte { return rules }

// Handler serves the file at Path (GET / HEAD) and 404s everything else.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != Path || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(rules)))
		if r.Method == http.MethodGet {
			w.Write(rules)
		}
	})
}

// HTTPLookups returns the rules file's HttpLookup objects (the external
// feeds the import would create enabled).
func HTTPLookups() ([]map[string]any, error) {
	zr, err := gzip.NewReader(bytes.NewReader(rules))
	if err != nil {
		return nil, fmt.Errorf("spam rules: %w", err)
	}
	var doc struct {
		HttpLookup []map[string]any `json:"HttpLookup"`
	}
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		return nil, fmt.Errorf("spam rules: %w", err)
	}
	return doc.HttpLookup, nil
}

// RuleNames are the vendored file's SpamRule names (the import's proof:
// every one of them in Stalwart).
func RuleNames() ([]string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(rules))
	if err != nil {
		return nil, fmt.Errorf("spam rules: %w", err)
	}
	var doc struct {
		SpamRule []struct {
			Name string `json:"name"`
		} `json:"SpamRule"`
	}
	if err := json.NewDecoder(zr).Decode(&doc); err != nil {
		return nil, fmt.Errorf("spam rules: %w", err)
	}
	out := make([]string, 0, len(doc.SpamRule))
	for _, r := range doc.SpamRule {
		if r.Name != "" {
			out = append(out, r.Name)
		}
	}
	return out, nil
}
