// Package spamrules serves the vendored Stalwart spam filter rules
// (stalwartlabs/spam-filter v3.0.4, contract §19.8) to Stalwart over
// portcullis-mail, so the spam filter never downloads them from GitHub.
package spamrules

import (
	_ "embed"
	"net/http"
	"strconv"
)

// SHA256 pins the vendored file (the release asset's digest).
const SHA256 = "604cc4386b1574e95185d37cb9c194ac20d360cca3865960b6ed0edf70475562"

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
