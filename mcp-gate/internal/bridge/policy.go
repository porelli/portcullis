package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/portcullis/mcp-gate/internal/config"
	mcp "github.com/portcullis/mcp-gate/internal/mcpsdk"
)

// Tool policy (contract §15.5, preflight G23). Patterns are the template's
// writes / confirm / never lists: "*" globs, matched case-folded on both
// sides; "tool:method" matches the tool whose arguments' method equals
// method. Every tools/call is decided here, listed or not.

// Tool names the gate passes (MCP 2025-11-25 naming rules): anything else
// is hidden and refused, so a name can never be read two ways (":" would
// split a pattern; control or look-alike characters would dodge a glob).
var toolNameR = regexp.MustCompile(`^[A-Za-z0-9_.\-/]{1,128}$`)

// ValidToolName reports a tool name the gate lists and calls.
func ValidToolName(name string) bool { return toolNameR.MatchString(name) }

func fold(s string) string { return strings.ToLower(s) }

// glob matches folded s against folded pattern p, where "*" is any run.
func glob(p, s string) bool {
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return p == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return strings.HasSuffix(s, last)
}

// Match reports whether pattern matches the tool (and, for a "tool:method"
// pattern, the call's arguments.method). Case-folded on both sides.
func Match(pattern, tool, method string) bool {
	pt, pm, hasMethod := strings.Cut(fold(pattern), ":")
	if !glob(pt, fold(tool)) {
		return false
	}
	if !hasMethod {
		return true
	}
	return method != "" && glob(pm, fold(method))
}

// argInfo is what the policy reads from a call's arguments.
type argInfo struct {
	methods []string // string values of every key folding to "method"
	unknown bool     // such a key holds something else: counts as matching
}

func (a argInfo) match(pattern, tool string) bool {
	pt, _, hasMethod := strings.Cut(pattern, ":")
	if !hasMethod {
		return Match(pattern, tool, "")
	}
	if !Match(pt, tool, "") {
		return false
	}
	if a.unknown {
		return true // fail closed: every list makes the call stricter
	}
	for _, m := range a.methods {
		if Match(pattern, tool, m) {
			return true
		}
	}
	return false
}

func matchAny(patterns []string, tool string, a argInfo) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { return a.match(p, tool) })
}

var errBadArgs = errors.New("bad arguments")

// inspectArgs accepts absent / null arguments or one JSON object in valid
// UTF-8 whose keys are unique at every level, top-level keys also unique
// after case folding (a Go companion reads "Method" as method).
func inspectArgs(raw json.RawMessage) (argInfo, error) {
	var info argInfo
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return info, nil
	}
	if !utf8.Valid(t) || t[0] != '{' {
		return info, errBadArgs
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	if err := checkValue(dec, 0, &info); err != nil {
		return info, errBadArgs
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return info, errBadArgs
	}
	return info, nil
}

const maxArgDepth = 64

// checkValue walks one value; depth 0 is the arguments object itself.
func checkValue(dec *json.Decoder, depth int, info *argInfo) error {
	if depth > maxArgDepth {
		return errBadArgs
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '[':
		for dec.More() {
			if err := checkValue(dec, depth+1, info); err != nil {
				return err
			}
		}
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			key := k
			if depth == 0 {
				key = fold(k)
			}
			if seen[key] {
				return errBadArgs
			}
			seen[key] = true
			if depth == 0 && key == "method" {
				var v json.RawMessage
				if err := dec.Decode(&v); err != nil {
					return err
				}
				var s string
				if len(v) > 0 && v[0] == '"' && json.Unmarshal(v, &s) == nil {
					info.methods = append(info.methods, s)
				} else {
					info.unknown = true
				}
				// Re-check the value's own shape (duplicates inside it).
				sub := json.NewDecoder(bytes.NewReader(v))
				if err := checkValue(sub, depth+1, info); err != nil {
					return err
				}
				continue
			}
			if err := checkValue(dec, depth+1, info); err != nil {
				return err
			}
		}
	}
	_, err = dec.Token() // the closing delimiter
	return err
}

// FilterTools is what tools/list shows: never hidden in every mode, writes
// hidden in read-only mode, invalid names hidden. A "tool:method" pattern
// never hides the tool itself (other methods stay callable); annotations
// never unhide anything.
func FilterTools(res *config.Resource, tools []*mcp.Tool) []*mcp.Tool {
	out := make([]*mcp.Tool, 0, len(tools))
	for _, t := range tools {
		if t == nil || !ValidToolName(t.Name) {
			continue
		}
		if listHides(res.Tools.Never, t.Name) {
			continue
		}
		if res.Mode != "read_write" && listHides(res.Tools.Writes, t.Name) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func listHides(patterns []string, tool string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool {
		return !strings.Contains(p, ":") && Match(p, tool, "")
	})
}

// CallDecision decides one tools/call from the template's policy and the
// admin's mode, listed or not (G23). ann is the tool's annotations from the
// gate's own cached tools/list of that upstream (nil when unknown): an
// explicit destructiveHint adds a confirmation, nothing ever removes one.
// reason is the access-log reason: allow, confirm, destructive, never,
// read_only, bad_tool or bad_arguments.
func CallDecision(res *config.Resource, tool string, args json.RawMessage, ann *mcp.ToolAnnotations) (allow, confirm bool, reason string) {
	if !ValidToolName(tool) {
		return false, false, "bad_tool"
	}
	info, err := inspectArgs(args)
	if err != nil {
		return false, false, "bad_arguments"
	}
	if matchAny(res.Tools.Never, tool, info) {
		return false, false, "never"
	}
	// Anything but an explicit read_write is read-only (fail closed).
	if res.Mode != "read_write" && matchAny(res.Tools.Writes, tool, info) {
		return false, false, "read_only"
	}
	if matchAny(res.Tools.Confirm, tool, info) {
		return true, true, "confirm"
	}
	if ann != nil && ann.DestructiveHint != nil && *ann.DestructiveHint {
		return true, true, "destructive"
	}
	return true, false, "allow"
}

// urlElicitationAllowed: a companion's URL-mode elicitation may name only
// an https:// URL on one of the resource's hosts or people.<main domain>
// (G54) — never auth., hub., mcp. or anything else. No userinfo, no port
// but 443, the host exactly as listed (lowercased).
func urlElicitationAllowed(res *config.Resource, mainDomain, raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\\ \t\r\n") || !utf8.ValidString(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host == "" {
		return false
	}
	if p := u.Port(); p != "" && p != "443" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "" || strings.HasSuffix(h, ".") || !config.ValidHostname(h) {
		return false
	}
	return slices.Contains(res.Hosts, h) || (mainDomain != "" && h == "people."+mainDomain)
}
