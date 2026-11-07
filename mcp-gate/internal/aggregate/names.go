package aggregate

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"slices"
	"strings"
)

// maxNameLen: longer aggregate names are shortened (§15.9).
const maxNameLen = 64

// PortcullisPrefix is the people tools' prefix (§15.9). No instance id has
// "portcullis" as a segment or contains "_" (§3), so no companion prefix
// can be confused with it or with another companion's.
const PortcullisPrefix = "portcullis"

func hex8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// ToolName is the aggregate's name of an upstream's tool or prompt:
// "<instance>__<tool>", and a name longer than 64 characters becomes its
// first 55 characters + "_" + the first 8 hex digits of sha256(the full
// name) (§15.9). Names are only ever looked up in a Table, never parsed.
func ToolName(instance, tool string) string {
	n := instance + "__" + tool
	if len(n) <= maxNameLen {
		return n
	}
	return n[:55] + "_" + hex8(n)
}

// Item is one upstream name going into a table: the upstream's prefix
// (instance id or "portcullis"), its resource URL and its own name.
type Item struct {
	Prefix, URL, Name string
}

// Target is where an aggregate name goes: the upstream resource's URL and
// the name its server knows.
type Target struct {
	URL, Name string
}

// Table maps aggregate names to targets (G24).
type Table map[string]Target

// BuildTable names every item. Two items whose names collide — literally,
// after shortening, or after case folding (stricter: a client may compare
// names without case) — are both dropped and returned in dropped (the
// names as they would have been); an item twice from one upstream counts
// as a collision too. The table is the only way back from a name.
func BuildTable(items []Item) (t Table, dropped []string) {
	byKey := map[string][]int{}
	full := make([]string, len(items))
	for i, it := range items {
		full[i] = ToolName(it.Prefix, it.Name)
		k := strings.ToLower(full[i])
		byKey[k] = append(byKey[k], i)
	}
	t = Table{}
	for _, idx := range byKey {
		if len(idx) > 1 {
			for _, i := range idx {
				dropped = append(dropped, full[i])
			}
			continue
		}
		it := items[idx[0]]
		t[full[idx[0]]] = Target{URL: it.URL, Name: it.Name}
	}
	slices.Sort(dropped)
	return t, dropped
}

// warnDropped logs the template warning for colliding names (once per
// refresh that finds them).
func warnDropped(kind string, dropped []string) {
	if len(dropped) > 0 {
		log.Printf("mcp-gate: template warning: aggregate %s names collide and are dropped: %s", kind, strings.Join(dropped, ", "))
	}
}
