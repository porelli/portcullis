package stalwart

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ViewerReadsObject reports an object (its name without x:) the viewer
// role reads (contract §19.13).
func ViewerReadsObject(obj string) bool {
	return viewerMethods["x:"+obj+"/get"] || viewerMethods["x:"+obj+"/query"]
}

// SecretFieldNames are the schema's property names whose type is one of
// Stalwart's secret types (masked on every read): format secret /
// secretText, or an x:Secret* object. A value under such a key reads back
// as "****".
func SecretFieldNames(schema []byte) (map[string]bool, error) {
	var s struct {
		Fields map[string]struct {
			Properties map[string]struct {
				Type struct {
					Format     string `json:"format"`
					ObjectName string `json:"objectName"`
				} `json:"type"`
			} `json:"properties"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, f := range s.Fields {
		for name, p := range f.Properties {
			if p.Type.Format == "secret" || p.Type.Format == "secretText" || strings.HasPrefix(p.Type.ObjectName, "x:Secret") {
				out[name] = true
			}
		}
	}
	return out, nil
}

// ViewerSecretLeaks is the data-flow check of a secret value (security
// review N4): the paths in a stored object of type obj where sentinel (a
// secret mailctl wrote from one of its sources) would reach the viewer —
// every path of a viewer-readable object holding it, unless a key on the
// way is a masked secret field (secretFields), then also nested secrets
// ("privateKey": {"secret": …}) are masked. A denied object leaks nothing.
func ViewerSecretLeaks(obj string, value any, sentinel string, secretFields map[string]bool) []string {
	if sentinel == "" || !ViewerReadsObject(obj) {
		return nil
	}
	var out []string
	var walk func(v any, path string, masked bool)
	walk = func(v any, path string, masked bool) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				seg := k[strings.LastIndex(k, "/")+1:] // a JSON-pointer patch key
				walk(x[k], path+"."+k, masked || secretFields[k] || secretFields[seg])
			}
		case []any:
			for i, e := range x {
				walk(e, fmt.Sprintf("%s[%d]", path, i), masked)
			}
		case string:
			if !masked && strings.Contains(x, sentinel) {
				out = append(out, obj+path)
			}
		}
	}
	walk(value, "", false)
	return out
}
