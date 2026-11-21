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

// Types is the schema snapshot's type information the secret data-flow
// check needs: each schema's fields, each multi-variant object's variants.
type Types struct {
	Schemas map[string]struct {
		Type       string `json:"type"`
		SchemaName string `json:"schemaName"`
		Variants   []struct {
			Name       string `json:"name"`
			SchemaName string `json:"schemaName"`
		} `json:"variants"`
	} `json:"schemas"`
	Fields map[string]struct {
		Properties map[string]struct {
			Type FieldType `json:"type"`
		} `json:"properties"`
	} `json:"fields"`
}

// FieldType is one field's type.
type FieldType struct {
	Type       string     `json:"type"`
	Format     string     `json:"format"`
	ObjectName string     `json:"objectName"`
	Class      *FieldType `json:"class"`
}

// ParseTypes reads a schema snapshot (testdata/schema-v1.1.0.json).
func ParseTypes(schema []byte) (*Types, error) {
	var t Types
	if err := json.Unmarshal(schema, &t); err != nil {
		return nil, err
	}
	if len(t.Fields) == 0 {
		return nil, fmt.Errorf("schema: no fields")
	}
	return &t, nil
}

// masked: a value of this type reads back masked ("****" or a file
// reference): Stalwart's secret formats and x:Secret* objects.
func (ft FieldType) masked() bool {
	return ft.Format == "secret" || ft.Format == "secretText" || strings.HasPrefix(ft.ObjectName, "x:Secret")
}

// schemasFor are the field schemas of object name on (x:<Obj>), narrowed
// to the variant the value names with "@type" when it does.
func (t *Types) schemasFor(on string, v map[string]any) []string {
	d, ok := t.Schemas[on]
	if !ok {
		if _, f := t.Fields[on]; f {
			return []string{on}
		}
		return nil
	}
	if d.Type == "single" {
		return []string{d.SchemaName}
	}
	vt, _ := v["@type"].(string)
	var all []string
	for _, x := range d.Variants {
		if x.SchemaName == "" {
			continue
		}
		if vt != "" && x.Name == vt {
			return []string{x.SchemaName}
		}
		all = append(all, x.SchemaName)
	}
	return all
}

// field is property p's type in any of schemas (ok false: unknown).
// Without a known variant it fails closed (N3): a property plain in any
// candidate variant is plain.
func (t *Types) field(schemas []string, p string) (FieldType, bool) {
	var first FieldType
	found := false
	for _, s := range schemas {
		if f, ok := t.Fields[s].Properties[p]; ok {
			if !f.Type.masked() {
				return f.Type, true
			}
			if !found {
				first, found = f.Type, true
			}
		}
	}
	return first, found
}

// ViewerSecretLeaks is the data-flow check of a secret value (security
// review N4, R2-M1): the paths of a stored or written object of type obj
// (without x:) where sentinel (a secret mailctl wrote from one of its
// sources) would reach the viewer. A denied object leaks nothing; in a
// readable one, the value is walked along the object's own schema — its
// variant by "@type", embedded objects by their own types, JSON-pointer
// patch keys segment by segment — and a field leaks unless its type is
// masked (secret / secretText / x:Secret*). An unknown field counts as
// plain (fail closed).
func ViewerSecretLeaks(t *Types, obj string, value any, sentinel string) []string {
	if sentinel == "" || !ViewerReadsObject(obj) {
		return nil
	}
	var out []string
	var walk func(v any, ft FieldType, typed bool, path string)
	// walkObj walks a map that is an object of type on.
	walkObj := func(m map[string]any, on string, path string) {
		schemas := t.schemasFor(on, m)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "@type" || k == "id" {
				walk(m[k], FieldType{Type: "string"}, true, path+"."+k)
				continue
			}
			segs := strings.Split(k, "/")
			ft, ok := t.field(schemas, segs[0])
			// A pointer key (a patch): descend through its segments.
			for _, s := range segs[1:] {
				if !ok {
					break
				}
				switch {
				case ft.masked():
				case ft.Type == "objectList" || ft.Type == "map" || ft.Type == "set":
					if ft.Class != nil {
						ft = *ft.Class
					} else if ft.ObjectName != "" {
						ft = FieldType{Type: "object", ObjectName: ft.ObjectName}
					} else {
						ft = FieldType{Type: "string"}
					}
				case ft.Type == "object":
					ft, ok = t.field(t.schemasFor(ft.ObjectName, nil), s)
				}
			}
			walk(m[k], ft, ok, path+"."+k)
		}
	}
	walk = func(v any, ft FieldType, typed bool, path string) {
		if typed && ft.masked() {
			return
		}
		switch x := v.(type) {
		case map[string]any:
			switch {
			case typed && ft.Type == "object" && ft.ObjectName != "" && ft.ObjectName != "x:Expression":
				walkObj(x, ft.ObjectName, path)
				return
			case typed && (ft.Type == "objectList" || (ft.Type == "map" || ft.Type == "set") && ft.Class != nil && ft.Class.ObjectName != ""):
				on := ft.ObjectName
				if ft.Class != nil && ft.Class.ObjectName != "" {
					on = ft.Class.ObjectName
				}
				for _, k := range sortedKeys(x) {
					if m, ok := x[k].(map[string]any); ok {
						walkObj(m, on, path+"."+k)
					} else {
						walk(x[k], FieldType{}, false, path+"."+k)
					}
				}
				return
			}
			// Untyped or plain (an expression, a string map): every string.
			for _, k := range sortedKeys(x) {
				walk(x[k], FieldType{}, false, path+"."+k)
				if strings.Contains(k, sentinel) {
					out = append(out, obj+path+"."+k)
				}
			}
		case []any:
			for i, e := range x {
				walk(e, ft, typed && ft.Type != "object", fmt.Sprintf("%s[%d]", path, i))
			}
		case string:
			if strings.Contains(x, sentinel) {
				out = append(out, obj+path)
			}
		}
	}
	if m, ok := value.(map[string]any); ok {
		walkObj(m, "x:"+obj, "")
	} else {
		walk(value, FieldType{}, false, "")
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
