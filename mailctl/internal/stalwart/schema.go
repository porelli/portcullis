package stalwart

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Use is one thing mailctl sends to Stalwart (plan ruling M13): an object
// or a field of it, a variant (`@type`) of a multi-variant object, or an
// enum value (a permission name, an action, ...). Every Use must exist in
// the pinned schema snapshot (testdata/schema-v1.1.0.json, Task 2);
// TestEveryUsedFieldInSchema checks Used. An image bump refreshes the
// snapshot and must keep the test green.
//
//	{Object: "x:Domain"}                         the object (or nested schema) exists
//	{Object: "x:Domain", Field: "name"}          a field of it (any variant)
//	{Object: "x:DataStore", Variant: "RocksDb"}  a variant name
//	{Object: "x:DataStore", Variant: "RocksDb", Field: "path"}
//	{Enum: "Permission", Value: "authenticate"}  an enum value
type Use struct {
	Object, Variant, Field string
	Enum, Value            string
}

func (u Use) String() string {
	if u.Enum != "" {
		return u.Enum + "." + u.Value
	}
	s := u.Object
	if u.Variant != "" {
		s += "/" + u.Variant
	}
	if u.Field != "" {
		s += "." + u.Field
	}
	return s
}

// Used is everything mailctl's code sends. Later tasks append here, next
// to the code that sends it.
var Used = []Use{
	// The client itself (Action).
	{Object: "x:Action", Variant: "ReloadSettings"},
	{Object: "x:Action", Variant: "InvalidateCaches"},
	{Enum: "ActionType", Value: "ReloadSettings"},
	{Enum: "ActionType", Value: "InvalidateCaches"},
}

// Schema is the part of /api/schema the check reads.
type Schema struct {
	Schemas map[string]struct {
		Type       string `json:"type"`
		SchemaName string `json:"schemaName"`
		Variants   []struct {
			Name       string `json:"name"`
			SchemaName string `json:"schemaName"`
		} `json:"variants"`
	} `json:"schemas"`
	Fields map[string]struct {
		Properties map[string]json.RawMessage `json:"properties"`
	} `json:"fields"`
	Enums map[string][]struct {
		Name string `json:"name"`
	} `json:"enums"`
}

// ParseSchema decodes a /api/schema document.
func ParseSchema(b []byte) (*Schema, error) {
	var s Schema
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	if len(s.Schemas) == 0 || len(s.Fields) == 0 || len(s.Enums) == 0 {
		return nil, fmt.Errorf("schema: no schemas, fields or enums")
	}
	return &s, nil
}

// Check returns one line per Use the schema lacks (sorted), none = ok.
func (s *Schema) Check(uses []Use) []string {
	var bad []string
	for _, u := range uses {
		if why := s.check(u); why != "" {
			bad = append(bad, u.String()+": "+why)
		}
	}
	sort.Strings(bad)
	return bad
}

func (s *Schema) check(u Use) string {
	if u.Enum != "" {
		vals, ok := s.Enums[u.Enum]
		if !ok {
			return "no such enum"
		}
		for _, v := range vals {
			if v.Name == u.Value {
				return ""
			}
		}
		return "no such value"
	}
	if u.Object == "" {
		return "empty use"
	}
	// Field-holding schema names for the object (and variant).
	var names []string
	if sc, ok := s.Schemas[u.Object]; ok {
		switch sc.Type {
		case "single":
			if u.Variant != "" {
				return "not a multi-variant object"
			}
			names = append(names, sc.SchemaName)
		case "multiple":
			found := u.Variant == ""
			for _, v := range sc.Variants {
				if u.Variant != "" && v.Name != u.Variant {
					continue
				}
				found = true
				if v.SchemaName != "" {
					names = append(names, v.SchemaName)
				}
			}
			if !found {
				return "no such variant"
			}
		default:
			return "unknown schema type " + sc.Type
		}
	} else if _, ok := s.Fields[u.Object]; ok && u.Variant == "" {
		names = append(names, u.Object) // a nested field schema named directly
	} else {
		return "no such object"
	}
	if u.Field == "" {
		return ""
	}
	for _, n := range names {
		if _, ok := s.Fields[n].Properties[u.Field]; ok {
			return ""
		}
	}
	return "no such field"
}
