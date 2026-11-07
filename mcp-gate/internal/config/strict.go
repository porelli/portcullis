package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"
)

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

func typeOf(v any) reflect.Type { return reflect.TypeOf(v).Elem() }

// checkShape walks the JSON against the Go type: objects of struct types
// have exactly the struct's json keys (case-sensitive; omitempty keys may
// be absent), no object has a duplicate key, and nothing is null.
// encoding/json alone matches keys case-insensitively, keeps the last of
// duplicate keys and silently leaves missing fields at their zero value.
// Errors carry JSON paths, never values.
func checkShape(raw []byte, t reflect.Type, path string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s: null", path)
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil // a leaf with its own decoder (Time)
	}
	switch t.Kind() {
	case reflect.Struct:
		keys, vals, err := object(raw, path)
		if err != nil {
			return err
		}
		type field struct {
			t         reflect.Type
			omitempty bool
		}
		fields := map[string]field{}
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			tag := sf.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if name == "-" || name == "" {
				continue
			}
			fields[name] = field{sf.Type, strings.Contains(opts, "omitempty")}
		}
		present := map[string]bool{}
		for i, k := range keys {
			f, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown field %q", path, k)
			}
			present[k] = true
			if err := checkShape(vals[i], f.t, path+"."+k); err != nil {
				return err
			}
		}
		for name, f := range fields {
			if !present[name] && !f.omitempty {
				return fmt.Errorf("%s: missing field %q", path, name)
			}
		}
	case reflect.Map:
		keys, vals, err := object(raw, path)
		if err != nil {
			return err
		}
		for i := range keys {
			if err := checkShape(vals[i], t.Elem(), path+"["+fmt.Sprintf("%q", keys[i])+"]"); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s: not a list", path)
		}
		for i, it := range items {
			if err := checkShape(it, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// object splits a JSON object into its keys and raw values, in order,
// refusing duplicate keys.
func object(raw []byte, path string) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, nil, fmt.Errorf("%s: not an object", path)
	}
	var keys []string
	var vals []json.RawMessage
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: malformed object", path)
		}
		k, _ := tok.(string)
		if seen[k] {
			return nil, nil, fmt.Errorf("%s: duplicate key %q", path, k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("%s: malformed object", path)
		}
		keys = append(keys, k)
		vals = append(vals, v)
	}
	return keys, vals, nil
}

func isUTF8(s string) bool { return utf8.ValidString(s) }
