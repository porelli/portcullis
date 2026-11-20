package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// strictVectors decodes a vector file strictly: exactly the struct's keys
// (case-sensitive; omitempty keys may be absent), no duplicate key, no
// trailing data, and null only where the Go type is a pointer or a
// json.RawMessage (the Hub's jsonstrict rules, with its Nullable as a
// pointer).
func strictVectors(b []byte, v any) error {
	if !json.Valid(b) {
		return fmt.Errorf("not valid JSON (or trailing data)")
	}
	if err := vecShape(b, reflect.TypeOf(v).Elem(), "$"); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

var vecRawType = reflect.TypeOf(json.RawMessage(nil))

func vecShape(raw []byte, t reflect.Type, path string) error {
	null := bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
	if t == vecRawType {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if null {
			return nil
		}
		return vecShape(raw, t.Elem(), path)
	}
	if null {
		return fmt.Errorf("%s: null", path)
	}
	switch t.Kind() {
	case reflect.Struct:
		if t.PkgPath() == "time" {
			return nil
		}
		keys, vals, err := vecMembers(raw, path)
		if err != nil {
			return err
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
			if name != "" && name != "-" {
				fields[name] = t.Field(i)
			}
		}
		seen := map[string]bool{}
		for i, k := range keys {
			f, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown field %q", path, k)
			}
			seen[k] = true
			if err := vecShape(vals[i], f.Type, path+"."+k); err != nil {
				return err
			}
		}
		for name, f := range fields {
			if !seen[name] && !strings.Contains(f.Tag.Get("json"), ",omitempty") {
				return fmt.Errorf("%s: missing field %q", path, name)
			}
		}
	case reflect.Map:
		keys, vals, err := vecMembers(raw, path)
		if err != nil {
			return err
		}
		for i, k := range keys {
			if err := vecShape(vals[i], t.Elem(), fmt.Sprintf("%s[%q]", path, k)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s: not a list", path)
		}
		for i, it := range items {
			if err := vecShape(it, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func vecMembers(raw []byte, path string) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
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
		keys, vals = append(keys, k), append(vals, v)
	}
	return keys, vals, nil
}
