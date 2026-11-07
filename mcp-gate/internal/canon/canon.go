// Package canon is the one form of tools/call arguments the gate uses
// (integration contract §15.6; security review of task 3b): the RFC 8785
// canonical JSON (gowebpki/jcs). The gate hashes it (args_sha256, the
// confirmation binding) and forwards exactly these bytes upstream, so the
// companion can never act on arguments other than the ones the person
// confirmed — no parser differential between the hash and the call.
//
// Arguments that can't round-trip are refused, never silently changed:
// duplicate keys at any level, numbers outside the IEEE-754 safe-integer
// range (|n| > 2^53 − 1), and numbers whose canonical text denotes a
// different decimal value than the input (precision loss), and U+2028 /
// U+2029 (the SDK's encoder re-escapes them). Equal values
// written differently (1.0 / 1, 1e2 / 100, -0 / 0) are the same
// arguments.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	maxDepth     = 64
	maxNumberLen = 40  // bytes of one number's text
	maxExponent  = 350 // |exponent| of one number
	maxSafeInt   = 1<<53 - 1
)

// ErrArguments: the arguments can't be canonicalised without changing them.
var ErrArguments = errors.New("arguments can't be passed on unchanged")

// Arguments returns the canonical bytes of tools/call arguments: absent or
// null = {}; otherwise exactly one JSON object.
func Arguments(raw json.RawMessage) ([]byte, error) {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return []byte("{}"), nil
	}
	if t[0] != '{' || !utf8.Valid(t) {
		return nil, ErrArguments
	}
	if err := check(t); err != nil {
		return nil, err
	}
	c, err := jcs.Transform(t)
	if err != nil {
		return nil, ErrArguments
	}
	// JCS writes U+2028 / U+2029 raw; Go's JSON encoder (the SDK client's)
	// re-escapes them, so the forwarded bytes would differ from the
	// hashed ones. Refused: the gate forwards exactly what it hashed.
	if bytes.ContainsRune(c, '\u2028') || bytes.ContainsRune(c, '\u2029') {
		return nil, ErrArguments
	}
	return c, nil
}

// check walks the tokens: one value, no trailing data, no duplicate keys,
// bounded depth, every number exactly representable.
func check(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := value(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrArguments
	}
	return nil
}

func value(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return ErrArguments
	}
	tok, err := dec.Token()
	if err != nil {
		return ErrArguments
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return ErrArguments
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrArguments
				}
				seen[key] = true
				if err := value(dec, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(dec, depth+1); err != nil {
					return err
				}
			}
		default:
			return ErrArguments
		}
		if _, err := dec.Token(); err != nil { // the closing delimiter
			return ErrArguments
		}
	case json.Number:
		return number(string(v))
	}
	return nil
}

// number: the canonical text must denote exactly the input's value.
func number(s string) error {
	if len(s) > maxNumberLen {
		return ErrArguments
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(strings.TrimPrefix(s[i+1:], "+"))
		if err != nil || e > maxExponent || e < -maxExponent {
			return ErrArguments
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || math.Abs(f) > maxSafeInt {
		return ErrArguments
	}
	text, err := jcs.NumberToJSON(f)
	if err != nil {
		return ErrArguments
	}
	in, ok1 := new(big.Rat).SetString(s)
	out, ok2 := new(big.Rat).SetString(text)
	if !ok1 || !ok2 || in.Cmp(out) != 0 {
		return ErrArguments
	}
	return nil
}
