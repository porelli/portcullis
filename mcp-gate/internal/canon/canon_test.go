package canon

import (
	"encoding/json"
	"strings"
	"testing"
)

// Different raw inputs with the same meaning → the same canonical bytes,
// which are what the gate hashes AND forwards.
func TestSameMeaningSameBytes(t *testing.T) {
	want := `{"a":"é","b":1,"c":[100,0.1,0,-2.5],"d":{"x":true,"y":null}}`
	for _, in := range []string{
		`{"b":1,"a":"é","c":[100,0.1,0,-2.5],"d":{"y":null,"x":true}}`,
		` { "d" : { "x" : true , "y" : null } , "c" : [ 1e2 , 0.10 , -0 , -2.50 ] , "b" : 1.0 , "a" : "é" } `,
	} {
		got, err := Arguments(json.RawMessage(in))
		if err != nil || string(got) != want {
			t.Errorf("%s → %s %v", in, got, err)
		}
	}
	for _, in := range []string{"", "null", " null "} {
		if got, err := Arguments(json.RawMessage(in)); err != nil || string(got) != "{}" {
			t.Errorf("%q → %s %v", in, got, err)
		}
	}
}

// Inputs that can't round-trip are refused, never silently changed.
func TestRefusesWhatCantRoundTrip(t *testing.T) {
	for name, in := range map[string]string{
		"big integer":        `{"a":12345678901234567890}`,
		"above safe integer": `{"a":9007199254740993}`,
		"2^53":               `{"a":9007199254740992}`,
		"big negative":       `{"a":-9007199254740992}`,
		"large float":        `{"a":1e300}`,
		"precision lost":     `{"a":0.30000000000000000001}`,
		"overflow":           `{"a":1e400}`,
		"huge exponent":      `{"a":1e-1000000}`,
		"long number":        `{"a":1.` + strings.Repeat("0", 100) + `1}`,
		"duplicate top":      `{"a":1,"a":2}`,
		"duplicate nested":   `{"a":{"x":1,"x":1}}`,
		"duplicate in array": `{"a":[{"x":1,"x":2}]}`,
		"duplicate escaped":  `{"a":1,"\u0061":1}`,
		"lone surrogate":     `{"a":"\ud800"}`,
		"line separator":     `{"a":"\u2028"}`,
		"paragraph raw":      "{\"a\":\"\u2029\"}",
		"invalid utf-8":      "{\"a\":\"\xff\"}",
		"not an object":      `[1]`,
		"string":             `"x"`,
		"trailing":           `{"a":1} {}`,
		"broken":             `{"a":`,
		"too deep":           `{"a":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}`,
	} {
		if got, err := Arguments(json.RawMessage(in)); err == nil {
			t.Errorf("%s: accepted as %s", name, got)
		}
	}
	// The largest safe integer is fine.
	if got, err := Arguments(json.RawMessage(`{"a":9007199254740991,"b":-9007199254740991}`)); err != nil || string(got) != `{"a":9007199254740991,"b":-9007199254740991}` {
		t.Errorf("safe integers: %s %v", got, err)
	}
}
