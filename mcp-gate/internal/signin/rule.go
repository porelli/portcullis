// Package signin is the gate's reader of compiled sign-in rules
// (integration contract §8.1, §15.2, §15.4): the method table, a rule's
// strict JSON form, the readers' check of a compiled rule, meeting it, and
// the methods an access token counts for.
//
// It mirrors the Hub's internal/signin (Node, ValidateCompiled, Satisfied,
// NeedsCertificate): the gate accepts exactly the compiled rules the Hub
// writes and refuses what the Hub's validator refuses. Both commit the
// shared vectors (testdata/signin_vectors.json = the Hub's
// internal/signin/testdata/vectors.json, byte for byte; CI compares).
//
// Certificates never count here: an MCP client presents none, so
// TokenMethods drops yubikey_cert and browser_cert whatever the token's
// amr says.
package signin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The seven method ids (§8.1), in canonical order. TOTP (an
// authenticator-app code, amr "otp") is a second factor only: Validate
// refuses a compiled rule with an alternative that is TOTP alone.
const (
	Password      = "password"
	TOTP          = "totp"
	PasskeySynced = "passkey_synced"
	BrowserCert   = "browser_cert"
	PasskeyDevice = "passkey_device"
	SecurityKey   = "security_key"
	YubiKeyCert   = "yubikey_cert"
)

// Methods lists every method id in canonical order.
var Methods = []string{Password, TOTP, PasskeySynced, BrowserCert, PasskeyDevice, SecurityKey, YubiKeyCert}

// amrOf is the §8.1 table: the amr value Keycloak records per method.
// "inv" (a setup-link session) is not a method and maps to nothing.
var amrOf = map[string]string{
	Password:      "pwd",
	TOTP:          "otp",
	PasskeySynced: "spk",
	BrowserCert:   "file",
	PasskeyDevice: "dpk",
	SecurityKey:   "hwk",
	YubiKeyCert:   "mtls",
}

// Group operators.
const (
	OpAll = "all"
	OpAny = "any"
)

// Compiled-rule limits every reader applies (§8.1 "Compiling").
const (
	MaxDepth  = 4  // group levels; the top group is level 1
	MaxItems  = 8  // items per group
	MaxLeaves = 48 // method leaves per rule
)

// maxJSONNesting bounds the decoder's recursion; Validate applies the real
// limits.
const maxJSONNesting = 16

// rank is m's canonical position, -1 for anything that isn't a method id.
func rank(m string) int {
	for i, x := range Methods {
		if x == m {
			return i
		}
	}
	return -1
}

// Known reports whether s is one of the seven method ids (no family, no amr
// value).
func Known(s string) bool { return rank(s) >= 0 }

// Rule is a compiled rule: a group (Op "all" or "any" with Items) or a
// leaf (Op "" with Leaf, a method id). In JSON a leaf is a string and a
// group {"op": …, "items": […]}.
type Rule struct {
	Op    string
	Items []Rule
	Leaf  string
}

func (r Rule) isLeaf() bool { return r.Op == "" }

// MarshalJSON writes a leaf as its string and a group as {"op","items"}
// (the Hub's form, so the shared gate vector re-encodes byte for byte).
func (r Rule) MarshalJSON() ([]byte, error) {
	if r.isLeaf() {
		if r.Leaf == "" || r.Items != nil {
			return nil, errors.New("signin: malformed rule node")
		}
		return json.Marshal(r.Leaf)
	}
	items := r.Items
	if items == nil {
		items = []Rule{}
	}
	return json.Marshal(struct {
		Op    string `json:"op"`
		Items []Rule `json:"items"`
	}{r.Op, items})
}

// UnmarshalJSON decodes strictly: a non-empty string, or an object with
// exactly the keys "op" ("all" or "any") and "items" (an array), each
// once. Anything else, trailing data included, is an error. Errors never
// quote values.
func (r *Rule) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeRule(dec, 1)
	if err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("signin: trailing data after rule")
	}
	*r = v
	return nil
}

func decodeRule(dec *json.Decoder, depth int) (Rule, error) {
	if depth > maxJSONNesting {
		return Rule{}, errors.New("signin: rule nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return Rule{}, errors.New("signin: malformed rule")
	}
	switch t := tok.(type) {
	case string:
		if t == "" {
			return Rule{}, errors.New("signin: empty rule item")
		}
		return Rule{Leaf: t}, nil
	case json.Delim:
		if t != '{' {
			return Rule{}, errors.New("signin: rule item must be a string or a group")
		}
	default:
		return Rule{}, errors.New("signin: rule item must be a string or a group")
	}
	var out Rule
	var sawOp, sawItems bool
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return Rule{}, errors.New("signin: malformed rule")
		}
		key, _ := kt.(string)
		switch key {
		case "op":
			if sawOp {
				return Rule{}, errors.New(`signin: duplicate "op"`)
			}
			sawOp = true
			vt, err := dec.Token()
			if err != nil {
				return Rule{}, errors.New("signin: malformed rule")
			}
			op, _ := vt.(string)
			if op != OpAll && op != OpAny {
				return Rule{}, errors.New(`signin: "op" must be "all" or "any"`)
			}
			out.Op = op
		case "items":
			if sawItems {
				return Rule{}, errors.New(`signin: duplicate "items"`)
			}
			sawItems = true
			vt, err := dec.Token()
			if err != nil {
				return Rule{}, errors.New("signin: malformed rule")
			}
			if d, ok := vt.(json.Delim); !ok || d != '[' {
				return Rule{}, errors.New(`signin: "items" must be an array`)
			}
			out.Items = []Rule{}
			for dec.More() {
				it, err := decodeRule(dec, depth+1)
				if err != nil {
					return Rule{}, err
				}
				out.Items = append(out.Items, it)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return Rule{}, errors.New("signin: malformed rule")
			}
		default:
			return Rule{}, errors.New("signin: unknown rule key")
		}
	}
	if _, err := dec.Token(); err != nil { // '}'
		return Rule{}, errors.New("signin: malformed rule")
	}
	if !sawOp || !sawItems {
		return Rule{}, errors.New(`signin: a group needs "op" and "items"`)
	}
	return out, nil
}

// Validate is the readers' check of a compiled rule (the Hub's
// ValidateCompiled): the top is a group; every group is "all" / "any"
// with 1–8 items; groups nest at most 4 levels; at most 48 leaves, each a
// method id (no families); no alternative is TOTP alone (an authenticator
// code is never a way in by itself, §8.1 "Rules"). It doesn't look at the
// switches.
func Validate(r Rule) error {
	if r.isLeaf() {
		return errors.New("a compiled rule must be a group")
	}
	leaves := 0
	var walk func(r Rule, depth int) error
	walk = func(r Rule, depth int) error {
		if r.isLeaf() {
			if r.Items != nil || !Known(r.Leaf) {
				return errors.New("an unknown method")
			}
			leaves++
			return nil
		}
		if r.Op != OpAll && r.Op != OpAny || r.Leaf != "" {
			return errors.New("an unknown group kind")
		}
		if depth > MaxDepth {
			return fmt.Errorf("groups nest at most %d levels", MaxDepth)
		}
		if len(r.Items) == 0 {
			return errors.New("an empty group")
		}
		if len(r.Items) > MaxItems {
			return fmt.Errorf("a group holds at most %d items", MaxItems)
		}
		for _, it := range r.Items {
			if err := walk(it, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(r, 1); err != nil {
		return err
	}
	if leaves > MaxLeaves {
		return fmt.Errorf("more than %d methods", MaxLeaves)
	}
	sets, err := alternatives(r)
	if err != nil {
		return err
	}
	for _, s := range sets {
		if s == codeOnly {
			return errors.New("an authenticator code alone is a way in")
		}
	}
	return nil
}

// Leaves calls fn with every leaf of r, in order.
func (r Rule) Leaves(fn func(string)) {
	if r.isLeaf() {
		fn(r.Leaf)
		return
	}
	for _, it := range r.Items {
		it.Leaves(fn)
	}
}

// Satisfied reports whether the methods in have meet the compiled rule: a
// leaf when have holds it, "any" when some item is met, "all" when every
// item is. Anything that isn't a compiled rule (an unknown leaf, an empty
// or unknown group) is never met.
func (r Rule) Satisfied(have map[string]bool) bool {
	if r.isLeaf() {
		return Known(r.Leaf) && have[r.Leaf]
	}
	if len(r.Items) == 0 {
		return false
	}
	switch r.Op {
	case OpAny:
		for _, it := range r.Items {
			if it.Satisfied(have) {
				return true
			}
		}
		return false
	case OpAll:
		for _, it := range r.Items {
			if !it.Satisfied(have) {
				return false
			}
		}
		return true
	}
	return false
}

// set is a set of methods, bit i = Methods[i] (TestMethodsFitTheSet:
// widen it before a ninth method).
type set uint8

// codeOnly is the one alternative no compiled rule may have.
var codeOnly = set(1 << rank(TOTP))

// minimal drops duplicates and supersets of another set, keeping the
// order of first appearance (the Hub's minimal).
func minimal(sets []set) []set {
	var out []set
	for i, s := range sets {
		keep := true
		for j, o := range sets {
			if i == j {
				continue
			}
			if o&s == o && (o != s || j < i) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, s)
		}
	}
	return out
}

func alternatives(r Rule) ([]set, error) {
	if r.isLeaf() {
		i := rank(r.Leaf)
		if i < 0 {
			return nil, errors.New("not a compiled rule")
		}
		return []set{1 << i}, nil
	}
	if len(r.Items) == 0 {
		return nil, errors.New("not a compiled rule")
	}
	switch r.Op {
	case OpAny:
		var out []set
		for _, it := range r.Items {
			a, err := alternatives(it)
			if err != nil {
				return nil, err
			}
			out = minimal(append(out, a...))
		}
		return out, nil
	case OpAll:
		out := []set{0}
		for _, it := range r.Items {
			a, err := alternatives(it)
			if err != nil {
				return nil, err
			}
			next := make([]set, 0, len(out)*len(a))
			for _, x := range out {
				for _, y := range a {
					next = append(next, x|y)
				}
			}
			out = minimal(next)
		}
		return out, nil
	}
	return nil, errors.New("not a compiled rule")
}

// Alternatives returns the compiled rule's ways to be met: the minimal
// any-of-all-of form, in the rule's order, each alternative's methods in
// canonical order.
func (r Rule) Alternatives() ([][]string, error) {
	sets, err := alternatives(r)
	if err != nil {
		return nil, err
	}
	out := make([][]string, 0, len(sets))
	for _, s := range sets {
		var alt []string
		for i, m := range Methods {
			if s&(1<<i) != 0 {
				alt = append(alt, m)
			}
		}
		out = append(out, alt)
	}
	return out, nil
}

// NeedsCertificate reports whether every alternative of the compiled rule
// contains yubikey_cert or browser_cert: no way in without a client
// certificate, so no MCP token can ever meet it. A rule that isn't
// compiled counts as needing one (the stricter answer).
func (r Rule) NeedsCertificate() bool {
	sets, err := alternatives(r)
	if err != nil {
		return true
	}
	cert := set(1<<rank(YubiKeyCert) | 1<<rank(BrowserCert))
	for _, s := range sets {
		if s&cert == 0 {
			return false
		}
	}
	return true
}

// TokenMethods is what an MCP access token counts for (§15.2): each amr
// value mapped through the §8.1 table, kept only while the method is in
// enabled (the gate file's switched-on methods; totp counts, T22: the
// browser sign-in behind the token typed the code), and never yubikey_cert or
// browser_cert — an MCP client presents no certificate, so a certificate
// amr in its token proves nothing on this request. "inv" and every value
// outside the table count as nothing.
func TokenMethods(amr []string, enabled []string) map[string]bool {
	on := make(map[string]bool, len(enabled))
	for _, m := range enabled {
		on[m] = true
	}
	have := map[string]bool{}
	for _, a := range amr {
		for m, v := range amrOf {
			if v != a || m == YubiKeyCert || m == BrowserCert || !on[m] {
				continue
			}
			have[m] = true
		}
	}
	return have
}

// Key is have's methods in canonical order, comma-joined: a comparable
// form of a token's method set (the aggregate keys its per-person
// servers on it). Only method ids are kept.
func Key(have map[string]bool) string {
	var out []string
	for _, m := range Methods {
		if have[m] {
			out = append(out, m)
		}
	}
	return strings.Join(out, ",")
}

// FromKey is the method set Key wrote. Anything that isn't a method id is
// dropped.
func FromKey(k string) map[string]bool {
	have := map[string]bool{}
	for _, m := range strings.Split(k, ",") {
		if Known(m) {
			have[m] = true
		}
	}
	return have
}
