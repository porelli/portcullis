package signin

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// vectorFile is testdata/signin_vectors.json, a byte copy of the Hub's
// internal/signin/testdata/vectors.json (CI unit-tests compares). The
// gate reads "compiled" only: Compile is the Hub's.
type vectorFile struct {
	Version int          `json:"version"`
	Note    string       `json:"note"`
	Cases   []vectorCase `json:"cases"`
}

type vectorCase struct {
	Name         string          `json:"name"`
	Rule         json.RawMessage `json:"rule,omitempty"`
	On           []string        `json:"on"`
	Compiled     *Rule           `json:"compiled,omitempty"`
	Error        string          `json:"error,omitempty"`
	Have         *[]string       `json:"have,omitempty"`
	Satisfied    *bool           `json:"satisfied,omitempty"`
	Alternatives [][]string      `json:"alternatives,omitempty"`
	Reject       bool            `json:"reject,omitempty"`
}

// amrMethods maps amr values through the table only (the vectors are the
// pure evaluator: no certificate filtering, no switches).
func amrMethods(amr []string) map[string]bool {
	have := map[string]bool{}
	for _, a := range amr {
		for m, v := range amrOf {
			if v == a {
				have[m] = true
			}
		}
	}
	return have
}

func TestRuleSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/signin_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f vectorFile
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	// The compiled rules exactly as the file has them, to check the
	// re-encoding against the vector's own bytes.
	var raws struct {
		Cases []struct {
			Compiled json.RawMessage `json:"compiled"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &raws); err != nil || len(raws.Cases) != len(f.Cases) {
		t.Fatalf("raw cases: %v", err)
	}
	if f.Version != 1 || len(f.Cases) < 25 {
		t.Fatalf("version %d, %d cases", f.Version, len(f.Cases))
	}
	rejects, evaluated := 0, 0
	for i, c := range f.Cases {
		if c.Reject {
			rejects++
			if c.Compiled == nil {
				t.Errorf("%s: reject without compiled", c.Name)
				continue
			}
			if err := Validate(*c.Compiled); err == nil {
				t.Errorf("%s: Validate accepted it", c.Name)
			}
			continue
		}
		if c.Error != "" {
			continue // a Hub compile error: no compiled rule reaches readers
		}
		if c.Compiled == nil || c.Have == nil || c.Satisfied == nil || c.Alternatives == nil {
			t.Errorf("%s: compiled, have, satisfied and alternatives are required", c.Name)
			continue
		}
		evaluated++
		r := *c.Compiled
		if err := Validate(r); err != nil {
			t.Errorf("%s: Validate: %v", c.Name, err)
		}
		// It re-encodes as the Hub wrote it (the vector's own bytes).
		want := raws.Cases[i].Compiled
		if got := mustJSON(t, r); !bytes.Equal(compact(t, got), compact(t, want)) {
			t.Errorf("%s: re-encoded %s, want %s", c.Name, got, want)
		}
		have := amrMethods(*c.Have)
		if s := r.Satisfied(have); s != *c.Satisfied {
			t.Errorf("%s: Satisfied(%v) = %v, want %v", c.Name, *c.Have, s, *c.Satisfied)
		}
		alts, err := r.Alternatives()
		if err != nil {
			t.Errorf("%s: Alternatives: %v", c.Name, err)
			continue
		}
		if !sameSetOfSets(alts, c.Alternatives) {
			t.Errorf("%s: alternatives %v, want %v", c.Name, alts, c.Alternatives)
		}
		// NeedsCertificate agrees with the alternatives.
		needs := !slices.ContainsFunc(alts, func(a []string) bool {
			return !slices.Contains(a, YubiKeyCert) && !slices.Contains(a, BrowserCert)
		})
		if r.NeedsCertificate() != needs {
			t.Errorf("%s: NeedsCertificate = %v", c.Name, !needs)
		}
	}
	if rejects < 5 || evaluated < 25 {
		t.Errorf("%d reject cases, %d evaluated", rejects, evaluated)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func compact(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func sameSetOfSets(a, b [][]string) bool {
	key := func(s []string) string {
		c := slices.Clone(s)
		slices.Sort(c)
		return strings.Join(slices.Compact(c), ",")
	}
	sa, sb := map[string]bool{}, map[string]bool{}
	for _, s := range a {
		sa[key(s)] = true
	}
	for _, s := range b {
		sb[key(s)] = true
	}
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

// §15.2: an MCP token never counts a certificate, never inv, never an
// unknown value, never a method that is switched off.
func TestTokenMethodsDropCertificates(t *testing.T) {
	all := []string{Password, PasskeySynced, BrowserCert, PasskeyDevice, SecurityKey, YubiKeyCert}
	for name, c := range map[string]struct {
		amr, enabled []string
		want         string
	}{
		"certificate amr":         {[]string{"mtls"}, all, ""},
		"browser certificate amr": {[]string{"file"}, all, ""},
		"both certificates":       {[]string{"mtls", "file", "hwk"}, all, SecurityKey},
		"setup link":              {[]string{"inv"}, all, ""},
		"unknown and case":        {[]string{"HWK", "webauthn", "otp", ""}, all, ""},
		"every passkey":           {[]string{"spk", "dpk", "hwk", "pwd"}, all, "password,passkey_synced,passkey_device,security_key"},
		"switched off":            {[]string{"pwd", "spk", "hwk"}, []string{PasskeyDevice, SecurityKey, YubiKeyCert}, SecurityKey},
		"nothing enabled":         {[]string{"hwk"}, nil, ""},
		"no amr":                  {nil, all, ""},
	} {
		if got := Key(TokenMethods(c.amr, c.enabled)); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	// A certificate-only alternative is never met over MCP, whatever amr says.
	var r Rule
	if err := json.Unmarshal([]byte(`{"op":"any","items":["yubikey_cert",{"op":"all","items":["security_key","yubikey_cert"]}]}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Satisfied(TokenMethods([]string{"mtls", "hwk"}, all)) {
		t.Error("a certificate rule met by an MCP token")
	}
	if !r.NeedsCertificate() {
		t.Error("NeedsCertificate false")
	}
	if !fromKeyRoundTrip(t, "security_key,password") {
		t.Error("FromKey: not the canonical set")
	}
}

func fromKeyRoundTrip(t *testing.T, k string) bool {
	t.Helper()
	h := FromKey(k + ",inv,,family:passkey")
	return len(h) == 2 && h[SecurityKey] && h[Password] && Key(h) == "password,security_key"
}
