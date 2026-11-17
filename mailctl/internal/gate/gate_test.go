package gate

import (
	"os"
	"path/filepath"
	"testing"
)

// Every P3 case (the template's entrypoint wrapper checks the same).
func TestGatePredicate(t *testing.T) {
	type files map[string]string
	cases := []struct {
		name    string
		f       files
		session string
		ok      bool
	}{
		{"absent", files{}, "", false},
		{"present", files{".present": Sentinel}, "", true},
		{"present newline", files{".present": Sentinel + "\n"}, "", true},
		{"present two newlines", files{".present": Sentinel + "\n\n"}, "", false},
		{"wrong present", files{".present": "yes"}, "", false},
		{"pending no session", files{"void-pending": "", ".present": Sentinel}, "n", false},
		{"pending empty session", files{"void-pending": "", "void-session": ""}, "", false},
		{"wrong nonce", files{"void-pending": "", "void-session": "abc"}, "abd", false},
		{"nonce with newline differs", files{"void-pending": "", "void-session": "abc\n"}, "abc", false},
		{"right nonce", files{"void-pending": "", "void-session": "abc"}, "abc", true},
		{"present with pending", files{"void-pending": "", ".present": Sentinel}, "", false},
	}
	for _, c := range cases {
		d := t.TempDir()
		for n, v := range c.f {
			os.WriteFile(filepath.Join(d, n), []byte(v), 0o640)
		}
		if err := Check(d, c.session); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if os.Getuid() != 0 {
		d := t.TempDir()
		p := filepath.Join(d, ".present")
		os.WriteFile(p, []byte(Sentinel), 0o000)
		if err := Check(d, ""); err == nil {
			t.Error("unreadable .present accepted")
		}
	}
}

// Ruling T3-c: only the _mail/ files; a directory or another entry (the
// whole hub_secrets volume because a subpath was ignored) refuses.
func TestCheckLayout(t *testing.T) {
	d := t.TempDir()
	for _, f := range []string{".present", "api-secret", "metrics-secret", "relay-password", "void-pending", "void-session"} {
		os.WriteFile(filepath.Join(d, f), []byte("x"), 0o640)
	}
	if err := CheckLayout(d); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(d, "stalwart"), 0o750)
	if err := CheckLayout(d); err == nil {
		t.Fatal("an instance directory accepted")
	}
	os.Remove(filepath.Join(d, "stalwart"))
	os.WriteFile(filepath.Join(d, "people.json"), nil, 0o640)
	if err := CheckLayout(d); err == nil {
		t.Fatal("a foreign file accepted")
	}
	if err := CheckLayout(filepath.Join(d, "missing")); err == nil {
		t.Fatal("a missing slot accepted")
	}
}
