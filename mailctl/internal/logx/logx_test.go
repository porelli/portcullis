package logx

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	AddSecret("hub-secret-value-0123456789")
	AddSecret("abc") // too short: ignored
	var b bytes.Buffer
	New(&b).Printf("key API_abcdefghijklmnopqrstuvwxyz012345678901 pw app_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 hub hub-secret-value-0123456789 abc")
	out := b.String()
	for _, s := range []string{"API_abc", "app_ABC", "hub-secret-value"} {
		if strings.Contains(out, s) {
			t.Errorf("%s leaked: %s", s, out)
		}
	}
	if !strings.Contains(out, "abc") || strings.Count(out, "[redacted]") != 3 {
		t.Errorf("redaction: %s", out)
	}
}

// L2: the bootstrap's server child writes through this: a registered
// secret never reaches the job's log, also split across writes.
func TestRedactingWriter(t *testing.T) {
	AddSecret("s3cret-recovery-pass")
	var b strings.Builder
	w := NewRedactingWriter(&b)
	w.Write([]byte("admin pw s3cret-rec"))
	w.Write([]byte("overy-pass ok\nnext line\n"))
	if strings.Contains(b.String(), "s3cret") || !strings.Contains(b.String(), "next line") {
		t.Fatalf("%q", b.String())
	}
}
