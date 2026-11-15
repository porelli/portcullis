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
