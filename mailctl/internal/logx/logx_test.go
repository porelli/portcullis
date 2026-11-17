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

// R2-LOG: a line over 64 KiB is dropped whole (one marker), never cut;
// the next line is written as usual; Close treats the last partial line
// the same way.
func TestRedactingWriterLongLineDropped(t *testing.T) {
	const sec = "straddling-secret-value-0123456789"
	AddSecret(sec)
	var b strings.Builder
	w := NewRedactingWriter(&b)
	w.Write([]byte(strings.Repeat("x", redactMax) + " " + sec[:10]))
	w.Write([]byte(sec[10:] + " tail\nnext " + sec + "\n"))
	w.Close()
	if b.String() != lineDropped+"\nnext [redacted]\n" {
		t.Fatalf("%.200q", b.String())
	}
	b.Reset()
	w = NewRedactingWriter(&b)
	w.Write([]byte(strings.Repeat("y", redactMax+1)))
	w.Close()
	if b.String() != lineDropped {
		t.Fatalf("close over the bound: %.100q", b.String())
	}
	// Close with a held partial line redacts it.
	b.Reset()
	w = NewRedactingWriter(&b)
	w.Write([]byte("tail " + sec))
	w.Close()
	if b.String() != "tail [redacted]" {
		t.Fatalf("close: %q", b.String())
	}
}

// the output (security review of the fix round).
func TestRedactingWriterNoWindowAcrossChunkings(t *testing.T) {
	s1 := "Q1w2E3r4T5y6U7i8O9p0-first-secret-QQ"
	s2 := "Z9y8X7w6V5u4T3s2R1q0-second-secret-ZZ"
	AddSecret(s1)
	AddSecret(s2)
	key := "API_" + strings.Repeat("K", 30) + "k1k2k3k4"
	toks := []string{s1, s2, key}
	windows := func(out string) string {
		for _, tok := range toks {
			for i := 0; i+8 <= len(tok); i++ {
				if strings.Contains(out, tok[i:i+8]) {
					return tok[i : i+8]
				}
			}
		}
		return ""
	}
	chunkings := []int{1, 7, 13, 255, 256, 4096, 65535, 65536, 65537, 100000}
	for _, base := range []int{redactMax - 40, redactMax - 3, redactMax, 2*redactMax - 20, 2 * redactMax, 3*redactMax - 7} {
		for gap := 0; gap <= 300; gap += 37 {
			for _, ch := range chunkings {
				// Filler without newlines; the first secret ends near base,
				// the second starts gap bytes after it, the key after that.
				for _, nl := range []string{"", "\n"} {
					// With nl, short lines around the secrets (redacted
					// whole); without, one long line (dropped or redacted
					// whole on Close).
					text := strings.Repeat(".", base-len(s1)/2) + nl + s1 + strings.Repeat(".", gap) + nl + s2 + " " + key + nl + strings.Repeat(".", 500)
					if nl != "" {
						text = strings.Repeat(".", 80) + nl + s1 + strings.Repeat(".", gap%61) + nl + s2 + " " + key + nl + strings.Repeat(".", base%5000)
					}
					var b strings.Builder
					w := NewRedactingWriter(&b)
					for i := 0; i < len(text); i += ch {
						w.Write([]byte(text[i:min(len(text), i+ch)]))
					}
					w.Close()
					if win := windows(b.String()); win != "" {
						t.Fatalf("base %d gap %d chunk %d nl %q: %q reached the output", base, gap, ch, nl, win)
					}
				}
			}
		}
	}
	// A token longer than twice the buffer, a secret right after it: the
	// forced flush must not let the secret's start through.
	huge := "API_" + strings.Repeat("K", 2*redactMax+100)
	for _, sep := range []string{" ", ";", ""} {
		for _, ch := range []int{1000, 4099, 65536, 65600, 131072, 131100, 200000} {
			text := huge + sep + s1 + strings.Repeat(".", 300) + s2 + strings.Repeat(".", 300)
			var b strings.Builder
			w := NewRedactingWriter(&b)
			for i := 0; i < len(text); i += ch {
				w.Write([]byte(text[i:min(len(text), i+ch)]))
			}
			w.Close()
			if win := windows(b.String()); win != "" {
				t.Fatalf("huge token, sep %q chunk %d: %q reached the output", sep, ch, win)
			}
		}
	}
}
