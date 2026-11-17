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

// A line longer than the buffer: a secret or an API-key shape across the
// flush cut is still redacted, and Close redacts the rest (fix round 1).
func TestRedactingWriterLongLineAcrossCut(t *testing.T) {
	const sec = "straddling-secret-value-0123456789"
	AddSecret(sec)
	key := "API_" + strings.Repeat("k", 38)
	for _, tok := range []string{sec, key} {
		for k := 2; k < len(tok)-1; k += 3 {
			var b strings.Builder
			w := NewRedactingWriter(&b)
			// The first write overflows the buffer with the token's first
			// k bytes at its end; the rest comes with the next write.
			w.Write([]byte(strings.Repeat("x", redactMax) + " " + tok[:k]))
			w.Write([]byte(tok[k:] + " " + strings.Repeat("y", 2000)))
			w.Close()
			out := b.String()
			if strings.Contains(out, tok[:k]) || strings.Contains(out, tok[k:]) || !strings.Contains(out, "[redacted]") {
				t.Fatalf("token %.8s… cut at %d escaped the redaction", tok, k)
			}
			if !strings.HasSuffix(out, "y") || strings.Count(out, "x") != redactMax {
				t.Fatalf("cut %d: output lost or duplicated", k)
			}
		}
	}
	// Close with a held partial line redacts it.
	var b strings.Builder
	w := NewRedactingWriter(&b)
	w.Write([]byte("tail " + sec))
	w.Close()
	if b.String() != "tail [redacted]" {
		t.Fatalf("close: %q", b.String())
	}
}

// One secret-shaped token longer than the buffer: the writer doesn't hold
// it forever, and what it writes is redacted (L-c).
func TestRedactingWriterHugeShapeBounded(t *testing.T) {
	var b strings.Builder
	w := NewRedactingWriter(&b)
	w.Write([]byte("API_"))
	for i := 0; i < 3; i++ {
		w.Write([]byte(strings.Repeat("k", redactMax)))
	}
	if b.Len() == 0 || len(w.buf) > 2*redactMax {
		t.Fatalf("held %d bytes, wrote %d", len(w.buf), b.Len())
	}
	if strings.Contains(b.String(), "kkkkkkkkkkkkkkkkkkkk") {
		t.Fatal("the token went out unredacted")
	}
}

// Two secrets (and an API key shape) placed across the flush cut points,
// written in many chunkings: no 8-byte window of any of them ever reaches
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
				text := strings.Repeat(".", base-len(s1)/2) + s1 + strings.Repeat(".", gap) + s2 + " " + key + strings.Repeat(".", 500)
				var b strings.Builder
				w := NewRedactingWriter(&b)
				for i := 0; i < len(text); i += ch {
					w.Write([]byte(text[i:min(len(text), i+ch)]))
				}
				w.Close()
				if win := windows(b.String()); win != "" {
					t.Fatalf("base %d gap %d chunk %d: %q reached the output", base, gap, ch, win)
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
			if win := windows(b.String()); win != "" && !strings.HasPrefix(win, "KKKK") {
				t.Fatalf("huge token, sep %q chunk %d: %q reached the output", sep, ch, win)
			}
		}
	}
}
