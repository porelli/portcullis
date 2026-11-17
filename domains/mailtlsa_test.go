package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/portcullis/domains/internal/dnsplan"
)

func tlsaRun(t *testing.T, dir, cmd string) (int, mailTLSAOutput) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runMailTLSA([]string{cmd, "--hostname", "mail.example.com"}, toolEnv{stdout: &out, stderr: &errb, acmeDir: dir})
	var o mailTLSAOutput
	if code == exitOK {
		if err := json.Unmarshal(out.Bytes(), &o); err != nil {
			t.Fatalf("%s: %v %s", cmd, err, out.String())
		}
	}
	return code, o
}

// The CLI's rollover through mail-tlsa: status (steady), next (both), the
// switch gated on 2×TTL + 1 day, mail-cert's switch recorded by status
// (retiring), drop after 2×TTL; tlsa.json 0600.
func TestMailTLSACommand(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	tlsaNow = func() time.Time { return now }
	live := false
	realLive := tlsaLive
	tlsaLive = func(_ context.Context, host, spki string) bool { return live && host == "mail.example.com" }
	t.Cleanup(func() { tlsaNow = time.Now; tlsaLive = realLive })
	if code, _ := tlsaRun(t, dir, "status"); code != exitProblem {
		t.Fatal("status without a key")
	}
	a, _ := loadOrCreateKey(filepath.Join(dir, "mail.key"))
	code, o := tlsaRun(t, dir, "status")
	if code != exitOK || o.Phase != dnsplan.TLSASteady || o.Due != nil || len(o.Publish) != 1 || o.Publish[0] != spkiSHA256(a) {
		t.Fatalf("steady %d %+v", code, o)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "tlsa.json")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if code, _ := tlsaRun(t, dir, "next"); code != exitProblem {
		t.Fatal("next without mail.next.key")
	}
	b, _ := loadOrCreateKey(filepath.Join(dir, "mail.next.key"))
	if code, o = tlsaRun(t, dir, "next"); code != exitOK || o.Phase != dnsplan.TLSARollover || len(o.Publish) != 2 {
		t.Fatalf("next %d %+v", code, o)
	}
	if code, _ := tlsaRun(t, dir, "switch"); code != exitProblem {
		t.Fatal("switch before 2×TTL + 1 day")
	}
	now = now.Add(dnsplan.TLSASwitchAfter)
	// R-H4: the time is up but the next key's TLSA isn't served: no switch.
	if code, _ := tlsaRun(t, dir, "switch"); code != exitProblem {
		t.Fatal("switch with the next TLSA not published")
	}
	live = true
	if code, o = tlsaRun(t, dir, "status"); code != exitOK || !o.NextLive || o.Due != nil {
		t.Fatalf("first seen %d %+v", code, o)
	}
	now = now.Add(dnsplan.TLSATTL * time.Second)
	if code, o = tlsaRun(t, dir, "switch"); code != exitOK || o.Due == nil || *o.Due != dnsplan.TLSADueSwitch {
		t.Fatalf("switch due %d %+v", code, o)
	}
	// mail-cert --switch-key: the next key becomes mail.key.
	os.Rename(filepath.Join(dir, "mail.next.key"), filepath.Join(dir, "mail.key"))
	now = now.Add(time.Hour)
	if code, o = tlsaRun(t, dir, "status"); code != exitOK || o.Phase != dnsplan.TLSARetiring || o.Publish[0] != spkiSHA256(b) || o.Publish[1] != spkiSHA256(a) {
		t.Fatalf("retiring %d %+v", code, o)
	}
	if code, _ := tlsaRun(t, dir, "drop"); code != exitProblem {
		t.Fatal("dropped early")
	}
	now = now.Add(dnsplan.TLSADropAfter)
	if code, o = tlsaRun(t, dir, "drop"); code != exitOK || o.Phase != dnsplan.TLSASteady || len(o.Publish) != 1 || o.Publish[0] != spkiSHA256(b) {
		t.Fatalf("dropped %d %+v", code, o)
	}
	os.WriteFile(filepath.Join(dir, "tlsa.json"), []byte(`{"version":1}`), 0o600)
	if code, _ := tlsaRun(t, dir, "status"); code != exitProblem {
		t.Fatal("a bad tlsa.json accepted")
	}
	if code, _ := tlsaRun(t, dir, "rotate"); code != exitUsage {
		t.Fatal("unknown subcommand")
	}
	var out, errb bytes.Buffer
	if code := runMailTLSA([]string{"status"}, toolEnv{stdout: &out, stderr: &errb, acmeDir: dir}); code != exitUsage {
		t.Fatal("status without --hostname")
	}
}
