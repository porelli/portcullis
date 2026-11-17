package dnsplan

import (
	"strings"
	"testing"
	"time"
)

var (
	spkiA = strings.Repeat("a", 64)
	spkiB = strings.Repeat("b", 64)
	tT0   = time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
)

// The rollover (moved from mailctl): next key → both published → the
// switch due after 2×TTL + 1 day → mail-cert switched → the old key kept
// 2×TTL → dropped.
func TestTLSARolloverStates(t *testing.T) {
	s, phase, due := TLSAStep(nil, spkiA, "", false, tT0)
	if s.Current != spkiA || s.Next != nil || phase != TLSASteady || due != "" || strings.Join(s.Publish(), ",") != spkiA {
		t.Fatalf("fresh %+v %s %s", s, phase, due)
	}
	if _, err := TLSAStartRollover(s, spkiA, tT0); err == nil {
		t.Fatal("next = current accepted")
	}
	s, err := TLSAStartRollover(s, spkiB, tT0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.Publish(), ",") != spkiA+","+spkiB {
		t.Fatalf("both %v", s.Publish())
	}
	if _, phase, due = TLSAStep(&s, spkiA, spkiB, true, tT0.Add(TLSASwitchAfter-time.Second)); phase != TLSARollover || due != "" {
		t.Fatalf("early %s %s", phase, due)
	}
	// R-H4: time alone never makes the switch due: the next key's TLSA
	// must be seen live, and for ≥ TTL.
	if _, phase, due = TLSAStep(&s, spkiA, spkiB, false, tT0.Add(TLSASwitchAfter+48*time.Hour)); phase != TLSARollover || due != "" {
		t.Fatalf("due without the TLSA live %s %s", phase, due)
	}
	seen := tT0.Add(TLSASwitchAfter)
	s, _, due = TLSAStep(&s, spkiA, spkiB, true, seen)
	if due != "" || s.NextSeenAt == nil || !s.NextSeenAt.Equal(seen) {
		t.Fatalf("first seen: %s %+v", due, s.NextSeenAt)
	}
	if _, _, due = TLSAStep(&s, spkiA, spkiB, true, seen.Add(TLSATTL*time.Second-time.Second)); due != "" {
		t.Fatal("due before the TLSA was live a TTL")
	}
	// Seen gone again: the clock restarts.
	gone, _, _ := TLSAStep(&s, spkiA, spkiB, false, seen.Add(30*time.Minute))
	if gone.NextSeenAt != nil {
		t.Fatal("a vanished TLSA kept its seen time")
	}
	if _, phase, due = TLSAStep(&s, spkiA, spkiB, true, seen.Add(TLSATTL*time.Second)); phase != TLSARollover || due != TLSADueSwitch {
		t.Fatalf("due %s %s", phase, due)
	}
	if TLSASwitchAfter != 7200*time.Second+86400*time.Second || TLSADropAfter != 7200*time.Second {
		t.Fatal("timing")
	}
	// mail-cert --switch-key: B is the current key, A retiring.
	sw := tT0.Add(TLSASwitchAfter + time.Hour)
	s2, phase, due := TLSAStep(&s, spkiB, "", false, sw)
	if s2.Current != spkiB || s2.Next == nil || *s2.Next != spkiA || !s2.BothSince.Equal(sw) || phase != TLSARetiring || due != "" {
		t.Fatalf("switched %+v %s %s", s2, phase, due)
	}
	if strings.Join(s2.Publish(), ",") != spkiB+","+spkiA {
		t.Fatalf("retiring publishes %v", s2.Publish())
	}
	if _, err := TLSAStartRollover(s2, strings.Repeat("c", 64), sw); err == nil {
		t.Fatal("a rollover during the retiring phase accepted")
	}
	if _, err := TLSADrop(s2, phase, due); err == nil {
		t.Fatal("dropped early")
	}
	s3, phase, due := TLSAStep(&s2, spkiB, "", false, sw.Add(TLSADropAfter))
	if due != TLSADueDrop {
		t.Fatalf("drop not due %s %s", phase, due)
	}
	s4, err := TLSADrop(s3, phase, due)
	if err != nil || s4.Next != nil || s4.BothSince != nil || strings.Join(s4.Publish(), ",") != spkiB {
		t.Fatalf("dropped %+v %v", s4, err)
	}
	// An unknown current key (nobody recorded it): it alone, fail closed.
	s5, phase, _ := TLSAStep(&s, strings.Repeat("c", 64), "", false, sw)
	if s5.Next != nil || phase != TLSASteady || s5.Current != strings.Repeat("c", 64) {
		t.Fatalf("unknown key %+v", s5)
	}
}

func TestTLSAJSONStrict(t *testing.T) {
	ok := `{"version":1,"current":"` + spkiA + `","next":"` + spkiB + `","both_since":"2026-11-17T10:00:00Z","next_seen_at":null}`
	s, err := ParseTLSAState([]byte(ok))
	if err != nil || *s.Next != spkiB {
		t.Fatalf("%v", err)
	}
	if s2, err := ParseTLSAState(s.Marshal()); err != nil || s2.Current != spkiA || !s2.BothSince.Equal(*s.BothSince) {
		t.Fatalf("round trip %v", err)
	}
	if _, err := ParseTLSAState([]byte(`{"version":1,"current":"` + spkiA + `","next":null,"both_since":null,"next_seen_at":null}`)); err != nil {
		t.Fatalf("steady: %v", err)
	}
	for _, bad := range []string{
		``, `[]`, `{"version":1}`,
		`{"version":1,"current":"` + spkiA + `","next":null,"both_since":null}`,
		`{"version":1,"current":"` + spkiA + `","next":null,"both_since":null,"next_seen_at":"2026-11-17T10:00:00Z"}`,
		`{"version":2,"current":"` + spkiA + `","next":null,"both_since":null}`,
		`{"version":1,"current":"` + strings.ToUpper(spkiA) + `","next":null,"both_since":null}`,
		`{"version":1,"current":"` + spkiA + `","next":"` + spkiB + `","both_since":null}`,
		`{"version":1,"current":"` + spkiA + `","next":null,"both_since":"2026-11-17T10:00:00Z"}`,
		`{"version":1,"current":"` + spkiA + `","next":"` + spkiA + `","both_since":"2026-11-17T10:00:00Z"}`,
		`{"version":1,"current":"` + spkiA + `","next":null,"both_since":null,"x":1}`,
		`{"version":1,"version":1,"current":"` + spkiA + `","next":null,"both_since":null}`,
		`{"version":1,"current":"` + spkiA + `","next":null,"both_since":null}{}`,
	} {
		if _, err := ParseTLSAState([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TLSA only while the main zone is secure; the HELO SPF always.
func TestTLSAWithheldUnlessSecure(t *testing.T) {
	recs := CoreMailRecords("mail.example.com", []string{spkiA, spkiB}, false)
	if len(recs) != 1 || recs[0].Type != "TXT" {
		t.Fatalf("insecure %+v", recs)
	}
	recs = CoreMailRecords("mail.example.com", []string{spkiA, spkiB}, true)
	if len(recs) != 3 || recs[1] != (MailRecord{Name: "_25._tcp.mail.example.com", Type: "TLSA", TTL: 3600, Value: "3 1 1 " + spkiA}) || recs[2].Value != "3 1 1 "+spkiB {
		t.Fatalf("secure %+v", recs)
	}
	if err := ValidateMainMail("example.com", "mail.example.com", recs); err != nil {
		t.Fatalf("core's records don't validate: %v", err)
	}
}

func TestHELOSPFAtHostname(t *testing.T) {
	r := CoreMailRecords("mx.other.example", nil, true)
	if len(r) != 1 || r[0] != (MailRecord{Name: "mx.other.example", Type: "TXT", TTL: 3600, Value: "v=spf1 a -all"}) {
		t.Fatalf("%+v", r)
	}
}
