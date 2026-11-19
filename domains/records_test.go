package main

import "testing"

// The enrolled domain's spec lists only the DKIM names its records step
// wrote (zone-relative refs made absolute): a foreign selector isn't
// removable (security review, fix round 1).
func TestSpecMailDKIMWrittenFromRecords(t *testing.T) {
	s := &Service{}
	d := &Domain{Name: "team-b.example.test", Records: map[string][]RecordRef{
		"example.test.": {
			{Name: "s1._domainkey.team-b", Type: "TXT", Value: "v=DKIM1; p=x"},
			{Name: "_dmarc.team-b", Type: "TXT", Value: "v=DMARC1; p=none"},
			{Name: "team-b", Type: "CAA", Value: `0 issue "x"`},
		},
	}}
	got := s.spec(d, "").MailDKIMWritten
	if len(got) != 1 || got[0] != "s1._domainkey.team-b.example.test" {
		t.Fatalf("MailDKIMWritten = %v", got)
	}
}
