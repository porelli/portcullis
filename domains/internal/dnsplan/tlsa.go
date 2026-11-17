package dnsplan

// Core's records at MAIL_HOSTNAME (contract §19.3): the HELO SPF and the
// TLSA `_25._tcp.<h> 3 1 1 <spki>`, from mail-cert's keys, published only
// while the main zone is DNSSEC secure. The rollover state is
// mail_acme/tlsa.json (TLSAState): mail-cert --next-key → both SPKIs
// published → 2×TTL + 1 day → mail-cert --switch-key at the next issue →
// the old SPKI dropped after a further 2×TTL. (Moved from mailctl's
// internal/tlsa with the mail provider plan.)

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"
)

// TLSA timing.
const (
	TLSATTL         = 3600
	TLSASwitchAfter = 2*TLSATTL*time.Second + 24*time.Hour
	TLSADropAfter   = 2 * TLSATTL * time.Second
)

// TLSA phases and due steps.
const (
	TLSASteady    = "steady"   // one key
	TLSARollover  = "rollover" // next is the next key (mail.next.key), both published
	TLSARetiring  = "retiring" // next is the old key, kept until both_since + 2×TTL
	TLSADueSwitch = "switch"
	TLSADueDrop   = "drop"
)

// TLSAState is mail_acme/tlsa.json.
type TLSAState struct {
	Version   int        `json:"version"`
	Current   string     `json:"current"`
	Next      *string    `json:"next"`
	BothSince *time.Time `json:"both_since"`
}

var reSPKIHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ParseTLSAState decodes tlsa.json strictly: one object, exactly the four
// keys (no duplicates, nothing trailing), version 1, SPKIs 64 lowercase
// hex, both_since exactly when next.
func ParseTLSAState(b []byte) (TLSAState, error) {
	var s TLSAState
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil || keys == nil {
		return s, errors.New("tlsa.json: not a JSON object")
	}
	for _, k := range []string{"version", "current", "next", "both_since"} {
		if _, ok := keys[k]; !ok {
			return s, fmt.Errorf("tlsa.json: missing %q", k)
		}
	}
	if err := noDupKeys(b); err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, fmt.Errorf("tlsa.json: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return s, errors.New("tlsa.json: trailing data")
	}
	switch {
	case s.Version != 1:
		return s, fmt.Errorf("tlsa.json: version %d (only 1)", s.Version)
	case !reSPKIHex.MatchString(s.Current):
		return s, errors.New("tlsa.json: current isn't 64 lowercase hex")
	case (s.Next == nil) != (s.BothSince == nil):
		return s, errors.New("tlsa.json: next and both_since go together")
	case s.Next != nil && (!reSPKIHex.MatchString(*s.Next) || *s.Next == s.Current):
		return s, errors.New("tlsa.json: next isn't another 64 lowercase hex SPKI")
	}
	return s, nil
}

func noDupKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return errors.New("tlsa.json: not a JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return errors.New("tlsa.json: unreadable")
		}
		k, _ := t.(string)
		if seen[k] {
			return fmt.Errorf("tlsa.json: %q twice", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return errors.New("tlsa.json: unreadable")
		}
	}
	return nil
}

// Marshal is tlsa.json's bytes.
func (s TLSAState) Marshal() []byte {
	b, _ := json.Marshal(s)
	return append(b, '\n')
}

// Publish are the SPKIs the TLSA carries (current first).
func (s TLSAState) Publish() []string {
	out := []string{s.Current}
	if s.Next != nil {
		out = append(out, *s.Next)
	}
	return out
}

// TLSAStep reconciles s with mail-cert's keys: cur the SPKI of
// /acme/mail.key, next that of /acme/mail.next.key ("" = none). It answers
// the new state, its phase and the step due ("" = none). A switch
// mail-cert made (the current key is the recorded next one) starts the
// retiring phase with the old key; an unknown current key (a key nobody
// recorded) resets to it alone.
func TLSAStep(s *TLSAState, cur, next string, now time.Time) (TLSAState, string, string) {
	now = now.UTC().Truncate(time.Second)
	var st TLSAState
	switch {
	case s == nil || (s.Current != cur && (s.Next == nil || *s.Next != cur)):
		st = TLSAState{Version: 1, Current: cur}
	case s.Current != cur:
		old := s.Current
		st = TLSAState{Version: 1, Current: cur, Next: &old, BothSince: &now}
	default:
		st = *s
	}
	phase := TLSASteady
	if st.Next != nil {
		phase = TLSARetiring
		if next != "" && *st.Next == next {
			phase = TLSARollover
		}
	}
	due := ""
	switch {
	case phase == TLSARollover && !now.Before(st.BothSince.Add(TLSASwitchAfter)):
		due = TLSADueSwitch
	case phase == TLSARetiring && !now.Before(st.BothSince.Add(TLSADropAfter)):
		due = TLSADueDrop
	}
	return st, phase, due
}

// TLSAStartRollover records next (mail-cert --next-key's SPKI): both
// published from now. Refused while another rollover or a retiring key is
// under way.
func TLSAStartRollover(s TLSAState, next string, now time.Time) (TLSAState, error) {
	if !reSPKIHex.MatchString(next) || next == s.Current {
		return s, errors.New("the next key's SPKI isn't another 64 lowercase hex SPKI")
	}
	if s.Next != nil {
		if *s.Next == next {
			return s, nil
		}
		return s, errors.New("a key change is already under way (the old key is still published)")
	}
	t := now.UTC().Truncate(time.Second)
	s.Next, s.BothSince = &next, &t
	return s, nil
}

// TLSADrop ends the retiring phase (due only: TLSAStep said drop).
func TLSADrop(s TLSAState, phase, due string) (TLSAState, error) {
	if phase != TLSARetiring || due != TLSADueDrop {
		return s, fmt.Errorf("nothing to drop yet (phase %s)", phase)
	}
	s.Next, s.BothSince = nil, nil
	return s, nil
}

// HELOSPF is the HELO SPF core publishes at MAIL_HOSTNAME.
const HELOSPF = heloSPF

// CoreMailRecords are core's records at host (MAIL_HOSTNAME): the HELO
// SPF always, the TLSA for each SPKI only while secure.
func CoreMailRecords(host string, spkis []string, secure bool) []MailRecord {
	out := []MailRecord{{Name: host, Type: "TXT", TTL: TLSATTL, Value: heloSPF}}
	if secure {
		for _, k := range spkis {
			out = append(out, MailRecord{Name: "_25._tcp." + host, Type: "TLSA", TTL: TLSATTL, Value: "3 1 1 " + k})
		}
	}
	return out
}
