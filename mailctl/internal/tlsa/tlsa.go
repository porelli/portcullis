// Package tlsa is the DANE record of MAIL_HOSTNAME (contract §19.7):
// `_25._tcp.<MAIL_HOSTNAME> TLSA 3 1 1 <spki>`, published only while the
// main zone's DNSSEC state is secure. The key is reused across renewals;
// a rollover (mail-cert --next-key) publishes both SPKIs, waits 2×TTL +
// 1 day before --switch-key, and drops the old SPKI 2×TTL after the
// switch.
package tlsa

import (
	"time"

	"github.com/portcullis/mailctl/internal/state"
)

// Wait before the switch and the old record's lifetime after it.
const (
	TTL          = 3600
	SwitchAfter  = 2*TTL*time.Second + 24*time.Hour
	DropOldAfter = 2 * TTL * time.Second
)

// Update records mail-cert's SPKIs (current, next: "" = none) and answers
// which mail-cert step is due: next_key (never on its own: a rollover
// starts with an operator's --next-key) and switch_key.
func Update(st state.TLSAState, current, next string, now time.Time) (state.TLSAState, bool) {
	if current != "" && st.Current != "" && current != st.Current {
		// The switch happened: the old SPKI stays 2×TTL more.
		t := now.Add(DropOldAfter)
		sw := now
		st.Old, st.OldUntil, st.SwitchedAt = st.Current, &t, &sw
		if st.Next == current {
			st.Next, st.NextSince = "", nil
		}
	}
	if current != "" {
		st.Current = current
	}
	if next != "" && next != st.Next && next != st.Current {
		t := now
		st.Next, st.NextSince = next, &t
	}
	if st.Old != "" && st.OldUntil != nil && !now.Before(*st.OldUntil) {
		st.Old, st.OldUntil = "", nil
	}
	switchKey := st.Next != "" && st.NextSince != nil && !now.Before(st.NextSince.Add(SwitchAfter))
	return st, switchKey
}

// Wanted are the SPKIs to publish: none unless secure.
func Wanted(st state.TLSAState, secure bool) []string {
	if !secure {
		return nil
	}
	var out []string
	for _, s := range []string{st.Current, st.Next, st.Old} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
