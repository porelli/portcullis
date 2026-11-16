// Package mtasts is the MTA-STS state machine per domain (contract §19.7):
// testing (max_age 86400) → enforce (604800) only on mtasts-enforce, after
// 7 days of testing with the certificate check ok and no TLS-RPT failure
// since testing began; any failure goes back to testing. Turning mail off
// makes the domain drain: mode none for the full max_age of the last
// published policy, then off. A document that says off without the drain
// goes enforce → testing for that max_age, then off (never straight off). MTA-STS follows VPN-only mode: while the
// well-known router isn't reachable from the internet nothing is
// published, and a drain waits max_age from the later of its start and
// the moment the policy stopped being reachable.
package mtasts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Modes (status mtasts[].mode).
const (
	Testing = "testing"
	Enforce = "enforce"
	None    = "none"
	Off     = "off"

	MaxAgeTesting = 86400
	MaxAgeEnforce = 604800
	EnforceAfter  = 7 * 24 * time.Hour
)

// Domain is one domain's state.
type Domain struct {
	Mode        string     `json:"mode"`
	Since       time.Time  `json:"since"`
	Policy      string     `json:"policy"`  // the text served ("" = none)
	ID          string     `json:"id"`      // the _mta-sts id
	MaxAge      int        `json:"max_age"` // of the last policy published while reachable
	DrainStart  *time.Time `json:"drain_start"`
	HiddenSince *time.Time `json:"hidden_since"` // the policy stopped being reachable
}

// PolicyText is the policy file.
func PolicyText(mode, mx string, maxAge int) string {
	return fmt.Sprintf("version: STSv1\nmode: %s\nmx: %s\nmax_age: %d\n", mode, mx, maxAge)
}

// ID is the first 20 hex digits of sha256(policy) + "T<unix>".
func ID(policy string, at time.Time) string {
	s := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(s[:])[:20] + "T" + fmt.Sprint(at.Unix())
}

// Inputs of one step.
type Inputs struct {
	Mail      string // on | draining | off (the document)
	Reachable bool   // the well-known router is on websecure
	MX        string // MAIL_HOSTNAME
	// Failure: the certificate check failed or TLS-RPT reports since the
	// given time show failures, strong enough to downgrade enforce to
	// testing (the caller requires independent reporters: reports are
	// unauthenticated mail).
	Failure func(since time.Time) bool
	// Blocking: any failure since the given time that keeps testing from
	// becoming enforce (one accepted report is enough). nil = Failure.
	Blocking func(since time.Time) bool
}

func (d *Domain) publish(mode, mx string, maxAge int, now time.Time) {
	text := PolicyText(mode, mx, maxAge)
	if text != d.Policy {
		d.Policy, d.ID = text, ID(text, now)
	}
}

// Step advances one domain.
func Step(d Domain, in Inputs, now time.Time) Domain {
	switch in.Mail {
	case "on":
		if !in.Reachable {
			if d.Mode == Testing || d.Mode == Enforce || d.Mode == None {
				t := now
				d.HiddenSince = &t
			}
			d.Mode, d.Policy, d.ID = Off, "", ""
			return d
		}
		if d.Mode != Testing && d.Mode != Enforce {
			d = Domain{Mode: Testing, Since: now}
		}
		if d.Mode == Enforce && in.Failure != nil && in.Failure(d.Since) {
			d.Mode, d.Since = Testing, now
		}
		maxAge := MaxAgeTesting
		if d.Mode == Enforce {
			maxAge = MaxAgeEnforce
		}
		d.publish(d.Mode, in.MX, maxAge, now)
		d.MaxAge, d.DrainStart, d.HiddenSince = maxAge, nil, nil
		return d
	case "draining":
		switch d.Mode {
		case Testing, Enforce:
			t := now
			d.Mode, d.Since, d.DrainStart = None, now, &t
		case None:
		case "", Off:
			if d.MaxAge == 0 {
				// Never published: nothing cached anywhere.
				return Domain{Mode: Off, Since: now}
			}
			if d.DrainStart == nil {
				t := now
				d.DrainStart = &t
			}
			d.Mode = None
		}
		return dwell(d, in, None, now)
	default:
		// Off (or anything else): never straight to off from a published
		// policy. enforce → testing, which dwells for the max_age of the
		// last published policy (senders cached it), then off; a drain
		// already under way (mode none) runs to its end.
		switch d.Mode {
		case Enforce:
			t := now
			d.Mode, d.Since, d.DrainStart = Testing, now, &t
		case Testing:
			if d.DrainStart == nil {
				t := now
				d.DrainStart = &t
			}
		case None:
			if d.DrainStart == nil {
				t := now
				d.DrainStart = &t
			}
		default:
			return Domain{Mode: Off, Since: now}
		}
		if d.MaxAge == 0 {
			return Domain{Mode: Off, Since: now}
		}
		return dwell(d, in, d.Mode, now)
	}
}

// dwell publishes mode (none or testing) until max_age of the last
// published policy has passed since the later of the drain's start and
// the moment the policy stopped being reachable, then the domain is off.
func dwell(d Domain, in Inputs, mode string, now time.Time) Domain {
	if !in.Reachable && d.HiddenSince == nil {
		t := now
		d.HiddenSince = &t
	}
	start := *d.DrainStart
	if d.HiddenSince != nil && d.HiddenSince.After(start) {
		start = *d.HiddenSince
	}
	if now.Sub(start) >= time.Duration(d.MaxAge)*time.Second {
		return Domain{Mode: Off, Since: now}
	}
	if in.Reachable {
		d.publish(mode, in.MX, MaxAgeTesting, now)
	} else {
		d.Policy, d.ID = "", ""
	}
	return d
}

// EnforceReady: the mtasts-enforce action would be accepted now (nil) or
// why not.
func EnforceReady(d Domain, in Inputs, now time.Time) error {
	switch {
	case d.Mode == Enforce:
		return errors.New("MTA-STS is already enforce")
	case d.Mode != Testing:
		return fmt.Errorf("MTA-STS is %s, not testing", d.Mode)
	case now.Sub(d.Since) < EnforceAfter:
		return fmt.Errorf("MTA-STS has been testing for less than 7 days (since %s)", d.Since.UTC().Format(time.RFC3339))
	case in.Blocking != nil && in.Blocking(d.Since), in.Blocking == nil && in.Failure != nil && in.Failure(d.Since):
		return errors.New("the certificate check or a TLS-RPT report failed since testing began")
	}
	return nil
}

// DoEnforce applies mtasts-enforce.
func DoEnforce(d Domain, in Inputs, now time.Time) (Domain, error) {
	if err := EnforceReady(d, in, now); err != nil {
		return d, err
	}
	d.Mode, d.Since = Enforce, now
	d.publish(Enforce, in.MX, MaxAgeEnforce, now)
	d.MaxAge = MaxAgeEnforce
	return d, nil
}
