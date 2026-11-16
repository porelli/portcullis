// Package dmarc is the DMARC policy per domain (contract §19.7): reject
// from the start when the domain had no MX or SPF before Portcullis, else
// none; after 14 clean days of aggregate reports (no source failing both
// SPF and DKIM alignment) the status proposes quarantine, after 14 more
// reject. A proposal is applied only on dmarc-promote.
package dmarc

import (
	"errors"
	"time"
)

// Policies.
const (
	None       = "none"
	Quarantine = "quarantine"
	Reject     = "reject"
	CleanFor   = 14 * 24 * time.Hour
)

// Domain is one domain's state.
type Domain struct {
	Policy      string     `json:"policy"`
	Since       time.Time  `json:"since"`
	LastFailure *time.Time `json:"last_failure"`
}

// Report is one aggregate report's verdict.
type Report struct {
	End     time.Time
	Failing bool // a source failed both SPF and DKIM alignment
}

// Start is a new domain's policy.
func Start(dmarcStart string, now time.Time) Domain {
	if dmarcStart == Reject {
		return Domain{Policy: Reject, Since: now}
	}
	return Domain{Policy: None, Since: now}
}

// Observe records the reports' failures.
func Observe(d Domain, reports []Report) Domain {
	for _, r := range reports {
		if r.Failing && (d.LastFailure == nil || r.End.After(*d.LastFailure)) {
			t := r.End
			d.LastFailure = &t
		}
	}
	return d
}

func next(p string) string {
	switch p {
	case None:
		return Quarantine
	case Quarantine:
		return Reject
	}
	return ""
}

// Proposed is the next policy once 14 clean days passed ("" = none).
func Proposed(d Domain, now time.Time) string {
	n := next(d.Policy)
	if n == "" {
		return ""
	}
	clean := d.Since
	if d.LastFailure != nil && d.LastFailure.After(clean) {
		clean = *d.LastFailure
	}
	if now.Sub(clean) < CleanFor {
		return ""
	}
	return n
}

// Promote applies the proposal.
func Promote(d Domain, now time.Time) (Domain, error) {
	p := Proposed(d, now)
	if p == "" {
		return d, errors.New("nothing to promote: no proposal (14 clean days of reports are needed)")
	}
	return Domain{Policy: p, Since: now, LastFailure: d.LastFailure}, nil
}
