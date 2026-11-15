package checks

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/state"
)

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// reportChecks: dmarc_reports / tlsrpt_reports, the accepted aggregate
// reports of the last 7 days with failures, naming the sources.
func reportChecks(ctx context.Context, d Deps, doc *state.Doc) []Check {
	dm := Check{ID: "dmarc_reports", Severity: OK, Detail: "no DMARC failures reported in 7 days"}
	tl := Check{ID: "tlsrpt_reports", Severity: OK, Detail: "no TLS failures reported in 7 days"}
	if doc == nil {
		return []Check{dm, tl}
	}
	rs, err := d.M.Reports(ctx)
	if err != nil {
		dm.Severity, dm.Detail = Info, "the reports couldn't be read"
		tl.Severity, tl.Detail = Info, "the reports couldn't be read"
		return []Check{dm, tl}
	}
	now := d.now()
	since := now.Add(-7 * 24 * time.Hour)
	for _, kind := range []string{"dmarc", "tls"} {
		c := &dm
		if kind == "tls" {
			c = &tl
		}
		var authDomains, unauthDomains, authSrc, unauthSrc []string
		for _, dom := range doc.Domains {
			acc := d.M.Accepted(rs, kind, dom.Name, since, now)
			var authed, unauthed []machines.Report
			for _, r := range acc {
				if !r.Failing {
					continue
				}
				if r.Authenticated {
					authed = append(authed, r)
				} else {
					unauthed = append(unauthed, r)
				}
			}
			if machines.Reporters(authed) >= machines.MinReporters {
				authDomains = append(authDomains, fmt.Sprintf("%s: %d", dom.Name, len(authed)))
				for _, r := range authed {
					authSrc = append(authSrc, r.Sender)
				}
			} else if len(authed)+len(unauthed) > 0 {
				unauthDomains = append(unauthDomains, fmt.Sprintf("%s: %d", dom.Name, len(authed)+len(unauthed)))
				for _, r := range append(authed, unauthed...) {
					src := r.Org
					if src == "" {
						src = r.From
					}
					unauthSrc = append(unauthSrc, src+" ("+r.From+")")
				}
			}
		}
		switch {
		case len(authDomains) > 0:
			// Ruling: reports never change a policy; independent
			// authenticated reporters make the admin act.
			c.Severity = Problem
			c.Detail = fmt.Sprintf("failing reports in 7 days from %d or more independent DKIM-authenticated reporters (%s; %s)",
				machines.MinReporters, joinMax(authDomains, 4), joinMax(uniq(authSrc), 5))
			if kind == "dmarc" {
				c.Steps = []string{"A source failing both SPF and DKIM alignment is either forging your domain or a service sending for you without DKIM: check the sources, fix the service, and don't promote DMARC until it is clean (nothing was changed automatically)."}
			} else {
				c.Steps = []string{"Remote servers couldn't use TLS to this server: check ./portcullis mail status (certificate, TLSA); MTA-STS stays as it is until you act (nothing was changed automatically)."}
			}
		case len(unauthDomains) > 0:
			c.Severity = Info
			c.Detail = fmt.Sprintf("unauthenticated failing reports in 7 days (%s) from %s: shown only, never acted on (anyone can send a report)",
				joinMax(unauthDomains, 4), joinMax(uniq(unauthSrc), 5))
		}
	}
	return []Check{dm, tl}
}
