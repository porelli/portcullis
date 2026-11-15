package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/portcullis/mailctl/internal/dkim"
	"github.com/portcullis/mailctl/internal/resolve"
	"github.com/portcullis/mailctl/internal/state"
)

// tagP is the p= value of a DKIM TXT record ("" = none).
func tagP(txt string) string {
	for _, t := range strings.Split(txt, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(t), "=")
		if ok && strings.TrimSpace(k) == "p" {
			return strings.Join(strings.Fields(v), "")
		}
	}
	return ""
}

// dkimChecks: dkim_stuck:<d> (a key pending more than 24 h) and
// dkim_selftest:<d> (Stalwart's publicKey of each active key is the p=
// both public resolvers serve, P2).
func dkimChecks(ctx context.Context, d Deps, doc *state.Doc) []Check {
	if doc == nil {
		return nil
	}
	now := d.now()
	keys := dkim.State{Keys: d.M.Keys()}
	var out []Check
	for _, dom := range doc.Domains {
		if dom.Mail != state.MailOn {
			continue
		}
		st := Check{ID: "dkim_stuck:" + dom.Name, Severity: OK, Detail: "no DKIM key waiting for DNS"}
		if stuck := dkim.Stuck(keys, dom.Name, now); len(stuck) > 0 {
			var sels []string
			for _, k := range stuck {
				sels = append(sels, k.Selector)
			}
			st.Severity = Warning
			st.Detail = fmt.Sprintf("DKIM key %s has waited more than 24 h for its TXT record at both public resolvers", strings.Join(sels, ", "))
			st.Steps = []string{fmt.Sprintf("Check the domain's DNS records (Settings → Domains, or ./portcullis dns plan for %s): the TXT at <selector>._domainkey.%s must be exactly mailctl's.", d.Cfg.MainDomain, dom.Name)}
		}
		out = append(out, st)
		out = append(out, selftest(ctx, d, keys, dom.Name))
	}
	return out
}

func selftest(ctx context.Context, d Deps, keys dkim.State, domain string) Check {
	c := Check{ID: "dkim_selftest:" + domain, Severity: OK}
	var active []dkim.Key
	for _, k := range keys.Keys {
		if k.Domain == domain && k.Stage == dkim.Active && k.ID != "" {
			active = append(active, k)
		}
	}
	if len(active) == 0 {
		c.Detail = "no active DKIM key yet"
		return c
	}
	ids := make([]string, len(active))
	for i, k := range active {
		ids[i] = k.ID
	}
	var got []struct {
		ID        string `json:"id"`
		PublicKey string `json:"publicKey"`
	}
	if err := d.C.Get(ctx, "DkimSignature", ids, []string{"id", "publicKey"}, &got); err != nil {
		c.Severity, c.Detail = Warning, "Stalwart's DKIM keys couldn't be read"
		return c
	}
	pub := map[string]string{}
	for _, g := range got {
		pub[g.ID] = g.PublicKey
	}
	var bad []string
	for _, k := range active {
		if pub[k.ID] == "" {
			bad = append(bad, k.Selector+" (gone from Stalwart)")
			continue
		}
		for _, srv := range d.Cfg.Resolvers {
			vals, err := resolve.TXT(ctx, srv, dkim.Name(k))
			if d.DNS != nil {
				vals, err = txtVia(ctx, d, srv, dkim.Name(k))
			}
			if err != nil {
				bad = append(bad, fmt.Sprintf("%s (%s: lookup failed)", k.Selector, srv))
				continue
			}
			ok := false
			for _, v := range vals {
				if tagP(v) == pub[k.ID] {
					ok = true
				}
			}
			if !ok {
				bad = append(bad, fmt.Sprintf("%s (%s serves another key)", k.Selector, srv))
			}
		}
	}
	if len(bad) == 0 {
		c.Detail = fmt.Sprintf("%d active key(s) match DNS at both resolvers", len(active))
		return c
	}
	c.Severity = Problem
	c.Detail = "the DKIM key in DNS isn't the one Stalwart signs with: " + joinMax(bad, 4)
	c.Steps = []string{fmt.Sprintf("Republish the mail records (Settings → Domains for an added domain; ./portcullis dns setup --only mail for %s).", d.Cfg.MainDomain)}
	return c
}

// txtVia is resolve.TXT through the Querier (tests).
func txtVia(ctx context.Context, d Deps, server, name string) ([]string, error) {
	m, err := d.DNS(ctx, server, name, dnsTypeTXT, false)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range m.Answer {
		if t, ok := rr.(*dnsTXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}
