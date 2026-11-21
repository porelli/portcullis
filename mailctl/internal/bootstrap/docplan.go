package bootstrap

import (
	"context"
	"fmt"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// The base plan's parts that MailState v2 carries (the host name, the
// client address mode and the relay): the adapter converges them on every
// reconcile pass with its own API key, so a Settings → Mail change reaches
// Stalwart without a bootstrap (the bootstrap job knows no document).
var (
	docSingletons  = map[string]bool{"SystemSettings": true, "SenderAuth": true, "MtaOutboundStrategy": true, "Security": true}
	docCollections = map[string]bool{"MtaTlsStrategy": true, "MtaRoute": true}
)

// DocParams are the base plan's inputs from the accepted document.
func DocParams(doc *state.Doc) Params {
	p := Params{Hostname: doc.MailHostname, PrimaryDomain: doc.PrimaryDomain, ClientIP: doc.ClientIP}
	if r := doc.Relay; r != nil {
		p.Relay = &Relay{Host: r.Host, Port: r.Port, Username: r.Username}
	}
	return p
}

// ensureSingleton writes only the fields of s that differ (true: wrote).
func ensureSingleton(ctx context.Context, c *stalwart.Client, s Singleton) (bool, error) {
	var have []object
	if err := c.Get(ctx, s.Object, []string{"singleton"}, nil, &have); err != nil {
		return false, fmt.Errorf("x:%s/get: %w", s.Object, err)
	}
	var cur object
	if len(have) == 1 {
		cur = have[0]
	}
	patch := differs(cur, s.Patch, nil)
	if len(patch) == 0 {
		return false, nil
	}
	return true, updateSingleton(ctx, c, Singleton{s.Object, patch})
}

// ApplyDoc converges the document's part of the base plan: the routes and
// TLS strategies (the relay), the host name, sender authentication and
// security (degraded mode) and the outbound strategy; ReloadSettings once
// when anything changed. The relay route is removed with the relay.
func ApplyDoc(ctx context.Context, c *stalwart.Client, doc *state.Doc) (bool, error) {
	p := DocParams(doc)
	changed := false
	for _, n := range p.Collections() {
		if !docCollections[n.Object] {
			continue
		}
		if n.Object == "MtaTlsStrategy" {
			ch, err := tightenStrategies(ctx, c, n.Want)
			if err != nil {
				return changed, err
			}
			changed = changed || ch
			continue
		}
		if n.Object == "MtaRoute" {
			n.DestroyOthers = true
		}
		_, ch, err := ensure(ctx, c, n)
		if err != nil {
			return changed, err
		}
		changed = changed || ch
	}
	for _, s := range p.Singletons() {
		if !docSingletons[s.Object] {
			continue
		}
		if s.Object == "SystemSettings" {
			// includeSecrets re-asserted false on every document (contract
			// §19.13: masking depends on it).
			patch := map[string]any{"defaultHostname": p.Hostname, "includeSecrets": false}
			// The default domain follows the primary domain once it exists
			// (the bootstrap left the parking domain there).
			if id, err := domainID(ctx, c, p.PrimaryDomain); err != nil {
				return changed, err
			} else if id != "" {
				patch["defaultDomainId"] = id
			}
			s = Singleton{s.Object, patch}
		}
		ch, err := ensureSingleton(ctx, c, s)
		if err != nil {
			return changed, err
		}
		changed = changed || ch
	}
	if changed {
		if err := c.Action(ctx, "ReloadSettings"); err != nil {
			return changed, fmt.Errorf("ReloadSettings: %w", err)
		}
	}
	return changed, nil
}

// tlsRank orders a strategy's dane / mtaSts / startTls values (stricter =
// higher; unknown = strictest, never touched).
var tlsRank = map[string]int{"disable": 0, "optional": 1, "require": 2}

// tightenStrategies creates the wanted TLS strategies that are missing and
// only ever tightens an existing one (mtaSts, startTls up; allowInvalidCerts
// to false): a loosening happens only on the DANE / MTA-STS machines' gated
// paths. dane is the DANE machine's: never changed here, and a new strategy
// takes "disable" while any existing one has it (DANE is off).
func tightenStrategies(ctx context.Context, c *stalwart.Client, want []map[string]any) (bool, error) {
	have, err := getAll(ctx, c, "MtaTlsStrategy")
	if err != nil {
		return false, err
	}
	byName := map[string]object{}
	daneOff := false
	for _, o := range have {
		byName[str(o, "name")] = o
		if str(o, "dane") == "disable" {
			daneOff = true
		}
	}
	create := map[string]any{}
	update := map[string]map[string]any{}
	for i, w := range want {
		o, ok := byName[w["name"].(string)]
		if !ok {
			nw := map[string]any{}
			for k, v := range w {
				nw[k] = v
			}
			if daneOff {
				nw["dane"] = "disable"
			}
			create[fmt.Sprintf("c%d", i)] = nw
			continue
		}
		patch := map[string]any{}
		for _, k := range []string{"mtaSts", "startTls"} {
			cur, ok := tlsRank[str(o, k)]
			if wv, _ := w[k].(string); ok && tlsRank[wv] > cur {
				patch[k] = wv
			}
		}
		if string(o["allowInvalidCerts"]) == "true" && w["allowInvalidCerts"] == false {
			patch["allowInvalidCerts"] = false
		}
		if len(patch) > 0 {
			update[str(o, "id")] = patch
		}
	}
	if len(create) == 0 && len(update) == 0 {
		return false, nil
	}
	r, err := c.Set(ctx, "MtaTlsStrategy", create, update, nil)
	return true, checkSet("MtaTlsStrategy", r, err)
}

// domainID is the id of the Domain named name ("" = none yet).
func domainID(ctx context.Context, c *stalwart.Client, name string) (string, error) {
	doms, err := getAll(ctx, c, "Domain")
	if err != nil {
		return "", err
	}
	for _, d := range doms {
		if str(d, "name") == name {
			return str(d, "id"), nil
		}
	}
	return "", nil
}
