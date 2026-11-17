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
			s = Singleton{s.Object, map[string]any{"defaultHostname": p.Hostname}}
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
