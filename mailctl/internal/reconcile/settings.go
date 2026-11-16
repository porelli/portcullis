package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// Spam list namespaces (the base plan's PORTCULLIS_ALLOW / _BLOCK rules).
const (
	NSSpamAllow = "portcullis-allow"
	NSSpamBlock = "portcullis-block"
)

// Outbound limits (P26): an MtaOutboundThrottle keyed on the sender holds
// the excess in the queue (rate_held), next to the inbound authenticatedAs
// throttles (the hard cap).
const (
	DescOutHour = "portcullis: outbound per hour"
	DescOutDay  = "portcullis: outbound per day"
)

// SettingsOpts are the inputs the document doesn't carry.
type SettingsOpts struct {
	Rewritten  bool   // client addresses rewritten: the IP DNSBLs off (M9)
	DQSKeyFile string // Spamhaus DQS key ("" / empty file = none)
}

var (
	reDQSKey  = regexp.MustCompile(`^[a-z0-9]{8,64}$`)
	reDQSZone = regexp.MustCompile(`\.[a-z0-9]{8,64}\.(zen|dbl)\.dq\.spamhaus\.net`)
	rePubZone = regexp.MustCompile(`\.(zen|dbl)\.spamhaus\.org`)
)

// DQSKey reads the DQS key file: "" when unset; a malformed key is an
// error (it goes into Stalwart's expressions: never anything but
// [a-z0-9]).
func DQSKey(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("the DQS key file: %w", err)
	}
	k := strings.ToLower(strings.TrimSpace(string(b)))
	if k == "" {
		return "", nil
	}
	if !reDQSKey.MatchString(k) {
		return "", errors.New("MAIL_SPAMHAUS_DQS_KEY must be 8-64 letters and digits")
	}
	logx.AddSecret(k)
	return k, nil
}

// zoneFor rewrites a Spamhaus zone expression for the DQS key (or back to
// the public zones without one).
func zoneFor(s, key string) string {
	s = reDQSZone.ReplaceAllString(s, ".$1.spamhaus.org")
	if key != "" {
		s = rePubZone.ReplaceAllString(s, "."+key+".$1.dq.spamhaus.net")
	}
	return s
}

func zoneExpr(raw json.RawMessage, key string) (json.RawMessage, bool) {
	var e struct {
		Match map[string]struct {
			If   string `json:"if"`
			Then string `json:"then"`
		} `json:"match"`
		Else string `json:"else"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return raw, false
	}
	changed := false
	if z := zoneFor(e.Else, key); z != e.Else {
		e.Else, changed = z, true
	}
	for k, m := range e.Match {
		if z := zoneFor(m.Then, key); z != m.Then {
			m.Then, changed = z, true
			e.Match[k] = m
		}
	}
	if e.Match == nil {
		e.Match = map[string]struct {
			If   string `json:"if"`
			Then string `json:"then"`
		}{}
	}
	b, _ := json.Marshal(e)
	return b, changed
}

// wantDNSBL: the document's switch for a DNSBL server by name (ok=false:
// not one of the three, left alone).
func wantDNSBL(name string, d state.DNSBL) (bool, bool) {
	n := strings.ToUpper(name)
	switch {
	case strings.Contains(n, "SPAMHAUS"):
		return d.Spamhaus, true
	case strings.Contains(n, "SPAMCOP"):
		return d.Spamcop, true
	case strings.Contains(n, "BARRACUDA"):
		return d.Barracuda, true
	}
	return false, false
}

// Settings makes the spam scores, the DNSBL switches (and the DQS zones),
// the allow / block lists and the outbound limits match the document. It
// reads everything each pass (the spam rules' import may rewrite them).
func Settings(ctx context.Context, c *stalwart.Client, doc *state.Doc, o SettingsOpts) error {
	key, keyErr := DQSKey(o.DQSKeyFile)
	reload, lookups := false, false
	// Scores.
	var ss []struct {
		Spam   float64 `json:"scoreSpam"`
		Reject float64 `json:"scoreReject"`
	}
	if err := c.Get(ctx, "SpamSettings", []string{"singleton"}, []string{"scoreSpam", "scoreReject"}, &ss); err != nil {
		return fmt.Errorf("x:SpamSettings/get: %w", err)
	}
	if len(ss) != 1 || ss[0].Spam != float64(doc.Spam.JunkScore) || ss[0].Reject != float64(doc.Spam.RejectScore) {
		r, err := c.Set(ctx, "SpamSettings", nil, map[string]map[string]any{"singleton": {"scoreSpam": doc.Spam.JunkScore, "scoreReject": doc.Spam.RejectScore}}, nil)
		if err := setErr("SpamSettings", r, err); err != nil {
			return err
		}
		reload = true
	}
	// DNSBL servers.
	servers, err := getAll(ctx, c, "SpamDnsblServer", nil)
	if err != nil {
		return err
	}
	upd := map[string]map[string]any{}
	for _, s := range servers {
		var enable bool
		_ = json.Unmarshal(s["enable"], &enable)
		name, typ := sval(s, "name"), sval(s, "@type")
		want, managed := wantDNSBL(name, doc.Spam.DNSBL)
		if !managed {
			want = enable
		}
		if o.Rewritten && typ == "Ip" {
			want = false
		}
		u := map[string]any{}
		if want != enable {
			u["enable"] = want
		}
		if strings.Contains(strings.ToUpper(name), "SPAMHAUS") && keyErr == nil {
			if z, changed := zoneExpr(s["zone"], key); changed {
				u["zone"] = z
			}
		}
		if len(u) > 0 {
			upd[sval(s, "id")] = u
		}
	}
	if len(upd) > 0 {
		r, err := c.Set(ctx, "SpamDnsblServer", nil, upd, nil)
		if err := setErr("SpamDnsblServer", r, err); err != nil {
			return err
		}
		reload = true
	}
	// Allow / block lists.
	want := map[string]bool{}
	for _, e := range doc.Spam.Allow {
		want[NSSpamAllow+"|"+strings.ToLower(e)] = true
	}
	for _, e := range doc.Spam.Block {
		want[NSSpamBlock+"|"+strings.ToLower(e)] = true
	}
	var destroy []string
	for _, ns := range []string{NSSpamAllow, NSSpamBlock} {
		keys, err := getAll(ctx, c, "MemoryLookupKey", map[string]string{"namespace": ns})
		if err != nil {
			return err
		}
		for _, k := range keys {
			id := ns + "|" + sval(k, "key")
			if sval(k, "namespace") != ns {
				continue
			}
			if want[id] {
				delete(want, id)
			} else {
				destroy = append(destroy, sval(k, "id"))
			}
		}
	}
	create := map[string]any{}
	ws := make([]string, 0, len(want))
	for k := range want {
		ws = append(ws, k)
	}
	sort.Strings(ws)
	for i, k := range ws {
		ns, v, _ := strings.Cut(k, "|")
		create[fmt.Sprintf("s%d", i)] = map[string]any{"namespace": ns, "key": v, "isGlobPattern": false}
	}
	if len(create) > 0 || len(destroy) > 0 {
		r, err := c.Set(ctx, "MemoryLookupKey", create, nil, destroy)
		if err := setErr("MemoryLookupKey", r, err); err != nil {
			return err
		}
		lookups = true
	}
	// Outbound limits.
	if changed, err := outboundThrottles(ctx, c, doc.Limits); err != nil {
		return err
	} else if changed {
		reload = true
	}
	if reload {
		if err := c.Action(ctx, "ReloadSettings"); err != nil {
			return fmt.Errorf("ReloadSettings: %w", err)
		}
	}
	if lookups {
		if err := c.Action(ctx, "ReloadLookupStores"); err != nil {
			return fmt.Errorf("ReloadLookupStores: %w", err)
		}
	}
	return keyErr
}

// OutboundMatch: our own senders only (bounces and forwarded mail aren't
// a person's outbound mail).
const OutboundMatch = "!is_empty(sender_domain) && is_local_domain(sender_domain)"

func outboundThrottles(ctx context.Context, c *stalwart.Client, l state.Limits) (bool, error) {
	live, err := getAll(ctx, c, "MtaOutboundThrottle", nil)
	if err != nil {
		return false, err
	}
	type rate struct {
		Count  int   `json:"count"`
		Period int64 `json:"period"`
	}
	create := map[string]any{}
	update := map[string]map[string]any{}
	for i, w := range []struct {
		desc  string
		count int
		per   int64
	}{{DescOutHour, l.RecipientsPerHour, 3600000}, {DescOutDay, l.RecipientsPerDay, 86400000}} {
		f := map[string]any{"description": w.desc, "enable": true, "key": set("sender"),
			"rate":  map[string]any{"count": w.count, "period": w.per},
			"match": map[string]any{"match": map[string]any{}, "else": OutboundMatch}}
		found := false
		for _, t := range live {
			if sval(t, "description") != w.desc {
				continue
			}
			found = true
			var r rate
			var en bool
			_ = json.Unmarshal(t["rate"], &r)
			_ = json.Unmarshal(t["enable"], &en)
			var m struct {
				Else string `json:"else"`
			}
			_ = json.Unmarshal(t["match"], &m)
			if r.Count != w.count || r.Period != w.per || !en || m.Else != OutboundMatch {
				update[sval(t, "id")] = f
			}
		}
		if !found {
			create[fmt.Sprintf("o%d", i)] = f
		}
	}
	if len(create) == 0 && len(update) == 0 {
		return false, nil
	}
	r, err := c.Set(ctx, "MtaOutboundThrottle", create, update, nil)
	return true, setErr("MtaOutboundThrottle", r, err)
}

func init() {
	for _, u := range []stalwart.Use{
		{Object: "x:SpamSettings", Field: "scoreSpam"}, {Object: "x:SpamSettings", Field: "scoreReject"},
		{Object: "x:SpamDnsblServer", Variant: "Ip", Field: "enable"}, {Object: "x:SpamDnsblServer", Variant: "Ip", Field: "zone"},
		{Object: "x:SpamDnsblServer", Variant: "Ip", Field: "name"}, {Object: "x:SpamDnsblServer", Variant: "Domain", Field: "zone"},
		{Object: "x:MemoryLookupKey", Field: "namespace"}, {Object: "x:MemoryLookupKey", Field: "key"}, {Object: "x:MemoryLookupKey", Field: "isGlobPattern"},
		{Object: "x:MtaOutboundThrottle", Field: "description"}, {Object: "x:MtaOutboundThrottle", Field: "enable"},
		{Object: "x:MtaOutboundThrottle", Field: "key"}, {Object: "x:MtaOutboundThrottle", Field: "rate"}, {Object: "x:MtaOutboundThrottle", Field: "match"},
		{Enum: "MtaOutboundThrottleKey", Value: "sender"},
		{Object: "x:Action", Variant: "ReloadLookupStores"}, {Enum: "ActionType", Value: "ReloadLookupStores"},
	} {
		stalwart.Used = append(stalwart.Used, u)
	}
}
