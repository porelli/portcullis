package reconcile

// App mail senders (contract §19.14): one submission-only Stalwart
// account per MailState sender, keyed by the Hub's uuid in its
// description (portcullis-sender:<uuid>):
//   - its login is its one address, <username>@<primary domain>, with no
//     alias: submission's mustMatchSender ties MAIL FROM to the login's
//     addresses and the base plan's DATA script (from-check) the From:
//     header to MAIL FROM, so any other From: is refused at DATA;
//   - its permissions Replace every inherited one with
//     stalwart.SenderPermissions (authenticate, emailSend): no
//     emailReceive, IMAP, JMAP, POP3, DAV or Sieve — no mailbox access;
//   - its address is a key of the senders' lookup namespace, which the
//     base plan's RCPT script refuses with 550 5.1.1 (keys are written
//     before the account, removed after it);
//   - the standard per-account limits apply (MtaInboundThrottle keyed on
//     authenticatedAs), and each sender has its own rate limit on top:
//     10 messages a minute (the burst) and 60 an hour (SenderLimits), two
//     MtaInboundThrottles matching only the senders' logins; a message
//     over either is refused with a temporary reply (452 4.4.5);
//   - its credentials follow submission_lan_only like a person's.
// The list is declarative when present (a sender not in it is removed,
// its credentials destroyed first), absent leaves every sender untouched
// (an older Hub), and senders never count in the 50 % mass-removal rule.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/portcullis/mailctl/internal/bootstrap"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// DescSenderPrefix marks a sender's account: portcullis-sender:<uuid>.
// It doesn't start with DescPrefix ("portcullis:"), so a sender is never
// read as a person.
const DescSenderPrefix = "portcullis-sender:"

// NSSenders is the senders' lookup namespace (the base plan's RCPT rule).
const NSSenders = bootstrap.NSSenders

// The senders' rate limits (contract §19.14): per sender (keyed on the
// login), only for the senders' logins (their addresses are the
// NSSenders keys).
const (
	DescSenderMinute = "portcullis: sender messages per minute"
	DescSenderHour   = "portcullis: sender messages per hour"
)

// SenderMatch selects the senders' sessions.
var SenderMatch = fmt.Sprintf("key_exists('%s', authenticated_as)", NSSenders)

// SenderLimit is one of the senders' rate limits.
type SenderLimit struct {
	Desc   string
	Count  int
	Period int64 // ms
}

// SenderLimits: the burst (10 a minute) and the hourly cap (60).
var SenderLimits = []SenderLimit{{DescSenderMinute, 10, 60000}, {DescSenderHour, 60, 3600000}}

// LiveSenderThrottle is one of the senders' MtaInboundThrottles.
type LiveSenderThrottle struct {
	ID, Desc string
	OK       bool // count, period, key, match and enable as wanted
	Count    int
	Period   int64
}

func senderThrottleFields(t SenderLimit) map[string]any {
	return map[string]any{"description": t.Desc, "enable": true, "key": set("authenticatedAs"),
		"rate":  map[string]any{"count": t.Count, "period": t.Period},
		"match": map[string]any{"match": map[string]any{}, "else": SenderMatch}}
}

func liveSenderThrottle(t obj) LiveSenderThrottle {
	lt := LiveSenderThrottle{ID: sval(t, "id"), Desc: sval(t, "description")}
	var rate struct {
		Count  int   `json:"count"`
		Period int64 `json:"period"`
	}
	_ = json.Unmarshal(t["rate"], &rate)
	lt.Count, lt.Period = rate.Count, rate.Period
	var en bool
	_ = json.Unmarshal(t["enable"], &en)
	var key map[string]bool
	_ = json.Unmarshal(t["key"], &key)
	var m struct {
		Match map[string]any `json:"match"`
		Else  string         `json:"else"`
	}
	_ = json.Unmarshal(t["match"], &m)
	for _, w := range SenderLimits {
		if w.Desc == lt.Desc {
			lt.OK = en && rate.Count == w.Count && rate.Period == w.Period && trueSet(key, set("authenticatedAs")) &&
				len(m.Match) == 0 && m.Else == SenderMatch
		}
	}
	return lt
}

// LiveSender is one sender account in Stalwart.
type LiveSender struct {
	ID, Name, DomainID, UUID string
	Aliases                  []string
	PermsOK                  bool   // exactly Replace SenderPermissions, nothing disabled
	Roles                    string // the roles' @type
}

// SenderAccountPermissions is a sender account's permissions.
func SenderAccountPermissions() map[string]any {
	return map[string]any{"@type": "Replace", "enabledPermissions": set(stalwart.SenderPermissions...),
		"disabledPermissions": map[string]bool{}}
}

func liveSender(a obj, l *Live) LiveSender {
	ls := LiveSender{ID: sval(a, "id"), Name: sval(a, "name"), DomainID: sval(a, "domainId"),
		UUID: strings.TrimPrefix(sval(a, "description"), DescSenderPrefix), Aliases: aliasAddrs(a["aliases"], l.DomainNames)}
	var perms struct {
		Type     string          `json:"@type"`
		Enabled  map[string]bool `json:"enabledPermissions"`
		Disabled map[string]bool `json:"disabledPermissions"`
	}
	_ = json.Unmarshal(a["permissions"], &perms)
	want := set(stalwart.SenderPermissions...)
	ls.PermsOK = perms.Type == "Replace" && trueSet(perms.Enabled, want) && len(trueKeys(perms.Disabled)) == 0
	var roles struct {
		Type string `json:"@type"`
	}
	_ = json.Unmarshal(a["roles"], &roles)
	ls.Roles = roles.Type
	return ls
}

func trueKeys(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	return out
}

// trueSet: got's true keys are exactly want's.
func trueSet(got, want map[string]bool) bool {
	keys := trueKeys(got)
	if len(keys) != len(want) {
		return false
	}
	for _, k := range keys {
		if !want[k] {
			return false
		}
	}
	return true
}

// SenderSpec is one wanted sender account (ID "" = create).
type SenderSpec struct {
	ID, Username, UUID string
}

// SenderOps is the senders' work of one document.
type SenderOps struct {
	Destroy     []LiveSender // their mail passwords first, then the account
	Accounts    []SenderSpec // to create or put back to the wanted shape
	Keys        []string     // addresses to add to NSSenders
	DestroyKeys []string     // NSSenders key ids
	// Throttles to create (ID "") or put back; DestroyThrottles are
	// duplicates of one limit.
	Throttles        []LiveSenderThrottle
	DestroyThrottles []string
}

// Empty reports no work.
func (o SenderOps) Empty() bool {
	return len(o.Destroy)+len(o.Accounts)+len(o.Keys)+len(o.DestroyKeys)+len(o.Throttles)+len(o.DestroyThrottles) == 0
}

// PlanSenders computes the senders' ops. An absent senders list (an older
// Hub) is no work at all: existing senders, their credentials and keys
// stay as they are.
func PlanSenders(l *Live, want *state.Doc) SenderOps {
	var ops SenderOps
	// The rate limits are kept whatever the list (they only ever match a
	// sender's login): an absent list leaves the senders, never their
	// limits, unenforced.
	for _, w := range SenderLimits {
		found := false
		for _, lt := range l.SenderThrottles {
			if lt.Desc != w.Desc {
				continue
			}
			if found {
				ops.DestroyThrottles = append(ops.DestroyThrottles, lt.ID)
				continue
			}
			found = true
			if !lt.OK {
				ops.Throttles = append(ops.Throttles, LiveSenderThrottle{ID: lt.ID, Desc: w.Desc})
			}
		}
		if !found {
			ops.Throttles = append(ops.Throttles, LiveSenderThrottle{Desc: w.Desc})
		}
	}
	if !want.SendersPresent() {
		return ops
	}
	byUUID := map[string]state.Sender{}
	for _, s := range want.SenderList() {
		byUUID[s.UUID] = s
	}
	primary := l.Domains[want.PrimaryDomain]
	kept := map[string]LiveSender{}
	for _, ls := range l.Senders {
		_, wanted := byUUID[ls.UUID]
		if _, dup := kept[ls.UUID]; !wanted || dup {
			// Not in the list, or a second account with that uuid (a hand
			// edit, a half-failed create): removed.
			ops.Destroy = append(ops.Destroy, ls)
			continue
		}
		kept[ls.UUID] = ls
	}
	for _, s := range want.SenderList() {
		ls, ok := kept[s.UUID]
		if !ok {
			ops.Accounts = append(ops.Accounts, SenderSpec{Username: s.Username, UUID: s.UUID})
			continue
		}
		if ls.Name != s.Username || ls.DomainID != primary || primary == "" || len(ls.Aliases) > 0 || !ls.PermsOK || ls.Roles != "User" {
			ops.Accounts = append(ops.Accounts, SenderSpec{ID: ls.ID, Username: s.Username, UUID: s.UUID})
		}
	}
	wantKeys := map[string]bool{}
	for _, s := range want.SenderList() {
		wantKeys[s.Address] = true
	}
	for _, k := range l.SenderKeys {
		if wantKeys[k.Key] {
			delete(wantKeys, k.Key)
		} else {
			ops.DestroyKeys = append(ops.DestroyKeys, k.ID)
		}
	}
	for k := range wantKeys {
		ops.Keys = append(ops.Keys, k)
	}
	sort.Strings(ops.Keys)
	return ops
}

// ApplySenders runs the senders' ops: removals (mail passwords first),
// then the RCPT keys (reloaded before any account exists), then the
// accounts, then InvalidateCaches.
func ApplySenders(ctx context.Context, c *stalwart.Client, l *Live, want *state.Doc, ops SenderOps) error {
	if ops.Empty() {
		return nil
	}
	if len(ops.Destroy) > 0 {
		var ids []string
		for _, ls := range ops.Destroy {
			if err := DestroyAppPasswords(ctx, c, ls.ID); err != nil {
				return fmt.Errorf("removing the sender %s: %w", ls.Name, err)
			}
			ids = append(ids, ls.ID)
		}
		r, err := c.Set(ctx, "Account", nil, nil, ids)
		if err := setErr("Account", r, err); err != nil {
			return fmt.Errorf("removing senders: %w", err)
		}
		for _, id := range ids {
			if _, still := r.NotDestroyed[id]; still {
				return fmt.Errorf("removing senders: account %s not destroyed", id)
			}
		}
	}
	if len(ops.Keys)+len(ops.DestroyKeys) > 0 {
		create := map[string]any{}
		for i, k := range ops.Keys {
			create[fmt.Sprintf("s%d", i)] = map[string]any{"namespace": NSSenders, "key": k, "isGlobPattern": false}
		}
		r, err := c.Set(ctx, "MemoryLookupKey", create, nil, ops.DestroyKeys)
		if err := setErr("MemoryLookupKey", r, err); err != nil {
			return fmt.Errorf("the senders' RCPT keys: %w", err)
		}
		if err := c.Action(ctx, "ReloadLookupStores"); err != nil {
			return fmt.Errorf("ReloadLookupStores: %w", err)
		}
	}
	if len(ops.Throttles)+len(ops.DestroyThrottles) > 0 {
		create := map[string]any{}
		update := map[string]map[string]any{}
		for i, t := range ops.Throttles {
			var f map[string]any
			for _, w := range SenderLimits {
				if w.Desc == t.Desc {
					f = senderThrottleFields(w)
				}
			}
			if t.ID == "" {
				create[fmt.Sprintf("r%d", i)] = f
			} else {
				update[t.ID] = f
			}
		}
		r, err := c.Set(ctx, "MtaInboundThrottle", create, update, ops.DestroyThrottles)
		if err := setErr("MtaInboundThrottle", r, err); err != nil {
			return fmt.Errorf("the senders' rate limits: %w", err)
		}
		if err := c.Action(ctx, "ReloadSettings"); err != nil {
			return fmt.Errorf("ReloadSettings: %w", err)
		}
	}
	if len(ops.Destroy)+len(ops.Keys)+len(ops.DestroyKeys)+len(ops.Accounts) == 0 {
		return nil
	}
	primary := l.Domains[want.PrimaryDomain]
	if primary == "" && len(ops.Accounts) > 0 {
		return fmt.Errorf("senders: the primary domain %s isn't in the mail server yet", want.PrimaryDomain)
	}
	for _, a := range ops.Accounts {
		fields := map[string]any{"name": a.Username, "domainId": primary, "aliases": map[string]any{}, "quotas": map[string]any{},
			"roles": map[string]any{"@type": "User"}, "permissions": SenderAccountPermissions()}
		var r stalwart.SetResult
		var err error
		if a.ID == "" {
			pw, perr := randomPassword()
			if perr != nil {
				return perr
			}
			fields["@type"], fields["description"] = "User", DescSenderPrefix+a.UUID
			fields["credentials"] = map[string]any{"0": map[string]any{"@type": "Password", "secret": pw}}
			r, err = c.Set(ctx, "Account", map[string]any{"s": fields}, nil, nil)
		} else {
			r, err = c.Set(ctx, "Account", nil, map[string]map[string]any{a.ID: fields}, nil)
		}
		if err := setErr("Account", r, err); err != nil {
			return fmt.Errorf("sender %s: %w", a.Username, err)
		}
	}
	if err := c.Action(ctx, "InvalidateCaches"); err != nil {
		return fmt.Errorf("InvalidateCaches: %w", err)
	}
	return nil
}

// FindSender is the live account id of a document sender (by uuid and
// name together). "" = none.
func FindSender(l *Live, d *state.Doc, username string) string {
	s, ok := d.Sender(username)
	if !ok {
		return ""
	}
	for _, ls := range l.Senders {
		if ls.UUID == s.UUID && ls.Name == s.Username && ls.DomainID == l.Domains[d.PrimaryDomain] {
			return ls.ID
		}
	}
	return ""
}

func init() {
	for _, u := range []stalwart.Use{
		{Object: "x:Permissions", Variant: "Replace", Field: "enabledPermissions"},
		{Object: "x:Permissions", Variant: "Replace", Field: "disabledPermissions"},
	} {
		stalwart.Used = append(stalwart.Used, u)
	}
}
