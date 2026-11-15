package reconcile

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// ErrMassRemoval: the document would remove more than half of the live
// accounts without confirm_mass_removal (contract §19.5: 409).
var ErrMassRemoval = errors.New("the document removes more than 50 % of the mail accounts without confirm_mass_removal")

// Removal parks one account (M4): its app passwords destroyed, then
// authenticate / emailSend / emailReceive disabled, the aliases cleared,
// renamed former-<uuid>@<parking domain>.
type Removal struct {
	AccountID, UUID, Username string
}

// AccountSpec is one wanted account (ID "" = create).
type AccountSpec struct {
	ID, Username, UUID string
	Aliases            []string // every address but the primary
	Quota              int64
	Rename             bool // name / domain differ (a primary domain change, a rejoin)
	Enable             bool // re-enable (a rejoin)
}

// ListSpec is one wanted list (ID "" = create).
type ListSpec struct {
	ID, Address, Desc string
	Recipients        []string
}

// KeySpec is one lookup entry.
type KeySpec struct{ Namespace, Key string }

// ThrottleSpec is one wanted limit (ID "" = create).
type ThrottleSpec struct {
	ID, Desc string
	Count    int
	Period   int64
}

// Ops is the ordered work of one document.
type Ops struct {
	Removals       []Removal
	Purges         []string // former accounts past retention (ids)
	PurgedUUIDs    []string
	Domains        []string // to create
	Accounts       []AccountSpec
	MailctlAliases []string // nil = unchanged
	Lists          []ListSpec
	DestroyLists   []string
	Keys           []KeySpec
	DestroyKeys    []string
	Throttles      []ThrottleSpec
	Empty          bool
}

func sortedEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Plan computes the ops that make Stalwart match want. former is mailctl's
// record of parked accounts (old uuid → since); retention is
// MAIL_FORMER_RETENTION.
func Plan(l *Live, want *state.Doc, former map[string]state.Former, now time.Time, retention time.Duration) (Ops, error) {
	var ops Ops
	byUUID := map[string]state.Account{}
	for _, a := range want.Accounts {
		byUUID[a.UUID] = a
	}
	primaryID := l.Domains[want.PrimaryDomain]
	active := 0
	var keep []LiveAccount
	for _, la := range l.Accounts {
		parked := la.Parked(l)
		if !parked {
			active++
		}
		wa, wanted := byUUID[la.UUID]
		switch {
		case !parked && !wanted:
			// Gone from the document, or its username came back with
			// another uuid: parked, never deleted at once.
			ops.Removals = append(ops.Removals, Removal{AccountID: la.ID, UUID: la.UUID, Username: la.Name})
		case parked && !wanted:
			if f, ok := former[la.UUID]; ok && now.Sub(f.Since) >= retention {
				ops.Purges = append(ops.Purges, la.ID)
				ops.PurgedUUIDs = append(ops.PurgedUUIDs, la.UUID)
			}
		default:
			_ = wa
			keep = append(keep, la)
		}
	}
	if !want.ConfirmMassRemoval && active > 0 && len(ops.Removals)*2 > active {
		return Ops{}, ErrMassRemoval
	}
	for _, d := range want.Domains {
		if _, ok := l.Domains[d.Name]; !ok {
			ops.Domains = append(ops.Domains, d.Name)
		}
	}
	// Aliases per username (the alias entries of the document).
	aliasOf := map[string][]string{}
	for _, al := range want.Aliases {
		aliasOf[al.Username] = append(aliasOf[al.Username], al.Address)
	}
	liveByUUID := map[string]LiveAccount{}
	for _, la := range keep {
		liveByUUID[la.UUID] = la
	}
	for _, wa := range want.Accounts {
		aliases := append(append([]string{}, wa.Addresses[1:]...), aliasOf[wa.Username]...)
		spec := AccountSpec{Username: wa.Username, UUID: wa.UUID, Aliases: aliases, Quota: wa.QuotaBytes}
		la, ok := liveByUUID[wa.UUID]
		if !ok {
			ops.Accounts = append(ops.Accounts, spec)
			continue
		}
		spec.ID = la.ID
		spec.Rename = la.Name != wa.Username || la.DomainID != primaryID || primaryID == ""
		spec.Enable = la.Disabled || la.Parked(l)
		if spec.Rename || spec.Enable || !sortedEq(la.Aliases, aliases) || la.Quota != wa.QuotaBytes || la.Roles != "User" {
			ops.Accounts = append(ops.Accounts, spec)
		}
	}
	// The reserved addresses of every domain that takes mail.
	var postmasters []string
	for _, u := range want.Postmaster {
		if a, ok := want.Account(u); ok {
			postmasters = append(postmasters, a.Primary())
		}
	}
	wantLists := map[string]ListSpec{}
	var reports []string
	for _, d := range want.Domains {
		if d.Mail == state.MailOff {
			continue
		}
		reports = append(reports, "dmarc-reports@"+d.Name, "tls-reports@"+d.Name)
		if len(postmasters) > 0 {
			for _, lp := range []string{"postmaster", "abuse"} {
				wantLists[lp+"@"+d.Name] = ListSpec{Address: lp + "@" + d.Name, Desc: DescReserved, Recipients: postmasters}
			}
		}
	}
	sort.Strings(reports)
	if !sortedEq(l.MailctlAliases, reports) {
		if reports == nil {
			reports = []string{}
		}
		ops.MailctlAliases = reports
	}
	wantKeys := map[KeySpec]bool{}
	for _, li := range want.Lists {
		var rec []string
		for _, m := range li.Members {
			a, _ := want.Account(m)
			rec = append(rec, a.Primary())
		}
		sort.Strings(rec)
		wantLists[li.Address] = ListSpec{Address: li.Address, Desc: DescList, Recipients: rec}
		if li.Posting == "members" {
			wantKeys[KeySpec{NSMembersOnly, li.Address}] = true
			for _, r := range rec {
				wantKeys[KeySpec{NSPosters, li.Address + "|" + r}] = true
			}
		}
	}
	for _, ll := range l.Lists {
		w, ok := wantLists[ll.Address]
		if !ok {
			ops.DestroyLists = append(ops.DestroyLists, ll.ID)
			continue
		}
		delete(wantLists, ll.Address)
		if !sortedEq(ll.Recipients, w.Recipients) || ll.Desc != w.Desc {
			w.ID = ll.ID
			ops.Lists = append(ops.Lists, w)
		}
	}
	for _, w := range wantLists {
		ops.Lists = append(ops.Lists, w)
	}
	sort.Slice(ops.Lists, func(i, j int) bool { return ops.Lists[i].Address < ops.Lists[j].Address })
	for _, k := range l.Keys {
		ks := KeySpec{k.Namespace, k.Key}
		if wantKeys[ks] {
			delete(wantKeys, ks)
		} else {
			ops.DestroyKeys = append(ops.DestroyKeys, k.ID)
		}
	}
	for k := range wantKeys {
		ops.Keys = append(ops.Keys, k)
	}
	sort.Slice(ops.Keys, func(i, j int) bool {
		return ops.Keys[i].Namespace+ops.Keys[i].Key < ops.Keys[j].Namespace+ops.Keys[j].Key
	})
	for _, t := range []ThrottleSpec{
		{Desc: DescLimitHour, Count: want.Limits.RecipientsPerHour, Period: 3600000},
		{Desc: DescLimitDay, Count: want.Limits.RecipientsPerDay, Period: 86400000},
	} {
		found := false
		for _, lt := range l.Throttles {
			if lt.Desc == t.Desc {
				found = true
				if lt.Count != t.Count || lt.Period != t.Period {
					t.ID = lt.ID
					ops.Throttles = append(ops.Throttles, t)
				}
			}
		}
		if !found {
			ops.Throttles = append(ops.Throttles, t)
		}
	}
	ops.Empty = len(ops.Removals)+len(ops.Purges)+len(ops.Domains)+len(ops.Accounts)+len(ops.Lists)+
		len(ops.DestroyLists)+len(ops.Keys)+len(ops.DestroyKeys)+len(ops.Throttles) == 0 && ops.MailctlAliases == nil
	return ops, nil
}

func set(vals ...string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// aliasList is an EmailAlias objectList for addresses.
func aliasList(addrs []string, domains map[string]string) (map[string]any, error) {
	m := map[string]any{}
	for i, a := range addrs {
		local, dom, ok := state.SplitAddress(a)
		if !ok || domains[dom] == "" {
			return nil, fmt.Errorf("alias %s: no such domain", a)
		}
		m[fmt.Sprint(i)] = map[string]any{"name": local, "domainId": domains[dom], "enable": true}
	}
	return m, nil
}

func setErr(obj string, r stalwart.SetResult, err error) error {
	if err != nil {
		return fmt.Errorf("x:%s/set: %w", obj, err)
	}
	if e := r.Failed(); e != nil {
		return fmt.Errorf("x:%s/set: %w", obj, e)
	}
	return nil
}

func randomPassword() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Disabled is a parked account's permissions (M4).
var Disabled = map[string]any{"@type": "Merge", "enabledPermissions": map[string]bool{},
	"disabledPermissions": set("authenticate", "emailSend", "emailReceive")}

// Park ends an account's mail (removal or uuid change): app passwords
// first, then the permissions, aliases and name in one update. The caller
// runs InvalidateCaches after its removals.
func Park(ctx context.Context, c *stalwart.Client, l *Live, accountID, uuid string) error {
	if err := DestroyAppPasswords(ctx, c, accountID); err != nil {
		return err
	}
	parking := l.Domains[state.ParkingDomain]
	if parking == "" {
		return errors.New("the parking domain is missing (run ./portcullis mail enable)")
	}
	r, err := c.Set(ctx, "Account", nil, map[string]map[string]any{accountID: {
		"permissions": Disabled, "aliases": map[string]any{}, "name": FormerPrefix + uuid, "domainId": parking,
	}}, nil)
	return setErr("Account", r, err)
}

// DestroyAppPasswords destroys every app password of one account.
func DestroyAppPasswords(ctx context.Context, c *stalwart.Client, accountID string) error {
	ac := c.As(accountID)
	ids, err := ac.Query(ctx, "AppPassword", nil)
	if err != nil {
		return fmt.Errorf("x:AppPassword/query: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}
	r, err := ac.Set(ctx, "AppPassword", nil, nil, ids)
	return setErr("AppPassword", r, err)
}

// Apply runs ops in order. Removals first, then InvalidateCaches; a removal
// that fails stops the run (it is retried: the person stays removed in
// mailctl's state). onParked records each parked account.
func Apply(ctx context.Context, c *stalwart.Client, l *Live, want *state.Doc, ops Ops, onParked func(uuid, username string) error) error {
	for _, rm := range ops.Removals {
		if err := Park(ctx, c, l, rm.AccountID, rm.UUID); err != nil {
			return fmt.Errorf("removing %s: %w", rm.Username, err)
		}
		if onParked != nil {
			if err := onParked(rm.UUID, rm.Username); err != nil {
				return err
			}
		}
	}
	if len(ops.Removals) > 0 {
		if err := c.Action(ctx, "InvalidateCaches"); err != nil {
			return fmt.Errorf("InvalidateCaches: %w", err)
		}
	}
	if len(ops.Purges) > 0 {
		for _, id := range ops.Purges {
			if err := DestroyAppPasswords(ctx, c, id); err != nil {
				return err
			}
		}
		r, err := c.Set(ctx, "Account", nil, nil, ops.Purges)
		if err := setErr("Account", r, err); err != nil {
			return err
		}
	}
	if len(ops.Domains) > 0 {
		create := map[string]any{}
		for i, d := range ops.Domains {
			create[fmt.Sprintf("d%d", i)] = map[string]any{"name": d,
				"certificateManagement": map[string]any{"@type": "Manual"}, "dnsManagement": map[string]any{"@type": "Manual"},
				"dkimManagement": map[string]any{"@type": "Manual"}}
		}
		r, err := c.Set(ctx, "Domain", create, nil, nil)
		if err := setErr("Domain", r, err); err != nil {
			return err
		}
		for i, d := range ops.Domains {
			id := r.CreatedID(fmt.Sprintf("d%d", i))
			l.Domains[d], l.DomainNames[id] = id, d
		}
	}
	primary := l.Domains[want.PrimaryDomain]
	accountsChanged := len(ops.Removals) > 0
	for _, a := range ops.Accounts {
		aliases, err := aliasList(a.Aliases, l.Domains)
		if err != nil {
			return err
		}
		quotas := map[string]any{}
		if a.Quota > 0 {
			quotas["maxDiskQuota"] = a.Quota
		}
		fields := map[string]any{"aliases": aliases, "quotas": quotas, "roles": map[string]any{"@type": "User"}}
		if a.ID == "" {
			pw, err := randomPassword()
			if err != nil {
				return err
			}
			fields["@type"], fields["name"], fields["domainId"] = "User", a.Username, primary
			fields["description"] = DescPrefix + a.UUID
			fields["credentials"] = map[string]any{"0": map[string]any{"@type": "Password", "secret": pw}}
			r, err := c.Set(ctx, "Account", map[string]any{"a": fields}, nil, nil)
			if err := setErr("Account", r, err); err != nil {
				return fmt.Errorf("account %s: %w", a.Username, err)
			}
			continue
		}
		if a.Rename {
			fields["name"], fields["domainId"] = a.Username, primary
		}
		if a.Enable {
			fields["permissions"] = map[string]any{"@type": "Inherit"}
			accountsChanged = true
		}
		r, err := c.Set(ctx, "Account", nil, map[string]map[string]any{a.ID: fields}, nil)
		if err := setErr("Account", r, err); err != nil {
			return fmt.Errorf("account %s: %w", a.Username, err)
		}
	}
	if ops.MailctlAliases != nil && l.MailctlID != "" {
		aliases, err := aliasList(ops.MailctlAliases, l.Domains)
		if err != nil {
			return err
		}
		r, err := c.Set(ctx, "Account", nil, map[string]map[string]any{l.MailctlID: {"aliases": aliases}}, nil)
		if err := setErr("Account", r, err); err != nil {
			return err
		}
	}
	if len(ops.DestroyLists) > 0 {
		r, err := c.Set(ctx, "MailingList", nil, nil, ops.DestroyLists)
		if err := setErr("MailingList", r, err); err != nil {
			return err
		}
	}
	for _, li := range ops.Lists {
		local, dom, _ := state.SplitAddress(li.Address)
		fields := map[string]any{"recipients": set(li.Recipients...), "description": li.Desc}
		var r stalwart.SetResult
		var err error
		if li.ID == "" {
			fields["name"], fields["domainId"] = local, l.Domains[dom]
			r, err = c.Set(ctx, "MailingList", map[string]any{"l": fields}, nil, nil)
		} else {
			r, err = c.Set(ctx, "MailingList", nil, map[string]map[string]any{li.ID: fields}, nil)
		}
		if err := setErr("MailingList", r, err); err != nil {
			return fmt.Errorf("list %s: %w", li.Address, err)
		}
	}
	if len(ops.Keys)+len(ops.DestroyKeys) > 0 {
		create := map[string]any{}
		for i, k := range ops.Keys {
			create[fmt.Sprintf("k%d", i)] = map[string]any{"namespace": k.Namespace, "key": k.Key, "isGlobPattern": false}
		}
		r, err := c.Set(ctx, "MemoryLookupKey", create, nil, ops.DestroyKeys)
		if err := setErr("MemoryLookupKey", r, err); err != nil {
			return err
		}
		// Lookup changes apply only after a reload (Task 2).
		if err := c.Action(ctx, "ReloadLookupStores"); err != nil {
			return fmt.Errorf("ReloadLookupStores: %w", err)
		}
	}
	if len(ops.Throttles) > 0 {
		create := map[string]any{}
		update := map[string]map[string]any{}
		for i, t := range ops.Throttles {
			f := map[string]any{"description": t.Desc, "enable": true, "key": set("authenticatedAs"),
				"rate":  map[string]any{"count": t.Count, "period": t.Period},
				"match": map[string]any{"match": map[string]any{}, "else": "!is_empty(authenticated_as)"}}
			if t.ID == "" {
				create[fmt.Sprintf("t%d", i)] = f
			} else {
				update[t.ID] = f
			}
		}
		r, err := c.Set(ctx, "MtaInboundThrottle", create, update, nil)
		if err := setErr("MtaInboundThrottle", r, err); err != nil {
			return err
		}
		if err := c.Action(ctx, "ReloadSettings"); err != nil {
			return fmt.Errorf("ReloadSettings: %w", err)
		}
	}
	if accountsChanged && len(ops.Removals) == 0 {
		if err := c.Action(ctx, "InvalidateCaches"); err != nil {
			return fmt.Errorf("InvalidateCaches: %w", err)
		}
	}
	return nil
}

// FindAccount is the live account id of a document username (by uuid,
// never by the name alone). "" = none.
func FindAccount(l *Live, d *state.Doc, username string) string {
	a, ok := d.Account(username)
	if !ok {
		return ""
	}
	for _, la := range l.Accounts {
		if la.UUID == a.UUID && !la.Parked(l) {
			return la.ID
		}
	}
	return ""
}

// FormerAccount is the id of a parked account former-<uuid> ("" = none).
func FormerAccount(l *Live, formerID string) string {
	uuid := strings.TrimPrefix(formerID, FormerPrefix)
	for _, la := range l.Accounts {
		if la.UUID == uuid && la.Parked(l) {
			return la.ID
		}
	}
	return ""
}
