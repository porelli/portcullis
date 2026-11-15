// Package reconcile turns MailState v1 into Stalwart objects (contract
// §19.5, §19.6): accounts keyed by the LLDAP uuid, removals onto the
// parking domain (M4), lists, the reserved addresses, quotas and limits.
// Plan is pure; Apply runs a plan against Stalwart.
package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// Owned objects carry these descriptions.
const (
	DescPrefix     = "portcullis:" // accounts: portcullis:<uuid>
	DescList       = "portcullis:list"
	DescReserved   = "portcullis:reserved" // postmaster@ / abuse@
	DescLimitHour  = "portcullis: recipients per hour"
	DescLimitDay   = "portcullis: recipients per day"
	FormerPrefix   = "former-"
	MailctlAccount = "portcullis-mailctl"
	NSMembersOnly  = "list-members-only"
	NSPosters      = "list-posters"
)

// LiveAccount is one Stalwart account Portcullis owns.
type LiveAccount struct {
	ID       string
	Name     string
	DomainID string
	UUID     string
	Aliases  []string // full addresses
	Disabled bool     // authenticate disabled
	Quota    int64
	Roles    string // the roles' @type
}

// Parked reports an account on the parking domain.
func (a LiveAccount) Parked(l *Live) bool {
	return a.DomainID == l.Domains[state.ParkingDomain] && strings.HasPrefix(a.Name, FormerPrefix)
}

// LiveList is one owned MailingList.
type LiveList struct {
	ID         string
	Address    string
	Desc       string
	Recipients []string
}

// LiveKey is one MemoryLookupKey in mailctl's namespaces.
type LiveKey struct{ ID, Namespace, Key string }

// LiveThrottle is one owned MtaInboundThrottle.
type LiveThrottle struct {
	ID, Desc string
	Count    int
	Period   int64
}

// Live is what Stalwart holds that the plan compares.
type Live struct {
	Domains        map[string]string // name → id
	DomainNames    map[string]string // id → name
	Accounts       []LiveAccount     // owned, by description portcullis:<uuid>
	MailctlID      string
	MailctlAliases []string
	Lists          []LiveList
	Keys           []LiveKey
	Throttles      []LiveThrottle
}

type obj = map[string]json.RawMessage

func sval(o obj, k string) string {
	var s string
	_ = json.Unmarshal(o[k], &s)
	return s
}

func getAll(ctx context.Context, c *stalwart.Client, name string, filter any) ([]obj, error) {
	ids, err := c.Query(ctx, name, filter)
	if err != nil {
		return nil, fmt.Errorf("x:%s/query: %w", name, err)
	}
	var out []obj
	if len(ids) == 0 {
		return out, nil
	}
	if err := c.Get(ctx, name, ids, nil, &out); err != nil {
		return nil, fmt.Errorf("x:%s/get: %w", name, err)
	}
	return out, nil
}

// addresses of an EmailAlias list ({"0": {name, domainId}}).
func aliasAddrs(raw json.RawMessage, names map[string]string) []string {
	var m map[string]struct {
		Name     string `json:"name"`
		DomainID string `json:"domainId"`
	}
	_ = json.Unmarshal(raw, &m)
	var out []string
	for _, a := range m {
		out = append(out, a.Name+"@"+names[a.DomainID])
	}
	sort.Strings(out)
	return out
}

// Read fetches Live.
func Read(ctx context.Context, c *stalwart.Client) (*Live, error) {
	l := &Live{Domains: map[string]string{}, DomainNames: map[string]string{}}
	doms, err := getAll(ctx, c, "Domain", nil)
	if err != nil {
		return nil, err
	}
	for _, d := range doms {
		l.Domains[sval(d, "name")] = sval(d, "id")
		l.DomainNames[sval(d, "id")] = sval(d, "name")
	}
	accts, err := getAll(ctx, c, "Account", nil)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if sval(a, "@type") != "" && sval(a, "@type") != "User" {
			continue
		}
		name, desc := sval(a, "name"), sval(a, "description")
		if name == MailctlAccount && sval(a, "domainId") == l.Domains[state.ParkingDomain] {
			l.MailctlID = sval(a, "id")
			l.MailctlAliases = aliasAddrs(a["aliases"], l.DomainNames)
			continue
		}
		if !strings.HasPrefix(desc, DescPrefix) {
			continue
		}
		la := LiveAccount{ID: sval(a, "id"), Name: name, DomainID: sval(a, "domainId"), UUID: strings.TrimPrefix(desc, DescPrefix),
			Aliases: aliasAddrs(a["aliases"], l.DomainNames)}
		var perms struct {
			Disabled map[string]bool `json:"disabledPermissions"`
		}
		_ = json.Unmarshal(a["permissions"], &perms)
		la.Disabled = perms.Disabled["authenticate"]
		var q map[string]int64
		_ = json.Unmarshal(a["quotas"], &q)
		la.Quota = q["maxDiskQuota"]
		var roles struct {
			Type string `json:"@type"`
		}
		_ = json.Unmarshal(a["roles"], &roles)
		la.Roles = roles.Type
		l.Accounts = append(l.Accounts, la)
	}
	lists, err := getAll(ctx, c, "MailingList", nil)
	if err != nil {
		return nil, err
	}
	for _, m := range lists {
		desc := sval(m, "description")
		if desc != DescList && desc != DescReserved {
			continue
		}
		var rec map[string]bool
		_ = json.Unmarshal(m["recipients"], &rec)
		ll := LiveList{ID: sval(m, "id"), Address: sval(m, "name") + "@" + l.DomainNames[sval(m, "domainId")], Desc: desc}
		for r := range rec {
			ll.Recipients = append(ll.Recipients, r)
		}
		sort.Strings(ll.Recipients)
		l.Lists = append(l.Lists, ll)
	}
	for _, ns := range []string{NSMembersOnly, NSPosters} {
		keys, err := getAll(ctx, c, "MemoryLookupKey", map[string]string{"namespace": ns})
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			if sval(k, "namespace") == ns {
				l.Keys = append(l.Keys, LiveKey{ID: sval(k, "id"), Namespace: ns, Key: sval(k, "key")})
			}
		}
	}
	ths, err := getAll(ctx, c, "MtaInboundThrottle", nil)
	if err != nil {
		return nil, err
	}
	for _, t := range ths {
		d := sval(t, "description")
		if d != DescLimitHour && d != DescLimitDay {
			continue
		}
		var rate struct {
			Count  int   `json:"count"`
			Period int64 `json:"period"`
		}
		_ = json.Unmarshal(t["rate"], &rate)
		l.Throttles = append(l.Throttles, LiveThrottle{ID: sval(t, "id"), Desc: d, Count: rate.Count, Period: rate.Period})
	}
	return l, nil
}
