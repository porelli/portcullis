// Package creds is mail passwords: Stalwart app passwords created only for
// a person (contract §19.6), at most 5 active, permissions Replace =
// MailPasswordPermissions (M6), allowed IPs the Local networks with
// MAIL_SUBMISSION_LAN_ONLY. The secret exists once, in the create answer.
package creds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// MaxActive is the most active mail passwords per person.
const MaxActive = 5

// ErrLimit: the person has MaxActive active mail passwords (409).
var ErrLimit = errors.New("the account has 5 active mail passwords")

// Created is one new password; Secret is shown once.
type Created struct {
	ID        string     `json:"id"`
	Secret    string     `json:"secret"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// Info is one password's metadata (never its secret).
type Info struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	LastUsed  *time.Time `json:"last_used"` // always null: v1.1.0 doesn't record it
}

// ValidLabel is 1-64 characters on one line.
func ValidLabel(l string) bool {
	n := len([]rune(l))
	return n >= 1 && n <= 64 && !strings.ContainsAny(l, "\r\n\t\x00") && strings.TrimSpace(l) != ""
}

// AllowedIPs is a mail password's allowedIps (contract §19.6): nil (the
// field left out: anywhere; Stalwart refuses /0 and an empty set means
// anywhere) without LAN-only; with it the Local networks, an IPv4 prefix
// shorter than /8 split into its /8s, and none at all = loopback only
// (127.0.0.1/32 + ::1/128), never an empty set.
func AllowedIPs(lanOnly bool, local []string) []string {
	if !lanOnly {
		return nil
	}
	var out []string
	for _, n := range local {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			continue
		}
		p = p.Masked()
		switch {
		case p.Addr().Is4() && p.Bits() < 8:
			base := p.Addr().As4()
			for i := 0; i < 1<<(8-p.Bits()); i++ {
				out = append(out, netip.PrefixFrom(netip.AddrFrom4([4]byte{base[0] + byte(i), 0, 0, 0}), 8).String())
			}
		case p.Addr().Is6() && p.Bits() == 0:
			// ::/0 can't be written and isn't a local network: left out
			// (narrower, never wider).
		default:
			out = append(out, p.String())
		}
	}
	if len(out) == 0 {
		out = []string{"127.0.0.1/32", "::1/128"}
	}
	sort.Strings(out)
	return out
}

func setOf(vals []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vals {
		m[v] = true
	}
	return m
}

type apw struct {
	ID          string     `json:"id"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	AllowedIPs  map[string]bool
}

func read(ctx context.Context, c *stalwart.Client, accountID string) ([]apw, error) {
	ac := c.As(accountID)
	ids, err := ac.Query(ctx, "AppPassword", nil)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var raw []map[string]json.RawMessage
	if err := ac.Get(ctx, "AppPassword", ids, []string{"id", "description", "createdAt", "expiresAt", "allowedIps"}, &raw); err != nil {
		return nil, err
	}
	var out []apw
	for _, r := range raw {
		var a apw
		b, _ := json.Marshal(r)
		_ = json.Unmarshal(b, &a)
		_ = json.Unmarshal(r["allowedIps"], &a.AllowedIPs)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// List is an account's mail passwords.
func List(ctx context.Context, c *stalwart.Client, accountID string) ([]Info, error) {
	ps, err := read(ctx, c, accountID)
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for _, p := range ps {
		out = append(out, Info{ID: p.ID, Label: p.Description, CreatedAt: p.CreatedAt.UTC(), ExpiresAt: p.ExpiresAt})
	}
	return out, nil
}

// Create makes one mail password (refused at MaxActive active ones).
func Create(ctx context.Context, c *stalwart.Client, accountID, label string, expires *time.Time, allowed []string, now time.Time) (Created, error) {
	if !ValidLabel(label) {
		return Created{}, errors.New("the label must be 1-64 characters on one line")
	}
	if expires != nil && !expires.After(now) {
		return Created{}, errors.New("expires_at is in the past")
	}
	ps, err := read(ctx, c, accountID)
	if err != nil {
		return Created{}, err
	}
	active := 0
	for _, p := range ps {
		if p.ExpiresAt == nil || p.ExpiresAt.After(now) {
			active++
		}
	}
	if active >= MaxActive {
		return Created{}, ErrLimit
	}
	fields := map[string]any{
		"description": label,
		"permissions": map[string]any{"@type": "Replace", "permissions": setOf(stalwart.MailPasswordPermissions)},
	}
	if expires != nil {
		fields["expiresAt"] = expires.UTC().Format(time.RFC3339)
	}
	if allowed != nil {
		fields["allowedIps"] = setOf(allowed)
	}
	ac := c.As(accountID)
	r, err := ac.Set(ctx, "AppPassword", map[string]any{"p": fields}, nil, nil)
	if err != nil {
		return Created{}, err
	}
	if e := r.Failed(); e != nil {
		return Created{}, e
	}
	var cr Created
	cr.ID = r.CreatedID("p")
	_ = json.Unmarshal(r.Created["p"]["secret"], &cr.Secret)
	if cr.ID == "" || cr.Secret == "" {
		return Created{}, errors.New("x:AppPassword/set: no id or secret in the answer")
	}
	// createdAt is Stalwart's own (the Hub matches on it, P25).
	after, err := read(ctx, c, accountID)
	if err != nil {
		return Created{}, err
	}
	for _, p := range after {
		if p.ID == cr.ID {
			cr.CreatedAt, cr.ExpiresAt = p.CreatedAt.UTC(), p.ExpiresAt
		}
	}
	if cr.CreatedAt.IsZero() {
		return Created{}, fmt.Errorf("x:AppPassword/get: the new password %s isn't there", cr.ID)
	}
	return cr, nil
}

// Revoke destroys one password (already gone is fine).
func Revoke(ctx context.Context, c *stalwart.Client, accountID, id string) error {
	ac := c.As(accountID)
	r, err := ac.Set(ctx, "AppPassword", nil, nil, []string{id})
	if err != nil {
		return err
	}
	if e, ok := r.NotDestroyed[id]; ok && e.Type != "notFound" {
		return e
	}
	return nil
}

// Restrict sets every password of the account to allowed (LAN-only turned
// on after they were made). It returns how many it changed.
func Restrict(ctx context.Context, c *stalwart.Client, accountID string, allowed []string) (int, error) {
	if allowed == nil {
		return 0, nil
	}
	ps, err := read(ctx, c, accountID)
	if err != nil {
		return 0, err
	}
	want := setOf(allowed)
	upd := map[string]map[string]any{}
	for _, p := range ps {
		if !sameSet(p.AllowedIPs, want) {
			upd[p.ID] = map[string]any{"allowedIps": want}
		}
	}
	if len(upd) == 0 {
		return 0, nil
	}
	r, err := c.As(accountID).Set(ctx, "AppPassword", nil, upd, nil)
	if err != nil {
		return 0, err
	}
	if e := r.Failed(); e != nil {
		return 0, e
	}
	return len(upd), nil
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// VoidAll destroys every app password of every account (a restore,
// contract §19.11) and returns how many.
func VoidAll(ctx context.Context, c *stalwart.Client) (int, error) {
	ids, err := c.Query(ctx, "Account", nil)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		ac := c.As(id)
		ps, err := ac.Query(ctx, "AppPassword", nil)
		if err != nil {
			return n, err
		}
		if len(ps) == 0 {
			continue
		}
		r, err := ac.Set(ctx, "AppPassword", nil, nil, ps)
		if err != nil {
			return n, err
		}
		if e := r.Failed(); e != nil {
			return n, e
		}
		n += len(r.Destroyed)
	}
	return n, nil
}

func init() {
	for _, f := range []string{"description", "permissions", "expiresAt", "allowedIps", "createdAt"} {
		stalwart.Used = append(stalwart.Used, stalwart.Use{Object: "x:AppPassword", Field: f})
	}
	stalwart.Used = append(stalwart.Used, stalwart.Use{Object: "x:CredentialPermissions", Variant: "Replace", Field: "permissions"})
}

// SASLExpression is MtaStageAuth.saslMechanisms (contract §19.6): PLAIN /
// LOGIN on the TLS listeners other than smtpPort (port 25), and with
// LAN-only on only from the Local networks (AllowedIPs: loopback when
// none). The base plan and the runner write exactly this.
func SASLExpression(lanOnly bool, local []string, smtpPort int) map[string]any {
	cond := fmt.Sprintf("local_port != %d && is_tls", smtpPort)
	if lanOnly {
		var any []string
		for _, n := range AllowedIPs(true, local) {
			any = append(any, fmt.Sprintf("is_ip_in_cidr(remote_ip, '%s')", n))
		}
		cond += " && (" + strings.Join(any, " || ") + ")"
	}
	return map[string]any{"match": map[string]any{"0": map[string]any{"if": cond, "then": "[plain, login]"}}, "else": "false"}
}
