package creds

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/stalwart/fake"
)

func setup(t *testing.T) (*fake.Server, *stalwart.Client, string) {
	t.Helper()
	f := fake.New()
	t.Cleanup(f.Close)
	d := f.Put("Domain", "", map[string]any{"name": "example.com"})
	id := f.Put("Account", "", map[string]any{"@type": "User", "name": "alice", "domainId": d})
	return f, stalwart.New(f.URL(), stalwart.Bearer("API_k")), id
}

var now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func TestCreateRefusesSixth(t *testing.T) {
	f, c, id := setup(t)
	f.Now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		cr, err := Create(context.Background(), c, id, "phone", nil, nil, now)
		if err != nil || !strings.HasPrefix(cr.Secret, "app_") || cr.CreatedAt.IsZero() {
			t.Fatalf("create %d: %+v %v", i, cr, err)
		}
	}
	if _, err := Create(context.Background(), c, id, "sixth", nil, nil, now); !errors.Is(err, ErrLimit) {
		t.Fatalf("sixth: %v", err)
	}
	// An expired one doesn't count.
	f2 := fake.New()
	t.Cleanup(f2.Close)
	d := f2.Put("Domain", "", map[string]any{"name": "example.com"})
	acct := f2.Put("Account", "", map[string]any{"@type": "User", "name": "bob", "domainId": d})
	c3 := stalwart.New(f2.URL(), stalwart.Bearer("API_k"))
	f2.Put("AppPassword", acct, map[string]any{"description": "old", "createdAt": "2026-01-01T00:00:00Z", "expiresAt": "2026-02-01T00:00:00Z"})
	for i := 0; i < 4; i++ {
		f2.Put("AppPassword", acct, map[string]any{"description": "live", "createdAt": "2026-03-01T00:00:00Z"})
	}
	if _, err := Create(context.Background(), c3, acct, "fifth active", nil, nil, now); err != nil {
		t.Fatalf("4 active + 1 expired refused: %v", err)
	}
}

func TestCreateFields(t *testing.T) {
	f, c, id := setup(t)
	exp := now.Add(90 * 24 * time.Hour)
	cr, err := Create(context.Background(), c, id, "laptop", &exp, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	p := f.Get("AppPassword", id, cr.ID)
	perms := p["permissions"].(map[string]any)
	if perms["@type"] != "Replace" || len(perms["permissions"].(map[string]any)) != len(stalwart.MailPasswordPermissions) {
		t.Fatalf("permissions %v", perms)
	}
	if _, ok := p["allowedIps"]; ok {
		t.Fatal("allowedIps set without LAN-only (an empty set or /0 must never be written)")
	}
	if cr.ExpiresAt == nil || !cr.ExpiresAt.Equal(exp.Truncate(time.Second)) {
		t.Fatalf("expires %v", cr.ExpiresAt)
	}
	list, _ := List(context.Background(), c, id, "6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b")
	if len(list) != 1 || list[0].Label != "laptop" || list[0].LastUsed != nil {
		t.Fatalf("list %+v", list)
	}
	for _, bad := range []string{"", "two\nlines", strings.Repeat("x", 65), "  "} {
		if _, err := Create(context.Background(), c, id, bad, nil, nil, now); err == nil {
			t.Errorf("label %q accepted", bad)
		}
	}
	old := now.Add(-time.Minute)
	if _, err := Create(context.Background(), c, id, "x", &old, nil, now); err == nil {
		t.Error("an expiry in the past accepted")
	}
	if err := Revoke(context.Background(), c, id, cr.ID); err != nil || len(f.Objects("AppPassword", id)) != 0 {
		t.Fatalf("revoke: %v", err)
	}
	if err := Revoke(context.Background(), c, id, cr.ID); err != nil {
		t.Fatalf("revoke again: %v", err)
	}
}

func TestCreateLanOnlyAllowedIps(t *testing.T) {
	f, c, id := setup(t)
	allowed := AllowedIPs(true, []string{"10.0.0.0/8", "192.168.1.0/24", "fd00::/8"})
	cr, err := Create(context.Background(), c, id, "phone", nil, allowed, now)
	if err != nil {
		t.Fatal(err)
	}
	ips := f.Get("AppPassword", id, cr.ID)["allowedIps"].(map[string]any)
	if len(ips) != 3 || ips["10.0.0.0/8"] != true || ips["192.168.1.0/24"] != true || ips["fd00::/8"] != true {
		t.Fatalf("allowedIps %v", ips)
	}
}

func TestAllowedIPs(t *testing.T) {
	if AllowedIPs(false, []string{"10.0.0.0/8"}) != nil {
		t.Fatal("without LAN-only the field must be left out")
	}
	got := AllowedIPs(true, nil)
	if strings.Join(got, " ") != "127.0.0.1/32 ::1/128" {
		t.Fatalf("loopback only: %v", got)
	}
	// Final review L3: an "anywhere" range is never split into allowed
	// pieces: left out (loopback only when nothing else is left).
	got = AllowedIPs(true, []string{"0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/6", "::ffff:0.0.0.0/96"})
	if strings.Join(got, " ") != "127.0.0.1/32 ::1/128" {
		t.Fatalf("anywhere ranges: %v", got)
	}
	got = AllowedIPs(true, []string{"0.0.0.0/0", "192.168.1.0/24"})
	if strings.Join(got, " ") != "192.168.1.0/24" {
		t.Fatalf("mixed: %v", got)
	}
	if !sort.StringsAreSorted(got) {
		t.Fatal("unsorted")
	}
}

func TestVoidAll(t *testing.T) {
	f, c, id := setup(t)
	other := f.Put("Account", "", map[string]any{"@type": "User", "name": "bob", "domainId": "x"})
	for i := 0; i < 3; i++ {
		f.Put("AppPassword", id, map[string]any{"description": "a"})
	}
	f.Put("AppPassword", other, map[string]any{"description": "b"})
	n, err := VoidAll(context.Background(), c)
	if err != nil || n != 4 {
		t.Fatalf("voided %d: %v", n, err)
	}
	if len(f.Objects("AppPassword", id))+len(f.Objects("AppPassword", other)) != 0 {
		t.Fatal("passwords left")
	}
}

// TestVoidAllPagesFailClosed: more passwords and accounts than a page;
// a broken page is an error, never "voided".
func TestVoidAllPagesFailClosed(t *testing.T) {
	old := stalwart.QueryPage
	stalwart.QueryPage = 2
	t.Cleanup(func() { stalwart.QueryPage = old })
	f, c, id := setup(t)
	others := []string{
		f.Put("Account", "", map[string]any{"@type": "User", "name": "bob", "domainId": "x"}),
		f.Put("Account", "", map[string]any{"@type": "User", "name": "carol", "domainId": "x"}),
	}
	for i := 0; i < 5; i++ {
		f.Put("AppPassword", id, map[string]any{"description": "a"})
	}
	for _, o := range others {
		f.Put("AppPassword", o, map[string]any{"description": "b"})
		f.Put("AppPassword", o, map[string]any{"description": "c"})
		f.Put("AppPassword", o, map[string]any{"description": "d"})
	}
	n, err := VoidAll(context.Background(), c)
	if err != nil || n != 11 {
		t.Fatalf("voided %d: %v", n, err)
	}
	f.Put("AppPassword", others[1], map[string]any{"description": "e"})
	for _, mode := range []string{"short", "no-total", "ignore-position"} {
		f.QueryMode = mode
		if _, err := VoidAll(context.Background(), c); err == nil {
			t.Fatalf("%s: a broken page voided", mode)
		}
	}
}

// Stalwart answers a /32 as the bare address: Restrict leaves such a
// password alone instead of rewriting it every pass.
func TestRestrictStalwartForm(t *testing.T) {
	f, c, id := setup(t)
	f.Put("AppPassword", id, map[string]any{"description": "a", "allowedIps": map[string]any{"127.0.0.1": true, "::1": true}})
	n, err := Restrict(context.Background(), c, id, AllowedIPs(true, nil))
	if err != nil || n != 0 {
		t.Fatalf("rewrote %d: %v", n, err)
	}
	f.Put("AppPassword", id, map[string]any{"description": "b", "allowedIps": map[string]any{"10.0.0.1": true}})
	if n, err := Restrict(context.Background(), c, id, AllowedIPs(true, nil)); err != nil || n != 1 {
		t.Fatalf("a wider one: %d %v", n, err)
	}
}
