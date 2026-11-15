// Package state is MailState v1, the Hub's desired-state document
// (contract §19.5), and mailctl's own persistent state (state.json).
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
)

// Version is the only document version.
const Version = 1

// ParkingDomain is never a mail domain of a document (M4).
const ParkingDomain = "portcullis-former.internal"

// Domain mail states.
const (
	MailOn       = "on"
	MailOff      = "off"
	MailDraining = "draining"
)

// Doc is MailState v1. Every key is required.
type Doc struct {
	Version            int       `json:"version"`
	Generation         int64     `json:"generation"`
	PrimaryDomain      string    `json:"primary_domain"`
	ConfirmMassRemoval bool      `json:"confirm_mass_removal"`
	Domains            []Domain  `json:"domains"`
	Accounts           []Account `json:"accounts"`
	Aliases            []Alias   `json:"aliases"`
	Lists              []List    `json:"lists"`
	Postmaster         []string  `json:"postmaster"`
	Limits             Limits    `json:"limits"`
	Spam               Spam      `json:"spam"`
	LocalNetworks      []string  `json:"local_networks"`
}

// Domain is one mail domain.
type Domain struct {
	Name       string `json:"name"`
	DMARCStart string `json:"dmarc_start"`
	Mail       string `json:"mail"`
	DNSSEC     string `json:"dnssec"`
}

// Account is one mailbox: the primary address first.
type Account struct {
	Username    string   `json:"username"`
	UUID        string   `json:"uuid"`
	DisplayName string   `json:"display_name"`
	Addresses   []string `json:"addresses"`
	QuotaBytes  int64    `json:"quota_bytes"`
}

// Alias delivers Address to one account (and lets it send as Address).
type Alias struct {
	Address  string `json:"address"`
	Username string `json:"username"`
}

// List is a group list.
type List struct {
	Address string   `json:"address"`
	Members []string `json:"members"`
	Posting string   `json:"posting"`
}

// Limits are per-account outbound limits.
type Limits struct {
	RecipientsPerHour int `json:"recipients_per_hour"`
	RecipientsPerDay  int `json:"recipients_per_day"`
}

// Spam is the spam filter's settings.
type Spam struct {
	RejectScore int      `json:"reject_score"`
	JunkScore   int      `json:"junk_score"`
	DNSBL       DNSBL    `json:"dnsbl"`
	Allow       []string `json:"allow"`
	Block       []string `json:"block"`
}

// DNSBL switches the three blocklists.
type DNSBL struct {
	Spamhaus  bool `json:"spamhaus"`
	Spamcop   bool `json:"spamcop"`
	Barracuda bool `json:"barracuda"`
}

// ReservedLocalParts are every mail domain's own addresses (contract §19.6).
var ReservedLocalParts = []string{"postmaster", "abuse", "dmarc-reports", "tls-reports", "mailer-daemon"}

var (
	reUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reUUID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reLabel    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reLocal    = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_{|}~-]+)*$`)
	reDNSSEC   = regexp.MustCompile(`^[a-z_]{1,32}$`)
)

// ValidDomain is a lowercase DNS name with at least two labels.
func ValidDomain(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if !reLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// SplitAddress splits a lowercase address into local part and domain.
func SplitAddress(a string) (local, domain string, ok bool) {
	i := strings.LastIndexByte(a, '@')
	if i <= 0 || i == len(a)-1 || len(a) > 254 {
		return "", "", false
	}
	local, domain = a[:i], a[i+1:]
	if len(local) > 64 || !reLocal.MatchString(local) || !ValidDomain(domain) {
		return "", "", false
	}
	return local, domain, true
}

// Parse decodes a document strictly (contract §19.5): one JSON object,
// unknown / duplicate / missing keys and trailing data refused, then every
// rule of the contract.
func Parse(b []byte) (*Doc, error) {
	if err := NoDuplicateKeys(b); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var doc Doc
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("document: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("document: trailing data after the object")
	}
	if err := requireKeys(b, reflect.TypeOf(doc), "document"); err != nil {
		return nil, err
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

// NoDuplicateKeys walks the token stream: a key twice in one object fails.
func NoDuplicateKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // the next string is a key
	}
	var stack []*frame
	for {
		t, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("document: %w", err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{obj: v == '{', keys: map[string]bool{}, key: v == '{'})
			case '}', ']':
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].key = true
				}
			}
			continue
		case string:
			if top != nil && top.obj && top.key {
				if top.keys[v] {
					return fmt.Errorf("document: duplicate key %q", v)
				}
				top.keys[v] = true
				top.key = false
				continue
			}
		}
		if top != nil && top.obj {
			top.key = true
		}
	}
}

// requireKeys checks that every json key of t's struct (recursively, for
// structs and slices of structs) is present in the raw object.
func requireKeys(raw []byte, t reflect.Type, where string) error {
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil || m == nil {
			return fmt.Errorf("%s: not an object", where)
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			v, ok := m[name]
			if !ok {
				return fmt.Errorf("%s: missing key %q", where, name)
			}
			if string(v) == "null" {
				return fmt.Errorf("%s.%s: null", where, name)
			}
			if err := requireKeys(v, f.Type, where+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() != reflect.Struct {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s: not a list", where)
		}
		for i, it := range items {
			if err := requireKeys(it, t.Elem(), fmt.Sprintf("%s[%d]", where, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Doc) validate() error {
	if d.Version != Version {
		return fmt.Errorf("version %d: only %d is known", d.Version, Version)
	}
	if d.Generation < 1 {
		return errors.New("generation must be a positive integer")
	}
	doms := map[string]bool{}
	for _, dm := range d.Domains {
		if !ValidDomain(dm.Name) {
			return fmt.Errorf("domains: %q is not a domain", dm.Name)
		}
		if dm.Name == ParkingDomain {
			return fmt.Errorf("domains: %s is the parking domain", dm.Name)
		}
		if doms[dm.Name] {
			return fmt.Errorf("domains: %s twice", dm.Name)
		}
		doms[dm.Name] = true
		if dm.DMARCStart != "reject" && dm.DMARCStart != "none" {
			return fmt.Errorf("domains: %s: dmarc_start must be reject or none", dm.Name)
		}
		if dm.Mail != MailOn && dm.Mail != MailOff && dm.Mail != MailDraining {
			return fmt.Errorf("domains: %s: mail must be on, off or draining", dm.Name)
		}
		if !reDNSSEC.MatchString(dm.DNSSEC) {
			return fmt.Errorf("domains: %s: dnssec %q", dm.Name, dm.DNSSEC)
		}
	}
	if !doms[d.PrimaryDomain] {
		return fmt.Errorf("primary_domain %q is not one of domains", d.PrimaryDomain)
	}
	reserved := map[string]bool{}
	for _, r := range ReservedLocalParts {
		reserved[r] = true
	}
	owner := map[string]string{} // address → owner
	claim := func(addr, who string) error {
		local, dom, ok := SplitAddress(addr)
		if !ok {
			return fmt.Errorf("%s: %q is not a lowercase address", who, addr)
		}
		if !doms[dom] {
			return fmt.Errorf("%s: %s is on %s, not a mail domain of the document", who, addr, dom)
		}
		if reserved[local] {
			return fmt.Errorf("%s: %s uses the reserved local part %s", who, addr, local)
		}
		if o, dup := owner[addr]; dup {
			return fmt.Errorf("%s is both %s's and %s's", addr, o, who)
		}
		owner[addr] = who
		return nil
	}
	users := map[string]bool{}
	uuids := map[string]bool{}
	for _, a := range d.Accounts {
		who := "account " + a.Username
		if !reUsername.MatchString(a.Username) {
			return fmt.Errorf("accounts: %q is not an LLDAP username", a.Username)
		}
		if users[a.Username] {
			return fmt.Errorf("accounts: %s twice", a.Username)
		}
		users[a.Username] = true
		if !reUUID.MatchString(a.UUID) {
			return fmt.Errorf("%s: uuid %q is not a UUID", who, a.UUID)
		}
		if uuids[a.UUID] {
			return fmt.Errorf("%s: uuid %s twice", who, a.UUID)
		}
		uuids[a.UUID] = true
		if strings.ContainsAny(a.DisplayName, "\r\n") || len(a.DisplayName) > 256 {
			return fmt.Errorf("%s: display_name must be one line", who)
		}
		if len(a.Addresses) == 0 || a.Addresses[0] != a.Username+"@"+d.PrimaryDomain {
			return fmt.Errorf("%s: the first address must be %s@%s", who, a.Username, d.PrimaryDomain)
		}
		for _, addr := range a.Addresses {
			if err := claim(addr, who); err != nil {
				return err
			}
		}
		if a.QuotaBytes < 0 {
			return fmt.Errorf("%s: quota_bytes < 0", who)
		}
	}
	for _, al := range d.Aliases {
		if !users[al.Username] {
			return fmt.Errorf("alias %s: %s is not an account", al.Address, al.Username)
		}
		if err := claim(al.Address, "alias of "+al.Username); err != nil {
			return err
		}
	}
	for _, l := range d.Lists {
		if l.Posting != "members" && l.Posting != "anyone" {
			return fmt.Errorf("list %s: posting must be members or anyone", l.Address)
		}
		if err := claim(l.Address, "list "+l.Address); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, m := range l.Members {
			if !users[m] {
				return fmt.Errorf("list %s: member %s is not an account", l.Address, m)
			}
			if seen[m] {
				return fmt.Errorf("list %s: member %s twice", l.Address, m)
			}
			seen[m] = true
		}
	}
	for _, p := range d.Postmaster {
		if !users[p] {
			return fmt.Errorf("postmaster: %s is not an account", p)
		}
	}
	for _, v := range []int{d.Limits.RecipientsPerHour, d.Limits.RecipientsPerDay} {
		if v < 1 || v > 100000 {
			return errors.New("limits must be 1-100000")
		}
	}
	s := d.Spam
	if s.JunkScore < 1 || s.JunkScore >= s.RejectScore || s.RejectScore > 100 {
		return errors.New("spam: 1 <= junk_score < reject_score <= 100")
	}
	for _, e := range append(append([]string{}, s.Allow...), s.Block...) {
		if _, _, ok := SplitAddress(e); !ok && !ValidDomain(e) {
			return fmt.Errorf("spam: %q is neither a domain nor an address", e)
		}
	}
	for _, n := range d.LocalNetworks {
		p, err := netip.ParsePrefix(n)
		if err != nil || p.Masked() != p {
			return fmt.Errorf("local_networks: %q is not a network", n)
		}
	}
	return nil
}

// Account looks up an account by username.
func (d *Doc) Account(username string) (Account, bool) {
	for _, a := range d.Accounts {
		if a.Username == username {
			return a, true
		}
	}
	return Account{}, false
}

// Primary is an account's login and first address.
func (a Account) Primary() string { return a.Addresses[0] }
