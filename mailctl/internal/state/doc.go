// Package state is MailState v2, the Hub's desired-state document
// (contract §19.5), and the adapter's own persistent state (state.json).
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
	"time"
)

// Version is the only document version.
const Version = 2

// ParkingDomain is never a mail domain of a document (M4).
const ParkingDomain = "portcullis-former.internal"

// Domain mail states.
const (
	MailOn       = "on"
	MailOff      = "off"
	MailDraining = "draining"
)

// Doc is MailState v2. Every key is required but senders (optional,
// contract §19.14); only relay may be null.
type Doc struct {
	Version           int    `json:"version"`
	Generation        int64  `json:"generation"`
	PrimaryDomain     string `json:"primary_domain"`
	MailHostname      string `json:"mail_hostname"`
	ClientIP          string `json:"client_ip"`
	SubmissionLANOnly bool   `json:"submission_lan_only"`
	DKIMRotate        string `json:"dkim_rotate"`
	FormerRetention   string `json:"former_retention"`
	// Relay: nil = deliver directly. Its password is the slot's
	// relay-password file, never in the document.
	Relay              *Relay    `json:"relay" nullable:"true"`
	TLS                TLS       `json:"tls"`
	ConfirmMassRemoval bool      `json:"confirm_mass_removal"`
	Domains            []Domain  `json:"domains"`
	Accounts           []Account `json:"accounts"`
	// Senders: app mail senders and Portcullis's own (§19.14). nil = the
	// key absent (an older Hub: existing senders are left untouched);
	// non-nil, pointing at an empty list = every sender removed. A
	// pointer with omitempty: the store's round trip keeps the two apart.
	Senders       *[]Sender `json:"senders,omitempty" optional:"true"`
	Aliases       []Alias   `json:"aliases"`
	Lists         []List    `json:"lists"`
	Postmaster    []string  `json:"postmaster"`
	Limits        Limits    `json:"limits"`
	Spam          Spam      `json:"spam"`
	LocalNetworks []string  `json:"local_networks"`
}

// Client address modes (client_ip, contract §19.8).
const (
	ClientIPPreserved = "preserved"
	ClientIPRewritten = "rewritten"
)

// Relay is the optional smarthost.
type Relay struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Username   string `json:"username"`
	SPFInclude string `json:"spf_include"`
}

// TLS is the mail certificate's current and next key (core's, §19.3).
type TLS struct {
	SPKISHA256 []string `json:"spki_sha256"`
}

// Domain is one mail domain.
type Domain struct {
	Name       string `json:"name"`
	DMARCStart string `json:"dmarc_start"`
	DMARCFloor string `json:"dmarc_floor"`
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

// Sender is one app mail sender (contract §19.14): a submission-only
// account, Username portcullis-hub-mail or portcullis-app-<instance>,
// Address <username>@<primary_domain>, UUID the Hub's.
type Sender struct {
	Username string `json:"username"`
	UUID     string `json:"uuid"`
	Address  string `json:"address"`
}

// SendersPresent: the document carries senders (possibly empty).
func (d *Doc) SendersPresent() bool { return d != nil && d.Senders != nil }

// SenderList is the document's senders (nil when absent or empty).
func (d *Doc) SenderList() []Sender {
	if d == nil || d.Senders == nil {
		return nil
	}
	return *d.Senders
}

// Sender looks up a sender by username.
func (d *Doc) Sender(username string) (Sender, bool) {
	for _, s := range d.SenderList() {
		if s.Username == username {
			return s, true
		}
	}
	return Sender{}, false
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
	reSPKI     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// reSender: portcullis-hub-mail, or portcullis-app-<instance> (an
	// instance id: a template id's form, §3 / §11.1).
	reSender = regexp.MustCompile(`^portcullis-(hub-mail|app-[a-z][a-z0-9-]{0,31})$`)
)

// ValidSenderUsername is a sender's username form (contract §19.5).
func ValidSenderUsername(u string) bool { return reSender.MatchString(u) }

// Duration bounds of dkim_rotate and former_retention.
const (
	MinPeriod = 24 * time.Hour
	MaxPeriod = 8760 * time.Hour
)

// Period parses dkim_rotate / former_retention (validated by Parse).
func Period(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

func validPeriod(s string) bool {
	d, err := time.ParseDuration(s)
	return err == nil && d >= MinPeriod && d <= MaxPeriod
}

// Rewritten: client addresses are rewritten (rootless Podman, degraded mode).
func (d *Doc) Rewritten() bool { return d != nil && d.ClientIP == ClientIPRewritten }

// SPFInclude is the relay's SPF include ("" without one).
func (d *Doc) SPFInclude() string {
	if d == nil || d.Relay == nil {
		return ""
	}
	return d.Relay.SPFInclude
}

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

var reDNSLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?$`)

// ValidDNSName is a lowercase DNS name of at least two labels whose labels
// may also hold underscores (an SPF include such as _spf.example.net).
func ValidDNSName(d string) bool {
	if len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, l := range strings.Split(d, ".") {
		if !reDNSLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidUUID is a lowercase UUID (an LLDAP user uuid).
func ValidUUID(u string) bool { return reUUID.MatchString(u) }

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
				if f.Tag.Get("optional") == "true" {
					continue
				}
				return fmt.Errorf("%s: missing key %q", where, name)
			}
			if string(v) == "null" {
				if f.Tag.Get("nullable") == "true" {
					continue
				}
				return fmt.Errorf("%s.%s: null", where, name)
			}
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if err := requireKeys(v, ft, where+"."+name); err != nil {
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
	if !ValidDomain(d.MailHostname) {
		return fmt.Errorf("mail_hostname %q is not a host name", d.MailHostname)
	}
	if d.ClientIP != ClientIPPreserved && d.ClientIP != ClientIPRewritten {
		return errors.New("client_ip must be preserved or rewritten")
	}
	if !validPeriod(d.DKIMRotate) {
		return errors.New("dkim_rotate must be a duration of 24h-8760h")
	}
	if !validPeriod(d.FormerRetention) {
		return errors.New("former_retention must be a duration of 24h-8760h")
	}
	if r := d.Relay; r != nil {
		if !ValidDomain(r.Host) {
			return fmt.Errorf("relay: host %q is not a host name", r.Host)
		}
		if r.Port < 1 || r.Port > 65535 {
			return errors.New("relay: port must be 1-65535")
		}
		if strings.ContainsAny(r.Username, "\r\n\x00") || len(r.Username) > 256 {
			return errors.New("relay: username must be one line")
		}
		if r.SPFInclude != "" && !ValidDNSName(r.SPFInclude) {
			return fmt.Errorf("relay: spf_include %q is not a host name", r.SPFInclude)
		}
	}
	if n := len(d.TLS.SPKISHA256); n < 1 || n > 2 {
		return errors.New("tls.spki_sha256 must hold 1-2 keys")
	}
	for _, k := range d.TLS.SPKISHA256 {
		if !reSPKI.MatchString(k) {
			return fmt.Errorf("tls.spki_sha256: %q is not 64 lowercase hex", k)
		}
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
		if !validFloor(dm.DMARCFloor) {
			return fmt.Errorf("domains: %s: dmarc_floor must be none, quarantine or reject", dm.Name)
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
	// Senders (§19.14): never a person's username, uuid or address, nor
	// another sender's.
	for _, sn := range d.SenderList() {
		who := "sender " + sn.Username
		if !reSender.MatchString(sn.Username) {
			return fmt.Errorf("senders: %q is not portcullis-hub-mail or portcullis-app-<instance>", sn.Username)
		}
		if users[sn.Username] {
			return fmt.Errorf("senders: %s is a person's account or another sender", sn.Username)
		}
		users[sn.Username] = true
		if !reUUID.MatchString(sn.UUID) {
			return fmt.Errorf("%s: uuid %q is not a UUID", who, sn.UUID)
		}
		if uuids[sn.UUID] {
			return fmt.Errorf("%s: uuid %s twice", who, sn.UUID)
		}
		uuids[sn.UUID] = true
		if sn.Address != sn.Username+"@"+d.PrimaryDomain {
			return fmt.Errorf("%s: the address must be %s@%s", who, sn.Username, d.PrimaryDomain)
		}
		if err := claim(sn.Address, who); err != nil {
			return err
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
	if len(d.LocalNetworks) > MaxLocalNetworks {
		return fmt.Errorf("local_networks: more than %d networks", MaxLocalNetworks)
	}
	for _, n := range d.LocalNetworks {
		p, err := netip.ParsePrefix(n)
		if err != nil || p.Masked() != p {
			return fmt.Errorf("local_networks: %q is not a network", n)
		}
		if err := LocalNetworkOK(p); err != nil {
			return fmt.Errorf("local_networks: %s: %w", n, err)
		}
	}
	return nil
}

// MaxLocalNetworks bounds local_networks: with the per-network bounds
// below, the list can never amount to anywhere.
const MaxLocalNetworks = 64

// localBlocks are the private and special-use IPv4 ranges a LAN uses: a
// network inside one of them may be as wide as the block.
var localBlocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
}

// v6Embeds are the IPv6 ranges that name IPv4 space (IPv4-mapped,
// IPv4-compatible, NAT64 well-known and local-use): a local network that
// overlaps any of them is refused, whatever its start address.
var v6Embeds = []netip.Prefix{
	netip.MustParsePrefix("::ffff:0:0/96"), netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
}

// v6Allowed: an IPv6 local network lies inside one of these (ULA,
// link-local, global unicast); anything else is refused.
var v6Allowed = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("2000::/3"),
}

func inside(p netip.Prefix, blocks []netip.Prefix) bool {
	for _, b := range blocks {
		if b.Bits() <= p.Bits() && b.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// LocalNetworkOK refuses a network that is, or helps amount to,
// "anywhere" (final review L3): inside a private block any width up to
// the block; elsewhere at most an IPv4 /16 or an IPv6 /32 (a site, never
// a slice of the internet). An IPv6 network overlapping a range that
// names IPv4 space (v6Embeds) is refused, and one outside ULA,
// link-local and global unicast too. Nothing is ever split or widened.
func LocalNetworkOK(p netip.Prefix) error {
	a := p.Addr()
	if a.Is6() {
		for _, e := range v6Embeds {
			if e.Overlaps(p) {
				return fmt.Errorf("it overlaps %s (IPv4 space in IPv6): not a local network", e)
			}
		}
		if !inside(p, v6Allowed) {
			return errors.New("an IPv6 local network lies in ULA (fc00::/7), link-local (fe80::/10) or global unicast (2000::/3)")
		}
	}
	if inside(p, localBlocks) {
		return nil
	}
	if a.Is4() && p.Bits() < 16 {
		return errors.New("a public IPv4 range wider than /16 is not a local network")
	}
	if a.Is6() && p.Bits() < 32 {
		return errors.New("a public IPv6 range wider than /32 is not a local network")
	}
	return nil
}

func validFloor(p string) bool { return p == "none" || p == "quarantine" || p == "reject" }

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
