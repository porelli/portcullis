// Package vpndoc reads hub_data/vpn.json v2 (contract §4/§16), the Hub's
// list of VPN providers, their device maps and the built-in peers. It
// fails closed: an unknown version or key, a duplicate key, a parse error,
// overlapping provider ranges or a duplicate address refuses the whole
// file, so the caller denies every VPN request. A provider past its
// stale_after (by this reader's clock) denies its own addresses only, and
// a device or peer past its expires is dropped by the same clock, so a
// stopped Hub also ends in deny.
package vpndoc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"syscall"
	"time"
)

// Version is the only vpn.json version this reader accepts.
const Version = 2

// BuiltinID is the provider id of the built-in people role.
const BuiltinID = "builtin"

// Provider sources: the built-in role, a hook-sourced map (refreshed by the
// Hub, goes stale) and an admin's static map (never stale).
const (
	SourceBuiltin = "builtin"
	SourceHook    = "hook"
	SourceStatic  = "static"
)

// Edge ports: 9001 + slot, slots 0–46 (gateways .16–.62).
const (
	EdgePortFirst = 9001
	EdgePortLast  = 9001 + 46
)

// MaxStaleSpan is the largest stale_after − refreshed_at a provider may
// carry: the Hub writes refreshed_at + max(3 × refresh, 3 min) and refresh
// is at most 10 min (contract §3.3 / §4), so anything later would keep a
// map alive longer than any legal refresh allows.
const MaxStaleSpan = 3 * 10 * time.Minute

// MaxSize bounds the file (the Hub caps 10 000 devices per provider).
const MaxSize = 64 << 20

type Doc struct {
	Version   int        `json:"version"`
	Builtin   *Builtin   `json:"builtin"`
	Providers []Provider `json:"providers"`
	Devices   []Device   `json:"devices"`

	byAddr map[netip.Addr]int // device index by address
}

type Builtin struct {
	Subnet          string   `json:"subnet"`
	ServerPublicKey string   `json:"server_public_key"`
	Domains         []string `json:"domains"`
	Peers           []Peer   `json:"peers"`

	subnet netip.Prefix
}

type Peer struct {
	IP        string     `json:"ip"`
	PublicKey string     `json:"public_key"`
	DeviceID  string     `json:"device_id"`
	Expires   *time.Time `json:"expires"`
}

type Provider struct {
	ID          string     `json:"id"`
	Source      string     `json:"source"`
	Label       string     `json:"label"`
	Ranges      []string   `json:"ranges"`
	EdgePort    int        `json:"edge_port"`
	GatewayIP   string     `json:"gateway_ip"`
	RefreshedAt *time.Time `json:"refreshed_at"`
	StaleAfter  *time.Time `json:"stale_after"`
	Stale       bool       `json:"stale"`

	prefixes []netip.Prefix
	gateway  netip.Addr
}

type Device struct {
	IP       string     `json:"ip"`
	Provider string     `json:"provider"`
	User     string     `json:"user"`
	DeviceID string     `json:"device_id"`
	Name     string     `json:"name"`
	Expires  *time.Time `json:"expires"`

	addr netip.Addr
}

// BuiltinPeer is a parsed built-in peer.
type BuiltinPeer struct {
	IP        netip.Addr
	PublicKey [32]byte
	DeviceID  string
}

// Parse decodes and validates a vpn.json document. Errors name JSON paths,
// never values.
func Parse(b []byte) (*Doc, error) {
	if len(b) > MaxSize {
		return nil, errors.New("vpn.json: too large")
	}
	if err := checkShape(b, reflect.TypeFor[Doc](), "$"); err != nil {
		return nil, fmt.Errorf("vpn.json: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var d Doc
	if err := dec.Decode(&d); err != nil {
		return nil, errors.New("vpn.json: malformed")
	}
	if dec.More() {
		return nil, errors.New("vpn.json: trailing data")
	}
	if err := d.validate(); err != nil {
		return nil, fmt.Errorf("vpn.json: %w", err)
	}
	return &d, nil
}

func (d *Doc) validate() error {
	if d.Version != Version {
		return fmt.Errorf("version %d, want %d", d.Version, Version)
	}
	if d.Builtin != nil {
		p, err := netip.ParsePrefix(d.Builtin.Subnet)
		if err != nil || !p.Addr().Is4() || p.Masked() != p || p.Bits() < 8 || p.Bits() > 30 {
			return errors.New("builtin.subnet: not an IPv4 prefix between /8 and /30")
		}
		d.Builtin.subnet = p
		if _, err := ParseKey(d.Builtin.ServerPublicKey); err != nil {
			return errors.New("builtin.server_public_key: not a WireGuard key")
		}
		ips := map[netip.Addr]bool{}
		keys := map[string]bool{}
		for i, pe := range d.Builtin.Peers {
			a, err := netip.ParseAddr(pe.IP)
			if err != nil || !a.Is4() || !p.Contains(a) || a == serverAddr(p) || a == p.Addr() || a == broadcast(p) {
				return fmt.Errorf("builtin.peers[%d].ip: not a client address of the subnet", i)
			}
			if ips[a] {
				return fmt.Errorf("builtin.peers[%d].ip: duplicate address", i)
			}
			ips[a] = true
			if _, err := ParseKey(pe.PublicKey); err != nil {
				return fmt.Errorf("builtin.peers[%d].public_key: not a WireGuard key", i)
			}
			if keys[pe.PublicKey] {
				return fmt.Errorf("builtin.peers[%d].public_key: duplicate key", i)
			}
			keys[pe.PublicKey] = true
			if pe.DeviceID == "" {
				return fmt.Errorf("builtin.peers[%d].device_id: empty", i)
			}
		}
	}
	ids := map[string]bool{}
	ports := map[int]bool{}
	var all []netip.Prefix
	var owner []string
	for i := range d.Providers {
		p := &d.Providers[i]
		if p.ID == "" || ids[p.ID] {
			return fmt.Errorf("providers[%d].id: empty or duplicate", i)
		}
		ids[p.ID] = true
		if len(p.Ranges) == 0 || len(p.Ranges) > 8 {
			return fmt.Errorf("providers[%d].ranges: 1–8 IPv4 prefixes", i)
		}
		for j, r := range p.Ranges {
			pr, err := netip.ParsePrefix(r)
			if err != nil || !pr.Addr().Is4() || pr.Masked() != pr || pr.Bits() < 8 || pr.Bits() > 30 {
				return fmt.Errorf("providers[%d].ranges[%d]: not an IPv4 prefix between /8 and /30", i, j)
			}
			for k, o := range all {
				if o.Overlaps(pr) {
					return fmt.Errorf("providers[%d].ranges[%d]: overlaps a range of %s", i, j, owner[k])
				}
			}
			all = append(all, pr)
			owner = append(owner, p.ID)
			p.prefixes = append(p.prefixes, pr)
		}
		switch p.Source {
		case SourceBuiltin, SourceHook, SourceStatic:
		default:
			return fmt.Errorf("providers[%d].source: builtin, hook or static", i)
		}
		if (p.ID == BuiltinID) != (p.Source == SourceBuiltin) {
			return fmt.Errorf("providers[%d]: the builtin id and source go together", i)
		}
		if p.ID == BuiltinID {
			if d.Builtin == nil {
				return errors.New("providers: builtin provider without a builtin section")
			}
			if len(p.prefixes) != 1 || p.prefixes[0] != d.Builtin.subnet {
				return errors.New("providers: builtin ranges differ from builtin.subnet")
			}
			if p.EdgePort != 0 || p.GatewayIP != "" || p.RefreshedAt != nil || p.StaleAfter != nil {
				return errors.New("providers: builtin has an edge port, a gateway, refreshed_at or stale_after")
			}
			continue
		}
		if p.EdgePort < EdgePortFirst || p.EdgePort > EdgePortLast || ports[p.EdgePort] {
			return fmt.Errorf("providers[%d].edge_port: outside %d–%d or duplicate", i, EdgePortFirst, EdgePortLast)
		}
		ports[p.EdgePort] = true
		if p.Source == SourceHook {
			if p.RefreshedAt == nil || p.StaleAfter == nil {
				return fmt.Errorf("providers[%d]: a hook provider needs refreshed_at and stale_after", i)
			}
			if span := p.StaleAfter.Sub(*p.RefreshedAt); span <= 0 || span > MaxStaleSpan {
				return fmt.Errorf("providers[%d].stale_after: not within %s after refreshed_at", i, MaxStaleSpan)
			}
		} else if p.RefreshedAt != nil || p.StaleAfter != nil {
			return fmt.Errorf("providers[%d]: a static provider carries no refreshed_at or stale_after", i)
		}
		g, err := netip.ParseAddr(p.GatewayIP)
		if err != nil || !g.Is4() {
			return fmt.Errorf("providers[%d].gateway_ip: not an IPv4 address", i)
		}
		p.gateway = g
	}
	if d.Builtin != nil && d.ProviderByID(BuiltinID) == nil {
		return errors.New("builtin: a builtin section without a builtin provider")
	}
	d.byAddr = map[netip.Addr]int{}
	for i := range d.Devices {
		dv := &d.Devices[i]
		a, err := netip.ParseAddr(dv.IP)
		if err != nil || !a.Is4() {
			return fmt.Errorf("devices[%d].ip: not an IPv4 address", i)
		}
		if _, dup := d.byAddr[a]; dup {
			return fmt.Errorf("devices[%d].ip: duplicate address", i)
		}
		p := d.ProviderByID(dv.Provider)
		if p == nil {
			return fmt.Errorf("devices[%d].provider: not a provider of the file", i)
		}
		if !p.contains(a) {
			return fmt.Errorf("devices[%d].ip: outside its provider's ranges", i)
		}
		if dv.User == "" || dv.DeviceID == "" {
			return fmt.Errorf("devices[%d]: empty user or device_id", i)
		}
		dv.addr = a
		d.byAddr[a] = i
	}
	return nil
}

// ParseKey decodes a base64 WireGuard key.
func ParseKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, errors.New("not a 32-byte base64 key")
	}
	copy(k[:], b)
	return k, nil
}

// ServerAddr is the built-in server's tunnel address (.1 of the subnet).
func serverAddr(p netip.Prefix) netip.Addr { return p.Addr().Next() }

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// SubnetPrefix is the parsed built-in subnet (invalid when no builtin).
func (b *Builtin) SubnetPrefix() netip.Prefix { return b.subnet }

func (p *Provider) contains(a netip.Addr) bool {
	for _, pr := range p.prefixes {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// Prefixes are the provider's parsed ranges.
func (p *Provider) Prefixes() []netip.Prefix { return p.prefixes }

// Gateway is the provider's assigned gateway address on portcullis-vpn
// (invalid for the built-in).
func (p *Provider) Gateway() netip.Addr { return p.gateway }

// Fresh reports whether the provider's map may be used at now: never when
// the Hub marked it stale; a hook provider only before its stale_after
// (none = never fresh; Parse refuses that anyway); the built-in and a
// static map have no refresh. An unknown source is never fresh.
func (p *Provider) Fresh(now time.Time) bool {
	if p.Stale {
		return false
	}
	switch p.Source {
	case SourceBuiltin, SourceStatic:
		return true
	case SourceHook:
		return p.StaleAfter != nil && now.Before(*p.StaleAfter)
	}
	return false
}

// ProviderOf is the provider whose ranges hold a (ranges are disjoint).
func (d *Doc) ProviderOf(a netip.Addr) *Provider {
	if d == nil {
		return nil
	}
	for i := range d.Providers {
		if d.Providers[i].contains(a) {
			return &d.Providers[i]
		}
	}
	return nil
}

// ProviderByID is the provider with that id, or nil.
func (d *Doc) ProviderByID(id string) *Provider {
	if d == nil {
		return nil
	}
	for i := range d.Providers {
		if d.Providers[i].ID == id {
			return &d.Providers[i]
		}
	}
	return nil
}

// Device is the device with address a under provider, or nil when the
// provider is absent or stale, a lies outside its ranges, no device of
// that provider has a, the device's expires has passed, or (built-in) its
// peer is missing or expired. provider must come from the ingress the
// connection arrived through (the edge port / the people stack), never
// from anything a gateway or client sends.
func (d *Doc) Device(provider string, a netip.Addr, now time.Time) *Device {
	if d == nil {
		return nil
	}
	p := d.ProviderByID(provider)
	if p == nil || !p.contains(a) || !p.Fresh(now) {
		return nil
	}
	i, ok := d.byAddr[a]
	if !ok {
		return nil
	}
	dv := &d.Devices[i]
	if dv.Provider != provider {
		return nil
	}
	if expired(dv.Expires, now) {
		return nil
	}
	if provider == BuiltinID {
		// A built-in device also needs its WireGuard peer, unexpired: the
		// peer is what wg loads, the device what group-gate binds.
		if d.Builtin == nil {
			return nil
		}
		ok := false
		for _, pe := range d.Builtin.Peers {
			if pe.IP == dv.IP && pe.DeviceID == dv.DeviceID && !expired(pe.Expires, now) {
				ok = true
			}
		}
		if !ok {
			return nil
		}
	}
	return dv
}

func expired(t *time.Time, now time.Time) bool { return t != nil && !now.Before(*t) }

// BuiltinPeers are the built-in peers whose expires hasn't passed at now.
func (d *Doc) BuiltinPeers(now time.Time) []BuiltinPeer {
	if d == nil || d.Builtin == nil {
		return nil
	}
	var out []BuiltinPeer
	for _, pe := range d.Builtin.Peers {
		if expired(pe.Expires, now) {
			continue
		}
		k, _ := ParseKey(pe.PublicKey) // validated by Parse
		out = append(out, BuiltinPeer{IP: netip.MustParseAddr(pe.IP), PublicKey: k, DeviceID: pe.DeviceID})
	}
	return out
}

// Watcher polls a vpn.json path by stat (device, inode, mtime, size) and
// calls back on every change, also when the file appears, disappears or
// stops parsing. The first poll always calls back.
type Watcher struct {
	Path  string
	Every time.Duration // default 2 s
}

type stamp struct {
	dev, ino uint64
	mtime    int64
	size     int64
	missing  bool
}

func statStamp(path string) (stamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stamp{missing: true}, nil
		}
		return stamp{}, err
	}
	s := stamp{mtime: fi.ModTime().UnixNano(), size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.dev, s.ino = uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // types differ per OS
	}
	return s, nil
}

// Load reads and parses path once.
func Load(path string) (*Doc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("vpn.json: missing")
		}
		return nil, errors.New("vpn.json: unreadable")
	}
	return Parse(b)
}

// Run polls until ctx ends. fn gets the parsed doc, or nil and the error.
func (w *Watcher) Run(ctx context.Context, fn func(*Doc, error)) {
	every := w.Every
	if every <= 0 {
		every = 2 * time.Second
	}
	var last stamp
	first := true
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s, err := statStamp(w.Path)
		if err != nil {
			s = stamp{size: -1}
		}
		if first || s != last {
			first = false
			last = s
			d, perr := Load(w.Path)
			if err != nil {
				d, perr = nil, errors.New("vpn.json: unreadable")
			}
			fn(d, perr)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// --- strict shape check (unknown / duplicate / case-folded keys) ---

func checkShape(raw []byte, t reflect.Type, path string) error {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		if path == "$" {
			return errors.New("$: null")
		}
		return nil // null leaves are checked by validate (pointers / zero values)
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[time.Time]() {
		var tm time.Time
		if err := json.Unmarshal(raw, &tm); err != nil {
			return fmt.Errorf("%s: not an RFC 3339 time", path)
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		keys, vals, err := object(raw, path)
		if err != nil {
			return err
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
			if name != "" && name != "-" {
				fields[name] = sf.Type
			}
		}
		for i, k := range keys {
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown key %q", path, k)
			}
			if err := checkShape(vals[i], ft, path+"."+k); err != nil {
				return err
			}
		}
		if path == "$" {
			if _, ok := indexOf(keys, "version"); !ok {
				return errors.New("$: missing version")
			}
		}
	case reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s: not a list", path)
		}
		for i, it := range items {
			if err := checkShape(it, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func indexOf(ks []string, k string) (int, bool) {
	for i, x := range ks {
		if x == k {
			return i, true
		}
	}
	return 0, false
}

func object(raw []byte, path string) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, nil, fmt.Errorf("%s: not an object", path)
	}
	var keys []string
	var vals []json.RawMessage
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: malformed object", path)
		}
		k, _ := tok.(string)
		if seen[k] {
			return nil, nil, fmt.Errorf("%s: duplicate key %q", path, k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, nil, fmt.Errorf("%s: malformed object", path)
		}
		keys = append(keys, k)
		vals = append(vals, v)
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, fmt.Errorf("%s: malformed object", path)
	}
	return keys, vals, nil
}
