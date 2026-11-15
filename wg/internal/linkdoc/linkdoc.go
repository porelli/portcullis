// Package linkdoc reads link.json v1 (the link_doc volume,
// /link-doc/link.json; contract §17), the Hub's list of worker servers
// (link peers) and relay token hashes for wg's link role. Public data only:
// public keys, tunnel addresses, states and sha256 hashes.
//
// It fails closed: an unknown version, an unknown, missing, null or
// duplicate key, a parse error, a peer outside 10.214.0.0/24's .10–.250,
// a duplicate id, key or address, a relay naming a server that isn't a
// ready peer, or too many entries refuses the whole file, so the role
// has no peers and refuses every CONNECT.
package linkdoc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Version is the only link.json version this reader accepts.
const Version = 1

// Subnet is the link tunnel subnet. It is fixed in v1 (ruling P3): vpn.json
// readers in three languages reserve it.
var Subnet = netip.MustParsePrefix("10.214.0.0/24")

// LinkAddr is the link role's own tunnel address (.1).
var LinkAddr = netip.MustParseAddr("10.214.0.1")

// Worker addresses are .10–.250 of Subnet.
const (
	FirstPeerHost = 10
	LastPeerHost  = 250
)

// Peer states. Every non-revoked server is a peer; "offline" is Hub-only.
const (
	StateEnrolling = "enrolling"
	StateReady     = "ready"
)

// Caps.
const (
	MaxPeers  = 250
	MaxRelays = 4096
	MaxSize   = 4 << 20
)

// IDRe constrains server ids (the Hub's servers.IDRe).
var IDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// InstanceRe constrains relays' instance ids (the Hub's linkdoc rule:
// lowercase labels joined by single hyphens, never "--"), at most
// MaxInstanceLen characters.
var InstanceRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// MaxInstanceLen bounds an instance id.
const MaxInstanceLen = 64

// ValidInstance reports whether s is an instance id link.json may name.
func ValidInstance(s string) bool { return len(s) <= MaxInstanceLen && InstanceRe.MatchString(s) }

// ReservedServerID is the local engine's name; no peer may take it.
const ReservedServerID = "primary"

var tokenRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Doc struct {
	Version   int       `json:"version"`
	WrittenAt time.Time `json:"written_at"`
	Subnet    string    `json:"subnet"`
	Peers     []Peer    `json:"peers"`
	Relays    []Relay   `json:"relays"`

	byID    map[string]int
	byAddr  map[netip.Addr]int
	byToken map[string]int
}

type Peer struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip"`
	State     string `json:"state"`

	key  [32]byte
	addr netip.Addr
}

type Relay struct {
	TokenSHA256 string `json:"token_sha256"`
	Instance    string `json:"instance"`
	Server      string `json:"server"`
}

// Key is the peer's parsed public key.
func (p *Peer) Key() [32]byte { return p.key }

// Addr is the peer's parsed tunnel address.
func (p *Peer) Addr() netip.Addr { return p.addr }

// Parse decodes and validates a link.json document. Errors name JSON
// paths, never values.
func Parse(b []byte) (*Doc, error) {
	if len(b) > MaxSize {
		return nil, errors.New("link.json: too large")
	}
	if err := checkShape(b, reflect.TypeFor[Doc](), "$"); err != nil {
		return nil, fmt.Errorf("link.json: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var d Doc
	if err := dec.Decode(&d); err != nil {
		return nil, errors.New("link.json: malformed")
	}
	if dec.More() {
		return nil, errors.New("link.json: trailing data")
	}
	if err := d.validate(); err != nil {
		return nil, fmt.Errorf("link.json: %w", err)
	}
	return &d, nil
}

func (d *Doc) validate() error {
	if d.Version != Version {
		return fmt.Errorf("version %d, want %d", d.Version, Version)
	}
	if d.WrittenAt.IsZero() {
		return errors.New("written_at: not set")
	}
	if _, off := d.WrittenAt.Zone(); off != 0 {
		return errors.New("written_at: must be UTC (Z)")
	}
	sn, err := netip.ParsePrefix(d.Subnet)
	if err != nil || sn != Subnet {
		return fmt.Errorf("subnet: must be %s", Subnet)
	}
	if len(d.Peers) > MaxPeers {
		return fmt.Errorf("peers: more than %d", MaxPeers)
	}
	if len(d.Relays) > MaxRelays {
		return fmt.Errorf("relays: more than %d", MaxRelays)
	}
	d.byID = map[string]int{}
	d.byAddr = map[netip.Addr]int{}
	keys := map[[32]byte]bool{}
	for i := range d.Peers {
		p := &d.Peers[i]
		if !IDRe.MatchString(p.ID) || p.ID == ReservedServerID {
			return fmt.Errorf("peers[%d].id: not a server id", i)
		}
		if _, dup := d.byID[p.ID]; dup {
			return fmt.Errorf("peers[%d].id: duplicate id", i)
		}
		k, err := parseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peers[%d].public_key: not a WireGuard key", i)
		}
		if keys[k] {
			return fmt.Errorf("peers[%d].public_key: duplicate key", i)
		}
		a, err := netip.ParseAddr(p.IP)
		if err != nil || !a.Is4() || a.String() != p.IP || !PeerAddr(a) {
			return fmt.Errorf("peers[%d].ip: not a worker address (%s .%d–.%d)", i, Subnet, FirstPeerHost, LastPeerHost)
		}
		if _, dup := d.byAddr[a]; dup {
			return fmt.Errorf("peers[%d].ip: duplicate address", i)
		}
		switch p.State {
		case StateEnrolling, StateReady:
		default:
			return fmt.Errorf("peers[%d].state: enrolling or ready", i)
		}
		p.key, p.addr = k, a
		keys[k] = true
		d.byID[p.ID] = i
		d.byAddr[a] = i
	}
	d.byToken = map[string]int{}
	for i := range d.Relays {
		r := &d.Relays[i]
		if !tokenRe.MatchString(r.TokenSHA256) {
			return fmt.Errorf("relays[%d].token_sha256: not 64 lowercase hex digits", i)
		}
		if _, dup := d.byToken[r.TokenSHA256]; dup {
			return fmt.Errorf("relays[%d].token_sha256: duplicate token", i)
		}
		if !ValidInstance(r.Instance) {
			return fmt.Errorf("relays[%d].instance: not an instance id", i)
		}
		p := d.PeerByID(r.Server)
		if p == nil || p.State != StateReady {
			return fmt.Errorf("relays[%d].server: not a ready peer", i)
		}
		d.byToken[r.TokenSHA256] = i
	}
	return nil
}

// PeerAddr reports whether a is a worker address: inside Subnet, .10–.250.
func PeerAddr(a netip.Addr) bool {
	if !a.Is4() || !Subnet.Contains(a) {
		return false
	}
	h := a.As4()[3]
	return h >= FirstPeerHost && h <= LastPeerHost
}

func parseKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return k, errors.New("not a 32-byte base64 key")
	}
	copy(k[:], b)
	var zero [32]byte
	if k == zero {
		return k, errors.New("zero key")
	}
	return k, nil
}

// PeerByID is the peer with that id, or nil (also for a nil document).
func (d *Doc) PeerByID(id string) *Peer {
	if d == nil {
		return nil
	}
	if i, ok := d.byID[id]; ok {
		return &d.Peers[i]
	}
	return nil
}

// PeerByAddr is the peer with that tunnel address, or nil.
func (d *Doc) PeerByAddr(a netip.Addr) *Peer {
	if d == nil {
		return nil
	}
	if i, ok := d.byAddr[a]; ok {
		return &d.Peers[i]
	}
	return nil
}

// RelayByToken is the relay entry whose token hashes to sha (lowercase
// hex), or nil.
func (d *Doc) RelayByToken(sha string) *Relay {
	if d == nil {
		return nil
	}
	if i, ok := d.byToken[sha]; ok {
		return &d.Relays[i]
	}
	return nil
}

// TokenSHA256 is the hex sha256 link.json stores for a relay token.
func TokenSHA256(sum [32]byte) string { return hex.EncodeToString(sum[:]) }

// Load reads and parses path once.
func Load(path string) (*Doc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("link.json: missing")
		}
		return nil, errors.New("link.json: unreadable")
	}
	return Parse(b)
}

// Watcher polls a link.json path by stat (device, inode, mtime, size) and
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
				d, perr = nil, errors.New("link.json: unreadable")
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

// --- strict shape check: the Hub's / mcp-gate's walker (unknown, missing,
// duplicate, case-folded keys and every null refused) ---

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

func checkShape(raw []byte, t reflect.Type, path string) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s: null", path)
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		// time.Time: decoded here so its refusal names the path.
		if err := reflect.New(t).Interface().(json.Unmarshaler).UnmarshalJSON(raw); err != nil {
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
		present := map[string]bool{}
		for i, k := range keys {
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown key %q", path, k)
			}
			present[k] = true
			if err := checkShape(vals[i], ft, path+"."+k); err != nil {
				return err
			}
		}
		for name := range fields {
			if !present[name] {
				return fmt.Errorf("%s: missing key %q", path, name)
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
	case reflect.String:
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("%s: not a string", path)
		}
	case reflect.Int:
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			return fmt.Errorf("%s: not an integer", path)
		}
	}
	return nil
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
