package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Former is a parked account: removed or replaced (uuid change), kept for
// MAIL_FORMER_RETENTION, then destroyed (M4).
type Former struct {
	Username string    `json:"username"`
	Since    time.Time `json:"since"`
}

// Persistent is mailctl's state.json (mailctl_data, 0600): the last accepted
// document, what was applied, the former accounts and the state machines'
// records (later tasks add theirs).
type Persistent struct {
	Version           int               `json:"version"`
	Doc               *Doc              `json:"doc"`
	Generation        int64             `json:"generation"`
	AppliedGeneration int64             `json:"applied_generation"`
	Errors            []string          `json:"errors"`
	Former            map[string]Former `json:"former"` // old uuid → record
	RestoredAt        *time.Time        `json:"restored_at"`
	// MassRemoval: the removal set a confirm_mass_removal PUT confirmed
	// (from the live read at that PUT); the guard is lifted only for it.
	MassRemoval *MassRemoval `json:"mass_removal"`
	TimerSeenAt       *time.Time        `json:"timer_seen_at"`
	// Ext holds the state machines' records (DKIM, MTA-STS, TLSA, DMARC,
	// checks: Tasks 8 and 9), kept verbatim by this package.
	Ext map[string]json.RawMessage `json:"ext"`
}

// MassRemoval binds a document's confirm_mass_removal to the removals it
// confirmed: the generation, the parked-to-be uuids (sorted) and their
// hash (RemovalSetHash).
type MassRemoval struct {
	Generation int64    `json:"generation"`
	UUIDs      []string `json:"uuids"`
	SHA256     string   `json:"sha256"`
}

// RemovalSetHash is the hex sha256 of the sorted uuids, one per line.
func RemovalSetHash(uuids []string) string {
	u := append([]string(nil), uuids...)
	sort.Strings(u)
	h := sha256.Sum256([]byte(strings.Join(u, "\n")))
	return hex.EncodeToString(h[:])
}

// NewMassRemoval is the binding for generation and uuids.
func NewMassRemoval(generation int64, uuids []string) *MassRemoval {
	u := append([]string(nil), uuids...)
	sort.Strings(u)
	return &MassRemoval{Generation: generation, UUIDs: u, SHA256: RemovalSetHash(u)}
}

// Covers: m confirms exactly this generation and every uuid of removals
// (a pass that parked part of the set and failed finishes the rest).
func (m *MassRemoval) Covers(generation int64, removals []string) bool {
	if m == nil || m.Generation != generation || m.SHA256 != RemovalSetHash(m.UUIDs) {
		return false
	}
	in := map[string]bool{}
	for _, u := range m.UUIDs {
		in[u] = true
	}
	for _, u := range removals {
		if !in[u] {
			return false
		}
	}
	return true
}

// Store is the file and an in-memory copy, behind one lock.
type Store struct {
	mu   sync.Mutex
	path string
	p    Persistent
	rev  uint64 // bumped by every Update (caches keyed on the state)
}

// Open reads dir/state.json (a missing file is an empty state).
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(s.path)
	switch {
	case os.IsNotExist(err):
		s.p = Persistent{Version: 1}
	case err != nil:
		return nil, fmt.Errorf("state: %w", err)
	default:
		if err := json.Unmarshal(b, &s.p); err != nil {
			return nil, fmt.Errorf("state: %s is not readable: %w", s.path, err)
		}
		if s.p.Version != 1 {
			return nil, fmt.Errorf("state: %s has version %d", s.path, s.p.Version)
		}
	}
	if s.p.Former == nil {
		s.p.Former = map[string]Former{}
	}
	if s.p.Ext == nil {
		s.p.Ext = map[string]json.RawMessage{}
	}
	return s, nil
}

// Get returns a deep copy of the state.
func (s *Store) Get() Persistent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copyLocked()
}

func (s *Store) copyLocked() Persistent {
	b, _ := json.Marshal(s.p)
	var c Persistent
	_ = json.Unmarshal(b, &c)
	if c.Former == nil {
		c.Former = map[string]Former{}
	}
	if c.Ext == nil {
		c.Ext = map[string]json.RawMessage{}
	}
	return c
}

// Update changes the state under the lock and writes it (atomically,
// 0600). fn's error aborts without writing.
func (s *Store) Update(fn func(*Persistent) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.copyLocked()
	if err := fn(&c); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("state: %w", err)
	}
	s.p = c
	s.rev++
	return nil
}

// GetRev returns a deep copy of the state and its revision (bumped by
// every Update since Open).
func (s *Store) GetRev() (Persistent, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copyLocked(), s.rev
}

// TLSAState is the mail certificate's key pins (Ext["tlsa"]), as mail-cert
// reported them through `mailctl rotate`: the current key, the next one
// during a rollover, and an old one until its record is dropped.
type TLSAState struct {
	Current    string     `json:"current"`
	Next       string     `json:"next"`
	NextSince  *time.Time `json:"next_since"`
	Old        string     `json:"old"`
	OldUntil   *time.Time `json:"old_until"`
	SwitchedAt *time.Time `json:"switched_at"`
}

// TLSA reads Ext["tlsa"].
func TLSA(p Persistent) TLSAState {
	var t TLSAState
	_ = json.Unmarshal(p.Ext["tlsa"], &t)
	return t
}

// SPKIs are the keys the mail certificate may present right now.
func SPKIs(p Persistent) []string {
	t := TLSA(p)
	var out []string
	for _, s := range []string{t.Current, t.Next, t.Old} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
