package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	TimerSeenAt       *time.Time        `json:"timer_seen_at"`
	// Ext holds the state machines' records (DKIM, MTA-STS, TLSA, DMARC,
	// checks: Tasks 8 and 9), kept verbatim by this package.
	Ext map[string]json.RawMessage `json:"ext"`
}

// Store is the file and an in-memory copy, behind one lock.
type Store struct {
	mu   sync.Mutex
	path string
	p    Persistent
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
	return nil
}
