package fake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/portcullis/mail-fake/internal/mailprovider"
)

// The fake's store survives a restart, as a real provider's does: the
// Hub's void runs a void-mode start (a recreated container), so a store
// kept only in memory would be empty by then and every void would pass
// whatever the mode (core run 44536396845's 12). Kept in the data volume
// (MAIL_FAKE_DATA/state.json, 0600): the last accepted document, its
// applied generation, the live passwords and the credential a hostile
// void kept. Never a secret: the passwords' secrets aren't stored.

type stored struct {
	Doc     *mailprovider.MailState `json:"doc"`
	Applied int                     `json:"applied"`
	Creds   map[string][]fakeCred   `json:"creds"`
	Kept    *keptCred               `json:"kept"`
}

// keptCred is the credential a hostile void kept (hostile.go).
type keptCred struct {
	User string `json:"user"`
	ID   string `json:"id"`
}

// UseStateFile loads file when it exists and saves the store there after
// every change from then on.
func (s *Server) UseStateFile(file string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	default:
		var st stored
		if err := json.Unmarshal(b, &st); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		s.Doc, s.Applied, s.kept = st.Doc, st.Applied, st.Kept
		if st.Creds != nil {
			s.creds = st.Creds
		}
	}
	s.stateFile = file
	return nil
}

// saveLocked writes the store (atomically) when a state file is in use.
// Caller holds s.mu.
func (s *Server) saveLocked() {
	if s.stateFile == "" {
		return
	}
	b, err := json.Marshal(stored{Doc: s.Doc, Applied: s.Applied, Creds: s.creds, Kept: s.kept})
	if err == nil {
		tmp := filepath.Join(filepath.Dir(s.stateFile), ".state.json.tmp")
		if err = os.WriteFile(tmp, b, 0o600); err == nil {
			err = os.Rename(tmp, s.stateFile)
		}
	}
	if err != nil {
		log.Printf("mail-fake: saving the store: %v", err)
	}
}
