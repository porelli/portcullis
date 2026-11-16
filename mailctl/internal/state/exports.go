package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ExportRecord is one export's password, recorded by `mailctl export`
// when it creates it and removed by its cleanup (final review M5 ruling):
// the reconcile sweep spares a parked account's password only when its
// id is recorded here for that account and still valid. A file per
// export under <data>/exports, because the export is its own process
// (state.json belongs to `serve`).
type ExportRecord struct {
	AccountID  string    `json:"account_id"`
	PasswordID string    `json:"password_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

var reObjectID = regexp.MustCompile(`^[a-z0-9]{1,64}$`)

func exportsDir(dataDir string) string { return filepath.Join(dataDir, "exports") }

// RecordExport writes rec durably.
func RecordExport(dataDir string, rec ExportRecord) error {
	if !reObjectID.MatchString(rec.PasswordID) || !reObjectID.MatchString(rec.AccountID) {
		return fmt.Errorf("export record: ids %q / %q", rec.AccountID, rec.PasswordID)
	}
	if err := os.MkdirAll(exportsDir(dataDir), 0o700); err != nil {
		return fmt.Errorf("export record: %w", err)
	}
	b, _ := json.Marshal(rec)
	if err := writeDurable(filepath.Join(exportsDir(dataDir), rec.PasswordID+".json"), b); err != nil {
		return fmt.Errorf("export record: %w", err)
	}
	return nil
}

// RemoveExport removes the record of password id (none: nil).
func RemoveExport(dataDir, passwordID string) error {
	if !reObjectID.MatchString(passwordID) {
		return fmt.Errorf("export record: id %q", passwordID)
	}
	err := os.Remove(filepath.Join(exportsDir(dataDir), passwordID+".json"))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("export record: %w", err)
	}
	return nil
}

// Exports reads every record (password id → record). A file that doesn't
// parse, or names another id than its own, is no record (the password
// it might belong to is then a stray: destroyed).
func Exports(dataDir string) (map[string]ExportRecord, error) {
	out := map[string]ExportRecord{}
	ents, err := os.ReadDir(exportsDir(dataDir))
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("export records: %w", err)
	}
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !e.Type().IsRegular() || !reObjectID.MatchString(id) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(exportsDir(dataDir), e.Name()))
		if err != nil {
			return nil, fmt.Errorf("export records: %w", err)
		}
		var rec ExportRecord
		if json.Unmarshal(b, &rec) != nil || rec.PasswordID != id || rec.AccountID == "" {
			continue
		}
		out[id] = rec
	}
	return out, nil
}

// Dir is the store's data directory.
func (s *Store) Dir() string { return filepath.Dir(s.path) }
