// Package gate is the mail slot's start gate (contract §19.4, P3): a
// gated service starts only when one of these holds:
//
//   - void-pending is absent and .present is exactly "portcullis-mail-gate"
//     (an optional trailing newline);
//   - void-pending exists, void-session is non-empty, and
//     PORTCULLIS_MAIL_VOID_SESSION equals it byte for byte.
//
// Anything else, an unreadable file included, refuses the start.
package gate

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Sentinel is .present's content.
const Sentinel = "portcullis-mail-gate"

// maxFile bounds what is read of a gate file.
const maxFile = 4096

func read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxFile+1))
}

// Check is the predicate over the files of slotDir; session is the
// environment's PORTCULLIS_MAIL_VOID_SESSION, unmodified.
func Check(slotDir, session string) error {
	_, err := os.Lstat(filepath.Join(slotDir, "void-pending"))
	switch {
	case err == nil:
		s, rerr := read(filepath.Join(slotDir, "void-session"))
		if rerr != nil || len(s) == 0 || len(s) > maxFile {
			return errors.New("the mail gate is closed: a void is owed and this isn't the Hub's void mode")
		}
		if session == "" || subtle.ConstantTimeCompare(s, []byte(session)) != 1 {
			return errors.New("the mail gate is closed: a void is owed and this isn't the Hub's void mode")
		}
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("the mail gate isn't readable: %v", errors.Unwrap(err))
	}
	b, err := read(filepath.Join(slotDir, ".present"))
	if err != nil {
		return errors.New("the mail gate isn't readable: the slot's files are missing (is this instance wired?)")
	}
	if string(b) != Sentinel && string(b) != Sentinel+"\n" {
		return errors.New("the mail gate is closed: .present isn't the gate sentinel")
	}
	return nil
}
