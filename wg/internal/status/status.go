// Package status writes wg_data/status.json v1 (contract §16), read by the
// Hub (a file older than 30 s = wg down) and by `wg status` / the CLI.
// Public data only: modes, role health, public keys, last handshakes.
package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Version of the document.
const Version = 1

// Interval between writes.
const Interval = 10 * time.Second

// MaxAge after which the file counts as stale (healthcheck, the Hub).
const MaxAge = 30 * time.Second

// SharedGID is the group the Hub (and group-gate) read through.
const SharedGID = 10001

type Role struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type Peer struct {
	PublicKey     string     `json:"public_key"`
	LastHandshake *time.Time `json:"last_handshake"`
}

type People struct {
	Role
	PublicKey string `json:"public_key"`
	Port      int    `json:"port"`
	Subnet    string `json:"subnet"`
	MTU       int    `json:"mtu"`
	Peers     []Peer `json:"peers"`
}

type Doc struct {
	Version int       `json:"version"`
	Written time.Time `json:"written"`
	Mode    string    `json:"mode"`
	Edge    Role      `json:"edge"`
	People  *People   `json:"people"`
}

// Write replaces path atomically (temp file in the same directory +
// rename), mode 0640. Its group (10001, the Hub's) comes from the
// directory: wg_data is 10006:10001 setgid 2750 (stack_prepare), and wg
// itself is in no group but its own.
func Write(path string, d Doc, now time.Time) error {
	d.Version = Version
	d.Written = now.UTC().Truncate(time.Second)
	if d.People != nil && d.People.Peers == nil {
		d.People.Peers = []Peer{}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".status-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// CheckDir reports why the Hub couldn't read files written in dir: it
// must have group SharedGID and the setgid bit (nil when it does).
func CheckDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return errors.New("status: the status directory is missing")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Gid) != SharedGID || fi.Mode()&os.ModeSetgid == 0 {
		return fmt.Errorf("status: %s must be group %d with the setgid bit (2750; ./portcullis up sets it), or the Hub can't read status.json", dir, SharedGID)
	}
	return nil
}

// Read parses a status file.
func Read(path string) (*Doc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("status: unreadable")
	}
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil || d.Version != Version {
		return nil, errors.New("status: invalid")
	}
	return &d, nil
}

// Run writes build() at once and every interval until ctx ends.
func Run(ctx context.Context, path string, every time.Duration, build func() Doc, now func() time.Time, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := Write(path, build(), now()); err != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
