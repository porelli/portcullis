// Package status writes wg_data/status.json v1 (contract §16), read by the
// Hub (a file older than 30 s = wg down) and by `wg status` / the CLI.
// Public data only: modes, role health, public keys, last handshakes.
package status

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
// rename), mode 0640, group 10001 (wg is a member; wg_data is setgid
// 10001 too).
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
	// wg is a member of 10001, so this needs no capability; outside the
	// container (tests) it fails with EPERM and the directory's group
	// applies.
	_ = f.Chown(-1, SharedGID)
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
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
