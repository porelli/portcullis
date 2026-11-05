package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// PollInterval: how often the files are stat'ed (§4.2, G21).
const PollInterval = time.Second

// Files larger than this are refused (they are a few hundred KB at most).
const maxFileBytes = 64 << 20

// A decrypted credential or caller secret is at most this long.
const maxSecretBytes = 64 << 10

// CredKey identifies a per-person credential.
type CredKey struct{ Instance, Companion, User string }

// Cred is a decrypted, active credential. Its Secret never prints.
type Cred struct {
	ID       string
	MintedAt time.Time
	Secret   string
}

// String hides the secret from %v / %s.
func (c Cred) String() string {
	return fmt.Sprintf("{ID:%s MintedAt:%s Secret:<redacted>}", c.ID, c.MintedAt.Format(time.RFC3339))
}

// GoString hides the secret from %#v.
func (c Cred) GoString() string { return "config.Cred" + c.String() }

// Snapshot is one consistent view of the three files. It is immutable:
// a reload builds a new one.
type Snapshot struct {
	// Err: a file exists but can't be read, decoded or decrypted; every
	// request is refused (503) and File is nil.
	Err error
	// Off: mcp-gate.json is missing or says enabled: false (503 "AI
	// support is off on this Portcullis"). File is set in the second case.
	Off  bool
	File *File
	// Creds: active credentials of resources in File (revoking entries and
	// entries without a resource are absent).
	Creds map[CredKey]Cred
	// Secrets: decrypted caller secrets by ref (<instance>/<companion>) of
	// identity_headers resources in File.
	Secrets map[string]string
	// Attrs: user-attributes.json; nil when missing or malformed (no
	// attribute headers, never a deny).
	Attrs *Attributes
}

// Resource looks the resource up from the request's Host (lowercased, a
// numeric :<port> and trailing dots stripped) and the exact path (§15.2).
func (sn *Snapshot) Resource(host, path string) (*Resource, bool) {
	if sn == nil || sn.Err != nil {
		return nil, false
	}
	h := NormalizeHost(host)
	if h == "" {
		return nil, false
	}
	return sn.File.lookup(h, path)
}

// Store holds the current snapshot and re-reads the files when their
// (device, inode, size, mtime ns) change.
type Store struct {
	dir   string
	ident age.Identity
	cur   atomic.Pointer[Snapshot]

	mu     sync.Mutex // serialises poll
	stamps [3]stamp

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

type stamp struct {
	dev, ino uint64
	size     int64
	mtime    int64
	missing  bool
	err      string
}

func statStamp(path string) stamp {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return stamp{missing: true}
	}
	if err != nil {
		return stamp{err: err.Error()}
	}
	s := stamp{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.dev, s.ino = uint64(st.Dev), uint64(st.Ino) //nolint:unconvert // int32 on darwin
	}
	return s
}

// Open loads the files in dir and polls them every second until Close.
// ident decrypts mcp-credentials.json; nil means any active entry
// refuses the file.
func Open(dir string, ident age.Identity) (*Store, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s: not a directory", dir)
	}
	s := &Store{dir: dir, ident: ident, stop: make(chan struct{}), done: make(chan struct{})}
	s.mu.Lock()
	s.reload()
	s.mu.Unlock()
	go s.loop()
	return s, nil
}

// Close stops polling.
func (s *Store) Close() {
	s.once.Do(func() { close(s.stop) })
	<-s.done
}

// Snapshot is the current view (never nil).
func (s *Store) Snapshot() *Snapshot { return s.cur.Load() }

func (s *Store) loop() {
	defer close(s.done)
	t := time.NewTicker(PollInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.poll()
		}
	}
}

func (s *Store) paths() [3]string {
	return [3]string{filepath.Join(s.dir, GateFile), filepath.Join(s.dir, CredsFile), filepath.Join(s.dir, AttrsFile)}
}

// poll re-reads everything when any file's stamp changed; true if so.
func (s *Store) poll() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var now [3]stamp
	for i, p := range s.paths() {
		now[i] = statStamp(p)
	}
	if now == s.stamps {
		return false
	}
	s.reload()
	return true
}

// reload stats (before reading, so a write racing the read is seen by
// the next poll) and rebuilds the snapshot. Caller holds s.mu.
func (s *Store) reload() {
	p := s.paths()
	for i := range p {
		s.stamps[i] = statStamp(p[i])
	}
	sn := build(p, s.ident)
	if sn.Err != nil {
		log.Printf("mcp-gate: refusing every request: %v", sn.Err)
	}
	s.cur.Store(sn)
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("too large")
	}
	return b, nil
}

func build(p [3]string, ident age.Identity) *Snapshot {
	b, err := readFile(p[0])
	if errors.Is(err, fs.ErrNotExist) {
		return &Snapshot{Off: true}
	}
	if err != nil {
		return &Snapshot{Err: fmt.Errorf("%s: cannot read", GateFile)}
	}
	f, err := DecodeFile(b)
	if err != nil {
		return &Snapshot{Err: fmt.Errorf("%s: %w", GateFile, err)}
	}
	if !f.Enabled {
		return &Snapshot{Off: true, File: f}
	}
	sn := &Snapshot{File: f, Creds: map[CredKey]Cred{}, Secrets: map[string]string{}}
	if err := loadCreds(p[1], ident, f, sn); err != nil {
		return &Snapshot{Err: fmt.Errorf("%s: %w", CredsFile, err)}
	}
	if b, err := readFile(p[2]); err == nil {
		if a, err := ParseAttributes(b); err == nil {
			sn.Attrs = a
		} else {
			log.Printf("mcp-gate: ignoring %s: %v (no attribute headers)", AttrsFile, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		log.Printf("mcp-gate: cannot read %s (no attribute headers)", AttrsFile)
	}
	return sn
}

func loadCreds(path string, ident age.Identity, f *File, sn *Snapshot) error {
	b, err := readFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // no credential yet: companions mint on first use
	}
	if err != nil {
		return fmt.Errorf("cannot read")
	}
	cf, err := DecodeCredFile(b)
	if err != nil {
		return err
	}
	companions := map[[2]string]*Resource{}
	for i := range f.Resources {
		if r := &f.Resources[i]; r.Kind == KindCompanion {
			companions[[2]string{r.Instance, r.Companion}] = r
		}
	}
	for i, e := range cf.Credentials {
		if companions[[2]string{e.Instance, e.Companion}] == nil || e.State != "active" {
			continue // no such resource: ignored; revoking: never used
		}
		secret, err := decrypt(e.Age, ident)
		if err != nil {
			return fmt.Errorf("credentials[%d]: %w", i, err)
		}
		sn.Creds[CredKey{e.Instance, e.Companion, e.User}] = Cred{ID: e.ID, MintedAt: e.MintedAt.Time, Secret: secret}
	}
	for i, e := range cf.CallerSecrets {
		in, co, _ := strings.Cut(e.Ref, "/")
		r := companions[[2]string{in, co}]
		if r == nil || r.Identity.Mode != "identity_headers" {
			continue
		}
		secret, err := decrypt(e.Age, ident)
		if err != nil {
			return fmt.Errorf("caller_secrets[%d]: %w", i, err)
		}
		sn.Secrets[e.Ref] = secret
	}
	return nil
}

// decrypt opens an armored age ciphertext. Errors never carry the
// ciphertext or the plaintext.
func decrypt(armored string, ident age.Identity) (string, error) {
	if ident == nil {
		return "", errors.New("cannot decrypt (no identity)")
	}
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), ident)
	if err != nil {
		return "", errors.New("cannot decrypt")
	}
	b, err := io.ReadAll(io.LimitReader(r, maxSecretBytes+1))
	if err != nil || len(b) > maxSecretBytes {
		return "", errors.New("cannot decrypt")
	}
	s := string(b)
	if s == "" || hasControl(s) || !isUTF8(s) {
		// A credential goes into a header: no CR/LF, no NUL.
		return "", errors.New("decrypted value is empty or has control characters")
	}
	return s, nil
}
