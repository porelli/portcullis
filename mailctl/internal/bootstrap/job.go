package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// RecoveryUser is the job's recovery admin (its password is made inside
// the job, never written anywhere but the server child's environment).
const RecoveryUser = "portcullis-recovery"

// Server starts the mail server once: recovery mode (with the recovery
// admin and the job's session nonce) or a normal start (extra env, e.g.
// STALWART_UPDATE_ROLE_PERMISSIONS=true). stop ends it and waits.
type Server func(ctx context.Context, env []string) (stop func() error, err error)

// Job is `mailctl bootstrap --job`: the template's one-off bootstrap
// (ordered before the server and the adapter by
// service_completed_successfully, so two openers of the store never
// overlap). It
//  1. starts the server in recovery mode (a random password made here; the
//     session nonce in SessionFile for the server's entrypoint wrapper),
//  2. applies the document-less base plan as the recovery admin, only on
//     an unmarked, empty store (Ruling R-H2b), always minting a new key,
//  3. writes the API key (MAILCTL_API_KEY_FILE, 0640, by rename),
//  4. stops the server, starts it normally once (with the role-permission
//     update after a server image change) and exits nil only when the
//     recovery login is refused there.
type Job struct {
	URL     string // the job's own server over loopback (MAILCTL_JOB_LOCAL_URL)
	DataDir string // job_data: the job's own files (.server-image)
	// KeyFile is where the API key goes (MAILCTL_API_KEY_FILE, 0640).
	KeyFile string
	// ViewerFile is where the admin view account's password goes
	// (MAILCTL_VIEWER_SECRET_FILE, 0640, the viewer key volume; contract
	// §19.13). "" = no admin view: the password is never written.
	ViewerFile string
	// StoreDir is the server's store volume as the job mounts it
	// (MAILCTL_STORE_DIR): the lock and the base-plan marker live there
	// (Ruling T17-c: the plan runs once per store).
	StoreDir    string
	SessionFile string // job-only tmpfs: the recovery session's nonce ("" = none)
	ServerImage string // MAILCTL_SERVER_IMAGE: the pinned server image ("" = never update roles)
	Params      Params // the neutral base plan inputs (resolver, rules URL, …)
	Start       Server
	Ready       time.Duration // how long the server may take to answer (default 5 min)
	Logf        func(string, ...any)
}

func (j *Job) logf(f string, a ...any) {
	if j.Logf != nil {
		j.Logf(f, a...)
	}
}

// KeyFile is the API key's default file in adapter_data.
func KeyFile(dataDir string) string { return filepath.Join(dataDir, "api-key") }

// The base plan's marker and the job's lock in the store volume.
const (
	planMarker = ".portcullis-base-plan"
	jobLock    = ".portcullis-bootstrap.lock"
)

type markerDoc struct {
	Version   int       `json:"version"`
	AppliedAt time.Time `json:"applied_at"`
}

// markerValid: the store's marker exists and reads as version 1 with a
// time (anything else: the plan runs again, fail closed).
func markerValid(store string) bool {
	b, err := os.ReadFile(filepath.Join(store, planMarker))
	if err != nil {
		return false
	}
	var m markerDoc
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(&m) == nil && m.Version == 1 && !m.AppliedAt.IsZero()
}

// writeMarker records the base plan (written whole, renamed, the
// directory synced).
func writeMarker(store string, now time.Time) error {
	b, _ := json.Marshal(markerDoc{Version: 1, AppliedAt: now.UTC().Truncate(time.Second)})
	return writeReplace(filepath.Join(store, planMarker), b, 0o600)
}

// writeKeyFile writes the API key 0640 (the adapter reads it through the
// template's shared group): a new file renamed over the old one, the
// directory synced, so a crash leaves the old key or the new one, never a
// torn one (M1).
func writeKeyFile(path, key string) error { return writeReplace(path, []byte(key), 0o640) }

// viewerFileInPlace: the viewer secret file holds a password.
func viewerFileInPlace(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && len(strings.TrimSpace(string(b))) >= 16
}

// writeReplace writes b to a temporary file beside path, fsyncs it,
// renames it over path and fsyncs the directory.
func writeReplace(path string, b []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := WriteInPlace(tmp, b, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lockStore takes the job's exclusive lock in the store volume (two jobs
// never overlap), retrying until ctx ends (never a hang past the job's
// deadline); release it with the returned func.
func lockStore(ctx context.Context, store string) (func(), error) {
	fi, err := os.Stat(store)
	if err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("the store volume %s isn't readable", store)
	}
	f, err := os.OpenFile(filepath.Join(store, jobLock), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the store's lock: %w", err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("the store's lock: %w", err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, errors.New("the store is locked by another bootstrap (gave up)")
		case <-time.After(time.Second):
		}
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func imageFile(dataDir string) string { return filepath.Join(dataDir, ".server-image") }

// waitReady polls the server's liveness until it answers 200.
func (j *Job) waitReady(ctx context.Context) error {
	d := j.Ready
	if d == 0 {
		d = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	c := &http.Client{Timeout: 5 * time.Second}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, j.URL+"/healthz/live", nil)
		if resp, err := c.Do(req); err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("the mail server didn't come up in time")
		case <-time.After(time.Second):
		}
	}
}

// WriteInPlace writes b into path without replacing the inode (O_TRUNC on
// the same file, then fsync), creating it 0600 when missing.
func WriteInPlace(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// recoveryPassword: the recovery admin's password for one start, hex
// (32 random bytes). Stalwart 1.1 refuses a recovery password starting
// with "_" (measured), which base64url gave one start in 64.
func recoveryPassword() (string, error) { return randomHex(32) }

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (j *Job) keyFile() string {
	if j.KeyFile != "" {
		return j.KeyFile
	}
	return KeyFile(j.DataDir)
}

// Run is the whole job, under the store's lock (Ruling T17-c, R-H2):
//   - an unmarked store: the base plan (recovery mode), the key, the
//     recovery login refused, then the marker;
//   - a marked store: never the plan. A recovery start judges the key
//     (KeyInPlace: never by using it, Ruling R2-N2b); a missing or
//     out-of-scope key is replaced by a new one only (Ruling R-H2); then
//     the normal start (with the role update after a server image change)
//     must refuse the recovery login.
func (j *Job) Run(ctx context.Context) (err error) {
	if j.Start == nil {
		return errors.New("no server to start")
	}
	if j.StoreDir == "" {
		return errors.New("no store volume (MAILCTL_STORE_DIR)")
	}
	unlock, err := lockStore(ctx, j.StoreDir)
	if err != nil {
		return err
	}
	defer unlock()
	if !markerValid(j.StoreDir) {
		if err := j.recovery(ctx, func(c *stalwart.Client) (Result, error) {
			p := j.Params
			if p.ClientIP == "" {
				p.ClientIP = state.ClientIPPreserved
			}
			if err := StoreEmpty(ctx, c, p); err != nil {
				return Result{}, err
			}
			// Always a new key (L-a): a half-done first plan may have left a
			// key in the store that the key file doesn't hold.
			return Apply(ctx, c, p, true, j.logf)
		}); err != nil {
			return err
		}
		if err := writeMarker(j.StoreDir, time.Now()); err != nil {
			return fmt.Errorf("marking the store bootstrapped: %w", err)
		}
		j.logf("bootstrap: done (the base plan, the recovery login refused)")
		return nil
	}
	// Ruling R2-N2b: the key is judged through the recovery admin, never
	// used (it is pinned to the adapter's address).
	return j.recovery(ctx, func(c *stalwart.Client) (Result, error) {
		var res Result
		// The admin view's password (contract §19.13): a lost or empty
		// viewer secret file gets a new password only, like the key. A
		// store from before the admin view gets exactly what it lacks
		// (the viewer role, the viewer account) and nothing else.
		healed := false
		if j.ViewerFile != "" && !viewerFileInPlace(j.ViewerFile) {
			v, err := ResetViewer(ctx, c)
			if err != nil {
				return res, err
			}
			switch {
			case v.Password == "":
				j.logf("bootstrap: the store has no parking domain (%s): the read-only admin view stays unavailable (no domain is made here)", ParkingDomain)
			case v.MadeAccount && v.MadeRole:
				j.logf("bootstrap: the store had no admin view account: made it (the viewer role and account only)")
			case v.MadeAccount:
				j.logf("bootstrap: the store had no admin view account: made it (the viewer account only)")
			case v.MadeRole:
				j.logf("bootstrap: the store had no admin view role: made it (the viewer role only; the viewer account holds it alone)")
			}
			if v.FixedRole {
				j.logf("bootstrap: the admin view role's permissions differed from the base plan's: set to the plan's (that role only)")
			}
			healed = v.MadeAccount || v.MadeRole || v.FixedRole
			res.ViewerPassword = v.Password
		}
		b, _ := os.ReadFile(j.keyFile())
		ok, err := KeyInPlace(ctx, c, j.Params.MailctlIP, strings.TrimSpace(string(b)))
		if err != nil {
			return res, err
		}
		if ok {
			// The CI and e2e checks read these lines (build-and-test-mail-
			// service.sh, e2e-podman-mail.sh): "; nothing to do" only when
			// the run changed nothing.
			if healed {
				j.logf("bootstrap: the store is bootstrapped and its API key is in place; the admin view role, account and a new password only")
			} else if res.ViewerPassword != "" {
				j.logf("bootstrap: the store is bootstrapped and its API key is in place; a new admin view password only")
			} else {
				j.logf("bootstrap: the store is bootstrapped and its API key is in place; nothing to do")
			}
			return res, nil
		}
		j.logf("bootstrap: the API key is missing or out of scope: a new key only (the store's settings untouched)")
		res.APIKey, err = MintKey(ctx, c, j.Params.MailctlIP)
		return res, err
	})
}

func (j *Job) imageUpdate() bool {
	recorded, _ := os.ReadFile(imageFile(j.DataDir))
	return j.ServerImage != "" && strings.TrimSpace(string(recorded)) != j.ServerImage
}

func (j *Job) recordImage() error {
	if !j.imageUpdate() {
		return nil
	}
	return WriteInPlace(imageFile(j.DataDir), []byte(j.ServerImage), 0o600)
}

func (j *Job) normalEnv() []string {
	if j.imageUpdate() {
		j.logf("bootstrap: the server image changed: the start runs the role-permission update")
		return []string{"STALWART_UPDATE_ROLE_PERMISSIONS=true"}
	}
	return nil
}

// recovery is one recovery-mode start (a password made here, the session
// nonce in SessionFile) running step as the recovery admin; the key step
// answers (if any) is written; then one normal start must refuse the
// recovery login. The key itself is never used here (Ruling R2-N2b).
func (j *Job) recovery(ctx context.Context, step func(*stalwart.Client) (Result, error)) (err error) {
	pw, err := recoveryPassword()
	if err != nil {
		return err
	}
	nonce, err := randomHex(32)
	if err != nil {
		return err
	}
	if j.SessionFile != "" {
		if err := WriteInPlace(j.SessionFile, []byte(nonce), 0o600); err != nil {
			return fmt.Errorf("the recovery session file: %w", err)
		}
		defer os.Remove(j.SessionFile)
	}
	stop, err := j.Start(ctx, []string{"STALWART_RECOVERY_MODE=1", "STALWART_RECOVERY_ADMIN=" + RecoveryUser + ":" + pw, "MAILCTL_RECOVERY_SESSION=" + nonce})
	if err != nil {
		return fmt.Errorf("starting the mail server in recovery mode: %w", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			if serr := stop(); serr != nil && err == nil {
				err = serr
			}
		}
	}()
	if err := j.waitReady(ctx); err != nil {
		return err
	}
	res, err := step(stalwart.New(j.URL, stalwart.Basic(RecoveryUser, pw)))
	if err != nil {
		return err
	}
	if res.APIKey != "" {
		if err := writeKeyFile(j.keyFile(), res.APIKey); err != nil {
			return fmt.Errorf("writing the API key: %w", err)
		}
		j.logf("bootstrap: a new API key written")
	}
	if res.ViewerPassword != "" && j.ViewerFile != "" {
		if err := writeKeyFile(j.ViewerFile, res.ViewerPassword); err != nil {
			return fmt.Errorf("writing the admin view's password: %w", err)
		}
		j.logf("bootstrap: a new admin view password written")
	}
	stopped = true
	if err := stop(); err != nil {
		return fmt.Errorf("stopping the recovery session: %w", err)
	}
	stop2, err := j.Start(ctx, j.normalEnv())
	if err != nil {
		return fmt.Errorf("starting the mail server: %w", err)
	}
	defer func() {
		if serr := stop2(); serr != nil && err == nil {
			err = serr
		}
	}()
	if err := j.waitReady(ctx); err != nil {
		return err
	}
	if err := VerifyGone(ctx, j.URL, Credentials{RecoveryUser: RecoveryUser, RecoveryPassword: pw}); err != nil {
		return err
	}
	return j.recordImage()
}
