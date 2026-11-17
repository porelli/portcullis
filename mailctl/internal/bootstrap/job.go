package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
//  2. applies the base plan as the recovery admin (the document's parts
//     from the adapter's last accepted document, when there is one),
//  3. writes the API key into DataDir (0600, in place),
//  4. stops the server, starts it normally once (with the role-permission
//     update after a server image change) and exits nil only when the
//     recovery login is refused there.
type Job struct {
	URL         string // the server's management listener (MAILCTL_STALWART_URL)
	DataDir     string // adapter_data
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

// KeyFile is the API key's file in adapter_data.
func KeyFile(dataDir string) string { return filepath.Join(dataDir, "api-key") }

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

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Run is the whole job.
func (j *Job) Run(ctx context.Context) (err error) {
	if j.Start == nil {
		return errors.New("no server to start")
	}
	pw, err := randomSecret(32)
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
	p := j.Params
	if st, serr := state.Open(j.DataDir); serr == nil {
		if doc := st.Get().Doc; doc != nil {
			dp := DocParams(doc)
			p.Hostname, p.PrimaryDomain, p.ClientIP, p.Relay = dp.Hostname, dp.PrimaryDomain, dp.ClientIP, dp.Relay
			p.LANOnly, p.LocalNetworks = doc.SubmissionLANOnly, doc.LocalNetworks
		}
	}
	if p.ClientIP == "" {
		p.ClientIP = state.ClientIPPreserved
	}
	old, _ := os.ReadFile(KeyFile(j.DataDir))
	rotate := strings.TrimSpace(string(old)) == ""

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
	res, err := Apply(ctx, stalwart.New(j.URL, stalwart.Basic(RecoveryUser, pw)), p, rotate, j.logf)
	if err != nil {
		return err
	}
	if res.APIKey != "" {
		if err := WriteInPlace(KeyFile(j.DataDir), []byte(res.APIKey), 0o600); err != nil {
			return fmt.Errorf("writing the API key: %w", err)
		}
		j.logf("bootstrap: a new API key written")
	}
	stopped = true
	if err := stop(); err != nil {
		return fmt.Errorf("stopping the recovery session: %w", err)
	}

	// The normal start: the recovery admin must be refused there.
	var env []string
	recorded, _ := os.ReadFile(imageFile(j.DataDir))
	update := j.ServerImage != "" && strings.TrimSpace(string(recorded)) != j.ServerImage
	if update {
		env = append(env, "STALWART_UPDATE_ROLE_PERMISSIONS=true")
		j.logf("bootstrap: the server image changed: one start with the role-permission update")
	}
	stop2, err := j.Start(ctx, env)
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
	if update {
		if err := WriteInPlace(imageFile(j.DataDir), []byte(j.ServerImage), 0o600); err != nil {
			return fmt.Errorf("recording the server image: %w", err)
		}
	}
	j.logf("bootstrap: done (the recovery login is refused)")
	return nil
}
