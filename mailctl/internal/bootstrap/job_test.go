package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// jobServer is the fake mail server behind the job: recovery mode accepts
// the recovery admin on /jmap; a normal start refuses it unless leak.
type jobServer struct {
	f        *fakeStalwart
	mu       sync.Mutex
	up       bool
	recovery bool
	leak     bool // a normal start that still accepts the recovery admin
	starts   [][]string
	// keyFile set: a Bearer must be the fake's latest API key (else 401).
	keyFile string
}

func (s *jobServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	up, rec, leak := s.up, s.recovery, s.leak
	s.mu.Unlock()
	if !up {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.URL.Path == "/healthz/live" {
		return
	}
	if h := r.Header.Get("Authorization"); s.keyFile != "" && strings.HasPrefix(h, "Bearer ") {
		s.f.mu.Lock()
		want := fmt.Sprintf("Bearer API_%038d", s.f.keyNext)
		s.f.mu.Unlock()
		if h != want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if u, _, _ := r.BasicAuth(); u == RecoveryUser && !rec {
		if leak {
			w.Write([]byte(`{"methodResponses":[]}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
		return
	}
	s.f.ServeHTTP(w, r)
}

func (s *jobServer) start(_ context.Context, env []string) (func() error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, env)
	s.up, s.recovery = true, false
	for _, e := range env {
		if e == "STALWART_RECOVERY_MODE=1" {
			s.recovery = true
		}
	}
	return func() error { s.mu.Lock(); s.up = false; s.mu.Unlock(); return nil }, nil
}

func newJob(t *testing.T, s *jobServer) *Job {
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return &Job{URL: srv.URL, DataDir: t.TempDir(), StoreDir: t.TempDir(), SessionFile: filepath.Join(t.TempDir(), "recovery-session"),
		ServerImage: "docker.io/stalwartlabs/stalwart:v1.1.0@sha256:aa", Params: params(), Start: s.start, Ready: 5 * time.Second}
}

// The job applies the plan in recovery mode, writes the key 0600, and
// exits nil only once a normal start refuses the recovery login.
func TestBootstrapJobVerifiesRecoveryRefused(t *testing.T) {
	s := &jobServer{f: newFake()}
	j := newJob(t, s)
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(KeyFile(j.DataDir))
	b, _ := os.ReadFile(KeyFile(j.DataDir))
	if err != nil || fi.Mode().Perm() != 0o640 || !strings.HasPrefix(string(b), "API_") {
		t.Fatalf("key %v %v %q", err, fi, b)
	}
	if len(s.starts) != 2 || !strings.HasPrefix(strings.Join(s.starts[0], " "), "STALWART_RECOVERY_MODE=1 STALWART_RECOVERY_ADMIN=portcullis-recovery:") ||
		strings.Join(s.starts[1], " ") != "STALWART_UPDATE_ROLE_PERMISSIONS=true" {
		t.Fatalf("starts %q", s.starts)
	}
	if _, err := os.Stat(j.SessionFile); !os.IsNotExist(err) {
		t.Fatal("the recovery session file outlived the job")
	}
	if s.up {
		t.Fatal("the server was left running")
	}
	// Ruling T17-c / R-H2: the store is marked; a cold start takes the
	// lock, sees the marker, and only checks the key on one normal start
	// (no plan, no settings touched).
	if !markerValid(j.StoreDir) {
		t.Fatal("no marker after the plan")
	}
	s.keyFile = KeyFile(j.DataDir)
	sets := func() string {
		s.f.mu.Lock()
		defer s.f.mu.Unlock()
		var out []string
		for _, c := range s.f.calls {
			if strings.Contains(c, "/set") && !strings.Contains(c, "x:ApiKey/set") {
				out = append(out, c)
			}
		}
		return strings.Join(out, ",")
	}
	ino := inode(t, KeyFile(j.DataDir))
	s.starts = nil
	s.f.calls = nil
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(KeyFile(j.DataDir))
	if string(b2) != string(b) || inode(t, KeyFile(j.DataDir)) != ino || len(s.starts) != 1 || len(s.starts[0]) != 0 || sets() != "" {
		t.Fatalf("second run: key %q starts %q sets %s", b2, s.starts, sets())
	}
	// A server image change: the check's start runs the role update.
	j.ServerImage = "docker.io/stalwartlabs/stalwart:v1.1.1@sha256:bb"
	s.starts = nil
	if err := j.Run(context.Background()); err != nil || len(s.starts) != 1 || strings.Join(s.starts[0], " ") != "STALWART_UPDATE_ROLE_PERMISSIONS=true" {
		t.Fatalf("image change: %v %q", err, s.starts)
	}
	// R-H2: a marked store with its key lost or refused mints a new key
	// only: the check's start, a recovery start, the normal start; no
	// object but the API key is written, and the new key works.
	for name, lose := range map[string]func(){
		"missing": func() { os.Remove(KeyFile(j.DataDir)) },
		"empty":   func() { os.WriteFile(KeyFile(j.DataDir), nil, 0o640) },
		"refused": func() { os.WriteFile(KeyFile(j.DataDir), []byte("API_stale"), 0o640) },
	} {
		lose()
		s.starts = nil
		s.f.calls = nil
		if err := j.Run(context.Background()); err != nil || len(s.starts) != 3 || sets() != "" || !markerValid(j.StoreDir) {
			t.Fatalf("%s key: %v starts %q sets %s", name, err, s.starts, sets())
		}
		if k, _ := os.ReadFile(KeyFile(j.DataDir)); !strings.HasPrefix(string(k), "API_") || string(k) == "API_stale" {
			t.Fatalf("%s key: new key %q", name, k)
		}
	}
	// No temporary key file left behind (written by rename).
	if _, err := os.Stat(KeyFile(j.DataDir) + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("a temporary key file is left")
	}
	// A marked store without mailctl's account: fail closed (no plan).
	s.f.mu.Lock()
	for id, a := range s.f.objs["Account"] {
		if a["name"] == MailctlAccount {
			delete(s.f.objs["Account"], id)
		}
	}
	s.f.mu.Unlock()
	os.Remove(KeyFile(j.DataDir))
	s.f.calls = nil
	if err := j.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "no mailctl account") || sets() != "" {
		t.Fatalf("no account: %v sets %s", err, sets())
	}
	s.keyFile = ""
	// An invalid marker runs the plan again (fail closed).
	os.WriteFile(filepath.Join(j.StoreDir, planMarker), []byte(`{"version":2}`), 0o600)
	s.starts = nil
	if err := j.Run(context.Background()); err != nil || len(s.starts) != 2 {
		t.Fatalf("invalid marker: %v %q", err, s.starts)
	}
	// The key at MAILCTL_API_KEY_FILE when set.
	j.KeyFile = filepath.Join(t.TempDir(), "key")
	os.Remove(filepath.Join(j.StoreDir, planMarker))
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(j.KeyFile); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("key file %v %v", fi, err)
	}
	// A held lock: the job gives up at its deadline, never hangs (L1).
	f, _ := os.OpenFile(filepath.Join(j.StoreDir, jobLock), os.O_RDWR|os.O_CREATE, 0o600)
	syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	err = j.Run(ctx)
	cancel()
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	f.Close()
	if err == nil || !strings.Contains(err.Error(), "locked by another bootstrap") {
		t.Fatalf("held lock: %v", err)
	}
	// No store volume: refused before anything starts.
	j2 := newJob(t, &jobServer{f: newFake()})
	j2.StoreDir = filepath.Join(t.TempDir(), "missing")
	if err := j2.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "store volume") {
		t.Fatalf("missing store: %v", err)
	}
	// A normal start that still accepts the recovery admin fails the job,
	// and leaves the store unmarked.
	os.Remove(filepath.Join(j.StoreDir, planMarker))
	s.leak = true
	if err := j.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "still works") {
		t.Fatalf("leak: %v", err)
	}
	if markerValid(j.StoreDir) {
		t.Fatal("a failed plan marked the store")
	}
	// A server that never comes up fails it too, and stops it.
	s2 := &jobServer{f: newFake()}
	j2 = newJob(t, s2)
	j2.Ready = 1500 * time.Millisecond
	j2.Start = func(ctx context.Context, env []string) (func() error, error) { return func() error { return nil }, nil }
	if err := j2.Run(context.Background()); err == nil {
		t.Fatal("no server: accepted")
	}
}
