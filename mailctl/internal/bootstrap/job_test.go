package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	return &Job{URL: srv.URL, DataDir: t.TempDir(), SessionFile: filepath.Join(t.TempDir(), "recovery-session"),
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
	if err != nil || fi.Mode().Perm() != 0o600 || !strings.HasPrefix(string(b), "API_") {
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
	// Again: the key is kept, the image already recorded (no role update).
	ino := inode(t, KeyFile(j.DataDir))
	s.starts = nil
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(KeyFile(j.DataDir))
	if string(b2) != string(b) || inode(t, KeyFile(j.DataDir)) != ino || len(s.starts[1]) != 0 {
		t.Fatalf("second run: key %q starts %q", b2, s.starts)
	}
	// A normal start that still accepts the recovery admin fails the job.
	s.leak = true
	if err := j.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "still works") {
		t.Fatalf("leak: %v", err)
	}
	// A server that never comes up fails it too, and stops it.
	s2 := &jobServer{f: newFake()}
	j2 := newJob(t, s2)
	j2.Ready = 1500 * time.Millisecond
	j2.Start = func(ctx context.Context, env []string) (func() error, error) { return func() error { return nil }, nil }
	if err := j2.Run(context.Background()); err == nil {
		t.Fatal("no server: accepted")
	}
}
