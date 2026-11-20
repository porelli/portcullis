package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/portcullis/wg/internal/status"
)

// TestStatusEndpoint: the status port (contract §20.10) answers status.json
// as written, GET only; WG_STATUS_LISTEN only in pod mode, on the pod's
// address.
func TestStatusEndpoint(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "status.json")
	h := statusHandler(file)
	do := func(method, target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, target, nil))
		return w
	}
	if w := do("GET", "/v1/status"); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no file yet: %d", w.Code)
	}
	if err := status.Write(file, status.Doc{Mode: "apps", Edge: status.Role{OK: true}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(file)
	w := do("GET", "/v1/status")
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" || !bytes.Equal(w.Body.Bytes(), disk) {
		t.Fatalf("status: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	if d, err := status.Read(file); err != nil || !d.Edge.OK {
		t.Fatalf("the served file doesn't parse: %v", err)
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "FOO"} {
		if w := do(m, "/v1/status"); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
			t.Errorf("%s: %d", m, w.Code)
		}
	}
	for _, p := range []string{"/", "/v1/status/", "/v1/log", "/metrics", "/v1/status?x=1", "/v1/%73tatus"} {
		if w := do("GET", p); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	// Never through a symlink.
	other := filepath.Join(dir, "other.json")
	_ = os.WriteFile(other, []byte(`{"secret":1}`), 0o640)
	_ = os.Remove(file)
	if err := os.Symlink(other, file); err != nil {
		t.Fatal(err)
	}
	if w := do("GET", "/v1/status"); w.Code != http.StatusInternalServerError || bytes.Contains(w.Body.Bytes(), []byte("secret")) {
		t.Fatalf("symlink: %d %s", w.Code, w.Body)
	}

	// The variable: pod mode, the pod's own address, a port.
	pod := map[string]string{
		"WG_ADDR_MODE": "pod", "WG_VPN_ADDR": "10.42.0.17", "WG_EDGE_ADDR": "10.42.0.17",
		"WG_TRAEFIK": "10.43.0.21:8444", "WG_DOMAIN": "example.org", "WG_METRICS": "10.42.0.17:9100",
		"WG_STATUS_LISTEN": "10.42.0.17:8093",
	}
	get := func(over map[string]string) func(string) string {
		return func(k string) string {
			if v, ok := over[k]; ok {
				return v
			}
			return pod[k]
		}
	}
	c, err := loadConfig(get(nil))
	if err != nil || c.StatusListen.String() != "10.42.0.17:8093" {
		t.Fatalf("pod: %+v %v", c, err)
	}
	if c, err := loadConfig(get(map[string]string{"WG_STATUS_LISTEN": ""})); err != nil || c.StatusListen.IsValid() {
		t.Fatalf("unset = off: %v", err)
	}
	for name, over := range map[string]map[string]string{
		"another address": {"WG_STATUS_LISTEN": "10.42.0.18:8093"},
		"all addresses":   {"WG_STATUS_LISTEN": ":8093"},
		"port 0":          {"WG_STATUS_LISTEN": "10.42.0.17:0"},
		"no port":         {"WG_STATUS_LISTEN": "10.42.0.17"},
		"docker mode":     {"WG_ADDR_MODE": "docker", "WG_EDGE_ADDR": "10.42.1.17"},
	} {
		if _, err := loadConfig(get(over)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
