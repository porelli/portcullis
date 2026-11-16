// Package admin is mailctl's control socket for the CLI (`docker compose
// exec mailctl mailctl dns|rotate|tls-key|status`): a unix socket inside the
// container, 0600, so only mailctl's own uid (the exec's user) reaches it.
// Nothing listens on a network for these.
package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/state"
)

// Socket is the control socket's path (mailctl's tmpfs /tmp).
const Socket = "/tmp/mailctl.sock"

// Status is the extra status input serve owns.
type Status struct {
	Bootstrapped func(context.Context) bool
	ClientIP     string
	// Checks is the last checks result (nil: none).
	Checks func(context.Context) any
}

// Handler serves the socket's routes.
func Handler(m *machines.Machines, st Status) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dns/main", func(w http.ResponseWriter, r *http.Request) {
		set, err := m.Set(m.Cfg.MainDomain)
		if err != nil {
			writeErr(w, http.StatusNotFound, "the main domain isn't a mail domain of the applied document (has the Hub sent one?)")
			return
		}
		writeJSON(w, http.StatusOK, set)
	})
	mux.HandleFunc("POST /rotate", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unreadable input")
			return
		}
		in, err := ParseRotate(b)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		out, err := m.Rotate(ctx, in)
		if errors.Is(err, machines.ErrNotMailDomain) {
			writeErr(w, http.StatusNotFound, "the main domain isn't a mail domain of the applied document (has the Hub sent one?)")
			return
		}
		if err != nil && out.Domain == "" {
			writeErr(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		// A failed machine step still answers the set (the records stay
		// what the state says); the error goes to mailctl's log.
		writeJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /tls-key", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unreadable input")
			return
		}
		cur, err := ParseTLSKey(b)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := m.RecordKey(cur); err != nil {
			writeErr(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"current": cur})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		boot := st.Bootstrapped != nil && st.Bootstrapped(ctx)
		s, err := m.Status(ctx, boot, st.ClientIP)
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "mail server unreachable")
			return
		}
		var ck any
		if st.Checks != nil {
			ck = st.Checks(ctx)
		}
		// document: the Hub's last accepted document (null: none yet —
		// with mail on, the Hub isn't reaching mailctl; the CLI says so).
		var doc any
		if p := m.Store.Get(); p.Doc != nil {
			doc = map[string]int64{"generation": p.Generation, "applied_generation": p.AppliedGeneration}
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": s, "checks": ck, "document": doc})
	})
	mux.HandleFunc("POST /dkim-rotate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Domain string `json:"domain"`
		}
		d := json.NewDecoder(io.LimitReader(r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || req.Domain == "" {
			writeErr(w, http.StatusBadRequest, `the input must be {"domain"}`)
			return
		}
		var nothing machines.ErrNothingToDo
		switch err := m.DKIMRotate(r.Context(), strings.ToLower(req.Domain)); {
		case errors.Is(err, machines.ErrNotMailDomain):
			writeErr(w, http.StatusNotFound, req.Domain+" isn't a mail domain")
		case errors.As(err, &nothing):
			writeErr(w, http.StatusConflict, nothing.Why)
		case err != nil:
			writeErr(w, http.StatusServiceUnavailable, err.Error())
		default:
			writeJSON(w, http.StatusOK, map[string]string{"domain": strings.ToLower(req.Domain), "result": "a new DKIM key pair is being made; it goes active once both public resolvers serve it"})
		}
	})
	return mux
}

// ParseTLSKey reads `mailctl tls-key --json`'s stdin strictly:
// {"current": <sha256 hex>} (lowercased).
func ParseTLSKey(b []byte) (string, error) {
	bad := fmt.Errorf(`the input must be {"current": <the certificate's SPKI sha256 hex>}`)
	var in struct {
		Current *string `json:"current"`
	}
	if state.NoDuplicateKeys(b) != nil {
		return "", bad
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.More() || in.Current == nil || !isHex64(*in.Current) {
		return "", bad
	}
	return strings.ToLower(*in.Current), nil
}

// ParseRotate reads `mailctl rotate --json`'s stdin strictly:
// {"dnssec_state", "spki": {"current", "next"}}.
func ParseRotate(b []byte) (machines.RotateIn, error) {
	var in machines.RotateIn
	bad := fmt.Errorf(`the input must be {"dnssec_state", "spki": {"current", "next"}}`)
	if state.NoDuplicateKeys(b) != nil {
		return in, bad
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.More() {
		return in, bad
	}
	var keys struct {
		DNSSEC *string `json:"dnssec_state"`
		SPKI   *struct {
			Current *string `json:"current"`
			Next    *string `json:"next"`
		} `json:"spki"`
	}
	_ = json.Unmarshal(b, &keys)
	if keys.DNSSEC == nil || keys.SPKI == nil || keys.SPKI.Current == nil || keys.SPKI.Next == nil {
		return in, bad
	}
	for _, s := range []string{in.SPKI.Current, in.SPKI.Next} {
		if s != "" && !isHex64(s) {
			return in, fmt.Errorf("spki values are sha256 hex digests or empty")
		}
	}
	if len(in.DNSSECState) > 32 {
		return in, fmt.Errorf("dnssec_state is too long")
	}
	return in, nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// Listen makes the socket 0600 (a stale one is replaced).
func Listen(path string) (net.Listener, error) {
	_ = os.Remove(path)
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Call is the client: one request on the socket, the answer's body on
// success, else an error with the server's message.
func Call(path, method, route string, body []byte) ([]byte, error) {
	c := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}}
	req, err := http.NewRequest(method, "http://mailctl"+route, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mailctl isn't serving (%v)", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, errors.New(e.Error)
	}
	return b, nil
}
