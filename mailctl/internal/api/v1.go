package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/mailctl/internal/creds"
	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
)

// MaxBody bounds every request body (contract §19.5).
const MaxBody = 4 << 20

// V1 is the Hub API's routes (behind Server's guard).
type V1 struct {
	Store   *state.Store
	C       *stalwart.Client
	Runner  *reconcile.Runner
	LANOnly bool
	Now     func() time.Time
	Logf    func(string, ...any)

	mu        sync.Mutex
	bootAt    time.Time
	bootState bool
}

// Handler is the v1 mux.
func (v *V1) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/state", v.putState)
	mux.HandleFunc("GET /v1/state", v.getState)
	mux.HandleFunc("GET /v1/credentials", v.listCreds)
	mux.HandleFunc("POST /v1/credentials", v.createCred)
	mux.HandleFunc("DELETE /v1/credentials/{id}", v.deleteCred)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (v *V1) unreachable(w http.ResponseWriter, err error) {
	if v.Logf != nil {
		v.Logf("api: stalwart: %v", err)
	}
	writeErr(w, http.StatusServiceUnavailable, "mail server unreachable")
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the body is unreadable or larger than 4 MiB")
		return nil, false
	}
	return b, true
}

func (v *V1) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *V1) putState(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	doc, err := state.Parse(b)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p := v.Store.Get()
	if doc.Generation <= p.Generation {
		writeErr(w, http.StatusConflict, "generation is not greater than the last accepted one")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	if _, err := reconcile.Plan(live, doc, p.Former, v.now(), 1<<62); errors.Is(err, reconcile.ErrMassRemoval) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if err := v.Store.Update(func(s *state.Persistent) error {
		if doc.Generation <= s.Generation {
			return errors.New("stale")
		}
		s.Doc, s.Generation = doc, doc.Generation
		return nil
	}); err != nil {
		writeErr(w, http.StatusConflict, "generation is not greater than the last accepted one")
		return
	}
	if v.Runner != nil {
		v.Runner.Trigger()
	}
	writeJSON(w, http.StatusAccepted, map[string]int64{"generation": doc.Generation})
}

// bootstrapped: the API key works (cached 10 s).
func (v *V1) bootstrapped(ctx context.Context) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Since(v.bootAt) < 10*time.Second {
		return v.bootState
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := v.C.Query(cctx, "Domain", nil)
	v.bootAt, v.bootState = time.Now(), err == nil
	return v.bootState
}

func (v *V1) getState(w http.ResponseWriter, r *http.Request) {
	p := v.Store.Get()
	errs := p.Errors
	if errs == nil {
		errs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"generation": p.Generation, "applied_generation": p.AppliedGeneration,
		"bootstrap": v.bootstrapped(r.Context()), "errors": errs})
}

// account resolves ?user= (or the body's username) to a live account id;
// it writes the answer itself when it fails.
func (v *V1) account(w http.ResponseWriter, ctx context.Context, user string) (string, *state.Doc, bool) {
	p := v.Store.Get()
	if p.Doc == nil {
		writeErr(w, http.StatusNotFound, "no such account")
		return "", nil, false
	}
	if _, ok := p.Doc.Account(user); !ok {
		writeErr(w, http.StatusNotFound, "no such account")
		return "", nil, false
	}
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return "", nil, false
	}
	id := reconcile.FindAccount(live, p.Doc, user)
	if id == "" {
		writeErr(w, http.StatusNotFound, "no such account")
		return "", nil, false
	}
	return id, p.Doc, true
}

func (v *V1) listCreds(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	id, _, ok := v.account(w, ctx, r.URL.Query().Get("user"))
	if !ok {
		return
	}
	list, err := creds.List(ctx, v.C, id)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type createReq struct {
	Username  string     `json:"username"`
	Label     string     `json:"label"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (v *V1) createCred(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var req createReq
	if err := state.NoDuplicateKeys(b); err != nil {
		writeErr(w, http.StatusBadRequest, "the body must be {username, label, expires_at}")
		return
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil || d.More() {
		writeErr(w, http.StatusBadRequest, "the body must be {username, label, expires_at}")
		return
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(b, &keys)
	for _, k := range []string{"username", "label", "expires_at"} {
		if _, ok := keys[k]; !ok {
			writeErr(w, http.StatusBadRequest, "missing "+k)
			return
		}
	}
	if !creds.ValidLabel(req.Label) {
		writeErr(w, http.StatusBadRequest, "the label must be 1-64 characters on one line")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(v.now()) {
		writeErr(w, http.StatusBadRequest, "expires_at is in the past")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	id, doc, ok := v.account(w, ctx, req.Username)
	if !ok {
		return
	}
	cr, err := creds.Create(ctx, v.C, id, req.Label, req.ExpiresAt, creds.AllowedIPs(v.LANOnly, doc.LocalNetworks), v.now())
	switch {
	case errors.Is(err, creds.ErrLimit):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		v.unreachable(w, err)
		return
	}
	if v.Logf != nil {
		v.Logf("credentials: created mail password %s for %s", cr.ID, strings.ToLower(req.Username))
	}
	writeJSON(w, http.StatusCreated, cr)
}

func (v *V1) deleteCred(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	user := r.URL.Query().Get("user")
	id, _, ok := v.account(w, ctx, user)
	if !ok {
		return
	}
	if err := creds.Revoke(ctx, v.C, id, r.PathValue("id")); err != nil {
		v.unreachable(w, err)
		return
	}
	if v.Logf != nil {
		v.Logf("credentials: revoked mail password %s of %s", r.PathValue("id"), user)
	}
	w.WriteHeader(http.StatusNoContent)
}
