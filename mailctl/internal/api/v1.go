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

	"github.com/portcullis/mailctl/internal/checks"
	"github.com/portcullis/mailctl/internal/creds"
	"github.com/portcullis/mailctl/internal/machines"
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
	// Rewritten client addresses: LAN-only admits loopback only.
	Rewritten bool
	Now       func() time.Time
	Logf      func(string, ...any)
	// M runs the state machines (DNS set, status, actions).
	M *machines.Machines
	// Checks are GET /v1/checks.
	Checks *checks.Runner

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
	mux.HandleFunc("GET /v1/dns/{domain}", v.getDNS)
	mux.HandleFunc("GET /v1/status", v.getStatus)
	mux.HandleFunc("GET /v1/checks", v.getChecks)
	mux.HandleFunc("POST /v1/actions/{action}", v.action)
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
		// The Hub branches on error_kind (contract §19.5).
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error(), "error_kind": "mass_removal"})
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

// Bootstrapped: the API key works (cached 10 s).
func (v *V1) Bootstrapped(ctx context.Context) bool { return v.bootstrapped(ctx) }

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
	cr, err := creds.Create(ctx, v.C, id, req.Label, req.ExpiresAt, creds.AllowedIPs(v.LANOnly, reconcile.LocalNets(doc, v.Rewritten)), v.now())
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

func (v *V1) clientIP() string {
	if v.Rewritten {
		return "rewritten"
	}
	return "preserved"
}

func (v *V1) getDNS(w http.ResponseWriter, r *http.Request) {
	var noWild bool
	switch r.URL.Query().Get("wildcard") {
	case "", "true":
	case "false":
		noWild = true
	default:
		writeErr(w, http.StatusBadRequest, "wildcard must be true or false")
		return
	}
	set, err := v.M.SetFor(strings.ToLower(r.PathValue("domain")), noWild)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not a mail domain")
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (v *V1) getStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	st, err := v.M.Status(ctx, v.bootstrapped(ctx), v.clientIP())
	if err != nil {
		v.unreachable(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (v *V1) action(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Domain *string `json:"domain"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if state.NoDuplicateKeys(b) != nil || d.Decode(&req) != nil || d.More() || req.Domain == nil {
		writeErr(w, http.StatusBadRequest, "the body must be {domain}")
		return
	}
	domain := strings.ToLower(*req.Domain)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var err error
	switch r.PathValue("action") {
	case "dkim-rotate":
		err = v.M.DKIMRotate(ctx, domain)
	case "dmarc-promote":
		err = v.M.DMARCPromote(domain)
	case "mtasts-enforce":
		err = v.M.MTASTSEnforce(ctx, domain)
	default:
		writeErr(w, http.StatusNotFound, "no such action")
		return
	}
	var nothing machines.ErrNothingToDo
	switch {
	case errors.Is(err, machines.ErrNotMailDomain):
		writeErr(w, http.StatusNotFound, "not a mail domain")
	case errors.As(err, &nothing):
		writeErr(w, http.StatusConflict, nothing.Why)
	case err != nil:
		v.unreachable(w, err)
	default:
		if v.Logf != nil {
			v.Logf("actions: %s %s", r.PathValue("action"), domain)
		}
		v.M.Trigger()
		writeJSON(w, http.StatusAccepted, map[string]string{})
	}
}

func (v *V1) getChecks(w http.ResponseWriter, r *http.Request) {
	refresh := false
	switch r.URL.Query().Get("refresh") {
	case "":
	case "1":
		refresh = true
	default:
		writeErr(w, http.StatusBadRequest, "refresh must be 1")
		return
	}
	writeJSON(w, http.StatusOK, v.Checks.Get(r.Context(), refresh))
}
