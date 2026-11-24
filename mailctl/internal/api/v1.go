package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/mailctl/internal/checks"
	"github.com/portcullis/mailctl/internal/creds"
	"github.com/portcullis/mailctl/internal/logx"
	"github.com/portcullis/mailctl/internal/machines"
	"github.com/portcullis/mailctl/internal/mailtest"
	"github.com/portcullis/mailctl/internal/reconcile"
	"github.com/portcullis/mailctl/internal/stalwart"
	"github.com/portcullis/mailctl/internal/state"
	"github.com/portcullis/mailctl/internal/tlsprobe"
)

// MaxBody bounds every request body (contract §19.5).
const MaxBody = 4 << 20

// V1 is the provider API v1's routes (behind Server's guard). LAN-only,
// the client address mode and the rest come from the accepted document
// (MailState v2), never from the environment.
type V1 struct {
	Store  *state.Store
	C      *stalwart.Client
	Runner *reconcile.Runner
	Now    func() time.Time
	Logf   func(string, ...any)
	// TLSDir holds fullchain.pem and privkey.pem (PORTCULLIS_MAIL_TLS_DIR).
	TLSDir string
	// Serving reads the leaf the listeners serve (the TLS reload's answer).
	Serving func(ctx context.Context) (*x509.Certificate, error)
	// Test submits the test message (POST /v1/actions/test): its queue id.
	Test func(ctx context.Context, doc *state.Doc, to string) (string, error)
	// Export: the template's mail: block has export (GET /v1/provider).
	Export bool
	// M runs the state machines (DNS set, status, actions).
	M *machines.Machines
	// Checks are GET /v1/checks.
	Checks *checks.Runner
	// beforeCreate runs between the account checks and the password's
	// creation (tests: a document swap there must change nothing).
	beforeCreate func()

	mu        sync.Mutex
	bootAt    time.Time
	bootState bool
}

// Handler is the v1 mux. Before the bootstrap only GET /v1/provider and
// GET /v1/state answer; every other route is 503 (contract §19.5).
func (v *V1) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/provider", v.getProvider)
	mux.HandleFunc("POST /v1/void", v.void)
	mux.HandleFunc("POST /v1/tls/reload", v.tlsReload)
	mux.HandleFunc("POST /v1/actions/test", v.actionTest)
	mux.HandleFunc("PUT /v1/state", v.putState)
	mux.HandleFunc("GET /v1/state", v.getState)
	mux.HandleFunc("GET /v1/credentials", v.listCreds)
	mux.HandleFunc("POST /v1/credentials", v.createCred)
	mux.HandleFunc("DELETE /v1/credentials/{id}", v.deleteCred)
	mux.HandleFunc("GET /v1/dns/{domain}", v.getDNS)
	mux.HandleFunc("GET /v1/status", v.getStatus)
	mux.HandleFunc("GET /v1/checks", v.getChecks)
	mux.HandleFunc("POST /v1/actions/{action}", v.action)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		always := r.Method == http.MethodGet && (r.URL.Path == "/v1/provider" || r.URL.Path == "/v1/state")
		if !always && !v.bootstrapped(r.Context()) {
			writeErr(w, http.StatusServiceUnavailable, "the mail server isn't ready")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Actions are the provider's actions (GET /v1/provider).
var Actions = []string{"dkim-rotate", "dmarc-promote", "mtasts-enforce", "test"}

func (v *V1) getProvider(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"name": machines.ProviderName, "version": machines.ProviderVersion, "api_version": 1,
		"checks": checks.Catalog, "actions": Actions, "export": v.Export})
}

// decodeStrict decodes one JSON object into dst: unknown and duplicate
// keys and trailing data refused, every key of keys required.
func decodeStrict(b []byte, dst any, keys ...string) bool {
	if state.NoDuplicateKeys(b) != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	for _, k := range keys {
		if v, ok := m[k]; !ok || string(v) == "null" {
			return false
		}
	}
	return true
}

// void is POST /v1/void: every mail password of every account (live and
// parked) destroyed, verified gone, then restored_at recorded (contract
// §19.11). Under the pass lock: no create lands meanwhile.
func (v *V1) void(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if !decodeStrict(b, &req, "reason") || (req.Reason != "wire" && req.Reason != "restore") {
		writeErr(w, http.StatusBadRequest, `the body must be {"reason": "wire" | "restore"}`)
		return
	}
	if v.Runner != nil {
		v.Runner.LockPass()
		defer v.Runner.UnlockPass()
	}
	// Its own deadline, never the client's (M6): the Hub's client gives up
	// after 30 s, and a void stopped half way only costs a retry.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
	defer cancel()
	n, err := creds.VoidAll(ctx, v.C)
	if err != nil {
		if v.Logf != nil {
			v.Logf("void: failed after %d mail passwords: %s", n, logx.Redact(err.Error()))
		}
		writeErr(w, http.StatusServiceUnavailable, "the void failed: mail passwords may be left")
		return
	}
	now := v.now().UTC().Truncate(time.Second)
	if err := v.Store.Update(func(p *state.Persistent) error { p.RestoredAt = &now; return nil }); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "the void's time couldn't be recorded")
		return
	}
	if v.Logf != nil {
		v.Logf("void (%s): %d mail passwords destroyed", req.Reason, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"voided": n, "restored_at": now})
}

var reSPKI = regexp.MustCompile(`^[0-9a-f]{64}$`)

// tlsReload is POST /v1/tls/reload: the certificate files read again
// (refused while they can't be), the server's TLS reloaded, and the SPKI
// its submissions listener then serves (contract §19.3).
func (v *V1) tlsReload(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		SPKI []string `json:"spki_sha256"`
	}
	valid := decodeStrict(b, &req, "spki_sha256") && len(req.SPKI) >= 1 && len(req.SPKI) <= 2
	for _, k := range req.SPKI {
		valid = valid && reSPKI.MatchString(k)
	}
	if !valid {
		writeErr(w, http.StatusBadRequest, `the body must be {"spki_sha256": ["<64 lowercase hex>", …]} with 1-2 keys`)
		return
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(v.TLSDir, "fullchain.pem"), filepath.Join(v.TLSDir, "privkey.pem")); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "the certificate files can't be read")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := v.C.Action(ctx, "ReloadTlsCertificates"); err != nil {
		v.unreachable(w, err)
		return
	}
	v.M.ForgetCert()
	if v.Serving == nil {
		writeErr(w, http.StatusServiceUnavailable, "the served certificate can't be read")
		return
	}
	leaf, err := v.Serving(ctx)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "the served certificate can't be read")
		return
	}
	got := tlsprobe.SPKI(leaf)
	if !slices.Contains(req.SPKI, got) && v.Logf != nil {
		v.Logf("tls reload: the listeners serve %s, not one of the keys sent", got)
	}
	writeJSON(w, http.StatusOK, map[string]string{"serving_spki_sha256": got})
}

// actionTest is POST /v1/actions/test: one message from the first
// postmaster account (contract §19.10).
func (v *V1) actionTest(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var req struct {
		To string `json:"to"`
	}
	if !decodeStrict(b, &req, "to") || !oneAddress(req.To) {
		writeErr(w, http.StatusBadRequest, "to must be one address")
		return
	}
	doc := v.Store.Get().Doc
	if doc == nil || len(doc.Postmaster) == 0 {
		writeErr(w, http.StatusConflict, "no postmaster account: an administrator who has a mailbox is one")
		return
	}
	if v.Test == nil {
		writeErr(w, http.StatusServiceUnavailable, "the test can't be sent")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	id, err := v.Test(ctx, doc, req.To)
	if errors.Is(err, mailtest.ErrNoPostmaster) {
		writeErr(w, http.StatusConflict, "no postmaster account: an administrator who has a mailbox is one")
		return
	}
	if err != nil {
		if v.Logf != nil {
			v.Logf("actions: test: %s", logx.Redact(err.Error()))
		}
		writeErr(w, http.StatusServiceUnavailable, "the test message couldn't be submitted")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"queue_id": id})
}

// oneAddress: a bare address (no display name, no list), one line.
func oneAddress(s string) bool {
	if s == "" || len(s) > 254 || strings.ContainsAny(s, " <>,\r\n\t") {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s && strings.Contains(s, "@")
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

// writeKind is a refusal the Hub branches on (contract §19.5: error_kind).
func writeKind(w http.ResponseWriter, status int, kind, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "error_kind": kind})
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
		writeKind(w, http.StatusConflict, "generation", "generation is not greater than the last accepted one")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	var confirmed *state.MassRemoval
	ops, err := reconcile.Plan(live, doc, p.Former, v.now(), 1<<62, nil)
	if errors.Is(err, reconcile.ErrMassRemoval) && doc.ConfirmMassRemoval {
		// Bound to the set this live read removes: a later pass that
		// would remove anything else is refused again (final review L2).
		var uuids []string
		for _, r := range ops.Removals {
			uuids = append(uuids, r.UUID)
		}
		confirmed = state.NewMassRemoval(doc.Generation, uuids)
	} else if errors.Is(err, reconcile.ErrMassRemoval) {
		// The Hub branches on error_kind and shows the accounts the
		// document would remove (from this one live read): username and
		// uuid only, sorted by username (contract §19.5).
		type gone struct {
			Username string `json:"username"`
			UUID     string `json:"uuid"`
		}
		removed := make([]gone, 0, len(ops.Removals))
		for _, r := range ops.Removals {
			removed = append(removed, gone{Username: r.Username, UUID: r.UUID})
		}
		sort.Slice(removed, func(i, j int) bool { return removed[i].Username < removed[j].Username })
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "error_kind": "mass_removal", "removed": removed})
		return
	}
	if err := v.Store.Update(func(s *state.Persistent) error {
		if doc.Generation <= s.Generation {
			return errors.New("stale")
		}
		s.Doc, s.Generation, s.MassRemoval = doc, doc.Generation, confirmed
		return nil
	}); err != nil {
		writeKind(w, http.StatusConflict, "generation", "generation is not greater than the last accepted one")
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

// listCreds is GET /v1/credentials?uuid=: the mail passwords of every
// account carrying that uuid, live or parked (a void's verification must
// see a parked account's too), each row echoing the uuid. 404 when no
// account carries it.
func (v *V1) listCreds(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uuid := q.Get("uuid")
	if len(q) != 1 || len(q["uuid"]) != 1 || !state.ValidUUID(uuid) {
		writeErr(w, http.StatusBadRequest, "GET /v1/credentials takes exactly ?uuid=<account uuid>")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	out := []creds.Info{}
	found := false
	for _, id := range accountsOfUUID(live, uuid) {
		found = true
		list, err := creds.List(ctx, v.C, id, uuid)
		if err != nil {
			v.unreachable(w, err)
			return
		}
		out = append(out, list...)
	}
	if !found {
		writeErr(w, http.StatusNotFound, "no account with that uuid")
		return
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	writeJSON(w, http.StatusOK, out)
}

type createReq struct {
	Username  string     `json:"username"`
	UUID      string     `json:"uuid"`
	Label     string     `json:"label"`
	ExpiresAt *time.Time `json:"expires_at"`
	// AllowedIPs (optional, contract §19.5): absent = from anywhere;
	// present = the networks the credential may submit from (1-64, each a
	// network, never one that amounts to anywhere).
	AllowedIPs []string `json:"allowed_ips"`
}

// MaxAllowedIPs bounds a credential's allowed_ips.
const MaxAllowedIPs = 64

// allowedIPs checks a create's allowed_ips: canonical networks (never
// split or widened), each within state.LocalNetworkOK's bounds.
func allowedIPs(ips []string) ([]string, error) {
	if len(ips) == 0 {
		return nil, errors.New("allowed_ips must name 1-64 networks, or be left out")
	}
	if len(ips) > MaxAllowedIPs {
		return nil, fmt.Errorf("allowed_ips: more than %d networks", MaxAllowedIPs)
	}
	out := make([]string, 0, len(ips))
	for _, n := range ips {
		p, err := netip.ParsePrefix(n)
		if err != nil || p.Masked() != p {
			return nil, fmt.Errorf("allowed_ips: %q is not a network", n)
		}
		if err := state.LocalNetworkOK(p); err != nil {
			return nil, fmt.Errorf("allowed_ips: %s: %w", n, err)
		}
		out = append(out, p.String())
	}
	sort.Strings(out)
	return out, nil
}

// accountsOfUUID: every account (a person's, live or parked, or an app
// mail sender's) carrying uuid.
func accountsOfUUID(live *reconcile.Live, uuid string) []string {
	var ids []string
	for _, la := range live.Accounts {
		if strings.EqualFold(la.UUID, uuid) {
			ids = append(ids, la.ID)
		}
	}
	for _, ls := range live.Senders {
		if strings.EqualFold(ls.UUID, uuid) {
			ids = append(ids, ls.ID)
		}
	}
	return ids
}

// mismatch: the account under this username isn't the person the Hub
// names (another uuid, or the username's account is parked).
func mismatch(live *reconcile.Live, doc *state.Doc, user, uuid string) bool {
	user = strings.ToLower(user)
	a, ok := doc.Account(user)
	if !ok || !strings.EqualFold(a.UUID, uuid) {
		return true
	}
	primary := live.Domains[doc.PrimaryDomain]
	for _, la := range live.Accounts {
		if la.Name == user && la.DomainID == primary && !strings.EqualFold(la.UUID, uuid) {
			return true
		}
		if strings.EqualFold(la.UUID, uuid) && la.Parked(live) {
			return true
		}
	}
	return false
}

func (v *V1) createCred(w http.ResponseWriter, r *http.Request) {
	b, ok := readBody(w, r)
	if !ok {
		return
	}
	var req createReq
	if err := state.NoDuplicateKeys(b); err != nil {
		writeErr(w, http.StatusBadRequest, "the body must be {username, uuid, label, expires_at[, allowed_ips]}")
		return
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil || d.More() {
		writeErr(w, http.StatusBadRequest, "the body must be {username, uuid, label, expires_at[, allowed_ips]}")
		return
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(b, &keys)
	for _, k := range []string{"username", "uuid", "label", "expires_at"} {
		if _, ok := keys[k]; !ok {
			writeErr(w, http.StatusBadRequest, "missing "+k)
			return
		}
	}
	var allowed []string
	raw, ipsGiven := keys["allowed_ips"]
	if ipsGiven {
		var err error
		if string(bytes.TrimSpace(raw)) == "null" {
			err = errors.New("allowed_ips must name 1-64 networks, or be left out")
		} else {
			allowed, err = allowedIPs(req.AllowedIPs)
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
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
	// One snapshot of the document and one live read decide everything
	// (no time-of-check / time-of-use gap), under the runner's pass lock:
	// no pass parks the account between the checks and the create (final
	// review M2). No document yet: refused.
	if v.Runner != nil {
		v.Runner.LockPass()
		defer v.Runner.UnlockPass()
	}
	p := v.Store.Get()
	doc := p.Doc
	if doc == nil {
		writeErr(w, http.StatusServiceUnavailable, "no accepted mail document yet")
		return
	}
	refuse := func() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the account " + strings.ToLower(req.Username) + " belongs to another person", "error_kind": "account_mismatch"})
	}
	if _, sender := doc.Sender(req.Username); sender {
		v.createSenderCred(ctx, w, doc, req, allowed, refuse)
		return
	}
	if _, known := doc.Account(req.Username); !known {
		writeErr(w, http.StatusNotFound, "no such account")
		return
	}
	// A person's mail passwords are the Local networks' under LAN-only
	// (the runner restricts every one of them): another list is refused,
	// never silently replaced.
	if ipsGiven && doc.SubmissionLANOnly {
		writeErr(w, http.StatusBadRequest, "allowed_ips can't be set on a person's mail password while submission is LAN-only")
		return
	}
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	if mismatch(live, doc, req.Username, req.UUID) {
		refuse()
		return
	}
	id := reconcile.FindAccount(live, doc, req.Username)
	if id == "" {
		writeErr(w, http.StatusNotFound, "no such account")
		return
	}
	if v.beforeCreate != nil {
		v.beforeCreate()
	}
	// The resolved account is the person the Hub names.
	resolved := false
	for _, la := range live.Accounts {
		if la.ID == id && strings.EqualFold(la.UUID, req.UUID) && !la.Parked(live) {
			resolved = true
		}
	}
	if !resolved {
		refuse()
		return
	}
	ips := creds.AllowedIPs(doc.SubmissionLANOnly, reconcile.LocalNets(doc, doc.Rewritten()))
	if ipsGiven {
		ips = allowed
	}
	cr, err := creds.Create(ctx, v.C, id, req.Label, req.ExpiresAt, ips, v.now())
	switch {
	case errors.Is(err, creds.ErrLimit):
		writeKind(w, http.StatusConflict, "limit", err.Error())
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

// createSenderCred makes an app mail sender's credential (contract
// §19.14): the sender's permissions only (authenticate, emailSend),
// allowed_ips as asked (absent = anywhere; LAN-only and the client
// address mode govern people's passwords, never a sender's). The caller
// holds the pass lock and the one document snapshot.
func (v *V1) createSenderCred(ctx context.Context, w http.ResponseWriter, doc *state.Doc, req createReq, allowed []string, refuse func()) {
	s, _ := doc.Sender(req.Username)
	if s.UUID != strings.ToLower(req.UUID) {
		refuse()
		return
	}
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	// Another live sender under this name (a uuid the Hub replaced, the
	// pass not run yet): not the sender the Hub names.
	for _, ls := range live.Senders {
		if ls.Name == s.Username && ls.UUID != s.UUID {
			refuse()
			return
		}
	}
	id := reconcile.FindSender(live, doc, s.Username)
	if id == "" {
		writeErr(w, http.StatusNotFound, "no such account (the sender isn't made yet)")
		return
	}
	if v.beforeCreate != nil {
		v.beforeCreate()
	}
	cr, err := creds.CreateWith(ctx, v.C, id, req.Label, req.ExpiresAt, allowed, stalwart.SenderPermissions, v.now())
	switch {
	case errors.Is(err, creds.ErrLimit):
		writeKind(w, http.StatusConflict, "limit", err.Error())
		return
	case err != nil:
		v.unreachable(w, err)
		return
	}
	if v.Logf != nil {
		v.Logf("credentials: created sender credential %s for %s", cr.ID, s.Username)
	}
	writeJSON(w, http.StatusCreated, cr)
}

// deleteCred revokes credential {id} inside the account of ?uuid= (live
// or parked), never the username's current holder. An unknown uuid or id
// is a success: nothing can hold it (the Hub retries).
func (v *V1) deleteCred(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uuid := strings.ToLower(q.Get("uuid"))
	if _, ok := q["user"]; ok || uuid == "" || len(q) != 1 {
		writeErr(w, http.StatusBadRequest, "DELETE /v1/credentials/{id} takes exactly ?uuid=<account uuid>")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	live, err := reconcile.Read(ctx, v.C)
	if err != nil {
		v.unreachable(w, err)
		return
	}
	// Every account with that uuid (final review L9: two can carry it
	// after a hand edit or a half-failed create): the revoke goes to each,
	// and 204 only once it went everywhere.
	accts := accountsOfUUID(live, uuid)
	for _, acct := range accts {
		if err := creds.Revoke(ctx, v.C, acct, r.PathValue("id")); err != nil {
			v.unreachable(w, err)
			return
		}
	}
	if len(accts) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if v.Logf != nil {
		v.Logf("credentials: revoked mail password %s of account %s", r.PathValue("id"), uuid)
	}
	w.WriteHeader(http.StatusNoContent)
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
	st, err := v.M.Status(ctx, v.bootstrapped(ctx))
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
