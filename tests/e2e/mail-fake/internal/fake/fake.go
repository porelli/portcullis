// Package fake is mail-fake's provider API v1 (contract §19.5), adapted
// from portcullis-hub's internal/mailprovider/mailprovidertest (built from
// the contract, not from any provider's code): the bearer secret from the
// slot's api-secret file and the caller's portcullis-mail-api address,
// strict bodies, generation and mass-removal refusals, MailState v2's
// refusals, the 5-password limit, credentials by uuid with allowed_ips,
// the void and the TLS reload, per-account id reuse; plus the hostile
// mode's knobs (hostile.go).
package fake

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/portcullis/mail-fake/internal/mailprovider"
)

// Server is the fake provider.
type Server struct {
	// SecretFile holds the Hub ⇄ provider bearer secret (read at every
	// request); Subnet is portcullis-mail-api: a request addressed outside
	// it is refused (403) like a wrong bearer.
	SecretFile string
	Subnet     netip.Prefix
	// Name is the provider's label (MAIL_FAKE_NAME: two copies apart).
	Name string
	// Hostile: the forbidden DNS set, no mass-removal guard, allowed_ips
	// 0.0.0.0/0 under LAN-only, a void that keeps a credential (hostile.go).
	Hostile bool

	mu sync.Mutex
	// Doc is the last accepted document (nil: none yet); Applied its
	// applied generation. HoldApply: accepted documents aren't applied
	// (GET /v1/state keeps the old applied_generation).
	Doc       *mailprovider.MailState
	Docs      []mailprovider.MailState // every accepted document, in order
	Applied   int
	HoldApply bool
	Bootstrap bool
	// Down: every request answers 503 "mail server unreachable".
	Down bool
	// PutErr: PUT /v1/state answers it (status, message) instead.
	PutStatus int
	PutMsg    string
	// DNSSets: domain → its wanted records (default: one MX).
	DNSSets  map[string]mailprovider.DNSSet
	ChecksV  mailprovider.Checks
	StatusV  mailprovider.Status
	ActionV  map[string]int // action name → status (default 202)
	Actions  []string       // "<name> <domain>"
	Requests []string       // "<METHOD> <path>"
	// Wildcards: domain → the last ?wildcard= of GET /v1/dns/{domain}.
	Wildcards map[string]string
	// creds: username → its live passwords; nextNow the clock.
	creds map[string][]fakeCred
	Now   func() time.Time
	// stateFile: the store's file (persist.go; "" = memory only); kept:
	// the credential a hostile void kept (nil: none).
	stateFile string
	kept      *keptCred
	// Created: every secret handed out (tests grep logs and state for them).
	Created []string
	// RevokeStatus: DELETE /v1/credentials answers it instead (0: 204).
	RevokeStatus int
	// Deletes: every DELETE /v1/credentials ("<uuid> <id>").
	Deletes []string
	// OmitRemoved: the mass-removal 409 carries no "removed" list.
	OmitRemoved bool
	// RevokeOK: DELETE answers 200 instead of 204 (a non-204 success).
	RevokeOK bool
	// ProviderV is GET /v1/provider's answer.
	ProviderV mailprovider.ProviderInfo
	// VoidStatus: POST /v1/void answers it instead (0: 200). VoidKeeps:
	// the void answers 200 but destroys nothing (a hostile provider).
	VoidStatus int
	VoidKeeps  bool
	// Voids: every POST /v1/void reason, in order.
	Voids []string
	// Reloads: every POST /v1/tls/reload's SPKIs; ServingSPKI the
	// answer (default: the first one asked for).
	Reloads     [][]string
	ServingSPKI string
	// Tests: every POST /v1/actions/test recipient.
	Tests []string
	// AllowedIPs, when set, replaces every credential row's allowed_ips
	// (a provider that doesn't enforce LAN-only).
	AllowedIPs []netip.Prefix
	// NoMassGuard: the provider has no mass-removal guard (a hostile or
	// buggy one): every document is accepted.
	NoMassGuard bool
}

type fakeCred struct {
	mailprovider.Credential
}

// New is a fake provider (honest, bootstrapped) named name.
func New(secretFile string, subnet netip.Prefix, name string) *Server {
	s := &Server{SecretFile: secretFile, Subnet: subnet, Name: name, Bootstrap: true, DNSSets: map[string]mailprovider.DNSSet{}, ActionV: map[string]int{}, creds: map[string][]fakeCred{},
		Now: func() time.Time { return time.Now().UTC().Truncate(time.Second) }}
	s.ProviderV = mailprovider.ProviderInfo{Name: name, Version: "1.0", APIVersion: 1,
		Checks:  []string{"port25", "fcrdns_v4", "cert", "records:", "dkim_stuck:"},
		Actions: []string{mailprovider.ActionDKIMRotate, mailprovider.ActionDMARCPromote, mailprovider.ActionMTASTSEnforce, mailprovider.ActionTest}}
	s.ChecksV = mailprovider.Checks{CheckedAt: s.Now(), Checks: []mailprovider.Check{}}
	s.StatusV = mailprovider.Status{Bootstrap: true, Provider: mailprovider.StatusProvider{Name: name, Version: "1.0"}, DKIM: []mailprovider.StatusDKIM{},
		MTASTS: []mailprovider.StatusMTASTS{}, DMARC: []mailprovider.StatusDMARC{}, Former: []mailprovider.StatusFormer{}, Cert: mailprovider.StatusCert{SANs: []string{}}}
	return s
}

// Handler is the v1 API behind the address and bearer guard.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.guard) }

// Lock runs f under the fake's lock (the mode switch changes knobs).
func (s *Server) Lock(f func(s *Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// Creds are user's live passwords.
func (s *Server) Creds(user string) []mailprovider.Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []mailprovider.Credential
	for _, c := range s.creds[user] {
		out = append(out, c.Credential)
	}
	return out
}

func localAddr(r *http.Request) (netip.Addr, bool) {
	a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return netip.Addr{}, false
	}
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	return ip.Unmap(), ok
}

// guard: addressed inside portcullis-mail-api, exactly one bearer equal to
// the slot's secret (≥ 32 characters); else 403 with an empty body.
func (s *Server) guard(w http.ResponseWriter, r *http.Request) {
	ip, ok := localAddr(r)
	if !ok || !s.Subnet.Contains(ip) {
		w.WriteHeader(403)
		return
	}
	b, err := os.ReadFile(s.SecretFile)
	sec := strings.TrimSpace(string(b))
	if err != nil || len(sec) < 32 || len(r.Header.Values("Authorization")) != 1 ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+sec)) != 1 {
		w.WriteHeader(403)
		return
	}
	s.serve(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, format string, a ...any) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf(format, a...)})
}

func strict(r *http.Request, v any) error {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 4<<20)); err != nil {
		return err
	}
	dec := json.NewDecoder(&buf)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method != http.MethodGet {
		defer s.saveLocked() // under the lock (deferred calls run last first)
	}
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path)
	if s.Down {
		errJSON(w, 503, "mail server unreachable")
		return
	}
	if !s.Bootstrap && r.URL.Path != "/v1/provider" && r.URL.Path != "/v1/state" {
		errJSON(w, 503, "the mail server isn't ready")
		return
	}
	switch p := r.URL.Path; {
	case p == "/v1/provider" && r.Method == http.MethodGet:
		writeJSON(w, 200, s.ProviderV)
	case p == "/v1/void" && r.Method == http.MethodPost:
		s.void(w, r)
	case p == "/v1/tls/reload" && r.Method == http.MethodPost:
		var body struct {
			SPKI []string `json:"spki_sha256"`
		}
		if err := strict(r, &body); err != nil || len(body.SPKI) < 1 || len(body.SPKI) > 2 {
			errJSON(w, 400, "bad body")
			return
		}
		s.Reloads = append(s.Reloads, body.SPKI)
		serving := s.ServingSPKI
		if serving == "" {
			serving = body.SPKI[0]
		}
		writeJSON(w, 200, map[string]string{"serving_spki_sha256": serving})
	case p == "/v1/actions/test" && r.Method == http.MethodPost:
		var body struct {
			To string `json:"to"`
		}
		if err := strict(r, &body); err != nil || !strings.Contains(body.To, "@") {
			errJSON(w, 400, "to isn't one address")
			return
		}
		if s.Doc == nil || len(s.Doc.Postmaster) == 0 {
			errJSON(w, 409, "no postmaster account")
			return
		}
		s.Tests = append(s.Tests, body.To)
		writeJSON(w, 202, map[string]string{"queue_id": fmt.Sprintf("q%d", len(s.Tests))})
	case p == "/v1/state" && r.Method == http.MethodPut:
		s.putState(w, r)
	case p == "/v1/state" && r.Method == http.MethodGet:
		gen := 0
		if s.Doc != nil {
			gen = s.Doc.Generation
		}
		writeJSON(w, 200, mailprovider.StateStatus{Generation: gen, AppliedGeneration: s.Applied, Bootstrap: s.Bootstrap, Errors: []string{}})
	case strings.HasPrefix(p, "/v1/dns/") && r.Method == http.MethodGet:
		d := strings.TrimPrefix(p, "/v1/dns/")
		wc := r.URL.Query().Get("wildcard")
		if wc != "true" && wc != "false" {
			errJSON(w, 400, "wildcard must be true or false")
			return
		}
		if s.Wildcards == nil {
			s.Wildcards = map[string]string{}
		}
		s.Wildcards[d] = wc
		if !s.mailDomain(d) {
			errJSON(w, 404, "%s is not a mail domain", d)
			return
		}
		set, ok := s.DNSSets[d]
		if s.Hostile {
			set, ok = hostileSet(d, s.Doc.MailHostname), true
		}
		if !ok && s.draining(d) {
			// A draining domain's set: only its _mta-sts record (§19.7).
			set, ok = mailprovider.DNSSet{Domain: d, DKIM: "auto", Records: []mailprovider.Record{{Name: "_mta-sts." + d, Type: "TXT", TTL: 3600, Value: "v=STSv1; id=fakedrain1"}}}, true
		}
		if !ok {
			set = honestSet(d, s.Doc.MailHostname)
		}
		writeJSON(w, 200, set)
	case p == "/v1/checks" && r.Method == http.MethodGet:
		writeJSON(w, 200, s.ChecksV)
	case p == "/v1/status" && r.Method == http.MethodGet:
		writeJSON(w, 200, s.StatusV)
	case p == "/v1/credentials" && r.Method == http.MethodGet:
		q := r.URL.Query()
		if len(q) != 1 || q.Get("uuid") == "" {
			errJSON(w, 400, "the query must be exactly ?uuid=")
			return
		}
		u := s.userOfUUID(q.Get("uuid"))
		if u == "" {
			errJSON(w, 404, "no account with that uuid")
			return
		}
		out := []mailprovider.Credential{}
		for _, c := range s.creds[u] {
			out = append(out, s.row(c.Credential))
		}
		writeJSON(w, 200, out)
	case p == "/v1/credentials" && r.Method == http.MethodPost:
		s.createCred(w, r)
	case strings.HasPrefix(p, "/v1/credentials/") && r.Method == http.MethodDelete:
		q := r.URL.Query()
		if len(q) != 1 || q.Get("uuid") == "" {
			errJSON(w, 400, "the query must be exactly ?uuid=")
			return
		}
		s.Deletes = append(s.Deletes, q.Get("uuid")+" "+strings.TrimPrefix(p, "/v1/credentials/"))
		u := s.userOfUUID(q.Get("uuid"))
		if u == "" {
			w.WriteHeader(204) // unknown (or parked) account: nothing here
			return
		}
		if s.RevokeStatus != 0 {
			errJSON(w, s.RevokeStatus, "mail server unreachable")
			return
		}
		if s.RevokeOK {
			w.WriteHeader(200)
			return
		}
		id := strings.TrimPrefix(p, "/v1/credentials/")
		if s.Hostile && s.kept != nil && s.kept.User == u && s.kept.ID == id {
			// The credential the hostile void kept: "revoked", still there.
			w.WriteHeader(204)
			return
		}
		keep := s.creds[u][:0]
		for _, c := range s.creds[u] {
			if c.ID != id {
				keep = append(keep, c)
			}
		}
		s.creds[u] = keep
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/v1/actions/") && r.Method == http.MethodPost:
		name := strings.TrimPrefix(p, "/v1/actions/")
		var body struct {
			Domain string `json:"domain"`
		}
		if err := strict(r, &body); err != nil {
			errJSON(w, 400, "bad body")
			return
		}
		if !s.mailDomain(body.Domain) {
			errJSON(w, 404, "%s is not a mail domain", body.Domain)
			return
		}
		s.Actions = append(s.Actions, name+" "+body.Domain)
		if st := s.ActionV[name]; st != 0 && st != 202 {
			errJSON(w, st, "nothing to do")
			return
		}
		w.WriteHeader(202)
	default:
		errJSON(w, 404, "not found")
	}
}

// row is c as GET /v1/credentials answers it: allowed_ips is the Local
// networks under LAN-only, else [] (AllowedIPs overrides).
func (s *Server) row(c mailprovider.Credential) mailprovider.Credential {
	c.AllowedIPs = []netip.Prefix{}
	if s.Hostile && s.Doc != nil && s.Doc.SubmissionLANOnly {
		c.AllowedIPs = append(c.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
	} else if s.AllowedIPs != nil {
		c.AllowedIPs = append(c.AllowedIPs, s.AllowedIPs...)
	} else if s.Doc != nil && s.Doc.SubmissionLANOnly {
		for _, n := range s.Doc.LocalNetworks {
			if p, err := netip.ParsePrefix(n); err == nil {
				c.AllowedIPs = append(c.AllowedIPs, p.Masked())
			}
		}
		if len(c.AllowedIPs) == 0 {
			c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
		}
	}
	return c
}

// void is POST /v1/void: every credential of every account destroyed
// (unless VoidKeeps), restored_at recorded.
func (s *Server) void(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Reason string `json:"reason"`
	}
	if err := strict(r, &body); err != nil || (body.Reason != mailprovider.VoidWire && body.Reason != mailprovider.VoidRestore) {
		errJSON(w, 400, "bad body")
		return
	}
	s.Voids = append(s.Voids, body.Reason)
	if s.VoidStatus != 0 {
		errJSON(w, s.VoidStatus, "void failed")
		return
	}
	n := 0
	for _, cs := range s.creds {
		n += len(cs)
	}
	switch {
	case s.Hostile:
		// Keeps one credential (the first account's first password), and
		// keeps it through the Hub's DELETE of it too (a provider that lies).
		for u, cs := range s.creds {
			if len(cs) > 0 {
				s.creds = map[string][]fakeCred{u: cs[:1]}
				s.kept = &keptCred{User: u, ID: cs[0].ID}
				break
			}
		}
	case !s.VoidKeeps:
		s.creds = map[string][]fakeCred{}
		s.kept = nil
	}
	now := s.Now()
	s.StatusV.RestoredAt = &now
	writeJSON(w, 200, map[string]any{"voided": n, "restored_at": now})
}

// draining: d is draining in the applied document.
func (s *Server) draining(d string) bool {
	if s.Doc == nil {
		return false
	}
	for _, x := range s.Doc.Domains {
		if x.Name == d {
			return x.Mail == mailprovider.MailDraining
		}
	}
	return false
}

func (s *Server) mailDomain(d string) bool {
	if s.Doc == nil {
		return false
	}
	for _, x := range s.Doc.Domains {
		if x.Name == d {
			return true
		}
	}
	return false
}

// userOfUUID is the username of the account with uuid ("" = none).
func (s *Server) userOfUUID(uuid string) string {
	if s.Doc == nil {
		return ""
	}
	for _, a := range s.Doc.Accounts {
		if a.UUID == uuid {
			return a.Username
		}
	}
	return ""
}

// uuidOf is u's uuid in the applied document ("" = none).
func (s *Server) uuidOf(u string) string {
	if s.Doc == nil {
		return ""
	}
	for _, a := range s.Doc.Accounts {
		if a.Username == u {
			return a.UUID
		}
	}
	return ""
}

func (s *Server) account(u string) bool {
	if s.Doc == nil {
		return false
	}
	for _, a := range s.Doc.Accounts {
		if a.Username == u {
			return true
		}
	}
	return false
}

var (
	usernameRe = regexp.MustCompile(`^[a-z0-9_.@-]{1,64}$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	spkiRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// parse is state.Parse's refusals (contract §19.5).
func parse(d *mailprovider.MailState) error {
	if d.Version != mailprovider.StateVersion {
		return fmt.Errorf("version %d", d.Version)
	}
	if d.MailHostname == "" || (d.ClientIP != mailprovider.ClientIPPreserved && d.ClientIP != mailprovider.ClientIPRewritten) {
		return fmt.Errorf("mail_hostname or client_ip")
	}
	for _, v := range []string{d.DKIMRotate, d.FormerRetention} {
		if dur, err := time.ParseDuration(v); err != nil || dur < 24*time.Hour || dur > 8760*time.Hour {
			return fmt.Errorf("duration %q", v)
		}
	}
	if r := d.Relay; r != nil && (r.Host == "" || r.Port < 1 || r.Port > 65535) {
		return fmt.Errorf("relay")
	}
	if d.TLS.SPKISHA256 == nil || len(d.TLS.SPKISHA256) > 2 {
		return fmt.Errorf("tls.spki_sha256")
	}
	for _, k := range d.TLS.SPKISHA256 {
		if !spkiRe.MatchString(k) {
			return fmt.Errorf("spki %q", k)
		}
	}
	doms := map[string]bool{}
	for _, x := range d.Domains {
		if x.Mail != mailprovider.MailOn && x.Mail != mailprovider.MailOff && x.Mail != mailprovider.MailDraining {
			return fmt.Errorf("domain %s: mail %q", x.Name, x.Mail)
		}
		if x.DMARCStart != "reject" && x.DMARCStart != "none" {
			return fmt.Errorf("domain %s: dmarc_start %q", x.Name, x.DMARCStart)
		}
		if x.DMARCFloor != "none" && x.DMARCFloor != "quarantine" && x.DMARCFloor != "reject" {
			return fmt.Errorf("domain %s: dmarc_floor %q", x.Name, x.DMARCFloor)
		}
		doms[x.Name] = true
	}
	if !doms[d.PrimaryDomain] {
		return fmt.Errorf("primary domain %s not in domains", d.PrimaryDomain)
	}
	used := map[string]string{}
	use := func(addr, owner string) error {
		local, dom, ok := strings.Cut(addr, "@")
		if !ok || !doms[dom] {
			return fmt.Errorf("address %s is not on a mail domain", addr)
		}
		for _, r := range mailprovider.ReservedLocalParts {
			if local == r {
				return fmt.Errorf("address %s is reserved", addr)
			}
		}
		if o, ok := used[addr]; ok {
			return fmt.Errorf("address %s used by %s and %s", addr, o, owner)
		}
		used[addr] = owner
		return nil
	}
	accts := map[string]bool{}
	for _, a := range d.Accounts {
		if !usernameRe.MatchString(a.Username) || !uuidRe.MatchString(a.UUID) || a.QuotaBytes < 0 || len(a.Addresses) == 0 {
			return fmt.Errorf("account %q", a.Username)
		}
		if a.Addresses[0] != a.Username+"@"+d.PrimaryDomain {
			return fmt.Errorf("account %s: first address %s", a.Username, a.Addresses[0])
		}
		accts[a.Username] = true
		for _, x := range a.Addresses {
			if err := use(x, a.Username); err != nil {
				return err
			}
		}
	}
	for _, x := range d.Aliases {
		if !accts[x.Username] {
			return fmt.Errorf("alias %s: %s is no account", x.Address, x.Username)
		}
		if err := use(x.Address, "alias of "+x.Username); err != nil {
			return err
		}
	}
	for _, l := range d.Lists {
		if l.Posting != "members" && l.Posting != "anyone" {
			return fmt.Errorf("list %s: posting %q", l.Address, l.Posting)
		}
		for _, m := range l.Members {
			if !accts[m] {
				return fmt.Errorf("list %s: %s is no account", l.Address, m)
			}
		}
		if err := use(l.Address, "list"); err != nil {
			return err
		}
	}
	for _, p := range d.Postmaster {
		if !accts[p] {
			return fmt.Errorf("postmaster %s is no account", p)
		}
	}
	if d.Limits.RecipientsPerHour < 1 || d.Limits.RecipientsPerHour > 100000 || d.Limits.RecipientsPerDay < 1 || d.Limits.RecipientsPerDay > 100000 {
		return fmt.Errorf("limits")
	}
	if d.Spam.JunkScore < 1 || d.Spam.JunkScore >= d.Spam.RejectScore || d.Spam.RejectScore > 100 {
		return fmt.Errorf("scores")
	}
	if d.Aliases == nil || d.Lists == nil || d.Postmaster == nil || d.LocalNetworks == nil || d.Domains == nil || d.Accounts == nil || d.Spam.Allow == nil || d.Spam.Block == nil {
		return fmt.Errorf("missing key")
	}
	return nil
}

func (s *Server) putState(w http.ResponseWriter, r *http.Request) {
	// Every key present: decode into raw first.
	var raw map[string]json.RawMessage
	body := new(bytes.Buffer)
	body.ReadFrom(r.Body)
	if err := json.Unmarshal(body.Bytes(), &raw); err != nil {
		errJSON(w, 400, "not JSON")
		return
	}
	for _, k := range []string{"version", "generation", "primary_domain", "mail_hostname", "client_ip", "submission_lan_only", "dkim_rotate", "former_retention", "relay", "tls", "confirm_mass_removal", "domains", "accounts", "aliases", "lists", "postmaster", "limits", "spam", "local_networks"} {
		if _, ok := raw[k]; !ok {
			errJSON(w, 400, "missing key %s", k)
			return
		}
	}
	var d mailprovider.MailState
	dec := json.NewDecoder(bytes.NewReader(body.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		errJSON(w, 400, "bad document: %v", err)
		return
	}
	if s.PutStatus != 0 {
		errJSON(w, s.PutStatus, "%s", s.PutMsg)
		return
	}
	if err := parse(&d); err != nil {
		errJSON(w, 400, "%v", err)
		return
	}
	if s.Doc != nil && d.Generation <= s.Doc.Generation {
		writeJSON(w, 409, map[string]string{"error": fmt.Sprintf("generation %d is not greater than %d", d.Generation, s.Doc.Generation), "error_kind": "generation"})
		return
	}
	if s.Doc != nil && len(s.Doc.Accounts) > 0 && !s.NoMassGuard && !s.Hostile {
		now := map[string]bool{}
		for _, a := range d.Accounts {
			now[a.UUID] = true
		}
		gone := 0
		removed := []map[string]string{}
		for _, a := range s.Doc.Accounts {
			if !now[a.UUID] {
				gone++
				removed = append(removed, map[string]string{"username": a.Username, "uuid": a.UUID})
			}
		}
		if gone*2 > len(s.Doc.Accounts) && !d.ConfirmMassRemoval {
			body := map[string]any{"error": fmt.Sprintf("mass removal: %d of %d accounts", gone, len(s.Doc.Accounts)), "error_kind": "mass_removal"}
			if !s.OmitRemoved {
				body["removed"] = removed
			}
			writeJSON(w, 409, body)
			return
		}
	}
	// A removed account loses every password first (M4).
	keep := map[string]bool{}
	for _, a := range d.Accounts {
		keep[a.Username] = true
	}
	for u := range s.creds {
		if !keep[u] {
			delete(s.creds, u)
		}
	}
	s.Doc = &d
	s.Docs = append(s.Docs, d)
	if !s.HoldApply {
		s.Applied = d.Generation
	}
	writeJSON(w, 202, map[string]int{"generation": d.Generation})
}

// Apply marks the last document applied (after HoldApply).
func (s *Server) Apply() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Doc != nil {
		s.Applied = s.Doc.Generation
	}
}

func (s *Server) createCred(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username  string     `json:"username"`
		UUID      string     `json:"uuid"`
		Label     string     `json:"label"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := strict(r, &body); err != nil {
		errJSON(w, 400, "bad body")
		return
	}
	now := s.Now()
	if n := len([]rune(body.Label)); n < 1 || n > 64 || strings.ContainsAny(body.Label, "\r\n") {
		errJSON(w, 400, "label must be 1–64 characters on one line")
		return
	}
	if body.ExpiresAt != nil && !body.ExpiresAt.After(now) {
		errJSON(w, 400, "expires_at is in the past")
		return
	}
	if !s.account(body.Username) {
		errJSON(w, 404, "no such account")
		return
	}
	if body.UUID != s.uuidOf(body.Username) {
		writeJSON(w, 409, map[string]string{"error": "the account has another uuid", "error_kind": "account_mismatch"})
		return
	}
	cs := s.creds[body.Username]
	if len(cs) >= mailprovider.MaxActivePasswords {
		writeJSON(w, 409, map[string]string{"error": "5 active mail passwords", "error_kind": "limit"})
		return
	}
	// Ids are reused: the next id is the highest + 1 (reused once the highest
	// is destroyed).
	next := 1
	for _, c := range cs {
		if n, _ := strconv.Atoi(c.ID); n >= next {
			next = n + 1
		}
	}
	sec := fmt.Sprintf("mailpw-%s-%d-%d", body.Username, next, now.UnixNano())
	c := fakeCred{mailprovider.Credential{ID: strconv.Itoa(next), UUID: body.UUID, Label: body.Label, CreatedAt: now, ExpiresAt: body.ExpiresAt}}
	s.creds[body.Username] = append(cs, c)
	sort.Slice(s.creds[body.Username], func(i, j int) bool { return s.creds[body.Username][i].ID < s.creds[body.Username][j].ID })
	s.Created = append(s.Created, sec)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, map[string]any{"id": c.ID, "secret": sec, "created_at": now, "expires_at": body.ExpiresAt})
}
