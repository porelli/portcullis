// Package config reads the files the Hub writes for the gate (integration
// contract §4.2, §15.4): mcp-gate.json (resources, populations, limits),
// mcp-credentials.json (per-person app credentials and caller secrets,
// age-encrypted to the gate) and user-attributes.json (§4.1).
//
// Both gate files are decoded strictly: an unknown, duplicate, missing or
// null field, trailing data, another version or a value outside its rule
// refuses the whole file. A refused file makes the gate refuse every
// request; the last good configuration is never kept.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Names of the files in the Hub's data directory.
const (
	GateFile  = "mcp-gate.json"
	CredsFile = "mcp-credentials.json"
	AttrsFile = "user-attributes.json"
)

// SupportedProtocols are the MCP versions the gate speaks (§15.3).
var SupportedProtocols = []string{"2025-06-18", "2025-11-25", "2026-07-28"}

// Resource kinds (§15.1).
const (
	KindCompanion = "companion"
	KindAggregate = "aggregate"
	KindAdmin     = "portcullis_admin"
	KindPeople    = "portcullis_people"
)

// Fixed limits of this release (§15.4).
const (
	FixedMaxRequestBytes  = 8388608
	FixedMaxResultBytes   = 16777216
	FixedUpstreamTimeoutS = 120
	// MaxFanout: the aggregate calls at most this many upstreams in
	// parallel per request (§15.9); a larger limits.fanout refuses the file.
	MaxFanout = 4
)

// File is mcp-gate.json (§15.4). Field order is the file's key order.
type File struct {
	Version        int            `json:"version"`
	Enabled        bool           `json:"enabled"`
	Issuer         string         `json:"issuer"`
	MainDomain     string         `json:"main_domain"`
	Clients        []string       `json:"clients"`
	AllowedOrigins []string       `json:"allowed_origins"`
	ACRLoA         map[string]int `json:"acr_loa"`
	Limits         Limits         `json:"limits"`
	CoreHosts      []string       `json:"core_hosts"`
	Resources      []Resource     `json:"resources"`

	index map[string]*Resource // host + path → resource
}

// Limits (§15.9). All positive.
type Limits struct {
	ResourceRPM          int   `json:"resource_rpm"`
	ResourceBurst        int   `json:"resource_burst"`
	PersonRPM            int   `json:"person_rpm"`
	ToolCallsRPM         int   `json:"tool_calls_rpm"`
	ConfirmationsPerHour int   `json:"confirmations_per_hour"`
	MintsPerMinute       int   `json:"mints_per_minute"`
	Fanout               int   `json:"fanout"`
	MaxRequestBytes      int64 `json:"max_request_bytes"`
	MaxResultBytes       int64 `json:"max_result_bytes"`
	UpstreamTimeoutS     int   `json:"upstream_timeout_s"`
}

// Resource is one OAuth protected resource (§15.1, §15.4).
type Resource struct {
	URL        string            `json:"url"`
	Scope      string            `json:"scope"`
	Clients    []string          `json:"clients"`
	Kind       string            `json:"kind"`
	Instance   string            `json:"instance"`
	Companion  string            `json:"companion"`
	Label      string            `json:"label"`
	Host       string            `json:"host"`
	Hosts      []string          `json:"hosts"`
	AppURL     string            `json:"app_url"`
	MinLoA     int               `json:"min_loa"`
	Upstream   string            `json:"upstream"`
	Protocol   []string          `json:"protocol"`
	Mode       string            `json:"mode"`
	Identity   Identity          `json:"identity"`
	Tools      Tools             `json:"tools"`
	Aggregate  bool              `json:"aggregate"`
	Population []string          `json:"population"`
	Expiring   map[string]Time   `json:"expiring"`
	People     map[string]Person `json:"people,omitempty"`

	path string
	pop  map[string]struct{}
}

// Identity is how the gate presents the person upstream (§15.5).
type Identity struct {
	Mode      string `json:"mode"`
	Header    string `json:"header"`
	Format    string `json:"format"`
	BasicUser string `json:"basic_user"`
	SecretRef string `json:"secret_ref"`
}

// Tools are the template's tool patterns (§3.2), in the template's order.
type Tools struct {
	Writes  []string `json:"writes"`
	Confirm []string `json:"confirm"`
	Never   []string `json:"never"`
}

// Person is what an identity_headers companion learns about a member.
type Person struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

// CredFile is mcp-credentials.json (§15.4).
type CredFile struct {
	Version       int           `json:"version"`
	Credentials   []CredEntry   `json:"credentials"`
	CallerSecrets []SecretEntry `json:"caller_secrets"`
}

// CredEntry is one per-person credential; Age is the armored ciphertext.
type CredEntry struct {
	Instance  string `json:"instance"`
	Companion string `json:"companion"`
	User      string `json:"user"`
	ID        string `json:"id"`
	MintedAt  Time   `json:"minted_at"`
	State     string `json:"state"`
	Age       string `json:"age"`
}

// SecretEntry is one identity_headers companion's caller secret.
type SecretEntry struct {
	Ref string `json:"ref"`
	Age string `json:"age"`
}

// Time is an RFC 3339 UTC ("Z") timestamp.
type Time struct{ time.Time }

// UnmarshalJSON accepts only RFC 3339 strings in UTC.
func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("not a timestamp string")
	}
	if !strings.HasSuffix(s, "Z") {
		return fmt.Errorf("timestamp not in UTC")
	}
	tt, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return fmt.Errorf("not an RFC 3339 timestamp")
	}
	t.Time = tt.UTC()
	return nil
}

// DecodeFile decodes and validates mcp-gate.json strictly.
func DecodeFile(b []byte) (*File, error) {
	var f File
	if err := decodeStrict(b, &f); err != nil {
		return nil, err
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// Encode writes the file in the Hub's form (§15.4): Go's indented JSON,
// two spaces, a trailing newline.
func (f *File) Encode() ([]byte, error) { return encode(f) }

// DecodeCredFile decodes and validates mcp-credentials.json strictly. Its
// errors name fields and entry indexes, never values.
func DecodeCredFile(b []byte) (*CredFile, error) {
	var c CredFile
	if err := decodeStrict(b, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Encode writes the file in the Hub's form.
func (c *CredFile) Encode() ([]byte, error) { return encode(c) }

func encode(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// decodeStrict: valid JSON with no trailing data, exactly the struct's
// keys (case-sensitive, no duplicates, none missing unless omitempty, no
// null), then the typed decode.
func decodeStrict(b []byte, v any) error {
	if !json.Valid(b) {
		// Never echo the content (the credentials file holds ciphertexts).
		return fmt.Errorf("not valid JSON (or trailing data)")
	}
	if err := checkShape(b, typeOf(v), "$"); err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		if te, ok := err.(*json.UnmarshalTypeError); ok {
			return fmt.Errorf("%s: wrong type", te.Field)
		}
		return fmt.Errorf("does not decode")
	}
	return nil
}

var (
	hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	idShape   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	credID    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	headerTok = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)
	upstreamR = regexp.MustCompile(`^http://portcullis-mcp-([a-z0-9-]+)--([a-z0-9-]+):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)$`)
	originR   = regexp.MustCompile(`^https://([^/:]+)(:[0-9]{1,5})?$`)
)

// ValidHostname: a lowercase DNS name without a trailing dot.
func ValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// NormalizeHost lowercases a request host, strips a numeric :<port> and
// trailing dots (§15.2). Anything else that isn't a hostname gives "".
func NormalizeHost(h string) string {
	h = strings.ToLower(h)
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		port := h[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return ""
		}
		h = h[:i]
	}
	h = strings.TrimRight(h, ".")
	if !ValidHostname(h) {
		return ""
	}
	return h
}

func sortedUnique(list []string, what string, valid func(string) bool) error {
	for i, s := range list {
		if valid != nil && !valid(s) {
			return fmt.Errorf("%s[%d]: invalid value", what, i)
		}
		if i > 0 && list[i-1] >= s {
			return fmt.Errorf("%s: not sorted or not unique", what)
		}
	}
	return nil
}

func nonEmpty(s string) bool { return s != "" && strings.TrimSpace(s) == s && !hasControl(s) }

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// usernameR is exactly the Hub's lldap.ValidUsername (hub
// internal/lldap/validate.go): lowercase ASCII. Matching after
// lowercasing alone isn't enough: strings.ToLower maps non-ASCII letters
// (the Kelvin sign U+212A) onto ASCII ones, so tokens are also checked
// before lowercasing (authz).
var usernameR = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidUsername: a lowercase ASCII username (the population's form).
func ValidUsername(s string) bool { return usernameR.MatchString(s) }

func validUser(s string) bool { return ValidUsername(s) }

// Clients that may never use an MCP resource (§15.2).
var forbiddenClients = []string{"portcullis-forward-auth", "portcullis-fresh-auth"}

// Header names the identity mode may never set: the gate controls them,
// or they carry identity the person's client must not choose.
func forbiddenHeader(h string) bool {
	l := strings.ToLower(h)
	switch l {
	case "host", "cookie", "content-length", "transfer-encoding", "connection", "te", "upgrade", "content-type", "accept":
		return true
	}
	for _, p := range []string{"x-forwarded-", "x-auth-request-", "remote-", "x-portcullis-", "mcp-"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

func (f *File) validate() error {
	if f.Version != 1 {
		return fmt.Errorf("version: not 1")
	}
	if !ValidHostname(f.MainDomain) {
		return fmt.Errorf("main_domain: invalid")
	}
	if f.Issuer != "https://auth."+f.MainDomain+"/realms/portcullis" {
		return fmt.Errorf("issuer: not https://auth.<main_domain>/realms/portcullis")
	}
	if err := sortedUnique(f.Clients, "clients", nonEmpty); err != nil {
		return err
	}
	for _, c := range forbiddenClients {
		if slices.Contains(f.Clients, c) {
			return fmt.Errorf("clients: %s may never use an MCP resource", c)
		}
	}
	if err := sortedUnique(f.AllowedOrigins, "allowed_origins", func(s string) bool {
		m := originR.FindStringSubmatch(s)
		return m != nil && ValidHostname(m[1]) && validPort(strings.TrimPrefix(m[2], ":"), m[2] == "")
	}); err != nil {
		return err
	}
	for k, v := range f.ACRLoA {
		if !nonEmpty(k) || v < 0 || v > 3 {
			return fmt.Errorf("acr_loa: invalid entry")
		}
	}
	l := f.Limits
	for name, v := range map[string]int64{
		"resource_rpm": int64(l.ResourceRPM), "resource_burst": int64(l.ResourceBurst), "person_rpm": int64(l.PersonRPM),
		"tool_calls_rpm": int64(l.ToolCallsRPM), "confirmations_per_hour": int64(l.ConfirmationsPerHour),
		"mints_per_minute": int64(l.MintsPerMinute), "fanout": int64(l.Fanout),
	} {
		if v <= 0 {
			return fmt.Errorf("limits.%s: not positive", name)
		}
	}
	if l.Fanout > MaxFanout {
		return fmt.Errorf("limits.fanout: at most %d", MaxFanout)
	}
	if l.MaxRequestBytes != FixedMaxRequestBytes || l.MaxResultBytes != FixedMaxResultBytes || l.UpstreamTimeoutS != FixedUpstreamTimeoutS {
		return fmt.Errorf("limits: max_request_bytes, max_result_bytes and upstream_timeout_s are fixed in this release")
	}
	if err := sortedUnique(f.CoreHosts, "core_hosts", ValidHostname); err != nil {
		return err
	}
	f.index = map[string]*Resource{}
	kinds := map[string]int{}
	for i := range f.Resources {
		r := &f.Resources[i]
		if i > 0 && f.Resources[i-1].URL >= r.URL {
			return fmt.Errorf("resources: not sorted by url or not unique")
		}
		if err := r.validate(f); err != nil {
			return fmt.Errorf("resources[%d]: %w", i, err)
		}
		key := r.Host + r.path
		if f.index[key] != nil {
			return fmt.Errorf("resources[%d]: a second resource on %s", i, r.URL)
		}
		f.index[key] = r
		kinds[r.Kind]++
		if r.Kind != KindCompanion && kinds[r.Kind] > 1 {
			return fmt.Errorf("resources[%d]: a second %s resource", i, r.Kind)
		}
	}
	return nil
}

func validPort(p string, empty bool) bool {
	if empty {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == p
}

func (r *Resource) validate(f *File) error {
	if !ValidHostname(r.Host) {
		return fmt.Errorf("host: invalid")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host != r.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.RawPath != "" || !strings.HasPrefix(u.Path, "/") || r.URL != "https://"+r.Host+u.Path {
		return fmt.Errorf("url: not https://<host><path>")
	}
	r.path = u.Path
	if !nonEmpty(r.Label) {
		return fmt.Errorf("label: empty")
	}
	if err := sortedUnique(r.Clients, "clients", func(c string) bool { return slices.Contains(f.Clients, c) }); err != nil {
		return fmt.Errorf("%w (each client must be in the top-level clients)", err)
	}
	if err := sortedUnique(r.Population, "population", validUser); err != nil {
		return err
	}
	r.pop = make(map[string]struct{}, len(r.Population))
	for _, p := range r.Population {
		r.pop[p] = struct{}{}
	}
	for u := range r.Expiring {
		if _, ok := r.pop[u]; !ok {
			return fmt.Errorf("expiring: a user outside the population")
		}
	}
	for _, list := range [][]string{r.Tools.Writes, r.Tools.Confirm, r.Tools.Never} {
		for _, p := range list {
			if !nonEmpty(p) {
				return fmt.Errorf("tools: an empty pattern")
			}
		}
	}
	if r.People != nil && r.Identity.Mode != "identity_headers" {
		return fmt.Errorf("people: only for identity_headers companions")
	}
	for u, p := range r.People {
		if _, ok := r.pop[u]; !ok {
			return fmt.Errorf("people: a user outside the population")
		}
		if hasControl(p.Email) {
			return fmt.Errorf("people: invalid email")
		}
		if err := sortedUnique(p.Groups, "people.groups", nonEmpty); err != nil {
			return err
		}
	}
	if r.Kind == KindCompanion {
		return r.validateCompanion(f)
	}
	want := map[string][3]string{
		KindAggregate: {"mcp", "mcp:all", "false"},
		KindAdmin:     {"hub", "mcp:portcullis.admin", "false"},
		KindPeople:    {"people", "mcp:portcullis.people", "true"},
	}
	w, ok := want[r.Kind]
	if !ok {
		return fmt.Errorf("kind: unknown")
	}
	if r.URL != "https://"+w[0]+"."+f.MainDomain+"/mcp" {
		return fmt.Errorf("url: not https://%s.<main_domain>/mcp", w[0])
	}
	if r.Scope != w[1] {
		return fmt.Errorf("scope: not %s", w[1])
	}
	if strconv.FormatBool(r.Aggregate) != w[2] {
		return fmt.Errorf("aggregate: must be %s", w[2])
	}
	if r.MinLoA != 2 {
		return fmt.Errorf("min_loa: must be 2")
	}
	if r.Instance != "" || r.Companion != "" || r.AppURL != "" || r.Upstream != "" || r.Mode != "" ||
		len(r.Hosts) != 0 || len(r.Protocol) != 0 || r.Identity != (Identity{Mode: "none"}) ||
		len(r.Tools.Writes)+len(r.Tools.Confirm)+len(r.Tools.Never) != 0 {
		return fmt.Errorf("companion-only fields set on a %s resource", r.Kind)
	}
	return nil
}

func (r *Resource) validateCompanion(f *File) error {
	if !idShape.MatchString(r.Instance) || !idShape.MatchString(r.Companion) {
		return fmt.Errorf("instance / companion: invalid id")
	}
	if r.Scope != "mcp:"+r.Instance+"."+r.Companion {
		return fmt.Errorf("scope: not mcp:<instance>.<companion>")
	}
	if err := sortedUnique(r.Hosts, "hosts", ValidHostname); err != nil {
		return err
	}
	if !slices.Contains(r.Hosts, r.Host) {
		return fmt.Errorf("hosts: must contain host")
	}
	for _, h := range r.Hosts {
		if slices.Contains(f.CoreHosts, h) {
			return fmt.Errorf("hosts: a core host")
		}
	}
	au, err := url.Parse(r.AppURL)
	if err != nil || au.Scheme != "https" || r.AppURL != "https://"+au.Host || !slices.Contains(r.Hosts, au.Host) {
		return fmt.Errorf("app_url: not https://<one of hosts>")
	}
	m := upstreamR.FindStringSubmatch(r.Upstream)
	if m == nil || m[1] != r.Instance || m[2] != r.Companion || !validPort(m[3], false) {
		return fmt.Errorf("upstream: not http://portcullis-mcp-<instance>--<companion>:<port><path>")
	}
	if len(r.Protocol) == 0 {
		return fmt.Errorf("protocol: empty")
	}
	seen := map[string]bool{}
	for _, p := range r.Protocol {
		if !slices.Contains(SupportedProtocols, p) || seen[p] {
			return fmt.Errorf("protocol: unsupported or repeated version")
		}
		seen[p] = true
	}
	if r.Mode != "read_only" && r.Mode != "read_write" {
		return fmt.Errorf("mode: not read_only or read_write")
	}
	if r.MinLoA < 0 || r.MinLoA > 2 {
		return fmt.Errorf("min_loa: outside 0..2 (LoA 3 can't get AI support)")
	}
	id := r.Identity
	if !headerTok.MatchString(id.Header) || forbiddenHeader(id.Header) {
		return fmt.Errorf("identity.header: invalid or reserved")
	}
	if hasControl(id.Format) || hasControl(id.BasicUser) {
		return fmt.Errorf("identity: control characters")
	}
	switch id.Mode {
	case "app_token":
		basic := id.Format == "" && id.BasicUser != ""
		formatted := id.Format != "" && id.BasicUser == "" && strings.Contains(id.Format, "{credential}")
		if !(basic || formatted) || id.SecretRef != "" {
			return fmt.Errorf("identity: app_token needs format with {credential} or basic_user")
		}
	case "identity_headers":
		if !strings.Contains(id.Format, "{secret}") || id.BasicUser != "" || id.SecretRef != r.Instance+"/"+r.Companion {
			return fmt.Errorf("identity: identity_headers needs format with {secret} and secret_ref <instance>/<companion>")
		}
	default:
		return fmt.Errorf("identity.mode: not app_token or identity_headers")
	}
	return nil
}

func (c *CredFile) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version: not 1")
	}
	for i, e := range c.Credentials {
		if !idShape.MatchString(e.Instance) || !idShape.MatchString(e.Companion) || !validUser(e.User) {
			return fmt.Errorf("credentials[%d]: invalid instance, companion or user", i)
		}
		if !credID.MatchString(e.ID) {
			return fmt.Errorf("credentials[%d]: invalid id", i)
		}
		switch {
		case e.State == "active" && e.Age != "":
		case e.State == "revoking" && e.Age == "":
		default:
			return fmt.Errorf("credentials[%d]: state must be active (with age) or revoking (age empty)", i)
		}
		if i > 0 && cmp3(c.Credentials[i-1], e) >= 0 {
			return fmt.Errorf("credentials[%d]: not sorted by instance, companion, user or not unique", i)
		}
	}
	for i, s := range c.CallerSecrets {
		in, co, ok := strings.Cut(s.Ref, "/")
		if !ok || !idShape.MatchString(in) || !idShape.MatchString(co) || s.Age == "" {
			return fmt.Errorf("caller_secrets[%d]: invalid ref or empty age", i)
		}
		if i > 0 && c.CallerSecrets[i-1].Ref >= s.Ref {
			return fmt.Errorf("caller_secrets[%d]: not sorted by ref or not unique", i)
		}
	}
	return nil
}

func cmp3(a, b CredEntry) int {
	return slices.Compare([]string{a.Instance, a.Companion, a.User}, []string{b.Instance, b.Companion, b.User})
}

// Path is the resource's URL path (the lookup key with Host).
func (r *Resource) Path() string { return r.path }

// MetadataURL is the RFC 9728 metadata URL of the resource (§15.1).
func (r *Resource) MetadataURL() string {
	return "https://" + r.Host + "/.well-known/oauth-protected-resource" + r.path
}

// AllowsClient: azp is in this resource's clients (§15.2).
func (r *Resource) AllowsClient(azp string) bool { return slices.Contains(r.Clients, azp) }

// Member: the lowercase user is in the population and not at or past
// their expiring time.
func (r *Resource) Member(user string, now time.Time) bool {
	if _, ok := r.pop[user]; !ok {
		return false
	}
	if at, ok := r.Expiring[user]; ok && !now.Before(at.Time) {
		return false
	}
	return true
}

// lookup finds the resource for a normalised host and an exact path.
func (f *File) lookup(host, path string) (*Resource, bool) {
	if f == nil {
		return nil, false
	}
	r, ok := f.index[host+path]
	return r, ok
}
