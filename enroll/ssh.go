package main

// enroll's SSH endpoints (contract §18.7, §18.8) on the Hub's internal
// listener: same bearer, strict JSON ≤ 64 KiB, certOpTimeout.
//
//	PUT    /internal/ssh-roles/{hg}         {"principals","extensions","source_address","max_ttl_s"}
//	       → 200 the role as Vault reads it back (same shape)
//	DELETE /internal/ssh-roles/{hg}         → 204
//	GET    /internal/ssh-roles              → {"roles": ["hg-…"]}
//	POST   /internal/ssh-certificates       {"user","host_group","public_key","principals","valid_seconds","extensions","key_id"}
//	       → 201 {"certificate","serial","valid_before"}
//	POST   /internal/ssh-host-certificates  {"public_key","principals","host_group","host_id"}
//	       → 201 {"certificate","serial","valid_before"}
//	GET    /internal/ssh-ca                 → {"user_cas","host_cas","problems"}
//
// Every value is checked here before Vault is called; Vault's role and
// enroll's policy (vault/policies/enroll.hcl) are the second fence. The
// answer from Vault is checked too (type, key, principals, key id,
// extensions, lifetime): a certificate that isn't exactly what was asked
// is never handed out. enroll logs what it signs (user, host group,
// principals, serial, key fingerprint), never a key or certificate.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
)

const (
	sshUserMount = "ssh_user"
	sshHostMount = "ssh_host"
	// sshUserCap / sshHostCap are the mounts' max_lease_ttl (§18.7).
	sshUserCap = 43200
	sshHostCap = 7776000
	// Limits (§18.8).
	sshMaxPrincipals     = 4096
	sshMaxCIDRs          = 16
	sshMaxHostPrincipals = 64
	sshMinValidSeconds   = 300
	sshMaxValidSeconds   = 43200
	// sshClockSlack: Vault backdates ValidAfter by 30 s; the answer's
	// ValidBefore may be this much past now + valid_seconds.
	sshClockSlack = 60 * time.Second
)

// The grammars (byte-identical to the Hub's internal/cliapi, checked
// against the shared vectors: testdata/ssh_vectors.json).
var (
	sshHostGroupRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	sshPrincipalRE = regexp.MustCompile(`^([us]):([a-z_][a-z0-9._-]{0,31})@([a-z][a-z0-9-]{0,30})$`)
	sshKeyIDRE     = regexp.MustCompile(`^pc:([a-z0-9][a-z0-9._-]{0,63}):([a-z][a-z0-9-]{0,30}):([0-9a-f]{16})$`)
	sshHostIDRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	sshDNSLabelRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// sshExtensionSets are the four canonical extension sets, in this order only.
var sshExtensionSets = []string{
	"permit-pty",
	"permit-pty,permit-port-forwarding",
	"permit-pty,permit-agent-forwarding",
	"permit-pty,permit-port-forwarding,permit-agent-forwarding",
}

// sshUserKeyLengths is the roles' allowed_user_key_lengths: the four
// accepted key types (§18.6; spike S1).
var sshUserKeyLengths = map[string][]int{
	"ssh-ed25519":                        {0},
	"ecdsa-sha2-nistp256":                {256},
	"sk-ssh-ed25519@openssh.com":         {0},
	"sk-ecdsa-sha2-nistp256@openssh.com": {256},
}

// sshRoleTTLs are the role TTLs the policy allows: whole hours, ≤ 12 h.
func sshRoundRoleTTL(seconds int) (int, bool) {
	if seconds <= 0 {
		return 0, false
	}
	h := (seconds + 3599) / 3600
	return h * 3600, h*3600 <= sshMaxValidSeconds
}

func validSSHHostGroup(hg string) bool {
	return sshHostGroupRE.MatchString(hg) && !strings.HasPrefix(hg, "portcullis-")
}

func validSSHExtensions(s string) bool { return slices.Contains(sshExtensionSets, s) }

// validSSHHostPrincipal: a DNS name (no wildcard) or an IP address
// without a zone.
func validSSHHostPrincipal(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == ""
	}
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !sshDNSLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// sshRoleSpec is a role as the Hub compiles it and as enroll reads it back.
type sshRoleSpec struct {
	Principals    []string `json:"principals"`
	Extensions    string   `json:"extensions"`
	SourceAddress []string `json:"source_address"`
	MaxTTLSeconds int      `json:"max_ttl_s"`
}

// checkRole validates spec for host group hg and rounds its TTL (400
// text on a refusal).
func checkRole(hg string, spec *sshRoleSpec) error {
	if !validSSHHostGroup(hg) {
		return refuse(400, "invalid host group id")
	}
	if len(spec.Principals) > sshMaxPrincipals {
		return refuse(400, "more than %d principals", sshMaxPrincipals)
	}
	seen := map[string]bool{}
	for _, p := range spec.Principals {
		m := sshPrincipalRE.FindStringSubmatch(p)
		if m == nil || m[3] != hg {
			return refuse(400, "principal %q isn't u:<user>@%s or s:<account>@%s", clipText(p), hg, hg)
		}
		if seen[p] {
			return refuse(400, "principal %q twice", p)
		}
		seen[p] = true
	}
	if !validSSHExtensions(spec.Extensions) {
		return refuse(400, "extensions must be one of the four canonical sets")
	}
	if len(spec.SourceAddress) > sshMaxCIDRs {
		return refuse(400, "more than %d source addresses", sshMaxCIDRs)
	}
	for _, c := range spec.SourceAddress {
		p, err := netip.ParsePrefix(c)
		if err != nil || p.Masked().String() != c {
			return refuse(400, "source address %q isn't a canonical CIDR", clipText(c))
		}
	}
	ttl, ok := sshRoundRoleTTL(spec.MaxTTLSeconds)
	if !ok {
		return refuse(400, "max_ttl_s must be 1–43200 (rounded up to the hour)")
	}
	spec.MaxTTLSeconds = ttl
	if spec.Principals == nil {
		spec.Principals = []string{}
	}
	if spec.SourceAddress == nil {
		spec.SourceAddress = []string{}
	}
	return nil
}

// sshRoleWrite is the Vault write for spec: every field a string or the
// documented map (spike S4: JSON booleans are refused by the policy).
func sshRoleWrite(spec sshRoleSpec) map[string]any {
	crit, defCrit := "", map[string]any{}
	if len(spec.SourceAddress) > 0 {
		crit = "source-address"
		defCrit["source-address"] = strings.Join(spec.SourceAddress, ",")
	}
	ttl := strconv.Itoa(spec.MaxTTLSeconds)
	lengths := map[string]any{}
	for k, v := range sshUserKeyLengths {
		lengths[k] = v
	}
	return map[string]any{
		"key_type":                 "ca",
		"allow_user_certificates":  "true",
		"allow_host_certificates":  "false",
		"allow_user_key_ids":       "true",
		"allowed_users":            strings.Join(spec.Principals, ","),
		"allowed_extensions":       spec.Extensions,
		"default_extensions":       map[string]any{},
		"allowed_critical_options": crit,
		"default_critical_options": defCrit,
		"allowed_user_key_lengths": lengths,
		"ttl":                      ttl,
		"max_ttl":                  ttl,
	}
}

// numberOf reads a Vault number (json.Number, float64 or a decimal string).
func numberOf(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case float64:
		return int64(n), n == float64(int64(n))
	case int:
		return int64(n), true
	case int64:
		return n, true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	}
	return 0, false
}

func splitList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sshRoleRead normalises Vault's read-back into the spec shape (§18.8);
// a role that isn't a user CA role at all is an error.
func sshRoleRead(data map[string]any) (*sshRoleSpec, error) {
	if data == nil {
		return nil, errors.New("the role reads back empty")
	}
	if kt, _ := data["key_type"].(string); kt != "ca" {
		return nil, fmt.Errorf("the role reads back with key_type %q", kt)
	}
	if b, _ := data["allow_host_certificates"].(bool); b {
		return nil, errors.New("the role reads back allowing host certificates")
	}
	users, _ := data["allowed_users"].(string)
	ext, _ := data["allowed_extensions"].(string)
	ttl, ok := numberOf(data["max_ttl"])
	if !ok {
		return nil, errors.New("the role reads back without a max_ttl")
	}
	out := &sshRoleSpec{Principals: splitList(users), Extensions: ext, SourceAddress: []string{}, MaxTTLSeconds: int(ttl)}
	if dc, ok := data["default_critical_options"].(map[string]any); ok {
		if sa, _ := dc["source-address"].(string); sa != "" {
			out.SourceAddress = splitList(sa)
		}
	}
	return out, nil
}

// sshUserSign is POST /internal/ssh-certificates' body.
type sshUserSign struct {
	User         string   `json:"user"`
	HostGroup    string   `json:"host_group"`
	PublicKey    string   `json:"public_key"`
	Principals   []string `json:"principals"`
	ValidSeconds int      `json:"valid_seconds"`
	Extensions   []string `json:"extensions"`
	KeyID        string   `json:"key_id"`
}

// sshHostSign is POST /internal/ssh-host-certificates' body.
type sshHostSign struct {
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`
	HostGroup  string   `json:"host_group"`
	HostID     string   `json:"host_id"`
}

// sshSigned is a signed certificate (public: no key).
type sshSigned struct {
	Certificate string `json:"certificate"`
	Serial      string `json:"serial"`
	ValidBefore string `json:"valid_before"`
}

// parseSSHKey is the posted public key: one authorized_keys key of an
// accepted type (no certificate), re-encoded as "type base64".
func parseSSHKey(line string, types map[string][]int) (ssh.PublicKey, string, error) {
	if strings.ContainsAny(line, "\r\n") {
		return nil, "", refuse(400, "public_key must be one line")
	}
	k, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(opts) != 0 || len(rest) != 0 {
		return nil, "", refuse(400, "public_key isn't an SSH public key line")
	}
	if _, ok := types[k.Type()]; !ok {
		return nil, "", refuse(400, "key type %s isn't accepted (ed25519, ECDSA P-256 or their security-key forms)", k.Type())
	}
	return k, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), nil
}

// checkUserSign validates r (400 texts; the user's protection and
// existence are checked by the handler).
func checkUserSign(r *sshUserSign) (ssh.PublicKey, string, error) {
	if !validSSHHostGroup(r.HostGroup) {
		return nil, "", refuse(400, "invalid host group id")
	}
	k, norm, err := parseSSHKey(r.PublicKey, sshUserKeyLengths)
	if err != nil {
		return nil, "", err
	}
	if len(r.Principals) == 0 || len(r.Principals) > sshMaxPrincipals {
		return nil, "", refuse(400, "1–%d principals", sshMaxPrincipals)
	}
	seen := map[string]bool{}
	for _, p := range r.Principals {
		m := sshPrincipalRE.FindStringSubmatch(p)
		if m == nil || m[3] != r.HostGroup {
			return nil, "", refuse(400, "principal %q isn't u:<user>@%s or s:<account>@%s", clipText(p), r.HostGroup, r.HostGroup)
		}
		// A person's own-account principal names that person only.
		if m[1] == "u" && m[2] != r.User {
			return nil, "", refuse(400, "principal %q is another person's account", p)
		}
		if seen[p] {
			return nil, "", refuse(400, "principal %q twice", p)
		}
		seen[p] = true
	}
	if r.ValidSeconds < sshMinValidSeconds || r.ValidSeconds > sshMaxValidSeconds {
		return nil, "", refuse(400, "valid_seconds must be %d–%d", sshMinValidSeconds, sshMaxValidSeconds)
	}
	if !validSSHExtensions(strings.Join(r.Extensions, ",")) {
		return nil, "", refuse(400, "extensions must be one of the four canonical sets")
	}
	m := sshKeyIDRE.FindStringSubmatch(r.KeyID)
	if m == nil || m[1] != r.User || m[2] != r.HostGroup {
		return nil, "", refuse(400, "key_id must be pc:%s:%s:<16 hex>", r.User, r.HostGroup)
	}
	return k, norm, nil
}

func checkHostSign(r *sshHostSign) (ssh.PublicKey, string, error) {
	if !validSSHHostGroup(r.HostGroup) {
		return nil, "", refuse(400, "invalid host group id")
	}
	if !sshHostIDRE.MatchString(r.HostID) {
		return nil, "", refuse(400, "invalid host id")
	}
	k, norm, err := parseSSHKey(r.PublicKey, map[string][]int{ssh.KeyAlgoED25519: {0}})
	if err != nil {
		return nil, "", err
	}
	if len(r.Principals) == 0 || len(r.Principals) > sshMaxHostPrincipals {
		return nil, "", refuse(400, "1–%d host names", sshMaxHostPrincipals)
	}
	for _, p := range r.Principals {
		if !validSSHHostPrincipal(p) {
			return nil, "", refuse(400, "%q isn't a DNS name or an IP address", clipText(p))
		}
	}
	return k, norm, nil
}

// checkSignedCert parses Vault's signed_key and refuses anything but
// exactly the certificate asked for.
func checkSignedCert(signed string, want ssh.PublicKey, certType uint32, principals []string, keyID string, ext map[string]string, validSeconds int, now time.Time) (*ssh.Certificate, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signed))
	if err != nil {
		return nil, fmt.Errorf("vault's certificate doesn't parse: %w", err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("vault's answer isn't a certificate")
	}
	switch {
	case c.CertType != certType:
		return nil, fmt.Errorf("vault's certificate has type %d", c.CertType)
	case string(c.Key.Marshal()) != string(want.Marshal()):
		return nil, errors.New("vault's certificate is for another key")
	case c.KeyId != keyID:
		return nil, errors.New("vault's certificate has another key id")
	}
	got, exp := slices.Clone(c.ValidPrincipals), slices.Clone(principals)
	slices.Sort(got)
	slices.Sort(exp)
	if !slices.Equal(got, exp) {
		return nil, errors.New("vault's certificate names other principals")
	}
	if ext != nil {
		if len(c.Extensions) != len(ext) {
			return nil, errors.New("vault's certificate has other extensions")
		}
		for k, v := range ext {
			if g, ok := c.Extensions[k]; !ok || g != v {
				return nil, errors.New("vault's certificate has other extensions")
			}
		}
		for k := range c.CriticalOptions {
			if k != "source-address" {
				return nil, fmt.Errorf("vault's certificate has the critical option %s", k)
			}
		}
	}
	if validSeconds > 0 && time.Unix(int64(c.ValidBefore), 0).After(now.Add(time.Duration(validSeconds)*time.Second+sshClockSlack)) {
		return nil, errors.New("vault's certificate lives longer than asked")
	}
	return c, nil
}

// sshBackend is what the endpoints need from Vault (*Config; a fake in tests).
type sshBackend interface {
	putSSHRole(ctx context.Context, hg string, spec sshRoleSpec) (*sshRoleSpec, error)
	deleteSSHRole(ctx context.Context, hg string) error
	listSSHRoles(ctx context.Context) ([]string, error)
	signSSHUser(ctx context.Context, r sshUserSign, key ssh.PublicKey, norm string) (*sshSigned, error)
	signSSHHost(ctx context.Context, r sshHostSign, key ssh.PublicKey, norm string) (*sshSigned, error)
	sshCA(ctx context.Context) (*sshCAView, error)
}

type sshCAView struct {
	UserCAs  []string `json:"user_cas"`
	HostCAs  []string `json:"host_cas"`
	Problems []string `json:"problems"`
}

// ── Vault (*Config) ──────────────────────────────────────────────────

func sshRolePath(hg string) string { return sshUserMount + "/roles/hg-" + hg }

func (cfg *Config) putSSHRole(ctx context.Context, hg string, spec sshRoleSpec) (*sshRoleSpec, error) {
	var back *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		if _, err := vc.Logical().WriteWithContext(ctx, sshRolePath(hg), sshRoleWrite(spec)); err != nil {
			return err
		}
		var err error
		back, err = vc.Logical().ReadWithContext(ctx, sshRolePath(hg))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("vault ssh role hg-%s: %w", hg, err)
	}
	if back == nil {
		return nil, fmt.Errorf("vault ssh role hg-%s: missing after the write", hg)
	}
	return sshRoleRead(back.Data)
}

func (cfg *Config) deleteSSHRole(ctx context.Context, hg string) error {
	err := cfg.vault.do(func(vc *vault.Client) error {
		_, err := vc.Logical().DeleteWithContext(ctx, sshRolePath(hg))
		return err
	})
	if err != nil {
		return fmt.Errorf("vault ssh role hg-%s delete: %w", hg, err)
	}
	return nil
}

func (cfg *Config) listSSHRoles(ctx context.Context) ([]string, error) {
	var s *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		s, err = vc.Logical().ListWithContext(ctx, sshUserMount+"/roles")
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("vault ssh roles list: %w", err)
	}
	out := []string{}
	if s == nil || s.Data == nil {
		return out, nil
	}
	keys, _ := s.Data["keys"].([]any)
	for _, k := range keys {
		if n, _ := k.(string); strings.HasPrefix(n, "hg-") && validSSHHostGroup(strings.TrimPrefix(n, "hg-")) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (cfg *Config) sshSign(ctx context.Context, path string, body map[string]any) (string, error) {
	var s *vault.Secret
	err := cfg.vault.do(func(vc *vault.Client) error {
		var err error
		s, err = vc.Logical().WriteWithContext(ctx, path, body)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("vault %s: %w", path, err)
	}
	if s == nil || s.Data == nil {
		return "", fmt.Errorf("vault %s: empty response", path)
	}
	signed, _ := s.Data["signed_key"].(string)
	if signed == "" {
		return "", fmt.Errorf("vault %s: no signed_key", path)
	}
	return signed, nil
}

func signedAnswer(c *ssh.Certificate) *sshSigned {
	return &sshSigned{
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(c))),
		Serial:      strconv.FormatUint(c.Serial, 10),
		ValidBefore: time.Unix(int64(c.ValidBefore), 0).UTC().Format(time.RFC3339),
	}
}

func (cfg *Config) signSSHUser(ctx context.Context, r sshUserSign, key ssh.PublicKey, norm string) (*sshSigned, error) {
	ext := map[string]string{}
	extBody := map[string]any{}
	for _, e := range r.Extensions {
		ext[e] = ""
		extBody[e] = ""
	}
	now := cfg.clock()
	signed, err := cfg.sshSign(ctx, sshUserMount+"/sign/hg-"+r.HostGroup, map[string]any{
		"public_key":       norm,
		"valid_principals": strings.Join(r.Principals, ","),
		"ttl":              strconv.Itoa(r.ValidSeconds) + "s",
		"extensions":       extBody,
		"key_id":           r.KeyID,
	})
	if err != nil {
		return nil, err
	}
	c, err := checkSignedCert(signed, key, ssh.UserCert, r.Principals, r.KeyID, ext, r.ValidSeconds, now)
	if err != nil {
		return nil, err
	}
	return signedAnswer(c), nil
}

func (cfg *Config) signSSHHost(ctx context.Context, r sshHostSign, key ssh.PublicKey, norm string) (*sshSigned, error) {
	keyID := "pc-host:" + r.HostID
	signed, err := cfg.sshSign(ctx, sshHostMount+"/sign/host", map[string]any{
		"public_key":       norm,
		"valid_principals": strings.Join(r.Principals, ","),
		// The host role refuses Vault's default (user); the policy takes
		// exactly this value (spike S4b).
		"cert_type": "host",
		"key_id":    keyID,
	})
	if err != nil {
		return nil, err
	}
	c, err := checkSignedCert(signed, key, ssh.HostCert, r.Principals, keyID, nil, 0, cfg.clock())
	if err != nil {
		return nil, err
	}
	return signedAnswer(c), nil
}

// sshCA reads the two CA keys and every §18.7 difference enroll can see.
// Only a Vault that can't be reached at all is an error.
func (cfg *Config) sshCA(ctx context.Context) (*sshCAView, error) {
	v := &sshCAView{UserCAs: []string{}, HostCAs: []string{}, Problems: []string{}}
	read := func(vc *vault.Client, path string) (map[string]any, error) {
		s, err := vc.Logical().ReadWithContext(ctx, path)
		if err != nil {
			return nil, err
		}
		if s == nil || s.Data == nil {
			return nil, errors.New("nothing there")
		}
		return s.Data, nil
	}
	err := cfg.vault.do(func(vc *vault.Client) error {
		v.UserCAs, v.HostCAs, v.Problems = []string{}, []string{}, []string{}
		for _, m := range []struct {
			mount string
			cap   int64
			human string
			into  *[]string
		}{{sshUserMount, sshUserCap, "12h", &v.UserCAs}, {sshHostMount, sshHostCap, "2160h", &v.HostCAs}} {
			if d, err := read(vc, "sys/mounts/"+m.mount+"/tune"); err != nil {
				v.Problems = append(v.Problems, m.mount+": the mount is missing or unreadable")
			} else if n, ok := numberOf(d["max_lease_ttl"]); !ok || n != m.cap {
				v.Problems = append(v.Problems, fmt.Sprintf("%s: max_lease_ttl is %v s, not %s", m.mount, d["max_lease_ttl"], m.human))
			}
			d, err := read(vc, m.mount+"/config/ca")
			pub, _ := d["public_key"].(string)
			pub = strings.TrimSpace(pub)
			if err != nil || pub == "" {
				v.Problems = append(v.Problems, m.mount+": no CA")
				continue
			}
			k, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(pub))
			if perr != nil {
				v.Problems = append(v.Problems, m.mount+": the CA key doesn't parse")
				continue
			}
			if k.Type() != ssh.KeyAlgoED25519 {
				v.Problems = append(v.Problems, m.mount+": the CA key is "+k.Type()+", not ed25519")
			}
			*m.into = append(*m.into, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
		}
		d, err := read(vc, sshHostMount+"/roles/host")
		if err != nil {
			v.Problems = append(v.Problems, "ssh_host/roles/host: missing or unreadable")
			return nil
		}
		if kt, _ := d["key_type"].(string); kt != "ca" {
			v.Problems = append(v.Problems, "ssh_host/roles/host: key_type isn't ca")
		}
		if b, _ := d["allow_host_certificates"].(bool); !b {
			v.Problems = append(v.Problems, "ssh_host/roles/host: allow_host_certificates isn't true")
		}
		if b, _ := d["allow_user_certificates"].(bool); b {
			v.Problems = append(v.Problems, "ssh_host/roles/host: allow_user_certificates isn't false")
		}
		if b, _ := d["allow_user_key_ids"].(bool); !b {
			// Without it Vault refuses the key_id pc-host:<id> (live test).
			v.Problems = append(v.Problems, "ssh_host/roles/host: allow_user_key_ids isn't true")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("vault ssh CA: %w", err)
	}
	return v, nil
}

// ── HTTP ─────────────────────────────────────────────────────────────

func (s *inviteService) sshReady(w http.ResponseWriter, r *http.Request) (sshBackend, bool) {
	if !s.apiAuthorized(w, r) {
		return nil, false
	}
	if s.ssh == nil {
		jsonError(w, http.StatusServiceUnavailable, "SSH certificates unavailable")
		return nil, false
	}
	return s.ssh, true
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	if status == http.StatusCreated {
		writeCreated(w, v)
		return
	}
	buf, err := json.Marshal(v)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "answer can't be encoded")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf)
}

// sshFailed answers err like actionFailed, with an SSH log prefix.
func sshFailed(w http.ResponseWriter, action string, err error) {
	var oe *opError
	switch {
	case errors.As(err, &oe):
		log.Printf("SSH %s refused (%d): %s", action, oe.status, oe.msg)
		jsonError(w, oe.status, clipText(oe.msg))
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		log.Printf("SSH %s: %v", action, err)
		jsonError(w, http.StatusServiceUnavailable, "the SSH certificate authority did not answer in time")
	default:
		log.Printf("SSH %s: %v", action, err)
		jsonError(w, http.StatusServiceUnavailable, "the SSH certificate authority is unavailable")
	}
}

// PUT /internal/ssh-roles/{hg}
func (s *inviteService) handleSSHPutRole(w http.ResponseWriter, r *http.Request) {
	b, ok := s.sshReady(w, r)
	if !ok {
		return
	}
	hg := r.PathValue("hg")
	var spec sshRoleSpec
	if !decodeAction(w, r, &spec) {
		return
	}
	if err := checkRole(hg, &spec); err != nil {
		sshFailed(w, "role "+hg, err)
		return
	}
	back, err := withDeadline(r.Context(), func(ctx context.Context) (*sshRoleSpec, error) { return b.putSSHRole(ctx, hg, spec) }, nil)
	if err != nil {
		sshFailed(w, "role "+hg, err)
		return
	}
	log.Printf("SSH role hg-%s written: %d principals, %s, %d source addresses, %d s", hg, len(spec.Principals), spec.Extensions, len(spec.SourceAddress), spec.MaxTTLSeconds)
	writeJSONStatus(w, http.StatusOK, back)
}

// DELETE /internal/ssh-roles/{hg}
func (s *inviteService) handleSSHDeleteRole(w http.ResponseWriter, r *http.Request) {
	b, ok := s.sshReady(w, r)
	if !ok {
		return
	}
	hg := r.PathValue("hg")
	if !validSSHHostGroup(hg) {
		jsonError(w, http.StatusBadRequest, "invalid host group id")
		return
	}
	if _, err := withDeadline(r.Context(), func(ctx context.Context) (struct{}, error) { return struct{}{}, b.deleteSSHRole(ctx, hg) }, nil); err != nil {
		sshFailed(w, "role "+hg+" delete", err)
		return
	}
	log.Printf("SSH role hg-%s deleted", hg)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// GET /internal/ssh-roles
func (s *inviteService) handleSSHListRoles(w http.ResponseWriter, r *http.Request) {
	b, ok := s.sshReady(w, r)
	if !ok {
		return
	}
	roles, err := withDeadline(r.Context(), b.listSSHRoles, nil)
	if err != nil {
		sshFailed(w, "roles list", err)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string][]string{"roles": roles})
}

// POST /internal/ssh-certificates
func (s *inviteService) handleSSHSignUser(w http.ResponseWriter, r *http.Request) {
	b, ok := s.sshReady(w, r)
	if !ok {
		return
	}
	var req sshUserSign
	if !decodeAction(w, r, &req) {
		return
	}
	user, ok := actionUser(w, req.User)
	if !ok {
		return
	}
	req.User = user
	key, norm, err := checkUserSign(&req)
	if err != nil {
		sshFailed(w, "certificate for "+user, err)
		return
	}
	if s.sshUserExists == nil {
		jsonError(w, http.StatusServiceUnavailable, "the directory is unavailable")
		return
	}
	if err := s.sshUserExists(user); err != nil {
		var oe *opError
		if errors.As(err, &oe) && oe.status == http.StatusNotFound {
			sshFailed(w, "certificate for "+user, refuse(http.StatusConflict, "no such user"))
			return
		}
		sshFailed(w, "certificate for "+user, err)
		return
	}
	res, err := withDeadline(r.Context(), func(ctx context.Context) (*sshSigned, error) { return b.signSSHUser(ctx, req, key, norm) }, nil)
	if err != nil {
		sshFailed(w, "certificate for "+user, err)
		return
	}
	log.Printf("SSH certificate %s for %s on %s: principals %s, key %s, until %s", res.Serial, user, req.HostGroup, strings.Join(req.Principals, ","), ssh.FingerprintSHA256(key), res.ValidBefore)
	writeCreated(w, res)
}

// POST /internal/ssh-host-certificates
func (s *inviteService) handleSSHSignHost(w http.ResponseWriter, r *http.Request) {
	b, ok := s.sshReady(w, r)
	if !ok {
		return
	}
	var req sshHostSign
	if !decodeAction(w, r, &req) {
		return
	}
	key, norm, err := checkHostSign(&req)
	if err != nil {
		sshFailed(w, "host certificate", err)
		return
	}
	res, err := withDeadline(r.Context(), func(ctx context.Context) (*sshSigned, error) { return b.signSSHHost(ctx, req, key, norm) }, nil)
	if err != nil {
		sshFailed(w, "host certificate for "+req.HostID, err)
		return
	}
	log.Printf("SSH host certificate %s for %s (%s): names %s, key %s, until %s", res.Serial, req.HostID, req.HostGroup, strings.Join(req.Principals, ","), ssh.FingerprintSHA256(key), res.ValidBefore)
	writeCreated(w, res)
}

// GET /internal/ssh-ca
func (s *inviteService) handleSSHCA(w http.ResponseWriter, r *http.Request) {
	b, ok := s.sshReady(w, r)
	if !ok {
		return
	}
	v, err := withDeadline(r.Context(), b.sshCA, nil)
	if err != nil {
		sshFailed(w, "CA", err)
		return
	}
	writeJSONStatus(w, http.StatusOK, v)
}

func (s *inviteService) registerSSH(m *http.ServeMux) {
	m.HandleFunc("PUT /internal/ssh-roles/{hg}", s.handleSSHPutRole)
	m.HandleFunc("DELETE /internal/ssh-roles/{hg}", s.handleSSHDeleteRole)
	m.HandleFunc("GET /internal/ssh-roles", s.handleSSHListRoles)
	m.HandleFunc("POST /internal/ssh-certificates", s.handleSSHSignUser)
	m.HandleFunc("POST /internal/ssh-host-certificates", s.handleSSHSignHost)
	m.HandleFunc("GET /internal/ssh-ca", s.handleSSHCA)
}
