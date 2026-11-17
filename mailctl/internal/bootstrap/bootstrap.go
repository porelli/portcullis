package bootstrap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// Input is `mailctl bootstrap`'s stdin (contract §19.4).
type Input struct {
	RecoveryUser     string   `json:"recovery_user"`
	RecoveryPassword string   `json:"recovery_password"`
	Hostname         string   `json:"hostname"`
	PrimaryDomain    string   `json:"primary_domain"`
	ClientIP         string   `json:"client_ip"`
	LANOnly          bool     `json:"lan_only"`
	LocalNetworks    []string `json:"local_networks"`
	Relay            *Relay   `json:"relay"`
	MetricsUser      string   `json:"metrics_user"`
}

// Credentials is `mailctl bootstrap --verify-gone`'s stdin.
type Credentials struct {
	RecoveryUser     string `json:"recovery_user"`
	RecoveryPassword string `json:"recovery_password"`
}

// decodeStrict reads exactly one JSON object (≤ 64 KiB): unknown keys and
// trailing data refused.
func decodeStrict(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, 64<<10+1))
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	if len(b) > 64<<10 {
		return errors.New("stdin is larger than 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("stdin: %w", err)
	}
	if d.More() {
		return errors.New("stdin: trailing data after the object")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("stdin: trailing data after the object")
	}
	return nil
}

// ReadInput decodes and checks the bootstrap input.
func ReadInput(r io.Reader) (Input, error) {
	var in Input
	if err := decodeStrict(r, &in); err != nil {
		return in, err
	}
	switch {
	case in.RecoveryUser == "" || in.RecoveryPassword == "":
		return in, errors.New("recovery_user and recovery_password are required")
	case in.Hostname == "" || !strings.Contains(in.Hostname, "."):
		return in, errors.New("hostname is required (MAIL_HOSTNAME)")
	case in.PrimaryDomain == "":
		return in, errors.New("primary_domain is required")
	case in.ClientIP != "preserved" && in.ClientIP != "rewritten":
		return in, errors.New("client_ip must be preserved or rewritten")
	case in.MetricsUser == "":
		return in, errors.New("metrics_user is required")
	}
	for _, n := range in.LocalNetworks {
		if _, err := netip.ParsePrefix(n); err != nil {
			return in, fmt.Errorf("local_networks: %q is not a network", n)
		}
	}
	if r := in.Relay; r != nil && (r.Host == "" || r.Port < 1 || r.Port > 65535) {
		return in, errors.New("relay needs a host and a port")
	}
	return in, nil
}

// ReadCredentials decodes --verify-gone's input.
func ReadCredentials(r io.Reader) (Credentials, error) {
	var c Credentials
	if err := decodeStrict(r, &c); err != nil {
		return c, err
	}
	if c.RecoveryUser == "" || c.RecoveryPassword == "" {
		return c, errors.New("recovery_user and recovery_password are required")
	}
	return c, nil
}

type object = map[string]json.RawMessage

func str(o object, k string) string {
	var s string
	_ = json.Unmarshal(o[k], &s)
	return s
}

func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// differs: the fields of want (but skip) whose value isn't the existing one
// (a missing field equals null).
func differs(have object, want map[string]any, skip map[string]bool) map[string]any {
	patch := map[string]any{}
	for k, w := range want {
		if skip[k] {
			continue
		}
		var h any
		if raw, ok := have[k]; ok {
			_ = json.Unmarshal(raw, &h)
		}
		if !reflect.DeepEqual(h, normalize(w)) {
			patch[k] = w
		}
	}
	return patch
}

func getAll(ctx context.Context, c *stalwart.Client, obj string) ([]object, error) {
	ids, err := c.Query(ctx, obj, nil)
	if err != nil {
		return nil, fmt.Errorf("x:%s/query: %w", obj, err)
	}
	var out []object
	if len(ids) == 0 {
		return out, nil
	}
	if err := c.Get(ctx, obj, ids, nil, &out); err != nil {
		return nil, fmt.Errorf("x:%s/get: %w", obj, err)
	}
	return out, nil
}

func checkSet(obj string, r stalwart.SetResult, err error) error {
	if err != nil {
		return fmt.Errorf("x:%s/set: %w", obj, err)
	}
	if err := r.Failed(); err != nil {
		return fmt.Errorf("x:%s/set: %w", obj, err)
	}
	return nil
}

// Ensure makes the named objects exist with these values (create missing,
// update differing, destroy unnamed ones when DestroyOthers, and duplicate
// keys always) and returns key → id.
func Ensure(ctx context.Context, c *stalwart.Client, n Named) (map[string]string, error) {
	ids, _, err := ensure(ctx, c, n)
	return ids, err
}

// ensure is Ensure, also saying whether it wrote anything.
func ensure(ctx context.Context, c *stalwart.Client, n Named) (map[string]string, bool, error) {
	have, err := getAll(ctx, c, n.Object)
	if err != nil {
		return nil, false, err
	}
	skip := map[string]bool{n.Key: true, "@type": true}
	for _, f := range n.Immutable {
		skip[f] = true
	}
	byKey := map[string]object{}
	var destroy []string
	for _, o := range have {
		k := str(o, n.Key)
		if _, dup := byKey[k]; dup {
			destroy = append(destroy, str(o, "id"))
			continue
		}
		byKey[k] = o
	}
	want := map[string]bool{}
	ids := map[string]string{}
	create := map[string]any{}
	update := map[string]map[string]any{}
	keys := map[string]string{} // creation id → key
	for i, w := range n.Want {
		k, _ := w[n.Key].(string)
		want[k] = true
		o, ok := byKey[k]
		if ok && w["@type"] != nil && str(o, "@type") != w["@type"] {
			// Another variant: replace it.
			destroy = append(destroy, str(o, "id"))
			ok = false
		}
		if !ok {
			cid := fmt.Sprintf("c%d", i)
			create[cid] = w
			keys[cid] = k
			continue
		}
		id := str(o, "id")
		ids[k] = id
		if p := differs(o, w, skip); len(p) > 0 {
			update[id] = p
		}
	}
	if n.DestroyOthers {
		for k, o := range byKey {
			if !want[k] {
				destroy = append(destroy, str(o, "id"))
			}
		}
	}
	sort.Strings(destroy)
	if len(destroy) > 0 {
		r, err := c.Set(ctx, n.Object, nil, nil, destroy)
		if err := checkSet(n.Object, r, err); err != nil {
			return nil, false, err
		}
	}
	if len(create) > 0 || len(update) > 0 {
		r, err := c.Set(ctx, n.Object, create, update, nil)
		if err := checkSet(n.Object, r, err); err != nil {
			return nil, false, err
		}
		for cid, k := range keys {
			id := r.CreatedID(cid)
			if id == "" {
				return nil, false, fmt.Errorf("x:%s/set: no id for the new %q", n.Object, k)
			}
			ids[k] = id
		}
	}
	return ids, len(destroy) > 0 || len(create) > 0 || len(update) > 0, nil
}

func updateSingleton(ctx context.Context, c *stalwart.Client, s Singleton) error {
	r, err := c.Set(ctx, s.Object, nil, map[string]map[string]any{"singleton": s.Patch}, nil)
	return checkSet(s.Object, r, err)
}

// randomSecret is n random bytes, URL-safe base64 (never kept or printed).
func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Result is the outcome of Apply. APIKey is "" when a key already existed
// and no rotation was asked for.
type Result struct {
	APIKey string
}

// Apply runs the base plan as the recovery admin (c), idempotently.
func Apply(ctx context.Context, c *stalwart.Client, p Params, rotateKey bool, logf func(string, ...any)) (Result, error) {
	var res Result
	ids := map[string]map[string]string{}
	for _, n := range p.Collections() {
		got, err := Ensure(ctx, c, n)
		if err != nil {
			return res, err
		}
		ids[n.Object] = got
	}

	// Every domain: certificates, DNS and DKIM are Portcullis's.
	doms, err := getAll(ctx, c, "Domain")
	if err != nil {
		return res, err
	}
	upd := map[string]map[string]any{}
	for _, d := range doms {
		if pt := differs(d, manual, nil); len(pt) > 0 {
			upd[str(d, "id")] = pt
		}
	}
	if len(upd) > 0 {
		r, err := c.Set(ctx, "Domain", nil, upd, nil)
		if err := checkSet("Domain", r, err); err != nil {
			return res, err
		}
	}

	// No ACME in Stalwart: the certificate is mail-cert's files.
	acme, err := getAll(ctx, c, "AcmeProvider")
	if err != nil {
		return res, err
	}
	var gone []string
	for _, a := range acme {
		gone = append(gone, str(a, "id"))
	}
	if len(gone) > 0 {
		r, err := c.Set(ctx, "AcmeProvider", nil, nil, gone)
		if err := checkSet("AcmeProvider", r, err); err != nil {
			return res, err
		}
	}
	certID, err := ensureCertificate(ctx, c)
	if err != nil {
		return res, err
	}

	for _, s := range p.Singletons() {
		if s.Object == "SystemSettings" {
			s.Patch["defaultCertificateId"] = certID
			s.Patch["defaultDomainId"] = ids["Domain"][p.PrimaryDomain]
		}
		if err := updateSingleton(ctx, c, s); err != nil {
			return res, err
		}
	}
	// The ASN / Geo download must be off before the first normal start.
	// A Disabled written onto a store that never held the object isn't
	// counted, and the first normal start then inserts the default (a
	// download of four GitHub CSVs): write the object first as a Resource
	// with no URL (nothing to fetch), then switch it to Disabled.
	if err := updateSingleton(ctx, c, Singleton{"Asn", map[string]any{"@type": "Resource", "asnUrls": set(), "geoUrls": set()}}); err != nil {
		return res, err
	}
	if err := ensureVariant(ctx, c, "Asn", "Disabled"); err != nil {
		return res, err
	}
	// Recovery-first stores never get Stalwart's default roles (Task 2):
	// accounts with the User role get portcullis-mail-user.
	if err := updateSingleton(ctx, c, Singleton{"Authentication", map[string]any{
		"defaultUserRoleIds": set(ids["Role"][UserRole]),
	}}); err != nil {
		return res, err
	}
	// The WebUI is re-created at every start if missing: disable, never destroy.
	apps, err := getAll(ctx, c, "Application")
	if err != nil {
		return res, err
	}
	off := map[string]map[string]any{}
	for _, a := range apps {
		if string(a["enable"]) != "false" {
			off[str(a, "id")] = map[string]any{"enable": false}
		}
	}
	if len(off) > 0 {
		r, err := c.Set(ctx, "Application", nil, off, nil)
		if err := checkSet("Application", r, err); err != nil {
			return res, err
		}
	}

	accountID, err := ensureAccount(ctx, c, ids["Domain"][ParkingDomain], ids["Role"][MailctlRole])
	if err != nil {
		return res, err
	}
	key, err := ensureAPIKey(ctx, c.As(accountID), p.MailctlIP, rotateKey)
	if err != nil {
		return res, err
	}
	res.APIKey = key
	if err := c.Action(ctx, "ReloadSettings"); err != nil {
		return res, fmt.Errorf("ReloadSettings: %w", err)
	}
	if logf != nil {
		logf("bootstrap: base plan applied (%s, client addresses %s)", p.RoutePlanText(), p.ClientIP)
	}
	return res, nil
}

// ensureVariant reads a variant singleton back and sets it again (once)
// when it isn't the wanted variant.
func ensureVariant(ctx context.Context, c *stalwart.Client, obj, variant string) error {
	for try := 0; try < 2; try++ {
		var got []object
		if err := c.Get(ctx, obj, []string{"singleton"}, nil, &got); err != nil {
			return fmt.Errorf("x:%s/get: %w", obj, err)
		}
		if len(got) == 1 && str(got[0], "@type") == variant {
			return nil
		}
		if err := updateSingleton(ctx, c, Singleton{obj, map[string]any{"@type": variant}}); err != nil {
			return err
		}
	}
	return fmt.Errorf("x:%s stays off %s after two writes", obj, variant)
}

func ensureCertificate(ctx context.Context, c *stalwart.Client) (string, error) {
	certs, err := getAll(ctx, c, "Certificate")
	if err != nil {
		return "", err
	}
	want := map[string]any{"certificate": file(TLSDir + "/fullchain.pem"), "privateKey": file(TLSDir + "/privkey.pem")}
	var id string
	var destroy []string
	for _, ct := range certs {
		var cert struct {
			FilePath string `json:"filePath"`
		}
		_ = json.Unmarshal(ct["certificate"], &cert)
		if id == "" && cert.FilePath == TLSDir+"/fullchain.pem" {
			id = str(ct, "id")
			continue
		}
		destroy = append(destroy, str(ct, "id"))
	}
	if len(destroy) > 0 {
		r, err := c.Set(ctx, "Certificate", nil, nil, destroy)
		if err := checkSet("Certificate", r, err); err != nil {
			return "", err
		}
	}
	if id != "" {
		// privateKey reads back hidden: send both on every run.
		r, err := c.Set(ctx, "Certificate", nil, map[string]map[string]any{id: want}, nil)
		return id, checkSet("Certificate", r, err)
	}
	r, err := c.Set(ctx, "Certificate", map[string]any{"cert": want}, nil, nil)
	if err := checkSet("Certificate", r, err); err != nil {
		return "", err
	}
	return r.CreatedID("cert"), nil
}

func ensureAccount(ctx context.Context, c *stalwart.Client, domainID, roleID string) (string, error) {
	if domainID == "" || roleID == "" {
		return "", errors.New("the parking domain or mailctl's role has no id")
	}
	accts, err := getAll(ctx, c, "Account")
	if err != nil {
		return "", err
	}
	roles := map[string]any{"@type": "Custom", "roleIds": set(roleID)}
	for _, a := range accts {
		if str(a, "name") == MailctlAccount && str(a, "domainId") == domainID {
			id := str(a, "id")
			if pt := differs(a, map[string]any{"roles": roles}, nil); len(pt) > 0 {
				r, err := c.Set(ctx, "Account", nil, map[string]map[string]any{id: pt}, nil)
				if err := checkSet("Account", r, err); err != nil {
					return "", err
				}
			}
			return id, nil
		}
	}
	pw, err := randomSecret(64)
	if err != nil {
		return "", err
	}
	r, err := c.Set(ctx, "Account", map[string]any{"m": map[string]any{
		"@type": "User", "name": MailctlAccount, "domainId": domainID, "description": "Portcullis mailctl",
		// A random password nobody keeps: nobody signs in as mailctl.
		"credentials": list(map[string]any{"@type": "Password", "secret": pw}),
		"roles":       roles,
	}}, nil, nil)
	if err := checkSet("Account", r, err); err != nil {
		return "", err
	}
	return r.CreatedID("m"), nil
}

// ensureAPIKey makes mailctl's one API key (Inherit, pinned to its
// portcullis-mail address, no expiry) unless one exists; rotate replaces it.
func ensureAPIKey(ctx context.Context, c *stalwart.Client, mailctlIP netip.Addr, rotate bool) (string, error) {
	keys, err := getAll(ctx, c, "ApiKey")
	if err != nil {
		return "", err
	}
	if len(keys) > 0 && !rotate {
		return "", nil
	}
	var old []string
	for _, k := range keys {
		old = append(old, str(k, "id"))
	}
	if len(old) > 0 {
		r, err := c.Set(ctx, "ApiKey", nil, nil, old)
		if err := checkSet("ApiKey", r, err); err != nil {
			return "", err
		}
	}
	r, err := c.Set(ctx, "ApiKey", map[string]any{"k": map[string]any{
		"description": APIKeyName,
		"permissions": map[string]any{"@type": "Inherit"},
		"allowedIps":  set(netip.PrefixFrom(mailctlIP, 32).String()),
	}}, nil, nil)
	if err := checkSet("ApiKey", r, err); err != nil {
		return "", err
	}
	var secret string
	if raw, ok := r.Created["k"]["secret"]; ok {
		_ = json.Unmarshal(raw, &secret)
	}
	if !strings.HasPrefix(secret, "API_") {
		return "", errors.New("x:ApiKey/set: the new key's secret is missing from the answer")
	}
	return secret, nil
}

// DisableExternalLookups disables every enabled HttpLookup (the spam rules'
// external feeds; mailctl has none of its own) and reloads the settings
// when it changed one. It returns how many it disabled.
func DisableExternalLookups(ctx context.Context, c *stalwart.Client) (int, error) {
	enabled := func(ids []string) (map[string]*bool, error) {
		var ls []struct {
			ID     string `json:"id"`
			Enable *bool  `json:"enable"`
		}
		if len(ids) > 0 {
			if err := c.Get(ctx, "HttpLookup", ids, []string{"id", "enable"}, &ls); err != nil {
				return nil, err
			}
		}
		out := map[string]*bool{}
		for _, l := range ls {
			out[l.ID] = l.Enable
		}
		return out, nil
	}
	ids, err := c.Query(ctx, "HttpLookup", nil)
	if err != nil {
		return 0, err
	}
	cur, err := enabled(ids)
	if err != nil {
		return 0, err
	}
	// Only an explicit false is off (final review L10): absent is not
	// known to be off, so it is written too.
	off := map[string]map[string]any{}
	var changed []string
	for id, e := range cur {
		if e == nil || *e {
			off[id] = map[string]any{"enable": false}
			changed = append(changed, id)
		}
	}
	if len(off) == 0 {
		return 0, nil
	}
	r, err := c.Set(ctx, "HttpLookup", nil, off, nil)
	if err := checkSet("HttpLookup", r, err); err != nil {
		return 0, err
	}
	if err := c.Action(ctx, "ReloadSettings"); err != nil {
		return len(off), err
	}
	// Read back: every one written must now say false.
	after, err := enabled(changed)
	if err != nil {
		return len(off), err
	}
	for _, id := range changed {
		if e, ok := after[id]; ok && (e == nil || *e) {
			return len(off), fmt.Errorf("x:HttpLookup %s: enable isn't false after turning it off", id)
		}
	}
	return len(off), nil
}

// ErrStillWorks: the recovery admin still authenticates.
var ErrStillWorks = errors.New("the recovery admin still works: stop mail and inspect")

// VerifyGone checks that the recovery login is refused (401) on the
// management listener. Any other answer, or none, is an error.
func VerifyGone(ctx context.Context, url string, cr Credentials) error {
	c := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/jmap",
		strings.NewReader(`{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(cr.RecoveryUser, cr.RecoveryPassword)
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("can't confirm the recovery admin is gone: %v", errors.Unwrap(err))
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return nil
	case http.StatusOK:
		return ErrStillWorks
	default:
		return fmt.Errorf("can't confirm the recovery admin is gone: HTTP %d", resp.StatusCode)
	}
}
