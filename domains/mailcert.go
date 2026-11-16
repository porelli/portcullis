package main

// `domains mail-cert [--next-key | --switch-key]` (contract §19.3): the
// mail server's certificate for MAIL_HOSTNAME, run by ./portcullis as the
// compose tools service mail-cert (`run --rm --no-deps -T`, the DNS
// credentials on stdin as for dns-tool) with the volumes mail_acme at
// /acme and mail_tls at /tls.
//
//   - Its own ACME account (/acme/account.json, EC P-256, 0600) and one
//     reused key (/acme/mail.key, EC P-256, created once): the TLSA
//     (3 1 1) stays the same across renewals. Never Traefik's wildcard
//     key: a compromised mail server can't impersonate auth.<main>.
//   - The CAA at the hostname (issue only, TTL 300) pins this account
//     (dnsplan.CAAValue), written through the same provider; before an
//     order it waits until every resolver lets the CA issue to it. The
//     closest RRset wins (RFC 8659): the main domain's pin is untouched.
//   - Issues [hostname] by DNS-01 when the current chain expires within
//     renew_below_days, or its key or SANs differ (or the account is new:
//     another CA). A chain whose SANs aren't exactly {hostname} or whose
//     key isn't the reused key is refused; the old files stay.
//   - Writes /tls/fullchain.pem and /tls/privkey.pem as one pair (0640;
//     the volume's setgid directory gives them Stalwart's group): both are
//     links into current/, a generation directory swapped by one rename
//     (writeTLSPair), so a reader never pairs a key with another chain; and
//     prints one line {"renewed", "not_after", "spki_sha256"}.
//   - --next-key creates /acme/mail.next.key (once) and prints its
//     spki_sha256 (TLSA rollover); --switch-key issues with it and, once
//     the new chain is written, makes it /acme/mail.key.
//
// Exit codes as `domains dns`: 0 ok, 1 problem (refused chain, CAA not
// visible in time, no next key), 2 usage or input, 3 provider / ACME
// failure (redacted).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"

	"github.com/portcullis/domains/internal/dnsplan"
)

// mailCertInput is mail-cert's stdin (unknown keys refused).
type mailCertInput struct {
	Hostname    string            `json:"hostname"`
	CAServer    string            `json:"ca_server"`
	Email       string            `json:"email"`
	Provider    string            `json:"provider"`
	Credentials map[string]string `json:"credentials"`
	CAA         struct {
		Enabled bool   `json:"enabled"`
		Issuer  string `json:"issuer"`
		IODEF   string `json:"iodef"`
	} `json:"caa"`
	RenewBelowDays int `json:"renew_below_days"`
}

// mailCertOutput is the one line mail-cert prints.
type mailCertOutput struct {
	Renewed  bool   `json:"renewed"`
	NotAfter string `json:"not_after,omitempty"`
	SPKI     string `json:"spki_sha256"`
}

// Defaults of the toolEnv fields mail-cert reads (tests shorten them).
const (
	mailCertAcmeDir      = "/acme"
	mailCertTLSDir       = "/tls"
	mailCertCAAWait      = 10 * time.Minute
	mailCertCAAPoll      = 15 * time.Second
	mailCertPropTimeout  = 10 * time.Minute
	mailCertPropInterval = 5 * time.Second
	mailCertMaxDays      = 365
)

// mailCertObtain orders the certificate (tests replace it).
var mailCertObtain = func(c *lego.Client, req certificate.ObtainRequest) (*certificate.Resource, error) {
	return c.Certificate.Obtain(req)
}

// runMailCert is `domains mail-cert <args>`.
func runMailCert(args []string, e toolEnv) int {
	usage := func(msg string) int {
		fmt.Fprintf(e.stderr, "domains mail-cert: %s\nusage: domains mail-cert [--next-key | --switch-key]  (input: one JSON object on stdin; --next-key reads none)\n", msg)
		return exitUsage
	}
	acmeDir, tlsDir := orStr(e.acmeDir, mailCertAcmeDir), orStr(e.tlsDir, mailCertTLSDir)
	keyPath, nextPath := filepath.Join(acmeDir, "mail.key"), filepath.Join(acmeDir, "mail.next.key")
	switchKey := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--next-key":
		k, err := loadOrCreateKey(nextPath)
		if err != nil {
			fmt.Fprintf(e.stderr, "domains mail-cert --next-key: %v\n", err)
			return exitProblem
		}
		return printJSON(e, mailCertOutput{SPKI: spkiSHA256(k)}, exitOK)
	case len(args) == 1 && args[0] == "--switch-key":
		switchKey = true
	default:
		return usage("unexpected argument " + args[0])
	}
	in, err := readMailCertInput(e.stdin)
	if err != nil {
		return usage(err.Error())
	}
	fail := func(code int, err error) int {
		fmt.Fprintf(e.stderr, "domains mail-cert: %s\n", redact(err.Error(), in.Credentials))
		return code
	}
	if err := in.validate(); err != nil {
		return fail(exitUsage, err)
	}
	host := strings.ToLower(strings.TrimSuffix(in.Hostname, "."))
	issuer, known := dnsplan.IssuerFor(in.CAServer, in.CAA.Issuer)
	if in.CAA.Enabled && !known {
		// Fail closed: a certificate from a CA the hostname's CAA doesn't
		// name would be refused, or (no pin written) leave the parent's.
		return fail(exitProblem, fmt.Errorf("CAA is on but the CAA issuer domain of %s isn't known: set MAIL_CAA_ISSUER (or DNS_CAA=false)", in.CAServer))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute+orDur(e.caaWait, mailCertCAAWait))
	defer cancel()

	// The key: the reused one, or (--switch-key) the next one.
	var key *ecdsa.PrivateKey
	if switchKey {
		if key, err = readKeyFile(nextPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fail(exitProblem, errors.New("no next key to switch to: run mail-cert --next-key first"))
			}
			return fail(exitProblem, err)
		}
	} else if key, err = loadOrCreateKey(keyPath); err != nil {
		return fail(exitProblem, err)
	}

	p, err := buildProvider(&Domain{Name: host, Provider: in.Provider, Credentials: in.Credentials})
	if err != nil {
		return fail(exitFailure, err)
	}
	zone, err := toolZone(ctx, p, host, e.resolvers)
	if err != nil {
		return fail(exitFailure, err)
	}

	// The ACME account: reused while the CA and the email are the same.
	u, fresh, err := mailCertAccount(filepath.Join(acmeDir, "account.json"), in.Email, in.CAServer, e.acmeHTTPClient)
	if err != nil {
		return fail(exitFailure, err)
	}
	uri := u.reg.URI

	// The CAA at the hostname pins this account (issue only); CAA off
	// removes the pin it wrote. An unknown CA with CAA on was refused above.
	pin := in.CAA.Enabled && known
	if known {
		sp := dnsplan.Spec{Name: host, CAA: in.CAA.Enabled, Issuer: issuer, AccountURI: uri, IODEF: strings.TrimSpace(in.CAA.IODEF), NoWild: true, Main: true}
		if _, _, err := dnsplan.Apply(ctx, dnsplan.Input{Spec: sp, Zone: zone, Provider: p, ProviderName: in.Provider, Resolvers: e.resolvers}, []string{dnsplan.SetCAA}); err != nil {
			return fail(exitFailure, fmt.Errorf("setting the CAA of %s: %w", host, err))
		}
	}

	now := time.Now()
	cur, why := currentChain(tlsDir, host, key, now, time.Duration(in.RenewBelowDays)*24*time.Hour)
	if why == "" && (switchKey || fresh) {
		why = map[bool]string{true: "switching to the next key", false: "a new ACME account"}[switchKey]
	}
	if why == "" {
		return printJSON(e, mailCertOutput{Renewed: false, NotAfter: rfc3339(cur.NotAfter), SPKI: spkiSHA256(key)}, exitOK)
	}
	fmt.Fprintf(e.stderr, "domains mail-cert: issuing a certificate for %s (%s)\n", host, why)
	if pin {
		if err := waitIssuable(ctx, e.resolvers, issuer, uri, []string{host}, orDur(e.caaWait, mailCertCAAWait), orDur(e.caaPoll, mailCertCAAPoll)); err != nil {
			return fail(exitProblem, fmt.Errorf("CAA at %s not visible at the public resolvers yet (written; run again): %w", host, err))
		}
	}
	client, err := lego.NewClient(legoConfigFor(u, in.CAServer, e.acmeHTTPClient))
	if err != nil {
		return fail(exitFailure, fmt.Errorf("ACME directory %s: %w", in.CAServer, err))
	}
	ch := &dns01Provider{p: p, zoneOf: func(fqdn string) (string, error) {
		return toolZone(ctx, p, strings.TrimSuffix(fqdn, "."), e.resolvers)
	}, timeout: orDur(e.propTimeout, mailCertPropTimeout), interval: orDur(e.propInterval, mailCertPropInterval)}
	if err := client.Challenge.SetDNS01Provider(ch, dns01.CondOption(skipsPropagation(p),
		dns01.WrapPreCheck(func(_, _, _ string, _ dns01.PreCheckFunc) (bool, error) { return true, nil }))); err != nil {
		return fail(exitFailure, err)
	}
	res, err := mailCertObtain(client, certificate.ObtainRequest{Domains: []string{host}, Bundle: true, PrivateKey: key})
	if err != nil {
		return fail(exitFailure, fmt.Errorf("ACME order for %s: %w", host, err))
	}
	leaf, err := checkMailChain(res.Certificate, host, key, time.Now())
	if err != nil {
		return fail(exitProblem, fmt.Errorf("the issued certificate is refused (the old files stay): %w", err))
	}
	kp, err := encodeKeyPEM(key)
	if err != nil {
		return fail(exitProblem, err)
	}
	if err := writeTLSPair(tlsDir, kp, res.Certificate); err != nil {
		return fail(exitProblem, err)
	}
	if switchKey {
		if err := os.Rename(nextPath, keyPath); err != nil {
			return fail(exitProblem, fmt.Errorf("making the next key current: %w", err))
		}
	}
	return printJSON(e, mailCertOutput{Renewed: true, NotAfter: rfc3339(leaf.NotAfter), SPKI: spkiSHA256(key)}, exitOK)
}

func orStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDur(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func readMailCertInput(r io.Reader) (mailCertInput, error) {
	var in mailCertInput
	raw, err := io.ReadAll(io.LimitReader(r, toolInputMax+1))
	if err != nil {
		return in, fmt.Errorf("reading stdin: %w", err)
	}
	if len(raw) > toolInputMax {
		return in, fmt.Errorf("stdin holds more than %d bytes", toolInputMax)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		// Never quote the input (it holds the credentials).
		return mailCertInput{}, errors.New("stdin must be one JSON object with the documented keys (hostname, ca_server, email, provider, credentials, caa, renew_below_days)")
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return mailCertInput{}, errors.New("stdin must hold exactly one JSON object")
	}
	return in, nil
}

func (in mailCertInput) validate() error {
	host := strings.ToLower(strings.TrimSuffix(in.Hostname, "."))
	if !validHostname(host) {
		return fmt.Errorf("hostname %q is not a valid hostname", in.Hostname)
	}
	if u, err := url.Parse(in.CAServer); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("ca_server %q is not an https ACME directory URL", in.CAServer)
	}
	if in.RenewBelowDays < 1 || in.RenewBelowDays > mailCertMaxDays {
		return fmt.Errorf("renew_below_days must be 1–%d", mailCertMaxDays)
	}
	if in.Provider == "" {
		return errors.New("mail-cert needs a provider and its credentials")
	}
	return validateCredentials(in.Provider, in.Credentials)
}

// mailCertAccount loads the account at path, or registers a new one when
// there is none or it belongs to another CA / email (fresh = new).
func mailCertAccount(path, email, caServer string, hc *http.Client) (*acmeUser, bool, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var a Account
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		if a.CAServer == caServer && a.Email == email && len(a.Registration) > 0 {
			u, err := accountUser(&a)
			return u, false, err
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, err
	}
	u, a, err := registerAccount(email, caServer, hc)
	if err != nil {
		return nil, false, err
	}
	out, err := json.Marshal(a)
	if err != nil {
		return nil, false, err
	}
	if err := writeAtomic(path, out, 0o600); err != nil {
		return nil, false, err
	}
	return u, true, nil
}

// currentChain reads /tls's chain and says why it must be (re)issued
// ("" = it's fine): missing or unreadable, not exactly {host}, another
// key than key (or privkey.pem isn't key), or within renew of expiry.
func currentChain(dir, host string, key *ecdsa.PrivateKey, now time.Time, renew time.Duration) (*x509.Certificate, string) {
	chain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return nil, "no certificate yet"
	}
	leaf, err := checkMailChain(chain, host, key, now)
	if err != nil {
		return nil, err.Error()
	}
	pk, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return nil, "no private key file"
	}
	if k, err := parseKeyPEM(pk); err != nil || !k.Equal(key) {
		return nil, "privkey.pem isn't the reused key"
	}
	if leaf.NotAfter.Sub(now) < renew {
		return nil, fmt.Sprintf("expires %s, within %d days", rfc3339(leaf.NotAfter), int(renew/(24*time.Hour)))
	}
	return leaf, ""
}

// checkMailChain: the chain's leaf names exactly {host} (DNS names only,
// CN empty or host), belongs to key and is valid at now.
func checkMailChain(chain []byte, host string, key *ecdsa.PrivateKey, now time.Time) (*x509.Certificate, error) {
	leaf, err := parseLeaf(string(chain))
	if err != nil {
		return nil, err
	}
	if len(leaf.DNSNames) != 1 || !strings.EqualFold(leaf.DNSNames[0], host) || len(leaf.IPAddresses) > 0 ||
		len(leaf.EmailAddresses) > 0 || len(leaf.URIs) > 0 || (leaf.Subject.CommonName != "" && !strings.EqualFold(leaf.Subject.CommonName, host)) {
		return nil, fmt.Errorf("its names %v aren't exactly {%s}", leaf.DNSNames, host)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("its key isn't the reused mail key")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("it isn't valid now (%s – %s)", rfc3339(leaf.NotBefore), rfc3339(leaf.NotAfter))
	}
	return leaf, nil
}

// spkiSHA256 is the TLSA 3 1 1 data of key: sha256 of its SPKI, hex.
func spkiSHA256(key *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// loadOrCreateKey reads the EC P-256 key at path, creating it (0600) the
// first time.
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	k, err := readKeyFile(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return k, err
	}
	if k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}
	return k, writeKeyFile(path, k)
}

func readKeyFile(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := parseKeyPEM(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

func writeKeyFile(path string, k *ecdsa.PrivateKey) error {
	b, err := encodeKeyPEM(k)
	if err != nil {
		return err
	}
	return writeAtomic(path, b, 0o600)
}

// encodeKeyPEM: PKCS#8 "PRIVATE KEY" (what Stalwart's rustls reads).
func encodeKeyPEM(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parseKeyPEM reads a PKCS#8 EC P-256 key.
func parseKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("no PRIVATE KEY PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("not an EC P-256 key")
	}
	return ec, nil
}

// writeTLSPair writes privkey.pem and fullchain.pem as one unit (final
// review L8): a new generation directory .gen-* in dir holds both files,
// then the link current → it replaces the old one by a single rename.
// fullchain.pem / privkey.pem are links to current/<name> (made once; a
// store whose files are still plain is first moved into a generation of
// its own, so the switch to links never mixes old and new). Older
// generations are removed after the swap.
func writeTLSPair(dir string, key, chain []byte) error {
	gen := func(k, c []byte) (string, error) {
		g, err := os.MkdirTemp(dir, ".gen-")
		if err != nil {
			return "", err
		}
		// Stalwart's group reads it (the volume's setgid directory gives
		// new entries its group; the mode keeps it).
		if err := os.Chmod(g, 0o2750); err != nil {
			return "", err
		}
		if err := writeAtomic(filepath.Join(g, "privkey.pem"), k, 0o640); err != nil {
			return "", err
		}
		if err := writeAtomic(filepath.Join(g, "fullchain.pem"), c, 0o640); err != nil {
			return "", err
		}
		return filepath.Base(g), nil
	}
	swap := func(link, target string) error {
		tmp := filepath.Join(dir, ".tmp-"+filepath.Base(link)+"-link")
		_ = os.Remove(tmp)
		if err := os.Symlink(target, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, link); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return nil
	}
	cur := filepath.Join(dir, "current")
	isLink := func(name string) bool {
		t, err := os.Readlink(filepath.Join(dir, name))
		return err == nil && t == filepath.Join("current", name)
	}
	if !isLink("privkey.pem") || !isLink("fullchain.pem") {
		// Plain files (or none): current points at a copy of them first.
		oldK, kerr := os.ReadFile(filepath.Join(dir, "privkey.pem"))
		oldC, cerr := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		if kerr != nil || cerr != nil {
			oldK, oldC = key, chain // nothing to keep: the new pair at once
		}
		g, err := gen(oldK, oldC)
		if err != nil {
			return fmt.Errorf("the TLS pair: %w", err)
		}
		if err := swap(cur, g); err != nil {
			return fmt.Errorf("the TLS pair: %w", err)
		}
		for _, n := range []string{"privkey.pem", "fullchain.pem"} {
			if err := swap(filepath.Join(dir, n), filepath.Join("current", n)); err != nil {
				return fmt.Errorf("the TLS pair: %w", err)
			}
		}
	}
	g, err := gen(key, chain)
	if err != nil {
		return fmt.Errorf("the TLS pair: %w", err)
	}
	if err := swap(cur, g); err != nil {
		return fmt.Errorf("the TLS pair: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".gen-") && e.Name() != g {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	return nil
}

// writeAtomic writes data to path through a temporary file in the same
// directory (mode set before the rename): readers see the old or the new
// file, never a part.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
