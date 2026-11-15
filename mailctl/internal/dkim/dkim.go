// Package dkim is the DKIM key state machine (contract §19.7), per domain
// and algorithm: pending (created in Stalwart with stage pending, its TXT
// wanted) → active once both public resolvers serve the exact TXT (the
// previous active key becomes retiring at the same step) → retired after
// 7 days (the TXT goes) → destroyed 30 days later. Rotation every
// MAIL_DKIM_ROTATE, or at once on dkim-rotate. Step is pure; the caller
// executes its actions in Stalwart and commits the returned state.
package dkim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sort"
	"time"
)

// Stages and algorithms.
const (
	Pending  = "pending"
	Active   = "active"
	Retiring = "retiring"
	Retired  = "retired"

	Ed25519 = "ed25519"
	RSA     = "rsa"

	RetireAfter = 7 * 24 * time.Hour
	DeleteAfter = 30 * 24 * time.Hour
	StuckAfter  = 24 * time.Hour
)

// Algorithms are both, always.
var Algorithms = []string{Ed25519, RSA}

// Key is one DKIM key. The private key never leaves the create step.
type Key struct {
	Domain    string    `json:"domain"`
	Algorithm string    `json:"algorithm"`
	Selector  string    `json:"selector"`
	Stage     string    `json:"stage"`
	Since     time.Time `json:"since"`
	ID        string    `json:"id"`         // Stalwart's DkimSignature id ("" = not created yet)
	PublicKey string    `json:"public_key"` // Stalwart's publicKey (the p= value)
}

// State is every domain's keys.
type State struct {
	Keys      []Key           `json:"keys"`
	RotateNow map[string]bool `json:"rotate_now"`
}

// Action is one Stalwart change.
type Action struct {
	Kind     string // create | stage | destroy
	Key      Key    // create: the new key (Selector, Algorithm, Domain)
	ID       string // stage / destroy
	Stage    string // stage
	Selector string
}

// TXT is a key's record value.
func TXT(k Key) string {
	return fmt.Sprintf("v=DKIM1; k=%s; p=%s", k.Algorithm, k.PublicKey)
}

// Name is a key's record name.
func Name(k Key) string { return k.Selector + "._domainkey." + k.Domain }

// Published are the domain's keys whose TXT is wanted (pending, active,
// retiring; with a public key).
func Published(st State, domain string) []Key {
	var out []Key
	for _, k := range st.Keys {
		if k.Domain == domain && k.PublicKey != "" && (k.Stage == Pending || k.Stage == Active || k.Stage == Retiring) {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Selector < out[j].Selector })
	return out
}

// Selector is v1-<algorithm>-YYYYMMDD, with -2, -3 … when taken.
func Selector(st State, domain, algo string, now time.Time) string {
	base := fmt.Sprintf("v1-%s-%s", algo, now.UTC().Format("20060102"))
	taken := map[string]bool{}
	for _, k := range st.Keys {
		if k.Domain == domain {
			taken[k.Selector] = true
		}
	}
	s := base
	for i := 2; taken[s]; i++ {
		s = fmt.Sprintf("%s-%d", base, i)
	}
	return s
}

func clone(st State) State {
	c := State{Keys: append([]Key(nil), st.Keys...), RotateNow: map[string]bool{}}
	for k, v := range st.RotateNow {
		c.RotateNow[k] = v
	}
	return c
}

// Step advances one domain. visible(name, value) reports both public
// resolvers serving exactly value at name (a failed lookup is false).
// The returned state holds the new keys without an ID: the caller sets ID
// and PublicKey from Stalwart's answer to the create actions.
func Step(st State, domain string, now time.Time, rotateEvery time.Duration, visible func(name, value string) bool) (State, []Action) {
	ns := clone(st)
	var acts []Action
	var keep []Key
	for _, k := range ns.Keys {
		if k.Domain != domain {
			keep = append(keep, k)
			continue
		}
		switch k.Stage {
		case Retiring:
			if now.Sub(k.Since) >= RetireAfter {
				k.Stage, k.Since = Retired, now
				acts = append(acts, Action{Kind: "stage", ID: k.ID, Stage: Retired, Selector: k.Selector})
			}
		case Retired:
			if now.Sub(k.Since) >= DeleteAfter {
				if k.ID != "" {
					acts = append(acts, Action{Kind: "destroy", ID: k.ID, Selector: k.Selector})
				}
				continue
			}
		}
		keep = append(keep, k)
	}
	ns.Keys = keep
	for _, algo := range Algorithms {
		idx := func(stage string) int {
			for i, k := range ns.Keys {
				if k.Domain == domain && k.Algorithm == algo && k.Stage == stage {
					return i
				}
			}
			return -1
		}
		p, a := idx(Pending), idx(Active)
		if p >= 0 && ns.Keys[p].ID != "" && ns.Keys[p].PublicKey != "" && visible(Name(ns.Keys[p]), TXT(ns.Keys[p])) {
			if a >= 0 {
				ns.Keys[a].Stage, ns.Keys[a].Since = Retiring, now
				acts = append(acts, Action{Kind: "stage", ID: ns.Keys[a].ID, Stage: Retiring, Selector: ns.Keys[a].Selector})
			}
			ns.Keys[p].Stage, ns.Keys[p].Since = Active, now
			acts = append(acts, Action{Kind: "stage", ID: ns.Keys[p].ID, Stage: Active, Selector: ns.Keys[p].Selector})
			p, a = -1, idx(Active)
		}
		if p >= 0 && ns.Keys[p].ID == "" {
			// A create that failed: try again with the same selector.
			acts = append(acts, Action{Kind: "create", Key: ns.Keys[p]})
			continue
		}
		due := a < 0 || now.Sub(ns.Keys[a].Since) >= rotateEvery || ns.RotateNow[domain]
		if p < 0 && due {
			k := Key{Domain: domain, Algorithm: algo, Selector: Selector(ns, domain, algo, now), Stage: Pending, Since: now}
			ns.Keys = append(ns.Keys, k)
			acts = append(acts, Action{Kind: "create", Key: k})
		}
	}
	delete(ns.RotateNow, domain)
	return ns, acts
}

// Stuck are the domain's pending keys older than 24 h.
func Stuck(st State, domain string, now time.Time) []Key {
	var out []Key
	for _, k := range st.Keys {
		if k.Domain == domain && k.Stage == Pending && now.Sub(k.Since) > StuckAfter {
			out = append(out, k)
		}
	}
	return out
}

// Generate makes a key pair: the PKCS#8 PEM private key (sent once to
// Stalwart, never kept) and the p= values Stalwart may derive from it (to
// check its answer): ed25519's raw key; RSA's SubjectPublicKeyInfo or
// PKCS#1 RSAPublicKey.
func Generate(algo string) (pemKey string, pubs []string, err error) {
	var der []byte
	switch algo {
	case Ed25519:
		pk, sk, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return "", nil, gerr
		}
		der, err = x509.MarshalPKCS8PrivateKey(sk)
		pubs = []string{b64(pk)}
	case RSA:
		sk, gerr := rsa.GenerateKey(rand.Reader, 2048)
		if gerr != nil {
			return "", nil, gerr
		}
		der, err = x509.MarshalPKCS8PrivateKey(sk)
		if err == nil {
			var spki []byte
			spki, err = x509.MarshalPKIXPublicKey(&sk.PublicKey)
			pubs = []string{b64(spki), b64(x509.MarshalPKCS1PublicKey(&sk.PublicKey))}
		}
	default:
		return "", nil, fmt.Errorf("dkim: unknown algorithm %q", algo)
	}
	if err != nil {
		return "", nil, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), pubs, nil
}

// Variant is Stalwart's DkimSignature @type for an algorithm.
func Variant(algo string) string {
	if algo == RSA {
		return "Dkim1RsaSha256"
	}
	return "Dkim1Ed25519Sha256"
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
