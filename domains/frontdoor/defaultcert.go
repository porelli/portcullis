package frontdoor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The HA Traefik's default certificate (Task 31 fix round 2, M3; found
// live: a starting Traefik served its own self-signed default until the
// domains HTTP provider's first answer, because hostPort sends traffic to
// a pod that isn't Ready yet). Traefik's file provider loads one more file
// from its watched directory, DefaultCertKey of the Secret
// DefaultCertSecret in the ingress namespace (projected by the chart as
// 00-default-cert.yml, sorted first). It is a dynamic document whose
// only content is tls.stores.default.defaultCertificate: the front door's
// served pair inline. So a Traefik serves the main domain's certificate
// from its first handshake, for no SNI and an unknown SNI too, and a
// renewed pair is reloaded on its own (FILE_WATCH). Traefik v3.7.17,
// pinned source: one provider owns the default store (two drop it,
// pkg/server/aggregator.go); a default certificate that fails to load
// leaves the store's default nil (pkg/tls/tlsmanager.go), which
// GetDefaultCertificate then dereferences (pkg/tls/certificate_store.go)
// — so only a pair the domains service would serve is ever written, and
// the chart's projection is not optional (no key = no pod).
const (
	DefaultCertSecret = "traefik-default-cert"
	DefaultCertKey    = "default-cert.yml"
)

type defaultCertDoc struct {
	TLS struct {
		Stores map[string]defaultCertStore `json:"stores"`
	} `json:"tls"`
}

type defaultCertStore struct {
	DefaultCertificate defaultCertPair `json:"defaultCertificate"`
}

type defaultCertPair struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// DefaultCertDoc is the file-provider document for chainPEM / keyPEM
// (JSON, which Traefik's .yml decoder reads as YAML).
func DefaultCertDoc(chainPEM, keyPEM string) ([]byte, error) {
	var d defaultCertDoc
	d.TLS.Stores = map[string]defaultCertStore{"default": {DefaultCertificate: defaultCertPair{CertFile: chainPEM, KeyFile: keyPEM}}}
	return json.Marshal(d)
}

// defaultCertOf is the pair a document holds ("", "" when it holds none
// or doesn't decode).
func defaultCertOf(doc []byte) (string, string) {
	var d defaultCertDoc
	if json.Unmarshal(doc, &d) != nil {
		return "", ""
	}
	p := d.TLS.Stores["default"].DefaultCertificate
	return p.CertFile, p.KeyFile
}

// DefaultCertMirror keeps DefaultCertSecret's document equal to the
// served pair of frontdoor-cert (leader only; the CLI seeds it before an
// HA release, ha.sh ha_default_cert_sync).
type DefaultCertMirror struct {
	Client kubernetes.Interface
	// Namespace is the ingress namespace (the Secret's).
	Namespace string
	Store     CertStore
	// Check is servableHA's: the pair is the main domain's, valid now.
	Check func(chainPEM, keyPEM string, now time.Time) error
	Fence WriteFence
	Now   func() time.Time
	Log   func(string)

	lastWhy string
}

// ErrNoDefaultCertSecret: the Secret isn't there (the CLI creates it).
var ErrNoDefaultCertSecret = errors.New("the Secret " + DefaultCertSecret + " doesn't exist yet (./portcullis up creates it)")

// Sync writes the served pair into the Secret when it differs and the
// domains service would serve it; it reports whether it wrote. A pair
// that isn't servable is never written (the Secret keeps the last good
// one), said once per reason. No key material is ever logged.
func (m *DefaultCertMirror) Sync(ctx context.Context) (bool, error) {
	if m.Fence == nil || !m.Fence.Leading() {
		return false, nil
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now()
	}
	served, err := m.Store.LoadServed(ctx)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", CertSecret, err)
	}
	if m.Check == nil {
		return false, errors.New("internal: no certificate check")
	}
	if err := m.Check(served.ChainPEM, served.KeyPEM, now); err != nil {
		m.say(fmt.Sprintf("frontdoor: Traefik's default certificate is kept: the served pair isn't servable (%v)", err))
		return false, nil
	}
	m.lastWhy = ""
	sec, err := m.Client.CoreV1().Secrets(m.Namespace).Get(ctx, DefaultCertSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, ErrNoDefaultCertSecret
	}
	if err != nil {
		return false, fmt.Errorf("reading %s/%s: %w", m.Namespace, DefaultCertSecret, err)
	}
	if c, k := defaultCertOf(sec.Data[DefaultCertKey]); c == served.ChainPEM && k == served.KeyPEM {
		return false, nil
	}
	doc, err := DefaultCertDoc(served.ChainPEM, served.KeyPEM)
	if err != nil {
		return false, err
	}
	wctx, cancel, err := m.Fence.WriteContext(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}
	sec.Data[DefaultCertKey] = doc
	// The read's resourceVersion: a concurrent writer makes it fail.
	if _, err := m.Client.CoreV1().Secrets(m.Namespace).Update(wctx, sec, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("writing %s/%s: %w", m.Namespace, DefaultCertSecret, err)
	}
	if na, err := NotAfter(served.ChainPEM); err == nil {
		m.say(fmt.Sprintf("frontdoor: Traefik's default certificate is the served one now (until %s)", na.UTC().Format(time.RFC3339)))
	} else {
		m.say("frontdoor: Traefik's default certificate is the served one now")
	}
	m.lastWhy = ""
	return true, nil
}

func (m *DefaultCertMirror) say(why string) {
	if why == m.lastWhy || m.Log == nil {
		m.lastWhy = why
		return
	}
	m.lastWhy = why
	m.Log(why)
}
