package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// The HA Traefik's default certificate (Task 31 fix round 2, M3; found
// live: a starting Traefik served its own self-signed default until the
// domains HTTP provider's first answer, because hostPort sends traffic to
// a pod that isn't Ready yet). The ingress namespace's Secret
// DefaultCertSecret, type kubernetes.io/tls, holds only the served pair
// (tls.crt, tls.key): the chart projects it into Traefik's watched
// directory as default-cert/*.crt|key, which the file provider never reads
// as configuration, beside the chart's own 00-default-cert.yml that names
// those files as the default store's certificate (security review: the
// front door writes a certificate, never Traefik configuration; admission
// portcullis-ingress-default-cert holds it to updates of exactly those two
// keys). So a Traefik serves the main domain's certificate from its first
// handshake, for no SNI and an unknown SNI too, and a renewed pair reloads
// on its own (the projection's swap fires the watch). Traefik v3.7.17,
// pinned source: a default certificate that fails to load leaves the
// store's default nil (pkg/tls/tlsmanager.go), which GetDefaultCertificate
// then dereferences (pkg/tls/certificate_store.go) — so only a pair the
// domains service would serve is ever written.
const DefaultCertSecret = "traefik-default-cert"

// DefaultCertMirror keeps DefaultCertSecret's pair equal to the served
// pair of frontdoor-cert (leader only; the CLI creates it before an HA
// release, ha.sh ha_default_cert_sync).
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
// one), said once per reason; a Secret of another type is refused (the
// CLI recreates it). No key material is ever logged.
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
	if sec.Type != corev1.SecretTypeTLS {
		return false, fmt.Errorf("%s/%s is of type %q, not %s (./portcullis up recreates it)", m.Namespace, DefaultCertSecret, sec.Type, corev1.SecretTypeTLS)
	}
	if len(sec.Data) == 2 && string(sec.Data[corev1.TLSCertKey]) == served.ChainPEM && string(sec.Data[corev1.TLSPrivateKeyKey]) == served.KeyPEM {
		return false, nil
	}
	wctx, cancel, err := m.Fence.WriteContext(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	// Exactly the pair (anything else in the Secret is dropped). The read's
	// resourceVersion: a concurrent writer makes it fail.
	sec.Data = map[string][]byte{corev1.TLSCertKey: []byte(served.ChainPEM), corev1.TLSPrivateKeyKey: []byte(served.KeyPEM)}
	sec.StringData = nil
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
