package machines

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/logx"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// Provider names the mail server (GET /v1/provider, MailStatus.provider).
const (
	ProviderName    = "Stalwart"
	ProviderVersion = "1.1.0" // the version the adapter is built and schema-checked for
)

// ProviderInfo is MailStatus.provider.
type ProviderInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CertStatus is MailStatus.cert: the certificate the listeners serve
// (null when none could be read).
type CertStatus struct {
	NotAfter   time.Time `json:"not_after"`
	SANs       []string  `json:"sans"`
	SPKISHA256 string    `json:"spki_sha256"`
}

// CertOf is a served leaf's status.
func CertOf(c *x509.Certificate) *CertStatus {
	sans := make([]string, 0, len(c.DNSNames))
	for _, n := range c.DNSNames {
		sans = append(sans, strings.ToLower(n))
	}
	sort.Strings(sans)
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return &CertStatus{NotAfter: c.NotAfter.UTC(), SANs: sans, SPKISHA256: hex.EncodeToString(sum[:])}
}

// QueueStatus is MailStatus.queue.
type QueueStatus struct {
	Messages int `json:"messages"`
	Deferred int `json:"deferred"`
}

// FormerStatus is one parked account.
type FormerStatus struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Since    time.Time `json:"since"`
}

// MailStatus is GET /v1/status (contract §19.5).
type MailStatus struct {
	Bootstrap  bool           `json:"bootstrap"`
	Provider   ProviderInfo   `json:"provider"`
	Cert       *CertStatus    `json:"cert"`
	DKIM       []DKIMStatus   `json:"dkim"`
	MTASTS     []MTASTSStatus `json:"mtasts"`
	DMARC      []DMARCStatus  `json:"dmarc"`
	Queue      QueueStatus    `json:"queue"`
	RestoredAt *time.Time     `json:"restored_at"`
	Former     []FormerStatus `json:"former"`
	// DNS: each mail domain's set hash (DNSHashes).
	DNS map[string]string `json:"dns"`
}

// queueFetchMax bounds the messages read for the deferred count.
const queueFetchMax = 500

// certCacheFor bounds how often Status probes the listeners.
const certCacheFor = time.Minute

// Cert is the certificate the submissions listener serves (nil = none
// could be read: no Serving probe, or it failed). Probed at most once a
// minute.
func (m *Machines) Cert(ctx context.Context) *CertStatus {
	if m.Serving == nil {
		return nil
	}
	m.certMu.Lock()
	defer m.certMu.Unlock()
	if m.certSeen != nil && m.Now().Sub(m.certAt) < certCacheFor {
		c := *m.certSeen
		return &c
	}
	leaf, err := m.Serving(ctx)
	if err != nil {
		if m.Logf != nil {
			m.Logf("status: the served certificate couldn't be read: %s", logx.Redact(err.Error()))
		}
		m.certSeen = nil
		return nil
	}
	m.certSeen, m.certAt = CertOf(leaf), m.Now()
	c := *m.certSeen
	return &c
}

// ForgetCert drops the cached served certificate (after a TLS reload).
func (m *Machines) ForgetCert() {
	m.certMu.Lock()
	m.certSeen = nil
	m.certMu.Unlock()
}

// Queue counts the queued messages; deferred = a recipient already retried.
func (m *Machines) Queue(ctx context.Context) (QueueStatus, error) {
	// The total from the first page, at most queueFetchMax ids read
	// (final review L12: a large queue never pages to the cap); deferred
	// is counted over those (a lower bound past queueFetchMax).
	ids, total, err := m.C.QueryFirst(ctx, "QueuedMessage", nil, queueFetchMax)
	if err != nil {
		return QueueStatus{}, err
	}
	q := QueueStatus{Messages: total}
	if len(ids) == 0 {
		return q, nil
	}
	var ms []struct {
		Recipients map[string]struct {
			RetryCount int `json:"retryCount"`
		} `json:"recipients"`
	}
	if err := m.C.Get(ctx, "QueuedMessage", ids, []string{"recipients"}, &ms); err != nil {
		return QueueStatus{}, err
	}
	for _, msg := range ms {
		for _, r := range msg.Recipients {
			if r.RetryCount > 0 {
				q.Deferred++
				break
			}
		}
	}
	return q, nil
}

// Status is MailStatus. Any Stalwart failure is an error (the API's 503).
func (m *Machines) Status(ctx context.Context, bootstrapped bool) (MailStatus, error) {
	cert := m.Cert(ctx)
	q, err := m.Queue(ctx)
	if err != nil {
		return MailStatus{}, err
	}
	dk, ms, ds := m.Statuses(ctx)
	p := m.Store.Get()
	former := []FormerStatus{}
	for uuid, f := range p.Former {
		former = append(former, FormerStatus{ID: "former-" + uuid, Username: f.Username, Since: f.Since.UTC()})
	}
	sort.Slice(former, func(i, j int) bool { return former[i].ID < former[j].ID })
	return MailStatus{Bootstrap: bootstrapped, Provider: ProviderInfo{Name: ProviderName, Version: ProviderVersion}, Cert: cert,
		DKIM: dk, MTASTS: ms, DMARC: ds, Queue: q,
		RestoredAt: p.RestoredAt, Former: former, DNS: m.DNSHashes()}, nil
}

func init() {
	stalwart.Used = append(stalwart.Used,
		stalwart.Use{Object: "x:QueuedMessage", Field: "recipients"},
		stalwart.Use{Object: "x:QueuedRecipient", Field: "retryCount"},
	)
}
