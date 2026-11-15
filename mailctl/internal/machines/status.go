package machines

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/portcullis/mailctl/internal/stalwart"
)

// StalwartVersion is the version mailctl is built and schema-checked for.
const StalwartVersion = "1.1.0"

// CertStatus is MailStatus.cert (null when Stalwart holds no certificate
// for MAIL_HOSTNAME).
type CertStatus struct {
	NotAfter time.Time `json:"not_after"`
	SANs     []string  `json:"sans"`
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
	Bootstrap       bool           `json:"bootstrap"`
	StalwartVersion string         `json:"stalwart_version"`
	Cert            *CertStatus    `json:"cert"`
	DKIM            []DKIMStatus   `json:"dkim"`
	MTASTS          []MTASTSStatus `json:"mtasts"`
	DMARC           []DMARCStatus  `json:"dmarc"`
	Queue           QueueStatus    `json:"queue"`
	ClientIP        string         `json:"client_ip"`
	RestoredAt      *time.Time     `json:"restored_at"`
	TimerSeenAt     *time.Time     `json:"timer_seen_at"`
	Former          []FormerStatus `json:"former"`
}

// queueFetchMax bounds the messages read for the deferred count.
const queueFetchMax = 500

// Cert reads Stalwart's certificate for MAIL_HOSTNAME (nil = none).
func (m *Machines) Cert(ctx context.Context) (*CertStatus, error) {
	ids, err := m.C.Query(ctx, "Certificate", nil)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	var cs []struct {
		NotAfter time.Time       `json:"notValidAfter"`
		SANs     map[string]bool `json:"subjectAlternativeNames"`
	}
	if err := m.C.Get(ctx, "Certificate", ids, []string{"notValidAfter", "subjectAlternativeNames"}, &cs); err != nil {
		return nil, err
	}
	var best *CertStatus
	for _, c := range cs {
		if !c.SANs[m.Cfg.Hostname] {
			continue
		}
		if best == nil || c.NotAfter.After(best.NotAfter) {
			sans := make([]string, 0, len(c.SANs))
			for s := range c.SANs {
				sans = append(sans, strings.ToLower(s))
			}
			sort.Strings(sans)
			best = &CertStatus{NotAfter: c.NotAfter.UTC(), SANs: sans}
		}
	}
	return best, nil
}

// Queue counts the queued messages; deferred = a recipient already retried.
func (m *Machines) Queue(ctx context.Context) (QueueStatus, error) {
	ids, err := m.C.Query(ctx, "QueuedMessage", nil)
	if err != nil {
		return QueueStatus{}, err
	}
	q := QueueStatus{Messages: len(ids)}
	if len(ids) == 0 {
		return q, nil
	}
	if len(ids) > queueFetchMax {
		ids = ids[:queueFetchMax]
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
func (m *Machines) Status(ctx context.Context, bootstrapped bool, clientIP string) (MailStatus, error) {
	cert, err := m.Cert(ctx)
	if err != nil {
		return MailStatus{}, err
	}
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
	return MailStatus{Bootstrap: bootstrapped, StalwartVersion: StalwartVersion, Cert: cert,
		DKIM: dk, MTASTS: ms, DMARC: ds, Queue: q, ClientIP: clientIP,
		RestoredAt: p.RestoredAt, TimerSeenAt: p.TimerSeenAt, Former: former}, nil
}

func init() {
	stalwart.Used = append(stalwart.Used,
		stalwart.Use{Object: "x:Certificate", Field: "notValidAfter"},
		stalwart.Use{Object: "x:Certificate", Field: "subjectAlternativeNames"},
		stalwart.Use{Object: "x:QueuedMessage", Field: "recipients"},
		stalwart.Use{Object: "x:QueuedRecipient", Field: "retryCount"},
	)
}
