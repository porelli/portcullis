// Package metrics is mailctl's Prometheus registry (contract §19.8),
// served only on its portcullis-metrics-mail address (MAILCTL_METRICS_ADDR,
// the alias mailctl-metrics), behind Basic auth (MAILCTL_METRICS_SECRET_FILE).
package metrics

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds mailctl's gauges on their own registry (no Go runtime or
// process collectors: nothing but the mail metrics is exposed).
type Metrics struct {
	Registry      *prometheus.Registry
	Check         *prometheus.GaugeVec // portcullis_mail_check{check} 0/1
	DKIMStage     *prometheus.GaugeVec // portcullis_mail_dkim_stage{domain,stage}
	QueueMessages prometheus.Gauge     // portcullis_mail_queue_messages
	QueueDeferred prometheus.Gauge     // portcullis_mail_queue_deferred_ratio
}

// New registers every gauge.
func New() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Check: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "portcullis_mail_check", Help: "1 when the mail check passes, 0 when it fails.",
		}, []string{"check"}),
		DKIMStage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "portcullis_mail_dkim_stage", Help: "1 for each DKIM key's current stage per domain.",
		}, []string{"domain", "stage"}),
		QueueMessages: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "portcullis_mail_queue_messages", Help: "Messages in Stalwart's outbound queue.",
		}),
		QueueDeferred: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "portcullis_mail_queue_deferred_ratio", Help: "Share of queued messages whose last attempt was deferred.",
		}),
	}
	m.Registry.MustRegister(m.Check, m.DKIMStage, m.QueueMessages, m.QueueDeferred)
	return m
}

// User is the scrape login (Prometheus' job mailctl, as for mail).
const User = "prometheus"

// MinSecret: a shorter metrics secret refuses every scrape.
const MinSecret = 32

// Handler serves /metrics behind Basic auth (final review I1): User and
// the secret in secretFile (re-read on every request; unreadable or
// shorter than MinSecret refuses everything); anything else is 404.
// readSecret is api.ReadSecret (passed in: no import cycle).
func (m *Metrics) Handler(secretFile string, readSecret func(string, int) (string, error), logf func(string, ...any)) http.Handler {
	mux := http.NewServeMux()
	inner := promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		secret, err := readSecret(secretFile, MinSecret)
		if err != nil {
			if logf != nil {
				logf("metrics: refusing every scrape: the metrics secret %v", err)
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		want := sha256.Sum256([]byte(User + "\x00" + secret))
		u, p, ok := r.BasicAuth()
		got := sha256.Sum256([]byte(u + "\x00" + p))
		if !ok || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="mailctl"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
	return mux
}

// SetChecks replaces portcullis_mail_check with one value per check id
// (1 ok / info, 0 warning / problem).
func (m *Metrics) SetChecks(vals map[string]float64) {
	m.Check.Reset()
	for id, v := range vals {
		m.Check.WithLabelValues(id).Set(v)
	}
}

// Stage is one DKIM key's (domain, stage).
type Stage struct{ Domain, Stage string }

// SetStatus sets the status gauges: the queue and every DKIM key's stage.
// The certificate's expiry is core's own metric (contract §19.8).
func (m *Metrics) SetStatus(messages, deferred int, stages []Stage) {
	m.QueueMessages.Set(float64(messages))
	ratio := 0.0
	if messages > 0 {
		ratio = float64(deferred) / float64(messages)
	}
	m.QueueDeferred.Set(ratio)
	m.DKIMStage.Reset()
	for _, s := range stages {
		m.DKIMStage.WithLabelValues(s.Domain, s.Stage).Add(1)
	}
}
