package frontdoor

import (
	"context"
	"encoding/json"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Status is frontdoor-status's status.json (§20.8).
type Status struct {
	V int `json:"v"`
	// State is "leading" or "standing by" (§20.5).
	State string `json:"state"`
	// Leader is the writing front door's Lease identity (its pod name):
	// admission lets the front door's ServiceAccount write the document
	// only with leader = its own pod (kube/admission/policies.yaml
	// portcullis-frontdoor-status), so a follower can tell who wrote it.
	Leader string `json:"leader"`
	// Generation grows with every write (Unix milliseconds of the write,
	// strictly increasing in one front door); WrittenAt is the write time:
	// a follower refuses a document older than it has seen, or stale.
	Generation int64     `json:"generation"`
	WrittenAt  time.Time `json:"written_at"`
	// SnapshotOK: the round read nodeadm's snapshot; false keeps the last
	// snapshot's probes and sites (SnapshotAt), never an empty view.
	SnapshotOK bool                   `json:"snapshot_ok"`
	SnapshotAt *time.Time             `json:"snapshot_at"`
	Names      map[string]NameStatus  `json:"names"`
	Probes     map[string]ProbeStatus `json:"probes"`
	Sites      map[string]SiteStatus  `json:"sites"`
}

// NameStatus is one name's published set.
type NameStatus struct {
	Addresses  []string       `json:"addresses"`
	TTL        int            `json:"ttl"`
	WorstCaseS int            `json:"worst_case_s"`
	LastChange *time.Time     `json:"last_change"`
	Pending    *PendingStatus `json:"pending"`
}

// PendingStatus is the change waiting for its hysteresis.
type PendingStatus struct {
	Op    string    `json:"op"`
	Value string    `json:"value"`
	Since time.Time `json:"since"`
}

// ProbeStatus is one node's judgement and whether it was a blind
// prober. Verdict is healthy, unhealthy, undecided (a tie: not failed,
// so ok) or none (not an ingress node: no address of its own to judge);
// ok = healthy or undecided.
type ProbeStatus struct {
	OK           bool   `json:"ok"`
	Verdict      string `json:"verdict"`
	InternalOnly bool   `json:"internal_only"`
	Blind        bool   `json:"blind"`
}

// BuildStatus is the status document of a round.
func BuildStatus(leading bool, names []string, published map[string][]string, ttl time.Duration, c Cluster, v View) Status {
	st := Status{V: 1, State: "standing by", Names: map[string]NameStatus{}, Probes: map[string]ProbeStatus{}, Sites: map[string]SiteStatus{}}
	if leading {
		st.State = "leading"
	}
	for _, n := range names {
		ns := NameStatus{Addresses: append([]string{}, published[n]...), TTL: int(ttl / time.Second), WorstCaseS: WorstCaseSeconds(ttl)}
		sort.Strings(ns.Addresses)
		if l, ok := v.LastChange[n]; ok {
			l := l.UTC()
			ns.LastChange = &l
		}
		if p := v.Pending[n]; p != nil {
			ns.Pending = &PendingStatus{Op: p.Op, Value: p.Value, Since: p.Since.UTC()}
		}
		st.Names[n] = ns
	}
	for _, id := range sortedKeys(c.Nodes) {
		ps := ProbeStatus{Blind: v.BlindProbers[id], Verdict: "none"}
		if j, ok := v.Judgements[id]; ok {
			ps.Verdict = map[Verdict]string{Healthy: "healthy", Unhealthy: "unhealthy", Undecided: "undecided"}[j.Verdict]
			ps.OK, ps.InternalOnly = j.Verdict != Unhealthy, j.InternalOnly
		}
		st.Probes[id] = ps
	}
	st.Sites = BuildSites(c, v)
	return st
}

// StatusSink stores the status document.
type StatusSink interface {
	Write(ctx context.Context, doc []byte) error
}

// ConfigMapSink writes status.json into the ConfigMap frontdoor-status
// (created empty by the chart; the front door's Role may get and update
// only it), with the key leader = Leader (the admission policy compares
// it with the writing pod, and the follower with status.json's leader).
type ConfigMapSink struct {
	Client    kubernetes.Interface
	Namespace string
	Leader    string
}

// StatusLeaderKey is the ConfigMap key naming the writer.
const StatusLeaderKey = "leader"

// StatusConfigMap is the status ConfigMap's name.
const StatusConfigMap = "frontdoor-status"

func (s ConfigMapSink) Write(ctx context.Context, doc []byte) error {
	cms := s.Client.CoreV1().ConfigMaps(s.Namespace)
	cm, err := cms.Get(ctx, StatusConfigMap, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if cm.Data["status.json"] == string(doc) && cm.Data[StatusLeaderKey] == s.Leader {
		return nil
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data["status.json"] = string(doc)
	cm.Data[StatusLeaderKey] = s.Leader
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// LastChanges reads each name's last written change from the status an
// earlier front door left (Engine.Seed): a new leader keeps the one
// change per name per 60 s.
func (s ConfigMapSink) LastChanges(ctx context.Context) (map[string]time.Time, error) {
	cm, err := s.Client.CoreV1().ConfigMaps(s.Namespace).Get(ctx, StatusConfigMap, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return ParseLastChanges(cm.Data["status.json"])
}

// ParseLastChanges is names.*.last_change of a status document ("" = none).
func ParseLastChanges(doc string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if doc == "" {
		return out, nil
	}
	var st Status
	if err := json.Unmarshal([]byte(doc), &st); err != nil {
		return nil, err
	}
	for n, ns := range st.Names {
		if ns.LastChange != nil {
			out[n] = *ns.LastChange
		}
	}
	return out, nil
}

// Metrics are the front door's Prometheus series (§20.8).
type Metrics struct {
	Registry  *prometheus.Registry
	addresses *prometheus.GaugeVec
	unhealthy *prometheus.GaugeVec
	siteOK    *prometheus.GaugeVec
	blind     *prometheus.GaugeVec
	snapOK    prometheus.Gauge
}

// NewMetrics registers portcullis_frontdoor_addresses{name},
// portcullis_frontdoor_unhealthy_published_seconds{name,address},
// portcullis_frontdoor_site_healthy{site} and
// portcullis_frontdoor_blind_probers{site}.
func NewMetrics() *Metrics {
	m := &Metrics{Registry: prometheus.NewRegistry(),
		addresses: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_frontdoor_addresses",
			Help: "Addresses published in the name's address set."}, []string{"name"}),
		unhealthy: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_frontdoor_unhealthy_published_seconds",
			Help: "How long a published address has been unhealthy (0 while healthy)."}, []string{"name", "address"}),
		siteOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_frontdoor_site_healthy",
			Help: "1 while an ingress node of the site is ok (healthy or undecided), else 0."}, []string{"site"}),
		blind: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_frontdoor_blind_probers",
			Help: "Probers of the site whose last counted round was blind (their own uplink lost)."}, []string{"site"}),
	}
	m.snapOK = prometheus.NewGauge(prometheus.GaugeOpts{Name: "portcullis_frontdoor_snapshot_ok",
		Help: "1 when the last round read nodeadm's snapshot; 0 = the site series are the last good round's (stale)."})
	m.Registry.MustRegister(m.addresses, m.unhealthy, m.siteOK, m.blind, m.snapOK)
	return m
}

// SnapshotFailed marks a round without nodeadm's snapshot: the other
// series keep the last good round's values, stale while this is 0.
func (m *Metrics) SnapshotFailed() { m.snapOK.Set(0) }

// Update sets the series from a round.
func (m *Metrics) Update(now time.Time, published map[string][]string, c Cluster, v View) {
	m.snapOK.Set(1)
	owner := map[string]string{}
	for id, n := range c.Nodes {
		for _, a := range n.Public {
			owner[a] = id
		}
	}
	m.unhealthy.Reset()
	// The site series are the snapshot's sites only (a removed site's go).
	m.siteOK.Reset()
	m.blind.Reset()
	for site, s := range BuildSites(c, v) {
		ok := 0.0
		if s.Healthy {
			ok = 1
		}
		m.siteOK.WithLabelValues(site).Set(ok)
		m.blind.WithLabelValues(site).Set(float64(s.BlindProbers))
	}
	for name, as := range published {
		m.addresses.WithLabelValues(name).Set(float64(len(as)))
		for _, a := range as {
			s := 0.0
			if since, ok := v.UnhealthySince[owner[a]]; ok {
				s = now.Sub(since).Seconds()
			}
			m.unhealthy.WithLabelValues(name, a).Set(s)
		}
	}
}

func marshalStatus(st Status) ([]byte, error) { return json.Marshal(st) }
