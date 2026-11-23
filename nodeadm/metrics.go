package main

// The R7 gauges on :9105 (contract §20.2 "Metrics"; Prometheus only, which
// gets no cluster-scoped right): portcullis_node_ready{node},
// portcullis_quorum_voters{system,state}, portcullis_volume_robustness
// {volume}, portcullis_pg_sync_standbys, portcullis_fencing_ready{node},
// portcullis_failover_total{kind}, portcullis_vault_active; the small-node
// inputs of PortcullisSmallNodePressure (Task 32):
// portcullis_node_class{node,class}, portcullis_node_pressure
// {node,condition}, portcullis_node_allocatable_memory_bytes{node},
// portcullis_node_requested_memory_bytes{node}; and
// portcullis_nodeadm_snapshot_age_seconds and
// portcullis_nodeadm_start_time_seconds (PortcullisNodeadmBlind).
// Refreshed by every snapshot (the metrics loop takes one every 30 s).
//
// A failed snapshot drops every cluster gauge (absent series, never the
// last healthy value: "couldn't ask" is not "healthy"); the snapshot age
// keeps growing, so PortcullisNodeadmBlind says so. Postgres's gauge is
// absent while CNPG's Cluster can't be read (no instance known).

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// The node conditions exported as portcullis_node_pressure.
var pressureConditions = []string{"MemoryPressure", "DiskPressure", "PIDPressure"}

type Metrics struct {
	reg         *prometheus.Registry
	nodeReady   *prometheus.GaugeVec
	quorum      *prometheus.GaugeVec
	robustness  *prometheus.GaugeVec
	pgSync      *prometheus.GaugeVec // no labels: absent until a snapshot reads CNPG
	fencing     *prometheus.GaugeVec
	failovers   *prometheus.CounterVec
	vaultActive *prometheus.GaugeVec // no labels: absent after a failed snapshot
	nodeClass   *prometheus.GaugeVec
	pressure    *prometheus.GaugeVec
	allocMem    *prometheus.GaugeVec
	reqMem      *prometheus.GaugeVec

	// mu: observe / failed hold it for writing, a scrape for reading, so a
	// scrape never sees a half-updated set.
	mu     sync.RWMutex
	now    func() time.Time
	lastOK atomic.Int64 // UnixNano of the last successful snapshot (the process start before one)
}

func newMetrics() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(), now: time.Now,
		nodeReady: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_node_ready",
			Help: "1 while the node is Ready."}, []string{"node"}),
		quorum: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_quorum_voters",
			Help: "Voters of each quorum system: state total (the configured voters) or healthy."}, []string{"system", "state"}),
		robustness: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_volume_robustness",
			Help: "A replicated volume's robustness: 0 healthy, 1 degraded, 2 faulted, 3 unknown."}, []string{"volume"}),
		pgSync: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_pg_sync_standbys",
			Help: "Postgres synchronous standbys."}, nil),
		fencing: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_fencing_ready",
			Help: "1 while the node's Self Node Remediation agent is Ready."}, []string{"node"}),
		failovers: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "portcullis_failover_total",
			Help: "Failovers seen (kind postgres: a new primary)."}, []string{"kind"}),
		vaultActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_vault_active",
			Help: "1 while at least one Vault voter serves requests (is the active node or a standby with a reachable active node), else 0."}, nil),
		nodeClass: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_node_class",
			Help: "1 for the node's class (label portcullis.io/class: small, home or cloud)."}, []string{"node", "class"}),
		pressure: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_node_pressure",
			Help: "1 while the node's condition (MemoryPressure, DiskPressure, PIDPressure) is True."}, []string{"node", "condition"}),
		allocMem: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_node_allocatable_memory_bytes",
			Help: "The node's allocatable memory."}, []string{"node"}),
		reqMem: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_node_requested_memory_bytes",
			Help: "The memory requests of the pods scheduled on the node (not finished)."}, []string{"node"}),
	}
	m.lastOK.Store(m.now().UnixNano())
	age := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "portcullis_nodeadm_snapshot_age_seconds",
		Help: "Seconds since nodeadm's last successful cluster snapshot (since its start before the first)."},
		func() float64 { return m.now().Sub(time.Unix(0, m.lastOK.Load())).Seconds() })
	// The process's start (PortcullisNodeadmBlind counts restarts with
	// changes(): a nodeadm restarting faster than the age can grow).
	start := prometheus.NewGauge(prometheus.GaugeOpts{Name: "portcullis_nodeadm_start_time_seconds",
		Help: "Unix time this nodeadm process started."})
	start.Set(float64(m.now().UnixNano()) / 1e9)
	m.reg.MustRegister(start)
	m.reg.MustRegister(m.nodeReady, m.quorum, m.robustness, m.pgSync, m.fencing, m.failovers, m.vaultActive,
		m.nodeClass, m.pressure, m.allocMem, m.reqMem, age)
	m.failovers.WithLabelValues("postgres")
	return m
}

var robustnessValue = map[string]float64{"healthy": 0, "degraded": 1, "faulted": 2, "unknown": 3}

// observe sets the gauges from a successful snapshot (nodes gone are
// dropped).
func (m *Metrics) observe(s *Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reset()
	for _, n := range s.Nodes {
		m.nodeReady.WithLabelValues(n.Name).Set(b2f(n.Ready))
		m.fencing.WithLabelValues(n.Name).Set(b2f(n.FencingReady))
		if c := n.Labels[labelClass]; c != "" {
			m.nodeClass.WithLabelValues(n.Name, c).Set(1)
		}
		for _, c := range pressureConditions {
			m.pressure.WithLabelValues(n.Name, c).Set(b2f(s.pressure[n.Name][c]))
		}
		m.allocMem.WithLabelValues(n.Name).Set(float64(n.Allocatable.MemBytes))
		m.reqMem.WithLabelValues(n.Name).Set(0)
	}
	for _, p := range s.Pods {
		if g, err := m.reqMem.GetMetricWithLabelValues(p.Node); err == nil && p.Node != "" {
			g.Add(float64(p.Requests.MemBytes))
		}
	}
	for sys, v := range map[string]Voters{"etcd": s.Quorum.Etcd, "vault": s.Quorum.Vault, "sentinel": s.Quorum.Sentinel} {
		m.quorum.WithLabelValues(sys, "total").Set(float64(v.Voters))
		m.quorum.WithLabelValues(sys, "healthy").Set(float64(v.Healthy))
	}
	m.vaultActive.WithLabelValues().Set(b2f(s.Quorum.Vault.Healthy > 0))
	for _, v := range s.Volumes {
		m.robustness.WithLabelValues(v.Name).Set(robustnessValue[v.Robustness])
	}
	if s.Postgres.Instances > 0 {
		m.pgSync.WithLabelValues().Set(float64(s.Postgres.SyncStandbys))
	}
	m.lastOK.Store(m.now().UnixNano())
}

// failed drops every cluster gauge after a snapshot that couldn't be taken.
func (m *Metrics) failed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reset()
}

// reset: the caller holds m.mu for writing.
func (m *Metrics) reset() {
	for _, g := range []*prometheus.GaugeVec{m.nodeReady, m.quorum, m.robustness, m.pgSync, m.fencing, m.vaultActive,
		m.nodeClass, m.pressure, m.allocMem, m.reqMem} {
		g.Reset()
	}
}

// Handler serves /metrics under m.mu's read lock: one consistent set.
func (m *Metrics) Handler() http.Handler {
	h := promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		defer m.mu.RUnlock()
		h.ServeHTTP(w, r)
	})
}
