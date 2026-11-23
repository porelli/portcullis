package main

// The R7 gauges on :9105 (contract §20.2 "Metrics"; Prometheus only, which
// gets no cluster-scoped right): portcullis_node_ready{node},
// portcullis_quorum_voters{system,state}, portcullis_volume_robustness
// {volume}, portcullis_pg_sync_standbys, portcullis_fencing_ready{node},
// portcullis_failover_total{kind}, portcullis_vault_active. Refreshed by
// every snapshot (the metrics loop takes one every 30 s).

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg         *prometheus.Registry
	nodeReady   *prometheus.GaugeVec
	quorum      *prometheus.GaugeVec
	robustness  *prometheus.GaugeVec
	pgSync      prometheus.Gauge
	fencing     *prometheus.GaugeVec
	failovers   *prometheus.CounterVec
	vaultActive prometheus.Gauge
}

func newMetrics() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry(),
		nodeReady: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_node_ready",
			Help: "1 while the node is Ready."}, []string{"node"}),
		quorum: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_quorum_voters",
			Help: "Voters of each quorum system: state total or healthy."}, []string{"system", "state"}),
		robustness: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_volume_robustness",
			Help: "A replicated volume's robustness: 0 healthy, 1 degraded, 2 faulted, 3 unknown."}, []string{"volume"}),
		pgSync: prometheus.NewGauge(prometheus.GaugeOpts{Name: "portcullis_pg_sync_standbys",
			Help: "Postgres synchronous standbys."}),
		fencing: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "portcullis_fencing_ready",
			Help: "1 while the node's Self Node Remediation agent is Ready."}, []string{"node"}),
		failovers: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "portcullis_failover_total",
			Help: "Failovers seen (kind postgres: a new primary)."}, []string{"kind"}),
		vaultActive: prometheus.NewGauge(prometheus.GaugeOpts{Name: "portcullis_vault_active",
			Help: "1 while at least one Vault voter serves requests (is the active node or a standby with a reachable active node), else 0."}),
	}
	m.reg.MustRegister(m.nodeReady, m.quorum, m.robustness, m.pgSync, m.fencing, m.failovers, m.vaultActive)
	m.failovers.WithLabelValues("postgres")
	return m
}

var robustnessValue = map[string]float64{"healthy": 0, "degraded": 1, "faulted": 2, "unknown": 3}

// observe sets the gauges from a snapshot (nodes gone are dropped).
func (m *Metrics) observe(s *Snapshot) {
	m.nodeReady.Reset()
	m.fencing.Reset()
	for _, n := range s.Nodes {
		m.nodeReady.WithLabelValues(n.Name).Set(b2f(n.Ready))
		m.fencing.WithLabelValues(n.Name).Set(b2f(n.FencingReady))
	}
	for sys, v := range map[string]Voters{"etcd": s.Quorum.Etcd, "vault": s.Quorum.Vault, "sentinel": s.Quorum.Sentinel} {
		m.quorum.WithLabelValues(sys, "total").Set(float64(v.Voters))
		m.quorum.WithLabelValues(sys, "healthy").Set(float64(v.Healthy))
	}
	m.vaultActive.Set(b2f(s.Quorum.Vault.Healthy > 0))
	m.robustness.Reset()
	for _, v := range s.Volumes {
		m.robustness.WithLabelValues(v.Name).Set(robustnessValue[v.Robustness])
	}
	m.pgSync.Set(float64(s.Postgres.SyncStandbys))
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
