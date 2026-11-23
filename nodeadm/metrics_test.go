package main

// Task 32: the R7 gauges as Prometheus scrapes them (configured voter
// totals, absent series after a failed snapshot, the snapshot age, the
// small-node inputs).

import (
	"bufio"
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// scrape: every series of /metrics → value (the series as exposed, e.g.
// `portcullis_node_ready{node="n1"}`).
func scrape(t *testing.T, m *Metrics) map[string]float64 {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := map[string]float64{}
	sc := bufio.NewScanner(rec.Body)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		i := strings.LastIndexByte(l, ' ')
		v, err := strconv.ParseFloat(l[i+1:], 64)
		if err != nil {
			t.Fatalf("metrics line %q: %v", l, err)
		}
		out[l[:i]] = v
	}
	return out
}

func hasPrefix(m map[string]float64, name string) bool {
	for k := range m {
		if k == name || strings.HasPrefix(k, name+"{") {
			return true
		}
	}
	return false
}

func wantSeries(t *testing.T, got map[string]float64, series string, want float64) {
	t.Helper()
	v, ok := got[series]
	if !ok {
		t.Fatalf("no series %s", series)
	}
	if v != want {
		t.Fatalf("%s = %v, want %v", series, v, want)
	}
}

func deletePod(t *testing.T, h *harness, ns, name string) {
	t.Helper()
	if err := h.kube.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
}

// TestMetricsVoterTotalsAreConfigured (review I6): 3 configured Vault voters
// with one pod left (Ready) → total 3, healthy 1 (QuorumLost's input), not
// 1 of 1; 0 configured → total 0 (never alerts) even with pods present.
func TestMetricsVoterTotalsAreConfigured(t *testing.T) {
	h := newHarness(t)
	snapshotFixture(t, h)
	deletePod(t, h, coreNS, "vault-1")
	deletePod(t, h, coreNS, "vault-2")
	h.s.cfg.SentinelVoters = 0
	snap, err := h.s.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Quorum.Vault != (Voters{Voters: 3, Healthy: 1}) {
		t.Fatalf("snapshot vault quorum %+v, want 3 configured, 1 healthy", snap.Quorum.Vault)
	}
	got := scrape(t, h.s.metrics)
	wantSeries(t, got, `portcullis_quorum_voters{state="total",system="vault"}`, 3)
	wantSeries(t, got, `portcullis_quorum_voters{state="healthy",system="vault"}`, 1)
	wantSeries(t, got, `portcullis_quorum_voters{state="total",system="sentinel"}`, 0)
	wantSeries(t, got, `portcullis_quorum_voters{state="healthy",system="sentinel"}`, 0)
	wantSeries(t, got, `portcullis_vault_active`, 1)
	// A configured voter that is Ready but beyond the configured count
	// never makes healthy exceed total.
	if v := configuredVoters(3, 5); v != (Voters{3, 3}) {
		t.Fatalf("configuredVoters(3, 5) = %+v", v)
	}
}

// TestMetricsFailedSnapshotDropsGauges (review M11): after a good snapshot,
// one that can't list the nodes leaves no cluster series (absent, not the
// last healthy values); the failover counter and the snapshot age stay,
// and the age keeps growing from the last good snapshot.
func TestMetricsFailedSnapshotDropsGauges(t *testing.T) {
	h := newHarness(t)
	snapshotFixture(t, h)
	if _, err := h.s.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := scrape(t, h.s.metrics)
	for _, n := range []string{"portcullis_node_ready", "portcullis_quorum_voters", "portcullis_volume_robustness",
		"portcullis_pg_sync_standbys", "portcullis_fencing_ready", "portcullis_vault_active", "portcullis_node_class",
		"portcullis_node_pressure", "portcullis_node_allocatable_memory_bytes", "portcullis_node_requested_memory_bytes"} {
		if !hasPrefix(got, n) {
			t.Fatalf("after a good snapshot: no %s", n)
		}
	}
	wantSeries(t, got, `portcullis_nodeadm_snapshot_age_seconds`, 0)
	h.kube.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("the API server is unreachable")
	})
	h.setNow(vecNow.Add(150 * time.Second))
	if _, err := h.s.snapshot(context.Background()); err == nil {
		t.Fatal("the snapshot succeeded without the nodes")
	}
	got = scrape(t, h.s.metrics)
	for _, n := range []string{"portcullis_node_ready", "portcullis_quorum_voters", "portcullis_volume_robustness",
		"portcullis_pg_sync_standbys", "portcullis_fencing_ready", "portcullis_vault_active", "portcullis_node_class",
		"portcullis_node_pressure", "portcullis_node_allocatable_memory_bytes", "portcullis_node_requested_memory_bytes"} {
		if hasPrefix(got, n) {
			t.Fatalf("after a failed snapshot: %s still exported", n)
		}
	}
	wantSeries(t, got, `portcullis_failover_total{kind="postgres"}`, 0)
	wantSeries(t, got, `portcullis_nodeadm_snapshot_age_seconds`, 150)
}

// TestMetricsSnapshotAgeFromStart: before any good snapshot the age counts
// from the process start (a nodeadm that never could ask is blind too).
func TestMetricsSnapshotAgeFromStart(t *testing.T) {
	h := newHarness(t)
	h.s.metrics.lastOK = vecNow
	h.setNow(vecNow.Add(121 * time.Second))
	wantSeries(t, scrape(t, h.s.metrics), `portcullis_nodeadm_snapshot_age_seconds`, 121)
}

// TestMetricsPostgresAbsentWithoutCNPG: CNPG's Cluster unreadable (or no
// dynamic client) → no pg_sync_standbys series, never a 0 that reads as
// "not synchronous".
func TestMetricsPostgresAbsentWithoutCNPG(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := scrape(t, h.s.metrics); hasPrefix(got, "portcullis_pg_sync_standbys") {
		t.Fatal("pg_sync_standbys exported without CNPG")
	}
	snapshotFixture(t, h)
	if _, err := h.s.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantSeries(t, scrape(t, h.s.metrics), `portcullis_pg_sync_standbys`, 1)
}

// TestMetricsSmallNodeInputs: PortcullisSmallNodePressure's inputs — the
// class, the kubelet's pressure conditions, allocatable and requested
// memory per node.
func TestMetricsSmallNodeInputs(t *testing.T) {
	nodes := append([]nodeSpec{}, baseNodes...)
	nodes = append(nodes, nodeSpec{"n4", "agent", "small", "main", "10.215.0.4", nil, nil, true, false})
	h := newHarness(t, nodes...)
	ctx := context.Background()
	n4, err := h.kube.CoreV1().Nodes().Get(ctx, "n4", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	n4.Status.Conditions = append(n4.Status.Conditions, corev1.NodeCondition{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionTrue},
		corev1.NodeCondition{Type: corev1.NodeDiskPressure, Status: corev1.ConditionFalse})
	if _, err := h.kube.CoreV1().Nodes().UpdateStatus(ctx, n4, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	for i, mem := range []int64{1000000000, 2600000000} {
		p := agentPod("sessions-sentinel-"+strconv.Itoa(i), coreNS, "n4", "sessions-sentinel", "StatefulSet", nil)
		p.Spec.Containers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: *resource.NewQuantity(mem, resource.DecimalSI)}
		if _, err := h.kube.CoreV1().Pods(coreNS).Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	done := agentPod("finished", coreNS, "n4", "job", "Job", nil)
	done.Status.Phase = corev1.PodSucceeded
	done.Spec.Containers[0].Resources.Requests = corev1.ResourceList{corev1.ResourceMemory: *resource.NewQuantity(999, resource.DecimalSI)}
	if _, err := h.kube.CoreV1().Pods(coreNS).Create(ctx, done, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	got := scrape(t, h.s.metrics)
	wantSeries(t, got, `portcullis_node_class{class="small",node="n4"}`, 1)
	wantSeries(t, got, `portcullis_node_class{class="home",node="n1"}`, 1)
	wantSeries(t, got, `portcullis_node_pressure{condition="MemoryPressure",node="n4"}`, 1)
	wantSeries(t, got, `portcullis_node_pressure{condition="DiskPressure",node="n4"}`, 0)
	wantSeries(t, got, `portcullis_node_pressure{condition="PIDPressure",node="n4"}`, 0)
	wantSeries(t, got, `portcullis_node_pressure{condition="MemoryPressure",node="n1"}`, 0)
	wantSeries(t, got, `portcullis_node_allocatable_memory_bytes{node="n4"}`, 4000000000)
	wantSeries(t, got, `portcullis_node_requested_memory_bytes{node="n4"}`, 3600000000)
	wantSeries(t, got, `portcullis_node_requested_memory_bytes{node="n1"}`, 0)
}
