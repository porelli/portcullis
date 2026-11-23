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
	"sync/atomic"
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
	h.s.metrics.lastOK.Store(vecNow.UnixNano())
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

var clusterFamilies = []string{"portcullis_node_ready", "portcullis_quorum_voters", "portcullis_volume_robustness",
	"portcullis_pg_sync_standbys", "portcullis_fencing_ready", "portcullis_vault_active", "portcullis_node_class",
	"portcullis_node_pressure", "portcullis_node_allocatable_memory_bytes", "portcullis_node_requested_memory_bytes"}

// TestClusterHandlerLeavesGauges (fix round 3): GET /v1/cluster whose
// request is cancelled (or times out) mid-snapshot fails for its caller
// only: the gauges the metrics loop set stay, and the snapshot age isn't
// touched (the alerts' holds keep running).
func TestClusterHandlerLeavesGauges(t *testing.T) {
	h := newHarness(t)
	snapshotFixture(t, h)
	if _, err := h.s.snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := scrape(t, h.s.metrics)
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		h.kube.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, cause
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := httptest.NewRequest("GET", "/v1/cluster", nil).WithContext(ctx)
		if err := h.s.handleCluster(httptest.NewRecorder(), r); err == nil {
			t.Fatalf("%v: the handler's snapshot succeeded", cause)
		}
		h.kube.ReactionChain = h.kube.ReactionChain[1:]
		if got := scrape(t, h.s.metrics); len(got) != len(before) {
			t.Fatalf("%v: the handler's failed snapshot changed the metrics: %d series, had %d", cause, len(got), len(before))
		} else {
			for k, v := range before {
				if got[k] != v {
					t.Fatalf("%v: %s = %v after the handler's failure, was %v", cause, k, got[k], v)
				}
			}
		}
	}
	// A successful handler snapshot doesn't observe either (the loop alone).
	h.setNow(vecNow.Add(90 * time.Second))
	if err := h.s.handleCluster(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/cluster", nil)); err != nil {
		t.Fatal(err)
	}
	wantSeries(t, scrape(t, h.s.metrics), `portcullis_nodeadm_snapshot_age_seconds`, 90)
}

// TestMetricsScrapeConsistent (fix round 3, run under -race): scrapes
// racing the metrics loop's good and failed snapshots see every cluster
// family or none, never a half-updated set.
func TestMetricsScrapeConsistent(t *testing.T) {
	h := newHarness(t)
	snapshotFixture(t, h)
	var failing atomic.Bool
	h.kube.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failing.Load() {
			return true, nil, errors.New("the API server is unreachable")
		}
		return false, nil, nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 60; i++ {
			failing.Store(i%2 == 1)
			_, _ = h.s.snapshot(context.Background())
		}
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		got := scrape(t, h.s.metrics)
		n := 0
		for _, f := range clusterFamilies {
			if hasPrefix(got, f) {
				n++
			}
		}
		if n != 0 && n != len(clusterFamilies) {
			t.Fatalf("a scrape saw %d of %d cluster families (half-updated)", n, len(clusterFamilies))
		}
	}
}

// TestMetricsStartTime: portcullis_nodeadm_start_time_seconds is the
// process's start (PortcullisNodeadmBlind's restart count), set once.
func TestMetricsStartTime(t *testing.T) {
	before := time.Now()
	m := newMetrics()
	got := scrape(t, m)["portcullis_nodeadm_start_time_seconds"]
	if got < float64(before.Unix())-1 || got > float64(time.Now().Unix())+1 {
		t.Fatalf("portcullis_nodeadm_start_time_seconds = %v, want about %d", got, before.Unix())
	}
	time.Sleep(10 * time.Millisecond)
	if again := scrape(t, m)["portcullis_nodeadm_start_time_seconds"]; again != got {
		t.Fatalf("the start time moved: %v → %v", got, again)
	}
}
