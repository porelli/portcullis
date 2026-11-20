package frontdoor

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libdns/libdns"
	coordv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

const testNS = "portcullis"

func leaseClient(withLease bool) *fake.Clientset {
	if !withLease {
		return fake.NewClientset()
	}
	return fake.NewClientset(&coordv1.Lease{ObjectMeta: metav1.ObjectMeta{Name: LeaseName, Namespace: testNS}})
}

func renew(t *testing.T, f *Fence, holder string) error {
	t.Helper()
	l := f.newLock()
	if _, _, err := l.Get(context.Background()); err != nil {
		return err
	}
	now := metav1.NewTime(f.clock.Now())
	return l.Update(context.Background(), resourcelock.LeaderElectionRecord{HolderIdentity: holder, LeaseDurationSeconds: 15, AcquireTime: now, RenewTime: now})
}

// TestFenceTiming (fake clock): it leads only after a renewal naming it,
// timed before the request is sent; it stands by at the RenewDeadline,
// for good (Lost closes, a later renewal doesn't reopen it); a renewal by
// another identity doesn't count.
func TestFenceTiming(t *testing.T) {
	fc := clocktesting.NewFakeClock(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC))
	cs := leaseClient(true)
	f := newFence(cs, testNS, "fd-a", fc, LeaseDuration, RenewDeadline, RetryPeriod)
	if f.Leading() {
		t.Fatal("leads before any renewal")
	}
	if _, _, err := f.WriteContext(context.Background()); !errors.Is(err, ErrStandingBy) {
		t.Fatalf("a write context before any renewal: %v", err)
	}
	if err := renew(t, f, "fd-b"); err != nil {
		t.Fatal(err)
	}
	if f.Leading() {
		t.Fatal("another identity's renewal counted")
	}
	// The request takes 3 s: the renewal counts from before it.
	cs.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		fc.Step(3 * time.Second)
		return false, nil, nil
	})
	start := fc.Now()
	if err := renew(t, f, "fd-a"); err != nil {
		t.Fatal(err)
	}
	if !f.Leading() {
		t.Fatal("not leading after its renewal")
	}
	fc.SetTime(start.Add(RenewDeadline - time.Millisecond))
	if !f.Leading() {
		t.Fatal("stood by before the RenewDeadline")
	}
	fc.SetTime(start.Add(RenewDeadline))
	if f.Leading() {
		t.Fatal("still leading at the RenewDeadline (timed from before the request)")
	}
	select {
	case <-f.Lost():
	default:
		t.Fatal("Lost isn't closed")
	}
	if err := renew(t, f, "fd-a"); err != nil {
		t.Fatal(err)
	}
	if f.Leading() {
		t.Fatal("led again after standing by")
	}
}

// TestFenceWriteContext: a write starts only with ≥ 5 s of fence time
// left and is cut at min(5 s, renewed + LeaseDuration − 5 s).
func TestFenceWriteContext(t *testing.T) {
	fc := clocktesting.NewFakeClock(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC))
	f := newFence(leaseClient(true), testNS, "fd-a", fc, LeaseDuration, RenewDeadline, RetryPeriod)
	if err := renew(t, f, "fd-a"); err != nil {
		t.Fatal(err)
	}
	renewed := fc.Now()
	fc.SetTime(renewed.Add(5*time.Second + time.Millisecond))
	if _, _, err := f.WriteContext(context.Background()); !errors.Is(err, ErrStandingBy) {
		t.Fatalf("a write started with under 5 s of fence time left: %v", err)
	}
	fc.SetTime(renewed.Add(time.Second))
	ctx, done, err := f.WriteContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	fc.Step(WriteMargin - time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("cut before 5 s")
	}
	fc.Step(time.Millisecond)
	waitDone(t, ctx)
}

func waitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the write context wasn't cancelled")
	}
}

// blockingProvider blocks every write until its context ends and records
// what it saw.
type blockingProvider struct {
	mu        sync.Mutex
	recs      []libdns.RR
	started   chan struct{}
	cancelled atomic.Bool
	writes    atomic.Int32
}

func (p *blockingProvider) GetRecords(context.Context, string) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []libdns.Record
	for _, r := range p.recs {
		out = append(out, r)
	}
	return out, nil
}

func (p *blockingProvider) block(ctx context.Context) error {
	p.writes.Add(1)
	p.started <- struct{}{}
	<-ctx.Done()
	p.cancelled.Store(true)
	return ctx.Err()
}

func (p *blockingProvider) AppendRecords(ctx context.Context, _ string, _ []libdns.Record) ([]libdns.Record, error) {
	return nil, p.block(ctx)
}

func (p *blockingProvider) DeleteRecords(ctx context.Context, _ string, _ []libdns.Record) ([]libdns.Record, error) {
	return nil, p.block(ctx)
}

// TestLeaseLostStopsInflightWrite: the Lease is lost while a delete is in
// flight (here the RenewDeadline, 3 s, comes before the write's own 5 s
// deadline, so only the loss can stop it): the provider sees its context
// cancelled at once, Apply reports the cut-off, and nothing more reaches
// the provider.
func TestLeaseLostStopsInflightWrite(t *testing.T) {
	fc := clocktesting.NewFakeClock(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC))
	f := newFence(leaseClient(true), testNS, "fd-a", fc, LeaseDuration, 3*time.Second, RetryPeriod)
	if err := renew(t, f, "fd-a"); err != nil {
		t.Fatal(err)
	}
	p := &blockingProvider{started: make(chan struct{}, 4), recs: []libdns.RR{
		{Name: "@", Type: "A", Data: "198.51.100.1"}, {Name: "@", Type: "A", Data: "198.51.100.2"}}}
	w := &Writer{Domain: "example.org", Zone: "example.org.", P: p, TTL: time.Minute, Fence: f, Policy: docs}
	res := make(chan error, 1)
	go func() {
		res <- w.Apply(context.Background(), Change{Name: "example.org", Op: "remove", Value: "198.51.100.2", Type: "A"})
	}()
	<-p.started
	// The renewals stop: at the RenewDeadline the fence stands by and the
	// write in flight is cancelled.
	fc.Step(3 * time.Second)
	if f.Leading() {
		t.Fatal("still leading")
	}
	select {
	case err := <-res:
		if !errors.Is(err, ErrCutOff) || !p.cancelled.Load() {
			t.Fatalf("Apply: %v, provider saw cancel %v", err, p.cancelled.Load())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the write in flight wasn't stopped")
	}
	if err := w.Apply(context.Background(), Change{Name: "example.org", Op: "add", Value: "198.51.100.3", Type: "A"}); !errors.Is(err, ErrStandingBy) {
		t.Errorf("a write after the cut-off: %v", err)
	}
	if n := p.writes.Load(); n != 1 {
		t.Errorf("%d writes reached the provider, want 1 (none after the cut-off)", n)
	}
}

// TestLeaseLostCancelsMidWriteByLoss: the cancellation comes from the
// loss itself (Lost), not the write's own deadline.
func TestLeaseLostCancelsMidWriteByLoss(t *testing.T) {
	fc := clocktesting.NewFakeClock(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC))
	f := newFence(leaseClient(true), testNS, "fd-a", fc, LeaseDuration, RenewDeadline, RetryPeriod)
	if err := renew(t, f, "fd-a"); err != nil {
		t.Fatal(err)
	}
	ctx, done, err := f.WriteContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	f.mu.Lock()
	f.loseLocked()
	f.mu.Unlock()
	waitDone(t, ctx)
}

func fastFence(cs *fake.Clientset, id string) *Fence {
	return newFence(cs, testNS, id, clock.RealClock{}, 1500*time.Millisecond, time.Second, 200*time.Millisecond)
}

func eventually(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestFenceElector (client-go's elector, real clock, short timings): it
// takes the pre-created Lease and leads; when renewals fail it stands by
// within the RenewDeadline, Run returns, and it never leads again; the
// Lease isn't released (ReleaseOnCancel false: the holder stays).
func TestFenceElector(t *testing.T) {
	cs := leaseClient(true)
	// The reactor is installed before the elector runs (the fake's
	// reactor list isn't safe to change concurrently).
	var failing atomic.Bool
	cs.PrependReactor("update", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		if failing.Load() {
			return true, nil, errors.New("the API server is unreachable")
		}
		return false, nil, nil
	})
	f := fastFence(cs, "fd-a")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{})
	go func() { _ = f.Run(ctx); close(ran) }()
	if !eventually(3*time.Second, f.Leading) {
		t.Fatal("never led with the Lease free")
	}
	failing.Store(true)
	lostAt := time.Now()
	if !eventually(3*time.Second, func() bool { return !f.Leading() }) {
		t.Fatal("still leading with every renewal failing")
	}
	if d := time.Since(lostAt); d > 1500*time.Millisecond {
		t.Errorf("stood by after %s (RenewDeadline 1 s)", d)
	}
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("Run didn't return after standing by")
	}
	failing.Store(false)
	time.Sleep(500 * time.Millisecond)
	if f.Leading() {
		t.Fatal("led again")
	}
	l, err := cs.CoordinationV1().Leases(testNS).Get(context.Background(), LeaseName, metav1.GetOptions{})
	if err != nil || l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity != "fd-a" {
		t.Errorf("the Lease was released or changed: %+v %v", l.Spec, err)
	}
}

// TestFenceNoLeaseNoCreate: without the chart's Lease, and without the
// right to create one (the Role has none), the front door never leads.
func TestFenceNoLeaseNoCreate(t *testing.T) {
	cs := leaseClient(false)
	cs.PrependReactor("create", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "coordination.k8s.io", Resource: "leases"}, LeaseName, errors.New("no create"))
	})
	f := fastFence(cs, "fd-a")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	if eventually(1500*time.Millisecond, f.Leading) {
		t.Fatal("led without a Lease")
	}
}
