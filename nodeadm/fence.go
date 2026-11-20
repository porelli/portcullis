package main

import (
	"context"
	"errors"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/utils/clock"
)

// ErrStandingBy: no write context while the fence doesn't lead.
var ErrStandingBy = errors.New("this nodeadm isn't the leader")

// The Lease timings of §20.5 (the front door's fence, domains/frontdoor/lease.go,
// with nodeadm's Lease).
const (
	LeaseDuration = 15 * time.Second
	RenewDeadline = 10 * time.Second
	RetryPeriod   = 2 * time.Second
	// LeaseName is nodeadm's Lease in the core namespace.
	LeaseName = "portcullis-nodeadm"
)

// Fence is nodeadm's write fence on its Lease (client-go
// leaderelection, LeaseLock): it leads from its first successful
// renewal until the last one is RenewDeadline old (measured locally,
// before client-go's own callback), and then stands by for good: the
// elector is cancelled, Run returns and the process exits, so a
// restarted pod campaigns afresh.
type Fence struct {
	client               kubernetes.Interface
	namespace, identity  string
	clock                clock.WithDelayedExecution
	mu                   sync.Mutex
	renewed              time.Time
	lost                 bool
	cancel               context.CancelFunc
	lostCh               chan struct{}
	lostOnce             sync.Once
	leaseD, renewD, retr time.Duration
	writers              map[int]context.CancelFunc
	nextWriter           int
}

// WriteMargin bounds a provider write: it starts only with at least this
// much fence time left and runs at most this long, ending no later than
// the last renewal + LeaseDuration − WriteMargin (the RenewDeadline), well
// before another nodeadm may take the Lease.
const WriteMargin = 5 * time.Second

// WriteContext is the context one provider write runs under: cancelled
// when the fence stands by (Lease lost) and at its deadline, min(5 s,
// renewed + LeaseDuration − 5 s). Without 5 s of fence time left it
// refuses (ErrStandingBy).
func (f *Fence) WriteContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost || f.renewed.IsZero() {
		return nil, nil, ErrStandingBy
	}
	now := f.clock.Now()
	if now.Sub(f.renewed) >= f.renewD {
		f.loseLocked()
		return nil, nil, ErrStandingBy
	}
	left := f.renewed.Add(f.leaseD - WriteMargin).Sub(now)
	if left < WriteMargin {
		return nil, nil, ErrStandingBy
	}
	ctx, cancel := context.WithCancel(parent)
	timer := f.clock.AfterFunc(min(WriteMargin, left), cancel)
	id := f.nextWriter
	f.nextWriter++
	f.writers[id] = cancel
	return ctx, func() {
		timer.Stop()
		cancel()
		f.mu.Lock()
		delete(f.writers, id)
		f.mu.Unlock()
	}, nil
}

// NewFence is a fence on the Lease portcullis-frontdoor in namespace,
// held as identity (the pod name).
func NewFence(client kubernetes.Interface, namespace, identity string) *Fence {
	return newFence(client, namespace, identity, clock.RealClock{}, LeaseDuration, RenewDeadline, RetryPeriod)
}

func newFence(client kubernetes.Interface, namespace, identity string, c clock.WithDelayedExecution, leaseD, renewD, retry time.Duration) *Fence {
	return &Fence{client: client, namespace: namespace, identity: identity, clock: c,
		lostCh: make(chan struct{}), leaseD: leaseD, renewD: renewD, retr: retry, writers: map[int]context.CancelFunc{}}
}

// Leading reports whether nodeadm may write now.
func (f *Fence) Leading() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost || f.renewed.IsZero() {
		return false
	}
	if f.clock.Since(f.renewed) >= f.renewD {
		f.loseLocked()
		return false
	}
	return true
}

// Lost is closed once the fence stood by after leading (or the elector
// ended).
func (f *Fence) Lost() <-chan struct{} { return f.lostCh }

func (f *Fence) loseLocked() {
	f.lost = true
	// Writes in flight stop at once.
	for id, cancel := range f.writers {
		cancel()
		delete(f.writers, id)
	}
	if f.cancel != nil {
		f.cancel()
	}
	f.lostOnce.Do(func() { close(f.lostCh) })
}

// Run campaigns for the Lease and renews it until ctx ends or the fence
// stands by.
func (f *Fence) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	f.mu.Lock()
	f.cancel = cancel
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.loseLocked()
		f.mu.Unlock()
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-f.clock.After(100 * time.Millisecond):
				f.Leading()
			}
		}
	}()
	le, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            f.newLock(),
		LeaseDuration:   f.leaseD,
		RenewDeadline:   f.renewD,
		RetryPeriod:     f.retr,
		ReleaseOnCancel: false,
		Name:            LeaseName,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(context.Context) {},
			OnStoppedLeading: func() {},
		},
	})
	if err != nil {
		return err
	}
	le.Run(ctx)
	return nil
}

// newLock is the Lease lock timing this fence's renewals.
func (f *Fence) newLock() *fenceLock {
	return &fenceLock{LeaseLock: &resourcelock.LeaseLock{
		LeaseMeta:  metav1.ObjectMeta{Namespace: f.namespace, Name: LeaseName},
		Client:     f.client.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{Identity: f.identity},
	}, f: f}
}

func (f *Fence) renewedAt(start time.Time) {
	f.mu.Lock()
	if !f.lost {
		f.renewed = start
	}
	f.mu.Unlock()
}

// fenceLock times each successful write of a record naming this front
// door; the time is taken before the request is sent.
type fenceLock struct {
	*resourcelock.LeaseLock
	f *Fence
}

func (l *fenceLock) Create(ctx context.Context, r resourcelock.LeaderElectionRecord) error {
	start := l.f.clock.Now()
	if err := l.LeaseLock.Create(ctx, r); err != nil {
		return err
	}
	if r.HolderIdentity == l.f.identity {
		l.f.renewedAt(start)
	}
	return nil
}

func (l *fenceLock) Update(ctx context.Context, r resourcelock.LeaderElectionRecord) error {
	start := l.f.clock.Now()
	if err := l.LeaseLock.Update(ctx, r); err != nil {
		return err
	}
	if r.HolderIdentity == l.f.identity {
		l.f.renewedAt(start)
	}
	return nil
}
