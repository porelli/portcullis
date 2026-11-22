package frontdoor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// Round is the probe interval (§20.4, §20.8).
const Round = 10 * time.Second

// Runner runs one round every 10 s: the cluster and the probes, the
// published sets, Engine.Step, the writes (only while leading), the
// status and the metrics.
type Runner struct {
	Engine  *Engine
	Writer  *Writer
	Source  Source
	Status  StatusSink
	Metrics *Metrics
	Log     *log.Logger
	// Redact cleans every message before it is logged (the provider's
	// credentials; the provider is already behind the redacting wrapper).
	Redact func(string) string

	// Identity is the front door's Lease identity (its pod name), written
	// as the status's leader.
	Identity string

	// lastPub is the last address set read (the status keeps it while a
	// round can't read the provider); lastCluster / lastSnapAt the last
	// snapshot (a round without one keeps its probes and sites, marked
	// stale: never an empty view).
	lastPub     map[string][]string
	lastCluster Cluster
	lastSnapAt  time.Time
	// lastBody / lastWrite / generation: the status is written when it
	// changes, else as a heartbeat every StatusHeartbeat (its written_at
	// tells a follower it is current).
	lastBody   string
	lastWrite  time.Time
	generation int64
}

// StatusHeartbeat: an unchanged status is written again this often.
const StatusHeartbeat = 30 * time.Second

// ClusterTimeout bounds the snapshot and the probes of a round (each
// probe has its own 3 s).
const ClusterTimeout = 5 * time.Second

func (r *Runner) logf(format string, args ...any) {
	if r.Log == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if r.Redact != nil {
		msg = r.Redact(msg)
	}
	r.Log.Print(msg)
}

func (r *Runner) leading() bool { return r.Writer.Fence != nil && r.Writer.Fence.Leading() }

// Step runs one round at now and returns the changes it applied. The
// reads have their own budgets; each write runs under the fence's write
// context (Writer.Apply).
func (r *Runner) Step(ctx context.Context, now time.Time) []Change {
	cctx, cancel := context.WithTimeout(ctx, ClusterTimeout)
	defer cancel()
	c, err := r.Source.Cluster(cctx)
	if err != nil {
		// Fail closed: no snapshot, no decision (and the next round isn't
		// consecutive with the last one: Engine.Step sees the gap).
		r.logf("frontdoor: no cluster snapshot, nothing changes this round: %v%s", err, deadline(cctx))
		r.writeStatus(ctx, now, r.lastPub, r.lastCluster, r.Engine.View(), false)
		if r.Metrics != nil {
			r.Metrics.SnapshotFailed()
		}
		return nil
	}
	for _, w := range c.Warnings {
		r.logf("frontdoor: %s", w)
	}
	probes, errs := r.Source.Probes(cctx, c, now)
	for _, e := range errs {
		r.logf("frontdoor: probes: %v", e)
	}
	pub, err := r.Writer.Published(ctx)
	if err != nil {
		r.logf("frontdoor: reading the address set, nothing changes this round: %v", err)
		r.lastCluster, r.lastSnapAt = c, now
		r.writeStatus(ctx, now, r.lastPub, c, r.Engine.View(), true)
		return nil
	}
	changes := r.Engine.Step(now, Inputs{Lease: r.leading(), Nodes: c.Nodes, Ready: c.Ready, Probes: probes, Published: pub})
	var done []Change
	for _, ch := range changes {
		if !r.leading() {
			r.logf("frontdoor: standing by: %s %s %s not written", ch.Op, ch.Name, ch.Value)
			break
		}
		if err := r.Writer.Apply(ctx, ch); err != nil {
			// Retried after the 60 s rate limit: the next rounds read the
			// set again.
			r.logf("frontdoor: %s %s %s: %v", ch.Op, ch.Name, ch.Value, err)
			continue
		}
		r.logf("frontdoor: %s %s %s", ch.Op, ch.Name, ch.Value)
		r.Engine.Applied(ch.Name, now)
		pub[ch.Name] = applyTo(pub[ch.Name], ch)
		done = append(done, ch)
	}
	r.lastPub = pub
	r.lastCluster, r.lastSnapAt = c, now
	r.writeStatus(ctx, now, pub, c, r.Engine.View(), true)
	if r.Metrics != nil {
		r.Metrics.Update(now, pub, c, r.Engine.View())
	}
	return done
}

// deadline names a read cut off by its budget.
func deadline(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Sprintf(" (the %s read budget ran out)", ClusterTimeout)
	}
	return ""
}

func applyTo(set []string, c Change) []string {
	out := []string{}
	for _, a := range set {
		if a != c.Value {
			out = append(out, a)
		}
	}
	if c.Op == "add" {
		out = append(out, c.Value)
	}
	return out
}

func (r *Runner) writeStatus(ctx context.Context, now time.Time, pub map[string][]string, c Cluster, v View, snapOK bool) {
	if r.Status == nil {
		return
	}
	st := BuildStatus(r.leading(), r.Writer.Names(), pub, r.Writer.TTL, c, v)
	st.Leader, st.SnapshotOK = r.Identity, snapOK
	// The comparison leaves out the times (snapshot_at moves every round;
	// written_at and generation are the write's own): they go with the next
	// change or heartbeat.
	body, err := marshalStatus(st)
	if err != nil {
		r.logf("frontdoor: writing %s: %v", StatusConfigMap, err)
		return
	}
	if string(body) == r.lastBody && now.Sub(r.lastWrite) < StatusHeartbeat {
		return
	}
	if !r.lastSnapAt.IsZero() {
		at := r.lastSnapAt.UTC()
		st.SnapshotAt = &at
	}
	st.WrittenAt = now.UTC()
	st.Generation = max(now.UnixMilli(), r.generation+1)
	// Compact JSON (json.Marshal): the admission policy finds
	// "leader":"<pod>" as a substring of status.json, so an indented writer
	// would be refused (tests/ha_admission_vectors.json pins the shape).
	b, err := marshalStatus(st)
	if err == nil {
		sctx, cancel := context.WithTimeout(ctx, ReadTimeout)
		err = r.Status.Write(sctx, b)
		cancel()
	}
	if err != nil {
		r.logf("frontdoor: writing %s: %v", StatusConfigMap, err)
		return
	}
	r.lastBody, r.lastWrite, r.generation = string(body), now, st.Generation
}

// Run steps every 10 s until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(Round)
	defer t.Stop()
	r.Step(ctx, time.Now().UTC())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.Step(ctx, now.UTC())
		}
	}
}
