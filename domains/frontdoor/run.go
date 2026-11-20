package frontdoor

import (
	"context"
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
	Leading func() bool
	Status  StatusSink
	Metrics *Metrics
	Log     *log.Logger
	// Redact cleans every message before it is logged (the provider's
	// credentials; the provider is already behind the redacting wrapper).
	Redact func(string) string

	// lastPub is the last address set read (the status keeps it while a
	// round can't read the provider).
	lastPub map[string][]string
}

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

// Step runs one round at now and returns the changes it applied.
func (r *Runner) Step(ctx context.Context, now time.Time) []Change {
	rctx, cancel := context.WithTimeout(ctx, Round-time.Second)
	defer cancel()
	c, err := r.Source.Cluster(rctx)
	if err != nil {
		// Fail closed: no snapshot, no decision.
		r.logf("frontdoor: no cluster snapshot, nothing changes this round: %v", err)
		r.writeStatus(rctx, r.lastPub, Cluster{}, r.Engine.View())
		return nil
	}
	probes, errs := r.Source.Probes(rctx, c, now)
	for _, e := range errs {
		r.logf("frontdoor: probes: %v", e)
	}
	pub, err := r.Writer.Published(rctx)
	if err != nil {
		r.logf("frontdoor: reading the address set, nothing changes this round: %v", err)
		r.writeStatus(rctx, r.lastPub, c, r.Engine.View())
		return nil
	}
	lead := r.Leading != nil && r.Leading()
	changes := r.Engine.Step(now, Inputs{Lease: lead, Nodes: c.Nodes, Ready: c.Ready, Probes: probes, Published: pub})
	var done []Change
	for _, ch := range changes {
		if r.Leading == nil || !r.Leading() {
			r.logf("frontdoor: standing by: %s %s %s not written", ch.Op, ch.Name, ch.Value)
			break
		}
		if err := r.Writer.Apply(rctx, ch); err != nil {
			// Retried after the 60 s rate limit: the next rounds read the
			// set again.
			r.logf("frontdoor: %s %s %s: %v", ch.Op, ch.Name, ch.Value, err)
			continue
		}
		r.logf("frontdoor: %s %s %s", ch.Op, ch.Name, ch.Value)
		pub[ch.Name] = applyTo(pub[ch.Name], ch)
		done = append(done, ch)
	}
	r.lastPub = pub
	r.writeStatus(rctx, pub, c, r.Engine.View())
	if r.Metrics != nil {
		r.Metrics.Update(now, pub, c, r.Engine.View())
	}
	return done
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

func (r *Runner) writeStatus(ctx context.Context, pub map[string][]string, c Cluster, v View) {
	if r.Status == nil {
		return
	}
	lead := r.Leading != nil && r.Leading()
	b, err := marshalStatus(BuildStatus(lead, r.Writer.Names(), pub, r.Writer.TTL, c, v))
	if err == nil {
		err = r.Status.Write(ctx, b)
	}
	if err != nil {
		r.logf("frontdoor: writing %s: %v", StatusConfigMap, err)
	}
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
