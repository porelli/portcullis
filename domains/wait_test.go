package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"

	"github.com/portcullis/domains/internal/dnsplan"
	"github.com/portcullis/domains/internal/fakedns"
)

// virtualClock replaces apply --wait's clock: a sleep advances it at once
// (onSleep runs first, with the duration slept).
type virtualClock struct {
	mu      sync.Mutex
	now     time.Time
	onSleep func(d time.Duration)
}

func useVirtualClock(t *testing.T) *virtualClock {
	t.Helper()
	c := &virtualClock{now: time.Date(2026, 11, 13, 4, 20, 0, 0, time.UTC)}
	oldNow, oldSleep := toolNow, toolSleep
	toolNow = func() time.Time {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.now
	}
	toolSleep = func(_ context.Context, d time.Duration) {
		if c.onSleep != nil {
			c.onSleep(d)
		}
		c.mu.Lock()
		c.now = c.now.Add(d)
		c.mu.Unlock()
	}
	t.Cleanup(func() { toolNow, toolSleep = oldNow, oldSleep })
	return c
}

const (
	oldAcct = "https://acme-v02.api.letsencrypt.org/acme/acct/1"
	newAcct = "https://acme-v02.api.letsencrypt.org/acme/acct/2"
)

// caaOnly: apply only the caa set, pinned to uri ("" = CA-only).
func caaOnly(uri string) func(m map[string]any) {
	return func(m map[string]any) {
		m["sets"] = []string{"caa"}
		m["caa"].(map[string]any)["account_uri"] = uri
	}
}

// pinAt: the zone holds issue + issuewild pinned to uri, with ttl.
func pinAt(z *fakedns.Zone, uri string, ttl time.Duration) {
	v := dnsplan.CAAValue("letsencrypt.org", uri)
	z.Set("portcullis.example.test",
		libdns.CAA{Name: "portcullis", TTL: ttl, Tag: "issue", Value: v}.RR(),
		libdns.CAA{Name: "portcullis", TTL: ttl, Tag: "issuewild", Value: v}.RR())
}

func decodeApply(t *testing.T, out string) applyOutput {
	t.Helper()
	var o applyOutput
	if err := json.Unmarshal([]byte(out), &o); err != nil {
		t.Fatalf("apply output %q: %v", out, err)
	}
	if o.Wait == nil {
		t.Fatalf("apply --wait output has no wait report: %s", out)
	}
	return o
}

func neverVisible(t *testing.T) string {
	t.Helper()
	empty, err := fakedns.Serve(fakedns.NewZone(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { empty.Close() })
	return empty.Addr
}

// Porkbun raises every TTL under 600 s to 600: the wait follows the TTL
// the provider stored (600 s + the margin), not the 300 s Portcullis
// asked for, and a timeout says the records were written.
func TestToolWaitAutoPorkbunTTL(t *testing.T) {
	f := newToolFixture(t)
	f.deleteMode = "porkbun"
	useVirtualClock(t)
	addr := neverVisible(t)
	f.resolvers = []string{addr}
	code, out, errs := f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct)))
	if code != exitProblem {
		t.Fatalf("apply --wait auto, never visible = %d %s %s", code, out, errs)
	}
	for _, rr := range f.zone.Records("portcullis.example.test") {
		if rr.Type == "CAA" && rr.TTL != 600*time.Second {
			t.Fatalf("the porkbun fake stored TTL %s, want its 600 s floor", rr.TTL)
		}
	}
	w := decodeApply(t, out).Wait
	if w.TTL != 600 || w.Limit != 660 || w.Waited != 660 || w.Visible || w.Settled {
		t.Fatalf("wait report %+v: want ttl 600, limit = waited = 660 (TTL + 60 s margin), not visible", *w)
	}
	if len(w.Pending) != 1 || w.Pending[0] != addr {
		t.Fatalf("pending %v, want [%s]", w.Pending, addr)
	}
	for _, want := range []string{"were written", "not visible yet at " + addr, "TTL 600 s"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr %q lacks %q", errs, want)
		}
	}
	if strings.Contains(errs, "could not") || strings.Contains(errs, "failed") {
		t.Errorf("a timeout after a good write reads as a failure: %q", errs)
	}
}

func TestToolWaitAutoVisibleAtOnce(t *testing.T) {
	f := newToolFixture(t)
	f.deleteMode = "porkbun"
	useVirtualClock(t)
	code, out, errs := f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct)))
	if code != exitOK {
		t.Fatalf("apply --wait auto = %d %s %s", code, out, errs)
	}
	w := decodeApply(t, out).Wait
	if !w.Visible || w.Waited != 0 || w.TTL != 600 || len(w.Pending) != 0 {
		t.Fatalf("wait report %+v", *w)
	}
}

// A resolver whose cache of the old pin outlives the stored TTL + margin
// (its remaining TTL is visible in its answers): the wait follows it.
func TestToolWaitAutoFollowsResolverTTL(t *testing.T) {
	f := newToolFixture(t)
	f.deleteMode = "porkbun"
	pinAt(f.zone, oldAcct, 600*time.Second)
	stale := fakedns.NewZone()
	left := 750 * time.Second
	pinAt(stale, oldAcct, left)
	srv, err := fakedns.Serve(stale, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	c := useVirtualClock(t)
	c.onSleep = func(d time.Duration) { // the stale cache counts down, then refetches
		left -= d
		if left > 0 {
			pinAt(stale, oldAcct, left)
			return
		}
		stale.Set("portcullis.example.test", f.zone.Records("portcullis.example.test")...)
	}
	f.resolvers = append(f.resolvers, srv.Addr)
	code, out, errs := f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct)))
	if code != exitOK {
		t.Fatalf("apply --wait auto with a resolver caching for 750 s = %d %s %s", code, out, errs)
	}
	if w := decodeApply(t, out).Wait; !w.Visible || w.Waited != 750 || w.TTL != 600 {
		t.Fatalf("wait report %+v: want visible after 750 s", *w)
	}
}

// A TTL above the cap: the wait stops at 15 minutes.
func TestToolWaitAutoCap(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, time.Hour)
	useVirtualClock(t)
	f.resolvers = []string{neverVisible(t)}
	code, out, errs := f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct)))
	if code != exitProblem {
		t.Fatalf("= %d %s %s", code, out, errs)
	}
	if w := decodeApply(t, out).Wait; w.TTL != 3600 || w.Limit != 900 || w.Waited != 900 {
		t.Fatalf("wait report %+v: want ttl 3600, limit = waited = 900", *w)
	}
}

// --settle (the relax before an ACME flip): visible at the resolvers is
// not enough; every cache that may hold the old pin (the CA's own
// resolvers) must have expired: the write + the old TTL + the margin.
func TestToolWaitSettle(t *testing.T) {
	f := newToolFixture(t)
	f.deleteMode = "porkbun"
	pinAt(f.zone, oldAcct, 600*time.Second)
	useVirtualClock(t)
	code, out, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if code != exitOK {
		t.Fatalf("apply --settle = %d %s %s", code, out, errs)
	}
	if w := decodeApply(t, out).Wait; !w.Visible || !w.Settled || w.Waited != 660 || w.ClearsIn != 0 {
		t.Fatalf("wait report %+v: want settled after 660 s", *w)
	}
	// Without --settle: done as soon as it is visible.
	pinAt(f.zone, oldAcct, 600*time.Second)
	code, out, _ = f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly("")))
	if w := decodeApply(t, out).Wait; code != exitOK || w.Waited != 0 {
		t.Fatalf("apply without --settle = %d, %+v", code, *w)
	}
}

// --settle when the old TTL is beyond the cap: no pointless wait, exit 1,
// and when the caches clear.
func TestToolWaitSettleBeyondCap(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, time.Hour)
	useVirtualClock(t)
	code, out, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if code != exitProblem {
		t.Fatalf("= %d %s %s", code, out, errs)
	}
	w := decodeApply(t, out).Wait
	if !w.Visible || w.Settled || w.Waited != 0 || w.ClearsIn != 3660 {
		t.Fatalf("wait report %+v: want visible, not settled, clears in 3660 s, no wait", *w)
	}
	for _, want := range []string{"were written", "TTL 3600 s, longer than one run waits", "lower the TTL at the provider"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr %q lacks %q", errs, want)
		}
	}
}

func TestToolWaitUsage(t *testing.T) {
	f := newToolFixture(t)
	for _, args := range [][]string{{"apply", "--settle"}, {"apply", "--wait", "soon"}, {"apply", "--wait", "0s"}, {"plan", "--settle"}} {
		if code, _, _ := f.run(args, toolJSON(nil)); code != exitUsage {
			t.Errorf("%v = %d, want usage", args, code)
		}
	}
}

// The provider's records can't be read back after the write: assume the
// worst TTL (the whole cap), never a short wait.
func TestToolWaitUnreadableTTL(t *testing.T) {
	f := newToolFixture(t)
	useVirtualClock(t)
	gets := 0
	f.hook = func(op string, _ []libdns.Record) error {
		if op == "get" {
			gets++
			if gets > 2 { // Apply's own read and Stored before it pass
				return errors.New("provider down")
			}
		}
		return nil
	}
	f.resolvers = []string{neverVisible(t)}
	code, out, errs := f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct)))
	if code != exitProblem {
		t.Fatalf("= %d %s %s", code, out, errs)
	}
	if w := decodeApply(t, out).Wait; w.TTL != 840 || w.Limit != 900 {
		t.Fatalf("wait report %+v: want the cap", *w)
	}
}

// C1: a rerun after an unsettled relax must not forget the old pin's TTL.
// Run 1 (old pin at TTL 3600) exits 1 at once; the zone now holds CA-only
// at TTL 300. Run 2 with the settle point run 1 reported
// (--settle-after) also refuses, until the clock passes it.
func TestToolSettleAfterRerun(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, time.Hour)
	c := useVirtualClock(t)
	code, out, _ := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	w1 := decodeApply(t, out).Wait
	if code != exitProblem || !w1.BeyondCap || w1.SettleAt != c.now.Add(3660*time.Second).Unix() {
		t.Fatalf("run 1 = %d %+v", code, *w1)
	}
	after := fmt.Sprint(w1.SettleAt)
	code, out, errs := f.run([]string{"apply", "--wait", "auto", "--settle", "--settle-after", after}, toolJSON(caaOnly("")))
	w2 := decodeApply(t, out).Wait
	if code != exitProblem || w2.Settled || w2.SettleAt != w1.SettleAt || w2.Waited != 0 {
		t.Fatalf("run 2 right away = %d %+v %s (would order against the old pin)", code, *w2, errs)
	}
	// Without --settle-after the rerun only sees the CA-only TTL: that is
	// what the shell's saved settle point is for.
	c.mu.Lock()
	c.now = c.now.Add(3600 * time.Second)
	c.mu.Unlock()
	code, out, errs = f.run([]string{"apply", "--wait", "auto", "--settle", "--settle-after", after}, toolJSON(caaOnly("")))
	if w3 := decodeApply(t, out).Wait; code != exitOK || !w3.Settled || w3.Waited != 60 {
		t.Fatalf("run 3, 60 s before the settle point = %d %+v %s", code, *w3, errs)
	}
}

// I1: a pending resolver showing a longer remaining TTL than the stored
// one moves the settle point (the CA's caches may hold as long).
func TestToolSettleFollowsResolverTTL(t *testing.T) {
	f := newToolFixture(t)
	f.deleteMode = "porkbun"
	pinAt(f.zone, oldAcct, 600*time.Second)
	stale := fakedns.NewZone()
	left := 750 * time.Second
	pinAt(stale, oldAcct, left)
	srv, err := fakedns.Serve(stale, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	c := useVirtualClock(t)
	c.onSleep = func(d time.Duration) {
		left -= d
		if left > 0 {
			pinAt(stale, oldAcct, left)
			return
		}
		stale.Set("portcullis.example.test", f.zone.Records("portcullis.example.test")...)
	}
	f.resolvers = append(f.resolvers, srv.Addr)
	code, out, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if w := decodeApply(t, out).Wait; code != exitOK || !w.Settled || w.Waited < 810 {
		t.Fatalf("= %d %+v %s: want settled no earlier than 750 + 60 s", code, *w, errs)
	}
}

// I1: a stored TTL of 0 or 1 (Cloudflare's "auto", Hetzner's zone
// default) is unknown: the TTL the authoritative servers serve counts.
func TestToolStoredTTLUnknown(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, 3600*time.Second) // what the nameservers serve
	zero := time.Duration(0)
	f.storedTTL = &zero
	useVirtualClock(t)
	code, out, _ := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if w := decodeApply(t, out).Wait; code != exitProblem || w.TTL != 3600 || !w.BeyondCap {
		t.Fatalf("stored 0, served 3600 = %d %+v", code, *w)
	}
	one := time.Second
	f.storedTTL = &one
	pinAt(f.zone, oldAcct, 300*time.Second)
	code, out, _ = f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if w := decodeApply(t, out).Wait; code != exitOK || w.TTL != 300 {
		t.Fatalf("stored 1, served 300 = %d %+v", code, *w)
	}
	// No authoritative answer either: unknown. A plain wait (dns setup,
	// the tighten) assumes the whole cap; --settle refuses before writing
	// (I7: a guess would become the saved settle point).
	toolAuthServers = func(context.Context, []string, string) []string { return nil }
	pinAt(f.zone, oldAcct, 300*time.Second)
	code, out, _ = f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct)))
	if w := decodeApply(t, out).Wait; code != exitOK || w.TTL != secs(unknownTTL) {
		t.Fatalf("stored 1, nothing served, no --settle = %d %+v", code, *w)
	}
	pinAt(f.zone, oldAcct, 300*time.Second)
	code, out, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if code != exitFailure || out != "" || !strings.Contains(errs, "set an explicit TTL at fake-tool") {
		t.Fatalf("stored 1, nothing served, --settle = %d %q %s", code, out, errs)
	}
	if rr := f.zone.Records("portcullis.example.test"); len(rr) != 2 || !strings.Contains(rr[0].Data, "acct/1") {
		t.Fatalf("--settle with an unknown TTL wrote: %v", rr)
	}
	if code, _, errs := f.run([]string{"ttl"}, toolJSON(caaOnly(""))); code != exitFailure || !strings.Contains(errs, "set an explicit TTL") {
		t.Fatalf("ttl with an unknown TTL = %d %s", code, errs)
	}
}

// I7: under --settle a failed read before the write refuses: nothing
// written. Without --settle the wait just assumes the cap.
func TestToolSettlePreWriteReadFails(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, 600*time.Second)
	useVirtualClock(t)
	gets := 0
	f.hook = func(op string, _ []libdns.Record) error {
		if op == "get" {
			gets++
			if gets == 1 {
				return errors.New("provider flaked")
			}
		}
		return nil
	}
	code, out, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if code != exitFailure || out != "" || !strings.Contains(errs, "nothing changed") {
		t.Fatalf("--settle, pre-write read failed = %d %q %s", code, out, errs)
	}
	if rr := f.zone.Records("portcullis.example.test"); len(rr) != 2 || !strings.Contains(rr[0].Data, "acct/1") {
		t.Fatalf("written although the read failed: %v", rr)
	}
	gets = 0
	if code, out, _ := f.run([]string{"apply", "--wait", "auto"}, toolJSON(caaOnly(newAcct))); code == exitFailure {
		t.Fatalf("no --settle, pre-write read failed = %d %s", code, out)
	}
}

// I8: right after the write, before the wait, the progress line carries
// the settle point (written_at + TTL + margin) for the shell to save.
func TestToolProgressSettlePoint(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, 600*time.Second)
	c := useVirtualClock(t)
	start := c.now
	_, _, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	want := fmt.Sprintf("settle_at=%d", start.Add(660*time.Second).Unix())
	first, _, _ := strings.Cut(errs, "\n")
	if !strings.HasPrefix(first, "domains dns apply: written;") || !strings.Contains(first, "written_at=") || !strings.Contains(errs, want) {
		t.Fatalf("progress line %q (want %s on the first line)", errs, want)
	}
}

// I6: ttl says whether the caa set is already CA-only (a relax happened).
func TestToolTTLRelaxed(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, 600*time.Second)
	var r struct {
		TTL     int  `json:"ttl"`
		Relaxed bool `json:"caa_relaxed"`
	}
	_, out, _ := f.run([]string{"ttl"}, toolJSON(caaOnly("")))
	if json.Unmarshal([]byte(out), &r) != nil || r.Relaxed || r.TTL != 600 {
		t.Fatalf("pinned: %s", out)
	}
	pinAt(f.zone, "", 600*time.Second)
	_, out, _ = f.run([]string{"ttl"}, toolJSON(caaOnly("")))
	if json.Unmarshal([]byte(out), &r) != nil || !r.Relaxed {
		t.Fatalf("CA-only: %s", out)
	}
}

// The served TTL counts when it is longer than the stored one.
func TestToolServedTTLLonger(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, 1200*time.Second)
	short := 300 * time.Second
	f.storedTTL = &short
	useVirtualClock(t)
	code, out, _ := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	if w := decodeApply(t, out).Wait; code != exitProblem || w.TTL != 1200 {
		t.Fatalf("stored 300, served 1200 = %d %+v", code, *w)
	}
}

// `dns ttl`: the TTL caches may hold the sets' current records for,
// read before any write (the shell saves it before the relax).
func TestToolTTL(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, 1800*time.Second)
	code, out, errs := f.run([]string{"ttl"}, toolJSON(caaOnly("")))
	var r struct {
		TTL int `json:"ttl"`
	}
	if code != exitOK || json.Unmarshal([]byte(out), &r) != nil || r.TTL != 1800 {
		t.Fatalf("ttl = %d %q %s", code, out, errs)
	}
	if len(f.zone.Records("portcullis.example.test")) != 2 || !strings.Contains(f.zone.Records("portcullis.example.test")[0].Data, "acct/1") {
		t.Fatal("ttl wrote something")
	}
	if code, _, _ := f.run([]string{"ttl"}, toolJSON(readOnly)); code != exitUsage {
		t.Fatalf("ttl without a provider = %d", code)
	}
}

// I5 + M1: the beyond-cap message names the cause, the time the caches
// clear and the way to shorten it; after the write one progress line says
// how long this run waits.
func TestToolWaitMessages(t *testing.T) {
	f := newToolFixture(t)
	pinAt(f.zone, oldAcct, time.Hour)
	c := useVirtualClock(t)
	_, _, errs := f.run([]string{"apply", "--wait", "auto", "--settle"}, toolJSON(caaOnly("")))
	clear := c.now.Add(3660 * time.Second).UTC().Format("15:04 MST")
	for _, want := range []string{"written; waiting up to 15m0s for " + f.resolvers[0], "TTL 3600 s, longer than one run waits (15m0s)", "after " + clear, "lower the TTL at the provider"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr %q lacks %q", errs, want)
		}
	}
}
