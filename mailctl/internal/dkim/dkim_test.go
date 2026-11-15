package dkim

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

const rotate = 4320 * time.Hour

// created fills in what Stalwart answers to the create actions.
func created(st State, acts []Action) State {
	for _, a := range acts {
		if a.Kind != "create" {
			continue
		}
		for i := range st.Keys {
			if st.Keys[i].Selector == a.Key.Selector && st.Keys[i].Domain == a.Key.Domain {
				st.Keys[i].ID, st.Keys[i].PublicKey = "id-"+a.Key.Selector, "P"+a.Key.Selector
			}
		}
	}
	return st
}

func stages(st State) string {
	var s []string
	for _, k := range st.Keys {
		s = append(s, k.Selector+"="+k.Stage)
	}
	return strings.Join(s, " ")
}

func none(string, string) bool { return false }
func all(string, string) bool  { return true }

func TestDKIMPendingNeedsBothResolvers(t *testing.T) {
	st, acts := Step(State{}, "example.com", t0, rotate, none)
	if len(acts) != 2 || acts[0].Kind != "create" || acts[0].Key.Selector != "v1-ed25519-20261115" || acts[1].Key.Selector != "v1-rsa-20261115" {
		t.Fatalf("first step %+v", acts)
	}
	st = created(st, acts)
	// The resolver view says no (one resolver, or a failed lookup): pending.
	st, acts = Step(st, "example.com", t0.Add(time.Hour), rotate, none)
	if len(acts) != 0 || stages(st) != "v1-ed25519-20261115=pending v1-rsa-20261115=pending" {
		t.Fatalf("not visible: %s %+v", stages(st), acts)
	}
	seen := map[string]bool{}
	st, acts = Step(st, "example.com", t0.Add(2*time.Hour), rotate, func(n, v string) bool {
		seen[n+" "+v] = true
		return true
	})
	if stages(st) != "v1-ed25519-20261115=active v1-rsa-20261115=active" || len(acts) != 2 {
		t.Fatalf("visible: %s %+v", stages(st), acts)
	}
	if !seen["v1-rsa-20261115._domainkey.example.com v=DKIM1; k=rsa; P"+"v1-rsa-20261115"] && !seen["v1-rsa-20261115._domainkey.example.com v=DKIM1; k=rsa; p=Pv1-rsa-20261115"] {
		t.Fatalf("visibility asked for %v", seen)
	}
}

func setup(t *testing.T) State {
	st, acts := Step(State{}, "example.com", t0, rotate, none)
	st = created(st, acts)
	st, _ = Step(st, "example.com", t0, rotate, all)
	return st
}

func TestDKIMRotateNow(t *testing.T) {
	st := setup(t)
	st.RotateNow = map[string]bool{"example.com": true}
	st, acts := Step(st, "example.com", t0.Add(time.Hour), rotate, none)
	if len(acts) != 2 || acts[0].Key.Selector != "v1-ed25519-20261115-2" {
		t.Fatalf("rotate now: %+v", acts)
	}
	if st.RotateNow["example.com"] {
		t.Fatal("the request wasn't consumed")
	}
	st = created(st, acts)
	st, acts = Step(st, "example.com", t0.Add(2*time.Hour), rotate, all)
	if stages(st) != "v1-ed25519-20261115=retiring v1-rsa-20261115=retiring v1-ed25519-20261115-2=active v1-rsa-20261115-2=active" {
		t.Fatalf("after: %s", stages(st))
	}
	if len(Published(st, "example.com")) != 4 {
		t.Fatal("retiring keys must stay published")
	}
}

func TestDKIMRetireAndDelete(t *testing.T) {
	st := setup(t)
	st.RotateNow = map[string]bool{"example.com": true}
	st, acts := Step(st, "example.com", t0, rotate, none)
	st = created(st, acts)
	st, _ = Step(st, "example.com", t0, rotate, all)
	st, acts = Step(st, "example.com", t0.Add(RetireAfter-time.Minute), rotate, all)
	if len(acts) != 0 {
		t.Fatalf("early: %+v", acts)
	}
	st, acts = Step(st, "example.com", t0.Add(RetireAfter), rotate, all)
	if len(acts) != 2 || acts[0].Stage != Retired || len(Published(st, "example.com")) != 2 {
		t.Fatalf("retire: %+v %d", acts, len(Published(st, "example.com")))
	}
	st, acts = Step(st, "example.com", t0.Add(RetireAfter+DeleteAfter), rotate, all)
	if len(acts) != 2 || acts[0].Kind != "destroy" || len(st.Keys) != 2 {
		t.Fatalf("delete: %+v %s", acts, stages(st))
	}
}

func TestDKIMRotationEvery180Days(t *testing.T) {
	st := setup(t)
	_, acts := Step(st, "example.com", t0.Add(rotate-time.Hour), rotate, none)
	if len(acts) != 0 {
		t.Fatal("rotated early")
	}
	_, acts = Step(st, "example.com", t0.Add(rotate), rotate, none)
	if len(acts) != 2 || acts[0].Kind != "create" {
		t.Fatalf("not rotated at 180 days: %+v", acts)
	}
}

func TestDKIMStuck24h(t *testing.T) {
	st, acts := Step(State{}, "example.com", t0, rotate, none)
	st = created(st, acts)
	if len(Stuck(st, "example.com", t0.Add(24*time.Hour))) != 0 {
		t.Fatal("stuck at exactly 24 h")
	}
	if len(Stuck(st, "example.com", t0.Add(25*time.Hour))) != 2 {
		t.Fatal("not stuck after 25 h")
	}
}

func TestDKIMCreateRetried(t *testing.T) {
	st, _ := Step(State{}, "example.com", t0, rotate, none) // creates failed: no ids
	st2, acts := Step(st, "example.com", t0.Add(time.Minute), rotate, all)
	if len(acts) != 2 || acts[0].Kind != "create" || acts[0].Key.Selector != "v1-ed25519-20261115" || len(st2.Keys) != 2 {
		t.Fatalf("retry: %+v %s", acts, stages(st2))
	}
}

func TestGenerate(t *testing.T) {
	for _, a := range Algorithms {
		k, p, err := Generate(a)
		if err != nil || !strings.HasPrefix(k, "-----BEGIN PRIVATE KEY-----") || len(p) == 0 || p[0] == "" {
			t.Fatalf("%s: %v", a, err)
		}
		if a == RSA && (len(p) != 2 || len(p[0]) < 360) {
			t.Fatalf("rsa p= %v", p)
		}
	}
}

func TestSelfTest(t *testing.T) {
	for _, a := range Algorithms {
		k, p, err := Generate(a)
		if err != nil {
			t.Fatal(err)
		}
		for _, pub := range p {
			if err := SelfTest(k, a, pub); err != nil {
				t.Fatalf("%s %s: %v", a, pub[:8], err)
			}
		}
		_, other, _ := Generate(a)
		if err := SelfTest(k, a, other[0]); err == nil {
			t.Fatalf("%s: verified with another key", a)
		}
	}
}
