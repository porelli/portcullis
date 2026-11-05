package bridge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// The gate's own request states for 2026-07-28 tools/call retries
// (SEP-2322, plan 4 task 4). A state the gate hands a client is a random
// token naming an entry kept here: single use, bound to (person, resource,
// tool, canonical arguments), valid for the confirmation's 10 minutes.
// A state with the prefix that names no live, matching entry is dropped
// with the input responses that came with it, and the call goes on as a
// fresh one; neither ever reaches the upstream.
//
//   - stateConfirm: the client is answering the gate's own URL elicitation
//     of a confirmation (§15.6).
//   - stateContinue: a call that consumed its confirmation was asked for
//     input by the companion; the entry holds the companion's own state, so
//     the retry continues that one call without a new confirmation.
const (
	gateStatePrefix  = "portcullis-gate:"
	gateStateTTL     = 10 * time.Minute
	maxGateStates    = 4096
	maxStatesPerUser = 16 // live states per person (fix round 1)
	confirmInputKey  = "portcullis_confirmation"
)

type stateKind int

const (
	stateConfirm stateKind = iota + 1
	stateContinue
)

type gateState struct {
	kind         stateKind
	user         string
	bind         string
	upstream     string // stateContinue: the companion's request state
	confirmation string // stateContinue: the id of the confirmation the call consumed
	exp          time.Time
}

type stateStore struct {
	mu sync.Mutex
	m  map[string]gateState
}

// bindingOf names a call: the person, the resource, the tool and the
// SHA-256 of its canonical arguments.
func bindingOf(k key, tool string, args json.RawMessage) string {
	sum := sha256.Sum256(args)
	return k.user + "\x00" + k.url + "\x00" + tool + "\x00" + hex.EncodeToString(sum[:])
}

// put stores st and returns its token; false when the store holds
// maxGateStates live entries, or st.user already has maxStatesPerUser (the
// caller falls back to the text answer or refuses). Expired entries are
// swept first and never count.
func (s *stateStore) put(st gateState, now time.Time) (string, bool) {
	if st.user == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]gateState{}
	}
	mine := 0
	for t, e := range s.m {
		switch {
		case !now.Before(e.exp):
			delete(s.m, t)
		case e.user == st.user:
			mine++
		}
	}
	if len(s.m) >= maxGateStates || mine >= maxStatesPerUser {
		return "", false
	}
	tok := gateStatePrefix + rand.Text()
	st.exp = now.Add(gateStateTTL)
	s.m[tok] = st
	return tok, true
}

// take removes tok and returns its entry if it is live and bound to bind.
func (s *stateStore) take(tok, bind string, now time.Time) (gateState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[tok]
	delete(s.m, tok)
	if !ok || st.bind != bind || !now.Before(st.exp) {
		return gateState{}, false
	}
	return st, true
}

// userOfBind is the person of a binding (bindingOf).
func userOfBind(bind string) string {
	u, _, _ := strings.Cut(bind, "\x00")
	return u
}
