package bridge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	gateStatePrefix = "portcullis-gate:"
	gateStateTTL    = 10 * time.Minute
	maxGateStates   = 4096
	confirmInputKey = "portcullis_confirmation"
)

type stateKind int

const (
	stateConfirm stateKind = iota + 1
	stateContinue
)

type gateState struct {
	kind     stateKind
	bind     string
	upstream string // stateContinue: the companion's request state
	exp      time.Time
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

// put stores st and returns its token; false when the store is full of
// live entries (the caller falls back or refuses).
func (s *stateStore) put(st gateState, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]gateState{}
	}
	if len(s.m) >= maxGateStates {
		for t, e := range s.m {
			if !now.Before(e.exp) {
				delete(s.m, t)
			}
		}
		if len(s.m) >= maxGateStates {
			return "", false
		}
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
