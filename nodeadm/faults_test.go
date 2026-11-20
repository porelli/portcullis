package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stesting "k8s.io/client-go/testing"
)

// echoInvalid: an API "invalid" answer whose message quotes the object, as
// the API server's may.
func echoInvalid(what string) error {
	e := apierrors.NewInvalid(schema.GroupKind{Kind: "Secret"}, "x", nil)
	e.ErrStatus.Message = "Secret is invalid: data: Invalid value: " + what
	return e
}

func noLeak(t *testing.T, h *harness, answer string, secrets ...string) {
	t.Helper()
	logs := h.logs.String()
	for _, sc := range secrets {
		if len(sc) < 8 {
			continue
		}
		if strings.Contains(logs, sc) {
			t.Errorf("a log line carries a secret (%.6s…)", sc)
		}
		if strings.Contains(answer, sc) {
			t.Errorf("the answer carries a secret (%.6s…): %s", sc, answer)
		}
	}
}

func joinerSecrets(j *joiner) []string {
	raw, _ := base64.RawURLEncoding.DecodeString(j.jc.Secret)
	sum := sha256.Sum256(raw)
	return []string{j.code, j.jc.Secret, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:])}
}

// TestFaultsNeverLeakSecrets (review M3): every failure path whose error
// could carry a secret (a fake echoing the request or the object into its
// error) leaves no secret in the log or the answer.
func TestFaultsNeverLeakSecrets(t *testing.T) {
	ctx := context.Background()
	t.Run("enroll Sign fails after the burn", func(t *testing.T) {
		h := newHarness(t)
		j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
		h.enroll.fail = fmt.Errorf("vault 400: csr %s code %s", j.csrPEM, j.code)
		w := h.enrol(t, j, "")
		if w.Code != 500 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		noLeak(t, h, w.Body.String(), append(joinerSecrets(j), j.csrPEM)...)
		if h.state(t).Nodes["n4"] != nil {
			t.Fatal("the serial-less record stays (M5)")
		}
	})
	t.Run("the bootstrap Secret create fails", func(t *testing.T) {
		h := newHarness(t)
		var minted string
		h.kube.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
			sec := a.(k8stesting.CreateAction).GetObject().(*corev1.Secret)
			if sec.Namespace != bootstrapNS {
				return false, nil, nil
			}
			minted = sec.StringData["token-secret"]
			return true, nil, echoInvalid(minted + " " + sec.StringData["token-id"] + "." + minted)
		})
		j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
		h.enrol(t, j, "")
		w := h.join(t, j, nearRTT)
		if w.Code != 500 || minted == "" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		noLeak(t, h, w.Body.String(), append(joinerSecrets(j), minted, testServerToken, testAgentToken)...)
	})
	t.Run("the state write fails", func(t *testing.T) {
		h := newHarness(t)
		h.kube.CoreV1().Secrets(coreNS).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: stateSecret, Namespace: coreNS}}, metav1.CreateOptions{})
		h.s.store = &secretStore{kube: h.kube, ns: coreNS}
		j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
		h.kube.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
			sec := a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret)
			if sec.Name != stateSecret {
				return false, nil, nil
			}
			return true, nil, echoInvalid(string(sec.Data[stateKey]))
		})
		w := h.enrol(t, j, "")
		if w.Code != 500 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		noLeak(t, h, w.Body.String(), joinerSecrets(j)...)
	})
	t.Run("the k3s token Secret read fails", func(t *testing.T) {
		h := newHarness(t)
		j := h.issue(t, "n5", "server", "home", "main", "10.215.0.5")
		h.enrol(t, j, "")
		h.kube.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if a.(k8stesting.GetAction).GetName() != tokenSecret {
				return false, nil, nil
			}
			return true, nil, echoInvalid(testServerToken + " " + testAgentToken)
		})
		w := h.join(t, j, nearRTT)
		if w.Code != 500 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		noLeak(t, h, w.Body.String(), append(joinerSecrets(j), testServerToken, testAgentToken,
			strings.SplitN(testServerToken, "::", 2)[1])...)
	})
	t.Run("Health fails", func(t *testing.T) {
		h := newHarness(t)
		j := h.issue(t, "n4", "agent", "cloud", "main", "10.215.0.4")
		h.enrol(t, j, "")
		h.agents.down["n4"] = true
		w := h.join(t, j, nearRTT)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "mesh_pending") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		noLeak(t, h, w.Body.String(), append(joinerSecrets(j), testServerToken, testAgentToken)...)
	})
	t.Run("TokenRotate fails echoing the token", func(t *testing.T) {
		h := newHarness(t)
		h.putState(t, func(st *nodeadmState) {
			st.Nodes["n3"] = &nodeRecord{Role: "server", Serial: "56:78", MeshIP: "10.215.0.3"}
		})
		h.agents.onRotate = h.bootFollows
		h.failAgent("rotate", true)
		w := h.internal(clientHub, "DELETE", "/v1/nodes/n3?mode=revoke", nil)
		if w.Code != 500 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		op := h.state(t).Ops["n3"]
		noLeak(t, h, w.Body.String()+op.LastError, testServerToken, testAgentToken, op.NewServer,
			strings.SplitN(op.NewServer, "::", 2)[1])
	})
}

// TestStateLoadStrict (fix round 9): a state with a field this nodeadm
// doesn't know (an older format's pending_revoke) is refused, by name and
// without its values; nodeadm doesn't start on it.
func TestStateLoadStrict(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	old := `{"v":1,"codes":{},"nodes":{"n4":{"role":"agent","serial":"","mesh_ip":"10.215.0.4","pending_revoke":["aa:bb"],"key_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}`
	h.kube.CoreV1().Secrets(coreNS).Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: stateSecret, Namespace: coreNS},
		Data: map[string][]byte{stateKey: []byte(old)}}, metav1.CreateOptions{})
	store := &secretStore{kube: h.kube, ns: coreNS}
	_, _, err := store.Load(ctx)
	if err == nil || !strings.Contains(err.Error(), `unknown field "pending_revoke"`) || strings.Contains(err.Error(), "aa:bb") || strings.Contains(err.Error(), "0123456789abcdef") {
		t.Fatalf("an older-format state: %v", err)
	}
	for _, bad := range []string{`{"v":1,"codes":{},"nodes":{}} {}`, `{"v":1,"codes":{},"nodes":{},"ops":{"n1":{"node":"n1","bogus":1}}}`, `not json`} {
		if _, err := decodeState([]byte(bad)); err == nil {
			t.Errorf("%.40q loaded", bad)
		}
	}
	// The current format round-trips.
	st := newState()
	st.queueRevoke("n4", "cc:dd", vecNow)
	b, _ := json.Marshal(st)
	if got, err := decodeState(b); err != nil || got.PendingRevokes["cc:dd"] == nil {
		t.Fatalf("the current format: %v", err)
	}
}
