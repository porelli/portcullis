package main

// The k3s tokens (contract §20.2, §20.4). nodeadm is the only holder of the
// server token (the Secret nodeadm-k3s-token, key token, which the CLI fills
// from /var/lib/rancher/k3s/server/token with --from-file). An agent gets a
// bootstrap token instead: a bootstrap.kubernetes.io/token Secret in
// kube-system, TTL ≤ 15 min, usage authentication only, the k3s bootstrap
// group only (judged by the VAP portcullis-nodeadm-tokens). Both reach the
// node in k3s's CA-pinned form K10<sha256 of the cluster CA>::<credentials>.
// Logs carry a token's id at most (a bootstrap token's id, or "server").
//
// There is no separate agent token (agent-token fix): no server runs with
// --agent-token-file, so k3s derives cred/passwd's node line from the
// server token, and its supported rotation (PUT /v1-k3s/token) rotates
// both and re-saves the datastore's bootstrap copy from that server's
// disk. k3s v1.37.2 has no way to rotate a separate agent token: genUsers
// rewrites passwd's node line from the file at every start, after the
// bootstrap reconcile, and nothing re-saves the datastore's copy, so the
// next start of every server is fatal ("cred/passwd newer than
// datastore"). No agent holds a shared token: after its join it restarts
// on its node identity (its kubelet client certificate, while its Node
// exists).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tokenSecret      = "nodeadm-k3s-token"
	tokenKey         = "token"
	bootstrapTTL     = 14 * time.Minute // inside the VAP's 15 min, with skew
	bootstrapGroup   = "system:bootstrappers:k3s:default-node-token"
	bootstrapNS      = "kube-system"
	tokenAlphabet    = "abcdefghijklmnopqrstuvwxyz0123456789"
	serverTokenLabel = "server"
)

// k10Re: k3s's CA-pinned token form (the nodeagent refuses anything else).
var k10Re = regexp.MustCompile(`^K10([0-9a-f]{64})::(.+)$`)

// serverToken reads the server token (never logged).
func (s *Server) serverToken(ctx context.Context) (string, error) {
	sec, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Get(ctx, tokenSecret, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading the Secret %s: %w", tokenSecret, secretErr(err))
	}
	t := strings.TrimSpace(string(sec.Data[tokenKey]))
	if !k10Re.MatchString(t) {
		return "", errors.New("the Secret " + tokenSecret + " doesn't hold a K10 server token")
	}
	return t, nil
}

// nodeCredential is the node user's credential k3s derives from a server
// token (no --agent-token-file): K10<hash>::node:<the server passphrase>.
// Only the rotation check uses it (the old one must answer 401); it is
// never given to a node.
func nodeCredential(serverTok string) string {
	m := k10Re.FindStringSubmatch(serverTok)
	if m == nil {
		return ""
	}
	pass := strings.TrimPrefix(m[2], serverTokenLabel+":")
	return "K10" + m[1] + "::node:" + pass
}

// caHash is the cluster CA's sha256 from the server token.
func caHash(token string) string {
	m := k10Re.FindStringSubmatch(token)
	if m == nil {
		return ""
	}
	return m[1]
}

// tokenID names a token in logs: "server" or a bootstrap token's id.
func tokenID(token string) string {
	m := k10Re.FindStringSubmatch(token)
	if m == nil {
		return "?"
	}
	if strings.HasPrefix(m[2], serverTokenLabel+":") {
		return serverTokenLabel
	}
	id, _, _ := strings.Cut(m[2], ".")
	return id
}

// randString: n characters of tokenAlphabet (rejection sampling).
func randString(r io.Reader, n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, 1)
	for len(out) < n {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		if int(buf[0]) < 252 {
			out = append(out, tokenAlphabet[int(buf[0])%36])
		}
	}
	return string(out), nil
}

// bootstrapToken creates bootstrap token id for an agent's join.
func (s *Server) bootstrapToken(ctx context.Context, id string) (string, error) {
	server, err := s.serverToken(ctx)
	if err != nil {
		return "", err
	}
	secret, err := randString(s.rand, 16)
	if err != nil {
		return "", err
	}
	sec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bootstrap-token-" + id, Namespace: bootstrapNS,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "portcullis-nodeadm"}},
		Type: corev1.SecretTypeBootstrapToken,
		StringData: map[string]string{
			"description":                    "Portcullis node join (nodeadm)",
			"token-id":                       id,
			"token-secret":                   secret,
			"expiration":                     rfc3339(s.now().Add(bootstrapTTL)),
			"usage-bootstrap-authentication": "true",
			"auth-extra-groups":              bootstrapGroup,
		},
	}
	if _, err := s.kube.CoreV1().Secrets(bootstrapNS).Create(ctx, sec, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("creating bootstrap token %s: %w", id, redactErr(secretErr(err), secret))
	}
	s.log.Info("bootstrap token created", "token_id", id, "expires_in", bootstrapTTL.String())
	return "K10" + caHash(server) + "::" + id + "." + secret, nil
}

// newK10: K10<ca hash>::<user>:<32 random bytes, hex>.
func newK10(ca, user string) (string, error) {
	pass := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, pass); err != nil {
		return "", err
	}
	return "K10" + ca + "::" + user + ":" + hex.EncodeToString(pass), nil
}

// waitReady waits for the node's Ready condition (Timing.NodeReady).
func (s *Server) waitReady(ctx context.Context, name string) error {
	deadline := time.Now().Add(s.timing.NodeReady)
	for {
		n, err := s.kube.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
		if err == nil && nodeReady(n) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("node %s isn't Ready again after the token apply", name)
		}
		if err := sleepCtx(ctx, s.timing.Poll); err != nil {
			return err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// redactErr removes the given secrets from an error's text.
func redactErr(err error, secrets ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, sc := range secrets {
		if sc != "" {
			msg = strings.ReplaceAll(msg, sc, "[redacted]")
		}
	}
	return errors.New(redact(msg))
}

// redact removes anything shaped like a k3s token, a join code, a PEM
// block or a bootstrap token from a log or error text (belt and braces:
// no code path puts one there).
var redactRes = []*regexp.Regexp{
	regexp.MustCompile(`K10[0-9a-fA-F]*::\S+`),
	regexp.MustCompile(`pcj2\.[A-Za-z0-9_-]+`),
	regexp.MustCompile(`-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----`),
	regexp.MustCompile(`\b[a-z0-9]{6}\.[a-z0-9]{16}\b`),
}

func redact(s string) string {
	for _, re := range redactRes {
		s = re.ReplaceAllString(s, "[redacted]")
	}
	return s
}
