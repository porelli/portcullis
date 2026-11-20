package main

// The k3s tokens (contract §20.2, §20.4). nodeadm is the only holder of the
// server token (the Secret nodeadm-k3s-token, key token, which the CLI fills
// from /var/lib/rancher/k3s/server/token with --from-file). An agent gets a
// bootstrap token instead: a bootstrap.kubernetes.io/token Secret in
// kube-system, TTL ≤ 15 min, usage authentication only, the k3s bootstrap
// group only (judged by the VAP portcullis-nodeadm-tokens). Both reach the
// node in k3s's CA-pinned form K10<sha256 of the cluster CA>::<credentials>.
// Logs carry a token's id at most (a bootstrap token's id, or "server").

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tokenSecret      = "nodeadm-k3s-token"
	tokenKey         = "token"
	agentTokenKey    = "agent"
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
		return "", fmt.Errorf("reading the Secret %s: %w", tokenSecret, err)
	}
	t := strings.TrimSpace(string(sec.Data[tokenKey]))
	if !k10Re.MatchString(t) {
		return "", errors.New("the Secret " + tokenSecret + " doesn't hold a K10 server token")
	}
	return t, nil
}

// agentToken reads the agent token (k3s --agent-token-file, K10…::node:…):
// what agents hold; never the server token.
func (s *Server) agentToken(ctx context.Context) (string, error) {
	sec, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Get(ctx, tokenSecret, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("reading the Secret %s: %w", tokenSecret, err)
	}
	t := strings.TrimSpace(string(sec.Data[agentTokenKey]))
	m := k10Re.FindStringSubmatch(t)
	if m == nil || strings.HasPrefix(m[2], serverTokenLabel+":") {
		return "", errors.New("the Secret " + tokenSecret + " doesn't hold a K10 agent token")
	}
	return t, nil
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

// bootstrapToken creates one bootstrap token for an agent's join.
func (s *Server) bootstrapToken(ctx context.Context) (string, error) {
	server, err := s.serverToken(ctx)
	if err != nil {
		return "", err
	}
	id, err := randString(s.rand, 6)
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
		return "", fmt.Errorf("creating bootstrap token %s: %w", id, redactErr(err, secret))
	}
	s.log.Info("bootstrap token created", "token_id", id, "expires_in", bootstrapTTL.String())
	return "K10" + caHash(server) + "::" + id + "." + secret, nil
}

// rotateServerToken (mode=revoke, §20.2 / §20.4): BOTH k3s tokens are
// replaced (the revoked node knew the server token, or the agent token).
//  1. a new server token through a surviving server's nodeagent (step
//     rotate), checked with server-bootstrap (old 401, new 200);
//  2. a new agent token (K10<ca>::node:<random>) through the same server
//     (step rotate-agent: the supervisor's rotation of the agent token),
//     checked with an agent-authenticated call (old 401, new 200);
//  3. both into the Secret nodeadm-k3s-token;
//  4. each server, one at a time: step apply (its token-file, the new
//     server token) and apply-agent (its agent-token-file), Ready again;
//  5. each agent: step apply with the new agent token (never a server
//     token), Ready again.
//
// Every token travels as a request body to a nodeagent, which keeps it in
// 0600 files only. gone is the revoked node.
func (s *Server) rotateServerToken(ctx context.Context, gone string) error {
	old, err := s.serverToken(ctx)
	if err != nil {
		return err
	}
	oldAgent, err := s.agentToken(ctx)
	if err != nil {
		return err
	}
	newTok, err := newK10(caHash(old), serverTokenLabel)
	if err != nil {
		return err
	}
	newAgent, err := newK10(caHash(old), "node")
	if err != nil {
		return err
	}
	secrets := []string{old, oldAgent, newTok, newAgent}
	cl, err := s.clusterNodes(ctx)
	if err != nil {
		return err
	}
	var servers, agents []clusterNode
	for _, n := range cl {
		if n.Name == gone || n.Mesh == "" {
			continue
		}
		if n.Role == "server" {
			servers = append(servers, n)
		} else {
			agents = append(agents, n)
		}
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	var rot *clusterNode
	for i := range servers {
		if servers[i].Ready {
			rot = &servers[i]
			break
		}
	}
	if rot == nil {
		return errors.New("no Ready server to rotate the k3s tokens on")
	}
	call := func(n clusterNode, tok, step string) error {
		if err := s.agents.TokenRotate(ctx, n.Name, n.Mesh, tok, step); err != nil {
			return fmt.Errorf("token %s on %s: %w", step, n.Name, redactErr(err, secrets...))
		}
		return nil
	}
	if err := call(*rot, newTok, "rotate"); err != nil {
		return err
	}
	if err := call(*rot, newAgent, "rotate-agent"); err != nil {
		return err
	}
	if s.bootstrap != nil {
		oldSt, err1 := s.bootstrap.Status(ctx, rot.Mesh, old)
		newSt, err2 := s.bootstrap.Status(ctx, rot.Mesh, newTok)
		if err1 != nil || err2 != nil || oldSt != http.StatusUnauthorized || newSt != http.StatusOK {
			return fmt.Errorf("the rotated server token isn't in effect on %s (old %d, new %d)", rot.Name, oldSt, newSt)
		}
		oldSt, err1 = s.bootstrap.AgentStatus(ctx, rot.Mesh, oldAgent)
		newSt, err2 = s.bootstrap.AgentStatus(ctx, rot.Mesh, newAgent)
		if err1 != nil || err2 != nil || oldSt != http.StatusUnauthorized || newSt != http.StatusOK {
			return fmt.Errorf("the rotated agent token isn't in effect on %s (old %d, new %d)", rot.Name, oldSt, newSt)
		}
	}
	sec, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Get(ctx, tokenSecret, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading the Secret %s: %w", tokenSecret, err)
	}
	sec.Data = map[string][]byte{tokenKey: []byte(newTok), agentTokenKey: []byte(newAgent)}
	sec.StringData = nil
	if _, err := s.kube.CoreV1().Secrets(s.cfg.CoreNS).Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("writing the Secret %s: %w", tokenSecret, err)
	}
	s.log.Info("k3s server and agent tokens rotated", "on", rot.Name)
	for _, n := range servers {
		if err := call(n, newTok, "apply"); err != nil {
			return err
		}
		if err := call(n, newAgent, "apply-agent"); err != nil {
			return err
		}
		if err := s.waitReady(ctx, n.Name); err != nil {
			return err
		}
		s.log.Info("k3s tokens applied", "node", n.Name)
	}
	for _, n := range agents {
		if err := call(n, newAgent, "apply"); err != nil {
			return err
		}
		if err := s.waitReady(ctx, n.Name); err != nil {
			return err
		}
		s.log.Info("k3s agent token applied", "node", n.Name)
	}
	return nil
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
