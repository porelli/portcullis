package main

// nodeadm's clients: enroll (its own bearer), the nodeagents (mTLS with
// nodeadm.control), etcd (the server's etcd client certificate) and the
// k3s supervisor's server-bootstrap check.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ── enroll ──

type enrollClient struct {
	base       string // http://enroll.<core ns>.svc:8444
	bearerFile string
	http       *http.Client
}

func (e *enrollClient) bearer() (string, error) {
	b, err := os.ReadFile(e.bearerFile)
	if err != nil {
		return "", fmt.Errorf("nodeadm's enroll bearer: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if len(t) < 32 {
		return "", errors.New("nodeadm's enroll bearer is too short")
	}
	return t, nil
}

func (e *enrollClient) post(ctx context.Context, path string, body any, out any) error {
	tok, err := e.bearer()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("enroll %s: %w", path, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(rb, &e)
		return fmt.Errorf("enroll %s answered %d: %s", path, resp.StatusCode, trunc(redact(e.Error), 200))
	}
	if out != nil {
		return json.Unmarshal(rb, out)
	}
	return nil
}

func (e *enrollClient) Sign(ctx context.Context, role, cn, csrPEM string) (*SignedCert, error) {
	var out struct {
		Certificate string `json:"certificate"`
		Serial      string `json:"serial"`
		NotAfter    string `json:"not_after"`
		CA          string `json:"ca"`
	}
	if err := e.post(ctx, "/internal/nodes/sign", map[string]string{"role": role, "common_name": cn, "csr": csrPEM}, &out); err != nil {
		return nil, err
	}
	na, err := time.Parse(time.RFC3339, out.NotAfter)
	if err != nil {
		return nil, errors.New("enroll's not_after doesn't parse")
	}
	return &SignedCert{CertPEM: out.Certificate, Serial: out.Serial, NotAfter: na, CAPEM: out.CA}, nil
}

func (e *enrollClient) Revoke(ctx context.Context, serial string) error {
	return e.post(ctx, "/internal/nodes/revoke", map[string]string{"serial": serial}, nil)
}

// ── certificates nodeadm holds ──

// newKeyCSR: a P-256 key and a CSR naming exactly CN (no SANs).
func newKeyCSR(cn string) (*ecdsa.PrivateKey, string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		return nil, "", err
	}
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func keyPEM(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// dueForRenewal: less than ⅓ of the certificate's life left.
func dueForRenewal(c *x509.Certificate, now time.Time) bool {
	life := c.NotAfter.Sub(c.NotBefore)
	return c.NotAfter.Sub(now) < life/3
}

// ensureOwnCert signs nodeadm's node-nodeadm certificate (CN
// nodeadm.control, SAN nodeadm.portcullis-nodeadm.svc; key in memory only)
// when it has none or ⅓ of its life is left, and learns the pki_node CA.
func (s *Server) ensureOwnCert(ctx context.Context) error {
	s.pki.mu.RLock()
	own, end := s.pki.own, s.pki.ownEnd
	s.pki.mu.RUnlock()
	if own != nil && own.Leaf != nil && !dueForRenewal(own.Leaf, s.now()) && s.now().Before(end) {
		return nil
	}
	k, csr, err := newKeyCSR(clientNodeadm)
	if err != nil {
		return err
	}
	sc, err := s.enroll.Sign(ctx, "node-nodeadm", clientNodeadm, csr)
	if err != nil {
		return err
	}
	if err := s.pki.setCA(sc.CAPEM); err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(sc.CertPEM), keyPEM(k))
	if err != nil {
		return fmt.Errorf("the node-nodeadm certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || !slicesContains(leaf.DNSNames, s.serviceName()) {
		return errors.New("the node-nodeadm certificate doesn't name " + s.serviceName())
	}
	cert.Leaf = leaf
	s.pki.mu.Lock()
	s.pki.own, s.pki.ownEnd = &cert, leaf.NotAfter
	s.pki.mu.Unlock()
	s.log.Info("node-nodeadm certificate signed", "serial", certSerial(leaf), "not_after", rfc3339(leaf.NotAfter))
	return nil
}

func slicesContains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

const (
	clientNodeadm   = "nodeadm.control"
	frontdoorSecret = "frontdoor-control-tls"
)

func (s *Server) serviceName() string { return "nodeadm." + s.cfg.NodeadmNS + ".svc" }

// ensureFrontdoorCert keeps the front door's frontdoor.control certificate
// in the Secret frontdoor-control-tls (tls.crt, tls.key, ca.crt), renewed at
// ⅓ left. No Secret (HA off: the chart renders none): nothing to do.
func (s *Server) ensureFrontdoorCert(ctx context.Context) error {
	secs := s.kube.CoreV1().Secrets(s.cfg.CoreNS)
	sec, err := secs.Get(ctx, frontdoorSecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if b, _ := pem.Decode(sec.Data["tls.crt"]); b != nil {
		if c, err := x509.ParseCertificate(b.Bytes); err == nil && !dueForRenewal(c, s.now()) &&
			string(sec.Data["ca.crt"]) == s.pki.caPEMString() {
			return nil
		}
	}
	k, csr, err := newKeyCSR(clientFrontdoor)
	if err != nil {
		return err
	}
	sc, err := s.enroll.Sign(ctx, "node-frontdoor", clientFrontdoor, csr)
	if err != nil {
		return err
	}
	sec.Data = map[string][]byte{"tls.crt": []byte(sc.CertPEM), "tls.key": keyPEM(k), "ca.crt": []byte(sc.CAPEM)}
	if _, err := secs.Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("writing the Secret %s: %w", frontdoorSecret, err)
	}
	s.log.Info("frontdoor.control certificate written", "serial", sc.Serial)
	return nil
}

// ── the nodeagents ──

type agentClient struct{ s *Server }

func (a agentClient) client(id string) (*http.Client, error) {
	own := a.s.pki.ownCert()
	pool := a.s.pki.caPool()
	if own == nil || pool == nil {
		return nil, errors.New("nodeadm has no node-nodeadm certificate yet")
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: id + "." + clusterDomain,
			Certificates: []tls.Certificate{*own}},
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, ForceAttemptHTTP2: false}}, nil
}

func (a agentClient) do(ctx context.Context, id, meshIP, method, path string, body, out any) error {
	if !meshAddrOK(meshIP) {
		return fmt.Errorf("%s has no mesh address", id)
	}
	c, err := a.client(id)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+meshIP+":7443"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("nodeagent %s %s: unreachable", id, path)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("nodeagent %s %s answered %d", id, path, resp.StatusCode)
	}
	if out != nil {
		return strictJSON(rb, out)
	}
	return nil
}

func (a agentClient) Health(ctx context.Context, id, meshIP string) (*AgentHealth, error) {
	var h AgentHealth
	if err := a.do(ctx, id, meshIP, http.MethodGet, "/v1/health", nil, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

func (a agentClient) PutProbeTargets(ctx context.Context, id, meshIP string, t ProbeTargets) error {
	return a.do(ctx, id, meshIP, http.MethodPut, "/v1/probes/targets", t, nil)
}

func (a agentClient) TokenRotate(ctx context.Context, id, meshIP, newToken, step string) error {
	// The error never carries the body (the token).
	return a.do(ctx, id, meshIP, http.MethodPost, "/v1/k3s/token-rotate", map[string]string{"new_token": newToken, "step": step}, nil)
}

// ── etcd ──

type etcdClient struct {
	endpoints []string
	tls       *tls.Config
}

func newEtcdClient(dir, hostIP string) (*etcdClient, error) {
	cert, err := tls.LoadX509KeyPair(dir+"/client.crt", dir+"/client.key")
	if err != nil {
		return nil, fmt.Errorf("etcd's client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(dir + "/server-ca.crt")
	if err != nil {
		return nil, fmt.Errorf("etcd's CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("etcd's CA doesn't parse")
	}
	if !meshAddrOK(hostIP) {
		return nil, fmt.Errorf("the node's address %q isn't a mesh address", hostIP)
	}
	return &etcdClient{endpoints: []string{"https://" + hostIP + ":2379"},
		tls: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}}, nil
}

func (e *etcdClient) connect(eps []string) (*clientv3.Client, error) {
	return clientv3.New(clientv3.Config{Endpoints: eps, TLS: e.tls, DialTimeout: 5 * time.Second})
}

func peerIP(urls []string) string {
	for _, u := range urls {
		if p, err := url.Parse(u); err == nil {
			if a, err := netip.ParseAddr(p.Hostname()); err == nil {
				return a.String()
			}
		}
	}
	return ""
}

func (e *etcdClient) Members(ctx context.Context) ([]EtcdMember, error) {
	c, err := e.connect(e.endpoints)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	l, err := c.MemberList(cctx)
	if err != nil {
		return nil, err
	}
	var out []EtcdMember
	for _, m := range l.Members {
		em := EtcdMember{ID: m.ID, Name: m.Name, PeerIP: peerIP(m.PeerURLs), Learner: m.IsLearner}
		for _, cu := range m.ClientURLs {
			sctx, scancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := c.Status(sctx, cu)
			scancel()
			if err == nil {
				em.Healthy = true
				break
			}
		}
		out = append(out, em)
	}
	return out, nil
}

func (e *etcdClient) Remove(ctx context.Context, id uint64) error {
	c, err := e.connect(e.endpoints)
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, err = c.MemberRemove(cctx, id)
	return err
}

// ── the k3s supervisor's checks ──

type k3sBootstrap struct{}

// Status: GET /v1-k3s/server-bootstrap with basic auth server:<passphrase>,
// the server's CA pinned by the token's hash (k3s's /cacerts).
func (k3sBootstrap) Status(ctx context.Context, serverIP, token string) (int, error) {
	return supervisorStatus(ctx, serverIP, token, "server", "/v1-k3s/server-bootstrap")
}

// AgentStatus: an agent's supervisor call (its kube-proxy client
// certificate) with basic auth node:<agent passphrase>.
func (k3sBootstrap) AgentStatus(ctx context.Context, serverIP, token string) (int, error) {
	return supervisorStatus(ctx, serverIP, token, "node", "/v1-k3s/client-kube-proxy.crt")
}

func supervisorStatus(ctx context.Context, serverIP, token, user, path string) (int, error) {
	m := k10Re.FindStringSubmatch(token)
	if m == nil || !meshAddrOK(serverIP) {
		return 0, errors.New("not a K10 token")
	}
	pass := m[2]
	if p, ok := strings.CutPrefix(pass, user+":"); ok {
		pass = p
	}
	base := "https://" + serverIP + ":6443"
	insecure := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // #nosec: the CA is checked against the token's hash below
	resp, err := insecure.Get(base + "/cacerts")
	if err != nil {
		return 0, err
	}
	ca, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	sum := sha256.Sum256(ca)
	if hex.EncodeToString(sum[:]) != m[1] {
		return 0, errors.New("the server's CA doesn't match the token's hash")
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: serverIP}}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	req.SetBasicAuth(user, pass)
	resp, err = c.Do(req)
	if err != nil {
		return 0, errors.New("the k3s supervisor is unreachable")
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp.StatusCode, nil
}
