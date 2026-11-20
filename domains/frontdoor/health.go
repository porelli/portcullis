package frontdoor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Cluster is the front door's view of the nodes from nodeadm's snapshot:
// each node's site, ingress role and public addresses, its readiness
// (the node Ready and its Traefik pod Ready) and its mesh address (where
// its nodeagent answers).
type Cluster struct {
	Nodes map[string]Node
	Ready map[string]bool
	Mesh  map[string]string
}

// Source gives one round's inputs.
type Source interface {
	Cluster(ctx context.Context) (Cluster, error)
	// Probes is each reachable prober's newest round (a node that doesn't
	// answer has none); errors are per node, for the log.
	Probes(ctx context.Context, c Cluster, now time.Time) ([]ProbeRound, []error)
}

// The labels nodeadm sets (§20.1).
const (
	labelSite    = "portcullis.io/site"
	labelIngress = "portcullis.io/ingress"
	defaultSite  = "main"
	maxBody      = 8 << 20
	// probeMaxAge: an older round is stale (the nodeagent probes every
	// 10 s).
	probeMaxAge = 30 * time.Second
)

// snapshot is the part of GET /v1/cluster (§20.2) the front door reads.
type snapshot struct {
	V     int `json:"v"`
	Nodes []struct {
		Name         string            `json:"name"`
		Ready        bool              `json:"ready"`
		TraefikReady bool              `json:"traefik_ready"`
		Labels       map[string]string `json:"labels"`
		Addresses    struct {
			Mesh   string   `json:"mesh"`
			Public []string `json:"public"`
		} `json:"addresses"`
	} `json:"nodes"`
}

// ParseSnapshot turns nodeadm's snapshot into a Cluster. A snapshot of
// another version, a node without a name, or a malformed address is
// refused whole (fail closed: no round).
func ParseSnapshot(b []byte) (Cluster, error) {
	var s snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return Cluster{}, fmt.Errorf("nodeadm's snapshot: %w", err)
	}
	if s.V != 1 {
		return Cluster{}, fmt.Errorf("nodeadm's snapshot: version %d", s.V)
	}
	c := Cluster{Nodes: map[string]Node{}, Ready: map[string]bool{}, Mesh: map[string]string{}}
	for _, n := range s.Nodes {
		if n.Name == "" {
			return Cluster{}, errors.New("nodeadm's snapshot: a node without a name")
		}
		if _, dup := c.Nodes[n.Name]; dup {
			return Cluster{}, fmt.Errorf("nodeadm's snapshot: node %s twice", n.Name)
		}
		site := n.Labels[labelSite]
		if site == "" {
			site = defaultSite
		}
		var pub []string
		for _, a := range n.Addresses.Public {
			ip, err := netip.ParseAddr(a)
			if err != nil || AddrType(a) == "" || !ip.IsGlobalUnicast() {
				return Cluster{}, fmt.Errorf("nodeadm's snapshot: node %s: public address %q", n.Name, a)
			}
			pub = append(pub, ip.String())
		}
		ingress := n.Labels[labelIngress] == "true"
		c.Nodes[n.Name] = Node{Site: site, Ingress: ingress, Public: pub}
		c.Ready[n.Name] = n.Ready && (n.TraefikReady || !ingress)
		if m, err := netip.ParseAddr(n.Addresses.Mesh); err == nil && m.Is4() {
			c.Mesh[n.Name] = m.String()
		}
	}
	return c, nil
}

// MTLSSource reads nodeadm's GET /v1/cluster and every nodeagent's
// GET /v1/probes with the front door's frontdoor.control certificate
// (the Secret frontdoor-control-tls, renewed by nodeadm: re-read on every
// round), verifying the servers against the pki_node CA.
type MTLSSource struct {
	// NodeadmURL is https://nodeadm.portcullis-nodeadm.svc:8443.
	NodeadmURL string
	// TLSDir holds tls.crt, tls.key and ca.crt.
	TLSDir string
	// Timeout bounds each request (5 s when zero).
	Timeout time.Duration
}

const nodeadmServerName = "nodeadm.portcullis-nodeadm.svc"

func (s MTLSSource) client(serverName string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(s.TLSDir, "tls.crt"), filepath.Join(s.TLSDir, "tls.key"))
	if err != nil {
		return nil, fmt.Errorf("the frontdoor.control certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(s.TLSDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("the pki_node CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("the pki_node CA: no certificate")
	}
	to := s.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	return &http.Client{Timeout: to, Transport: &http.Transport{
		Proxy:           nil,
		DialContext:     (&net.Dialer{Timeout: to}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName},
	}}, nil
}

func getJSON(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("GET %s: the answer is over %d bytes", req.URL.Path, maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", req.URL.Path, resp.StatusCode)
	}
	return b, nil
}

// Cluster is nodeadm's snapshot.
func (s MTLSSource) Cluster(ctx context.Context) (Cluster, error) {
	c, err := s.client(nodeadmServerName)
	if err != nil {
		return Cluster{}, err
	}
	defer c.CloseIdleConnections()
	b, err := getJSON(ctx, c, s.NodeadmURL+"/v1/cluster")
	if err != nil {
		return Cluster{}, fmt.Errorf("nodeadm: %w", err)
	}
	return ParseSnapshot(b)
}

// Probes asks every node's nodeagent at once.
func (s MTLSSource) Probes(ctx context.Context, c Cluster, now time.Time) ([]ProbeRound, []error) {
	var (
		mu   sync.Mutex
		out  []ProbeRound
		errs []error
		wg   sync.WaitGroup
	)
	for _, id := range sortedKeys(c.Mesh) {
		wg.Add(1)
		go func(id, mesh string) {
			defer wg.Done()
			r, err := s.probe(ctx, id, mesh, c.Nodes[id].Site, now)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, fmt.Errorf("node %s: %w", id, err))
				return
			}
			out = append(out, r)
		}(id, c.Mesh[id])
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Prober < out[j].Prober })
	return out, errs
}

func (s MTLSSource) probe(ctx context.Context, id, mesh, site string, now time.Time) (ProbeRound, error) {
	c, err := s.client(id + ".cluster.portcullis.internal")
	if err != nil {
		return ProbeRound{}, err
	}
	defer c.CloseIdleConnections()
	b, err := getJSON(ctx, c, "https://"+net.JoinHostPort(mesh, "7443")+"/v1/probes")
	if err != nil {
		return ProbeRound{}, err
	}
	return NewestRound(b, id, site, now)
}

// NewestRound picks a nodeagent's newest probe round from its
// GET /v1/probes answer: it must be that prober's, at its site, and at
// most 30 s old; anything else is refused (the prober has no round).
func NewestRound(b []byte, id, site string, now time.Time) (ProbeRound, error) {
	var a struct {
		Rounds []ProbeRound `json:"rounds"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return ProbeRound{}, fmt.Errorf("probes: %w", err)
	}
	if len(a.Rounds) == 0 {
		return ProbeRound{}, errors.New("probes: no round yet")
	}
	r := a.Rounds[0]
	for _, o := range a.Rounds[1:] {
		if o.T.After(r.T) {
			r = o
		}
	}
	switch {
	case r.Prober != id:
		return ProbeRound{}, fmt.Errorf("probes: a round of %q", r.Prober)
	case r.Site != site:
		return ProbeRound{}, fmt.Errorf("probes: the prober says site %q, nodeadm %q", r.Site, site)
	case now.Sub(r.T) > probeMaxAge || r.T.After(now.Add(probeMaxAge)):
		return ProbeRound{}, fmt.Errorf("probes: the newest round (%s) is stale", r.T.Format(time.RFC3339))
	}
	return r, nil
}
