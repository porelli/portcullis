package link

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/proto"

	"github.com/portcullis/wg/internal/linkdoc"
)

// NodeDomain: a worker's certificate names <server id>.node.portcullis.internal.
const NodeDomain = "node.portcullis.internal"

var (
	handshakeDesc = prometheus.NewDesc("wg_link_peer_handshake_age_seconds",
		"Seconds since the server's last WireGuard handshake (+Inf: none yet).", []string{"server"}, nil)
	rxDesc   = prometheus.NewDesc("wg_link_peer_rx_bytes_total", "Bytes received from the server.", []string{"server"}, nil)
	txDesc   = prometheus.NewDesc("wg_link_peer_tx_bytes_total", "Bytes sent to the server.", []string{"server"}, nil)
	openDesc = prometheus.NewDesc("wg_link_open_streams", "Open CONNECT streams.", nil, nil)
)

// Collectors are the role's own metrics.
func (l *Link) Collectors() []prometheus.Collector {
	return []prometheus.Collector{l.rejected, l.closed, peerCollector{l}}
}

type peerCollector struct{ l *Link }

func (c peerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- handshakeDesc
	ch <- rxDesc
	ch <- txDesc
	ch <- openDesc
}

func (c peerCollector) Collect(ch chan<- prometheus.Metric) {
	now := time.Now()
	ch <- prometheus.MustNewConstMetric(openDesc, prometheus.GaugeValue, float64(c.l.OpenStreams()))
	for _, p := range c.l.Peers() {
		age := math.Inf(1)
		if p.Handshake != nil {
			age = now.Sub(*p.Handshake).Seconds()
		}
		ch <- prometheus.MustNewConstMetric(handshakeDesc, prometheus.GaugeValue, age, p.ID)
		ch <- prometheus.MustNewConstMetric(rxDesc, prometheus.CounterValue, float64(p.Rx), p.ID)
		ch <- prometheus.MustNewConstMetric(txDesc, prometheus.CounterValue, float64(p.Tx), p.ID)
	}
}

// Agent scrape caps.
const (
	maxAgentBody     = 4 << 20
	maxAgentFamilies = 2000
	maxAgentMetrics  = 20000
	agentTimeout     = 5 * time.Second
)

// AgentGatherer fetches each ready agent's GET /v1/metrics over the
// tunnel with the link.control client certificate, verifying the agent's
// certificate for <id>.node.portcullis.internal under the pki_node CA,
// and re-labels every sample server=<id>. The files are read on every
// gather (the CLI renews the certificate in place). A missing or empty
// file means no agent is scraped; a failed agent only reports
// wg_link_agent_scrape_ok{server} 0. Families named wg_* are dropped (an
// agent can't shadow link's own metrics). It never returns an error.
type AgentGatherer struct {
	Link              *Link
	CertFile, KeyFile string
	CAFile            string
	Timeout           time.Duration

	// dial overrides the tunnel dial (tests).
	dial func(ctx context.Context, to netip.AddrPort) (net.Conn, error)
}

func (g *AgentGatherer) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(g.CertFile, g.KeyFile)
	if err != nil {
		return nil, errors.New("link: the link.control certificate is unreadable")
	}
	ca, err := os.ReadFile(g.CAFile)
	if err != nil {
		return nil, errors.New("link: the node CA is unreadable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("link: the node CA holds no certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

// Gather implements prometheus.Gatherer.
func (g *AgentGatherer) Gather() ([]*dto.MetricFamily, error) {
	l := g.Link
	l.mu.Lock()
	live, cur := l.docsLocked()
	var targets []*linkdoc.Peer
	if cur != nil && live == cur {
		for i := range cur.Peers {
			if cur.Peers[i].State == linkdoc.StateReady {
				targets = append(targets, &cur.Peers[i])
			}
		}
	}
	l.mu.Unlock()
	if len(targets) == 0 {
		return nil, nil
	}
	base, err := g.tlsConfig()
	if err != nil {
		return nil, nil // not set up yet: nothing to scrape
	}
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = agentTimeout
	}
	dial := g.dial
	if dial == nil {
		dial = l.stack.DialTCP
	}
	type result struct {
		id   string
		fams map[string]*dto.MetricFamily
	}
	results := make([]result, len(targets))
	var wg sync.WaitGroup
	for i, p := range targets {
		wg.Add(1)
		go func(i int, id string, addr netip.Addr) {
			defer wg.Done()
			fams, err := scrape(base, dial, id, addr, timeout)
			if err != nil {
				fams = nil
			}
			results[i] = result{id, fams}
		}(i, p.ID, p.Addr())
	}
	wg.Wait()

	okFam := &dto.MetricFamily{Name: proto.String("wg_link_agent_scrape_ok"), Help: proto.String("1 when the server's agent metrics were read."), Type: dto.MetricType_GAUGE.Enum()}
	merged := map[string]*dto.MetricFamily{}
	for _, r := range results {
		v := 0.0
		if r.fams != nil {
			v = 1
		}
		okFam.Metric = append(okFam.Metric, &dto.Metric{Label: []*dto.LabelPair{{Name: proto.String("server"), Value: proto.String(r.id)}}, Gauge: &dto.Gauge{Value: proto.Float64(v)}})
		for name, f := range r.fams {
			if strings.HasPrefix(name, "wg_") {
				continue
			}
			for _, m := range f.Metric {
				relabel(m, r.id)
			}
			if have, ok := merged[name]; ok {
				if have.GetType() != f.GetType() {
					continue
				}
				have.Metric = append(have.Metric, f.Metric...)
				continue
			}
			merged[name] = f
		}
	}
	out := []*dto.MetricFamily{okFam}
	names := make([]string, 0, len(merged))
	for n := range merged {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, merged[n])
	}
	return out, nil
}

func relabel(m *dto.Metric, id string) {
	ls := m.Label[:0]
	for _, lp := range m.Label {
		if lp.GetName() != "server" {
			ls = append(ls, lp)
		}
	}
	ls = append(ls, &dto.LabelPair{Name: proto.String("server"), Value: proto.String(id)})
	sort.Slice(ls, func(i, j int) bool { return ls[i].GetName() < ls[j].GetName() })
	m.Label = ls
}

func scrape(base *tls.Config, dial func(context.Context, netip.AddrPort) (net.Conn, error), id string, addr netip.Addr, timeout time.Duration) (map[string]*dto.MetricFamily, error) {
	cfg := base.Clone()
	cfg.ServerName = id + "." + NodeDomain
	to := netip.AddrPortFrom(addr, ControlPort)
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, to) },
		TLSClientConfig:   cfg,
		DisableKeepAlives: true,
		Proxy:             nil,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, "https://"+cfg.ServerName+":"+fmt.Sprint(ControlPort)+"/v1/metrics", nil)
	req.Header.Set("Accept", string(expfmt.NewFormat(expfmt.TypeTextPlain)))
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAgentBody+1))
	if err != nil || len(b) > maxAgentBody {
		return nil, errors.New("body unreadable or too large")
	}
	p := expfmt.NewTextParser(model.UTF8Validation)
	fams, err := p.TextToMetricFamilies(strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	n := 0
	for _, f := range fams {
		n += len(f.Metric)
	}
	if len(fams) > maxAgentFamilies || n > maxAgentMetrics {
		return nil, errors.New("too many metrics")
	}
	return fams, nil
}
