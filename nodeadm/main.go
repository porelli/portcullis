// nodeadm (contract §20.1, §20.2): the only holder of the k3s server token
// and the only cluster-scoped actor besides the CLI. It runs node
// enrolment (join codes, the public /node/ paths, join.sh) and the
// internal cluster API for the Hub and the front door, Lease-guarded
// (portcullis-nodeadm), on server nodes only.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

//go:embed join.sh
var joinScript []byte

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
		default:
			fmt.Fprintln(os.Stderr, "usage: nodeadm [serve]")
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("nodeadm stopped", "err", redact(err.Error()))
		os.Exit(1)
	}
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func run(log *slog.Logger) error {
	core := env("NODEADM_CORE_NAMESPACE", "portcullis")
	cfg := Config{
		Domain:      os.Getenv("PORTCULLIS_DOMAIN"),
		CoreNS:      core,
		NodeadmNS:   env("POD_NAMESPACE", "portcullis-nodeadm"),
		IngressNS:   env("NODEADM_INGRESS_NAMESPACE", "portcullis-ingress"),
		FencingNS:   env("NODEADM_FENCING_NAMESPACE", "portcullis-fencing"),
		LonghornNS:  env("NODEADM_LONGHORN_NAMESPACE", "longhorn-system"),
		ClusterCIDR: os.Getenv("NODEADM_CLUSTER_CIDR"),
		ServiceCIDR: os.Getenv("NODEADM_SERVICE_CIDR"),
		EgressHost:  os.Getenv("NODEADM_PROBE_EGRESS_HOST"),
		PodName:     os.Getenv("POD_NAME"),
		Script:      joinScript,
		AgentFiles:  map[string]string{}, AgentSHA256: map[string]string{},
	}
	if cfg.Domain == "" || cfg.PodName == "" || cfg.ClusterCIDR == "" || cfg.ServiceCIDR == "" {
		return errors.New("PORTCULLIS_DOMAIN, POD_NAME, NODEADM_CLUSTER_CIDR and NODEADM_SERVICE_CIDR are required")
	}
	sum := sha256.Sum256(joinScript)
	cfg.ScriptSHA256 = hex.EncodeToString(sum[:])
	agentDir := env("NODEADM_AGENT_DIR", "/usr/local/lib/portcullis")
	for _, arch := range []string{"amd64", "arm64"} {
		p := filepath.Join(agentDir, "nodeagent-"+arch)
		h, err := sha256File(p)
		if err != nil {
			return fmt.Errorf("the nodeagent binary for %s: %w", arch, err)
		}
		cfg.AgentFiles[arch], cfg.AgentSHA256[arch] = p, h
	}

	rc, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return err
	}
	s := newServer(cfg)
	s.log, s.kube, s.dyn, s.rand = log, kube, dyn, rand.Reader
	s.store = &secretStore{kube: kube, ns: core}
	s.enroll = &enrollClient{base: env("NODEADM_ENROLL_URL", "http://enroll."+core+".svc:8444"),
		bearerFile: env("NODEADM_ENROLL_BEARER_FILE", "/run/portcullis/nodeadm/enroll-bearer"),
		http:       &http.Client{Timeout: 30 * time.Second}}
	s.agents = agentClient{s: s}
	s.bootstrap = k3sBootstrap{}
	fence := NewFence(kube, core, cfg.PodName)
	s.leader = fence

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 4)
	serve := func(name string, srv *http.Server, tlsOn bool) {
		var err error
		if tlsOn {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		errc <- fmt.Errorf("%s listener: %w", name, err)
	}
	pub := &http.Server{Addr: ":8080", Handler: s.PublicHandler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute}
	mm := http.NewServeMux()
	mm.Handle("GET /metrics", s.metrics.Handler())
	mm.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"leading": fence.Leading(), "serving": s.pki.ownCert() != nil})
	})
	met := &http.Server{Addr: ":9105", Handler: mm, ReadHeaderTimeout: 10 * time.Second}
	go serve("public", pub, false)
	go serve("metrics", met, false)
	go func() {
		// The internal listener needs nodeadm's own certificate first.
		for s.ensureOwnCert(ctx) != nil {
			log.Warn("waiting for enroll to sign the node-nodeadm certificate")
			if sleepCtx(ctx, 5*time.Second) != nil {
				return
			}
		}
		in := &http.Server{Addr: ":8443", Handler: s.InternalHandler(), ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 15 * time.Minute,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequestClientCert,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.pki.ownCert(), nil }}}
		serve("internal", in, true)
	}()
	go func() {
		for {
			if sleepCtx(ctx, 10*time.Minute) != nil {
				return
			}
			if err := s.ensureOwnCert(ctx); err != nil {
				log.Warn("renewing the node-nodeadm certificate", "err", redact(err.Error()))
			}
		}
	}()
	go func() {
		for {
			if _, err := s.snapshot(ctx); err != nil {
				log.Warn("snapshot", "err", redact(err.Error()))
			}
			if sleepCtx(ctx, 30*time.Second) != nil {
				return
			}
		}
	}()
	go func() { errc <- fence.Run(ctx) }()
	go func() {
		// Standing by is final: the process exits and campaigns afresh.
		<-fence.Lost()
		errc <- errors.New("the Lease portcullis-nodeadm was lost: standing by")
	}()
	go func() {
		for s.pki.ownCert() == nil {
			if sleepCtx(ctx, time.Second) != nil {
				return
			}
		}
		s.loop(ctx)
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}
