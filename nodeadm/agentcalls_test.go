package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

type seenCall struct{ method, path, body, clientCN string }

// agentServer: a nodeagent stand-in for node id (its certificate from the
// test CA), requiring a client certificate.
func agentServer(t *testing.T, h *harness, id string) (*httptest.Server, *x509.Certificate, *[]seenCall) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, leaf := h.ca.sign(id+"."+clusterDomain, &k.PublicKey, []string{id + "." + clusterDomain})
	var mu sync.Mutex
	seen := &[]seenCall{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		cn := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			cn = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		mu.Lock()
		*seen = append(*seen, seenCall{r.Method, r.URL.Path, string(b), cn})
		mu.Unlock()
		if r.URL.Path == "/v1/health" {
			w.Write([]byte(`{"id":"` + id + `","version":"1","mesh_ip":"10.215.0.1","mesh_pub":"x","k3s":"running","time":"2026-11-18T10:00:00Z"}`))
		}
	}))
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.cert)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf}},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// nodeadm's own node-nodeadm certificate.
	ok, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	oder, oleaf := h.ca.sign(clientNodeadm, &ok.PublicKey, []string{"nodeadm.portcullis-nodeadm.svc"})
	h.s.pki.mu.Lock()
	h.s.pki.own = &tls.Certificate{Certificate: [][]byte{oder}, PrivateKey: ok, Leaf: oleaf}
	h.s.pki.mu.Unlock()
	return srv, leaf, seen
}

// TestNodeagentCallVectors (review I6, M12): the exact requests nodeadm
// sends a nodeagent, over mTLS as nodeadm.control; a nodeagent whose
// certificate isn't the recorded serial, or a removed node, gets nothing.
func TestNodeagentCallVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/nodeagent_call_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Calls []struct {
			Name, Call, Via, ViaMesh, Node, NodeMesh, Token, Step, Method, Path, Body string
		} `json:"calls"`
	}
	dec := json.NewDecoder(strings.NewReader(strings.NewReplacer(`"via_mesh"`, `"viamesh"`, `"node_mesh"`, `"nodemesh"`).Replace(string(b))))
	if err := dec.Decode(&f); err != nil || len(f.Calls) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	ctx := context.Background()
	for _, c := range f.Calls {
		t.Run(c.Name, func(t *testing.T) {
			h := newHarness(t)
			srv, leaf, seen := agentServer(t, h, c.Via)
			a := agentClient{s: h.s, base: func(string) string { return srv.URL }}
			// The via node enrolled by nodeadm with this very certificate.
			h.putState(t, func(st *nodeadmState) {
				st.Nodes[c.Via] = &nodeRecord{Role: "server", Serial: certSerial(leaf), MeshIP: c.ViaMesh}
			})
			call := func() error {
				switch c.Call {
				case "etcd_remove_member":
					return a.EtcdRemoveMember(ctx, c.Via, c.ViaMesh, c.Node, c.NodeMesh)
				case "token_rotate":
					return a.TokenRotate(ctx, c.Via, c.ViaMesh, c.Token, c.Step)
				default:
					_, err := a.Health(ctx, c.Via, c.ViaMesh)
					return err
				}
			}
			if err := call(); err != nil {
				t.Fatalf("call: %v", err)
			}
			if len(*seen) != 1 {
				t.Fatalf("%d requests", len(*seen))
			}
			got := (*seen)[0]
			if got.method != c.Method || got.path != c.Path || got.body != c.Body || got.clientCN != clientNodeadm {
				t.Fatalf("sent %+v, want %s %s %s as %s", got, c.Method, c.Path, c.Body, clientNodeadm)
			}
			// Another serial recorded (a re-enrolment): refused before any request.
			h.putState(t, func(st *nodeadmState) { st.Nodes[c.Via].Serial = "de:ad" })
			if err := call(); err == nil || len(*seen) != 1 {
				t.Fatalf("a nodeagent with another serial was called: %v", err)
			} else if c.Token != "" && strings.Contains(err.Error(), c.Token) {
				t.Fatal("the error carries the token")
			}
			// A removed node: nothing.
			h.putState(t, func(st *nodeadmState) { st.Nodes[c.Via].Serial, st.Nodes[c.Via].Removed = "", true })
			if err := call(); err == nil || len(*seen) != 1 {
				t.Fatal("a removed node's nodeagent was called")
			}
		})
	}
}
