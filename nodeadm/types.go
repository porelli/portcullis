package main

// The wire shapes of contract §20.2 / §20.4 / §20.9 (the Hub's
// nodeadm.Snapshot is the same JSON).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// MeshPeer is one peer of a mesh plan (§20.4 PUT /v1/mesh/peers).
type MeshPeer struct {
	ID         string   `json:"id"`
	Pub        string   `json:"pub"`
	Endpoint   *string  `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive  int      `json:"keepalive"`
}

// MeshPlan is a node's peer plan; the code carries the bootstrap one.
type MeshPlan struct {
	Peers   []MeshPeer `json:"peers"`
	Forward bool       `json:"forward"`
}

// MeshReport is what a node reports of itself at enrolment.
type MeshReport struct {
	Pub    string  `json:"pub"`
	LAN    *string `json:"lan"`
	Public *string `json:"public"`
}

// CodeReq is POST /v1/codes.
type CodeReq struct {
	ServerID string   `json:"server_id"`
	Role     string   `json:"role"`
	Class    string   `json:"class"`
	Site     string   `json:"site"`
	MeshIP   string   `json:"mesh_ip"`
	Ingress  bool     `json:"ingress"`
	Storage  bool     `json:"storage"`
	Mesh     MeshPlan `json:"mesh"`
	// PublicEndpoint: the node's forwarded public UDP endpoint
	// ("<ip:port>", optional; Task 30 fix round 1): a NATed node reports
	// none, so this is what makes it its site's gateway (siteGateway).
	PublicEndpoint string `json:"public_endpoint,omitempty"`
}

// LabelsReq is PUT /v1/nodes/{id}/labels (a full replacement).
type LabelsReq struct {
	Class   string `json:"class"`
	Site    string `json:"site"`
	Ingress bool   `json:"ingress"`
	Storage bool   `json:"storage"`
}

type Resources struct {
	CPUm     int64 `json:"cpu_m"`
	MemBytes int64 `json:"mem_bytes"`
}

type Voters struct {
	Voters  int `json:"voters"`
	Healthy int `json:"healthy"`
}

type Taint struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Effect string `json:"effect"`
}

type NodeAddresses struct {
	Mesh   string   `json:"mesh"`
	LAN    []string `json:"lan"`
	Public []string `json:"public"`
}

type SnapNode struct {
	Name          string            `json:"name"`
	Role          string            `json:"role"`
	Ready         bool              `json:"ready"`
	NotReadySince *string           `json:"not_ready_since"`
	Unschedulable bool              `json:"unschedulable"`
	Allocatable   Resources         `json:"allocatable"`
	Labels        map[string]string `json:"labels"`
	Taints        []Taint           `json:"taints"`
	Addresses     NodeAddresses     `json:"addresses"`
	TraefikReady  bool              `json:"traefik_ready"`
	FencingReady  bool              `json:"fencing_ready"`
	EtcdMember    bool              `json:"etcd_member"`
}

type SnapEnrolling struct {
	ID         string     `json:"id"`
	Role       string     `json:"role"`
	Class      string     `json:"class"`
	Site       string     `json:"site"`
	MeshIP     string     `json:"mesh_ip"`
	Mesh       MeshReport `json:"mesh"`
	EnrolledAt string     `json:"enrolled_at"`
}

type Toleration struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Effect   string `json:"effect"`
	Seconds  *int64 `json:"seconds"`
}

type Expr struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}

type PodSet struct {
	Name string `json:"name"`
	Min  int    `json:"min"`
}

type SnapPod struct {
	Name             string       `json:"name"`
	Namespace        string       `json:"namespace"`
	Node             string       `json:"node"`
	Priority         int          `json:"priority"`
	PriorityClass    string       `json:"priority_class"`
	PreemptionPolicy string       `json:"preemption_policy"`
	Requests         Resources    `json:"requests"`
	Tolerations      []Toleration `json:"tolerations"`
	RequiredAffinity [][]Expr     `json:"required_affinity"`
	AntiAffinityHost bool         `json:"anti_affinity_host"`
	SpreadHost       bool         `json:"spread_host"`
	DaemonSet        bool         `json:"daemonset"`
	Set              *PodSet      `json:"set"`
}

type Quorum struct {
	Etcd     Voters `json:"etcd"`
	Vault    Voters `json:"vault"`
	Sentinel Voters `json:"sentinel"`
}

type Postgres struct {
	Instances    int     `json:"instances"`
	SyncStandbys int     `json:"sync_standbys"`
	Primary      *string `json:"primary"`
}

type Volume struct {
	Name          string  `json:"name"`
	Robustness    string  `json:"robustness"`
	DegradedSince *string `json:"degraded_since"`
}

// Snapshot is GET /v1/cluster (§20.2), the Hub's nodeadm.Snapshot.
type Snapshot struct {
	V         int             `json:"v"`
	TakenAt   string          `json:"taken_at"`
	Nodes     []SnapNode      `json:"nodes"`
	Enrolling []SnapEnrolling `json:"enrolling"`
	Pods      []SnapPod       `json:"pods"`
	Quorum    Quorum          `json:"quorum"`
	Postgres  Postgres        `json:"postgres"`
	Volumes   []Volume        `json:"volumes"`
	Errors    []string        `json:"errors"`
	// pressure: node → condition (pressureConditions) → True; metrics only.
	pressure map[string]map[string]bool
}

// AddressesDoc is the ConfigMap portcullis-cluster-addresses (§20.9).
type AddressesDoc struct {
	V           int                `json:"v"`
	MeshCIDR    string             `json:"mesh_cidr"`
	ClusterCIDR string             `json:"cluster_cidr"`
	ServiceCIDR string             `json:"service_cidr"`
	API         []string           `json:"api"`
	Nodes       map[string]DocNode `json:"nodes"`
	// RemovedNames: every node name removed (nodeadmState.RemovedNames),
	// sorted; params removedNodes (portcullis-removed-nodes).
	RemovedNames []string `json:"removed_names"`
}

// DocNode is one node of the document: its addresses and its state
// (ruling R-ADM): pending (enrolled, no k3s material yet), active, or
// removed (being removed; the entry goes once the active admission
// generation no longer holds it).
type DocNode struct {
	Mesh   string   `json:"mesh"`
	LAN    []string `json:"lan"`
	Public []string `json:"public"`
	State  string   `json:"state"`
}

const (
	statePending = "pending"
	stateActive  = "active"
	stateRemoved = "removed"
)

func docNode(a NodeAddresses, state string) DocNode {
	return DocNode{Mesh: a.Mesh, LAN: nonNilS(a.LAN), Public: nonNilS(a.Public), State: state}
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ProbeTargets is the nodeagent's PUT /v1/probes/targets (§20.4).
type ProbeTargets struct {
	Domain     string        `json:"domain"`
	Targets    []ProbeTarget `json:"targets"`
	EgressHost string        `json:"egress_host"`
}

type ProbeTarget struct {
	Node    string `json:"node"`
	Site    string `json:"site"`
	Address string `json:"address"`
}

// AgentHealth is the nodeagent's GET /v1/health.
type AgentHealth struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	MeshIP  string `json:"mesh_ip"`
	MeshPub string `json:"mesh_pub"`
	K3s     string `json:"k3s"`
	Time    string `json:"time"`
	// Peers: each plan peer's WireGuard state, for the Hub (contract
	// §20.4, Hub Task 10); nodeadm never reads it. Without the field the
	// strict decode refused every real answer, so every join stayed
	// mesh_pending (found live, Task 30).
	Peers json.RawMessage `json:"peers,omitempty"`
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The mesh (§20.11): 10.215.0.0/24, the network and broadcast refused.
var meshPrefix = netip.MustParsePrefix("10.215.0.0/24")

func meshAddrOK(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !meshPrefix.Contains(a) || a.String() != s {
		return false
	}
	last := a.As4()[3]
	return last != 0 && last != 255
}

func checkMeshPlan(p MeshPlan) error {
	if len(p.Peers) > 256 {
		return fmt.Errorf("more than 256 peers")
	}
	for _, pr := range p.Peers {
		if !serverIDRe.MatchString(pr.ID) || !wgKeyOK(pr.Pub) {
			return fmt.Errorf("a peer's id or key")
		}
		if pr.Endpoint != nil {
			if _, err := netip.ParseAddrPort(*pr.Endpoint); err != nil {
				return fmt.Errorf("a peer's endpoint")
			}
		}
		if pr.Keepalive != 0 && pr.Keepalive != 25 {
			return fmt.Errorf("a peer's keepalive")
		}
		for _, c := range pr.AllowedIPs {
			pf, err := netip.ParsePrefix(c)
			if err != nil || !meshPrefix.Contains(pf.Addr()) || pf.Bits() < meshPrefix.Bits() {
				return fmt.Errorf("allowed_ips outside the mesh")
			}
		}
	}
	return nil
}

func checkMeshReport(m MeshReport) error {
	if !wgKeyOK(m.Pub) {
		return fmt.Errorf("pub")
	}
	for _, e := range []*string{m.LAN, m.Public} {
		if e != nil {
			if _, err := netip.ParseAddrPort(*e); err != nil {
				return fmt.Errorf("endpoint")
			}
		}
	}
	return nil
}

// wgKeyOK: a WireGuard public key, standard base64 of 32 bytes.
func wgKeyOK(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}
