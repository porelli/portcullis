package main

// The /node/v1/join answer's flags (contract §20.2, §20.11). A server gets
// kube_install_k3s's server flags (the shared fixture
// tests/fixtures/k3s-server-flags.txt; TestJoinFlagsEqualInitFlags holds
// them equal) with these substitutions:
//   - no --cluster-init; --server=<server_url> added;
//   - the node's own mesh address in --node-ip, --advertise-address,
//     --bind-address, --kubelet-arg=address and etcd's listen-client-urls;
//   - --node-name=<server id> (the node's Kubernetes name, §20.1);
//   - its labels: class, site (and the zone), ingress (+ ServiceLB's
//     enablelb), storage, node.longhorn.io/create-default-disk=true only on
//     a storage node at main (§20.11);
//   - --node-taint=portcullis.io/small=true:NoSchedule on class small.
// A server also gets --agent-token-file (init's; the answer's agent_token
// goes there, 0600, as the token does) and --cluster-cidr (the answer's
// cluster_cidr, init's too).
// An agent gets the subset k3s agent takes: --server, --token-file,
// --node-name, --node-ip, the labels and taint, the flannel interface and
// net-conf, the kubelet args. The token itself is never a flag: the
// nodeagent writes it to the --token-file path (0600).

import "sort"

const (
	k3sTokenFile      = "/etc/rancher/k3s/token"
	k3sAgentTokenFile = "/etc/rancher/k3s/agent-token"
	k3sFlannelConf    = "/etc/rancher/k3s/flannel-net-conf.json"
	meshIface         = "pcmesh"
	primarySite       = "main"
	smallTaint        = "portcullis.io/small=true:NoSchedule"
)

// nodeLabels are the --node-label values of a node (§20.1).
func nodeLabels(class, site string, ingress, storage bool) []string {
	l := []string{"portcullis.io/class=" + class, "portcullis.io/site=" + site, "topology.kubernetes.io/zone=" + site}
	if ingress {
		l = append(l, "portcullis.io/ingress=true", "svccontroller.k3s.cattle.io/enablelb=true")
	}
	if storage {
		l = append(l, "portcullis.io/storage=true")
		if site == primarySite {
			l = append(l, "node.longhorn.io/create-default-disk=true")
		}
	}
	return l
}

// joinFlags is the flag list for the node, sorted (as the fixture).
func joinFlags(rec *nodeRecord, id, serverURL, clusterCIDR string) []string {
	ip := rec.MeshIP
	f := []string{
		"--server=" + serverURL,
		"--token-file=" + k3sTokenFile,
		"--node-name=" + id,
		"--node-ip=" + ip,
		"--kubelet-arg=address=" + ip,
		"--kubelet-arg=pod-max-pids=1024",
		"--kubelet-arg=sync-frequency=10s",
		"--flannel-conf=" + k3sFlannelConf,
		"--flannel-iface=" + meshIface,
	}
	if rec.Role == "server" {
		f = append(f,
			"--agent-token-file="+k3sAgentTokenFile,
			"--cluster-cidr="+clusterCIDR,
			"--secrets-encryption",
			"--disable=traefik",
			"--write-kubeconfig-mode=0600",
			"--flannel-backend=wireguard-native",
			"--advertise-address="+ip,
			"--bind-address="+ip,
			"--etcd-arg=listen-client-urls=https://"+ip+":2379,https://127.0.0.1:2379",
			"--etcd-arg=heartbeat-interval=200",
			"--etcd-arg=election-timeout=2000",
		)
	}
	for _, l := range nodeLabels(rec.Class, rec.Site, rec.Ingress, rec.Storage) {
		f = append(f, "--node-label="+l)
	}
	if rec.Class == "small" {
		f = append(f, "--node-taint="+smallTaint)
	}
	sort.Strings(f)
	return f
}
