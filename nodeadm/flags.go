package main

// The /node/v1/join answer's flags (contract §20.2, §20.11). A server gets
// kube_install_k3s's server flags (the shared fixture
// tests/fixtures/k3s-server-flags.txt; TestJoinFlagsEqualInitFlags holds
// them equal) with these substitutions:
//   - no --cluster-init; --server=<server_url> added;
//   - the node's own mesh address in --node-ip, --advertise-address,
//     --bind-address, --kubelet-arg=address and etcd's listen-client-urls;
//   - --node-name=<server id> (the node's Kubernetes name, §20.1);
//   - no placement label or portcullis.io/ taint (ruling R-NODELABELS):
//     nodeadm labels the registered Node (class, site and zone, ingress +
//     enablelb, storage, the Longhorn default disk at main; the small
//     taint); the joining node registers with --node-taint=
//     nodeadm.portcullis/unlabelled=true:NoSchedule until then.
// A server also gets --agent-token-file (init's; the answer's agent_token
// goes there, 0600, as the token does) and --cluster-cidr (the answer's
// cluster_cidr, init's too).
// An agent gets the subset k3s agent takes: --server, --token-file,
// --node-name, --node-ip, the registration taint, the flannel interface and
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
	// unlabelledTaint: a joining node's registration taint (its key outside
	// the prefixes kubelets may not set), removed when nodeadm labels it.
	taintUnlabelled = "nodeadm.portcullis/unlabelled"
	unlabelledTaint = taintUnlabelled + "=true:NoSchedule"
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
		// The kubelet (and kube-proxy's health / metrics) on the mesh
		// address only, through k3s's own listener setting: k3s v1.37.2's
		// agent tunnel dials the kubelet at that same address
		// (pkg/agent/config/config.go:583-591 sets ListenAddress from
		// --bind-address, pkg/daemons/agent/agent.go:226-227 makes it the
		// kubelet's address, pkg/agent/tunnel/tunnel.go:96 + :430-438 dial
		// it). A --kubelet-arg=address=<ip> alone left the tunnel dialing
		// 0.0.0.0:10250 (refused): no kubectl logs / exec / port-forward on
		// an agent (found live, Task 28).
		"--bind-address=" + ip,
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
			// init's flags (tests/fixtures/k3s-server-flags.txt): the same
			// kubelet address as --bind-address gives it.
			"--kubelet-arg=address="+ip,
			"--etcd-arg=listen-client-urls=https://"+ip+":2379,https://127.0.0.1:2379",
			"--etcd-arg=heartbeat-interval=200",
			"--etcd-arg=election-timeout=2000",
			// Fencing unconfirmed → no stateful failover (plan Task 24): no
			// volume leaves an unready node by timeout, only through SNR's
			// out-of-service taint.
			"--kube-controller-manager-arg=disable-force-detach-on-timeout=true",
		)
	}
	// No placement label and no portcullis.io/ taint (ruling R-NODELABELS:
	// a kubelet may not set them on its own Node): nodeadm sets them once
	// the Node registers (labelRegistered). Until then the registration
	// taint keeps every pod off it but a DaemonSet tolerating it (fail
	// closed: pinned pods need the labels anyway).
	f = append(f, "--node-taint="+unlabelledTaint)
	sort.Strings(f)
	return f
}
