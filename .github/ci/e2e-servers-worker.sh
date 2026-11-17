#!/usr/bin/env bash
# ci.yml jobs e2e-servers / e2e-servers-podman: start one worker server and
# join it to the primary (contract §17.7), the join code on STDIN (never an
# argument; e2e_servers.py pipes it from its 0700 temp dir).
#
#   e2e-servers-worker.sh dind <name>     a docker:dind container with its own
#                                         daemon and a copy of this checkout
#   e2e-servers-worker.sh podman <name>   a pinned quay.io/podman/stable container
#                                         (systemd, user `podman`, rootless Podman
#                                         on its user socket) with a copy of this checkout
#   e2e-servers-worker.sh exec <name> <cmd…>   a command in that worker's
#                                         checkout (as its operator)
#   e2e-servers-worker.sh compose <name> <args…>  docker compose on that
#                                         worker's own files (as the CLI runs it)
#
# The worker reaches the primary only over UDP to the runner's published
# link port (portcullis.local → $RUNNER_IP in the agent's /etc/hosts, the
# operator's docker-compose.worker.override.yml). Run from the workspace root.
set -euo pipefail
: "${RUNNER_IP:?}" "${AGENT_IMAGE:=ghcr.io/porelli/portcullis-agent:edge}" "${E2E_DOMAIN:=portcullis.local}"
DIND_IMG="docker.io/library/docker:29.9.3-dind@sha256:7bf70dcb85c822e3fa6f2d332143e474b99147b9d7b39102b0cfe8b04a7dd61b"
kind="${1:?dind|podman|exec}" name="${2:?worker name}"
[[ "$name" =~ ^[a-z][a-z0-9-]{0,20}$ ]] || { echo "bad worker name"; exit 2; }
# The rootless Podman worker: a container of its own (systemd as PID 1, the
# image's user `podman` with linger, its user socket and podman-restart),
# never a user on the runner (the runner's environment leaks into a host
# user manager). Same image locally (run-job.sh) and on GitHub.
PODMAN_IMG="quay.io/podman/stable:v6.1.3-immutable@sha256:4cc31850c189386faca95d72988fe9573b3df06360cb65aea3ff5b17a04d0454"
PODMAN_WORKER_IMG=localhost/pcci-podman-worker:ci
# reviewed exception: both CI workers run privileged (dind: its own daemon;
# podman: systemd, a user manager and rootless Podman inside); never in a
# compose file or the product (tests/test_cli.sh allows it here only).
priv=(--privileged) # reviewed exception

is_podman_worker() { [ "$(docker inspect -f '{{index .Config.Labels "pcci.worker"}}' "e2e-$1" 2>/dev/null)" = podman ]; }

# pexec <name> <cmd…> — as the Podman worker's operator `podman`, in its
# user session's environment (nothing of the runner's).
pexec() {
  local n="$1" uid; shift
  uid="$(docker exec "e2e-$n" id -u podman)"
  docker exec -i -u podman -w /home/podman "e2e-$n" env -i HOME=/home/podman USER=podman LOGNAME=podman \
    PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 XDG_RUNTIME_DIR="/run/user/$uid" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" DOCKER_HOST="unix:///run/user/$uid/podman/podman.sock" "$@"
}

# wexec <name> <cmd…> — a command in the worker's checkout.
wexec() {
  local n="$1"; shift
  if is_podman_worker "$n"; then
    # shellcheck disable=SC2016  # expanded by the worker's bash
    pexec "$n" bash -c 'cd "$HOME/portcullis" && exec "$@"' bash "$@"
  else
    docker exec -i -w /opt/portcullis "e2e-$n" "$@"
  fi
}

override() {  # <extra_hosts value>
  printf 'services:\n  agent:\n    extra_hosts:\n      - "%s:%s"\n' "$E2E_DOMAIN" "$1"
}

case "$kind" in
  # The CI agent image (never the published :edge) for whatever compose
  # these run on the worker: worker join got it from the environment only.
  exec) shift 2; wexec "$name" env AGENT_IMAGE="$AGENT_IMAGE" "$@"; exit ;;
  compose)
    shift 2
    # shellcheck disable=SC2016  # expanded by the worker's bash
    wexec "$name" env AGENT_IMAGE="$AGENT_IMAGE" bash -c 'export PORTCULLIS_HOME="$PWD" PORTCULLIS_ROOT="$PWD" PORTCULLIS_LIB="$PWD/scripts/lib"
      source scripts/lib/common.sh; source scripts/lib/worker.sh; env_load; runtime_export
      exec docker compose --project-directory "$PWD" "$@"' bash "$@"
    exit ;;
  dind)
    docker run -d "${priv[@]}" --name "e2e-$name" --hostname "$name" -e DOCKER_TLS_CERTDIR= \
      -v "$PWD:/src:ro" "$DIND_IMG" >/dev/null
    for i in $(seq 1 60); do
      docker exec "e2e-$name" docker info >/dev/null 2>&1 && break
      [ "$i" -eq 60 ] && { echo "FAIL: $name's daemon"; docker logs --tail=40 "e2e-$name"; exit 1; }
      sleep 2
    done
    docker exec "e2e-$name" apk add --no-cache -q bash jq curl openssl coreutils util-linux >/dev/null
    docker exec "e2e-$name" sh -c 'cp -a /src /opt/portcullis && cd /opt/portcullis && rm -rf .env secrets/* certs/* worker-data docker-compose.ci.yml'
    docker save "$AGENT_IMAGE" | docker exec -i "e2e-$name" docker load -q
    override "$RUNNER_IP" | docker exec -i "e2e-$name" sh -c 'cat > /opt/portcullis/docker-compose.worker.override.yml'
    rt=docker ;;
  podman)
    # The setup never reads this script's stdin: that is the join code,
    # for worker join below (docker exec -i would swallow it).
    {
    echo "== podman worker $name: the image (systemd, passt, the CLI's tools)"
    printf '%s\n' "FROM $PODMAN_IMG" \
      "RUN dnf -y -q install systemd passt jq openssl procps-ng util-linux sudo findutils diffutils && dnf -y -q clean all && rm -rf /etc/containers/containers.conf /home/podman/.config/containers && echo net.ipv4.ip_unprivileged_port_start=80 > /etc/sysctl.d/90-pcci.conf && echo podman:100000:65536 > /etc/subuid && cp /etc/subuid /etc/subgid" \
      "STOPSIGNAL SIGRTMIN+3" 'CMD ["/sbin/init"]' | docker build -q -t "$PODMAN_WORKER_IMG" - >/dev/null
    docker run -d "${priv[@]}" --cgroupns=private --tmpfs /run --tmpfs /run/lock --label pcci.worker=podman \
      --name "e2e-$name" --hostname "$name" -v "$PWD:/src:ro" "$PODMAN_WORKER_IMG" >/dev/null
    for i in $(seq 1 60); do
      case "$(docker exec "e2e-$name" systemctl is-system-running 2>/dev/null)" in running|degraded) break ;; esac
      [ "$i" -eq 60 ] && { echo "FAIL: $name's systemd"; docker exec "e2e-$name" systemctl --failed --no-pager 2>&1 | tail -20; exit 1; }
      sleep 2
    done
    # The runner's docker CLI and compose plugin (the primary's versions).
    plug="$(docker info --format '{{json .ClientInfo.Plugins}}' | jq -r '.[] | select(.Name == "compose") | .Path')"
    docker cp -L "$(command -v docker)" "e2e-$name:/usr/local/bin/docker"
    docker exec "e2e-$name" mkdir -p /usr/local/lib/docker/cli-plugins
    docker cp -L "$plug" "e2e-$name:/usr/local/lib/docker/cli-plugins/docker-compose"
    docker exec "e2e-$name" sysctl -qw net.ipv4.ip_unprivileged_port_start=80
    echo "== podman worker $name: linger, the user's podman.socket + podman-restart"
    docker exec "e2e-$name" loginctl enable-linger podman
    uid="$(docker exec "e2e-$name" id -u podman)"
    for i in $(seq 1 60); do docker exec "e2e-$name" test -S "/run/user/$uid/bus" && break
      [ "$i" -eq 60 ] && { echo "FAIL: no user manager for podman in $name"; exit 1; }; sleep 1; done
    pexec "$name" systemctl --user enable --now podman.socket podman-restart.service
    for i in $(seq 1 30); do
      pexec "$name" docker version --format '{{json .Server.Components}}' 2>/dev/null | grep -q 'Podman Engine' && break
      [ "$i" -eq 30 ] && { echo "FAIL: $name's Podman socket"; pexec "$name" systemctl --user status podman.socket podman.service --no-pager 2>&1 | tail -20; exit 1; }
      sleep 2
    done
    echo "== podman worker $name: the checkout, the agent image"
    docker exec "e2e-$name" sh -c 'cp -a /src /home/podman/portcullis && cd /home/podman/portcullis && rm -rf .env secrets/* certs/* worker-data docker-compose.ci.yml && chown -R podman:podman /home/podman/portcullis'
    docker save "$AGENT_IMAGE" | pexec "$name" podman load -q
    override "$RUNNER_IP" | pexec "$name" sh -c 'cat > portcullis/docker-compose.worker.override.yml'
    } </dev/null
    rt=podman ;;
  *) echo "usage: $0 dind|podman|exec <name>"; exit 2 ;;
esac

# The code: this script's stdin, straight into worker join's stdin.
echo "== $kind worker $name: worker join"
wexec "$name" env AGENT_IMAGE="$AGENT_IMAGE" WORKER_JOIN_WAIT="${WORKER_JOIN_WAIT:-240}" ./portcullis worker join --runtime "$rt"
wexec "$name" ./portcullis worker status --json | jq -e '.agent.state == "ready"' >/dev/null \
  || { echo "FAIL: $name: $(wexec "$name" ./portcullis worker status --json)"; exit 1; }
echo "PASS: worker $name ($kind) joined and ready"
