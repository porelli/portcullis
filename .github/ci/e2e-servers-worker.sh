#!/usr/bin/env bash
# ci.yml jobs e2e-servers / e2e-servers-podman: start one worker server and
# join it to the primary (contract §17.7), the join code on STDIN (never an
# argument; e2e_servers.py pipes it from its 0700 temp dir).
#
#   e2e-servers-worker.sh dind <name>     a docker:dind container with its own
#                                         daemon and a copy of this checkout
#   e2e-servers-worker.sh podman <name>   rootless Podman as the runner user pcci-worker
#                                         `worker` (its own user socket)
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
# Its own user (the runner image may already have a `worker`): set up once,
# marked by a stamp file, not by the user existing.
WUSER=pcci-worker
WSTAMP=/var/tmp/pcci-worker.setup

# asworker <cmd…> — as the Podman worker's operator, with a clean
# environment (the runner's XDG_* / DOCKER_* must never leak in).
asworker() (
  local uid; uid="$(id -u "$WUSER")"
  # From / : the runner's workspace isn't the worker's to enter.
  cd / && sudo -u "$WUSER" env -i HOME="/home/$WUSER" USER="$WUSER" LOGNAME="$WUSER" PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 \
    XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    DOCKER_HOST="unix:///run/user/$uid/podman/podman.sock" "$@"
)

# wexec <name> <cmd…> — a command in the worker's checkout.
wexec() {
  local n="$1"; shift
  if docker inspect "e2e-$n" >/dev/null 2>&1; then
    docker exec -i -w /opt/portcullis "e2e-$n" "$@"
  else
    asworker bash -c 'cd "$HOME/portcullis" && exec "$@"' bash "$@"
  fi
}

override() {  # <extra_hosts value>
  printf 'services:\n  agent:\n    extra_hosts:\n      - "%s:%s"\n' "$E2E_DOMAIN" "$1"
}

case "$kind" in
  exec) shift 2; wexec "$name" "$@"; exit ;;
  compose)
    shift 2
    # shellcheck disable=SC2016  # expanded by the worker's bash
    wexec "$name" bash -c 'export PORTCULLIS_HOME="$PWD" PORTCULLIS_ROOT="$PWD" PORTCULLIS_LIB="$PWD/scripts/lib"
      source scripts/lib/common.sh; source scripts/lib/worker.sh; env_load; runtime_export
      exec docker compose --project-directory "$PWD" "$@"' bash "$@"
    exit ;;
  dind)
    # reviewed exception: the CI worker is a privileged docker:dind (its own
    # daemon needs it); never in a compose file or the product (the lint in
    # tests/test_cli.sh allows a privileged run here only).
    priv=(--privileged) # reviewed exception
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
    if [ ! -e "$WSTAMP" ]; then
      echo "== podman worker: packages, the user, linger"
      ! id "$WUSER" >/dev/null 2>&1 || { echo "FAIL: the user $WUSER already exists on this runner"; exit 1; }
      sudo apt-get update -qq && sudo apt-get install -y -qq podman passt uidmap >/dev/null
      sudo useradd -m -s /bin/bash "$WUSER"
      grep -q "^$WUSER:" /etc/subuid || sudo usermod --add-subuids 200000-265535 "$WUSER"
      grep -q "^$WUSER:" /etc/subgid || sudo usermod --add-subgids 200000-265535 "$WUSER"
      sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80 >/dev/null
      if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ] && [ -f /etc/apparmor.d/usr.bin.pasta ] \
         && ! grep -q 'peer=podman' /etc/apparmor.d/usr.bin.pasta /etc/apparmor.d/local/usr.bin.pasta 2>/dev/null; then
        if grep -q 'local/usr.bin.pasta' /etc/apparmor.d/usr.bin.pasta; then
          echo 'signal (receive) set=(term) peer=podman,' | sudo tee -a /etc/apparmor.d/local/usr.bin.pasta >/dev/null
        else
          sudo sed -i 's/^}$/  signal (receive) set=(term) peer=podman,\n}/' /etc/apparmor.d/usr.bin.pasta
        fi
        sudo apparmor_parser -r /etc/apparmor.d/usr.bin.pasta
      fi
      sudo loginctl enable-linger "$WUSER"
      uid="$(id -u "$WUSER")"
      # Linger starts the user manager; start it explicitly too (a new user).
      # /run/user/<uid> is the worker's (0700): test its bus as root.
      sudo systemctl start "user@$uid.service" || true
      for i in $(seq 1 60); do sudo test -S "/run/user/$uid/bus" && break; [ "$i" -eq 60 ] && { echo "FAIL: no user manager for $WUSER"; systemctl status "user@$uid.service" --no-pager | tail -20; exit 1; }; sleep 1; done
      # The runner's image hands its own environment to every user manager
      # (pam_env's /etc/environment and more: XDG_RUNTIME_DIR=/run/user/<the
      # runner>, XDG_CONFIG_HOME=/home/runner/.config, ...): podman.service
      # then fails ("faccessat /home/runner/.config/containers/storage.conf:
      # permission denied"). The worker's manager keeps an allowlist only,
      # gets its own runtime dir, and the socket starts afresh.
      # shellcheck disable=SC2016
      asworker sh -c '
        keep="^(PATH|HOME|USER|LOGNAME|SHELL|LANG|LANGUAGE|LC_[A-Z_]+|TERM|XDG_RUNTIME_DIR|DBUS_SESSION_BUS_ADDRESS|MANAGERPID|INVOCATION_ID|SYSTEMD_EXEC_PID|JOURNAL_STREAM|MEMORY_PRESSURE_WATCH|MEMORY_PRESSURE_WRITE|NOTIFY_SOCKET)="
        drop="$(systemctl --user show-environment | grep -Ev "$keep" | cut -d= -f1 | tr "\n" " ")"
        [ -z "$drop" ] || systemctl --user unset-environment $drop
        systemctl --user set-environment XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" HOME="$HOME"
        systemctl --user reset-failed podman.socket podman.service 2>/dev/null || true
        systemctl --user enable podman.socket podman-restart.service && systemctl --user restart podman.socket'
      echo "== podman worker: the user manager's environment: $(asworker systemctl --user show-environment 2>&1 | cut -d= -f1 | tr '\n' ' ')"
      sudo touch "$WSTAMP"
    fi
    echo "== podman worker: the user's socket"
    for i in $(seq 1 30); do
      asworker docker version --format '{{json .Server.Components}}' >/dev/null 2>&1 && break
      if [ "$i" -eq 10 ]; then
        # Diagnostics, then the socket's service by hand (the unit stays
        # enabled, which is what the host checks read).
        echo "::warning::$WUSER's podman.socket doesn't answer after 20 s: $(asworker systemctl --user is-active podman.socket 2>&1 | head -1)"
        sudo ls -la "/run/user/$(id -u "$WUSER")" "/run/user/$(id -u "$WUSER")/podman" 2>&1 | tail -8
        asworker systemctl --user status podman.socket --no-pager 2>&1 | tail -8 || true
        sudo journalctl "_UID=$(id -u "$WUSER")" --no-pager -n 40 2>&1 | grep -iv 'gpg-agent\|ssh-agent\|dirmngr\|keyboxd' | tail -30 || true
        asworker sh -c 'mkdir -p "$XDG_RUNTIME_DIR/podman" && setsid nohup podman system service --time=0 "unix://$XDG_RUNTIME_DIR/podman/podman.sock" >"$HOME/podman-service.log" 2>&1 < /dev/null &'
      fi
      if [ "$i" -eq 30 ]; then
        echo "FAIL: $WUSER's Podman socket doesn't answer"
        asworker docker version 2>&1 | tail -3
        sudo tail -20 "/home/$WUSER/podman-service.log" 2>/dev/null || true
        exit 1
      fi
      sleep 2
    done
    echo "== podman worker: the checkout, the agent image"
    sudo rm -rf "/home/$WUSER/portcullis"
    sudo cp -a "$PWD" "/home/$WUSER/portcullis"
    sudo rm -rf "/home/$WUSER/portcullis/.env" "/home/$WUSER/portcullis/secrets/"* "/home/$WUSER/portcullis/certs/"* "/home/$WUSER/portcullis/docker-compose.ci.yml"
    sudo chown -R "$WUSER:$WUSER" "/home/$WUSER/portcullis"
    docker save "$AGENT_IMAGE" | asworker podman load -q
    override host-gateway | sudo -u "$WUSER" tee "/home/$WUSER/portcullis/docker-compose.worker.override.yml" >/dev/null
    rt=podman ;;
  *) echo "usage: $0 dind|podman|exec <name>"; exit 2 ;;
esac

# The code: this script's stdin, straight into worker join's stdin.
echo "== $kind worker $name: worker join"
wexec "$name" env AGENT_IMAGE="$AGENT_IMAGE" WORKER_JOIN_WAIT="${WORKER_JOIN_WAIT:-240}" ./portcullis worker join --runtime "$rt"
wexec "$name" ./portcullis worker status --json | jq -e '.agent.state == "ready"' >/dev/null \
  || { echo "FAIL: $name: $(wexec "$name" ./portcullis worker status --json)"; exit 1; }
echo "PASS: worker $name ($kind) joined and ready"
