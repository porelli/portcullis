#!/usr/bin/env bash
# e2e-k3s-local.sh — run ci.yml's e2e-k3s job locally, the same commands:
#
#   e2e-k3s-local.sh steps [--from <n>] [--to <n>]
#       on a Linux host (Ubuntu, systemd, docker, sudo): every `run:` step of
#       the job in order (read from ci.yml, so it can't drift), with the job's
#       env, RUNNER_TEMP / GITHUB_ENV / GITHUB_STEP_SUMMARY like Actions
#       (GITHUB_ENV lines are applied before the next step), stopping at the
#       first failure. The `uses:` steps are local: HUB_IMAGE / KEYCLOAK_IMAGE
#       come from the caller (unset = the published ones); failure() steps
#       are skipped. E2E_K3S_SKIP_DOCKER=1 skips the Docker phase and the
#       Docker → Kubernetes restore.
#
#   e2e-k3s-local.sh container [--hub <hub checkout>] [--k3s-keep] [steps args]
#       anywhere with Docker (macOS too): an Ubuntu 26.04 systemd container
#       (privileged; docker and k3s inside, their state on throwaway
#       volumes) as the runner, this checkout copied in, the Hub image built
#       from <hub checkout>'s HUB_REF (default HEAD) when given (HUB_IMAGE=portcullis-hub:ci),
#       then `steps`; removed with its volumes afterwards (--k3s-keep keeps
#       it for a rerun with `docker exec -it pk-e2e-k3s …`). One cluster at a
#       time: refuses when the container already exists.
set -euo pipefail
here="$(cd "$(dirname "$0")/../.." && pwd)"

steps() {
  local from=1 to=999
  while [ $# -gt 0 ]; do
    case "$1" in --from) from="$2"; shift 2 ;; --to) to="$2"; shift 2 ;; *) echo "usage: $0 steps [--from n] [--to n]" >&2; exit 2 ;; esac
  done
  cd "$here"
  export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
  export GITHUB_ENV="${GITHUB_ENV:-$RUNNER_TEMP/github-env}" \
    GITHUB_STEP_SUMMARY="${GITHUB_STEP_SUMMARY:-$RUNNER_TEMP/step-summary}" GITHUB_HEAD_REF="${GITHUB_HEAD_REF:-}" \
    GITHUB_REF_NAME="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo kube1)}"
  touch "$GITHUB_ENV" "$GITHUB_STEP_SUMMARY"
  python3 - "$here/.github/workflows/ci.yml" "$RUNNER_TEMP/steps" <<'PY'
import json, sys, yaml, pathlib
job = yaml.safe_load(open(sys.argv[1]))["jobs"]["e2e-k3s"]
out = pathlib.Path(sys.argv[2]); out.mkdir(exist_ok=True)
(out / "env.json").write_text(json.dumps(job.get("env") or {}))
n = 0
for s in job["steps"]:
    if "run" not in s or str(s.get("if", "")).startswith("failure()"):
        continue
    n += 1
    env = {k: v for k, v in (s.get("env") or {}).items() if "${{" not in str(v)}
    (out / f"{n:02d}.json").write_text(json.dumps({"name": s.get("name", s["run"][:40]), "run": s["run"], "env": env}))
PY
  local f n name
  for f in "$RUNNER_TEMP"/steps/[0-9][0-9].json; do
    n="$((10#$(basename "$f" .json)))"
    [ "$n" -ge "$from" ] && [ "$n" -le "$to" ] || continue
    name="$(jq -r .name "$f")"
    echo "::group::[$n] $name"
    # The job env, then this step's env, then GITHUB_ENV (as Actions does).
    if ! ( set -a
           eval "$(jq -r 'to_entries[] | "export \(.key)=\(.value | tostring | @sh)"' "$RUNNER_TEMP/steps/env.json")"
           eval "$(jq -r '.env | to_entries[] | "export \(.key)=\(.value | tostring | @sh)"' "$f")"
           # GITHUB_ENV: KEY=VALUE lines (what these scripts write).
           # shellcheck disable=SC2163
           while IFS= read -r line; do [ -n "$line" ] && export "$line"; done < "$GITHUB_ENV"
           set +a
           bash -e -o pipefail -c "$(jq -r .run "$f")" ); then
      echo "::endgroup::"; echo "LOCAL e2e-k3s: FAILED at step [$n] $name"; exit 1
    fi
    echo "::endgroup::"; echo "LOCAL e2e-k3s: step [$n] $name OK"
  done
  echo "LOCAL e2e-k3s: every step passed"
}

container() {
  local hub="" keep=false name=pk-e2e-k3s img=pk-e2e-k3s-runner:26.04
  while [ $# -gt 0 ]; do
    case "$1" in --hub) hub="$2"; shift 2 ;; --k3s-keep) keep=true; shift ;; *) break ;; esac
  done
  docker info >/dev/null 2>&1 || { echo "FAIL: docker isn't answering"; exit 1; }
  ! docker inspect "$name" >/dev/null 2>&1 || { echo "FAIL: $name exists (one cluster at a time): docker rm -f $name; docker volume rm $name-docker $name-containerd $name-rancher"; exit 1; }
  docker build -q -t "$img" - >/dev/null <<'DOCKERFILE'
FROM docker.io/library/ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus sudo docker.io docker-buildx docker-compose-v2 \
      jq curl git iproute2 iptables python3 python3-yaml python3-venv openssl rsync ca-certificates kmod procps acl file \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash runner && usermod -aG docker runner \
    && echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner && systemctl enable docker
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE
  # The inner dockerd's image store (containerd snapshots) needs a real
  # filesystem too: overlay on the container's overlay root fails.
  docker volume create "$name-docker" >/dev/null; docker volume create "$name-containerd" >/dev/null; docker volume create "$name-rancher" >/dev/null
  # The trap runs after container() returns: its locals are gone, so the
  # values are bound now.
  # shellcheck disable=SC2064
  [ "$keep" = true ] || trap "docker rm -f '$name' >/dev/null 2>&1 || true; docker volume rm '$name-docker' '$name-containerd' '$name-rancher' >/dev/null 2>&1 || true" EXIT
  docker run -d --name "$name" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$name-docker:/var/lib/docker" -v "$name-containerd:/var/lib/containerd" -v "$name-rancher:/var/lib/rancher" --tmpfs /run --tmpfs /run/lock "$img" >/dev/null
  for i in $(seq 1 60); do docker exec "$name" docker info >/dev/null 2>&1 && break; [ "$i" = 60 ] && { echo "FAIL: docker in the runner didn't start"; exit 1; }; sleep 2; done
  local w=/home/runner/work/portcullis/portcullis
  docker exec "$name" sudo -u runner mkdir -p "$w"
  (cd "$here" && git ls-files -co --exclude-standard | tar -cf - -T -) | docker exec -i "$name" sudo -u runner tar -C "$w" -xf -
  docker exec "$name" sudo -u runner bash -c "cd $w && git init -q && git add -A && git -c user.email=l@l -c user.name=local commit -qm local && git branch -m kube1"
  local envs=(-e E2E_K3S_SKIP_DOCKER="${E2E_K3S_SKIP_DOCKER:-}" -e K3S_LINE="${K3S_LINE:-}" -e GITHUB_REF_NAME=kube1)
  if [ -n "$hub" ]; then
    git -C "$hub" archive "${HUB_REF:-HEAD}" | docker exec -i "$name" sudo -u runner bash -c 'mkdir -p ~/hub && tar -C ~/hub -xf -'
    docker exec "$name" sudo -u runner bash -c 'cd ~/hub && docker build -q -t portcullis-hub:ci . >/tmp/hub-build.log 2>&1' \
      || { docker exec "$name" tail -n 30 /tmp/hub-build.log; echo "FAIL: the Hub image didn't build"; exit 1; }
    envs+=(-e HUB_IMAGE=portcullis-hub:ci -e HUB_LOCAL=1)
  fi
  [ -z "${KEYCLOAK_IMAGE:-}" ] || envs+=(-e KEYCLOAK_IMAGE="$KEYCLOAK_IMAGE")
  # docker exec -u, never sudo -E: Ubuntu 26.04's sudo ignores -E, and the
  # steps then ran without HUB_IMAGE (the published edge Hub was deployed).
  docker exec "${envs[@]}" -e HOME=/home/runner -e USER=runner -u runner -w "$w" "$name" bash -c "bash .github/ci/e2e-k3s-local.sh steps $*"
}

case "${1:-}" in
  steps) shift; steps "$@" ;;
  container) shift; container "$@" ;;
  *) echo "usage: $0 steps [--from n] [--to n] | container [--hub <dir>] [--k3s-keep] [steps args]" >&2; exit 2 ;;
esac
