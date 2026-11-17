#!/usr/bin/env bash
# runner-loop.sh <instance> — one ephemeral GitHub Actions runner job, run by
# pcci-runner@<instance>.service as user ghrunner (systemd restarts it after
# every job: a fresh registration and a fresh container each time).
#
# /etc/pcci-runner/<instance>.env: REPO (owner/name), WORKFLOW (the one
# workflow file it serves, e.g. .github/workflows/ci.yml), OWNER (the only
# actor admitted), NAME, SUBNET (its bridge network, 10.251.x.0/24), CPUS,
# MEMORY.
# The registration token (valid 1 h, one registration):
#   1. /etc/pcci-runner/gh-pat (0600 ghrunner): a fine-grained token limited
#      to the runner's repositories with "Administration: read and write"
#      → POST /repos/<REPO>/actions/runners/registration-token, or
#   2. /var/lib/pcci-runner/tokens/<instance>.json ({"token","expires_at"},
#      what `gh api -X POST …/registration-token` prints), dropped there by
#      an admin; used once and deleted.
#   Without either the loop waits (re-checks every minute).
# The job runs in container pcci-runner-<instance> (the run-job.sh job
# image, .github/ci/local/Dockerfile: privileged, systemd, its own dockerd)
# with the official actions/runner as user `runner`. job-started-hook.sh
# (ACTIONS_RUNNER_HOOK_JOB_STARTED) refuses every job that isn't a
# workflow_dispatch of WORKFLOW in REPO by OWNER, before any step runs: the
# privileged container and the shared caches are acceptable only under that
# rule. New for every job and removed with the container: the workspace,
# /srv, the image store (docker + containerd) and the tool cache. Kept per
# instance (owner-dispatched jobs only, see the hook): pip / Playwright /
# go-build (~/.cache) and the Go module cache (~/go; go.sum-verified,
# GOFLAGS=-mod=readonly).
set -euo pipefail
inst="${1:?instance}"
[[ "$inst" =~ ^[a-z0-9-]+$ ]] || { echo "bad instance $inst"; exit 2; }
# shellcheck disable=SC1090
. "/etc/pcci-runner/$inst.env"
: "${REPO:?}" "${WORKFLOW:?}" "${OWNER:?}" "${NAME:?}" "${SUBNET:?}" "${CPUS:=4}" "${MEMORY:=16g}"
img="${IMAGE:-pcci-job:runner}"
c="pcci-runner-$inst"
api="https://api.github.com/repos/$REPO/actions/runners"

clean() {
  docker rm -f "$c" >/dev/null 2>&1 || true
  for v in work srv docker containerd tools; do docker volume rm -f "$c-$v" >/dev/null 2>&1 || true; done
}
trap clean EXIT
clean

token=""
if [ -s /etc/pcci-runner/gh-pat ]; then
  token="$(curl -fsS -X POST -H @<(printf 'Authorization: Bearer %s\n' "$(cat /etc/pcci-runner/gh-pat)") \
    -H 'Accept: application/vnd.github+json' "$api/registration-token" | jq -r .token)" \
    || { echo "minting a registration token for $REPO failed"; sleep 60; exit 1; }
else
  f="/var/lib/pcci-runner/tokens/$inst.json"
  if [ -s "$f" ]; then
    exp="$(jq -r .expires_at "$f")"
    if [ "$(date -d "$exp" +%s 2>/dev/null || echo 0)" -gt "$(( $(date +%s) + 120 ))" ]; then
      token="$(jq -r .token "$f")"
    else
      echo "the dropped token for $inst expired ($exp)"
    fi
    rm -f "$f"
  fi
fi
if [ -z "$token" ] || [ "$token" = null ]; then
  echo "no registration token for $REPO (neither /etc/pcci-runner/gh-pat nor a dropped token): waiting"
  sleep 60
  exit 0
fi

docker network inspect "$c" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$c" >/dev/null
for v in home gopath work srv docker containerd tools; do docker volume create "$c-$v" >/dev/null; done
docker run -d --name "$c" --hostname "$c" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock \
  --network "$c" -e GOFLAGS=-mod=readonly --cpus "$CPUS" --memory "$MEMORY" --memory-swap "$MEMORY" \
  -v "$c-docker:/var/lib/docker" -v "$c-containerd:/var/lib/containerd" \
  -v "$c-work:/home/runner/work" -v "$c-srv:/srv" -v "$c-home:/home/runner/.cache" \
  -v "$c-gopath:/home/runner/go" -v "$c-tools:/opt/hostedtoolcache" "$img" >/dev/null
for i in $(seq 1 90); do
  docker exec "$c" docker info >/dev/null 2>&1 && break
  [ "$i" = 90 ] && { echo "the container's dockerd didn't start"; exit 1; }
  sleep 2
done
docker exec "$c" pcci-docker-sanitize
docker exec "$c" chown runner:runner /home/runner/work /home/runner/.cache /home/runner/go /opt/hostedtoolcache /srv
docker exec "$c" chmod 0755 /srv
docker cp "$(dirname "$0")/job-started-hook.sh" "$c:/usr/local/bin/pcci-job-started"
docker exec "$c" chmod 0755 /usr/local/bin/pcci-job-started

export ACTIONS_RUNNER_INPUT_TOKEN="$token"
docker exec -u runner -w /home/runner/actions-runner -e ACTIONS_RUNNER_INPUT_TOKEN "$c" ./config.sh --unattended \
  --ephemeral --disableupdate --replace --url "https://github.com/$REPO" --name "$NAME" --labels pc-builder \
  --work /home/runner/work
unset ACTIONS_RUNNER_INPUT_TOKEN token
echo "registered $NAME on $REPO (ephemeral): waiting for one job"
docker exec -u runner -w /home/runner/actions-runner -e HOME=/home/runner -e GOFLAGS=-mod=readonly \
  -e ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/bin/pcci-job-started \
  -e PCCI_ALLOWED_REPO="$REPO" -e PCCI_ALLOWED_WORKFLOW="$WORKFLOW" -e PCCI_ALLOWED_ACTOR="$OWNER" "$c" ./run.sh || true
echo "$NAME: job done; removing the container"
