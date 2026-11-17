#!/usr/bin/env bash
# run-job.sh — run one ci.yml job on a Linux Docker host (the dev builder),
# the way GitHub's runner does, in its own isolated job container.
#
#   .github/ci/local/run-job.sh <job> [--scenario <name>]… [--ref <branch|sha>] [--local <dir>]
#                               [--keep] [--no-cache] [--cpus N] [--memory SIZE] [--shell]
#
#   <job>         a ci.yml job: build-and-test, e2e, e2e-instances, e2e-signin,
#                 e2e-settings, e2e-folders, e2e-filesharing, e2e-mail, e2e-ai,
#                 e2e-vpn (unit-tests works too). Not e2e-podman / e2e-k3s
#                 (they stop Docker / install k3s on the runner: use GitHub,
#                 or .github/ci/e2e-k3s-local.sh for k3s).
#   --scenario    only this e2e scenario (repeatable; E2E_SCENARIOS, see
#                 tests/e2e/scenarios.py) plus its setup; needs a ref that has it
#   --ref         the branch / tag / sha of porelli/portcullis to test (default
#                 main), cloned fresh from GitHub
#   --local       test this working tree instead (uncommitted changes included;
#                 GITHUB_REF_NAME = its branch, so same-named Hub / Keycloak /
#                 templates branches are used as in CI)
#   --keep        keep the container (and its volumes) afterwards for
#                 `docker exec -it <name> bash`; remove with --cleanup <name>
#   --no-cache    fresh image store / caches (default: this job's image store
#                 and the shared pip / Playwright / Go caches are reused,
#                 one run of a job at a time; a second concurrent run of the
#                 same job gets a throwaway store)
#   --cpus/--memory  the container's limits (default 4 / 16g: a GitHub runner)
#   --shell       open a shell in the prepared container instead of the steps
#
# How (the same model as e2e-k3s-local.sh's container mode): every run is a
# privileged Ubuntu 24.04 system container (.github/ci/local/Dockerfile:
# systemd, its own dockerd, user `runner` with sudo, like GitHub's image) on
# its own bridge network, named pcci-<job>-<id>; inside it the job's compose
# project, networks (the fixed 172.30/172.31 subnets), published ports,
# /etc/hosts edits and /tmp files are its own, so runs never collide with
# each other or with the host's Docker. The checkout is a fresh clone in
# ~/w/ci-local/<id>/ (host), copied into the container's workspace volume
# (/home/runner/work/portcullis/portcullis, as on GitHub). steps.py runs the
# job's steps from ci.yml (see its header for the emulated `uses:`).
# Afterwards the container, its network and its volumes are removed and the
# checkout deleted; the log and any uploaded artifacts stay in
# ~/w/ci-local/<id>/ (removed after 7 days by the next run).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
base="${PCCI_HOME:-$HOME/w/ci-local}"
img_base=pcci-job

die() { echo "run-job: $*" >&2; exit 2; }

cleanup_named() { # cleanup_named <container name>: the container, its run volumes and network
  local n="$1"
  docker rm -f "$n" >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=pcci.run=$n" | xargs -r docker volume rm -f >/dev/null 2>&1 || true
  docker network rm "$n" >/dev/null 2>&1 || true
}

job="" ref=main local_dir="" keep=false cache=true cpus=4 memory=16g shell=false scen=()
while [ $# -gt 0 ]; do
  case "$1" in
    --scenario) scen+=("${2:?--scenario needs a name}"); shift 2 ;;
    --ref) ref="${2:?}"; shift 2 ;;
    --local) local_dir="$(cd "${2:?}" && pwd)"; shift 2 ;;
    --keep) keep=true; shift ;;
    --no-cache) cache=false; shift ;;
    --cpus) cpus="${2:?}"; shift 2 ;;
    --memory) memory="${2:?}"; shift 2 ;;
    --shell) shell=true; keep=true; shift ;;
    --cleanup) cleanup_named "${2:?}"; echo "removed $2"; exit 0 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$job" ] || die "one job at a time"; job="$1"; shift ;;
  esac
done
[ -n "$job" ] || die "usage: $0 <job> [--scenario <name>]… [--ref <ref>|--local <dir>] [--keep] [--no-cache]"
case "$job" in
  e2e-podman|e2e-k3s) die "$job can't run here: it stops the runner's Docker / installs k3s (GitHub only; k3s: .github/ci/e2e-k3s-local.sh container)" ;;
esac
[[ "$job" =~ ^[a-z0-9-]+$ ]] || die "bad job name"
for s in "${scen[@]}"; do [[ "$s" =~ ^[A-Za-z0-9_]+$ ]] || die "bad scenario name $s"; done
docker info >/dev/null 2>&1 || die "docker isn't answering"
command -v git >/dev/null || die "git missing"

id="$(date +%Y%m%d-%H%M%S)-$$"
name="pcci-$job-$id"
run="$base/$id"
mkdir -p "$run/artifacts" "$base/locks"
chmod 0777 "$run/artifacts"   # written by the container's runner (uid 1001)
find "$base" -mindepth 1 -maxdepth 1 -type d -name '2*' -mtime +7 -exec rm -rf {} + 2>/dev/null || true
log="$run/run.log"
exec > >(tee -a "$log") 2>&1
echo "run-job: $job → $name (log $log)"

on_exit() {
  [ "$keep" = true ] && return
  echo "run-job: cleaning up $name"
  cleanup_named "$name"
  rm -rf "$run/src"
}
trap on_exit EXIT

# ── the checkout ──
if [ -n "$local_dir" ]; then
  git clone --quiet --no-local "$local_dir" "$run/src"
  (cd "$local_dir" && git ls-files -z -mo --exclude-standard | tar --null -T - -cf -) | tar -C "$run/src" -xf -
  (cd "$local_dir" && git ls-files -z -d) | (cd "$run/src" && xargs -0 -r rm -f)
  ref_name="$(git -C "$local_dir" rev-parse --abbrev-ref HEAD)"
  git -C "$run/src" remote set-url origin https://github.com/porelli/portcullis.git
else
  git init -q "$run/src"
  git -C "$run/src" remote add origin https://github.com/porelli/portcullis.git
  git -C "$run/src" fetch -q --depth=1 origin "$ref"
  git -C "$run/src" checkout -q FETCH_HEAD
  ref_name="$ref"
  [[ "$ref" =~ ^[0-9a-f]{7,40}$ ]] && ref_name=main
fi
sha="$(git -C "$run/src" rev-parse HEAD)"
git -C "$run/src" -c advice.detachedHead=false checkout -q -B "$ref_name" 2>/dev/null || true
echo "run-job: $ref_name @ $sha"
[ -f "$run/src/.github/workflows/ci.yml" ] || die "no .github/workflows/ci.yml at that ref"

# ── the job image (rebuilt when its Dockerfile, sanitizer or the pinned Playwright change) ──
ctx="$(mktemp -d)"
cp "$here/Dockerfile" "$here/docker-sanitize.sh" "$ctx/"
cp "$run/src/tests/e2e/requirements.txt" "$ctx/requirements.txt"
tag="$img_base:$(cat "$ctx"/* | sha256sum | cut -c1-12)"
if ! docker image inspect "$tag" >/dev/null 2>&1; then
  echo "run-job: building $tag"
  docker build -q -t "$tag" "$ctx" >/dev/null
fi
rm -rf "$ctx"

# ── volumes: the run's own, and the reused caches ──
vol() { docker volume create --label "pcci.run=$name" "$name-$1" >/dev/null; echo "$name-$1"; }
work="$(vol work)" srv="$(vol srv)"
if [ "$cache" = true ] && exec 9>"$base/locks/$job.lock" && flock -n 9; then
  dk="pcci-cache-$job-docker" ct="pcci-cache-$job-containerd"
  docker volume create "$dk" >/dev/null; docker volume create "$ct" >/dev/null
  home_cache=(-v pcci-cache-home:/home/runner/.cache -v pcci-cache-gopath:/home/runner/go -v pcci-cache-tools:/opt/hostedtoolcache)
  echo "run-job: reusing the image store of $job (pcci-cache-$job-*) and the shared caches"
else
  dk="$(vol docker)" ct="$(vol containerd)"
  home_cache=()
  echo "run-job: throwaway image store and caches"
fi

# ── its own bridge network (10.250.<n>.0/24: never the fixed 172.30/172.31 ranges the jobs use) ──
for _ in $(seq 1 50); do
  n=$((RANDOM % 250 + 1))
  docker network create --label "pcci.run=$name" --subnet "10.250.$n.0/24" "$name" >/dev/null 2>&1 && break
done
docker network inspect "$name" >/dev/null 2>&1 || die "no free 10.250.x.0/24 network"

docker run -d --name "$name" --hostname "pcci-$job" --label "pcci.run=$name" \
  --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock --network "$name" \
  --cpus "$cpus" --memory "$memory" --memory-swap "$memory" \
  -v "$dk:/var/lib/docker" -v "$ct:/var/lib/containerd" -v "$work:/home/runner/work" -v "$srv:/srv" \
  "${home_cache[@]}" -v "$run/artifacts:/pcci/artifacts" "$tag" >/dev/null
for i in $(seq 1 90); do
  docker exec "$name" docker info >/dev/null 2>&1 && break
  [ "$i" = 90 ] && { docker exec "$name" systemctl status docker --no-pager || true; die "the container's dockerd didn't start"; }
  sleep 2
done
docker exec "$name" pcci-docker-sanitize
docker exec "$name" chown runner:runner /home/runner/work /home/runner/.cache /home/runner/go /opt/hostedtoolcache /srv 2>/dev/null || true
docker exec "$name" chmod 0755 /srv

w=/home/runner/work/portcullis/portcullis
docker exec -u runner "$name" mkdir -p "$w" /home/runner/work/_temp
tar -C "$run/src" -cf - . | docker exec -i -u runner "$name" tar -C "$w" -xf -
docker cp "$here/steps.py" "$name:/pcci/steps.py" >/dev/null

scenarios="${scen[*]:-}"
envs=(-e HOME=/home/runner -e USER=runner -e RUNNER_TEMP=/home/runner/work/_temp -e PCCI_ARTIFACTS=/pcci/artifacts
      -e "PCCI_EXTRA_ENV=${scenarios:+E2E_SCENARIOS=$scenarios}")
if [ "$shell" = true ]; then
  echo "run-job: prepared. Steps: docker exec -it -u runner -w $w ${envs[*]} $name python3 /pcci/steps.py --job $job --ref-name $ref_name"
  echo "run-job: shell (exit to leave; the container stays: $0 --cleanup $name)"
  exec docker exec -it -u runner -w "$w" "${envs[@]}" "$name" bash
fi
rc=0
docker exec -u runner -w "$w" "${envs[@]}" "$name" python3 /pcci/steps.py --job "$job" --ref-name "$ref_name" --sha "$sha" \
  --input "jobs=$job" --input "scenarios=$scenarios" --input runner=github || rc=$?
docker exec "$name" pcci-docker-sanitize || true
if [ "$keep" = true ]; then echo "run-job: kept $name ($0 --cleanup $name)"; fi
[ -z "$(ls -A "$run/artifacts")" ] || echo "run-job: artifacts in $run/artifacts"
echo "run-job: $job $([ "$rc" = 0 ] && echo PASSED || echo "FAILED ($rc)") — log $log"
exit "$rc"
