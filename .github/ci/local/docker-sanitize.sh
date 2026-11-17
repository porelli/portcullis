#!/usr/bin/env bash
# pcci-docker-sanitize — run as root inside a job container before a job:
# the image store may be reused from an earlier job (a cache volume), so
# everything but images and build cache goes (containers, volumes,
# networks), and so does every image name that isn't backed by a registry
# pull of that repository (a locally built or re-tagged `ghcr.io/…:edge`
# from an earlier job must never stand in for the published one).
set -uo pipefail
docker ps -aq | xargs -r docker rm -f >/dev/null 2>&1
docker volume ls -q | xargs -r docker volume rm -f >/dev/null 2>&1
docker network prune -f >/dev/null 2>&1
docker images --format '{{.Repository}}:{{.Tag}}' | grep -v '<none>' | while read -r ref; do
  repo="${ref%:*}"
  if ! docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$ref" 2>/dev/null | grep -q "^${repo}@sha256:"; then
    docker image rm "$ref" >/dev/null 2>&1 || true
  fi
done
docker image prune -f >/dev/null 2>&1
exit 0
