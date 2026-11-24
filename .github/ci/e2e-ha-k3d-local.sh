#!/usr/bin/env bash
# e2e-ha-k3d-local.sh — run ci.yml's e2e-ha-k3d job locally, the same
# commands (e2e-k3s-local.sh with E2E_LOCAL_JOB=e2e-ha-k3d):
#
#   e2e-ha-k3d-local.sh steps [--from <n>] [--to <n>]
#       on a Linux host with Docker and sudo: every `run:` step of the job in
#       order (read from ci.yml), with the job's env, stopping at the first
#       failure. HUB_IMAGE / HUB_SRC (the Hub checkout the nodeagent image is
#       built from) come from the caller.
#
#   e2e-ha-k3d-local.sh container [--hub <hub checkout>] [--k3s-keep] [steps args]
#       anywhere with Docker: an Ubuntu 26.04 systemd container with its own
#       dockerd (k3d's node containers run inside it, never on this host's
#       engine), this checkout copied in, the Hub image and the nodeagent
#       image built from <hub checkout>'s HUB_REF (default HEAD); removed
#       afterwards (--k3s-keep keeps it: `docker exec -it pk-e2e-ha-k3d …`).
#       One cluster at a time. E2E_SCENARIOS names the scenarios
#       (tests/e2e/scenarios.py), as the workflow's input does.
#
# The runner container's size: E2E_K3S_RUNNER_ARGS (e.g. "--cpus 4
# --memory 16g", a GitHub runner's).
set -euo pipefail
E2E_LOCAL_JOB=e2e-ha-k3d exec bash "$(dirname "$0")/e2e-k3s-local.sh" "$@"
