#!/usr/bin/env bash
# job-started-hook.sh — the runner's ACTIONS_RUNNER_HOOK_JOB_STARTED (runs
# before any step of the job; a non-zero exit fails the job before it runs
# anything). The builder's runner is privileged (nested Docker) and shares
# caches between jobs: that is acceptable ONLY because this hook admits
# nothing but jobs the repository owner dispatched by hand from the one
# workflow the runner exists for. PCCI_ALLOWED_* come from runner-loop.sh
# (the runner process's environment, set before registration; a job's
# steps can't change it before this hook runs).
set -u
deny() { echo "::error::pc-builder runner refuses this job: $*"; exit 1; }
owner="${PCCI_ALLOWED_ACTOR:?}"
[ "${GITHUB_EVENT_NAME:-}" = workflow_dispatch ] || deny "event ${GITHUB_EVENT_NAME:-?} (only workflow_dispatch)"
[ "${GITHUB_ACTOR:-}" = "$owner" ] || deny "actor ${GITHUB_ACTOR:-?} (only $owner)"
[ "${GITHUB_TRIGGERING_ACTOR:-}" = "$owner" ] || deny "triggering actor ${GITHUB_TRIGGERING_ACTOR:-?} (only $owner)"
[ "${GITHUB_REPOSITORY:-}" = "${PCCI_ALLOWED_REPO:?}" ] || deny "repository ${GITHUB_REPOSITORY:-?} (only $PCCI_ALLOWED_REPO)"
case "${GITHUB_WORKFLOW_REF:-}" in
  "$PCCI_ALLOWED_REPO/${PCCI_ALLOWED_WORKFLOW:?}@refs/heads/"*) ;;
  *) deny "workflow ${GITHUB_WORKFLOW_REF:-?} (only $PCCI_ALLOWED_REPO/$PCCI_ALLOWED_WORKFLOW on a branch)" ;;
esac
echo "pc-builder: admitted $GITHUB_WORKFLOW_REF, dispatched by $GITHUB_TRIGGERING_ACTOR"
