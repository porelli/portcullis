#!/usr/bin/env bash
# install.sh — install (or update) the ephemeral self-hosted runners on this
# host, as root: `sudo .github/ci/local/runner/install.sh`.
#   user ghrunner (no password, no sudo; in the docker group — which is
#   root-equivalent on the host), /opt/pcci-runner, the job image
#   pcci-job:runner, /etc/pcci-runner/{portcullis,portcullis-hub}.env and
#   pcci-runner@{portcullis,portcullis-hub}.service (enabled, started).
# Registration tokens: see runner-loop.sh. Removal: uninstall.sh.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
here="$(cd "$(dirname "$0")" && pwd)"
local_dir="$(cd "$here/.." && pwd)"
repo_root="$(cd "$here/../../../.." && pwd)"
id ghrunner >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/pcci-runner --shell /usr/sbin/nologin \
  --comment "ephemeral GitHub Actions runners (pc-builder)" ghrunner
usermod -aG docker ghrunner
install -d -m 0755 /opt/pcci-runner /etc/pcci-runner
install -d -o ghrunner -g ghrunner -m 0700 /var/lib/pcci-runner /var/lib/pcci-runner/tokens
install -m 0755 "$here/runner-loop.sh" "$here/job-started-hook.sh" /opt/pcci-runner/
ctx="$(mktemp -d)"
cp "$local_dir/Dockerfile" "$local_dir/docker-sanitize.sh" "$ctx/"
cp "$repo_root/tests/e2e/requirements.txt" "$ctx/"
docker build -q -t pcci-job:runner "$ctx" >/dev/null
rm -rf "$ctx"
# instance repository workflow subnet
while read -r r wf net; do
  printf 'REPO=porelli/%s\nWORKFLOW=%s\nOWNER=porelli\nNAME=pc-builder-%s\nSUBNET=%s\nCPUS=4\nMEMORY=16g\n' \
    "$r" "$wf" "$r" "$net" > "/etc/pcci-runner/$r.env"
  chmod 0644 "/etc/pcci-runner/$r.env"
done <<'LIST'
portcullis .github/workflows/ci.yml 10.251.1.0/24
portcullis-hub .github/workflows/build.yml 10.251.2.0/24
LIST
[ ! -f /etc/pcci-runner/gh-pat ] || { chown ghrunner:ghrunner /etc/pcci-runner/gh-pat; chmod 0600 /etc/pcci-runner/gh-pat; }
install -m 0644 "$here/pcci-runner@.service" /etc/systemd/system/pcci-runner@.service
systemctl daemon-reload
for r in portcullis portcullis-hub; do systemctl enable --now "pcci-runner@$r.service"; done
systemctl --no-pager --lines=0 status 'pcci-runner@*' || true
