#!/usr/bin/env bash
# uninstall.sh — remove the self-hosted runners from this host, as root.
# Remove their GitHub registrations too (repo owner):
#   gh api repos/porelli/<repo>/actions/runners --jq '.runners[] | select(.name|startswith("pc-builder-")) | .id' \
#     | xargs -I{} gh api -X DELETE repos/porelli/<repo>/actions/runners/{}
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
for r in portcullis portcullis-hub; do
  systemctl disable --now "pcci-runner@$r.service" 2>/dev/null || true
  c="pcci-runner-$r"
  docker rm -f "$c" >/dev/null 2>&1 || true
  for v in work srv tmp docker containerd home gopath tools; do docker volume rm -f "$c-$v" >/dev/null 2>&1 || true; done
  docker network rm "$c" >/dev/null 2>&1 || true
done
rm -f /etc/systemd/system/pcci-runner@.service
systemctl daemon-reload
docker image rm pcci-job:runner >/dev/null 2>&1 || true
rm -rf /opt/pcci-runner /etc/pcci-runner
userdel -r ghrunner 2>/dev/null || true
echo "removed (GitHub registrations: see the comment at the top)"
