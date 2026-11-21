#!/usr/bin/env bash
# ci.yml (build-and-test, e2e-mail, e2e-podman): the mail provider
# template for core CI (mail provider plan Task 25, P2).
#   mail-templates-checkout.sh <dest> <fake dns ip>
#
# 1. portcullis-templates at the same-named branch (else main) into
#    <dest>, as e2e-settings' "Templates" step; the step fails without
#    stalwart/manifest.yaml's mail: block.
# 2. P2: the stalwart template's adapter image lines (exactly
#    ghcr.io/porelli/portcullis-mailctl:<tag>@sha256:<64 hex>, four of
#    them) become the locally built portcullis-mailctl:ci: core CI never
#    pulls the published adapter, it tests the checkout's mailctl/.
# 3. Nothing leaves the runner (P40): the template's resolver forwards
#    every name to the domains service's fake DNS at <fake dns ip>:8053
#    (tests/e2e/mail/unbound-ci.conf, no DNSSEC: the fake zone is unsigned)
#    and its health check asks a name that zone answers (MAIL_CI_DNS_PROBE).
#
# The copy is CI's own: the Hub hashes the template as it finds it there.
# Runs from the workspace root with GitHub's default shell behaviour (bash -e).
set -euo pipefail
dest="${1:?usage: mail-templates-checkout.sh <dest> <fake dns ip>}"
fakedns="${2:?usage: mail-templates-checkout.sh <dest> <fake dns ip>}"
probe="${MAIL_CI_DNS_PROBE:-portcullis.local}"
REF="${REF:-${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-main}}}"
[[ "$fakedns" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "::error::fake DNS address $fakedns isn't an IPv4 address"; exit 1; }
[[ "$probe" =~ ^[a-z0-9.-]+$ ]] || { echo "::error::MAIL_CI_DNS_PROBE $probe isn't a DNS name"; exit 1; }

if [ ! -d "$dest/.git" ]; then
  url=https://github.com/porelli/portcullis-templates
  ref=main
  # The heads, listed once: a failed listing fails the step instead of
  # quietly testing main. Exactly refs/heads/<REF>; release tags are vX.Y.Z.
  heads=$(git ls-remote --heads "$url") || { echo "::error::git ls-remote $url failed"; exit 1; }
  if [[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] && [ "$REF" != main ] && ! [[ "$REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
      && awk -v r="refs/heads/$REF" '$2 == r { f = 1 } END { exit !f }' <<<"$heads"; then
    ref="$REF"
  fi
  git clone --quiet --depth=1 --branch "$ref" "$url" "$dest"
  echo "Templates: portcullis-templates@$ref ($(git -C "$dest" rev-parse --short HEAD))" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
fi

T="$dest/stalwart"
grep -q '^mail:' "$T/manifest.yaml" 2>/dev/null || { echo "::error::$T/manifest.yaml has no mail: block"; exit 1; }

# P2: exactly four adapter image lines (adapter-bin, key-init, adapter, admin-view) of the pinned shape, nothing else
# naming the published adapter.
re='^    image: ghcr\.io/porelli/portcullis-mailctl:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$'
n="$(grep -cE "$re" "$T/compose.yml" || true)"
[ "$n" = 4 ] || { echo "::error::$T/compose.yml: $n adapter image lines of the shape ghcr.io/porelli/portcullis-mailctl:<tag>@sha256:<digest> (want 4)"; exit 1; }
[ "$(grep -c 'portcullis-mailctl' "$T/compose.yml")" = 4 ] || { echo "::error::$T/compose.yml names portcullis-mailctl outside its four image lines"; exit 1; }
sed -i -E "s#$re#    image: portcullis-mailctl:ci#" "$T/compose.yml"
docker image inspect portcullis-mailctl:ci >/dev/null 2>&1 || { echo "::error::portcullis-mailctl:ci isn't built"; exit 1; }

# P40: the resolver forwards everything to the fake DNS.
sed "s/__FAKEDNS__/$fakedns/" tests/e2e/mail/unbound-ci.conf > "$T/unbound/unbound.conf"
grep -q '"drill-hc", "-p", "5353", "@127.0.0.1", "dnssec.works"' "$T/compose.yml" \
  || { echo "::error::$T/compose.yml: the resolver's health check changed (dnssec.works)"; exit 1; }
sed -i "s/\"@127.0.0.1\", \"dnssec.works\"/\"@127.0.0.1\", \"$probe\"/" "$T/compose.yml"
# e2e-mail (MAIL_CI_EGRESS="<subnet> <dynamic range> <stalwart's address>"):
# the egress network's subnet pinned, its dynamic range away from the pins
# (the resolver starts first and would take stalwart's address), and
# stalwart's address on it (the remote mail server and the fake zone's
# records name it).
if [ -n "${MAIL_CI_EGRESS:-}" ]; then
  read -r esub erange eip <<<"$MAIL_CI_EGRESS"
  [[ "$esub" =~ ^[0-9.]+/[0-9]+$ && "$erange" =~ ^[0-9.]+/[0-9]+$ && "$eip" =~ ^[0-9.]+$ ]] \
    || { echo "::error::MAIL_CI_EGRESS must be '<subnet> <range> <address>'"; exit 1; }
  ESUB="$esub" ERANGE="$erange" EIP="$eip" python3 - "$T/compose.yml" <<'PY'
import os, sys
p = sys.argv[1]
lines = open(p).read().split("\n")
svc, out, done = None, [], {"svc": False, "net": False}
for ln in lines:
    if ln.startswith("  ") and not ln.startswith("   ") and ln.rstrip().endswith(":"):
        svc = ln.strip()[:-1]
    if ln and not ln.startswith((" ", "#")):
        svc = None if ln.strip() != "networks:" else "networks"
    if svc == "stalwart" and ln == "      egress: {}":
        out += ["      egress:", "        ipv4_address: " + os.environ["EIP"]]
        done["svc"] = True
        continue
    if ln == "  egress: {}":
        out += ["  egress:", "    ipam:", "      config:", "        - subnet: " + os.environ["ESUB"],
                "          ip_range: " + os.environ["ERANGE"]]
        done["net"] = True
        continue
    out.append(ln)
if not all(done.values()):
    sys.exit("the template's egress lines changed: %r" % done)
open(p, "w").write("\n".join(out))
PY
  echo "PASS: stalwart template: egress $esub (dynamic $erange), stalwart at $eip"
fi
echo "PASS: stalwart template: adapter image portcullis-mailctl:ci, resolver → $fakedns:8053 (probe $probe)"
