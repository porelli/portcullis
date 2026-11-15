#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test a node certificate (pki_node) passes
# no TLS tier and no Keycloak X.509" (contract §17, ruling P1): pki_node is
# its own self-signed root, so a node-worker / node-control / node-link
# certificate, with or without its CA, fails Traefik's protected,
# protected-any and authaware handshakes (Keycloak's auth.<d> is
# authaware) and verifies under none of the trust files. Runs from the
# workspace root after "Test Keycloak X.509 login" (Traefik, Keycloak, the
# ci-mtls test app and /tmp/test-client.* are there).
set -euo pipefail

VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
D="$(mktemp -d)"
chmod 700 "$D"
WHOAMI=docker.io/traefik/whoami:v1.12.0@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44
cleanup() {
  docker compose -p ci-node-any -f "$D/any.yml" down -v >/dev/null 2>&1 || true
  rm -rf "$D"
}
trap cleanup EXIT

# 0) The exported file: present, its own root, in no trust list.
test -s certs/node-ca.crt || { echo "FAIL: certs/node-ca.crt missing after pki setup"; exit 1; }
openssl verify -CAfile certs/node-ca.crt certs/node-ca.crt >/dev/null \
  || { echo "FAIL: node-ca.crt is not self-signed"; exit 1; }
if openssl verify -CAfile certs/root-ca.crt certs/node-ca.crt >/dev/null 2>&1; then
  echo "FAIL: node-ca.crt is signed by the Portcullis root"; exit 1
fi
BODY="$(sed -n 2p certs/node-ca.crt)"
LEAKS="$(grep -rlF "$BODY" certs | grep -v '^certs/node-ca.crt$' || true)"
[ -z "$LEAKS" ] || { echo "FAIL: the node CA is in a trust file: $LEAKS"; exit 1; }
echo "PASS: node-ca.crt is its own root and in no chain, truststore or group-gate file"

# 1) One certificate of each node role (root token; `issue` makes the key —
#    CI only, enroll may neither issue nor sign node-link).
issue() {  # <role> <cn>
  (umask 077 && vault write -format=json "pki_node/issue/$1" common_name="$2" ttl=1h > "$D/$1.json") \
    || { echo "FAIL: issuing a $1 certificate"; exit 1; }
  jq -r .data.certificate "$D/$1.json" > "$D/$1.crt"
  jq -r .data.issuing_ca "$D/$1.json" > "$D/$1.ca"
  cat "$D/$1.crt" "$D/$1.ca" > "$D/$1.chain"
  (umask 077 && jq -r .data.private_key "$D/$1.json" > "$D/$1.key")
  rm -f "$D/$1.json"
  cmp -s "$D/$1.ca" certs/node-ca.crt || { echo "FAIL: $1 was not issued by node-ca.crt"; exit 1; }
}
issue node-worker ci.node.portcullis.internal
issue node-control hub.control
issue node-link link.control
openssl x509 -in "$D/node-worker.crt" -noout -ext extendedKeyUsage | grep -q 'TLS Web Client Authentication' \
  || { echo "FAIL: node-worker has no clientAuth (the test would prove nothing)"; exit 1; }

# 2) A protected-any router next to ci-mtls (protected) and ci-gated (authaware).
cat > "$D/any.yml" <<YML
services:
  whoami:
    image: $WHOAMI
    networks: [portcullis-proxy]
    labels:
      traefik.enable: "true"
      traefik.http.services.ci-node-any.loadbalancer.server.port: "80"
      traefik.http.routers.ci-node-any.rule: Host(\`any.portcullis.local\`)
      traefik.http.routers.ci-node-any.entrypoints: websecure
      traefik.http.routers.ci-node-any.tls.options: protected-any@file
      traefik.http.routers.ci-node-any.middlewares: client-headers@file
      traefik.http.routers.ci-node-any.service: ci-node-any
networks:
  portcullis-proxy:
    external: true
YML
docker compose -p ci-node-any -f "$D/any.yml" up -d >/dev/null

code() {  # <host> [curl args] — the HTTP status, 000 when the handshake fails
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 --cacert certs/ca-chain.crt \
    --resolve "$1:443:127.0.0.1" "${@:2}" "https://$1/" || true
}
# Positive controls: the YubiKey certificate passes each tier (so a 000
# below is the node certificate's refusal, not a dead router).
for i in $(seq 1 30); do
  [ "$(code any.portcullis.local --cert /tmp/test-client.crt --key /tmp/test-client.key)" = 200 ] && break
  [ "$i" -eq 30 ] && { echo "FAIL: the protected-any router never answered the YubiKey certificate"; docker compose logs --tail=40 traefik; exit 1; }
  sleep 2
done
for h in mtls.portcullis.local gated.portcullis.local auth.portcullis.local; do
  c="$(code "$h" --cert /tmp/test-client.crt --key /tmp/test-client.key)"
  [ "$c" != 000 ] || { echo "FAIL: control: the YubiKey certificate's handshake with $h failed"; exit 1; }
done
echo "PASS: control: the YubiKey certificate passes protected, protected-any and authaware"

# 3) Every node certificate, with its CA and alone, fails every tier.
for role in node-worker node-control node-link; do
  for sent in chain crt; do
    for h in mtls.portcullis.local any.portcullis.local gated.portcullis.local auth.portcullis.local; do
      c="$(code "$h" --cert "$D/$role.$sent" --key "$D/$role.key")"
      [ "$c" = 000 ] || { echo "FAIL: a $role certificate ($sent) completed a TLS handshake with $h (HTTP $c)"; exit 1; }
    done
  done
done
echo "PASS: node-worker, node-control and node-link certificates (with or without their CA) fail protected, protected-any and authaware (Keycloak's auth host included)"

# 4) Keycloak's X.509 truststore and group-gate's CA files: no path.
for f in certs/truststore/portcullis-ca-chain.pem certs/truststore/portcullis-yubikey-ca.pem \
         certs/truststore/portcullis-browser-ca.pem certs/yubikey-ca.crt certs/browser-ca.crt \
         certs/ca-chain.crt certs/ca-chain-yubikey.crt; do
  if openssl verify -partial_chain -purpose sslclient -CAfile "$f" -untrusted "$D/node-worker.ca" "$D/node-worker.crt" >/dev/null 2>&1; then
    echo "FAIL: a node-worker certificate verifies under $f"; exit 1
  fi
done
echo "PASS: a node-worker certificate verifies under no truststore, CA chain or group-gate CA file"
