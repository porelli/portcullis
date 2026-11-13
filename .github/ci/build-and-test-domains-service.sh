#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test the domains service (Pebble, fake DNS provider, Traefik HTTP provider over mTLS)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
# Contract §12.4 "Checks" / "CI". Pebble's directory TLS root ships in its image.
cid="$(docker create "$PEBBLE_IMG")"; docker cp "$cid:/test/certs/pebble.minica.pem" /tmp/pebble.minica.pem; docker rm "$cid" >/dev/null
chmod 644 /tmp/pebble.minica.pem
docker compose up -d pebble domains
for i in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q domains)")" = healthy ] && break
  [ "$i" -eq 40 ] && { echo "FAIL: domains not healthy"; docker compose logs --tail=40 domains; exit 1; }
  sleep 3
done
docker compose exec -T domains sh -c 'test "$(id -u)" = 10004' || { echo "FAIL: domains is not uid 10004"; exit 1; }
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
SECRET="$(cat secrets/domains/api-secret)"; echo "::add-mask::$SECRET"
# The API on portcullis-domains (the Hub's network); the bearer comes from stdin.
dapi() { printf 'Authorization: Bearer %s\n' "$SECRET" \
         | docker run --rm -i --network portcullis_portcullis-domains "$CURL_IMG" -s -H @- -H 'Content-Type: application/json' "$@"; }
code=$(docker run --rm --network portcullis_portcullis-domains "$CURL_IMG" -s -o /dev/null -w '%{http_code}' http://domains:8080/domains)
[ "$code" = 401 ] || { echo "FAIL: domains API without the bearer secret got $code"; exit 1; }
# The API answers only on portcullis-domains: not to Traefik (portcullis-certs).
# Positive control from the same container: domains:8443 answers HTTP
# (Go's TLS server replies "400 … HTTP request to an HTTPS server").
tstatus() { docker compose exec -T traefik wget -q -T 5 -O /dev/null -S "$1" 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -n1 | cut -d' ' -f2; }
[ "$(tstatus http://domains:8443/)" = 400 ] || { echo "FAIL: positive control: Traefik can't reach domains:8443 ($(tstatus http://domains:8443/))"; exit 1; }
[ -z "$(tstatus http://domains:8080/healthz)" ] || { echo "FAIL: Traefik reached the domains API (:8080)"; exit 1; }
# The certificate endpoint, as Traefik fetches it (client certificate), and without.
E=secrets/domains/certs-endpoint
dyn() { docker run --rm --user 0:0 --network portcullis_portcullis-certs -v "$PWD/$E:/c:ro" "$CURL_IMG" \
          -sf --cacert /c/ca.crt --cert /c/client.crt --key /c/client.key https://domains:8443/traefik/dynamic; }
if docker run --rm --network portcullis_portcullis-certs -v "$PWD/$E/ca.crt:/ca.crt:ro" "$CURL_IMG" -sf --cacert /ca.crt https://domains:8443/traefik/dynamic >/dev/null 2>&1; then
  echo "FAIL: certificate endpoint answered without a client certificate"; exit 1
fi
dyn | jq -e '. == {"tls": {"certificates": []}}' >/dev/null || { echo "FAIL: empty document: $(dyn)"; exit 1; }
# Membership of the internal networks at runtime.
docker network inspect portcullis_portcullis-certs | jq -e '[.[0].Containers[].Name | sub("^portcullis-"; "") | sub("-[0-9]+$"; "")] | sort == ["domains", "traefik"]' >/dev/null \
  || { echo "FAIL: portcullis-certs members: $(docker network inspect portcullis_portcullis-certs | jq -c '[.[0].Containers[].Name]')"; exit 1; }
TRAEFIK_STARTED="$(docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q traefik)")"

D=team-b.ci-domains.test
code=$(dapi -o /dev/null -w '%{http_code}' -X PUT -d '{"provider":"fake","credentials":{"api_token":"ci-fake-token-0123456789"}}' "http://domains:8080/domains/$D")
[ "$code" = 202 ] || { echo "FAIL: enroll $D got $code"; exit 1; }
code=$(dapi -o /dev/null -w '%{http_code}' -X PUT -d '{"provider":"fake","credentials":{"api_token":"x"}}' "http://domains:8080/domains/auth.portcullis.local")
[ "$code" = 400 ] || { echo "FAIL: enrolling a core host got $code"; exit 1; }
for i in $(seq 1 60); do
  st="$(dapi http://domains:8080/domains | jq -r --arg d "$D" '.[] | select(.name == $d) | .state')"
  [ "$st" = ready ] && break
  [ "$i" -eq 60 ] && { echo "FAIL: $D state $st: $(dapi http://domains:8080/domains)"; docker compose logs --tail=60 domains pebble; exit 1; }
  sleep 2
done
dapi http://domains:8080/domains | jq -e --arg d "$D" '.[] | select(.name == $d) | .records_ok == true and (.cert_not_after | type) == "string" and .last_error == ""' >/dev/null \
  || { echo "FAIL: domain object: $(dapi http://domains:8080/domains)"; exit 1; }
if docker compose logs domains 2>&1 | grep -q 'ci-fake-token-0123456789'; then echo "FAIL: the DNS token is in the domains logs"; exit 1; fi
if docker run --rm -v portcullis_domains_data:/d:ro docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a grep -rq 'ci-fake-token-0123456789' /d; then
  echo "FAIL: the DNS token is in clear in domains_data"; exit 1
fi

# The served document: only tls.certificates with certFile/keyFile;
# every certificate's SANs exactly <d> and *.<d> of an enrolled domain.
DOC="$(dyn)"
echo "$DOC" | jq -e '(keys == ["tls"]) and (.tls | keys == ["certificates"]) and (.tls.certificates | length == 1)
    and (.tls.certificates | all(keys == ["certFile", "keyFile"]))' >/dev/null \
  || { echo "FAIL: served document shape: $(echo "$DOC" | jq -c 'walk(if type == "string" then .[0:20] else . end)')"; exit 1; }
ENROLLED="$(dapi http://domains:8080/domains | jq -c '[.[].name]')"
for i in $(echo "$DOC" | jq -r '.tls.certificates | keys[]'); do
  SANS="$(echo "$DOC" | jq -r ".tls.certificates[$i].certFile" | openssl x509 -noout -ext subjectAltName | tail -n +2 | tr -d ' ' | tr ',' '\n' | sort | paste -sd,)"
  name="${SANS##*DNS:}"
  [ "$SANS" = "DNS:*.$name,DNS:$name" ] || { echo "FAIL: served SANs $SANS"; exit 1; }
  echo "$ENROLLED" | jq -e --arg n "$name" 'index($n) != null' >/dev/null || { echo "FAIL: served a certificate for $name, not enrolled"; exit 1; }
  case "$name" in *portcullis.local) echo "FAIL: served a main-domain certificate ($name)"; exit 1 ;; esac
done
echo "PASS: domains enrolled $D (Pebble, DNS-01), serves only {tls: {certificates}} with SANs {<d>, *.<d>}, mTLS required"

# DNS hardening (contract §12.2 / §12.4): the caa set of $D is pinned
# to the service's own ACME account (Pebble's, DNS_CAA_ISSUER=pebble.test).
ACCT="$(dapi http://domains:8080/acme/account)"
echo "$ACCT" | jq -e '.caa_issuer == "pebble.test" and (.account_uri | startswith("https://")) and .ca_server == "https://pebble:14000/dir"' >/dev/null \
  || { echo "FAIL: /acme/account: $ACCT"; exit 1; }
PLAN="$(dapi "http://domains:8080/domains/$D/dns?refresh=1")"
echo "$PLAN" | jq -e --argjson a "$ACCT" '.can_write == true and .caa.would_issue == true and .caa.account_uri == $a.account_uri
    and ([.items[] | select(.set == "caa" and .status != "foreign")] | length == 1 and all(.status == "ok"))
    and ([.items[] | select(.set == "address" and .status != "foreign")] | all(.status == "ok"))' >/dev/null \
  || { echo "FAIL: the plan of $D: $PLAN"; exit 1; }
dapi http://domains:8080/domains | jq -e --arg d "$D" '.[] | select(.name == $d) | .caa_ok == true' >/dev/null \
  || { echo "FAIL: caa_ok of $D: $(dapi http://domains:8080/domains)"; exit 1; }
dapi http://domains:8080/main/dns | jq -e '.can_write == false and .name == "portcullis.local"' >/dev/null \
  || { echo "FAIL: the main-domain plan: $(dapi http://domains:8080/main/dns)"; exit 1; }
docker compose exec -T domains domains report --main --json | jq -e --arg d "$D" '.main.name == "portcullis.local" and (.domains | keys == [$d])' >/dev/null \
  || { echo "FAIL: domains report --main --json"; exit 1; }
# The one-shot dns tool (profile tools): apply in its own fake zone
# (the testprovider build), the credentials on stdin only.
TOOL_IN="$(jq -n '{name: "tool.ci-domains.test", provider: "fake", credentials: {api_token: "ci-fake-token-0123456789"},
    ipv4: "203.0.113.10", ipv6: "", ca_server: "https://pebble:14000/dir",
    caa: {enabled: true, issuer: "pebble.test", account_uri: "", iodef: ""}, nomail: false, sets: ["address", "caa"], mail_from: ""}')"
printf '%s' "$TOOL_IN" | docker compose run --rm -T dns-tool apply --wait 60s > /tmp/dns-tool-apply.json \
  || { echo "FAIL: dns-tool apply: $(cat /tmp/dns-tool-apply.json)"; exit 1; }
jq -e '.can_write == true and .caa.would_issue == true
    and ([.items[] | select((.set == "address" or .set == "caa") and .status != "foreign" and .severity != "info")] | length >= 3 and all(.status == "ok"))' /tmp/dns-tool-apply.json >/dev/null \
  || { echo "FAIL: dns-tool apply plan: $(cat /tmp/dns-tool-apply.json)"; exit 1; }
# check without credentials, against the domains service's fake DNS:
# the enrolled $D, pinned to the service's account, exits 0.
IP4="$(echo "$PLAN" | jq -r '[.items[] | select(.set == "address" and .type == "A")][0].want[0]')"
jq -n --arg d "$D" --arg ip "$IP4" --argjson a "$ACCT" '{name: $d, provider: "", ipv4: $ip, ipv6: "", ca_server: $a.ca_server,
    caa: {enabled: true, issuer: "pebble.test", account_uri: $a.account_uri, iodef: ""}, nomail: false, sets: [], mail_from: ""}' \
  | docker compose run --rm -T -e DOMAINS_RESOLVERS=domains:8053 dns-tool check > /tmp/dns-tool-check.json \
  || { echo "FAIL: dns-tool check: $(cat /tmp/dns-tool-check.json)"; exit 1; }
jq -e '.can_write == false and .caa.would_issue == true' /tmp/dns-tool-check.json >/dev/null || { echo "FAIL: dns-tool check plan: $(cat /tmp/dns-tool-check.json)"; exit 1; }
if printf '%s' "$TOOL_IN" | docker compose run --rm -T dns-tool check >/dev/null 2>&1; then echo "FAIL: dns-tool check accepted credentials"; exit 1; fi
echo "PASS: dns plan of $D pinned to the service's account; dns-tool apply / check (stdin credentials)"

# Traefik picks it up by SNI through its HTTP provider, without a restart.
sni_sans() { openssl s_client -connect 127.0.0.1:443 -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' '; }
for i in $(seq 1 25); do
  sni_sans "app.$D" | grep -q "DNS:\*\.$D" && break
  [ "$i" -eq 25 ] && { echo "FAIL: Traefik does not serve the $D certificate for app.$D: $(sni_sans "app.$D")"; docker compose logs --tail=40 traefik; exit 1; }
  sleep 1
done
[ "$(docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q traefik)")" = "$TRAEFIK_STARTED" ] || { echo "FAIL: Traefik restarted"; exit 1; }
for h in auth.portcullis.local hub.portcullis.local; do
  sni_sans "$h" | grep -q 'DNS:\*\.portcullis\.local' || { echo "FAIL: $h no longer serves the main certificate: $(sni_sans "$h")"; exit 1; }
done
echo "PASS: the $D certificate is served by SNI within ~25 s without a Traefik restart; auth and hub keep the main certificate"

# The HTTP provider contributed nothing but certificates.
tapi() { docker run --rm --network portcullis "$CURL_IMG" -sf "http://traefik:8080/api/$1"; }
for ep in http/routers http/services http/middlewares tcp/routers tcp/services tcp/middlewares udp/routers udp/services; do
  tapi "$ep" | jq -e '[.[] | select((.provider // "") == "http" or ((.name // "") | endswith("@http")))] == []' >/dev/null \
    || { echo "FAIL: @http objects in /api/$ep: $(tapi "$ep" | jq -c '[.[] | select(.provider == "http") | .name]')"; exit 1; }
done
tapi rawdata | jq -e '[.. | objects | keys[] | select(endswith("@http"))] == []' >/dev/null \
  || { echo "FAIL: @http keys in /api/rawdata"; exit 1; }
echo "PASS: Traefik's API lists no @http router / service / middleware / transport"

# Delete: the certificate stops being served, the records go.
code=$(dapi -o /dev/null -w '%{http_code}' -X DELETE "http://domains:8080/domains/$D")
[ "$code" = 204 ] || { echo "FAIL: delete $D got $code"; exit 1; }
dyn | jq -e '.tls.certificates == []' >/dev/null || { echo "FAIL: certificate still in the document after delete"; exit 1; }
for i in $(seq 1 25); do
  sni_sans "app.$D" | grep -q "DNS:\*\.$D" || break
  [ "$i" -eq 25 ] && { echo "FAIL: Traefik still serves the deleted $D certificate"; exit 1; }
  sleep 1
done
[ "$(docker inspect -f '{{.State.StartedAt}}' "$(docker compose ps -q traefik)")" = "$TRAEFIK_STARTED" ] || { echo "FAIL: Traefik restarted"; exit 1; }
# A domain that stays enrolled: the backup / restore test below checks it survives.
code=$(dapi -o /dev/null -w '%{http_code}' -X PUT -d '{"provider":"fake","credentials":{"api_token":"ci-fake-token-0123456789"}}' http://domains:8080/domains/keep.ci-domains.test)
[ "$code" = 202 ] || { echo "FAIL: enroll keep.ci-domains.test got $code"; exit 1; }
echo "PASS: a deleted domain's certificate stops being served (no restart)"
