#!/usr/bin/env bash
# ci.yml job build-and-test, steps "Test the mail provider", "Mail: the
# backup holds the provider's archive" and "Mail: the restore voided the
# mail passwords" (mail provider plan Task 25; spec §12; contract §19).
#   build-and-test-mail-service.sh setup | after-backup | after-restore
# Runs from the workspace root with GitHub's default shell behaviour (bash -e).
#
# The mail server is the stalwart template wired into the mail slot by the
# Hub (`mail enable --provider stalwart`), from the templates checkout in
# $RUNNER_TEMP/templates (mail-templates-checkout.sh: the locally built
# adapter portcullis-mailctl:ci, the resolver on the fake DNS) loaded as
# the Hub's "portcullis" source.
#
# Nothing leaves the runner (user rule, P40, P41): outbound TCP 25 / 465 /
# 587 is rejected first (containers and the runner itself), the template's
# resolver forwards every name to the domains service's fake DNS (host
# port 8053, CI override), and no message is ever sent to an external
# domain: foreign recipients are only tried at RCPT (refused).
set -euo pipefail
cmd="${1:?usage: build-and-test-mail-service.sh setup|after-backup|after-restore}"
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
ALPINE_IMG=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
HOST=mail.portcullis.local
UUID=7d1f0c2e-5a4b-4c3d-9e8f-0a1b2c3d4e5f
INST=stalwart
PROJ="portcullis-$INST"
ST=/tmp/mail-ci
mkdir -p "$ST"

fail() {
  echo "FAIL: $*"
  for s in bootstrap stalwart adapter resolver; do
    c="$(cid "$s" 2>/dev/null || true)"; [ -z "$c" ] || { echo "--- $s"; docker logs --tail=40 "$c" 2>&1 | tail -n 40; }
  done
  docker compose logs --tail=40 hub 2>/dev/null || true
  exit 1
}
# cid <service> — the wired instance's container (any state).
cid() { docker ps -aq --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=$1" | head -n1; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$(cid "$1")" 2>/dev/null || echo missing; }
wait_healthy() { for _ in $(seq 1 100); do [ "$(health "$1")" = healthy ] && return 0; sleep 3; done; fail "$1 not healthy ($(health "$1"))"; }
# vol <volume> <file> — a file of a named volume (read as root, offline).
vol() { docker run --rm --network none -v "$1:/v:ro" "$ALPINE_IMG" cat "/v/$2"; }

# hubapi <method> <path> [body file] — as the Hub: its pinned address on
# portcullis-mail-api (.18, the Hub stopped meanwhile), the provider at
# .19, the API secret from the slot volume (R-POD2; never on an argv).
hubapi() {
  local body=()
  [ -z "${3:-}" ] || body=(-v "$3:/body.json:ro")
  docker run --rm --network portcullis-mail-api --ip 172.31.255.18 --user 0:0 -v portcullis_mail_provider_slot:/hs:ro "${body[@]}" \
    --entrypoint sh "$CURL_IMG" -c 'printf "Authorization: Bearer %s\n" "$(cat /hs/api-secret)" > /tmp/h
      if [ -f /body.json ]; then curl -s -H @/tmp/h -H "Content-Type: application/json" -X "$0" --data-binary @/body.json -w "\n%{http_code}" "http://172.31.255.19:8080$1"
      else curl -s -H @/tmp/h -X "$0" -w "\n%{http_code}" "http://172.31.255.19:8080$1"; fi' "$1" "$2"
}
hub_mail() { docker compose exec -T hub hub mail "$@"; }

block_egress() {
  # Outbound SMTP never leaves (containers and the runner); only the
  # stack's own networks and loopback stay reachable.
  sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 25,465,587 ! -d 172.16.0.0/12 -j REJECT --reject-with tcp-reset
  sudo iptables -I OUTPUT -p tcp -m multiport --dports 25,465,587 ! -d 127.0.0.0/8 -j REJECT --reject-with tcp-reset
  sudo ip6tables -I FORWARD -p tcp -m multiport --dports 25,465,587 -j REJECT --reject-with tcp-reset
  sudo ip6tables -I OUTPUT -p tcp -m multiport --dports 25,465,587 ! -d ::1/128 -j REJECT --reject-with tcp-reset
  probe_egress bridge
  # Refused (rc 1: the REJECT's reset), never a timeout (124) or a connect.
  local rc
  set +e
  timeout 5 bash -c 'exec 3<>/dev/tcp/192.0.2.1/25' 2>/dev/null; rc=$?
  set -e
  [ "$rc" = 1 ] || fail "outbound 25 from the runner: rc $rc (want 1: refused at once)"
  echo "PASS: outbound TCP 25/465/587 rejected (containers and runner)"
}
# probe_egress <network> — every SMTP port to TEST-NET-1 is refused (exit 7).
probe_egress() {
  local p rc
  for p in 25 465 587; do
    set +e
    docker run --rm --network "$1" "$CURL_IMG" -s --connect-timeout 5 "telnet://192.0.2.1:$p" </dev/null; rc=$?
    set -e
    [ "$rc" = 7 ] || fail "outbound $p from a container on $1 isn't refused (curl exit $rc)"
  done
}

# smtp.py — the host-side SMTP / IMAP checks (stdlib).
cat > "$ST/smtp.py" <<'PY'
import imaplib, smtplib, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
what = sys.argv[1]
if what == "relay25":
    s = smtplib.SMTP(sys.argv[2], int(sys.argv[3]), timeout=20); s.ehlo("relay-test.example")
    assert "auth" not in s.esmtp_features, "AUTH offered on 25"
    s.mail("probe@relay-test.example")
    c, m = s.rcpt("x@foreign.test")
    assert 500 <= c < 600, ("foreign RCPT accepted", c, m)
    print("relay refused", c, m.decode()[:80]); s.quit()
elif what == "submit":
    user, pw, mode = sys.argv[2], open(sys.argv[3]).read().strip(), sys.argv[4]
    s = smtplib.SMTP("127.0.0.1", 587, timeout=20); s.starttls(context=ctx); s.login(user, pw)
    if mode == "foreign-envelope":
        c, m = s.mail("someone@foreign.test")
        if c < 400:
            c, m = s.rcpt(user)
        assert c >= 500, ("foreign MAIL FROM accepted", c, m); print("foreign envelope refused", c)
    elif mode == "foreign-header":
        s.mail(user); s.rcpt(user)
        c, m = s.data(f"From: boss@foreign.test\r\nTo: {user}\r\nSubject: ci\r\n\r\nci\r\n".encode())
        assert c >= 500, ("foreign From: accepted", c, m); print("foreign From: refused", c, m.decode()[:80])
    elif mode == "own":
        s.mail(user); s.rcpt(user)
        c, m = s.data(f"From: {user}\r\nTo: {user}\r\nSubject: ci own\r\n\r\nci\r\n".encode())
        assert c == 250, ("own message refused", c, m); print("own message queued", m.decode()[:80])
    s.quit()
elif what == "imap":
    user, pw, want = sys.argv[2], open(sys.argv[3]).read().strip(), sys.argv[4]
    i = imaplib.IMAP4_SSL("127.0.0.1", 993, ssl_context=ctx)
    try:
        i.login(user, pw); ok = True
    except imaplib.IMAP4.error:
        ok = False
    assert ok == (want == "ok"), ("imap login", ok, "want", want); print("imap login", "ok" if ok else "refused")
PY

# seed_source — the templates checkout as the Hub's "portcullis" source:
# the Hub stopped, the source's clone directory replaced by the checkout,
# its URL emptied (a local source: never pulled), the Hub started again.
seed_source() {
  docker compose stop hub >/dev/null
  docker run --rm --network none -v portcullis_hub_data:/d -v "$RUNNER_TEMP/templates:/tpl:ro" "$ALPINE_IMG" sh -ec '
    p=$(awk "/- name: portcullis\$/ {f=1; next} f && /path:/ {print \$2; exit}" /d/state.yaml)
    case "$p" in /data/repos/*) ;; *) echo "no portcullis source path in state.yaml: $p" >&2; exit 1 ;; esac
    d="/d/${p#/data/}"
    rm -rf "$d" && mkdir -p "$d" && cp -r /tpl/. "$d/" && rm -rf "$d/.git"
    sed -i "s#^\( *\)url: https://github.com/porelli/portcullis-templates.git\$#\1url: \"\"#" /d/state.yaml
    grep -q "url: \"\"" /d/state.yaml
    chown -R 10001:10001 "$d" /d/state.yaml'
  docker compose start hub >/dev/null
  for _ in $(seq 1 40); do hub_mail provider >/dev/null 2>&1 && return 0; sleep 3; done
  fail "the Hub didn't answer after the source swap"
}

case "$cmd" in
setup)
  block_egress
  # mail-cert against the second Pebble (accepts its own DNS-01: the
  # one-shot's fake zone is its own), the CI-only fake provider.
  export PORTCULLIS_TESTPROVIDER=1 DNS_PROVIDER=fake FAKE_API_TOKEN=ci-mail-fake-token-0123 \
    MAIL_ACME_CA_SERVER=https://pebble-mail:14000/dir MAIL_CAA_ISSUER=pebble.test
  # pebble-mail's TLS certificate (DNS:pebble-mail) from a throwaway CI CA:
  # Pebble's own names the host "pebble", which is the domains step's.
  rm -rf /tmp/pebble-mail && mkdir -p /tmp/pebble-mail && (
    cd /tmp/pebble-mail
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=ci-pebble-mail-ca -keyout ca.key -out ca.pem 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=pebble-mail -keyout key.pem -out req.csr 2>/dev/null
    printf 'subjectAltName=DNS:pebble-mail\n' > ext.cnf
    openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out cert.pem 2>/dev/null
    jq -n '{pebble: {listenAddress: "0.0.0.0:14000", managementListenAddress: "0.0.0.0:15000", certificate: "/ci/cert.pem",
      privateKey: "/ci/key.pem", httpPort: 5002, tlsPort: 5001, ocspResponderURL: "", externalAccountBindingRequired: false}}' > pebble.json
    rm -f ca.key req.csr ext.cnf ca.srl; chmod 644 ./*
  )
  docker compose --profile ci-mail up -d pebble-mail
  seed_source
  bash .github/ci/mail-enable-logged.sh stalwart "$ST/enable.out" || fail "mail enable"
  hub_mail provider | jq -e --arg i "$INST" '.wired == true and .instance == $i' >/dev/null || fail "not wired: $(hub_mail provider)"
  for s in resolver stalwart adapter; do wait_healthy "$s"; done
  probe_egress "${PROJ}_egress"
  echo "PASS: outbound TCP 25/465/587 rejected from the template's egress network too"

  # 1. Users, capabilities, read-only (the template's, as the Hub runs it).
  docker inspect "$(cid stalwart)" | jq -e '.[0] | .Config.User == "2000:2000" and .HostConfig.ReadonlyRootfs
      and (.HostConfig.CapAdd | map(ltrimstr("CAP_"))) == ["NET_BIND_SERVICE"] and (.HostConfig.CapDrop | map(ltrimstr("CAP_")) | index("ALL")) != null and .HostConfig.Privileged == false' >/dev/null \
    || fail "stalwart container: $(docker inspect "$(cid stalwart)" | jq -c '.[0] | {u: .Config.User, ro: .HostConfig.ReadonlyRootfs, add: .HostConfig.CapAdd, drop: .HostConfig.CapDrop}')"
  docker inspect "$(cid adapter)" | jq -e '.[0] | .Config.User == "10010:10010" and .HostConfig.ReadonlyRootfs
      and (.HostConfig.CapAdd // []) == [] and .Config.Image == "portcullis-mailctl:ci"' >/dev/null || fail "adapter container: $(docker inspect "$(cid adapter)" | jq -c '.[0] | {u: .Config.User, img: .Config.Image, add: .HostConfig.CapAdd}')"
  echo "PASS: stalwart 2000:2000 read-only with NET_BIND_SERVICE only; the adapter 10010, no capability, the checkout's mailctl"

  # 2. The bootstrap: the job ran the base plan once on the fresh (empty,
  # Ruling R-H2b) store and exited 0; no container keeps a recovery
  # variable; the store is marked; the key file 0640 group 2010.
  [ "$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(cid bootstrap)")" = "exited 0" ] \
    || fail "the bootstrap job: $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$(cid bootstrap)")"
  # The install ran the job more than once (void mode, then normal mode,
  # each a new container): the plan on the fresh store (R-H2b) shows as the
  # store's marker (written only after it); the last run is the marked path.
  bslog="$(docker logs "$(cid bootstrap)" 2>&1)"; grep -qE 'bootstrap: done \(the base plan, the recovery login refused\)|its API key is in place; nothing to do' <<<"$bslog" \
    || fail "the bootstrap job's last run: $(docker logs --tail=20 "$(cid bootstrap)" 2>&1)"
  for s in stalwart adapter bootstrap; do
    docker inspect -f '{{json .Config.Env}}' "$(cid "$s")" | jq -e 'map(select(startswith("STALWART_RECOVERY_"))) == []' >/dev/null \
      || fail "$s carries a STALWART_RECOVERY_* variable"
  done
  vol "${PROJ}_data" .portcullis-base-plan | jq -e '.version == 1' >/dev/null || fail "the store has no base-plan marker"
  docker run --rm --network none -v "${PROJ}_adapter_key:/k:ro" "$ALPINE_IMG" stat -c '%a %g %s' /k/api-key > "$ST/key.stat"
  read -r kmode kgid ksize < "$ST/key.stat"
  [ "$kmode $kgid" = "640 2010" ] && [ "$ksize" -gt 0 ] || fail "api-key is $(cat "$ST/key.stat") (want 640 2010, non-empty)"
  # A second job run (a restart) is the marked path: the key works, no plan.
  docker start -a "$(cid bootstrap)" > "$ST/bootstrap2.out" 2>&1 || { cat "$ST/bootstrap2.out"; fail "the bootstrap job's second run"; }
  grep -q 'nothing to do\|store is locked' "$ST/bootstrap2.out" || fail "second job run: $(tail -5 "$ST/bootstrap2.out")"
  echo "PASS: bootstrap: the base plan once on the empty store, recovery login refused, no recovery variable left, marker, api-key 0640 group 2010; a second run plans nothing"

  # 3. The management listener: 404 for any other address on the
  # template's internal network, the API key too; stalwart isn't on
  # portcullis-proxy at all.
  for path in /jmap /admin /api/schema; do
    code="$(docker run --rm --network "${PROJ}_internal" --user 10010:2010 -v "${PROJ}_adapter_key:/k:ro" --entrypoint sh "$CURL_IMG" \
      -c 'printf "Authorization: Bearer %s\n" "$(cat /k/api-key)" > /tmp/h; curl -s -o /dev/null -w "%{http_code}" -H @/tmp/h "http://172.31.255.2:8080$0"' "$path")"
    [ "$code" = 404 ] || fail "$path from another internal address with the API key got $code (want 404)"
  done
  docker inspect "$(cid stalwart)" | jq -e '.[0].NetworkSettings.Networks | keys | map(select(. == "portcullis-proxy" or . == "portcullis")) == []' >/dev/null \
    || fail "stalwart is on a core network: $(docker inspect "$(cid stalwart)" | jq -c '.[0].NetworkSettings.Networks | keys')"
  # The admin view's listener (contract §19.13) is bound after the job's
  # runs (EnsureAdminView also makes it on a store from before the admin
  # view): it answers TLS, and its rule refuses any address but the proxy's.
  code="$(docker run --rm --network "${PROJ}_internal" "$CURL_IMG" -sk -o /dev/null -w '%{http_code}' https://172.31.255.2:8443/admin || true)"
  [ "$code" = 404 ] || fail "the admin-view listener (8443) from another internal address got '$code' (want 404: bound, refused by its rule)"
  echo "PASS: management listener 404 from another internal address (API key too); admin-view listener bound, 404 off the proxy's address; stalwart on no core network"

  # 4. The certificate: SAN exactly the host, the key reused by a second
  # mail cert, presented on all four published ports.
  vol portcullis_mail_tls fullchain.pem > "$ST/fullchain.pem"
  san="$(openssl x509 -in "$ST/fullchain.pem" -noout -ext subjectAltName | tail -n +2 | tr -d ' ')"
  [ "$san" = "DNS:$HOST" ] || fail "SAN is $san"
  spki() { openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1; }
  SPKI="$(spki < "$ST/fullchain.pem")"
  ./portcullis mail cert
  [ "$(vol portcullis_mail_tls fullchain.pem | spki)" = "$SPKI" ] || fail "a second mail cert changed the key"
  for p in 465 993; do
    got="$(openssl s_client -connect "127.0.0.1:$p" -servername "$HOST" </dev/null 2>/dev/null | spki)"
    [ "$got" = "$SPKI" ] || fail "port $p presents another key"
  done
  for p in 25 587; do
    got="$(openssl s_client -starttls smtp -connect "127.0.0.1:$p" -servername "$HOST" </dev/null 2>/dev/null | spki)"
    [ "$got" = "$SPKI" ] || fail "STARTTLS on $p presents another key"
  done
  echo "PASS: certificate SAN DNS:$HOST, key kept by a second mail cert, presented on 25/465/587/993"

  # 5. Status (the Hub's view): wired, reachable, no void owed, no hold;
  # the timer missing, then installed.
  ./portcullis mail status --json > "$ST/status.json" || true
  jq -e --arg i "$INST" '.hub.wired == true and .hub.instance == $i and .hub.reachable == true and .hub.void_owed == null and .hub.held == null
      and .cert.not_after != null and .timer == "inactive"' "$ST/status.json" >/dev/null || fail "mail status --json: $(cat "$ST/status.json")"
  st_text="$(./portcullis status 2>&1 || true)"
  grep -q 'daily timer portcullis-mail.timer missing or inactive' <<<"$st_text" || fail "no timer warning: $(grep -i mail <<<"$st_text" | head -20)"
  ./portcullis mail schedule --systemd --out "$ST/units"
  sudo install -m 0644 "$ST/units/portcullis-mail.service" "$ST/units/portcullis-mail.timer" /etc/systemd/system/
  sudo systemctl daemon-reload && sudo systemctl enable --now portcullis-mail.timer
  ./portcullis mail status --json > "$ST/status.json" || true
  [ "$(jq -r .timer "$ST/status.json")" = active ] || fail "timer not active after schedule --systemd: $(cat "$ST/status.json")"
  echo "PASS: mail status --json (wired, reachable, nothing owed or held, certificate; timer warning → active)"

  # 6. A mail document (as the Hub) with one account, and its mail
  # password: the Hub stopped (it would send its own document), the
  # generation above the Hub's.
  docker compose stop hub >/dev/null
  out="$(hubapi GET /v1/state)"
  GEN=$(( $(head -n1 <<<"$out" | jq -r '.generation // 0') + 1000 ))
  jq --arg u "$UUID" --argjson g "$GEN" --arg h "$HOST" '.generation = $g | .primary_domain = "portcullis.local" | .mail_hostname = $h
      | .domains = [{name: "portcullis.local", dmarc_start: "reject", dmarc_floor: "reject", mail: "on", dnssec: "unsigned"}]
      | .accounts = [{username: "mailtest", uuid: $u, display_name: "Mail Test", addresses: ["mailtest@portcullis.local"], quota_bytes: 104857600}]
      | .aliases = [] | .lists = [] | .postmaster = ["mailtest"] | .local_networks = [] | .spam.allow = [] | .spam.block = []
      | .relay = null | .confirm_mass_removal = false | del(.senders)' \
    mailctl/internal/state/testdata/mailstate_v2.json > "$ST/doc.json"
  out="$(hubapi PUT /v1/state "$ST/doc.json")"; [ "$(tail -n1 <<<"$out")" = 202 ] || fail "PUT /v1/state: $out"
  for _ in $(seq 1 40); do
    out="$(hubapi GET /v1/state)"; head -n1 <<<"$out" | jq -e --argjson g "$GEN" '.applied_generation == $g' >/dev/null && break; sleep 3
  done
  out="$(hubapi GET /v1/state)"
  head -n1 <<<"$out" | jq -e --argjson g "$GEN" '.applied_generation == $g' >/dev/null || fail "state: $out"
  printf '{"username":"mailtest","uuid":"%s","label":"ci","expires_at":null}' "$UUID" > "$ST/cred.json"
  out="$(hubapi POST /v1/credentials "$ST/cred.json")"; [ "$(tail -n1 <<<"$out")" = 201 ] || fail "POST /v1/credentials: $(tail -n1 <<<"$out")"
  head -n1 <<<"$out" | jq -r .secret > "$ST/pw"; chmod 600 "$ST/pw"; echo "::add-mask::$(cat "$ST/pw")"
  python3 "$ST/smtp.py" imap mailtest@portcullis.local "$ST/pw" ok

  # 7. Never an open relay: no AUTH and no relay on 25 (the published port
  # and from the template's egress network), submission refuses a foreign
  # envelope and a foreign From:, own mail accepted.
  python3 "$ST/smtp.py" relay25 127.0.0.1 25
  python3 "$ST/smtp.py" submit mailtest@portcullis.local "$ST/pw" foreign-envelope
  python3 "$ST/smtp.py" submit mailtest@portcullis.local "$ST/pw" foreign-header
  python3 "$ST/smtp.py" submit mailtest@portcullis.local "$ST/pw" own
  EGRESS_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${PROJ}_egress\").IPAddress}}" "$(cid stalwart)")"
  [ -n "$EGRESS_IP" ] || fail "stalwart has no egress address"
  docker run --rm --network "${PROJ}_egress" -v "$ST/smtp.py:/smtp.py:ro" --entrypoint python3 portcullis-group-gate /smtp.py relay25 "$EGRESS_IP" 10025
  echo "PASS: no AUTH and no relay on 25 (host and from the egress network), submission refuses a foreign envelope and a foreign From:, own mail accepted"

  # 8. The gate, for real (P3): the sentinel gone (as after a core restore
  # empties the slot volume, R-POD2), a raw start of the server fails before
  # it opens the store; the files back, it starts.
  docker run --rm --network none -v portcullis_mail_provider_slot:/hs "$ALPINE_IMG" rm /hs/.present
  sentinel_back() { docker run --rm --network none -v portcullis_mail_provider_slot:/hs "$ALPINE_IMG" sh -c 'printf "portcullis-mail-gate\n" > /hs/.present && chown 10001:2000 /hs/.present && chmod 0640 /hs/.present'; }
  docker stop "$(cid stalwart)" >/dev/null
  set +e
  docker start -a "$(cid stalwart)" > "$ST/gate.out" 2>&1; rc=$?
  set -e
  [ "$rc" != 0 ] || fail "stalwart started without the gate sentinel"
  grep -qi 'gate\|refus\|not wired' "$ST/gate.out" || fail "stalwart failed for another reason: $(tail -5 "$ST/gate.out")"
  sentinel_back
  docker start "$(cid stalwart)" >/dev/null
  wait_healthy stalwart
  echo "PASS: the gate: without .present a raw start of stalwart exits $rc before serving; with it, healthy again"

  # The pass the daily timer runs (it must succeed), then the Hub again.
  # The Hub's start brings the instance up again (its containers may be
  # recreated: the alias mail-api is gone meanwhile), so the pass waits
  # for the provider to be healthy and reachable through the Hub.
  docker compose start hub >/dev/null
  provider_ready() {
    for _ in $(seq 1 60); do
      st="$(hub_mail status 2>/dev/null || true)"
      if jq -e '.wired == true and .reachable == true' <<<"$st" >/dev/null 2>&1 \
         && [ "$(health stalwart)" = healthy ] && [ "$(health adapter)" = healthy ]; then
        return 0
      fi
      sleep 5
    done
    fail "the provider isn't reachable through the Hub after its start: $st"
  }
  provider_ready
  sleep 10; provider_ready  # still there (not mid-recreate)
  ./portcullis mail rotate > "$ST/rotate.out" 2>&1 || { cat "$ST/rotate.out"; fail "mail rotate"; }
  echo "PASS: the mail provider"
  ;;
after-backup)
  B="$(find backups -maxdepth 1 -type d -name '2*' | sort | tail -n1)"
  a="$(jq -r '.mail_provider_archive // ""' "$B/MANIFEST.json")"
  [[ "$a" =~ ^$INST/[0-9]{8}T[0-9]{6}Z\.tar$ ]] || fail "MANIFEST.json's mail_provider_archive: '$a'"
  tar -xzOf "$B/hub_data.tar.gz" "./backups/$a" > "$ST/provider.tar" || fail "$a isn't in hub_data.tar.gz"
  members="$(tar -tf "$ST/provider.tar")"
  grep -q 'data' <<<"$members" || fail "the provider archive has no data volume: $(head -20 <<<"$members")"
  for f in mail_tls.tar.gz mail_acme.tar.gz; do test -s "$B/$f" || fail "backup lacks $f"; done
  ./portcullis backup verify --local "$B" > "$ST/verify.out" 2>&1 || { cat "$ST/verify.out"; fail "backup verify"; }
  grep -q "the mail provider's archive $a is in hub_data.tar.gz" "$ST/verify.out" || fail "backup verify didn't check the provider archive"
  echo "PASS: the backup names the provider's archive ($a), hub_data holds it, mail_tls / mail_acme archived, verify checks it"
  ;;
after-restore)
  for s in resolver stalwart adapter; do wait_healthy "$s"; done
  # The Hub verified the void (P8) and lifted void mode.
  for _ in $(seq 1 60); do
    st="$(hub_mail status 2>/dev/null || true)"
    jq -e '.wired == true and .void_owed == null and .reachable == true' <<<"$st" >/dev/null 2>&1 && break
    sleep 5
  done
  jq -e '.wired == true and .void_owed == null and .reachable == true' <<<"$st" >/dev/null || fail "after the restore: $st"
  docker run --rm --network none -v portcullis_hub_data:/d:ro "$ALPINE_IMG" test ! -e /d/mail-restore-pending || fail "mail-restore-pending left after the restore"
  python3 "$ST/smtp.py" imap mailtest@portcullis.local "$ST/pw" refused
  docker compose stop hub >/dev/null
  out="$(hubapi GET "/v1/credentials?uuid=$UUID")"
  [ "$(tail -n1 <<<"$out")" = 200 ] && head -n1 <<<"$out" | jq -e 'length == 0' >/dev/null || fail "credentials after the restore: $out"
  docker compose start hub >/dev/null
  echo "PASS: after the restore: the Hub verified the void (nothing owed), no hold file left, the old mail password refused, no credential left"
  ;;
*) echo "usage: $0 setup|after-backup|after-restore"; exit 2 ;;
esac
