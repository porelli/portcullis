#!/usr/bin/env bash
# ci.yml job build-and-test, steps "Test the mail service", "Mail: the
# backup stopped and restarted mail" and "Mail: the restore voided the
# mail passwords" (mail plan Task 11; contract §19).
#   build-and-test-mail-service.sh setup | after-backup | after-restore
# Runs from the workspace root with GitHub's default shell behaviour (bash -e).
#
# Nothing leaves the runner (user rule, P40, P41): outbound TCP 25 / 465 /
# 587 is rejected first (containers and the runner itself), mail-resolver
# forwards every name to the domains service's fake DNS, and mailctl's
# "public" resolvers are mail-resolver. No message is ever sent to an
# external domain: foreign recipients are only tried at RCPT (refused).
set -euo pipefail
cmd="${1:?usage: build-and-test-mail-service.sh setup|after-backup|after-restore}"
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
ALPINE_IMG=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
HOST=mail.portcullis.local
UUID=7d1f0c2e-5a4b-4c3d-9e8f-0a1b2c3d4e5f
ST=/tmp/mail-ci
mkdir -p "$ST"

fail() { echo "FAIL: $*"; docker compose --profile mail logs --tail=40 mail mailctl mail-resolver 2>/dev/null || true; exit 1; }
cid() { docker compose --profile mail ps -q "$1"; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$(cid "$1")" 2>/dev/null || echo missing; }
wait_healthy() { for _ in $(seq 1 60); do [ "$(health "$1")" = healthy ] && return 0; sleep 3; done; fail "$1 not healthy ($(health "$1"))"; }
vol() { docker run --rm --network none -v "portcullis_$1:/v:ro" "$ALPINE_IMG" cat "/v/$2"; }

# hubapi <method> <path> [body file] — as the Hub: portcullis-mailctl's
# pinned .18 (the Hub is stopped meanwhile), the bearer from the secret
# file inside the container (never on an argv).
hubapi() {
  local body=()
  [ -z "${3:-}" ] || body=(-v "$3:/body.json:ro")
  docker run --rm --network portcullis-mailctl --ip 172.31.255.18 -v "$PWD/secrets/mail/hub-secret:/s:ro" "${body[@]}" \
    --entrypoint sh "$CURL_IMG" -c 'printf "Authorization: Bearer %s\n" "$(cat /s)" > /tmp/h
      if [ -f /body.json ]; then curl -s -H @/tmp/h -H "Content-Type: application/json" -X "$0" --data-binary @/body.json -w "\n%{http_code}" "http://172.31.255.19:8080$1"
      else curl -s -H @/tmp/h -X "$0" -w "\n%{http_code}" "http://172.31.255.19:8080$1"; fi' "$1" "$2"
}

block_egress() {
  # Outbound SMTP never leaves (containers and the runner); only the
  # stack's own networks and loopback stay reachable.
  sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 25,465,587 ! -d 172.16.0.0/12 -j REJECT --reject-with tcp-reset
  sudo iptables -I OUTPUT -p tcp -m multiport --dports 25,465,587 ! -d 127.0.0.0/8 -j REJECT --reject-with tcp-reset
  sudo ip6tables -I FORWARD -p tcp -m multiport --dports 25,465,587 -j REJECT --reject-with tcp-reset
  sudo ip6tables -I OUTPUT -p tcp -m multiport --dports 25,465,587 ! -d ::1/128 -j REJECT --reject-with tcp-reset
  # Probes to TEST-NET-1: refused at once (exit 7), never a timeout.
  set +e
  docker run --rm --network portcullis_mail-egress "$CURL_IMG" -s --connect-timeout 5 telnet://192.0.2.1:25 </dev/null; rc=$?
  set -e
  [ "$rc" = 7 ] || fail "outbound 25 from a container isn't refused (curl exit $rc)"
  if timeout 5 bash -c 'exec 3<>/dev/tcp/192.0.2.1/25' 2>/dev/null; then fail "outbound 25 from the runner connected"; fi
  echo "PASS: outbound TCP 25/465/587 rejected (containers and runner)"
}

# smtp.py — the host-side SMTP / IMAP checks (stdlib).
cat > "$ST/smtp.py" <<'PY'
import imaplib, smtplib, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
what = sys.argv[1]
def code(e): return getattr(e, "smtp_code", None) or (list(e.recipients.values())[0][0] if isinstance(e, smtplib.SMTPRecipientsRefused) else 0)
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

case "$cmd" in
setup)
  block_egress
  # The CI resolver: every name to the fake DNS (domains on domains-egress).
  FAKEDNS="$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis_domains-egress").IPAddress}}' "$(docker compose ps -q domains)")"
  [ -n "$FAKEDNS" ] || fail "no domains address on domains-egress"
  sed "s/__FAKEDNS__/$FAKEDNS/" tests/e2e/mail/unbound-ci.conf > /tmp/unbound-ci.conf
  chmod 644 /tmp/unbound-ci.conf
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
  docker compose --profile mail up -d pebble-mail
  ./portcullis mail enable --yes 2>&1 | tee "$ST/enable.out"
  [ "${PIPESTATUS[0]}" = 0 ] || fail "mail enable"
  for s in mail mailctl mail-resolver; do wait_healthy "$s"; done
  # 1. Users, capabilities, read-only.
  docker inspect "$(cid mail)" | jq -e '.[0] | .Config.User == "2000:2000" and .HostConfig.ReadonlyRootfs
      and .HostConfig.CapAdd == ["NET_BIND_SERVICE"] and (.HostConfig.CapDrop | index("ALL")) != null and .HostConfig.Privileged == false' >/dev/null \
    || fail "mail container: $(docker inspect "$(cid mail)" | jq -c '.[0] | {u: .Config.User, ro: .HostConfig.ReadonlyRootfs, add: .HostConfig.CapAdd, drop: .HostConfig.CapDrop}')"
  docker inspect "$(cid mailctl)" | jq -e '.[0] | .Config.User == "10010:10010" and .HostConfig.GroupAdd == ["10001"] and .HostConfig.ReadonlyRootfs
      and (.HostConfig.CapAdd // []) == []' >/dev/null || fail "mailctl container"
  echo "PASS: mail 2000:2000 read-only with NET_BIND_SERVICE only; mailctl 10010 + group 10001; resolver healthy"
  # 2. The recovery admin is gone; the API key file.
  [ ! -e secrets/mail/recovery.env ] || fail "recovery.env left behind"
  [ "$(stat -c '%a %g' secrets/mail/api-key)" = "640 10010" ] || fail "api-key is $(stat -c '%a %g' secrets/mail/api-key)"
  [ -s secrets/mail/api-key ] || fail "api-key empty"
  head -c 24 /dev/urandom | base64 | jq -Rc '{recovery_user: "portcullis-recovery", recovery_password: .}' \
    | docker compose --profile mail run --rm --no-deps -T mailctl bootstrap --verify-gone || fail "a recovery login isn't refused"
  echo "PASS: no recovery.env, a recovery login gets 401, api-key 0640 group 10010"
  # 3. The management listener: unreachable from portcullis-proxy, 404 for
  # anyone else on portcullis-mail (the API key too), /admin 404.
  if docker run --rm --network portcullis-proxy "$CURL_IMG" -s --connect-timeout 5 -o /dev/null http://172.31.255.2:8080/healthz/live; then
    fail "the management listener answered on portcullis-proxy"
  fi
  for path in /jmap /admin /api/schema; do
    code="$(docker run --rm --network portcullis-mail --ip 172.31.255.9 -v "$PWD/secrets/mail/api-key:/k:ro" --entrypoint sh "$CURL_IMG" \
      -c 'printf "Authorization: Bearer %s\n" "$(cat /k)" > /tmp/h; curl -s -o /dev/null -w "%{http_code}" -H @/tmp/h "http://172.31.255.2:8080$0"' "$path")"
    [ "$code" = 404 ] || fail "$path from 172.31.255.9 with the API key got $code (want 404)"
  done
  echo "PASS: management listener: unreachable from portcullis-proxy, 404 from another portcullis-mail address (API key too)"
  # 4. The certificate: SAN exactly the host, the key reused by a second
  # mail cert, presented on all four ports.
  vol mail_tls fullchain.pem > "$ST/fullchain.pem"
  san="$(openssl x509 -in "$ST/fullchain.pem" -noout -ext subjectAltName | tail -n +2 | tr -d ' ')"
  [ "$san" = "DNS:$HOST" ] || fail "SAN is $san"
  spki() { openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | cut -d' ' -f1; }
  SPKI="$(spki < "$ST/fullchain.pem")"
  ./portcullis mail cert
  [ "$(vol mail_tls fullchain.pem | spki)" = "$SPKI" ] || fail "a second mail cert changed the key"
  for p in 465 993; do
    got="$(openssl s_client -connect "127.0.0.1:$p" -servername "$HOST" </dev/null 2>/dev/null | spki)"
    [ "$got" = "$SPKI" ] || fail "port $p presents another key"
  done
  for p in 25 587; do
    got="$(openssl s_client -starttls smtp -connect "127.0.0.1:$p" -servername "$HOST" </dev/null 2>/dev/null | spki)"
    [ "$got" = "$SPKI" ] || fail "STARTTLS on $p presents another key"
  done
  echo "PASS: certificate SAN DNS:$HOST, key kept by a second mail cert, presented on 25/465/587/993"
  # A mail document (as the Hub) with one account, and its mail password.
  docker compose stop hub >/dev/null
  jq --arg u "$UUID" '.generation = 1000 | .primary_domain = "portcullis.local"
      | .domains = [{name: "portcullis.local", dmarc_start: "reject", mail: "on", dnssec: "unsigned"}]
      | .accounts = [{username: "mailtest", uuid: $u, display_name: "Mail Test", addresses: ["mailtest@portcullis.local"], quota_bytes: 104857600}]
      | .aliases = [] | .lists = [] | .postmaster = ["mailtest"] | .local_networks = [] | .spam.allow = [] | .spam.block = []' \
    mailctl/internal/state/testdata/mailstate_v1.json > "$ST/doc.json"
  out="$(hubapi PUT /v1/state "$ST/doc.json")"; [ "$(tail -n1 <<<"$out")" = 202 ] || fail "PUT /v1/state: $out"
  for _ in $(seq 1 40); do
    hubapi GET /v1/state | head -n1 | jq -e '.applied_generation == 1000' >/dev/null && break; sleep 3
  done
  hubapi GET /v1/state | head -n1 | jq -e '.applied_generation == 1000 and .bootstrap == true' >/dev/null || fail "state: $(hubapi GET /v1/state)"
  printf '{"username":"mailtest","uuid":"%s","label":"ci","expires_at":null}' "$UUID" > "$ST/cred.json"
  out="$(hubapi POST /v1/credentials "$ST/cred.json")"; [ "$(tail -n1 <<<"$out")" = 201 ] || fail "POST /v1/credentials: $(tail -n1 <<<"$out")"
  head -n1 <<<"$out" | jq -r .secret > "$ST/pw"; chmod 600 "$ST/pw"; echo "::add-mask::$(cat "$ST/pw")"
  python3 "$ST/smtp.py" imap mailtest@portcullis.local "$ST/pw" ok
  # 5. Never an open relay.
  python3 "$ST/smtp.py" relay25 127.0.0.1 25
  python3 "$ST/smtp.py" submit mailtest@portcullis.local "$ST/pw" foreign-envelope
  python3 "$ST/smtp.py" submit mailtest@portcullis.local "$ST/pw" foreign-header
  python3 "$ST/smtp.py" submit mailtest@portcullis.local "$ST/pw" own
  MAIL_EGRESS_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis_mail-egress").IPAddress}}' "$(cid mail)")"
  docker run --rm --network portcullis_mail-egress -v "$ST/smtp.py:/smtp.py:ro" --entrypoint python3 portcullis-group-gate /smtp.py relay25 "$MAIL_EGRESS_IP" 10025
  echo "PASS: no AUTH and no relay on 25 (host and from mail-egress), submission refuses a foreign envelope and a foreign From:, own mail accepted"
  # mail test: to a LOCAL address only.
  ./portcullis mail test --to mailtest@portcullis.local | tee "$ST/test.out"
  grep -q 'Message queued' "$ST/test.out" || fail "mail test"
  # 6. Status: the Mail block; the timer missing, then installed.
  st="$(./portcullis status --json || true)"
  jq -e '.mail.mailctl.bootstrap == true and .mail.mailctl.cert.sans == ["'"$HOST"'"] and .mail.timer == "inactive" and .mail.void_pending == false' <<<"$st" >/dev/null \
    || fail "status --json .mail: $(jq -c .mail <<<"$st")"
  ./portcullis status | grep -q 'daily timer portcullis-mail.timer missing or inactive' || fail "no timer warning"
  ./portcullis mail schedule --systemd --out "$ST/units"
  sudo install -m 0644 "$ST/units/portcullis-mail.service" "$ST/units/portcullis-mail.timer" /etc/systemd/system/
  sudo systemctl daemon-reload && sudo systemctl enable --now portcullis-mail.timer
  [ "$(./portcullis status --json | jq -r .mail.timer)" = active ] || fail "timer not active after schedule --systemd"
  echo "PASS: status --json .mail (bootstrap, cert, timer warning → active after schedule --systemd)"
  # For the backup / restore checks.
  docker inspect -f '{{.State.StartedAt}}' "$(cid mail)" > "$ST/started"
  docker run --rm --network none -v portcullis_mailctl_data:/d:ro "$ALPINE_IMG" cat /d/state.json | jq -c '.ext.dkim.keys' > "$ST/dkim.json"
  docker compose start hub >/dev/null
  echo "PASS: the mail service"
  ;;
after-backup)
  B="$(find backups -maxdepth 1 -type d -name '2*' | sort | tail -n1)"
  for f in mail_data.tar.gz mail_etc.tar.gz mailctl_data.tar.gz mail_tls.tar.gz mail_acme.tar.gz; do
    test -s "$B/$f" || fail "backup lacks $f"
  done
  [ "$(docker inspect -f '{{.State.StartedAt}}' "$(cid mail)")" != "$(cat "$ST/started")" ] || fail "the backup didn't stop and restart mail"
  wait_healthy mail
  tar -tzf "$B/mailctl_data.tar.gz" | grep -qx './state.json' || fail "state.json not in mailctl_data's archive"
  [ ! -e "$B/secrets/mail/recovery.env" ] || fail "recovery.env in the backup"
  echo "PASS: the backup stopped mail for its store, restarted it, archived mail_data / mail_etc / mailctl_data / mail_tls / mail_acme"
  ;;
after-restore)
  wait_healthy mail
  wait_healthy mailctl
  [ ! -e secrets/mail/gate/void-pending ] || fail "void-pending left after the restore"
  [ ! -e secrets/mail/recovery.env ] || fail "recovery.env left after the restore"
  python3 "$ST/smtp.py" imap mailtest@portcullis.local "$ST/pw" refused
  docker run --rm --network none -v portcullis_mailctl_data:/d:ro "$ALPINE_IMG" cat /d/state.json > "$ST/state-after.json"
  [ "$(jq -c '.ext.dkim.keys' "$ST/state-after.json")" = "$(cat "$ST/dkim.json")" ] || fail "the DKIM state changed across backup / restore"
  jq -e '.restored_at != null' "$ST/state-after.json" >/dev/null || fail "restored_at not recorded"
  echo "PASS: after the restore: the old mail password is voided (IMAP refused), mail healthy, mailctl_data restored (DKIM state equal, restored_at)"
  ;;
*) echo "usage: $0 setup|after-backup|after-restore"; exit 2 ;;
esac
