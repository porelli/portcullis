#!/usr/bin/env bash
# ci.yml job unit-tests, step "mail profile wiring (contract §19.1)".
# Asserts the mail profile's compose wiring over `docker compose config`
# with --profile mail (plus tools for mail-cert), on Docker, with the
# Podman overlay and with the SELinux overlay: network members and flags,
# pinned addresses, mounts, users, capabilities, pins, no engine socket,
# no Traefik router. Run from the workspace root (bash -e); generates a CI
# .env when there is none.
set -euo pipefail
[ -f .env ] || ./portcullis init --env-only --runtime docker --non-interactive --domain ci.example.org --dns-provider none >/dev/null
export PODMAN_SOCK=/run/user/1001/podman/podman.sock

mail_rule() {  # <config json>
  printf '%s' "$1" | jq -e '
    def nets: .networks | if . == null then {} elif type == "object" then . else error("networks: not a map") end;
    def members($n): [.services | to_entries[] | select(.value | nets | has($n)) | .key] | sort;
    def mounts($src): [.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume" and .source == $src)] | length > 0) | .key] | sort;
    def binds($re): [.services | to_entries[] | select([.value.volumes[]? | select(.type == "bind" and (.source | test($re)))] | length > 0) | .key] | sort;
    def vmount($svc; $src): [.services[$svc].volumes[]? | select(.type == "volume" and .source == $src) | "\(.target):\(.read_only // false)"];
    .services.mail as $m | .services.mailctl as $c | .services["mail-resolver"] as $r | .services["mail-cert"] as $t | .services.hub as $h
    # Membership and flags.
    | (members("portcullis-mail") == ["mail", "mail-resolver", "mailctl"])
    and (members("portcullis-mailctl") == ["hub", "mailctl"])
    and (members("portcullis-metrics-mail") == ["mail", "mailctl", "prometheus"])
    and (members("mail-egress") == ["mail", "mail-resolver", "mailctl"])
    and .networks["portcullis-mail"].internal == true and .networks["portcullis-mail"].name == "portcullis-mail"
    and .networks["portcullis-mailctl"].internal == true and .networks["portcullis-mailctl"].name == "portcullis-mailctl"
    and .networks["portcullis-metrics-mail"].internal == true
    and (.networks["mail-egress"].internal // false) == false
    and .networks["mail-egress"].enable_ipv6 == false
    and .networks["portcullis-mail"].ipam.config[0].subnet == "172.31.255.0/28"
    and .networks["portcullis-mail"].ipam.config[0].ip_range == "172.31.255.8/29"
    and .networks["portcullis-mailctl"].ipam.config[0].subnet == "172.31.255.16/28"
    and .networks["portcullis-mailctl"].ipam.config[0].ip_range == "172.31.255.24/29"
    # Pinned addresses.
    and $m.networks["portcullis-mail"].ipv4_address == "172.31.255.2"
    and $c.networks["portcullis-mail"].ipv4_address == "172.31.255.3"
    and $r.networks["portcullis-mail"].ipv4_address == "172.31.255.4"
    and $h.networks["portcullis-mailctl"].ipv4_address == "172.31.255.18"
    and $c.networks["portcullis-mailctl"].ipv4_address == "172.31.255.19"
    and $c.networks["portcullis-proxy"].ipv4_address == "172.31.250.4"
    and ([.services | to_entries[] | select(.value.networks["portcullis-proxy"].ipv4_address? != null) | "\(.key)=\(.value.networks["portcullis-proxy"].ipv4_address)"] | sort
         == ["mailctl=172.31.250.4", "mcp-gate=172.31.250.3", "traefik=172.31.250.2"])
    and $m.networks["portcullis-metrics-mail"].aliases == ["mail-metrics"]
    and $c.networks["portcullis-metrics-mail"].aliases == ["mailctl-metrics"]
    and ([$m.networks | keys[]] | sort == ["mail-egress", "portcullis-mail", "portcullis-metrics-mail"])
    and ([$c.networks | keys[]] | sort == ["mail-egress", "portcullis-mail", "portcullis-mailctl", "portcullis-metrics-mail", "portcullis-proxy"])
    and ([$r.networks | keys[]] | sort == ["mail-egress", "portcullis-mail"])
    and ([$t.networks | keys[]] == ["domains-egress"])
    # The API answers on its portcullis-mailctl subnet; the addresses of mailctl.
    and $c.environment.MAILCTL_API_SUBNET == .networks["portcullis-mailctl"].ipam.config[0].subnet
    and $c.environment.MAILCTL_RULES_ADDR == "\($c.networks["portcullis-mail"].ipv4_address):8082"
    and $c.environment.MAILCTL_STALWART_URL == "http://\($m.networks["portcullis-mail"].ipv4_address):8080"
    and $c.environment.MAILCTL_LOCAL_RESOLVER == "\($r.networks["portcullis-mail"].ipv4_address):5353"
    and $c.environment.MAILCTL_METRICS_ADDR == "mailctl-metrics:9100"
    and $c.environment.MAILCTL_WELLKNOWN_ENTRYPOINTS == "websecure,vpnsecure"
    and $h.environment.HUB_MAILCTL_API_URL == "http://mailctl:8080"
    and $h.environment.HUB_MAILCTL_SECRET_FILE == "/run/portcullis/mail/hub-secret"
    # Every secret-like value is a file path, never a value.
    and (([$c, $m] | map(.environment // {} | to_entries[]) | map(select(.key | test("SECRET|KEY|PASSWORD|TOKEN"))) | all(.value | startswith("/run/portcullis/mail/"))))
    # Mounts.
    and (binds("/secrets/mail/api-key$") == ["mailctl"])
    and (binds("/secrets/mail/hub-secret$") == ["hub", "mailctl"])
    and (binds("/secrets/mail/dqs-key$") == ["mailctl"])
    and (binds("/secrets/mail/mailctl-metrics-secret$") == ["mailctl"])
    and $c.environment.MAILCTL_METRICS_SECRET_FILE == "/run/portcullis/mail/metrics-secret"
    and (binds("/secrets/mail/(metrics-secret|relay-password)$") == ["mail"])
    and (binds("/secrets/mail/gate$") == ["mail"])
    # The start gate: a non-recovery start refuses while the marker exists,
    # then the image binary and its arguments.
    and ($m.entrypoint | length) == 4 and $m.entrypoint[0:2] == ["/bin/sh", "-c"]
    and ($m.entrypoint[2] | test("-e /run/portcullis/mail/gate/void-pending") and test("STALWART_RECOVERY_MODE") and test("-e /run/portcullis/mail/gate/recovery-session") and test("exit 1") and test("exec /usr/local/bin/stalwart"))
    and $m.command == ["--config", "/etc/stalwart/config.json"]
    and (binds("/secrets/mail/") == ["hub", "mail", "mailctl"])
    and (binds("/mail/unbound\\.conf$") == ["mail-resolver"])
    and ([.services[].volumes[]? | select(.type == "bind" and (.source | test("/secrets/mail/"))) | .read_only] | all)
    and (mounts("mail_data") == ["mail"]) and (mounts("mail_etc") == ["mail"])
    and (mounts("mail_tls") == ["mail", "mail-cert"]) and vmount("mail"; "mail_tls") == ["/run/portcullis/mail/tls:true"]
    and vmount("mail-cert"; "mail_tls") == ["/tls:false"]
    and (mounts("mail_acme") == ["mail-cert"]) and (mounts("mailctl_data") == ["mailctl"])
    and ([$c.volumes[] | select(.type == "volume") | .source] == ["mailctl_data"])
    and ([$r.volumes[] | "\(.type):\(.target):\(.read_only // false)"] == ["bind:/etc/unbound/custom.conf:true"])
    # No engine socket, no privilege, no devices, no sysctls; caps.
    and ([$m, $c, $r, $t] | all(([.volumes[]? | select(.target == "/var/run/docker.sock" or (.source // "" | test("docker\\.sock$|podman\\.sock$")))] == [])
         and (.privileged // false) == false and (.devices // []) == [] and (.sysctls // {}) == {} and (.network_mode // null) == null
         and .cap_drop == ["ALL"] and (.security_opt | index("no-new-privileges:true")) != null and .read_only == true))
    and $m.cap_add == ["NET_BIND_SERVICE"]
    and ([$c, $r, $t] | all((.cap_add // []) == []))
    and ([.services | to_entries[] | select((.value.cap_add // []) | index("NET_BIND_SERVICE")) | .key] | sort == ["mail", "traefik"])
    # Users, groups, limits.
    and $m.user == "2000:2000" and ($m.group_add // []) == [] and $m.init == true
    and $c.user == "10010:10010" and $c.group_add == ["10001"]
    and $r.user == "101:102" and ($r.group_add // []) == []
    and $t.user == "10004:2000"
    and $m.ulimits.nofile.soft == 65536 and $m.ulimits.nofile.hard == 65536
    and $m.mem_limit != null and $m.pids_limit == 256 and $c.pids_limit == 128 and $r.pids_limit == 64
    and ([$m.tmpfs[] | split(":")[0]] | sort == ["/tmp", "/var/log/stalwart"])
    and ($c.tmpfs | index("/tmp")) != null
    # Pins and images.
    and ($m.image | test("^docker\\.io/stalwartlabs/stalwart:v1\\.1\\.0@sha256:f772aa6ef8cd8018969fa491640f1436b0270eb14e2c219b5f37f1a77020837e$"))
    and ($r.image | test("^docker\\.io/klutchell/unbound:v1\\.26\\.2@sha256:50cbeb32b5838a829a7226b19cb151f9535bd7f9f3190f950780f452fe807478$"))
    and $c.image == "portcullis-mailctl" and ($c.build.context | endswith("/mailctl"))
    and $t.image == "portcullis-domains" and $t.pull_policy == "never" and $t.profiles == ["tools"]
    and $t.entrypoint == ["domains", "mail-cert"] and $t.healthcheck.disable == true
    and $t.environment == {"DOMAINS_RESOLVERS": "1.1.1.1:53,8.8.8.8:53"} and ($t.env_file // null) == null
    and .services.domains.environment.DOMAINS_MAIL_HOSTNAME == ""
    and ([$m, $c, $r] | all(.profiles == ["mail"]))
    # Ports: exactly the four, on IPv4, mail only.
    and ([$m.ports[] | "\(.host_ip):\(.published):\(.target)"] | sort == ["0.0.0.0:25:10025", "0.0.0.0:465:10465", "0.0.0.0:587:10587", "0.0.0.0:993:10993"])
    and ([$c, $r, $t] | all((.ports // []) == []))
    # Health checks (no shell in the Unbound image).
    and $r.healthcheck.test == ["CMD", "drill-hc", "-p", "5353", "@127.0.0.1", "dnssec.works"]
    and $c.healthcheck.test == ["CMD", "mailctl", "healthcheck"]
    and ($m.healthcheck.test | index("http://127.0.0.1:8080/healthz/live")) != null
    and $m.environment.STALWART_HEALTHCHECK_URL == "http://127.0.0.1:8080/healthz/live"
    # No Traefik router on the mail services (the well-known router of mailctl
    # comes in Task 8 as the only one).
    and ([$m, $c, $r, $t] | all([.labels // {} | keys[] | select(startswith("traefik.http.routers.")) | select(test("^traefik\\.http\\.routers\\.mail-wellknown\\.") | not)] == []))
  ' >/dev/null
}

PROFILES=(--profile mail --profile tools --profile monitoring)
CFG="$(docker compose -f docker-compose.yml "${PROFILES[@]}" config --format json)"
CFG_PODMAN="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml -f docker-compose.podman.yml "${PROFILES[@]}" config --format json)"
CFG_SELINUX="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml -f docker-compose.podman.yml -f docker-compose.podman-selinux.yml "${PROFILES[@]}" config --format json)"
for c in CFG CFG_PODMAN CFG_SELINUX; do
  mail_rule "${!c}" || { echo "FAIL: mail profile wiring (contract §19.1) in $c"; exit 1; }
done
echo "$CFG_PODMAN" | jq -e '[.services.mail.restart, .services.mailctl.restart, .services["mail-resolver"].restart] == ["always", "always", "always"]' >/dev/null \
  || { echo "FAIL: docker-compose.podman.yml must set restart: always on mail, mailctl, mail-resolver"; exit 1; }
echo "$CFG" | jq -e '[.services.mail.restart, .services.mailctl.restart, .services["mail-resolver"].restart] == ["unless-stopped", "unless-stopped", "unless-stopped"]' >/dev/null \
  || { echo "FAIL: mail services restart unless-stopped on Docker"; exit 1; }
# The SELinux overlay labels the mail binds: Z for one reader, z for the shared hub-secret.
echo "$CFG_SELINUX" | jq -e --arg p "$PWD/" '
    [.services | to_entries[] | .key as $s | .value.volumes[]? | select(.type == "bind" and (.source | test("/secrets/mail/|/mail/unbound\\.conf$")))
     | "\($s) \(.source | ltrimstr($p)) \(.bind.selinux // "-")"] | sort
    == ["hub secrets/mail/hub-secret z", "mail secrets/mail/gate Z", "mail secrets/mail/metrics-secret Z", "mail secrets/mail/relay-password Z",
        "mail-resolver mail/unbound.conf Z", "mailctl secrets/mail/api-key Z", "mailctl secrets/mail/dqs-key Z", "mailctl secrets/mail/hub-secret z",
        "mailctl secrets/mail/mailctl-metrics-secret Z"]' >/dev/null \
  || { echo "FAIL: the SELinux overlay's mail binds (Z one reader, z the shared hub-secret)"; exit 1; }
# The recovery admin reaches mail only through its optional env file
# (compose folds env_file into environment, so read the source).
yq -o=json ".services.mail.env_file" docker-compose.yml 2>/dev/null | jq -e '. == [{"path": "./secrets/mail/recovery.env", "required": false}, {"path": "./secrets/mail/update.env", "required": false}]' >/dev/null \
  || { echo "FAIL: mail's only env_files are ./secrets/mail/recovery.env and update.env, required: false"; exit 1; }
# Moved subnets follow everywhere they are used.
MOVED="$(PORTCULLIS_MAIL_SUBNET=10.86.0.0/28 PORTCULLIS_MAIL_IP_RANGE=10.86.0.8/29 PORTCULLIS_MAIL_IP=10.86.0.2 PORTCULLIS_MAILCTL_MAIL_IP=10.86.0.3 PORTCULLIS_MAIL_RESOLVER_IP=10.86.0.4 \
  PORTCULLIS_MAILCTL_SUBNET=10.87.0.0/28 PORTCULLIS_MAILCTL_IP_RANGE=10.87.0.8/29 PORTCULLIS_MAILCTL_HUB_IP=10.87.0.2 PORTCULLIS_MAILCTL_API_IP=10.87.0.3 \
  docker compose -f docker-compose.yml --profile mail config --format json)"
echo "$MOVED" | jq -e '.services.mailctl.environment as $e
    | $e.MAILCTL_API_SUBNET == "10.87.0.0/28" and $e.MAILCTL_RULES_ADDR == "10.86.0.3:8082"
    and $e.MAILCTL_STALWART_URL == "http://10.86.0.2:8080" and $e.MAILCTL_LOCAL_RESOLVER == "10.86.0.4:5353"
    and .services.hub.networks["portcullis-mailctl"].ipv4_address == "10.87.0.2"' >/dev/null \
  || { echo "FAIL: moved mail subnets don't follow into mailctl's environment / the Hub's address"; exit 1; }
# Without the profile: no mail service runs, but the Hub keeps its
# portcullis-mailctl address and the hub-secret bind (it tolerates no mailctl).
docker compose -f docker-compose.yml config --format json | jq -e '
    (.services | has("mail") or has("mailctl") or has("mail-resolver") | not)
    and .services.hub.networks["portcullis-mailctl"].ipv4_address == "172.31.255.18"
    and ([.services.hub.volumes[] | select(.target == "/run/portcullis/mail/hub-secret") | .read_only] == [true])' >/dev/null \
  || { echo "FAIL: without the mail profile the Hub keeps portcullis-mailctl and the hub-secret bind, and no mail service runs"; exit 1; }
echo "PASS: mail profile wiring (networks, addresses, mounts, users, caps, pins, ports, health checks; Docker, Podman, SELinux)"
