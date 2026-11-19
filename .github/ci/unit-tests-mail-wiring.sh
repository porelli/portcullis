#!/usr/bin/env bash
# ci.yml job unit-tests, step "mail slot wiring (contract §19.1)".
# Asserts the mail slot's core wiring over `docker compose config` (every
# profile), on Docker, with the Podman overlay and with the SELinux
# overlay: portcullis-mail-api (internal, the subnet, the Hub pinned),
# portcullis-metrics-mail (named, internal, Prometheus only in core),
# mail_slot (the Hub rw, Prometheus ro, nobody else), the Hub's group 2000
# and slot env, mail-cert unchanged, and no mail server in core: no
# service mail / mailctl / mail-resolver, no profile mail, no
# secrets/mail bind. The provider's own wiring is the Hub's override
# (contract §19.1). Run from the workspace root (bash -e); generates a CI
# .env when there is none.
set -euo pipefail
[ -f .env ] || ./portcullis init --env-only --runtime docker --non-interactive --domain ci.example.org --dns-provider none >/dev/null
export PODMAN_SOCK=/run/user/1001/podman/podman.sock

slot_rule() {  # <config json>
  printf '%s' "$1" | jq -e '
    def nets: .networks | if . == null then {} elif type == "object" then . else error("networks: not a map") end;
    def members($n): [.services | to_entries[] | select(.value | nets | has($n)) | .key] | sort;
    def mounts($src): [.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume" and .source == $src)] | length > 0) | .key] | sort;
    def vmount($svc; $src): [.services[$svc].volumes[]? | select(.type == "volume" and .source == $src) | "\(.target):\(.read_only // false)"];
    .services.hub as $h | .services["mail-cert"] as $t | .services.prometheus as $p
    # No mail server in core.
    | (.services | has("mail") or has("mailctl") or has("mail-resolver") | not)
    and ([.services[] | (.profiles // [])[] | select(. == "mail")] == [])
    and ([.services[].volumes[]? | select(.type == "bind" and (.source | test("/secrets/mail/|/mail/unbound\\.conf$")))] == [])
    and (.networks | has("portcullis-mail") or has("portcullis-mailctl") or has("mail-egress") | not)
    and ([.volumes | keys[] | select(. == "mail_data" or . == "mail_etc" or . == "mailctl_data")] == [])
    # The API network: internal, fixed subnet and range, the Hub pinned at .18.
    and .networks["portcullis-mail-api"].name == "portcullis-mail-api"
    and .networks["portcullis-mail-api"].internal == true
    and .networks["portcullis-mail-api"].ipam.config[0].subnet == "172.31.255.16/28"
    and .networks["portcullis-mail-api"].ipam.config[0].ip_range == "172.31.255.24/29"
    and (members("portcullis-mail-api") == ["hub"])
    and $h.networks["portcullis-mail-api"].ipv4_address == "172.31.255.18"
    # The metrics network: named (the override joins it as external).
    and .networks["portcullis-metrics-mail"].name == "portcullis-metrics-mail"
    and .networks["portcullis-metrics-mail"].internal == true
    and (members("portcullis-metrics-mail") == ["prometheus"])
    # mail_slot: the Hub rw at /mail-slot, Prometheus ro, nobody else.
    and (mounts("mail_slot") == ["hub", "prometheus"])
    and vmount("hub"; "mail_slot") == ["/mail-slot:false"]
    and vmount("prometheus"; "mail_slot") == ["/mail-slot:true"]
    # mail_provider_slot (R-POD2): the Hub rw at /mail-provider-slot,
    # nobody else in core; a fixed name (the override mounts it external).
    and (mounts("mail_provider_slot") == ["hub"])
    and vmount("hub"; "mail_provider_slot") == ["/mail-provider-slot:false"]
    and .volumes["mail_provider_slot"].name == "portcullis_mail_provider_slot"
    # The Hub: group 2000 (P6), the slot env, no mailctl leftovers.
    and ($h.group_add | index("2000")) != null and ($h.group_add | index("10007")) != null
    and $h.environment.HUB_MAIL_SLOT_DIR == "/mail-slot"
    and ($h.environment | has("HUB_MAILCTL_API_URL") or has("HUB_MAILCTL_SECRET_FILE") | not)
    # mail-cert unchanged.
    and $t.image == "portcullis-domains" and $t.pull_policy == "never" and $t.profiles == ["tools"]
    and $t.user == "10004:2000" and $t.read_only == true and $t.entrypoint == ["domains", "mail-cert"]
    and $t.healthcheck.disable == true and $t.environment == {"DOMAINS_RESOLVERS": "1.1.1.1:53,8.8.8.8:53"}
    and ([$t.networks | keys[]] == ["domains-egress"]) and (($t.ports // []) == [])
    and (mounts("mail_tls") == ["mail-cert"]) and (mounts("mail_acme") == ["mail-cert"])
    and vmount("mail-cert"; "mail_tls") == ["/tls:false"] and vmount("mail-cert"; "mail_acme") == ["/acme:false"]
    and $t.cap_drop == ["ALL"] and ($t.cap_add // []) == [] and (.services.domains.environment.DOMAINS_MAIL_HOSTNAME == "")
    # The one capability exception left in core is Traefik.
    and ([.services | to_entries[] | select((.value.cap_add // []) | index("NET_BIND_SERVICE")) | .key] == ["traefik"])
    # Nothing in core publishes a mail port.
    and ([.services[].ports[]? | .published | tostring | select(. == "25" or . == "465" or . == "587" or . == "993")] == [])
  ' >/dev/null
}

# shellcheck disable=SC2034  # read through ${!c}
CFG="$(docker compose -f docker-compose.yml --profile '*' config --format json)"
# shellcheck disable=SC2034
CFG_PODMAN="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml -f docker-compose.podman.yml --profile '*' config --format json)"
# shellcheck disable=SC2034
CFG_SELINUX="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml -f docker-compose.podman.yml -f docker-compose.podman-selinux.yml --profile '*' config --format json)"
for c in CFG CFG_PODMAN CFG_SELINUX; do
  slot_rule "${!c}" || { echo "FAIL: mail slot wiring (contract §19.1) in $c"; exit 1; }
done
[ ! -e docker-compose.mail-recovery.yml ] || { echo "FAIL: docker-compose.mail-recovery.yml is the stalwart template's now"; exit 1; }
# A moved API subnet follows into the Hub's address and the core subnets lists.
MOVED="$(PORTCULLIS_MAIL_API_SUBNET=10.87.0.0/28 PORTCULLIS_MAIL_API_IP_RANGE=10.87.0.8/29 PORTCULLIS_MAIL_API_HUB_IP=10.87.0.2 \
  docker compose -f docker-compose.yml --profile '*' config --format json)"
echo "$MOVED" | jq -e '.networks["portcullis-mail-api"].ipam.config[0].subnet == "10.87.0.0/28"
    and .services.hub.networks["portcullis-mail-api"].ipv4_address == "10.87.0.2"
    and (.services["group-gate"].environment.GATE_CORE_SUBNETS | split(" ") | index("10.87.0.0/28")) != null
    and (.services.wg.environment.WG_CORE_SUBNETS | split(" ") | index("10.87.0.0/28")) != null' >/dev/null \
  || { echo "FAIL: a moved PORTCULLIS_MAIL_API_SUBNET doesn't follow into the Hub's address and the core subnet lists"; exit 1; }
echo "PASS: mail slot wiring (portcullis-mail-api, portcullis-metrics-mail, mail_slot, mail_provider_slot, the Hub's group 2000, mail-cert; Docker, Podman, SELinux)"
