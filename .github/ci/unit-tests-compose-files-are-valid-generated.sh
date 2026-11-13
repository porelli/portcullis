#!/usr/bin/env bash
# ci.yml job unit-tests, step "compose files are valid with a generated .env".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
./portcullis init --env-only --runtime docker --non-interactive --domain ci.example.org --dns-provider none
docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml -f docker-compose.podman-selinux.yml --profile '*' config -q
# Healthchecks that behave the same on Podman (its compat API
# re-splits CMD arguments on whitespace).
tests/lint_healthchecks.sh .env
# The podman overlay: restart: always (what podman-restart.service
# starts at boot) on exactly the core services that have a restart
# policy, nothing else; Docker keeps unless-stopped.
docker compose -f docker-compose.yml -f docker-compose.podman.yml --profile '*' config -q
WANT_RS="$(docker compose -f docker-compose.yml --profile '*' config --format json | jq -c '[.services | to_entries[] | select(.value.restart != null) | .key] | sort')"
GOT_RS="$(yq -o=json '.services' docker-compose.podman.yml | jq -c '[to_entries[] | select(.value == {"restart": "always"}) | .key] | sort')"
ALL_RS="$(yq -o=json '.services' docker-compose.podman.yml | jq -c 'keys | sort')"
[ "$WANT_RS" = "$GOT_RS" ] && [ "$GOT_RS" = "$ALL_RS" ] \
  || { echo "FAIL: docker-compose.podman.yml must set only restart: always on every core service with a restart policy (want $WANT_RS, got $GOT_RS / $ALL_RS)"; exit 1; }
docker compose -f docker-compose.yml --profile '*' config --format json | jq -e '[.services[] | select(.restart != null) | .restart] | unique == ["unless-stopped"]' >/dev/null \
  || { echo "FAIL: Docker's restart policy is unless-stopped everywhere"; exit 1; }
docker compose -f docker-compose.yml --profile monitoring config -q
docker compose -f docker-compose.yml --profile '*' config -q
docker compose -f docker-compose.yml -f docker-compose.apps.yml config -q
docker compose -f docker-compose.test.yml config -q
docker compose -f docker-compose.yml config --format json \
  | jq -e '.services.hub.environment.HUB_PROXY_SECRET | test("^[0-9a-f]{64}$")' >/dev/null \
  || { echo "FAIL: hub has no generated HUB_PROXY_SECRET"; exit 1; }
if HUB_PROXY_SECRET='' docker compose -f docker-compose.yml config -q 2>/dev/null; then
  echo "FAIL: compose accepted an empty HUB_PROXY_SECRET"; exit 1
fi
for v in FORWARD_AUTH_REDIS_PASSWORD FORWARD_AUTH_EXT_REDIS_PASSWORD; do
  if env "$v=" docker compose -f docker-compose.yml config -q 2>/dev/null; then
    echo "FAIL: compose accepted an empty $v"; exit 1
  fi
done
if grep -rn 'portcullis-forward-auth-secret' docker-compose*.yml keycloak/ .env.example; then
  echo "FAIL: public default forward-auth secret is back"; exit 1
fi
CFG="$(docker compose -f docker-compose.yml config --format json)"
# Every profile (monitoring, ...): same pin + hardening rules.
CFG_ALL="$(docker compose -f docker-compose.yml --profile '*' config --format json)"
# Contract §6: only the socket proxies mount the engine socket —
# rootful Docker's, or the operator's rootless Podman socket
# (PORTCULLIS_ENGINE_SOCKET) — read-only at /var/run/docker.sock;
# the Hub gets the runtime as HUB_CONTAINER_RUNTIME.
socket_rule() {  # <config json> <runtime>
  printf '%s' "$1" | jq -e --arg rt "$2" '(env.PORTCULLIS_ENGINE_SOCKET // "/var/run/docker.sock") as $src
      | ([.services | to_entries[] | select([.value.volumes[]?.source] | index($src)) | .key] | sort == ["socket-proxy-hub", "socket-proxy-traefik"])
      and ([.services["socket-proxy-traefik", "socket-proxy-hub"].volumes[] | select(.source == $src) | "\(.target):\(.read_only)"] == ["/var/run/docker.sock:true", "/var/run/docker.sock:true"])
      and ([.services[].volumes[]? | select(.source == "/var/run/docker.sock" or .target == "/var/run/docker.sock")] | length == 2)
      and .services.hub.environment.HUB_CONTAINER_RUNTIME == $rt' >/dev/null
}
socket_rule "$CFG" docker || { echo "FAIL: the engine socket (docker): only the two proxies, read-only; HUB_CONTAINER_RUNTIME=docker"; exit 1; }
export PODMAN_SOCK=/run/user/1001/podman/podman.sock
CFG_PODMAN="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml config --format json)"
PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" socket_rule "$CFG_PODMAN" podman \
  || { echo "FAIL: the engine socket (podman): only the two proxies mount $PODMAN_SOCK read-only; HUB_CONTAINER_RUNTIME=podman"; exit 1; }
# No default runtime (P0): compose refuses an empty CONTAINER_RUNTIME.
if CONTAINER_RUNTIME='' docker compose -f docker-compose.yml config -q 2>/dev/null; then
  echo "FAIL: compose accepted an empty CONTAINER_RUNTIME"; exit 1
fi
# Core stays userspace (VPN cross-reference): no NET_ADMIN / SYS_ADMIN.
CAPS="$(echo "$CFG_ALL" | jq -r '.services | to_entries[] | select((.value.cap_add // []) | any(. == "NET_ADMIN" or . == "SYS_ADMIN")) | .key')"
[ -z "$CAPS" ] || { echo "FAIL: core services with NET_ADMIN / SYS_ADMIN: $CAPS"; exit 1; }
# The rootless Podman SELinux overlay (P10 + the controller's
# narrowing): every project bind (source inside the checkout)
# re-declared with the base's target / read_only and a label — Z
# when one service mounts the path, z only when several services
# mount it or a path above / below it (or templates/ / appfiles/,
# which the Hub's app instances mount) —; never a label on the
# checkout, secrets/, backups/ or .env (or a parent of them): the
# Hub's `.:/project` becomes a tmpfs with group-gate's map bound in;
# nothing outside the checkout relabelled (never the engine socket);
# no service the base lacks; label=disable on the two proxies only
# (compose services; the CLI's short-lived helpers — ct_run, restic —
# run label=disable under Podman instead of relabelling host files)
# (each keeping no-new-privileges); the base itself relabels nothing.
OV_ALL="$(docker compose -f docker-compose.yml -f docker-compose.podman-selinux.yml --profile '*' config --format json)"
binds() {  # <config json> — "service target read_only selinux" of every project bind
  printf '%s' "$1" | jq -r --arg p "$PWD" '.services | to_entries[] | .key as $s | (.value.volumes // [])[]
      | select(.type == "bind" and (.source == $p or (.source | startswith($p + "/"))))
      | "\($s) \(.target) \(.read_only // false) \(.bind.selinux // "-")"' | sort
}
[ -z "$(binds "$CFG_ALL" | awk '$4 != "-"')" ] || { echo "FAIL: docker-compose.yml relabels a bind (selinux): only the overlay may"; exit 1; }
NBINDS="$(binds "$CFG_ALL" | wc -l | tr -d ' ')"
[ "$NBINDS" = 46 ] || { echo "FAIL: expected 46 project binds in docker-compose.yml, got $NBINDS: update docker-compose.podman-selinux.yml (and this count)"; exit 1; }
diff <({ binds "$CFG_ALL" | grep -vx 'hub /project true -' | awk '{print $1, $2, $3}'; echo "hub /project/group-gate/group-gate-map.conf true"; } | sort) \
     <(binds "$OV_ALL" | awk '{print $1, $2, $3}' | sort) \
  || { echo "FAIL: docker-compose.podman-selinux.yml must re-declare every project bind (but the Hub's /project root) with the same target / read_only, plus the Hub's map file"; exit 1; }
echo "$OV_ALL" | jq -e '[.services.hub.volumes[] | select(.target == "/project") | .type] == ["tmpfs"]' >/dev/null \
  || { echo "FAIL: the overlay must turn the Hub's /project root into a tmpfs (never relabel the checkout)"; exit 1; }
BADLABEL="$(echo "$OV_ALL" | jq -r --arg p "$PWD" '
    def inside($a; $b): $a == $b or ($a | startswith($b + "/"));
    [.services | to_entries[] | .key as $s | (.value.volumes // [])[] | select(.type == "bind") | {s: $s, src: .source, lab: (.bind.selinux // null)}] as $all
    | ($all | map(select(.lab != null))) as $lab
    | ($lab[] | select(inside(.src; $p) | not) | "\(.s) \(.src): a label outside the checkout"),
      ($lab[] | select(.src as $x | ([$p, $p + "/secrets", $p + "/backups", $p + "/.env"] | any(inside(.; $x)))) | "\(.s) \(.src): never label the checkout, secrets/, backups/ or .env (or a parent)"),
      ($lab[] | . as $b
        | ([$all[] | select(.s != $b.s and (inside(.src; $b.src) or inside($b.src; .src)))] | length > 0
           or inside($b.src; $p + "/templates") or inside($b.src; $p + "/appfiles")) as $shared
        | select(($shared and .lab != "z") or (($shared | not) and .lab != "Z"))
        | "\(.s) \(.src): \(.lab), want \(if $shared then "z (shared)" else "Z (one service)" end)"),
      ([.services[].volumes[]? | select(.target == "/var/run/docker.sock") | .bind.selinux // empty][] | "the engine socket is relabelled")')"
[ -z "$BADLABEL" ] || { echo "FAIL: SELinux labels in docker-compose.podman-selinux.yml:"; echo "$BADLABEL"; exit 1; }
EXTRA="$(comm -23 <(yq -r '.services | keys | .[]' docker-compose.podman-selinux.yml | sort) <(docker compose -f docker-compose.yml --profile '*' config --services | sort))"
[ -z "$EXTRA" ] || { echo "FAIL: docker-compose.podman-selinux.yml names services docker-compose.yml lacks: $EXTRA"; exit 1; }
if ! echo "$OV_ALL" | jq -e '([.services | to_entries[] | select((.value.security_opt // []) | index("label=disable")) | .key] | sort == ["socket-proxy-hub", "socket-proxy-traefik"])
       and ([.services["socket-proxy-traefik", "socket-proxy-hub"].security_opt | index("no-new-privileges:true")] | all(. != null))' >/dev/null \
   || ! echo "$CFG_ALL" | jq -e '[.services[].security_opt[]? | select(startswith("label"))] == []' >/dev/null; then
  echo "FAIL: label=disable must be on exactly the two socket proxies, only in the overlay, next to no-new-privileges"; exit 1
fi
# The hardening baseline holds with the overlay merged too.
WEAK="$(echo "$OV_ALL" | jq -r '.services | to_entries[]
    | select((.value.security_opt // [] | index("no-new-privileges:true") | not) or ((.value.cap_drop // []) != ["ALL"])
             or (.value.mem_limit == null) or (.value.pids_limit == null)) | .key')"
[ -z "$WEAK" ] || { echo "FAIL: with the SELinux overlay, services without no-new-privileges/cap_drop ALL/limits: $WEAK"; exit 1; }
echo "$CFG" | jq -e '.services.traefik.environment.TRAEFIK_PROVIDERS_DOCKER_ENDPOINT == "tcp://socket-proxy-traefik:2375"
    and .services.hub.environment.DOCKER_HOST == "tcp://socket-proxy-hub:2375"
    and .services["socket-proxy-traefik"].environment.POST == "0"
    and ([.services.traefik.networks | keys[]] | index("socket-proxy-traefik"))
    and ([.services.hub.networks | keys[]] | index("socket-proxy-hub"))
    and ([.services | to_entries[] | select((.value.networks // {}) | has("socket-proxy-hub")) | .key] | sort == ["hub", "socket-proxy-hub"])
    and ([.services | to_entries[] | select((.value.networks // {}) | has("socket-proxy-traefik")) | .key] | sort == ["socket-proxy-traefik", "traefik"])' >/dev/null \
  || { echo "FAIL: socket proxy wiring"; exit 1; }
# Contract §5: Traefik injects the generated secret on the Hub router.
echo "$CFG" | jq -e '.services.hub.labels as $l
    | ($l["traefik.http.routers.hub.middlewares"] | test("hub-proxy-secret@docker"))
    and $l["traefik.http.middlewares.hub-proxy-secret.headers.customrequestheaders.X-Portcullis-Proxy-Secret"] == .services.hub.environment.HUB_PROXY_SECRET
    and (.services.hub.image | test("^ghcr.io/porelli/portcullis-hub:"))
    and ([.services.hub.environment | keys[] | select(test("LLDAP") and test("PASS|SECRET|TOKEN|KEY"))] == [])
    and ([.services.hub.volumes[] | select(.target == "/run/portcullis/lldap" or .target == "/run/portcullis/invite") | .read_only] == [true, true])' >/dev/null \
  || { echo "FAIL: hub proxy-secret middleware / image / LLDAP + invite credentials only as read-only files"; exit 1; }
# Contract §1 / §8.1: Keycloak is Portcullis's image (KEYCLOAK_IMAGE,
# edge on main) and reads the Hub's signin-keycloak.json read-only.
# hub_data's readers over every profile (never wg: vpn.json is in vpn_doc).
echo "$CFG_ALL" | jq -e '(.services.keycloak.image | test("^ghcr.io/porelli/portcullis-keycloak:"))
    and ([.services.keycloak.volumes[] | select(.type == "volume") | "\(.source):\(.target):\(.read_only // false)"] == ["hub_data:/hub-data:true"])
    and ([.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume" and .source == "hub_data")] | length > 0) | .key] | sort
         == ["group-gate", "hub", "keycloak", "mcp-gate"])' >/dev/null \
  || { echo "FAIL: keycloak image (ghcr.io/porelli/portcullis-keycloak) / hub_data:/hub-data:ro / hub_data readers"; exit 1; }
# Hardening baseline on every core service (all profiles).
WEAK="$(echo "$CFG_ALL" | jq -r '.services | to_entries[]
    | select((.value.security_opt // [] | index("no-new-privileges:true") | not) or ((.value.cap_drop // []) != ["ALL"])
             or (.value.mem_limit == null) or (.value.pids_limit == null)) | .key')"
[ -z "$WEAK" ] || { echo "FAIL: services without no-new-privileges/cap_drop ALL/limits: $WEAK"; exit 1; }
# Keycloak trusts proxy headers only from Traefik's address on portcullis-auth.
echo "$CFG" | jq -e '(.services.keycloak.command | index("--proxy-trusted-addresses=172.31.251.2"))
    and .services.traefik.networks["portcullis-auth"].ipv4_address == "172.31.251.2"
    and ([.services | to_entries[] | select((.value.networks // {}) | has("portcullis-auth")) | .key] | sort == ["keycloak", "traefik"])' >/dev/null \
  || { echo "FAIL: portcullis-auth / proxy-trusted-addresses wiring"; exit 1; }
# Monitoring profile: internal network, nothing published, Grafana
# behind forward-auth + group-gate, header auth only from Traefik.
echo "$CFG_ALL" | jq -e --arg ip 172.31.250.2 '.networks.monitoring.internal == true
    and ([.services | to_entries[] | select((.value.profiles // []) | index("monitoring")) | select(.value.ports != null) | .key] == [])
    and ([.services.traefik.ports[].target] | sort == [80, 443])
    and (.services.traefik.environment.TRAEFIK_ENTRYPOINTS_METRICS_ADDRESS == ":8082")
    and (.services.keycloak.command | index("--metrics-enabled=true"))
    and (.services.grafana.labels["traefik.http.routers.grafana-metrics.middlewares"] | test("portcullis-auth@docker,portcullis-groups@docker"))
    and .services.grafana.environment.GF_AUTH_PROXY_WHITELIST == $ip
    and .services.grafana.environment.GF_AUTH_PROXY_HEADER_PROPERTY == "username"
    and .services.grafana.environment.GF_AUTH_BASIC_ENABLED == "false"' >/dev/null \
  || { echo "FAIL: monitoring profile wiring"; exit 1; }
grep -qx 'metrics=lldap_admin' group-gate/group-gate-map.conf || { echo "FAIL: metrics is not lldap_admin in the group-gate map"; exit 1; }
# Contract §5 / §5.1: attribute headers, people.<domain>, directory redirect.
grep -qx 'people=\*' group-gate/group-gate-map.conf || { echo "FAIL: people is not * (any signed-in user) in the group-gate map"; exit 1; }
echo "$CFG" | jq -e --arg d "${PORTCULLIS_DOMAIN:-ci.example.org}" '.services["group-gate"].labels as $g | .services["forward-auth"].labels as $f | .services.hub.labels as $h
    | ([$g["traefik.http.middlewares.portcullis-groups.forwardauth.authResponseHeadersRegex"],
        $g["traefik.http.middlewares.portcullis-public-guard.forwardauth.authResponseHeadersRegex"],
        $f["traefik.http.middlewares.portcullis-auth.forwardauth.authResponseHeadersRegex"],
        $f["traefik.http.middlewares.portcullis-auth-console.forwardauth.authResponseHeadersRegex"],
        .services["forward-auth-ext"].labels["traefik.http.middlewares.portcullis-auth-ext.forwardauth.authResponseHeadersRegex"]] | all(. == "^X-Forwarded-Attr-"))
    and .services.hub.environment.HUB_PEOPLE_ADDR == ":8889"
    and $h["traefik.http.routers.people.rule"] == "Host(`people.\($d)`)"
    and $h["traefik.http.routers.people.tls.options"] == "authaware@file"
    and $h["traefik.http.routers.people.middlewares"] == "rate-limit@file,client-cert-pem@file,portcullis-auth@docker,portcullis-groups@docker,hub-proxy-secret@docker,security-headers@file"
    and $h["traefik.http.services.\($h["traefik.http.routers.people.service"]).loadbalancer.server.port"] == "8889"
    and $h["traefik.http.services.\($h["traefik.http.routers.hub.service"]).loadbalancer.server.port"] == "8888"
    and .services.lldap.labels["traefik.http.middlewares.directory-redirect.redirectregex.replacement"] == "https://people.\($d)/"
    and .services["forward-auth"].environment.OAUTH2_PROXY_COOKIE_REFRESH == "1m"
    and (.services["forward-auth"].environment.OAUTH2_PROXY_COOKIE_EXPIRE // null) == null' >/dev/null \
  || { echo "FAIL: attribute-header regex / people router / directory redirect / forward-auth cookie refresh wiring"; exit 1; }
# Every HTTPS router names its Host: Traefik cannot pick TLS options
# (authaware / protected / public) for a host-less rule and answers
# 421 on it (that broke /oauth2/start on app hosts).
HOSTLESS="$(for files in "docker-compose.yml" "docker-compose.yml -f docker-compose.apps.yml" "docker-compose.test.yml"; do
    # shellcheck disable=SC2086
    docker compose -f $files --profile '*' config --format json \
      | jq -r '.services[].labels // {} | to_entries[] | select(.key | test("^traefik\\.http\\.routers\\.[^.]+\\.rule$")) | select(.value | test("Host\\(") | not) | "\(.key)=\(.value)"'
  done)"
[ -z "$HOSTLESS" ] || { echo "FAIL: routers without Host(): $HOSTLESS"; exit 1; }
# group-gate needs the username header from portcullis-auth and must
# pass it on; both forward-auth middlewares strip client copies.
echo "$CFG" | jq -e '[.services["forward-auth"].labels["traefik.http.middlewares.portcullis-auth.forwardauth.authResponseHeaders"],
       .services["group-gate"].labels["traefik.http.middlewares.portcullis-groups.forwardauth.authResponseHeaders"]]
    | all(split(",") | index("X-Auth-Request-Preferred-Username") and index("X-Forwarded-User") and index("X-Auth-Request-User"))' >/dev/null \
  || { echo "FAIL: identity headers missing from a forward-auth authResponseHeaders"; exit 1; }
# Sign-in part 3 (contract §5, §8): group-gate's impersonation headers are
# listed on all four forward-auth middlewares (Traefik deletes client
# copies), Keycloak's own impersonation is off, and the impersonation
# file / portal URL / max minutes reach their readers.
echo "$CFG" | jq -e --arg d "${PORTCULLIS_DOMAIN:-ci.example.org}" '
    def hdrs($svc; $mw): .services[$svc].labels["traefik.http.middlewares.\($mw).forwardauth.authResponseHeaders"] | split(",");
    ([hdrs("forward-auth"; "portcullis-auth"), hdrs("forward-auth"; "portcullis-auth-console"),
      hdrs("forward-auth-ext"; "portcullis-auth-ext"), hdrs("group-gate"; "portcullis-groups")]
     | all(index("X-Forwarded-Impersonator") and index("X-Forwarded-Impersonation")))
    and (.services.keycloak.command | index("--features-disabled=impersonation"))
    and ([.services.keycloak.command[] | select(test("^--features(-enabled)?=.*impersonation"))] == [])
    and ((.services.keycloak.environment // {}) | keys | map(select(test("^KC_FEATURES"))) == [])
    and .services.keycloak.environment.PORTCULLIS_PORTAL_URL == "https://\($d)/"
    and .services["group-gate"].environment.GATE_IMPERSONATION_FILE == "/hub-data/impersonation.json"
    and .services.hub.environment.HUB_IMPERSONATION_MAX_MINUTES == "30"' >/dev/null \
  || { echo "FAIL: impersonation wiring (the four middlewares' headers, --features-disabled=impersonation, PORTCULLIS_PORTAL_URL, GATE_IMPERSONATION_FILE, HUB_IMPERSONATION_MAX_MINUTES)"; exit 1; }
# Expired memberships: group-gate must be able to withhold the token
# headers, so portcullis-groups lists them (Traefik deletes unreturned ones).
echo "$CFG" | jq -e '.services["group-gate"].labels["traefik.http.middlewares.portcullis-groups.forwardauth.authResponseHeaders"]
    | split(",") | index("Authorization") and index("X-Forwarded-Access-Token")' >/dev/null \
  || { echo "FAIL: portcullis-groups does not list Authorization / X-Forwarded-Access-Token"; exit 1; }
# Token headers (contract §4 "How group-gate decides" reads amr from
# X-Forwarded-Access-Token only): every forwardAuth in front of
# group-gate lists it, so Traefik deletes a client's copy and only
# oauth2-proxy's reaches group-gate. portcullis-auth and -ext also
# strip Authorization; portcullis-auth-console deliberately keeps the
# client's Authorization (the Keycloak console's own bearer) but
# strips the access token.
echo "$CFG" | jq -e '
    def hdrs($svc; $mw): .services[$svc].labels["traefik.http.middlewares.\($mw).forwardauth.authResponseHeaders"] | split(",");
    (hdrs("forward-auth"; "portcullis-auth") | index("X-Forwarded-Access-Token") and index("Authorization"))
    and (hdrs("forward-auth-ext"; "portcullis-auth-ext") | index("X-Forwarded-Access-Token") and index("Authorization"))
    and (hdrs("forward-auth"; "portcullis-auth-console") | index("X-Forwarded-Access-Token") and (index("Authorization") | not))' >/dev/null \
  || { echo "FAIL: a forward-auth middleware lets a client's X-Forwarded-Access-Token / Authorization through"; exit 1; }
# Contract §5 "Extra-domain hosts": forward-auth-ext = forward-auth
# with a relative callback and a host-only __Host-portcullis_ext cookie;
# portcullis-auth-ext strips exactly what portcullis-auth strips.
echo "$CFG" | jq -e '.services["forward-auth"] as $m | .services["forward-auth-ext"] as $x
    | ($m.labels | with_entries(select(.key | startswith("traefik.http.middlewares.portcullis-auth.forwardauth.")) | .key |= sub("portcullis-auth"; "portcullis-auth-ext")) | del(.["traefik.http.middlewares.portcullis-auth-ext.forwardauth.address"])) as $want
    | $x.image == $m.image and $x.command == $m.command and $x.read_only == true
    and $x.labels["traefik.http.middlewares.portcullis-auth-ext.forwardauth.address"] == "http://forward-auth-ext:4180"
    and ($want | to_entries | all(. as $e | $x.labels[$e.key] == $e.value))
    and ([$x.labels | keys[] | select(test("^traefik\\.http\\.routers\\."))] == [])
    and $x.environment.OAUTH2_PROXY_REDIRECT_URL == "/oauth2/callback"
    and $x.environment.OAUTH2_PROXY_COOKIE_NAME == "__Host-portcullis_ext"
    and $x.environment.OAUTH2_PROXY_COOKIE_SECURE == "true" and $x.environment.OAUTH2_PROXY_COOKIE_PATH == "/"
    and ($x.environment.OAUTH2_PROXY_COOKIE_DOMAINS // null) == null
    and ($x.environment.OAUTH2_PROXY_WHITELIST_DOMAINS // null) == null
    and $x.environment.OAUTH2_PROXY_COOKIE_SECRET == $m.environment.OAUTH2_PROXY_COOKIE_SECRET
    and $x.environment.FORWARD_AUTH_CLIENT_SECRET == $m.environment.FORWARD_AUTH_CLIENT_SECRET
    and $x.environment.OAUTH2_PROXY_TRUSTED_PROXY_IPS == $m.environment.OAUTH2_PROXY_TRUSTED_PROXY_IPS
    and $x.environment.OAUTH2_PROXY_COOKIE_REFRESH == "1m"
    and ($x.environment.OAUTH2_PROXY_COOKIE_EXPIRE // null) == null' >/dev/null \
  || { echo "FAIL: forward-auth-ext / portcullis-auth-ext wiring (contract §5)"; exit 1; }
grep -qE '^\s+code_challenge_method: S256$' oauth2-proxy/alpha.yaml || { echo "FAIL: oauth2-proxy (both services) must send PKCE S256"; exit 1; }
if grep -nE '^\s*userIDClaim:' oauth2-proxy/alpha.yaml; then echo "FAIL: userIDClaim is an alias of emailClaim in oauth2-proxy v7"; exit 1; fi
# Contract §12.1 / §12.4: the domains service. portcullis-domains =
# {domains, hub}, portcullis-certs = {domains, traefik}, both internal;
# domains is never routed, reads its secrets as read-only files, and
# Traefik polls it over mTLS with paths only (no key material in env).
echo "$CFG" | jq -e '.services.domains as $d | .services.traefik as $t | .services.hub as $h
    | .networks["portcullis-domains"].internal == true and .networks["portcullis-certs"].internal == true
    and ([.services | to_entries[] | select((.value.networks // {}) | has("portcullis-domains")) | .key] | sort == ["domains", "hub"])
    and ([.services | to_entries[] | select((.value.networks // {}) | has("portcullis-certs")) | .key] | sort == ["domains", "traefik"])
    and ([$d.networks | keys[]] | sort == ["domains-egress", "portcullis-certs", "portcullis-domains"])
    and ([.services | to_entries[] | select((.value.networks // {}) | has("domains-egress")) | .key] == ["domains"])
    and ([$d.labels // {} | keys[] | select(startswith("traefik."))] == [])
    and $d.read_only == true and $d.user == "10004:10004" and $d.group_add == ["10001"]
    and ([$d.volumes[] | select(.type == "bind") | .read_only] | all)
    and ([$d.volumes[] | select(.type == "bind") | .target] | sort == ["/run/portcullis/domains/age.key", "/run/portcullis/domains/api-secret",
          "/run/portcullis/domains/certs-endpoint/ca.crt", "/run/portcullis/domains/certs-endpoint/server.crt", "/run/portcullis/domains/certs-endpoint/server.key"])
    and ([$d.volumes[] | select(.type == "volume") | .source] == ["domains_data"])
    and ([.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume") | .source] | index("domains_data")) | .key] == ["domains"])
    and ([$d.environment | keys[] | select(test("TOKEN|SECRET|KEY|PASSWORD"))] == [])
    and ($d.environment.DOMAINS_API_SUBNET | length > 0)
    and $d.environment.DOMAINS_API_SUBNET == .networks["portcullis-domains"].ipam.config[0].subnet
    and $t.environment.TRAEFIK_PROVIDERS_HTTP_ENDPOINT == "https://domains:8443/traefik/dynamic"
    and $t.environment.TRAEFIK_PROVIDERS_HTTP_POLLINTERVAL == "10s" and $t.environment.TRAEFIK_PROVIDERS_HTTP_POLLTIMEOUT == "5s"
    and $t.environment.TRAEFIK_PROVIDERS_HTTP_MAXRESPONSEBODYSIZE == "4194304"
    and ([$t.environment | keys[] | select(test("RESPONDINGTIMEOUTS"))] == [])
    and ([$t.environment.TRAEFIK_PROVIDERS_HTTP_TLS_CA, $t.environment.TRAEFIK_PROVIDERS_HTTP_TLS_CERT, $t.environment.TRAEFIK_PROVIDERS_HTTP_TLS_KEY] | all(startswith("/run/portcullis/domains-endpoint/")))
    and ([$t.environment | keys[] | select(startswith("TRAEFIK_PROVIDERS_HTTP_HEADERS"))] == [])
    and ([$t.volumes[] | select(.target | startswith("/run/portcullis/domains-endpoint/")) | .read_only] == [true, true, true])
    and ([$t.volumes[] | select(.source | test("certs-endpoint/(ca|server)\\.key$"))] == [])
    and $h.environment.HUB_DOMAINS_API_URL == "http://domains:8080"
    and $h.environment.HUB_DOMAINS_SECRET_FILE == "/run/portcullis/domains/api-secret"
    and ([$h.volumes[] | select(.target == "/run/portcullis/domains/api-secret") | .read_only] == [true])
    and ([.services | to_entries[] | select([.value.volumes[]? | .source // "" | select(test("secrets/domains/age\\.key$"))] | length > 0) | .key] == ["domains"])' >/dev/null \
  || { echo "FAIL: domains service wiring (contract §12.1 / §12.4)"; exit 1; }
# Contract §12.1: the one-shot dns tool (profile tools) — the domains
# image on domains-egress only, read-only, no volumes, no environment
# or env file (credentials reach it on stdin only).
echo "$CFG_ALL" | jq -e '.services["dns-tool"] as $t
    | $t.image == "portcullis-domains" and $t.profiles == ["tools"]
    and ([$t.networks | keys[]] == ["domains-egress"])
    and (($t.volumes // []) == []) and ($t.environment == null) and ($t.env_file == null)
    and $t.read_only == true and $t.user == "10004:10004"
    and $t.entrypoint == ["domains", "dns"] and ($t.ports // []) == []
    and $t.healthcheck.disable == true
    and ([$t.labels // {} | keys[] | select(startswith("traefik."))] == [])
    and ([.services | to_entries[] | select((.value.networks // {}) | has("domains-egress")) | .key] | sort == ["dns-tool", "domains"])' >/dev/null \
  || { echo "FAIL: dns-tool wiring (contract §12.1: egress only, no volumes / env, credentials on stdin)"; exit 1; }
# Contract §15 / §5 / §6: mcp-gate. Networks exactly portcullis +
# portcullis-proxy at the pinned address; group 10001 only (G74);
# hub_data read-only; mcp_gate_data written by the gate only and
# read-only in the Hub; age.key only in the gate; the three MCP
# routers have no forward-auth / groups / proxy secret, hub-mcp /
# people-mcp outrank hub / people and share their TLS options (G44);
# no router targets the Hub's :8890 (G36, every compose file).
echo "$CFG" | jq -e --arg d "${PORTCULLIS_DOMAIN:-ci.example.org}" '.services["mcp-gate"] as $g | .services.hub as $h | $g.labels as $l | $h.labels as $hl
    | def prio($r; $labels): ($labels["traefik.http.routers.\($r).priority"] // ($labels["traefik.http.routers.\($r).rule"] | length) | tonumber);
      def mounts($src): [.services | to_entries[] | select([.value.volumes[]? | .source // "" | select(test($src))] | length > 0) | .key] | sort;
    ([$g.networks | keys[]] | sort == ["portcullis-mcp", "portcullis-proxy"])
    and $g.networks["portcullis-proxy"].ipv4_address == "172.31.250.3"
    and .networks["portcullis-mcp"].name == "portcullis-mcp" and .networks["portcullis-mcp"].internal == true
    and .networks["portcullis-mcp"].ipam.config[0].subnet == "172.31.253.0/28"
    and ([.services | to_entries[] | select((.value.networks // {}) | has("portcullis-mcp")) | .key] | sort == ["hub", "keycloak", "mcp-gate"])
    and .networks["portcullis-mcp"].ipam.config[0].ip_range == "172.31.253.8/29"
    and .services.keycloak.networks["portcullis-mcp"].ipv4_address == "172.31.253.2"
    and .services.hub.networks["portcullis-mcp"].ipv4_address == "172.31.253.3"
    and ($g.networks["portcullis-mcp"].ipv4_address // null) == null
    and ($g.extra_hosts | sort) == ["hub=172.31.253.3", "keycloak=172.31.253.2"]
    and ([.services | to_entries[] | select(.value.networks["portcullis-proxy"].ipv4_address? != null) | "\(.key)=\(.value.networks["portcullis-proxy"].ipv4_address)"] | sort == ["mcp-gate=172.31.250.3", "traefik=172.31.250.2"])
    and $g.user == "10005:10005" and $g.group_add == ["10001"] and $g.read_only == true
    and ($g.tmpfs // [] | index("/tmp")) != null and ($g.ports // []) == []
    and (($g.environment | to_entries | map(select(.key | test("SECRET|KEY|PASSWORD|TOKEN"))) | all(.value | startswith("/run/portcullis/mcp-gate/"))))
    and $g.environment.MCP_GATE_HUB_URL == "http://hub:8890"
    and $g.environment.MCP_GATE_JWKS_URL == "http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs"
    and ([$g.volumes[] | select(.type == "volume") | "\(.source):\(.target):\(.read_only // false)"] | sort == ["hub_data:/hub-data:true", "mcp_gate_data:/data:false"])
    and ([$g.volumes[] | select(.type == "bind") | "\(.target):\(.read_only // false)"] | sort == ["/run/portcullis/mcp-gate/age.key:true", "/run/portcullis/mcp-gate/hub-secret:true"])
    and (mounts("secrets/mcp-gate/age\\.key$") == ["mcp-gate"])
    and (mounts("secrets/mcp-gate/age\\.pub$") == ["hub"])
    and (mounts("secrets/mcp-gate/hub-secret$") == ["hub", "mcp-gate"])
    and ([.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume" and .source == "mcp_gate_data")] | length > 0) | .key] | sort == ["hub", "mcp-gate"])
    and ([$h.volumes[] | select(.source == "mcp_gate_data") | "\(.target):\(.read_only // false)"] == ["/mcp-gate-data:true"])
    and ([$h.volumes[] | select(.target | startswith("/run/portcullis/mcp-gate/")) | "\(.target):\(.read_only // false)"] | sort == ["/run/portcullis/mcp-gate/age.pub:true", "/run/portcullis/mcp-gate/hub-secret:true"])
    and $h.environment.HUB_MCP_ADDR == ":8890" and $h.environment.HUB_MCP_GATE_DATA_DIR == "/mcp-gate-data"
    and $h.environment.HUB_MCP_GATE_SECRET_FILE == "/run/portcullis/mcp-gate/hub-secret"
    and $h.environment.HUB_MCP_GATE_RECIPIENT_FILE == "/run/portcullis/mcp-gate/age.pub"
    and $l["traefik.enable"] == "true" and $l["traefik.docker.network"] == "portcullis-proxy"
    and $l["traefik.http.services.mcp-gate.loadbalancer.server.port"] == "8080"
    and ([$l | keys[] | capture("^traefik\\.http\\.routers\\.(?<r>[^.]+)\\.rule$").r] | sort == ["hub-mcp", "mcp", "people-mcp"])
    and $l["traefik.http.routers.mcp.rule"] == "Host(`mcp.\($d)`)"
    and $l["traefik.http.routers.hub-mcp.rule"] == "Host(`hub.\($d)`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))"
    and $l["traefik.http.routers.people-mcp.rule"] == "Host(`people.\($d)`) && (Path(`/mcp`) || Path(`/.well-known/oauth-protected-resource/mcp`))"
    and (["mcp", "hub-mcp", "people-mcp"] | all(. as $r
          | $l["traefik.http.routers.\($r).middlewares"] == "rate-limit@file,security-headers@file"
          and $l["traefik.http.routers.\($r).service"] == "mcp-gate"
          and $l["traefik.http.routers.\($r).entrypoints"] == "websecure,vpnsecure"))
    and ([$l | to_entries[] | select(.key | test("\\.middlewares$")) | .value | select(test("portcullis-auth|portcullis-groups|proxy-secret"))] == [])
    and $l["traefik.http.routers.mcp.tls.options"] == "authaware@file"
    and $l["traefik.http.routers.hub-mcp.tls.options"] == $hl["traefik.http.routers.hub.tls.options"]
    and $l["traefik.http.routers.people-mcp.tls.options"] == $hl["traefik.http.routers.people.tls.options"]
    and prio("hub-mcp"; $l) > prio("hub"; $hl) and prio("people-mcp"; $l) > prio("people"; $hl)' >/dev/null \
  || { echo "FAIL: mcp-gate wiring (contract §15 / §5, G36 G44 G74)"; exit 1; }
# Session store (scripts/lib/sessions.sh; oauth2-proxy #3486): Valkey
# pinned, hardened, read-only, non-root, no ports / env / routers,
# memory-only on a tmpfs /data; its config only in it, read-only;
# portcullis-sessions internal with exactly sessions + the two
# oauth2-proxies (like portcullis-mcp's members); each proxy its own
# store user and generated password (never shared with any other
# service), waits for the store healthy; the cookie name / domain
# unchanged.
echo "$CFG" | jq -e '.services.sessions as $s | .services["forward-auth"] as $m | .services["forward-auth-ext"] as $x
    | def members($n): [.services | to_entries[] | select((.value.networks // {}) | has($n)) | .key] | sort;
    def mounts($src): [.services | to_entries[] | select([.value.volumes[]? | .source // "" | select(test($src))] | length > 0) | .key] | sort;
    ($s.image | test("^docker.io/valkey/valkey:[0-9]+\\.[0-9]+\\.[0-9]+(-alpine[0-9.]*)?@sha256:[0-9a-f]{64}$"))
    and $s.user == "999:1000" and $s.read_only == true
    and $s.cap_drop == ["ALL"] and ($s.security_opt | index("no-new-privileges:true")) != null
    and $s.mem_limit != null and $s.pids_limit != null
    and ($s.tmpfs // [] | index("/data")) != null
    and ($s.ports // []) == [] and ($s.expose // []) == []
    and ($s.environment // {}) == {}
    and ([$s.labels // {} | keys[] | select(startswith("traefik."))] == [])
    and $s.command == ["valkey-server", "/etc/valkey/valkey.conf"]
    and ([$s.volumes[] | "\(.type):\(.source | sub("^.*/secrets/"; "secrets/")):\(.target):\(.read_only // false)"]
         == ["bind:secrets/sessions/valkey.conf:/etc/valkey/valkey.conf:true"])
    and (mounts("secrets/sessions/") == ["sessions"])
    and ($s.healthcheck.test | join(" ") | test("NOAUTH"))
    and ([$s.networks | keys[]] == ["portcullis-sessions"])
    and .networks["portcullis-sessions"].internal == true
    and (members("portcullis-sessions") == ["forward-auth", "forward-auth-ext", "sessions"])
    and ([$m.networks | keys[]] | sort == ["portcullis", "portcullis-sessions"])
    and ([$x.networks | keys[]] | sort == ["portcullis", "portcullis-sessions"])
    and ([$m, $x] | all(.depends_on.sessions.condition == "service_healthy"
         and .environment.OAUTH2_PROXY_SESSION_STORE_TYPE == "redis"
         and .environment.OAUTH2_PROXY_REDIS_CONNECTION_URL == "redis://sessions:6379"
         and (.environment.OAUTH2_PROXY_REDIS_PASSWORD | test("^[A-Za-z0-9]{40}$"))))
    and $m.environment.OAUTH2_PROXY_REDIS_USERNAME == "forward-auth"
    and $x.environment.OAUTH2_PROXY_REDIS_USERNAME == "forward-auth-ext"
    and $m.environment.OAUTH2_PROXY_REDIS_PASSWORD != $x.environment.OAUTH2_PROXY_REDIS_PASSWORD
    and ($m.environment.OAUTH2_PROXY_COOKIE_NAME // null) == null
    and $m.environment.OAUTH2_PROXY_COOKIE_DOMAINS == ".\($m.environment.PORTCULLIS_DOMAIN)"
    and ([.services | to_entries[] | select(.key != "forward-auth" and .key != "forward-auth-ext") | .value.environment // {} | to_entries[]
         | select(.value == $m.environment.OAUTH2_PROXY_REDIS_PASSWORD or .value == $x.environment.OAUTH2_PROXY_REDIS_PASSWORD)] == [])' >/dev/null \
  || { echo "FAIL: session store wiring (sessions, portcullis-sessions, the oauth2-proxies' redis settings)"; exit 1; }
# Contract §4 "Opened log" / §8.2 (sign-in part 2): group_gate_data is
# mounted by exactly group-gate (rw at /data, uid 10003 + group 10001
# only) and the Hub (rw at /group-gate-data, to prune day files);
# group-gate reads both CA files read-only and both CAs' CRL lists;
# no enroll / enroll-self router and no self-service middleware —
# enroll-invite is the only router on enroll.<domain>.
echo "$CFG" | jq -e --arg d "${PORTCULLIS_DOMAIN:-ci.example.org}" '.services["group-gate"] as $g | .services.hub as $h
    | ([.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume" and .source == "group_gate_data")] | length > 0) | .key] | sort == ["group-gate", "hub"])
    and ([$g.volumes[] | select(.source == "group_gate_data") | "\(.target):\(.read_only // false)"] == ["/data:false"])
    and ([$h.volumes[] | select(.source == "group_gate_data") | "\(.target):\(.read_only // false)"] == ["/group-gate-data:false"])
    and $g.user == "10003:10003" and $g.group_add == ["10001", "10007"]
    and $g.environment.GATE_OPENED_DIR == "/data/opened" and $h.environment.HUB_GROUP_GATE_DATA_DIR == "/group-gate-data"
    and $g.environment.GATE_YUBIKEY_CA_FILE == "/etc/group-gate/ca/yubikey-ca.crt"
    and $g.environment.GATE_BROWSER_CA_FILE == "/etc/group-gate/ca/browser-ca.crt"
    and ([$g.volumes[] | select(.target | startswith("/etc/group-gate/ca/")) | "\(.source | sub("^.*/certs/"; "certs/")):\(.target):\(.read_only // false)"] | sort
         == ["certs/browser-ca.crt:/etc/group-gate/ca/browser-ca.crt:true", "certs/yubikey-ca.crt:/etc/group-gate/ca/yubikey-ca.crt:true"])
    and $g.environment.GATE_CRL_URLS == "http://vault:8200/v1/pki_int/crl http://vault:8200/v1/pki_file/crl"
    and $g.environment.GATE_DELTA_CRL_URLS == "http://vault:8200/v1/pki_int/crl/delta http://vault:8200/v1/pki_file/crl/delta"
    and ($g.environment | has("GATE_CRL_URL") or has("GATE_DELTA_CRL_URL") | not)
    and $h.environment.HUB_CLIENT_CERT_TTL == "720h" and $h.environment.HUB_CERT_EXPIRY_WARN_DAYS == "7"
    and .services.keycloak.environment.PORTCULLIS_SIGNIN_URL == "https://people.\($d)/signin"
    and ([.services[].labels // {} | keys[] | select(test("^traefik\\.http\\.middlewares\\.[^.]*-self\\."))] == [])
    and ([.services[].labels // {} | to_entries[] | select(.key | test("^traefik\\.http\\.routers\\.[^.]+\\.rule$")) | select(.value | test("enroll\\.")) | .key]
         == ["traefik.http.routers.enroll-invite.rule"])
    and .services.enroll.labels["traefik.http.routers.enroll-invite.rule"] == "Host(`enroll.\($d)`) && PathPrefix(`/invite/`)"' >/dev/null \
  || { echo "FAIL: group_gate_data / group-gate CA files + CRL lists / Hub sign-in env / enroll.<domain> routers (contract §4, §5, §8.2)"; exit 1; }
grep -qx 'mcp=\*' group-gate/group-gate-map.conf || { echo "FAIL: mcp is not * in the group-gate map (core host, contract §4)"; exit 1; }
PORT8890="$(for files in "docker-compose.yml" "docker-compose.yml -f docker-compose.apps.yml" "docker-compose.test.yml"; do
    # shellcheck disable=SC2086
    docker compose -f $files --profile '*' config --format json \
      | jq -r '.services[].labels // {} | to_entries[] | select(.key | test("^traefik\\.http\\.services\\.[^.]+\\.loadbalancer\\.server\\.port$")) | select(.value == "8890") | .key'
  done)"
[ -z "$PORT8890" ] || { echo "FAIL: a Traefik service targets the Hub's MCP listener :8890: $PORT8890"; exit 1; }
# ... nor does the file provider (a server URL, a port, hub:8890).
if grep -rnE '(^|[^0-9])8890([^0-9]|$)' traefik/dynamic/; then
  echo "FAIL: traefik/dynamic references the Hub's MCP listener :8890"; exit 1
fi
# Every core service name is in the CLI's DNS-shadowing guard (network.sh).
diff <(bash -c 'source scripts/lib/common.sh; source scripts/lib/network.sh; printf "%s\n" $CORE_SERVICE_NAMES' | sort) \
     <(docker compose -f docker-compose.yml --profile '*' config --services | sort) \
  || { echo "FAIL: CORE_SERVICE_NAMES (scripts/lib/network.sh) differs from docker-compose.yml's services"; exit 1; }
diff <(bash -c 'source scripts/lib/common.sh; source scripts/lib/network.sh; printf "%s\n" $CORE_PROXY_SERVICES' | sort) \
     <(docker compose -f docker-compose.yml --profile '*' config --format json | jq -r '.services | to_entries[] | select((.value.networks // {}) | has("portcullis-proxy")) | .key' | sort) \
  || { echo "FAIL: CORE_PROXY_SERVICES (scripts/lib/network.sh) differs from the core services on portcullis-proxy"; exit 1; }
# oauth2-proxy never accepts bearer tokens on browser routes (contract §5).
if grep -nE '^\s*skipJwtBearerTokens:\s*true' oauth2-proxy/alpha.yaml \
   || grep -rniE 'skip[-_]jwt[-_]bearer[-_]tokens' docker-compose*.yml oauth2-proxy/; then
  echo "FAIL: oauth2-proxy must not accept JWT bearer tokens"; exit 1
fi
# VPN (contract §16): over every profile, on Docker and Podman, with
# and without the SELinux overlay. wg is userspace only and least
# privilege: no capability, device, sysctl, privilege, network_mode
# or engine socket, no hub_data, only group 10007 (vpn_doc, shared
# with the Hub and group-gate alone). Traefik trusts PROXY on
# vpnsecure from wg's address on portcullis-vpn-edge only (exactly
# wg + Traefik) and never forwarded headers; Traefik isn't on
# portcullis-vpn (core: wg alone; gateways join per instance through
# the Hub's overrides); metrics on portcullis-metrics-wg (wg +
# Prometheus); wg_data is wg's, read-only in the Hub; every core
# router is on one of the three entrypoint classes;
# people-vpn-enrol = people's chain on /vpn/.
vpn_rule() {  # <config json>
  printf '%s' "$1" | jq -e '.services.wg as $w | .services.traefik as $t | .services.hub as $h | .services["group-gate"] as $g
      | def lab: .labels | if . == null then {} elif type == "object" then . else error("labels: not a map") end;
        def nets: .networks | if . == null then {} elif type == "object" then . else error("networks: not a map") end;
        def gids: .group_add | if . == null then [] elif type == "array" then . else error("group_add: not a list") end;
        def members($n): [.services | to_entries[] | select(.value | nets | has($n)) | .key] | sort;
        def mounts($src): [.services | to_entries[] | select([.value.volumes[]? | select(.type == "volume" and .source == $src)] | length > 0) | .key] | sort;
        def vmount($svc; $src): [.services[$svc].volumes[]? | select(.type == "volume" and .source == $src) | "\(.target):\(.read_only // false)"];
      ($w.cap_add // []) == [] and ($w.devices // []) == [] and ($w.sysctls // {}) == {}
      and ($w.privileged // false) == false and ($w.network_mode // null) == null
      and ($w.cap_drop == ["ALL"]) and ($w.security_opt | index("no-new-privileges:true")) != null
      and ([$w.volumes[] | select(.target == "/var/run/docker.sock" or (.source // "" | test("docker\\.sock$|podman\\.sock$")))] == [])
      and $w.user == "10006:10006" and $w.group_add == ["10007"] and $w.read_only == true and $w.profiles == ["wg"]
      and $w.image == "portcullis-wg"
      and ([$w.ports[] | "\(.target)/\(.protocol)"] == ["51820/udp"])
      and ([$w.volumes[] | "\(.type):\(.source | sub("^.*/secrets/"; "secrets/")):\(.target):\(.read_only // false)"] | sort
           == ["bind:secrets/wg/people.key:/run/portcullis/wg/people.key:true", "volume:vpn_doc:/vpn-doc:true", "volume:wg_data:/data:false"])
      and ([$w.networks | keys[]] | sort == ["portcullis-metrics-wg", "portcullis-vpn", "portcullis-vpn-edge", "wg-egress"])
      and $w.networks["portcullis-metrics-wg"].aliases == ["wg-metrics"]
      and $w.environment.WG_PEOPLE == "off" and $w.environment.WG_MODE == "apps"
      and $w.environment.WG_VPN_FILE == "/vpn-doc/vpn.json"
      and $w.environment.WG_VPN_ADDR == $w.networks["portcullis-vpn"].ipv4_address
      and $w.environment.WG_EDGE_ADDR == $w.networks["portcullis-vpn-edge"].ipv4_address
      and $w.environment.WG_TRAEFIK == "\($t.networks["portcullis-vpn-edge"].ipv4_address):8443"
      and $w.environment.WG_METRICS == "wg-metrics:9100"
      and $w.environment.WG_EDGE_MAX_PER_PROVIDER == "1024" and $w.environment.WG_EDGE_MAX_PER_USER == "128"
      and $w.environment.WG_EDGE_MAX_PER_CLIENT == "32" and $w.environment.WG_EDGE_PRESSURE_PERCENT == "90"
      and $w.environment.WG_EDGE_PRESSURE_IDLE == "2m"
      and ([$w.environment | keys[] | select(test("KEY$|SECRET|TOKEN|PASSWORD"))] == ["WG_PEOPLE_KEY"])
      and $w.environment.WG_PEOPLE_KEY == "/run/portcullis/wg/people.key"
      and $t.environment.TRAEFIK_ENTRYPOINTS_VPNSECURE_PROXYPROTOCOL_TRUSTEDIPS == "\($w.networks["portcullis-vpn-edge"].ipv4_address)/32"
      and $t.environment.TRAEFIK_ENTRYPOINTS_VPNSECURE_ADDRESS == "\($t.networks["portcullis-vpn-edge"].ipv4_address):8443"
      and $t.environment.TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_ALIASHEADERSSTRATEGY == "delete"
      and $t.environment.TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_MIDDLEWARES == "strip-client-forwarded@file"
      and $t.environment.TRAEFIK_ENTRYPOINTS_WEBSECURE_HTTP_MIDDLEWARES == "strip-client-forwarded@file"
      and ([$t.environment | keys[] | select(test("^TRAEFIK_ENTRYPOINTS_[A-Z]+_(FORWARDEDHEADERS_|PROXYPROTOCOL_INSECURE)"))] == [])
      and ([$t.environment | keys[] | select(startswith("TRAEFIK_ENTRYPOINTS_VPNSECURE_"))] | sort
           == ["TRAEFIK_ENTRYPOINTS_VPNSECURE_ADDRESS", "TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_ALIASHEADERSSTRATEGY",
               "TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_MIDDLEWARES", "TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_TLS_CERTRESOLVER", "TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_TLS_DOMAINS_0_MAIN",
               "TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_TLS_DOMAINS_0_SANS", "TRAEFIK_ENTRYPOINTS_VPNSECURE_PROXYPROTOCOL_TRUSTEDIPS"])
      and $t.environment.TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_TLS_DOMAINS_0_MAIN == $t.environment.TRAEFIK_ENTRYPOINTS_WEBSECURE_HTTP_TLS_DOMAINS_0_MAIN
      and $t.environment.TRAEFIK_ENTRYPOINTS_VPNSECURE_HTTP_TLS_DOMAINS_0_SANS == $t.environment.TRAEFIK_ENTRYPOINTS_WEBSECURE_HTTP_TLS_DOMAINS_0_SANS
      and ([$t.ports[].target] | sort == [80, 443])
      and ($t.networks | has("portcullis-vpn") | not)
      and .networks["portcullis-vpn"].name == "portcullis-vpn" and .networks["portcullis-vpn"].internal == true
      and (members("portcullis-vpn") == ["wg"])
      and .networks["portcullis-vpn-edge"].name == "portcullis-vpn-edge" and .networks["portcullis-vpn-edge"].internal == true
      and (members("portcullis-vpn-edge") == ["traefik", "wg"])
      and ([.services | to_entries[] | select(.value.networks["portcullis-vpn-edge"].ipv4_address? != null) | .key] | sort == ["traefik", "wg"])
      and $t.networks["portcullis-vpn-edge"].ipv4_address != $w.networks["portcullis-vpn-edge"].ipv4_address
      and .networks["portcullis-metrics-wg"].internal == true
      and (members("wg-egress") == ["wg"])
      and (mounts("wg_data") == ["hub", "wg"]) and vmount("hub"; "wg_data") == ["/wg-data:true"]
      and (mounts("vpn_doc") == ["group-gate", "hub", "wg"])
      and vmount("hub"; "vpn_doc") == ["/vpn-doc:false"] and vmount("wg"; "vpn_doc") == ["/vpn-doc:true"]
      and vmount("group-gate"; "vpn_doc") == ["/vpn-doc:true"]
      and ($h | gids | any(.[]; . == "10007")) and ($g | gids | sort) == ["10001", "10007"]
      and ([.services | to_entries[] | select(.value | gids | any(.[]; . == "10007")) | .key] | sort == ["group-gate", "hub", "wg"])
      and $h.environment.HUB_VPN_STATUS_FILE == "/wg-data/status.json" and $h.environment.HUB_VPN_DOC_DIR == "/vpn-doc" and $h.environment.HUB_VPN_DOC_GID == "10007"
      and ([$h.networks | keys[]] | (index("portcullis-vpn") or index("portcullis-vpn-edge")) | not)
      and ($h.labels as $l
           | $l["traefik.http.routers.people-vpn-enrol.rule"] == ($l["traefik.http.routers.people.rule"] + " && PathPrefix(`/vpn/`)")
           and $l["traefik.http.routers.people-vpn-enrol.middlewares"] == $l["traefik.http.routers.people.middlewares"]
           and $l["traefik.http.routers.people-vpn-enrol.service"] == $l["traefik.http.routers.people.service"]
           and $l["traefik.http.routers.people-vpn-enrol.tls.options"] == $l["traefik.http.routers.people.tls.options"]
           and ($l["traefik.http.routers.people-vpn-enrol.priority"] | tonumber) > ($l["traefik.http.routers.people.rule"] | length))
      and $g.labels["traefik.http.middlewares.vpn-required-path.replacepath.path"] == "/vpn-required"
      and $g.environment.GATE_VPN_FILE == "/vpn-doc/vpn.json"
      and $g.environment.GATE_VPN_MODE == "apps" and $g.environment.GATE_VPN_PUBLIC_ENROL == "true"
      and $g.environment.GATE_CORE_SUBNETS == $w.environment.WG_CORE_SUBNETS
      and ($g.environment.GATE_CORE_SUBNETS | split(" ") | map(select(. != "")) | sort) == ([.networks[] | .ipam.config[0].subnet? // empty] | sort)
      and $g.labels["traefik.http.middlewares.portcullis-groups-vpn.forwardauth.address"] == "http://group-gate:8080/auth/vpn"
      and $g.labels["traefik.http.middlewares.portcullis-public-guard-vpn.forwardauth.address"] == "http://group-gate:8080/public-guard/vpn"
      and $g.labels["traefik.http.middlewares.portal-vpn-path.replacepath.path"] == "/portal/vpn"
      and $g.labels["traefik.http.middlewares.portcullis-groups-vpn.forwardauth.authResponseHeaders"] == $g.labels["traefik.http.middlewares.portcullis-groups.forwardauth.authResponseHeaders"]
      and $t.environment.TRAEFIK_ENTRYPOINTS_PARKED_ADDRESS == "127.0.0.1:8441"
      and ([.services[] | lab | to_entries[] | select(.key | test("^traefik\\.http\\.routers\\.[^.]+\\.entrypoints$")) | .value] | unique == ["vpnsecure", "websecure", "websecure,vpnsecure"])
      # Parenthesised: jq 1.8 binds `A and B as $x | C` as `(A and B) as $x`
      # (1.7: `A and (B as $x | C)`). Every gate router must be on its class:
      # VPN middlewares only on vpnsecure, the normal ones never on it; both
      # kinds must be present, so the check never passes on an empty set.
      and (([.services[] | lab] | add) as $L
           | [$L | to_entries[] | select(.key | test("^traefik\\.http\\.routers\\.[^.]+\\.middlewares$"))
              | (.key | sub("\\.middlewares$"; ".entrypoints")) as $ek
              | (.value | if type == "string" then split(",") else error("\(.): middlewares not a string") end) as $m
              | def ep: $L[$ek] | if type == "string" then split(",") else error("\($ek): no entrypoints") end;
                if any($m[]; . == "portcullis-groups-vpn@docker" or . == "portal-vpn-path@docker" or . == "portcullis-public-guard-vpn@docker")
                then {vpn: true, ok: (ep == ["vpnsecure"])}
                elif any($m[]; . == "portcullis-groups@docker" or . == "portal-path@docker" or . == "portcullis-public-guard@docker")
                then {vpn: false, ok: (any(ep[]; . == "vpnsecure") | not)}
                else empty end]
           | (map(select(.vpn)) | length) > 0 and (map(select(.vpn | not)) | length) > 0 and all(.[]; .ok))' >/dev/null
}
# With the monitoring profile, Prometheus is wg's metrics network's only other member.
echo "$CFG_ALL" | jq -e '[.services | to_entries[] | select((.value.networks // {}) | has("portcullis-metrics-wg")) | .key] | sort == ["prometheus", "wg"]' >/dev/null \
  || { echo "FAIL: portcullis-metrics-wg must hold exactly prometheus and wg"; exit 1; }
# shellcheck disable=SC2034  # read through ${!c} below
CFG_PODMAN_ALL="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml -f docker-compose.podman.yml --profile '*' config --format json)"
# shellcheck disable=SC2034  # read through ${!c} below
OV_PODMAN_ALL="$(CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET="$PODMAN_SOCK" docker compose -f docker-compose.yml -f docker-compose.podman.yml -f docker-compose.podman-selinux.yml --profile '*' config --format json)"
for c in CFG_ALL CFG_PODMAN_ALL OV_ALL OV_PODMAN_ALL; do
  vpn_rule "${!c}" || { echo "FAIL: VPN wiring (wg userspace only and least privilege, vpnsecure PROXY trust on portcullis-vpn-edge, network members, vpn_doc / wg_data, people-vpn-enrol, entrypoint classes) in $c"; exit 1; }
done
echo "$CFG_PODMAN_ALL" | jq -e '.services.wg.restart == "always"' >/dev/null || { echo "FAIL: docker-compose.podman.yml must name wg"; exit 1; }
# group-gate's VPN mode follows .env (I3 ruling: authoritative for the
# core classes, so vpn mode apps is a break-glass with the Hub down).
PORTCULLIS_VPN_MODE=server PORTCULLIS_VPN_PUBLIC_ENROL=false docker compose -f docker-compose.yml config --format json \
  | jq -e '.services["group-gate"].environment | .GATE_VPN_MODE == "server" and .GATE_VPN_PUBLIC_ENROL == "false"' >/dev/null \
  || { echo "FAIL: group-gate's GATE_VPN_MODE / GATE_VPN_PUBLIC_ENROL don't follow PORTCULLIS_VPN_MODE / _PUBLIC_ENROL"; exit 1; }
# The Hub's reserved list (core.env PORTCULLIS_VPN_RESERVED_RANGES,
# vpn_reserved_ranges) is exactly what wg and group-gate refuse: Docker's
# default address pools 172.16.0.0/12 and 192.168.0.0/16, the link subnet
# + their *_CORE_SUBNETS (under podman ending in Podman's pools,
# PORTCULLIS_VPN_RUNTIME_POOLS: runtime_export, test_shell_libs), with the
# defaults and with every subnet moved. Compared word by word.
for pools in "" "10.88.0.0/16 10.89.0.0/16"; do
  for over in "" "PORTCULLIS_PROXY_SUBNET=10.80.0.0/24 PORTCULLIS_PROXY_IP_RANGE=10.80.0.128/25 PORTCULLIS_TRAEFIK_IP=10.80.0.2 PORTCULLIS_AUTH_SUBNET=10.81.0.0/28 PORTCULLIS_DOMAINS_SUBNET=10.82.0.0/28 PORTCULLIS_MCP_SUBNET=10.83.0.0/28 PORTCULLIS_VPN_NET=10.84.0.0/26 PORTCULLIS_VPN_EDGE_SUBNET=10.85.0.0/28"; do
    # shellcheck disable=SC2086  # VAR=value words
    HUBLIST="$(env $over PORTCULLIS_VPN_RUNTIME_POOLS="$pools" bash -c 'source scripts/lib/common.sh; source scripts/lib/network.sh; vpn_reserved_ranges')"
    # shellcheck disable=SC2086
    READERS="$(env $over PORTCULLIS_VPN_RUNTIME_POOLS="$pools" docker compose -f docker-compose.yml --profile '*' config --format json \
        | jq -r '.services["group-gate"].environment.GATE_CORE_SUBNETS as $g | .services.wg.environment.WG_CORE_SUBNETS as $w
                 | if $g == $w then "172.16.0.0/12 192.168.0.0/16 10.214.0.0/24 " + ($g | split(" ") | map(select(. != "")) | join(" ")) else "MISMATCH" end')"
    [ "$HUBLIST" = "$READERS" ] || { echo "FAIL: core.env PORTCULLIS_VPN_RESERVED_RANGES ($HUBLIST) != what wg / group-gate refuse ($READERS)"; exit 1; }
    case " $READERS " in *" 10.88.0.0/16 10.89.0.0/16 "*) [ -n "$pools" ] ;; *) [ -z "$pools" ] ;; esac \
      || { echo "FAIL: Podman's pools reserved ($READERS) without PORTCULLIS_VPN_RUNTIME_POOLS, or missing with it"; exit 1; }
  done
done
# shellcheck disable=SC2016  # expanded by the inner bash
bash -c 'source scripts/lib/common.sh; source scripts/lib/network.sh; env_load; export PORTCULLIS_ROOT="$(mktemp -d)"; hub_env_write
         grep -qx "PORTCULLIS_VPN_RESERVED_RANGES=$(vpn_reserved_ranges)" "$PORTCULLIS_ROOT/secrets/hub/core.env"' \
  || { echo "FAIL: hub_env_write does not give the Hub PORTCULLIS_VPN_RESERVED_RANGES"; exit 1; }
# Each router's entrypoints is exactly its class variable: with the
# three set to distinct values, every router shows its own class.
EP_ROUTERS="$(PORTCULLIS_EP_CORE=x-core PORTCULLIS_EP_ADMIN=x-admin PORTCULLIS_EP_ENROL=x-enrol PORTCULLIS_WEB_CORE=w-core PORTCULLIS_WEB_ADMIN=w-admin PORTCULLIS_WEB_ENROL=w-enrol docker compose -f docker-compose.yml --profile '*' config --format json \
    | jq -r '[.services[].labels // {} | to_entries[] | select(.key | test("^traefik\\.http\\.routers\\.[^.]+\\.entrypoints$")) | "\(.key | split(".")[3])=\(.value)"] | sort | join(" ")')"
WANT_EP="core-vpn-required=websecure dashboard-vpn=vpnsecure dashboard=w-admin enroll-invite=x-enrol grafana-metrics-vpn=vpnsecure grafana-metrics=w-admin hub-mcp=x-admin hub-vpn=vpnsecure hub=w-admin keycloak-admin-vpn-required=websecure keycloak-admin-vpn=vpnsecure keycloak-admin=w-admin keycloak-resources=x-enrol keycloak=x-enrol lldap=x-admin mcp=x-admin oauth2-callback=x-enrol people-mcp=x-admin people-vpn-enrol-vpn=vpnsecure people-vpn-enrol=w-enrol people-vpn=vpnsecure people=w-core portal-vpn=vpnsecure portal=w-core"
[ "$EP_ROUTERS" = "$WANT_EP" ] || { echo "FAIL: core router entrypoint classes: got $EP_ROUTERS, want $WANT_EP"; exit 1; }
echo "PASS: socket proxies, hub proxy secret, hardening, auth network, monitoring wiring, domains service, mcp-gate, session store"
