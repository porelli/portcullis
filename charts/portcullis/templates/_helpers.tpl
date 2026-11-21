{{/*
Shared helpers. Every core service is described by a small spec (the
per-service files: a YAML document built with these helpers' values) and
rendered by "portcullis.deployment": one Deployment (replicas 1, Recreate),
its pod hardened the same way for every service (restricted PSA, drop ALL,
no escalation, RuntimeDefault seccomp, read-only root unless compose says
otherwise, memory limit = request = compose mem_limit, probes = compose
healthcheck), labelled with its component and its compose networks.
*/}}

{{- define "portcullis.ns" -}}{{ .Release.Namespace }}{{- end }}

{{/* portcullis.image <root> <service> — images.<service>, by digest only. */}}
{{- define "portcullis.image" -}}
{{- $root := index . 0 -}}{{- $svc := index . 1 -}}
{{- $ref := required (printf "images.%s is required (./portcullis resolves every image to a digest)" $svc) (index $root.Values.images $svc) -}}
{{- if not (regexMatch "^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$" $ref) -}}
{{- fail (printf "images.%s must be a fully qualified name@sha256:<digest>, got %q" $svc $ref) -}}
{{- end -}}
{{- $ref -}}
{{- end }}

{{/* portcullis.domain — the main domain (required). */}}
{{- define "portcullis.domain" -}}{{ required "domain is required (PORTCULLIS_DOMAIN)" .Values.domain }}{{- end }}

{{/* portcullis.confighash <root> <list of object names> — sha256 over their hashes. */}}
{{- define "portcullis.confighash" -}}
{{- $root := index . 0 -}}
{{- $parts := list -}}
{{- range (index . 1) -}}{{- $parts = append $parts (printf "%s=%s" . (index $root.Values.hashes . | default "")) -}}{{- end -}}
{{- $parts | join "," | sha256sum -}}
{{- end }}

{{/*
portcullis.probes <healthcheck dict> — compose healthcheck → probes (Task 4's
mapping, K17): readiness = the exec, periodSeconds = interval, timeoutSeconds
= timeout, failureThreshold = retries; liveness the same with failureThreshold
× 2; start_period → a startupProbe (periodSeconds = interval,
failureThreshold = ceil(start_period / interval) + retries). Never
initialDelaySeconds. A CMD-SHELL test runs as ["sh", "-c", <string>].
*/}}
{{- define "portcullis.probes" -}}
{{- $h := . -}}
{{- $cmd := $h.test -}}
{{- $iv := int $h.interval -}}{{- $to := int $h.timeout -}}{{- $re := int $h.retries -}}
readinessProbe:
  exec:
    command: {{ toJson $cmd }}
  periodSeconds: {{ $iv }}
  timeoutSeconds: {{ $to }}
  failureThreshold: {{ $re }}
livenessProbe:
  exec:
    command: {{ toJson $cmd }}
  periodSeconds: {{ $iv }}
  timeoutSeconds: {{ $to }}
  failureThreshold: {{ mul $re 2 }}
{{- if $h.startPeriod }}
startupProbe:
  exec:
    command: {{ toJson $cmd }}
  periodSeconds: {{ $iv }}
  timeoutSeconds: {{ $to }}
  failureThreshold: {{ add (div (add (int $h.startPeriod) (sub $iv 1)) $iv) $re }}
{{- end }}
{{- end }}

{{/*
portcullis.deployment (dict "root" . "s" <spec>) — the workload of one core
service. Spec keys: name, uid, gid, groups ([gid]), readOnly (default true),
caps ([cap] added after drop ALL), memory (the limit; the request is
portcullis.memRequest's), health (probes dict), env (list of EnvVar),
envFrom, args, command, ports ([{name, port, protocol, hostPort}]), mounts
([VolumeMount]), volumes ([Volume]), nets ([compose network]), egress
(bool), token (bool: the ServiceAccount token, Traefik and the Hub only),
serviceAccount, hostAliases, dnsSearches (dnsConfig.searches), hashes ([object names]), grace (seconds),
extraLabels (map), fsGroup, initContainers ([Container], as given), httpReady ({path, port}: a kube-only readiness
httpGet for an image without a compose healthcheck — distroless —, so helm
--wait and status see a crash loop; readiness only, never liveness;
k8s_parity's delta kind kube-probe).
NEW (HA, Task 19; contract §20.1, spec §6 "Placement"):
  - replicas (default 1): one replica is a Deployment with Recreate; more
    is RollingUpdate (maxUnavailable 0, maxSurge 1: one stays up) and gets
    a PodDisruptionBudget minAvailable 1 (portcullis.pdb) and the spread;
  - spread (ScheduleAnyway | DoNotSchedule): topologySpreadConstraints on
    kubernetes.io/hostname, maxSkew 1 (the stateless gates ScheduleAnyway,
    quorum and data pieces DoNotSchedule, with nodeTaintsPolicy Honor);
    default DoNotSchedule for a StatefulSet with per-replica claims (review
    I1: node-local, pinned where it first lands), ScheduleAnyway for another
    replicated workload, none for one replica;
  - priorityClass (default portcullis-core: ruling I5, every core pod);
  - with ha.enabled, the not-ready / unreachable tolerations at 30 s on
    every pod (contract §3.4: the cluster's default is 300 s);
  - pin (bool): in HA, pinned to the primary site (portcullis.sitePin:
    a required node affinity portcullis.io/site In [ha.primarySite]);
    nodeExpressions ([NodeSelectorRequirement]): a class term, merged into
    the same required term (never replacing it);
  - namespace (default the release's), daemonSet ({nodeSelector}): a
    DaemonSet instead (Traefik on the ingress nodes in HA), RollingUpdate
    maxUnavailable 1 (its hostPorts can't surge).
statefulSet ({replicas, serviceName?, claims: [{name, uid, gid, mode, size?, storageClass?}]}): a
StatefulSet instead (HA's per-replica logs, contract §20.10; Keycloak's and
Alertmanager's stable pod names in HA): `replicas` pods, each with its own
PVC per claim (portcullis-core unless the claim says, the K3 owner
annotations, kept when scaled down or deleted), spread over the nodes, a
claim mounted by its name like a volume; serviceName (default the
component's ClusterIP Service: no per-pod DNS) a headless Service for
per-pod names.
*/}}
{{- define "portcullis.deployment" -}}
{{- $root := .root -}}{{- $s := .s -}}
{{- $ro := true -}}{{- if hasKey $s "readOnly" -}}{{- $ro = $s.readOnly -}}{{- end }}
{{- $sts := $s.statefulSet }}
{{- $ds := $s.daemonSet }}
{{- $n := int ($s.replicas | default 1) }}
{{- if $sts }}{{ $n = int $sts.replicas }}{{ end }}
{{- $spread := $s.spread | default "" }}
{{- /* Review I1: a StatefulSet whose replicas each have a node-local PVC
(portcullis-core) is pinned where it first lands, so it never co-locates:
DoNotSchedule. */}}
{{- if and (not $spread) $sts $sts.claims }}{{ $spread = "DoNotSchedule" }}{{ end }}
{{- if and (not $spread) (or $sts (gt $n 1)) }}{{ $spread = "ScheduleAnyway" }}{{ end }}
{{- $img := include "portcullis.image" (list $root ($s.image | default $s.name)) }}
{{- $pin := include "portcullis.sitePin" (dict "root" $root "s" $s) | trim }}
apiVersion: apps/v1
kind: {{ ternary "DaemonSet" (ternary "StatefulSet" "Deployment" (not (empty $sts))) (not (empty $ds)) }}
metadata:
  name: {{ $s.name }}
  namespace: {{ $s.namespace | default (include "portcullis.ns" $root) }}
  labels:
    app.kubernetes.io/managed-by: portcullis
    portcullis.io/component: {{ $s.name }}
spec:
  {{- if $ds }}
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 0
  {{- else if $sts }}
  replicas: {{ $sts.replicas }}
  {{- /* The ClusterIP Service, not a headless one: no per-pod DNS names (the
  Hub finds the replicas by listing pods, contract §20.10), unless the spec
  names its headless Service (Keycloak's servers, Alertmanager's peers). */}}
  serviceName: {{ $sts.serviceName | default $s.name }}
  podManagementPolicy: Parallel
  updateStrategy:
    type: RollingUpdate
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Retain
    whenScaled: Retain
  {{- with $sts.claims }}
  volumeClaimTemplates:
    {{- range . }}
    - metadata:
        name: {{ .name }}
        labels:
          app.kubernetes.io/managed-by: portcullis
          portcullis.io/component: {{ $s.name }}
        annotations:
          portcullis.io/uid: {{ .uid | quote }}
          portcullis.io/gid: {{ .gid | quote }}
          portcullis.io/mode: {{ .mode | quote }}
      spec:
        storageClassName: {{ .storageClass | default "portcullis-core" }}
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: {{ .size | default "1Gi" }}
    {{- end }}
  {{- end }}
  {{- else }}
  replicas: {{ $n }}
  strategy:
    {{- if gt $n 1 }}
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
    {{- else }}
    type: Recreate
    {{- end }}
  {{- end }}
  selector:
    matchLabels:
      portcullis.io/component: {{ $s.name }}
  template:
    metadata:
      labels:
        portcullis.io/component: {{ $s.name }}
        {{- range $s.nets }}
        portcullis.io/net-{{ . }}: "true"
        {{- end }}
        {{- if $s.egress }}
        portcullis.io/egress: "true"
        {{- end }}
        {{- range $k, $v := ($s.extraLabels | default dict) }}
        {{ $k }}: {{ $v | quote }}
        {{- end }}
      annotations:
        portcullis.io/config-hash: {{ include "portcullis.confighash" (list $root ($s.hashes | default list)) }}
    spec:
      {{- if $s.serviceAccount }}
      serviceAccountName: {{ $s.serviceAccount }}
      {{- end }}
      automountServiceAccountToken: {{ $s.token | default false }}
      enableServiceLinks: false
      {{- /* NEW (HA): every core pod names its class (kube/priorityclasses.yaml;
      ruling I5): portcullis-core, or portcullis-critical where the plan says. */}}
      priorityClassName: {{ $s.priorityClass | default "portcullis-core" }}
      {{- with $s.grace }}
      terminationGracePeriodSeconds: {{ . }}
      {{- end }}
      {{- with $s.hostAliases }}
      hostAliases:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $s.dnsSearches }}
      dnsConfig:
        searches: {{ toJson . }}
      {{- end }}
      {{- with $ds }}
      nodeSelector:
        {{- toYaml .nodeSelector | nindent 8 }}
      {{- end }}
      {{- with $pin }}
      affinity:
        {{- . | nindent 8 }}
      {{- end }}
      {{- if $root.Values.ha.enabled }}
      {{- /* HA (contract §3.4, §20.1): a pod on a lost node is evicted after
      30 s, not the cluster's 300 s. */}}
      tolerations:
        - key: node.kubernetes.io/not-ready
          operator: Exists
          effect: NoExecute
          tolerationSeconds: 30
        - key: node.kubernetes.io/unreachable
          operator: Exists
          effect: NoExecute
          tolerationSeconds: 30
      {{- end }}
      {{- if $spread }}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: {{ $spread }}
          {{- if eq $spread "DoNotSchedule" }}
          {{- /* A node this pod can't run on (the small taint) is no empty
          domain: without Honor, 3 replicas on 2 eligible nodes stay Pending. */}}
          nodeTaintsPolicy: Honor
          {{- end }}
          labelSelector:
            matchLabels:
              portcullis.io/component: {{ $s.name }}
      {{- end }}
      securityContext:
        runAsNonRoot: true
        runAsUser: {{ $s.uid }}
        runAsGroup: {{ $s.gid }}
        {{- with $s.groups }}
        supplementalGroups: {{ toJson . }}
        {{- end }}
        {{- with $s.fsGroup }}
        fsGroup: {{ . }}
        fsGroupChangePolicy: OnRootMismatch
        {{- end }}
        seccompProfile:
          type: RuntimeDefault
      {{- with $s.initContainers }}
      initContainers:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
        - name: {{ $s.name }}
          image: {{ $img }}
          imagePullPolicy: {{ ternary "Never" "IfNotPresent" (hasPrefix "localhost/" $img) }}
          {{- with $s.command }}
          command: {{ toJson . }}
          {{- end }}
          {{- with $s.args }}
          args: {{ toJson . }}
          {{- end }}
          {{- with $s.ports }}
          ports:
            {{- range . }}
            - name: {{ .name }}
              containerPort: {{ .port }}
              protocol: {{ .protocol | default "TCP" }}
              {{- with .hostPort }}
              hostPort: {{ . }}
              {{- end }}
            {{- end }}
          {{- end }}
          {{- with $s.env }}
          env:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with $s.envFrom }}
          envFrom:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          resources:
            limits:
              memory: {{ $s.memory }}
            requests:
              memory: {{ include "portcullis.memRequest" (list $root $s.name $s.memory) }}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: {{ $ro }}
            capabilities:
              drop: ["ALL"]
              {{- with $s.caps }}
              add: {{ toJson . }}
              {{- end }}
          {{- with $s.health }}
          {{- include "portcullis.probes" . | nindent 10 }}
          {{- end }}
          {{- with $s.httpReady }}
          readinessProbe:
            httpGet:
              path: {{ .path }}
              port: {{ .port }}
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3
          {{- end }}
          {{- with $s.mounts }}
          volumeMounts:
            {{- toYaml . | nindent 12 }}
          {{- end }}
      {{- with $s.volumes }}
      volumes:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- if and (not $ds) (ge $n 2) }}
---
{{ include "portcullis.pdb" (list $root $s.name) }}
{{- end }}
{{- end }}

{{/*
portcullis.memRequest <root> <service> <limit> — the memory request (user
ruling 2026-11-19, plan Amendment 2): the measured peak
(values memoryPeakMi) × 1.25, rounded up to 16 Mi, never above the limit;
a service with no measurement requests its limit; values memoryRequestMi
(a reviewed figure) wins over both. The limit stays compose's mem_limit.
*/}}
{{- define "portcullis.memRequest" -}}
{{- $root := index . 0 -}}{{- $lim := index . 2 -}}
{{- $peak := index ($root.Values.memoryPeakMi | default dict) (index . 1) -}}
{{- $fixed := index ($root.Values.memoryRequestMi | default dict) (index . 1) -}}
{{- if $fixed -}}
{{- int $fixed }}Mi
{{- else if $peak -}}
{{- $limMi := 0 -}}
{{- if hasSuffix "Gi" $lim }}{{ $limMi = mul (int (trimSuffix "Gi" $lim)) 1024 }}{{ else if hasSuffix "Mi" $lim }}{{ $limMi = int (trimSuffix "Mi" $lim) }}{{ else }}{{ fail (printf "memory %q: Mi or Gi only" $lim) }}{{ end -}}
{{- $req := mul (int (ceil (divf (mulf (float64 $peak) 1.25) 16.0))) 16 -}}
{{- min $req $limMi }}Mi
{{- else -}}
{{- $lim -}}
{{- end -}}
{{- end }}

{{/*
portcullis.primarySite — ha.primarySite, the primary site (contract
§20.11): fixed to main in this version, so any other value (or none) is
refused at render time. kube_render_values writes main; there is no option.
*/}}
{{- define "portcullis.primarySite" -}}
{{- $p := .Values.ha.primarySite | default "" -}}
{{- if ne $p "main" -}}
{{- fail (printf "ha.primarySite %q: the primary site is main and can't be changed in this version (contract §20.11)" $p) -}}
{{- end -}}
{{- $p -}}
{{- end }}

{{/*
portcullis.sitePin (dict "root" . "s" <spec>) — a pod's affinity (the body
under `affinity:`), contract §20.11. With ha.enabled and `pin: true` it
requires portcullis.io/site In [<ha.primarySite>]: the data and sign-in
pieces run only at the primary site (CNPG, Vault, the Sentinels and
sessions, the Hub, domains, Keycloak, LLDAP, the gates, enroll, mcp-gate,
wg; Longhorn's disks through the node label nodeadm sets). A class term
(`nodeExpressions`, e.g. portcullis.io/class NotIn [small], plan R2) is
merged into the same required term, never replacing it (nodeSelectorTerms
are ORed, a term's expressions ANDed). Without HA, or without `pin`, only
the class term (nothing without one). Never on the Traefik DaemonSet,
frontdoor or nodeadm (tests/k8s_parity.py check_sites).
*/}}
{{- define "portcullis.sitePin" -}}
{{- $root := .root -}}{{- $s := .s -}}
{{- $site := include "portcullis.primarySite" $root -}}
{{- $exprs := list -}}
{{- if and $s.pin $root.Values.ha.enabled -}}
{{- $exprs = append $exprs (dict "key" "portcullis.io/site" "operator" "In" "values" (list $site)) -}}
{{- end -}}
{{- $exprs = concat $exprs ($s.nodeExpressions | default list) -}}
{{- with $exprs }}
nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
      - matchExpressions:
          {{- toYaml . | nindent 10 }}
{{- end }}
{{- end }}

{{/*
portcullis.pvc <root> <name> <uid> <gid> <mode> [size] — a core PVC
(StorageClass portcullis-core, kept on uninstall, K3 owner annotations: the
provisioner creates the directory with them; no seed container ever). The
name is portcullis.pvcName's: in HA a replicated one is <name>-r on
portcullis-core-replicated (contract §20.1 "Core volumes").
*/}}
{{- define "portcullis.pvc" -}}
{{- $root := index . 0 -}}
{{- $name := include "portcullis.pvcName" (list $root (index . 1)) -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ $name }}
  namespace: {{ include "portcullis.ns" $root }}
  labels:
    app.kubernetes.io/managed-by: portcullis
  annotations:
    helm.sh/resource-policy: keep
    portcullis.io/uid: {{ index . 2 | quote }}
    portcullis.io/gid: {{ index . 3 | quote }}
    portcullis.io/mode: {{ index . 4 | quote }}
spec:
  storageClassName: {{ ternary "portcullis-core-replicated" "portcullis-core" (ne $name (index . 1)) }}
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: {{ if gt (len .) 5 }}{{ index . 5 }}{{ else }}1Gi{{ end }}
{{- end }}

{{/*
portcullis.pvcName <root> <name> — a core PVC's name (contract §20.1 "Core
volumes", preflight P35): hub-state, hub-secrets, hub-backups, domains-data
and wg-data are on the replicated tier in HA, as <name>-r (a PVC's class
is immutable: `ha enable` copies each X into X-r); every other PVC keeps
its name (prometheus-data stays local: Prometheus' history is rebuildable).
The CLI's kube_pvc_name follows the same list.
*/}}
{{- define "portcullis.pvcName" -}}
{{- $n := index . 1 -}}
{{- if and (index . 0).Values.ha.enabled (has $n (list "hub-state" "hub-secrets" "hub-backups" "domains-data" "wg-data")) -}}
{{- $n }}-r
{{- else -}}
{{- $n -}}
{{- end -}}
{{- end }}

{{/* portcullis.items <list of {key, path}> — ConfigMap items for a nested tree. */}}
{{- define "portcullis.items" -}}
{{- range . }}
- key: {{ .key | quote }}
  path: {{ .path | quote }}
{{- end }}
{{- end }}

{{/* portcullis.secretEnv <NAME> <key> [optional] — an env var from the portcullis-env Secret. */}}
{{- define "portcullis.secretEnv" -}}
- name: {{ index . 0 }}
  valueFrom:
    secretKeyRef:
      name: portcullis-env
      key: {{ index . 1 }}
      {{- if gt (len .) 2 }}
      optional: true
      {{- end }}
{{- end }}

{{/* portcullis.keycloakInternal — the URL internal Keycloak clients use (kcinternal, K15). */}}
{{- define "portcullis.keycloakInternal" -}}http://keycloak-internal:8081{{- end }}

{{/* portcullis.svcHost <root> <service> — a core Service's cluster DNS name. */}}
{{- define "portcullis.svcHost" -}}{{ index . 1 }}.{{ (index . 0).Release.Namespace }}.svc.cluster.local{{- end }}

{{/* portcullis.wgEdgePorts — wg's 47 edge container ports (9001–9047, slots 0–46). */}}
{{- define "portcullis.wgEdgePorts" -}}
{{- range $n := until 47 }}
- name: edge-{{ $n }}
  port: {{ add 9001 $n }}
{{- end }}
{{- end }}

{{/*
portcullis.haGate (dict "root" . "s" <spec> "uid" <data owner> "port" <log port> "env" [EnvVar]) — a
gate's HA shape (contract §20.10), changing <spec> in place: a StatefulSet
of ha.gateReplicas with its own `data` PVC per replica (instead of the
shared one), the read-only log port, port-bound (portcullis.io/ingress:
bound: netpol-gate-logs.yaml admits the Hub alone on the log port).
*/}}
{{- define "portcullis.haGate" -}}
{{- $s := .s -}}
{{- if or (lt (int .root.Values.ha.gateReplicas) 1) (gt (int .root.Values.ha.gateReplicas) 16) }}{{ fail "ha.gateReplicas must be 1-16 (the Hub's HUB_GATE_REPLICAS bound)" }}{{ end -}}
{{- $vols := list -}}
{{- range $s.volumes }}{{ if ne .name "data" }}{{ $vols = append $vols . }}{{ end }}{{ end -}}
{{- $_ := set $s "volumes" $vols -}}
{{- $_ = set $s "statefulSet" (dict "replicas" (int .root.Values.ha.gateReplicas) "claims" (list (dict "name" "data" "uid" .uid "gid" .root.Values.uids.hub "mode" "0750"))) -}}
{{- $_ = set $s "env" (concat $s.env .env) -}}
{{- $_ = set $s "ports" (append $s.ports (dict "name" "log" "port" .port)) -}}
{{- $_ = set $s "extraLabels" (merge (dict "portcullis.io/ingress" "bound") ($s.extraLabels | default dict)) -}}
{{- end }}

{{/*
portcullis.pdb <root> <name> — a PodDisruptionBudget keeping one pod of a
replicated core service up (HA; only for 2 replicas or more: with one,
minAvailable 1 would block every node drain).
*/}}
{{- define "portcullis.pdb" -}}
{{- $root := index . 0 -}}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ index . 1 }}
  namespace: {{ include "portcullis.ns" $root }}
  labels:
    app.kubernetes.io/managed-by: portcullis
spec:
  minAvailable: 1
  selector:
    matchLabels:
      portcullis.io/component: {{ index . 1 }}
{{- end }}

{{/*
portcullis.pubDocs — the published documents (contract §4 "On Kubernetes:
published documents"): the rows of files/published_docs.json, the byte
copy of the Hub's internal/publish/testdata/published_docs.json (CI
compares it, and tests/published_docs.json, with the Hub's), as a YAML
list. mode stays the row's octal string ("0444"): `int` reads it as octal.
*/}}
{{- define "portcullis.pubDocs" -}}
{{- $rows := .Files.Get "files/published_docs.json" | fromJsonArray -}}
{{- if not $rows }}{{ fail "files/published_docs.json: no rows (the Hub's published_docs.json byte copy)" }}{{ end -}}
{{- toYaml $rows -}}
{{- end }}

{{/*
portcullis.published (dict "root" . "s" <spec>) — a reader of the
published documents, changing <spec> in place: every mount of the spec at
a documents' directory (/hub-data, /vpn-doc) gets one projected volume of
that name holding the reader's rows (each object through items, never
subPath; the document's key and its .rev as .rev-<doc>, with the row's
mode; every source optional: true, so the chart's empty objects and a
withdrawn document are a missing file, never a failed mount), read-only;
and the init container portcullis-bin (the Hub's image by digest) copies
only the hub binary (`hub seed-self /portcullis-bin`, 0555) into an
emptyDir, writable there only, mounted read-only at /portcullis-bin in the
reader, for the Hub's `hub rev <dir> <doc>` exec (§4 "Confirmation").
*/}}
{{- define "portcullis.published" -}}
{{- $root := .root -}}{{- $s := .s -}}
{{- $rows := include "portcullis.pubDocs" $root | fromYamlArray -}}
{{- $vols := $s.volumes -}}
{{- $mounts := list -}}
{{- range $s.mounts -}}
{{- $m := . -}}
{{- $srcs := list -}}
{{- range $rows -}}
{{- if and (eq .mount $m.mountPath) (has $s.name .readers) -}}
{{- $items := list (dict "key" .key "path" .key "mode" (int .mode)) (dict "key" ".rev" "path" (printf ".rev-%s" .doc) "mode" (int .mode)) -}}
{{- $srcs = append $srcs (dict (ternary "secret" "configMap" (eq .kind "secret")) (dict "name" .object "optional" true "items" $items)) -}}
{{- end -}}
{{- end -}}
{{- if $srcs -}}
{{- $vols = append $vols (dict "name" $m.name "projected" (dict "sources" $srcs)) -}}
{{- $mounts = append $mounts (dict "name" $m.name "mountPath" $m.mountPath "readOnly" true) -}}
{{- else -}}
{{- $mounts = append $mounts $m -}}
{{- end -}}
{{- end -}}
{{- $img := include "portcullis.image" (list $root "hub") -}}
{{- $bin := dict "name" "portcullis-bin" "image" $img "imagePullPolicy" (ternary "Never" "IfNotPresent" (hasPrefix "localhost/" $img))
  "command" (list "/usr/local/bin/hub" "seed-self" "/portcullis-bin")
  "resources" (dict "limits" (dict "memory" "192Mi") "requests" (dict "memory" "192Mi"))
  "securityContext" (dict "allowPrivilegeEscalation" false "readOnlyRootFilesystem" true "capabilities" (dict "drop" (list "ALL")))
  "volumeMounts" (list (dict "name" "portcullis-bin" "mountPath" "/portcullis-bin")) -}}
{{- $_ := set $s "initContainers" (prepend ($s.initContainers | default list) $bin) -}}
{{- /* Sizes (e2e-k3s): the copy's page cache counts against the init
container, and 64Mi was OOM-killed writing the 77 MB hub; 192Mi. The
emptyDir outlives a pod sandbox restart, which re-runs the init container:
the old hub plus the new temporary copy (plus one left by a killed copy)
is ~231 MB, so 256Mi (128Mi got the pod evicted). */ -}}
{{- $_ = set $s "volumes" (append $vols (dict "name" "portcullis-bin" "emptyDir" (dict "sizeLimit" "256Mi"))) -}}
{{- $_ = set $s "mounts" (append $mounts (dict "name" "portcullis-bin" "mountPath" "/portcullis-bin" "readOnly" true)) -}}
{{- end }}

{{/*
portcullis.keycloakReplicas — Keycloak's replicas in HA (spec §6): 3 when
the primary site has 3 non-small nodes or more (ha.nonSmallNodesAtPrimary,
preflight P33: Keycloak is pinned there), else 2.
*/}}
{{- define "portcullis.keycloakReplicas" -}}
{{- ternary 3 2 (ge (int .Values.ha.nonSmallNodesAtPrimary) 3) -}}
{{- end }}

{{/*
portcullis.traefikPeer — Traefik as a NetworkPolicy peer of a core-namespace
policy, one list item: its pods in the core namespace, or in HA (plan
Amendment 3, contract §20.1 "Network flows") the DaemonSet's pods in
portcullis-ingress by namespace and app.kubernetes.io/name.
*/}}
{{- define "portcullis.traefikPeer" -}}
{{- if .Values.ha.enabled -}}
- namespaceSelector:
    matchLabels:
      kubernetes.io/metadata.name: {{ .Values.ingressNamespace }}
  podSelector:
    matchLabels:
      app.kubernetes.io/name: traefik
{{- else -}}
- podSelector:
    matchLabels:
      portcullis.io/component: traefik
{{- end -}}
{{- end }}

{{/* portcullis.traefikNets — Traefik's compose networks with a Kubernetes form (traefik.yaml's nets, the VPN ones excepted). */}}
{{- define "portcullis.traefikNets" -}}
{{- toJson (list "portcullis" "portcullis-proxy" "portcullis-auth" "portcullis-certs") -}}
{{- end }}

{{/*
portcullis.nodeRule — router portcullis-node's rule: the main domain's
public nodeadm paths exactly (contract §20.2's GET / POST /node/… routes;
nodeadm answers 404 for any other /node/<file> anyway).
*/}}
{{- define "portcullis.nodeRule" -}}
{{- $paths := list "/node/join.sh" "/node/nodeagent-amd64" "/node/nodeagent-arm64" "/node/v1/nonce" "/node/v1/enrol" "/node/v1/join" "/node/v1/renew" "/node/v1/renew/confirm" -}}
{{- $p := list -}}{{- range $paths }}{{- $p = append $p (printf "Path(`%s`)" .) -}}{{- end -}}
Host(`{{ include "portcullis.domain" . }}`) && ({{ join " || " $p }})
{{- end }}

{{/*
portcullis.traefikPeerParam — Traefik as the admission params name it
(<namespace>:<label>=<value>, the CLI's kube_traefik_peer): the Hub's
HUB_TRAEFIK_PEER, the peer of its routed apps' NetworkPolicies (Hub Task
13), so the two can't disagree (k8s_hardening checks them equal).
*/}}
{{- define "portcullis.traefikPeerParam" -}}
{{- if .Values.ha.enabled -}}
{{ .Values.ingressNamespace }}:app.kubernetes.io/name=traefik
{{- else -}}
{{ .Release.Namespace }}:portcullis.io/component=traefik
{{- end -}}
{{- end }}

{{/* portcullis.dnsProvider — dnsProvider, a provider name only (else the render fails: never a credential). */}}
{{- define "portcullis.dnsProvider" -}}
{{- $v := .Values.dnsProvider | default "" | toString -}}
{{- if and $v (not (regexMatch "^[a-z0-9-]{1,32}$" $v)) }}{{ fail "dnsProvider must be a DNS provider's name ([a-z0-9-], at most 32)" }}{{ end -}}
{{- $v -}}
{{- end }}

{{/*
portcullis.pgInstances — the CNPG Cluster's instances (plan Task 23,
preflight P40): 1 without HA; in HA min(3, cnpg.nodesAtPrimary: the
labelled non-small nodes at the primary site, Ready or not — review I1: a
NotReady node never scales Postgres down), at least 1; never below
cnpg.minInstances (the live Cluster's: only `node remove` lowers it).
*/}}
{{- define "portcullis.pgInstances" -}}
{{- $n := 1 -}}
{{- if .Values.ha.enabled -}}{{- $n = max 1 (min 3 (int .Values.cnpg.nodesAtPrimary)) -}}{{- end -}}
{{- max $n (int .Values.cnpg.minInstances) -}}
{{- end }}

{{/* portcullis.pgHost — the CNPG primary's Service (portcullis-pg-rw). */}}
{{- define "portcullis.pgHost" -}}portcullis-pg-rw.{{ .Values.cnpg.namespace }}.svc.cluster.local{{- end }}

{{/*
portcullis.pgImage — the CNPG Cluster's imageName: images.postgres with its
tag (CNPG's webhook refuses a digest without a tag: "can't detect
upgrades"). The CLI resolves pinned refs to name@sha256, so the tag is
images.json's pin, used only when its digest is the resolved one.
*/}}
{{- define "portcullis.pgImage" -}}
{{- $ref := include "portcullis.image" (list . "postgres") -}}
{{- if regexMatch ":[A-Za-z0-9._-]+@sha256:" $ref -}}
{{- $ref -}}
{{- else -}}
{{- $pin := (.Files.Get "images.json" | fromJson).images.postgres | default "" -}}
{{- if or (not (contains "@" $ref)) (not (hasSuffix (index (splitList "@" $ref) 1) $pin)) -}}
{{- fail (printf "images.postgres %q isn't images.json's pin %q (the CNPG Cluster needs its tag)" $ref $pin) -}}
{{- end -}}
{{- $pin -}}
{{- end -}}
{{- end }}
