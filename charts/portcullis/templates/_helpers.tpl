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
portcullis.deployment (dict "root" . "s" <spec>) — the Deployment of one core
service. Spec keys: name, uid, gid, groups ([gid]), readOnly (default true),
caps ([cap] added after drop ALL), memory, health (probes dict), env (list of
EnvVar), envFrom, args, command, ports ([{name, port, protocol}]), mounts
([VolumeMount]), volumes ([Volume]), nets ([compose network]), egress
(bool), token (bool: the ServiceAccount token, Traefik and the Hub only),
serviceAccount, hostAliases, dnsSearches (dnsConfig.searches), hashes ([object names]), grace (seconds),
extraLabels (map), fsGroup, initContainers ([Container], as given), httpReady ({path, port}: a kube-only readiness
httpGet for an image without a compose healthcheck — distroless —, so helm
--wait and status see a crash loop; readiness only, never liveness;
k8s_parity's delta kind kube-probe).
statefulSet ({replicas, claims: [{name, uid, gid, mode, size?}]}): a
StatefulSet instead (HA's per-replica logs, contract §20.10): `replicas`
pods, each with its own PVC per claim (portcullis-core, the K3 owner
annotations, kept when scaled down or deleted), spread over the nodes, a
claim mounted by its name like a volume.
*/}}
{{- define "portcullis.deployment" -}}
{{- $root := .root -}}{{- $s := .s -}}
{{- $ro := true -}}{{- if hasKey $s "readOnly" -}}{{- $ro = $s.readOnly -}}{{- end }}
{{- $sts := $s.statefulSet }}
apiVersion: apps/v1
kind: {{ ternary "StatefulSet" "Deployment" (not (empty $sts)) }}
metadata:
  name: {{ $s.name }}
  namespace: {{ include "portcullis.ns" $root }}
  labels:
    app.kubernetes.io/managed-by: portcullis
    portcullis.io/component: {{ $s.name }}
spec:
  {{- if $sts }}
  replicas: {{ $sts.replicas }}
  {{- /* The ClusterIP Service, not a headless one: no per-pod DNS names (the
  Hub finds the replicas by listing pods, contract §20.10). */}}
  serviceName: {{ $s.name }}
  podManagementPolicy: Parallel
  updateStrategy:
    type: RollingUpdate
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Retain
    whenScaled: Retain
  volumeClaimTemplates:
    {{- range $sts.claims }}
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
        storageClassName: portcullis-core
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: {{ .size | default "1Gi" }}
    {{- end }}
  {{- else }}
  replicas: 1
  strategy:
    type: Recreate
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
      {{- /* NEW (HA): every core pod (templates/priorityclasses.yaml). */}}
      priorityClassName: portcullis-core
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
      {{- if $sts }}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
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
          image: {{ include "portcullis.image" (list $root ($s.image | default $s.name)) }}
          imagePullPolicy: {{ ternary "Never" "IfNotPresent" (hasPrefix "localhost/" (include "portcullis.image" (list $root ($s.image | default $s.name)))) }}
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
              memory: {{ $s.memory }}
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
{{- end }}

{{/*
portcullis.pvc <root> <name> <uid> <gid> <mode> [size] — a core PVC
(StorageClass portcullis-core, kept on uninstall, K3 owner annotations: the
provisioner creates the directory with them; no seed container ever).
*/}}
{{- define "portcullis.pvc" -}}
{{- $root := index . 0 -}}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ index . 1 }}
  namespace: {{ include "portcullis.ns" $root }}
  labels:
    app.kubernetes.io/managed-by: portcullis
  annotations:
    helm.sh/resource-policy: keep
    portcullis.io/uid: {{ index . 2 | quote }}
    portcullis.io/gid: {{ index . 3 | quote }}
    portcullis.io/mode: {{ index . 4 | quote }}
spec:
  storageClassName: portcullis-core
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: {{ if gt (len .) 5 }}{{ index . 5 }}{{ else }}1Gi{{ end }}
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
{{- if lt (int .root.Values.ha.gateReplicas) 1 }}{{ fail "ha.gateReplicas must be at least 1" }}{{ end -}}
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
published documents"): the rows of tests/published_docs.json (the Hub's
internal/publish/testdata/, byte-copied), as a YAML list; k8s_parity
compares them. mode is decimal (0444 = 292, 0440 = 288).
*/}}
{{- define "portcullis.pubDocs" -}}
- {doc: group-gate-policy, object: pub-group-gate-policy, kind: configmap, key: group-gate-policy.json, mount: /hub-data, readers: [group-gate], mode: 292}
- {doc: user-attributes, object: pub-user-attributes, kind: configmap, key: user-attributes.json, mount: /hub-data, readers: [group-gate], mode: 292}
- {doc: portal-apps, object: pub-portal-apps, kind: configmap, key: portal-apps.json, mount: /hub-data, readers: [group-gate], mode: 292}
- {doc: signin-keycloak, object: pub-signin-keycloak, kind: configmap, key: signin-keycloak.json, mount: /hub-data, readers: [keycloak], mode: 292}
- {doc: impersonation, object: pub-impersonation, kind: configmap, key: impersonation.json, mount: /hub-data, readers: [group-gate, keycloak], mode: 292}
- {doc: mcp-gate, object: pub-mcp-gate, kind: configmap, key: mcp-gate.json, mount: /hub-data, readers: [mcp-gate], mode: 292}
- {doc: mcp-credentials, object: pub-mcp-credentials, kind: secret, key: mcp-credentials.json, mount: /hub-data, readers: [mcp-gate], mode: 288}
- {doc: vpn, object: pub-vpn, kind: configmap, key: vpn.json, mount: /vpn-doc, readers: [group-gate, wg], mode: 292}
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
the hub binary into an emptyDir mounted read-only at /portcullis-bin in
the reader, for the Hub's `hub rev <dir> <doc>` exec (§4 "Confirmation").
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
  "command" (list "/usr/local/bin/hub" "seed" "/usr/local/bin" "/portcullis-bin")
  "resources" (dict "limits" (dict "memory" "64Mi") "requests" (dict "memory" "64Mi"))
  "securityContext" (dict "allowPrivilegeEscalation" false "readOnlyRootFilesystem" true "capabilities" (dict "drop" (list "ALL")))
  "volumeMounts" (list (dict "name" "portcullis-bin" "mountPath" "/portcullis-bin")) -}}
{{- $_ := set $s "initContainers" (prepend ($s.initContainers | default list) $bin) -}}
{{- $_ = set $s "volumes" (append $vols (dict "name" "portcullis-bin" "emptyDir" (dict "sizeLimit" "128Mi"))) -}}
{{- $_ = set $s "mounts" (append $mounts (dict "name" "portcullis-bin" "mountPath" "/portcullis-bin" "readOnly" true)) -}}
{{- end }}
