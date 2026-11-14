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
serviceAccount, hostAliases, hashes ([object names]), grace (seconds),
extraLabels (map), fsGroup.
*/}}
{{- define "portcullis.deployment" -}}
{{- $root := .root -}}{{- $s := .s -}}
{{- $ro := true -}}{{- if hasKey $s "readOnly" -}}{{- $ro = $s.readOnly -}}{{- end }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $s.name }}
  namespace: {{ include "portcullis.ns" $root }}
  labels:
    app.kubernetes.io/managed-by: portcullis
    portcullis.io/component: {{ $s.name }}
spec:
  replicas: 1
  strategy:
    type: Recreate
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
      {{- with $s.grace }}
      terminationGracePeriodSeconds: {{ . }}
      {{- end }}
      {{- with $s.hostAliases }}
      hostAliases:
        {{- toYaml . | nindent 8 }}
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
