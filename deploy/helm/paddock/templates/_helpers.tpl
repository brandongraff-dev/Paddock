{{/* ---------------------------------------------------------------------
     Names + labels
     --------------------------------------------------------------------- */}}
{{- define "paddock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "paddock.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* <fullname>-<component> */}}
{{- define "paddock.componentName" -}}
{{- printf "%s-%s" (include "paddock.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "paddock.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "paddock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: paddock
{{- end -}}

{{/* selector labels for a component: (dict "root" $ "component" "orchestrator") */}}
{{- define "paddock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "paddock.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "paddock.componentLabels" -}}
{{ include "paddock.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "paddock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "paddock.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* image: (dict "root" $ "image" .Values.orchestrator.image) */}}
{{- define "paddock.image" -}}
{{- $reg := .root.Values.global.imageRegistry -}}
{{- $tag := .image.tag | default .root.Values.global.imageTag | default .root.Chart.AppVersion -}}
{{- if $reg -}}
{{- printf "%s/%s:%s" $reg .image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .image.repository $tag -}}
{{- end -}}
{{- end -}}

{{/* ---------------------------------------------------------------------
     Secrets
     --------------------------------------------------------------------- */}}
{{- define "paddock.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-env" (include "paddock.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* The migration Job runs before regular resources exist, so it reads a
     hook-managed copy of the connection secret (unless existingSecret). */}}
{{- define "paddock.migrateSecretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-migrate" (include "paddock.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "paddock.postgresHost" -}}
{{- printf "%s-postgresql" (include "paddock.fullname" .) -}}
{{- end -}}

{{- define "paddock.redisHost" -}}
{{- printf "%s-redis" (include "paddock.fullname" .) -}}
{{- end -}}

{{/* DATABASE_URL env for a container: (dict "root" $ "secret" <name>).
     Bundled Postgres: the password lives ONLY in the <fullname>-postgresql
     Secret and is interpolated with Kubernetes' $(VAR) env syntax. */}}
{{- define "paddock.databaseEnv" -}}
{{- $r := .root -}}
{{- if $r.Values.postgresql.enabled }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "paddock.postgresHost" $r }}
      key: POSTGRES_PASSWORD
- name: DATABASE_URL
  value: {{ printf "postgresql://%s:$(POSTGRES_PASSWORD)@%s:5432/%s" $r.Values.postgresql.username (include "paddock.postgresHost" $r) $r.Values.postgresql.database | quote }}
{{- else }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ .secret | default (include "paddock.secretName" $r) }}
      key: DATABASE_URL
{{- end }}
{{- end -}}

{{- define "paddock.databaseUrl" -}}
{{- required "secrets.databaseUrl (or secrets.existingSecret, or postgresql.enabled=true) is required" .Values.secrets.databaseUrl -}}
{{- end -}}

{{- define "paddock.redisUrl" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s:6379/0" (include "paddock.redisHost" .) -}}
{{- else -}}
{{- required "secrets.redisUrl (or secrets.existingSecret, or redis.enabled=true) is required" .Values.secrets.redisUrl -}}
{{- end -}}
{{- end -}}

{{/* Keep a generated value stable across upgrades: (dict "root" $ "key" "JWT_SECRET" "value" "") */}}
{{- define "paddock.stableSecret" -}}
{{- if .value -}}
{{- .value -}}
{{- else -}}
{{- $s := lookup "v1" "Secret" .root.Release.Namespace (printf "%s-env" (include "paddock.fullname" .root)) -}}
{{- if and $s $s.data (index $s.data .key) -}}
{{- index $s.data .key | b64dec -}}
{{- else -}}
{{- randAlphaNum 48 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* env var from the app secret: (dict "root" $ "name" "JWT_SECRET" "optional" true) */}}
{{- define "paddock.secretEnv" -}}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ include "paddock.secretName" .root }}
      key: {{ .key | default .name }}
      optional: {{ .optional | default false }}
{{- end -}}

{{/* ---------------------------------------------------------------------
     Common container fragments
     --------------------------------------------------------------------- */}}
{{- define "paddock.commonPythonEnv" -}}
- name: LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: PYTHONDONTWRITEBYTECODE
  value: "1"
{{ include "paddock.databaseEnv" (dict "root" .) }}
{{ include "paddock.secretEnv" (dict "root" . "name" "REDIS_URL") }}
- name: ORCHESTRATOR_URL
  value: {{ printf "http://%s:%v" (include "paddock.componentName" (dict "root" . "component" "orchestrator")) .Values.orchestrator.port | quote }}
{{ include "paddock.secretEnv" (dict "root" . "name" "SERVICE_API_KEY" "optional" true) }}
{{- range $k, $v := .Values.config.extraEnv }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}

{{- define "paddock.podSecurityContext" -}}
{{- $base := deepCopy .root.Values.podSecurityContext -}}
{{- $over := .override | default dict -}}
{{- toYaml (mergeOverwrite $base $over) -}}
{{- end -}}

{{- define "paddock.containerSecurityContext" -}}
{{- $ctx := deepCopy .root.Values.containerSecurityContext -}}
{{- if .netRaw -}}
{{- $_ := set $ctx "capabilities" (dict "drop" (list "ALL") "add" (list "NET_RAW")) -}}
{{- end -}}
{{- toYaml $ctx -}}
{{- end -}}

{{- define "paddock.scheduling" -}}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* NetworkPolicy peers */}}
{{- define "paddock.np.component" -}}
podSelector:
  matchLabels:
    app.kubernetes.io/instance: {{ .root.Release.Name }}
    app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "paddock.np.anyPaddock" -}}
podSelector:
  matchLabels:
    app.kubernetes.io/instance: {{ .Release.Name }}
    app.kubernetes.io/part-of: paddock
{{- end -}}

{{/* Init container for pods that read the DB: `migrate up` against the
     regular <fullname>-schema ConfigMap. Advisory-locked and a no-op once the
     hook Job has run; with bundled Postgres (no pre-install Job possible) it
     is what migrates a fresh install, so `helm install --wait` cannot
     deadlock. Pair with "paddock.schemaVolume". */}}
{{- define "paddock.waitForSchemaInit" -}}
{{- if .Values.migrations.enabled }}
- name: migrate
  image: {{ include "paddock.image" (dict "root" . "image" .Values.orchestrator.image) }}
  imagePullPolicy: {{ .Values.global.imagePullPolicy }}
  command: ["python", "-m", "app.migrate", "up", "--wait", {{ .Values.migrations.waitSeconds | quote }}, "--lock-timeout", {{ .Values.migrations.lockTimeoutSeconds | quote }}]
  env:
    {{- include "paddock.databaseEnv" (dict "root" .) | nindent 4 }}
    - name: SCHEMA_DIR
      value: /schema
    - name: MIGRATE_ALLOW_CHECKSUM_DRIFT
      value: {{ .Values.migrations.allowChecksumDrift | quote }}
  securityContext:
    {{- include "paddock.containerSecurityContext" (dict "root" .) | nindent 4 }}
  resources:
    {{- toYaml .Values.migrations.resources | nindent 4 }}
  volumeMounts:
    - name: schema
      mountPath: /schema
      readOnly: true
{{- end }}
{{- end -}}

{{- define "paddock.schemaVolume" -}}
{{- if .Values.migrations.enabled }}
- name: schema
  configMap:
    name: {{ include "paddock.fullname" . }}-schema
{{- end }}
{{- end -}}
