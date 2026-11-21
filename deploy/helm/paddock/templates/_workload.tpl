{{/*
Generic hardened Deployment.

  include "paddock.deployment" (dict
    "root" $ "component" "orchestrator" "values" .Values.orchestrator
    "image" .Values.orchestrator.image      # optional override
    "command" (list ...)                    # optional
    "env" "<yaml list string>"
    "probes" "<yaml string>"                # liveness/readiness/startup
    "initContainers" "<yaml list string>"
    "extraMounts" "<yaml list string>" "extraVolumes" "<yaml list string>"
    "netRaw" false)
*/}}
{{- define "paddock.deployment" -}}
{{- $r := .root -}}
{{- $c := .component -}}
{{- $v := .values -}}
{{- $sel := dict "root" $r "component" $c -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "paddock.componentName" $sel }}
  labels:
    {{- include "paddock.componentLabels" $sel | nindent 4 }}
spec:
  {{- if not (and $v.autoscaling $v.autoscaling.enabled) }}
  replicas: {{ $v.replicas }}
  {{- end }}
  revisionHistoryLimit: 5
  selector:
    matchLabels:
      {{- include "paddock.selectorLabels" $sel | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "paddock.componentLabels" $sel | nindent 8 }}
      annotations:
        checksum/config: {{ toJson $r.Values.config | sha256sum | trunc 16 }}
    spec:
      serviceAccountName: {{ include "paddock.serviceAccountName" $r }}
      automountServiceAccountToken: {{ $r.Values.serviceAccount.automountServiceAccountToken }}
      enableServiceLinks: false
      securityContext:
        {{- include "paddock.podSecurityContext" (dict "root" $r "override" $v.podSecurityContext) | nindent 8 }}
      {{- with .initContainers }}
      initContainers:
        {{- . | nindent 8 }}
      {{- end }}
      containers:
        - name: {{ $c }}
          image: {{ include "paddock.image" (dict "root" $r "image" (.image | default $v.image)) }}
          imagePullPolicy: {{ $r.Values.global.imagePullPolicy }}
          {{- with .command }}
          command:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- if $v.port }}
          ports:
            - name: http
              containerPort: {{ $v.port }}
              protocol: TCP
          {{- end }}
          {{- with .env }}
          env:
            {{- . | nindent 12 }}
          {{- end }}
          securityContext:
            {{- include "paddock.containerSecurityContext" (dict "root" $r "netRaw" .netRaw) | nindent 12 }}
          resources:
            {{- toYaml $v.resources | nindent 12 }}
          {{- with .probes }}
          {{- . | nindent 10 }}
          {{- end }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            {{- with .extraMounts }}
            {{- . | nindent 12 }}
            {{- end }}
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 512Mi
        {{- with .extraVolumes }}
        {{- . | nindent 8 }}
        {{- end }}
      {{- with $r.Values.topologySpreadConstraints }}
      topologySpreadConstraints:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- include "paddock.scheduling" $r | nindent 6 }}
{{- end -}}

{{/* ClusterIP Service for a component with a port. */}}
{{- define "paddock.service" -}}
{{- $sel := dict "root" .root "component" .component -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "paddock.componentName" $sel }}
  labels:
    {{- include "paddock.componentLabels" $sel | nindent 4 }}
spec:
  type: ClusterIP
  selector:
    {{- include "paddock.selectorLabels" $sel | nindent 4 }}
  ports:
    - name: http
      port: {{ .values.port }}
      targetPort: http
      protocol: TCP
{{- end -}}

{{/* Liveness/readiness on HTTP paths. (dict "live" "/healthz" "ready" "/readyz") */}}
{{- define "paddock.httpProbes" -}}
startupProbe:
  httpGet: {path: {{ .live }}, port: http}
  periodSeconds: 5
  failureThreshold: 36
livenessProbe:
  httpGet: {path: {{ .live }}, port: http}
  periodSeconds: 15
  timeoutSeconds: 5
  failureThreshold: 4
readinessProbe:
  httpGet: {path: {{ .ready | default .live }}, port: http}
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
{{- end -}}

{{/* Queue workers have no HTTP port: probe that Redis is reachable from the
     pod (same check as the compose healthcheck), parsed from REDIS_URL. */}}
{{- define "paddock.workerProbes" -}}
livenessProbe:
  exec:
    command:
      - python
      - -c
      - "import os,socket,urllib.parse as u; p=u.urlparse(os.environ['REDIS_URL']); socket.create_connection((p.hostname, p.port or 6379), 3).close()"
  initialDelaySeconds: 20
  periodSeconds: 30
  timeoutSeconds: 10
  failureThreshold: 3
{{- end -}}
