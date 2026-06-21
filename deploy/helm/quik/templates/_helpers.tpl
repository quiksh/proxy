{{/* Expand the name of the chart. */}}
{{- define "quik.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "quik.fullname" -}}
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

{{- define "quik.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "quik.labels" -}}
helm.sh/chart: {{ include "quik.chart" . }}
{{ include "quik.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "quik.selectorLabels" -}}
app.kubernetes.io/name: {{ include "quik.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "quik.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "quik.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference: image.tag falls back to Chart.AppVersion. */}}
{{- define "quik.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* Name of the TLS secret to mount (cert-manager-issued or pre-existing). */}}
{{- define "quik.tlsSecretName" -}}
{{- if .Values.tls.certManager.enabled -}}
{{- printf "%s-tls" (include "quik.fullname" .) -}}
{{- else -}}
{{- required "tls.secretName is required unless tls.certManager.enabled" .Values.tls.secretName -}}
{{- end -}}
{{- end -}}

{{/* Render a YAML list of strings as a TOML array: ["a", "b"]. */}}
{{- define "quik.tomlStrArray" -}}
[{{ range $i, $v := . }}{{ if $i }}, {{ end }}{{ $v | quote }}{{ end }}]
{{- end -}}
