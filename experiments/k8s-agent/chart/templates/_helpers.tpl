{{/* SPDX-License-Identifier: Apache-2.0 */}}

{{- define "openshell-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openshell-agent.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "openshell-agent.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "openshell-agent.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "openshell-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: agent-launcher
{{- end -}}

{{- define "openshell-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "openshell-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Name of the Secret holding agent credentials. Prefers an externally managed
Secret; falls back to a chart-created one only when credentials.create is set.
*/}}
{{- define "openshell-agent.secretName" -}}
{{- if .Values.credentials.existingSecret -}}
{{- .Values.credentials.existingSecret -}}
{{- else -}}
{{- printf "%s-credentials" (include "openshell-agent.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Grafana MCP service name and the host forms the server will accept. The sandbox
reaches it by cluster DNS, so the FQDN is the name that must be allowed.
*/}}
{{/*
Fixed, not release-derived: the sandbox policy that authorizes this host is
baked into the agent image and cannot know a Helm release name. One shared MCP
server per namespace — enable grafanaMcp on exactly one release.
*/}}
{{- define "openshell-agent.grafanaMcpService" -}}
{{- .Values.grafanaMcp.serviceName -}}
{{- end -}}

{{- define "openshell-agent.grafanaMcpFqdn" -}}
{{- printf "%s.%s.svc.cluster.local" (include "openshell-agent.grafanaMcpService" .) .Release.Namespace -}}
{{- end -}}

{{- define "openshell-agent.grafanaMcpAllowedHosts" -}}
{{- $svc := include "openshell-agent.grafanaMcpService" . -}}
{{- $fqdn := include "openshell-agent.grafanaMcpFqdn" . -}}
{{- $port := .Values.grafanaMcp.port | toString -}}
{{- printf "%s,%s:%s,%s,%s:%s" $fqdn $fqdn $port $svc $svc $port -}}
{{- end -}}
