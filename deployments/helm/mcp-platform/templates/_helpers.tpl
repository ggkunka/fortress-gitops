{{/*
Expand the name of the chart.
*/}}
{{- define "mcp-platform.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mcp-platform.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mcp-platform.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mcp-platform.labels" -}}
helm.sh/chart: {{ include "mcp-platform.chart" . }}
{{ include "mcp-platform.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mcp-platform.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-platform.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mcp-platform.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mcp-platform.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create service labels for a specific service
*/}}
{{- define "mcp-platform.serviceLabels" -}}
{{ include "mcp-platform.labels" . }}
app.kubernetes.io/component: {{ .service }}
{{- end }}

{{/*
Create selector labels for a specific service
*/}}
{{- define "mcp-platform.serviceSelectorLabels" -}}
{{ include "mcp-platform.selectorLabels" . }}
app.kubernetes.io/component: {{ .service }}
{{- end }}

{{/*
Create image reference for a service
*/}}
{{- define "mcp-platform.image" -}}
{{- $registry := default .Values.image.registry .Values.global.imageRegistry }}
{{- $repository := .Values.image.repository }}
{{- $service := .service }}
{{- $tag := default .Values.image.tag .Chart.AppVersion }}
{{- printf "%s/%s-%s:%s" $registry $repository $service $tag }}
{{- end }}

{{/*
Create image pull policy
*/}}
{{- define "mcp-platform.imagePullPolicy" -}}
{{- default "IfNotPresent" .Values.image.pullPolicy }}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "mcp-platform.imagePullSecrets" -}}
{{- $secrets := default .Values.image.pullSecrets .Values.global.imagePullSecrets }}
{{- if $secrets }}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create PostgreSQL connection string
*/}}
{{- define "mcp-platform.postgresql.connectionString" -}}
{{- if .Values.postgresql.enabled }}
{{- $host := printf "%s-postgresql" (include "mcp-platform.fullname" .) }}
{{- $port := "5432" }}
{{- $database := .Values.postgresql.auth.database }}
{{- $username := .Values.postgresql.auth.username }}
{{- $password := .Values.postgresql.auth.password }}
{{- printf "postgresql://%s:%s@%s:%s/%s" $username $password $host $port $database }}
{{- else }}
{{- required "External PostgreSQL connection string is required when postgresql.enabled is false" .Values.externalPostgresql.connectionString }}
{{- end }}
{{- end }}

{{/*
Create Redis connection string
*/}}
{{- define "mcp-platform.redis.connectionString" -}}
{{- if .Values.redis.enabled }}
{{- $host := printf "%s-redis-master" (include "mcp-platform.fullname" .) }}
{{- $port := "6379" }}
{{- $password := .Values.redis.auth.password }}
{{- if .Values.redis.auth.enabled }}
{{- printf "redis://:%s@%s:%s/0" $password $host $port }}
{{- else }}
{{- printf "redis://%s:%s/0" $host $port }}
{{- end }}
{{- else }}
{{- required "External Redis connection string is required when redis.enabled is false" .Values.externalRedis.connectionString }}
{{- end }}
{{- end }}

{{/*
Create security context
*/}}
{{- define "mcp-platform.securityContext" -}}
{{- if .Values.securityContext }}
securityContext:
{{- toYaml .Values.securityContext | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Create pod security context
*/}}
{{- define "mcp-platform.podSecurityContext" -}}
{{- if .Values.podSecurityContext }}
securityContext:
{{- toYaml .Values.podSecurityContext | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Create resources
*/}}
{{- define "mcp-platform.resources" -}}
{{- if .resources }}
resources:
{{- toYaml .resources | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Create node selector
*/}}
{{- define "mcp-platform.nodeSelector" -}}
{{- if .nodeSelector }}
nodeSelector:
{{- toYaml .nodeSelector | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Create tolerations
*/}}
{{- define "mcp-platform.tolerations" -}}
{{- if .tolerations }}
tolerations:
{{- toYaml .tolerations | nindent 0 }}
{{- end }}
{{- end }}

{{/*
Create affinity
*/}}
{{- define "mcp-platform.affinity" -}}
{{- if .affinity }}
affinity:
{{- toYaml .affinity | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Create environment variables
*/}}
{{- define "mcp-platform.env" -}}
{{- if .env }}
env:
{{- toYaml .env | nindent 0 }}
{{- end }}
{{- end }}

{{/*
Check Kubernetes version compatibility
*/}}
{{- define "mcp-platform.kubeVersionCheck" -}}
{{- $kubeVersion := .Capabilities.KubeVersion.Version }}
{{- $minVersion := "1.21.0" }}
{{- $maxVersion := "1.33.0" }}
{{- if not (semverCompare (printf ">=%s" $minVersion) $kubeVersion) }}
{{- fail (printf "Kubernetes version %s is not supported. Minimum version is %s" $kubeVersion $minVersion) }}
{{- end }}
{{- if not (semverCompare (printf "<%s" $maxVersion) $kubeVersion) }}
{{- fail (printf "Kubernetes version %s is not supported. Maximum version is %s" $kubeVersion $maxVersion) }}
{{- end }}
{{- end }}

{{/*
Create API version for Ingress based on Kubernetes version
*/}}
{{- define "mcp-platform.ingress.apiVersion" -}}
{{- if semverCompare ">=1.19.0" .Capabilities.KubeVersion.Version }}
{{- print "networking.k8s.io/v1" }}
{{- else if semverCompare ">=1.14.0" .Capabilities.KubeVersion.Version }}
{{- print "networking.k8s.io/v1beta1" }}
{{- else }}
{{- print "extensions/v1beta1" }}
{{- end }}
{{- end }}

{{/*
Create API version for HPA based on Kubernetes version
*/}}
{{- define "mcp-platform.hpa.apiVersion" -}}
{{- if semverCompare ">=1.23.0" .Capabilities.KubeVersion.Version }}
{{- print "autoscaling/v2" }}
{{- else }}
{{- print "autoscaling/v2beta2" }}
{{- end }}
{{- end }}

{{/*
Create API version for PodDisruptionBudget based on Kubernetes version
*/}}
{{- define "mcp-platform.pdb.apiVersion" -}}
{{- if semverCompare ">=1.21.0" .Capabilities.KubeVersion.Version }}
{{- print "policy/v1" }}
{{- else }}
{{- print "policy/v1beta1" }}
{{- end }}
{{- end }}

{{/*
Create API version for NetworkPolicy based on Kubernetes version
*/}}
{{- define "mcp-platform.networkPolicy.apiVersion" -}}
{{- if semverCompare ">=1.7.0" .Capabilities.KubeVersion.Version }}
{{- print "networking.k8s.io/v1" }}
{{- else }}
{{- print "extensions/v1beta1" }}
{{- end }}
{{- end }}

{{/*
Create storage class
*/}}
{{- define "mcp-platform.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else if .Values.kubernetesFlavorConfig.openshift.enabled }}
{{- .Values.kubernetesFlavorConfig.openshift.storageClass }}
{{- else if .Values.kubernetesFlavorConfig.eks.enabled }}
{{- .Values.kubernetesFlavorConfig.eks.storageClass }}
{{- else if .Values.kubernetesFlavorConfig.aks.enabled }}
{{- .Values.kubernetesFlavorConfig.aks.storageClass }}
{{- else if .Values.kubernetesFlavorConfig.gke.enabled }}
{{- .Values.kubernetesFlavorConfig.gke.storageClass }}
{{- else }}
{{- .Values.kubernetesFlavorConfig.vanilla.storageClass }}
{{- end }}
{{- end }}

{{/*
Create ingress class
*/}}
{{- define "mcp-platform.ingressClass" -}}
{{- if .Values.kubernetesFlavorConfig.openshift.enabled }}
{{- .Values.kubernetesFlavorConfig.openshift.ingressClass }}
{{- else if .Values.kubernetesFlavorConfig.eks.enabled }}
{{- .Values.kubernetesFlavorConfig.eks.ingressClass }}
{{- else if .Values.kubernetesFlavorConfig.aks.enabled }}
{{- .Values.kubernetesFlavorConfig.aks.ingressClass }}
{{- else if .Values.kubernetesFlavorConfig.gke.enabled }}
{{- .Values.kubernetesFlavorConfig.gke.ingressClass }}
{{- else }}
{{- .Values.kubernetesFlavorConfig.vanilla.ingressClass }}
{{- end }}
{{- end }}

{{/*
Create common annotations
*/}}
{{- define "mcp-platform.annotations" -}}
meta.helm.sh/release-name: {{ .Release.Name }}
meta.helm.sh/release-namespace: {{ .Release.Namespace }}
{{- end }}

{{/*
Create common pod annotations
*/}}
{{- define "mcp-platform.podAnnotations" -}}
checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end }}