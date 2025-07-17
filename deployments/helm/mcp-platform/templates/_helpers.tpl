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
Kubernetes version detection and API version helpers
*/}}

{{/*
Get major.minor version from Kubernetes version
*/}}
{{- define "mcp-platform.kubeVersion" -}}
{{- regexReplaceAll "^v?([0-9]+\\.[0-9]+).*" .Capabilities.KubeVersion.Version "${1}" }}
{{- end }}

{{/*
Check if Kubernetes version supports a specific API
*/}}
{{- define "mcp-platform.supportsAPI" -}}
{{- $kubeVersion := include "mcp-platform.kubeVersion" . }}
{{- $apiVersion := .apiVersion }}
{{- $minVersion := .minVersion }}
{{- if semverCompare (printf ">=%s" $minVersion) $kubeVersion }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
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
Create pathType for Ingress based on Kubernetes version
*/}}
{{- define "mcp-platform.ingress.pathType" -}}
{{- if semverCompare ">=1.18.0" .Capabilities.KubeVersion.Version }}
{{- print "Prefix" }}
{{- else }}
{{- print "" }}
{{- end }}
{{- end }}

{{/*
Create API version for CronJob based on Kubernetes version
*/}}
{{- define "mcp-platform.cronjob.apiVersion" -}}
{{- if semverCompare ">=1.25.0" .Capabilities.KubeVersion.Version }}
{{- print "batch/v1" }}
{{- else if semverCompare ">=1.21.0" .Capabilities.KubeVersion.Version }}
{{- print "batch/v1" }}
{{- else }}
{{- print "batch/v1beta1" }}
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
{{- if .Values.kubernetesFlavorConfig.eks.enabled }}
{{- if .Values.kubernetesFlavorConfig.eks.serviceAccount.annotations }}
{{- range $key, $value := .Values.kubernetesFlavorConfig.eks.serviceAccount.annotations }}
{{ $key }}: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- if .Values.kubernetesFlavorConfig.aks.enabled }}
{{- if .Values.kubernetesFlavorConfig.aks.podAnnotations }}
{{- range $key, $value := .Values.kubernetesFlavorConfig.aks.podAnnotations }}
{{ $key }}: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Platform-specific helpers
*/}}

{{/*
Detect Kubernetes platform/flavor
*/}}
{{- define "mcp-platform.detectPlatform" -}}
{{- if .Values.kubernetesFlavorConfig.openshift.enabled }}
{{- print "openshift" }}
{{- else if .Values.kubernetesFlavorConfig.eks.enabled }}
{{- print "eks" }}
{{- else if .Values.kubernetesFlavorConfig.aks.enabled }}
{{- print "aks" }}
{{- else if .Values.kubernetesFlavorConfig.gke.enabled }}
{{- print "gke" }}
{{- else }}
{{- print "vanilla" }}
{{- end }}
{{- end }}

{{/*
Check if running on OpenShift
*/}}
{{- define "mcp-platform.isOpenShift" -}}
{{- if .Values.kubernetesFlavorConfig.openshift.enabled }}
{{- print "true" }}
{{- else if .Capabilities.APIVersions.Has "route.openshift.io/v1" }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end }}

{{/*
Check if running on EKS
*/}}
{{- define "mcp-platform.isEKS" -}}
{{- if .Values.kubernetesFlavorConfig.eks.enabled }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end }}

{{/*
Check if running on AKS
*/}}
{{- define "mcp-platform.isAKS" -}}
{{- if .Values.kubernetesFlavorConfig.aks.enabled }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end }}

{{/*
Check if running on GKE
*/}}
{{- define "mcp-platform.isGKE" -}}
{{- if .Values.kubernetesFlavorConfig.gke.enabled }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end }}

{{/*
Security context helpers for different platforms
*/}}

{{/*
Create Pod Security Standards policy (K8s 1.25+)
*/}}
{{- define "mcp-platform.podSecurityStandards" -}}
{{- if semverCompare ">=1.25.0" .Capabilities.KubeVersion.Version }}
{{- if not (eq (include "mcp-platform.isOpenShift" .) "true") }}
pod-security.kubernetes.io/enforce: {{ .Values.security.podSecurityStandards.enforce | default "restricted" }}
pod-security.kubernetes.io/audit: {{ .Values.security.podSecurityStandards.audit | default "restricted" }}
pod-security.kubernetes.io/warn: {{ .Values.security.podSecurityStandards.warn | default "restricted" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create security context based on platform
*/}}
{{- define "mcp-platform.platformSecurityContext" -}}
{{- if eq (include "mcp-platform.isOpenShift" .) "true" }}
{{/* OpenShift SCCs handle security context automatically */}}
securityContext: {}
{{- else }}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .Values.security.runAsUser | default 1000 }}
  runAsGroup: {{ .Values.security.runAsGroup | default 1000 }}
  fsGroup: {{ .Values.security.fsGroup | default 1000 }}
  seccompProfile:
    type: RuntimeDefault
{{- end }}
{{- end }}

{{/*
Create container security context based on platform
*/}}
{{- define "mcp-platform.platformContainerSecurityContext" -}}
{{- if eq (include "mcp-platform.isOpenShift" .) "true" }}
{{/* OpenShift SCCs handle security context automatically */}}
securityContext: {}
{{- else }}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: {{ .Values.security.runAsUser | default 1000 }}
  capabilities:
    drop:
    - ALL
  seccompProfile:
    type: RuntimeDefault
{{- end }}
{{- end }}

{{/*
Create service account annotations for platform-specific features
*/}}
{{- define "mcp-platform.serviceAccountAnnotations" -}}
{{- if eq (include "mcp-platform.isEKS" .) "true" }}
{{/* EKS IRSA annotations */}}
{{- if .Values.kubernetesFlavorConfig.eks.serviceAccount.annotations }}
{{- range $key, $value := .Values.kubernetesFlavorConfig.eks.serviceAccount.annotations }}
{{ $key }}: {{ $value | quote }}
{{- end }}
{{- end }}
{{- else if eq (include "mcp-platform.isAKS" .) "true" }}
{{/* AKS Managed Identity annotations */}}
{{- if .Values.kubernetesFlavorConfig.aks.managedIdentity.enabled }}
azure.workload.identity/client-id: {{ .Values.kubernetesFlavorConfig.aks.managedIdentity.clientId | quote }}
azure.workload.identity/tenant-id: {{ .Values.kubernetesFlavorConfig.aks.managedIdentity.tenantId | quote }}
{{- end }}
{{- else if eq (include "mcp-platform.isGKE" .) "true" }}
{{/* GKE Workload Identity annotations */}}
{{- if .Values.kubernetesFlavorConfig.gke.workloadIdentity.enabled }}
iam.gke.io/gcp-service-account: {{ .Values.kubernetesFlavorConfig.gke.workloadIdentity.serviceAccount | quote }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create network policy based on platform capabilities
*/}}
{{- define "mcp-platform.networkPolicyEnabled" -}}
{{- if .Values.networkPolicy.enabled }}
{{- if eq (include "mcp-platform.isOpenShift" .) "true" }}
{{- print "true" }}
{{- else if .Capabilities.APIVersions.Has "networking.k8s.io/v1/NetworkPolicy" }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- end }}

{{/*
Create PodSecurityPolicy or Pod Security Standards based on K8s version
*/}}
{{- define "mcp-platform.podSecurityPolicy" -}}
{{- if semverCompare "<1.25.0" .Capabilities.KubeVersion.Version }}
{{- if .Values.security.podSecurityPolicy.enabled }}
{{- if .Capabilities.APIVersions.Has "policy/v1beta1/PodSecurityPolicy" }}
{{- print "true" }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- else }}
{{- print "false" }}
{{- end }}
{{- else }}
{{/* Use Pod Security Standards for K8s 1.25+ */}}
{{- print "false" }}
{{- end }}
{{- end }}

{{/*
Create storage class annotation based on platform
*/}}
{{- define "mcp-platform.storageClassAnnotation" -}}
{{- $platform := include "mcp-platform.detectPlatform" . }}
{{- if eq $platform "openshift" }}
volume.beta.kubernetes.io/storage-class: {{ include "mcp-platform.storageClass" . }}
{{- else if eq $platform "eks" }}
{{- if .Values.kubernetesFlavorConfig.eks.ebs.enabled }}
volume.beta.kubernetes.io/storage-class: {{ include "mcp-platform.storageClass" . }}
ebs.csi.aws.com/encrypted: "{{ .Values.kubernetesFlavorConfig.eks.ebs.encrypted }}"
{{- end }}
{{- else if eq $platform "aks" }}
{{- if .Values.kubernetesFlavorConfig.aks.disk.enabled }}
volume.beta.kubernetes.io/storage-class: {{ include "mcp-platform.storageClass" . }}
kubernetes.azure.com/scalesetpriority: {{ .Values.kubernetesFlavorConfig.aks.disk.priority | default "regular" }}
{{- end }}
{{- else if eq $platform "gke" }}
{{- if .Values.kubernetesFlavorConfig.gke.disk.enabled }}
volume.beta.kubernetes.io/storage-class: {{ include "mcp-platform.storageClass" . }}
{{- end }}
{{- else }}
volume.beta.kubernetes.io/storage-class: {{ include "mcp-platform.storageClass" . }}
{{- end }}
{{- end }}

{{/*
Create ingress annotations based on platform
*/}}
{{- define "mcp-platform.ingressAnnotations" -}}
{{- $platform := include "mcp-platform.detectPlatform" . }}
{{- if eq $platform "eks" }}
{{- if .Values.kubernetesFlavorConfig.eks.alb.enabled }}
kubernetes.io/ingress.class: alb
alb.ingress.kubernetes.io/scheme: {{ .Values.kubernetesFlavorConfig.eks.alb.scheme | default "internet-facing" }}
alb.ingress.kubernetes.io/target-type: {{ .Values.kubernetesFlavorConfig.eks.alb.targetType | default "ip" }}
{{- if .Values.kubernetesFlavorConfig.eks.alb.certificateArn }}
alb.ingress.kubernetes.io/certificate-arn: {{ .Values.kubernetesFlavorConfig.eks.alb.certificateArn }}
alb.ingress.kubernetes.io/ssl-policy: {{ .Values.kubernetesFlavorConfig.eks.alb.sslPolicy | default "ELBSecurityPolicy-TLS-1-2-2017-01" }}
{{- end }}
{{- end }}
{{- else if eq $platform "aks" }}
{{- if .Values.kubernetesFlavorConfig.aks.appGateway.enabled }}
kubernetes.io/ingress.class: azure/application-gateway
appgw.ingress.kubernetes.io/ssl-redirect: "{{ .Values.kubernetesFlavorConfig.aks.appGateway.sslRedirect }}"
{{- end }}
{{- else if eq $platform "gke" }}
{{- if .Values.kubernetesFlavorConfig.gke.gce.enabled }}
kubernetes.io/ingress.class: gce
{{- if .Values.kubernetesFlavorConfig.gke.gce.staticIp }}
kubernetes.io/ingress.global-static-ip-name: {{ .Values.kubernetesFlavorConfig.gke.gce.staticIp }}
{{- end }}
{{- end }}
{{- else }}
{{- if .Values.ingress.className }}
kubernetes.io/ingress.class: {{ .Values.ingress.className }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create resource quotas based on platform
*/}}
{{- define "mcp-platform.resourceQuota" -}}
{{- $platform := include "mcp-platform.detectPlatform" . }}
{{- if .Values.resourceQuota.enabled }}
{{- if eq $platform "openshift" }}
{{- if .Values.kubernetesFlavorConfig.openshift.quotas }}
{{- toYaml .Values.kubernetesFlavorConfig.openshift.quotas }}
{{- end }}
{{- else }}
{{- if .Values.resourceQuota.hard }}
{{- toYaml .Values.resourceQuota.hard }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create monitoring annotations based on platform
*/}}
{{- define "mcp-platform.monitoringAnnotations" -}}
{{- if .Values.monitoring.enabled }}
prometheus.io/scrape: "true"
prometheus.io/port: "{{ .Values.monitoring.port | default 8080 }}"
prometheus.io/path: "{{ .Values.monitoring.path | default "/metrics" }}"
{{- if eq (include "mcp-platform.isOpenShift" .) "true" }}
{{- if .Values.monitoring.openshift.enabled }}
{{- range $key, $value := .Values.monitoring.openshift.annotations }}
{{ $key }}: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}