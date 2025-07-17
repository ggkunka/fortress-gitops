"""Kubernetes configuration for the MCP Security Assessment Platform."""

from typing import Dict, List, Optional
from pydantic import Field
from .base import BaseConfig


class KubernetesConfig(BaseConfig):
    """Kubernetes configuration settings."""
    
    # Cluster settings
    k8s_config_file: Optional[str] = Field(default=None, description="Kubernetes config file path")
    k8s_context: Optional[str] = Field(default=None, description="Kubernetes context")
    k8s_namespace: str = Field(default="mcp-security", description="Kubernetes namespace")
    k8s_cluster_name: Optional[str] = Field(default=None, description="Kubernetes cluster name")
    
    # API settings
    k8s_api_server: Optional[str] = Field(default=None, description="Kubernetes API server URL")
    k8s_api_version: str = Field(default="v1", description="Kubernetes API version")
    k8s_request_timeout: int = Field(default=30, description="API request timeout in seconds")
    k8s_retry_count: int = Field(default=3, description="API retry count")
    
    # Authentication settings
    k8s_token: Optional[str] = Field(default=None, description="Kubernetes service account token")
    k8s_cert_file: Optional[str] = Field(default=None, description="Kubernetes client certificate file")
    k8s_key_file: Optional[str] = Field(default=None, description="Kubernetes client key file")
    k8s_ca_file: Optional[str] = Field(default=None, description="Kubernetes CA certificate file")
    k8s_insecure: bool = Field(default=False, description="Skip TLS verification")
    
    # Service account settings
    k8s_service_account: str = Field(default="mcp-security-sa", description="Service account name")
    k8s_service_account_namespace: Optional[str] = Field(default=None, description="Service account namespace")
    
    # RBAC settings
    k8s_rbac_enabled: bool = Field(default=True, description="Enable RBAC")
    k8s_cluster_role: str = Field(default="mcp-security-cluster-role", description="Cluster role name")
    k8s_role_binding: str = Field(default="mcp-security-role-binding", description="Role binding name")
    
    # Resource settings
    k8s_resource_quotas: Dict[str, str] = Field(
        default={
            "requests.cpu": "1000m",
            "requests.memory": "2Gi",
            "limits.cpu": "2000m",
            "limits.memory": "4Gi",
        },
        description="Resource quotas"
    )
    
    k8s_limit_ranges: Dict[str, Dict[str, str]] = Field(
        default={
            "default": {
                "cpu": "100m",
                "memory": "128Mi",
            },
            "defaultRequest": {
                "cpu": "50m",
                "memory": "64Mi",
            },
            "max": {
                "cpu": "1000m",
                "memory": "1Gi",
            },
        },
        description="Limit ranges"
    )
    
    # Network policy settings
    k8s_network_policies_enabled: bool = Field(default=True, description="Enable network policies")
    k8s_default_deny_all: bool = Field(default=True, description="Default deny all network policy")
    
    # Security context settings
    k8s_pod_security_context: Dict[str, any] = Field(
        default={
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "fsGroup": 1000,
            "seccompProfile": {
                "type": "RuntimeDefault"
            }
        },
        description="Pod security context"
    )
    
    k8s_container_security_context: Dict[str, any] = Field(
        default={
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "capabilities": {
                "drop": ["ALL"]
            }
        },
        description="Container security context"
    )
    
    # Pod security standards
    k8s_pod_security_standards: str = Field(default="restricted", description="Pod security standards")
    k8s_admission_controller_enabled: bool = Field(default=True, description="Enable admission controller")
    
    # Ingress settings
    k8s_ingress_enabled: bool = Field(default=True, description="Enable ingress")
    k8s_ingress_class: str = Field(default="nginx", description="Ingress class")
    k8s_ingress_annotations: Dict[str, str] = Field(
        default={
            "nginx.ingress.kubernetes.io/ssl-redirect": "true",
            "nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
            "nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
        },
        description="Ingress annotations"
    )
    
    # Storage settings
    k8s_storage_class: str = Field(default="standard", description="Storage class")
    k8s_persistent_volume_size: str = Field(default="10Gi", description="Persistent volume size")
    k8s_backup_enabled: bool = Field(default=True, description="Enable backup")
    k8s_backup_schedule: str = Field(default="0 2 * * *", description="Backup schedule (cron)")
    
    # Monitoring settings
    k8s_monitoring_enabled: bool = Field(default=True, description="Enable monitoring")
    k8s_metrics_server_enabled: bool = Field(default=True, description="Enable metrics server")
    k8s_prometheus_enabled: bool = Field(default=True, description="Enable Prometheus")
    k8s_grafana_enabled: bool = Field(default=True, description="Enable Grafana")
    
    # Logging settings
    k8s_logging_enabled: bool = Field(default=True, description="Enable logging")
    k8s_log_level: str = Field(default="INFO", description="Log level")
    k8s_log_format: str = Field(default="json", description="Log format")
    
    # Autoscaling settings
    k8s_hpa_enabled: bool = Field(default=True, description="Enable HPA")
    k8s_hpa_min_replicas: int = Field(default=2, description="HPA minimum replicas")
    k8s_hpa_max_replicas: int = Field(default=10, description="HPA maximum replicas")
    k8s_hpa_target_cpu: int = Field(default=70, description="HPA target CPU utilization")
    k8s_hpa_target_memory: int = Field(default=80, description="HPA target memory utilization")
    
    # Multi-cluster settings
    k8s_multi_cluster_enabled: bool = Field(default=False, description="Enable multi-cluster")
    k8s_cluster_configs: List[Dict[str, str]] = Field(
        default=[], description="Multi-cluster configurations"
    )
    
    # Kubernetes flavors
    k8s_flavor: str = Field(default="vanilla", description="Kubernetes flavor")
    k8s_version: str = Field(default="1.28.0", description="Kubernetes version")
    
    # OpenShift specific settings
    openshift_enabled: bool = Field(default=False, description="Enable OpenShift support")
    openshift_routes_enabled: bool = Field(default=False, description="Enable OpenShift routes")
    openshift_security_context_constraints: str = Field(
        default="restricted", description="OpenShift SCC"
    )
    
    # EKS specific settings
    eks_enabled: bool = Field(default=False, description="Enable EKS support")
    eks_cluster_name: Optional[str] = Field(default=None, description="EKS cluster name")
    eks_node_groups: List[str] = Field(default=[], description="EKS node groups")
    eks_fargate_enabled: bool = Field(default=False, description="Enable EKS Fargate")
    
    # AKS specific settings
    aks_enabled: bool = Field(default=False, description="Enable AKS support")
    aks_resource_group: Optional[str] = Field(default=None, description="AKS resource group")
    aks_cluster_name: Optional[str] = Field(default=None, description="AKS cluster name")
    aks_node_pools: List[str] = Field(default=[], description="AKS node pools")
    
    # GKE specific settings
    gke_enabled: bool = Field(default=False, description="Enable GKE support")
    gke_project_id: Optional[str] = Field(default=None, description="GKE project ID")
    gke_cluster_name: Optional[str] = Field(default=None, description="GKE cluster name")
    gke_zone: Optional[str] = Field(default=None, description="GKE zone")
    
    def get_client_config(self) -> dict:
        """Get Kubernetes client configuration."""
        config = {
            "config_file": self.k8s_config_file,
            "context": self.k8s_context,
            "api_server": self.k8s_api_server,
            "verify_ssl": not self.k8s_insecure,
        }
        
        if self.k8s_token:
            config["api_key"] = {"authorization": f"Bearer {self.k8s_token}"}
        
        if self.k8s_cert_file and self.k8s_key_file:
            config["cert_file"] = self.k8s_cert_file
            config["key_file"] = self.k8s_key_file
        
        if self.k8s_ca_file:
            config["ssl_ca_cert"] = self.k8s_ca_file
        
        return config
    
    def get_resource_requirements(self) -> dict:
        """Get resource requirements configuration."""
        return {
            "requests": {
                "cpu": self.k8s_resource_quotas.get("requests.cpu", "100m"),
                "memory": self.k8s_resource_quotas.get("requests.memory", "128Mi"),
            },
            "limits": {
                "cpu": self.k8s_resource_quotas.get("limits.cpu", "1000m"),
                "memory": self.k8s_resource_quotas.get("limits.memory", "1Gi"),
            },
        }
    
    def get_security_context(self) -> dict:
        """Get security context configuration."""
        return {
            "pod": self.k8s_pod_security_context,
            "container": self.k8s_container_security_context,
        }
    
    def get_hpa_config(self) -> dict:
        """Get HPA configuration."""
        return {
            "enabled": self.k8s_hpa_enabled,
            "min_replicas": self.k8s_hpa_min_replicas,
            "max_replicas": self.k8s_hpa_max_replicas,
            "target_cpu": self.k8s_hpa_target_cpu,
            "target_memory": self.k8s_hpa_target_memory,
        }
    
    def get_flavor_config(self) -> dict:
        """Get Kubernetes flavor-specific configuration."""
        config = {
            "flavor": self.k8s_flavor,
            "version": self.k8s_version,
        }
        
        if self.openshift_enabled:
            config["openshift"] = {
                "routes_enabled": self.openshift_routes_enabled,
                "scc": self.openshift_security_context_constraints,
            }
        
        if self.eks_enabled:
            config["eks"] = {
                "cluster_name": self.eks_cluster_name,
                "node_groups": self.eks_node_groups,
                "fargate_enabled": self.eks_fargate_enabled,
            }
        
        if self.aks_enabled:
            config["aks"] = {
                "resource_group": self.aks_resource_group,
                "cluster_name": self.aks_cluster_name,
                "node_pools": self.aks_node_pools,
            }
        
        if self.gke_enabled:
            config["gke"] = {
                "project_id": self.gke_project_id,
                "cluster_name": self.gke_cluster_name,
                "zone": self.gke_zone,
            }
        
        return config