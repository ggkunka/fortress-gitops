#!/usr/bin/env python3
"""
Fortress Dynamic Security Agent - On-Demand Tool Orchestrator
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from kubernetes import client, config
import structlog

logger = structlog.get_logger()

class ScanRequest(BaseModel):
    scan_id: str
    tool_name: str  # trivy, falco, kube-bench, gitleaks, etc.
    target_type: str  # pod, deployment, namespace, cluster
    target_identifier: str
    target_namespace: str = "default"
    scan_parameters: Dict[str, Any] = {}

class FortressAgent:
    def __init__(self):
        config.load_incluster_config()
        self.k8s_batch = client.BatchV1Api()
        self.k8s_core = client.CoreV1Api()
        self.active_scans = {}
        
    async def execute_scan(self, scan_request: ScanRequest):
        """Execute on-demand security scan"""
        try:
            job_manifest = self.generate_job_manifest(scan_request)
            
            # Create Kubernetes Job
            job = self.k8s_batch.create_namespaced_job(
                namespace=scan_request.target_namespace,
                body=job_manifest
            )
            
            self.active_scans[scan_request.scan_id] = {
                "job_name": job.metadata.name,
                "status": "running",
                "start_time": datetime.now()
            }
            
            logger.info(f"Started scan {scan_request.scan_id} with tool {scan_request.tool_name}")
            return {"status": "started", "job_name": job.metadata.name}
            
        except Exception as e:
            logger.error(f"Failed to start scan: {e}")
            return {"status": "failed", "error": str(e)}
    
    def generate_job_manifest(self, scan_request: ScanRequest) -> Dict[str, Any]:
        """Generate job manifest based on tool type"""
        
        tool_configs = {
            # SBOM & CVE Scanning
            "syft": {
                "image": "anchore/syft:latest",
                "command": ["syft", scan_request.target_identifier, "-o", "json"]
            },
            "grype": {
                "image": "anchore/grype:latest", 
                "command": ["grype", scan_request.target_identifier, "-o", "json"]
            },
            "trivy": {
                "image": "aquasec/trivy:latest",
                "command": ["trivy", "image", scan_request.target_identifier, "--format", "json"]
            },
            "dockle": {
                "image": "goodwithtech/dockle:latest",
                "command": ["dockle", "--format", "json", scan_request.target_identifier]
            },
            "cve-check-tool": {
                "image": "clearlinux/cve-check-tool:latest",
                "command": ["cve-check-update", "&&", "cve-check", scan_request.target_identifier]
            },
            
            # Runtime Detection  
            "falco": {
                "image": "falcosecurity/falco-no-driver:latest",
                "command": ["falco", "--modern-bpf", "--duration=300"],
                "privileged": True,
                "host_network": True
            },
            "tetragon": {
                "image": "quay.io/cilium/tetragon:latest",
                "command": ["tetragon", "--export-filename", "/results/tetragon-events.json"],
                "privileged": True,
                "host_pid": True
            },
            "sysdig": {
                "image": "sysdig/sysdig:latest",
                "command": ["sysdig", "-j", "-w", "/results/sysdig-capture.json"],
                "privileged": True,
                "host_pid": True
            },
            
            # Misconfiguration Detection
            "kube-bench": {
                "image": "aquasec/kube-bench:latest", 
                "command": ["kube-bench", "--json"],
                "privileged": True,
                "host_mounts": True
            },
            "kube-hunter": {
                "image": "aquasec/kube-hunter:latest",
                "command": ["kube-hunter", "--report", "json", "--log", "none"]
            },
            "polaris": {
                "image": "quay.io/fairwinds/polaris:latest",
                "command": ["polaris", "audit", "--format", "json"]
            },
            "rakkess": {
                "image": "corneliusweig/rakkess:latest",
                "command": ["rakkess", "resource", "--output", "json"]
            },
            
            # Secrets & Credentials
            "gitleaks": {
                "image": "zricethezav/gitleaks:latest",
                "command": ["gitleaks", "detect", "--source", "/workspace", "--format", "json"]
            },
            "trufflehog": {
                "image": "trufflesecurity/trufflehog:latest",
                "command": ["trufflehog", "filesystem", "/workspace", "--json"]
            },
            
            # Network Visibility
            "cilium-hubble": {
                "image": "quay.io/cilium/hubble:latest",
                "command": ["hubble", "observe", "--output", "json", "--follow=false"],
                "host_network": True
            },
            "netobserv": {
                "image": "quay.io/netobserv/network-observability-operator:latest",
                "command": ["netobserv-cli", "capture", "--output", "json"],
                "host_network": True,
                "privileged": True
            },
            "suricata": {
                "image": "suricata/suricata:latest",
                "command": ["suricata", "-c", "/etc/suricata/suricata.yaml", "-i", "any"],
                "privileged": True,
                "host_network": True
            },
            
            # Compliance, Licensing, and Policy Enforcement
            "openscap": {
                "image": "quay.io/compliance-operator/openscap:latest",
                "command": ["oscap", "xccdf", "eval", "--results", "/results/openscap-results.xml"],
                "privileged": True,
                "host_mounts": True
            },
            "opa": {
                "image": "openpolicyagent/opa:latest",
                "command": ["opa", "test", "/policies", "--format", "json"]
            },
            "gatekeeper": {
                "image": "openpolicyagent/gatekeeper:latest",
                "command": ["gatekeeper-audit", "--operation-mode=webhook", "--audit-interval=60"]
            },
            
            # Simulated Attacks / BAS
            "atomic-red-team": {
                "image": "redcanaryco/atomic-red-team:latest",
                "command": ["pwsh", "-Command", "Invoke-AtomicTest", "T1059.001", "-GetPrereqs"],
                "privileged": True
            },
            "metasploit": {
                "image": "metasploitframework/metasploit-framework:latest",
                "command": ["msfconsole", "-x", "use auxiliary/scanner/discovery/udp_sweep; set RHOSTS", scan_request.target_identifier, "; run; exit"],
                "privileged": True,
                "host_network": True
            },
            "pacu": {
                "image": "rhinosecuritylabs/pacu:latest",
                "command": ["pacu", "--session", scan_request.scan_id, "--data-dir", "/results"]
            }
        }
        
        config = tool_configs.get(scan_request.tool_name, tool_configs["trivy"])
        
        # Add host mounts for tools that need them
        volumes = [{"name": "results", "emptyDir": {}}]
        volume_mounts = [{"name": "results", "mountPath": "/results"}]
        
        if config.get("host_mounts"):
            volumes.extend([
                {"name": "var-lib-etcd", "hostPath": {"path": "/var/lib/etcd"}},
                {"name": "var-lib-kubelet", "hostPath": {"path": "/var/lib/kubelet"}},
                {"name": "etc-kubernetes", "hostPath": {"path": "/etc/kubernetes"}},
                {"name": "proc", "hostPath": {"path": "/proc"}},
                {"name": "boot", "hostPath": {"path": "/boot"}},
                {"name": "lib-modules", "hostPath": {"path": "/lib/modules"}}
            ])
            volume_mounts.extend([
                {"name": "var-lib-etcd", "mountPath": "/var/lib/etcd", "readOnly": True},
                {"name": "var-lib-kubelet", "mountPath": "/var/lib/kubelet", "readOnly": True},
                {"name": "etc-kubernetes", "mountPath": "/etc/kubernetes", "readOnly": True},
                {"name": "proc", "mountPath": "/host/proc", "readOnly": True},
                {"name": "boot", "mountPath": "/host/boot", "readOnly": True},
                {"name": "lib-modules", "mountPath": "/host/lib/modules", "readOnly": True}
            ])

        return {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {
                "name": f"fortress-{scan_request.tool_name}-{scan_request.scan_id}",
                "namespace": scan_request.target_namespace,
                "labels": {
                    "fortress.scan.id": scan_request.scan_id,
                    "fortress.tool": scan_request.tool_name,
                    "fortress.target": scan_request.target_type
                }
            },
            "spec": {
                "template": {
                    "spec": {
                        "serviceAccountName": "fortress-scanner",
                        "restartPolicy": "Never",
                        "hostNetwork": config.get("host_network", False),
                        "hostPID": config.get("host_pid", False),
                        "containers": [{
                            "name": f"{scan_request.tool_name}-scanner",
                            "image": config["image"],
                            "command": config["command"],
                            "volumeMounts": volume_mounts,
                            "securityContext": {
                                "privileged": config.get("privileged", False),
                                "runAsUser": 0 if config.get("privileged") else 1000,
                                "capabilities": {
                                    "add": ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"] if config.get("privileged") else []
                                }
                            },
                            "resources": {
                                "requests": {"memory": "256Mi", "cpu": "100m"},
                                "limits": {"memory": "1Gi", "cpu": "500m"}
                            }
                        }],
                        "volumes": volumes,
                        "activeDeadlineSeconds": 1800  # 30 minute timeout
                    }
                },
                "backoffLimit": 1
            }
        }

# FastAPI Application
app = FastAPI(title="Fortress Dynamic Security Agent", version="1.0.0")
agent = FortressAgent()

@app.post("/scan/execute")
async def execute_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Execute on-demand security scan"""
    background_tasks.add_task(agent.execute_scan, scan_request)
    return {"message": f"Scan {scan_request.scan_id} initiated"}

@app.get("/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get scan execution status"""
    return agent.active_scans.get(scan_id, {"status": "not_found"})

@app.get("/tools/available")
async def list_available_tools():
    """List all available security tools by category"""
    return {
        "categories": {
            "sbom_cve_scanning": {
                "description": "Software Bill of Materials & CVE Vulnerability Scanning",
                "tools": [
                    {"name": "syft", "description": "Generate SBOM for container images"},
                    {"name": "grype", "description": "Vulnerability scanner using Anchore engine"},
                    {"name": "trivy", "description": "Container vulnerability and misconfiguration scanner"},
                    {"name": "dockle", "description": "Container image linter for security best practices"},
                    {"name": "cve-check-tool", "description": "CVE vulnerability checker"}
                ]
            },
            "runtime_detection": {
                "description": "Runtime Security and Behavioral Monitoring", 
                "tools": [
                    {"name": "falco", "description": "Runtime security monitoring with eBPF/kernel modules"},
                    {"name": "tetragon", "description": "eBPF-based security observability and enforcement"},
                    {"name": "sysdig", "description": "System-level monitoring and forensics"}
                ]
            },
            "misconfig_detection": {
                "description": "Configuration Assessment and Compliance Scanning",
                "tools": [
                    {"name": "kube-bench", "description": "CIS Kubernetes benchmark scanner"},
                    {"name": "kube-hunter", "description": "Kubernetes penetration testing tool"},
                    {"name": "polaris", "description": "Kubernetes configuration validation"},
                    {"name": "rakkess", "description": "Kubernetes RBAC access reviewer"}
                ]
            },
            "secrets_credential": {
                "description": "Secret Detection and Credential Scanning",
                "tools": [
                    {"name": "gitleaks", "description": "Git repository secret scanner"},
                    {"name": "trufflehog", "description": "Credential scanner for multiple sources"}
                ]
            },
            "network_visibility": {
                "description": "Network Traffic Analysis and Monitoring",
                "tools": [
                    {"name": "cilium-hubble", "description": "Network observability with eBPF"},
                    {"name": "netobserv", "description": "OpenShift network observability"},
                    {"name": "suricata", "description": "Network intrusion detection system"}
                ]
            },
            "compliance_policy": {
                "description": "Compliance Assessment and Policy Enforcement",
                "tools": [
                    {"name": "openscap", "description": "Security compliance scanner (NIST, CIS)"},
                    {"name": "opa", "description": "Open Policy Agent for policy as code"},
                    {"name": "gatekeeper", "description": "Kubernetes admission control with OPA"}
                ]
            },
            "simulated_attacks": {
                "description": "Breach and Attack Simulation (BAS)",
                "tools": [
                    {"name": "atomic-red-team", "description": "MITRE ATT&CK framework testing"},
                    {"name": "metasploit", "description": "Penetration testing and exploitation framework"},
                    {"name": "pacu", "description": "AWS exploitation and post-exploitation framework"}
                ]
            }
        },
        "total_tools": 23,
        "execution_model": "on_demand_only",
        "default_timeout": "30m",
        "supported_targets": ["pod", "deployment", "namespace", "cluster", "image"]
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "agent": "fortress-dynamic-security"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
