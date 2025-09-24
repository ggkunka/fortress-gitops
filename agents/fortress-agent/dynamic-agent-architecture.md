# 🛡️ Fortress Dynamic Security Agent Architecture

## 🎯 OVERVIEW
**On-Demand Security Orchestrator** deployed with cluster-level permissions, capable of dynamically running security tools across any pod in the cluster.

## 🏗️ DYNAMIC AGENT ARCHITECTURE

### Core Agent Components
```
Fortress Agent (Privileged Pod)
├── Security Tool Orchestrator     # Manages tool lifecycle
├── Cluster Scanner Controller     # Schedules and executes scans
├── Tool Container Manager         # Deploys tools as sidecar/jobs
├── Results Aggregator            # Collects and normalizes results
├── Communication Handler         # mTLS to Fortress platform
└── RBAC Policy Manager          # Manages cluster permissions
```

### Agent Deployment Model
- **Single Agent Pod**: One privileged agent per cluster
- **Cluster Admin Permissions**: Full cluster read/write access
- **Tool Execution**: On-demand deployment of security tools
- **Resource Management**: Dynamic resource allocation per scan

## 🔧 ON-DEMAND TOOL EXECUTION

### 1. SBOM & CVE Scanning
**Tools**: Syft, Grype, Trivy, Dockle, cve-check-tool
- **Trigger**: API request, scheduled scan, CI/CD webhook
- **Execution**: Deploy scanner as Job targeting specific pods/images
- **Scope**: Individual containers, entire deployments, or cluster-wide
- **Output**: SBOM files, vulnerability reports, compliance status

### 2. Runtime Detection
**Tools**: Falco, eBPF, Tetragon, Sysdig OSS  
- **Trigger**: Security incident, compliance audit, threat hunting
- **Execution**: Deploy runtime monitor as DaemonSet for duration
- **Scope**: Specific namespaces, workloads, or cluster-wide
- **Output**: Runtime behavior analysis, syscall monitoring, threat detection

### 3. Misconfiguration Detection
**Tools**: kube-bench, kube-hunter, Polaris, rakkess
- **Trigger**: Configuration change, compliance check, audit request
- **Execution**: Deploy as Jobs with cluster-reader permissions
- **Scope**: Cluster configuration, specific namespaces, RBAC analysis
- **Output**: CIS benchmark results, security misconfigurations, privilege analysis

### 4. Secrets & Credentials
**Tools**: Gitleaks, TruffleHog
- **Trigger**: Code deployment, security audit, incident response
- **Execution**: Scan ConfigMaps, Secrets, mounted volumes
- **Scope**: Specific namespaces, all secrets, or targeted resources
- **Output**: Exposed credentials, secret leakage, compliance violations

### 5. Network Visibility
**Tools**: Cilium Hubble, Netobserv, Suricata
- **Trigger**: Network incident, traffic analysis, compliance monitoring
- **Execution**: Deploy network monitoring pods with host network access
- **Scope**: Specific services, entire namespaces, or cluster traffic
- **Output**: Network topology, traffic flows, security violations

### 6. Compliance & Policy Enforcement
**Tools**: OpenSCAP, OPA, Gatekeeper
- **Trigger**: Compliance audit, policy validation, regulatory check
- **Execution**: Deploy compliance scanners as Jobs
- **Scope**: Node-level compliance, pod policies, cluster governance
- **Output**: Compliance reports, policy violations, remediation recommendations

### 7. Simulated Attacks & BAS (Breach Attack Simulation)
**Tools**: Atomic Red Team, Metasploit, Pacu
- **Trigger**: Security testing, red team exercises, resilience testing
- **Execution**: Deploy attack simulation pods in isolated namespaces
- **Scope**: Controlled attack scenarios, specific attack vectors
- **Output**: Attack simulation results, defense effectiveness, security gaps

## 🚀 AGENT IMPLEMENTATION

### Agent Controller Service
```python
class FortressAgentController:
    def __init__(self):
        self.k8s_client = kubernetes.client.ApiClient()
        self.tool_registry = SecurityToolRegistry()
        self.scan_scheduler = ScanScheduler()
        self.result_collector = ResultCollector()
    
    async def execute_scan(self, scan_request: ScanRequest):
        """Execute on-demand security scan"""
        tool = self.tool_registry.get_tool(scan_request.tool_name)
        job_manifest = tool.generate_job_manifest(scan_request)
        
        # Deploy security tool as Kubernetes Job
        job = await self.k8s_client.create_namespaced_job(
            namespace=scan_request.target_namespace,
            body=job_manifest
        )
        
        # Monitor execution and collect results
        results = await self.monitor_and_collect_results(job)
        
        # Send results to Fortress platform
        await self.send_results_to_platform(results)
        
        return results
```

### Tool Registry
```python
class SecurityToolRegistry:
    TOOLS = {
        'trivy': TrivyScanner(),
        'falco': FalcoMonitor(), 
        'kube-bench': KubeBenchScanner(),
        'gitleaks': GitleaksScanner(),
        'atomic-red-team': AtomicRedTeam(),
        # ... all security tools
    }
    
    def get_tool(self, tool_name: str) -> SecurityTool:
        return self.TOOLS.get(tool_name)
```

### Dynamic Job Deployment
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: fortress-trivy-scan-{{scan-id}}
  namespace: {{target-namespace}}
spec:
  template:
    spec:
      serviceAccountName: fortress-scanner
      containers:
      - name: trivy-scanner
        image: aquasec/trivy:latest
        command: ["trivy"]
        args: ["image", "{{target-image}}", "--format", "json"]
        volumeMounts:
        - name: results
          mountPath: /results
      restartPolicy: Never
      volumes:
      - name: results
        emptyDir: {}
```

## 🔐 CLUSTER PERMISSIONS

### RBAC Configuration
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: fortress-agent
rules:
# Full cluster access for comprehensive security scanning
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
# Additional security-specific permissions
- apiGroups: ["security.istio.io"]
  resources: ["*"]
  verbs: ["*"]
- nonResourceURLs: ["/metrics", "/logs"]
  verbs: ["get"]
```

### Security Context
```yaml
securityContext:
  privileged: true              # Required for eBPF and host access
  runAsUser: 0                 # Root access for system scanning
  capabilities:
    add: ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE"]
  hostNetwork: true            # Network visibility
  hostPID: true               # Process monitoring
  hostIPC: true               # IPC monitoring
```

## 📊 ON-DEMAND EXECUTION API

### Scan Request Format
```json
{
  "scan_id": "scan-fortress-001",
  "tool_category": "sbom_cve_scanning",
  "tool_name": "trivy",
  "target_type": "deployment",
  "target_identifier": "nginx-deployment",
  "target_namespace": "production", 
  "scan_parameters": {
    "severity": ["CRITICAL", "HIGH"],
    "output_format": "json",
    "include_sbom": true
  },
  "scheduling": {
    "trigger": "on_demand",
    "priority": "high",
    "timeout": "30m"
  }
}
```

### Platform Integration API
```python
@app.post("/agent/execute-scan")
async def execute_security_scan(scan_request: ScanRequest):
    """Execute on-demand security scan via agent"""
    
    scan_job = await agent_controller.execute_scan(scan_request)
    
    return {
        "scan_id": scan_request.scan_id,
        "status": "executing",
        "job_id": scan_job.metadata.name,
        "estimated_duration": "15m"
    }

@app.get("/agent/scan-status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get real-time scan execution status"""
    
    status = await agent_controller.get_scan_status(scan_id)
    
    return {
        "scan_id": scan_id,
        "status": status.phase,
        "progress": status.progress_percentage,
        "results_available": status.completed,
        "next_poll_interval": "30s"
    }
```

## 🎯 ADVANTAGES OF ON-DEMAND APPROACH

### Resource Efficiency
- **No Continuous Overhead**: Tools only consume resources when needed
- **Dynamic Scaling**: Resources allocated based on scan complexity
- **Cost Optimization**: Reduced infrastructure costs vs always-on monitoring

### Security Benefits
- **Reduced Attack Surface**: Tools not permanently deployed
- **Fresh Tool Versions**: Always use latest security tool images
- **Controlled Execution**: Scans triggered by security events or policies

### Operational Excellence
- **Flexibility**: Add new tools without agent redeployment
- **Scalability**: Handle multiple concurrent scans across clusters
- **Compliance**: On-demand compliance checks for audits

This architecture transforms Fortress into a **dynamic security orchestration platform** that can execute comprehensive security assessments across any Kubernetes cluster on-demand, making it more efficient and powerful than traditional always-on security agents. 🚀
