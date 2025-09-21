# Fortress Intelligent Scan Orchestration Workflow

## 🎯 **PROGRESSIVE SECURITY ANALYSIS**

### **Phase 1: Reconnaissance (Local)**
```
Fortress → Target K8s API → Discover images in namespace
Fortress → Private Registry → Pull images locally  
Fortress → Local SYFT → Generate SBOM
Fortress → Local Trivy → Vulnerability scan
Result → Initial vulnerability assessment
```

### **Phase 2: Discovery (Agent-Based)**
```
IF vulnerabilities found:
  Performance Check → Agent → kube-bench (CIS compliance)
  Performance Check → Agent → Polaris (configuration issues)
  Agent → Harbor → Pull security tools
  Agent → Scan → Send results to Fortress
```

### **Phase 3: Assessment (Deep Analysis)**
```  
IF critical vulnerabilities:
  Performance Check → Agent → Falco (runtime monitoring)
  Performance Check → Agent → Tetragon (BPF analysis)
  Performance Check → Agent → Network analysis
  Agent → Real-time monitoring → Send telemetry
```

### **Phase 4: Validation (Controlled Exploitation)**
```
IF high exploitability score:
  Fortress → Create sandbox environment
  Fortress → Safe exploit validation (Log4Shell, DirtyPipe, etc)
  Fortress → Risk validation report
  Fortress → Remediation recommendations
```

## 🔧 **PERFORMANCE-AWARE ORCHESTRATION**

### **Cluster Impact Management:**
- **CPU Threshold**: <70% usage before new scans
- **Memory Threshold**: <80% usage before new scans  
- **Scan Spacing**: 5 minutes between tool launches
- **Concurrency**: Max 2 scans per cluster
- **Auto-Delay**: 5 min delay if thresholds exceeded

### **Progressive Escalation Logic:**
```python
if vulnerabilities > 0:
    → Schedule configuration scans
if critical_vulnerabilities > 0:  
    → Schedule runtime monitoring
if exploitability_score > 7.0:
    → Schedule controlled validation
```

## 📡 **API INTEGRATION FLOW**

### **New Tenant Analysis:**
```bash
POST /analyze/tenant
{
  "cluster_name": "prod-east",
  "namespace": "tenant01", 
  "tenant_id": "customer-123"
}
```

### **Performance Check:**
```bash
GET /performance/prod-east/tenant01
{
  "cpu_usage": 0.65,
  "memory_usage": 0.72,
  "scan_ready": true
}
```

### **Exploit Validation:**
```bash  
POST /exploit/validate
{
  "tenant_id": "customer-123",
  "cve_id": "CVE-2021-44228",
  "cluster": "prod-east"
}
```

## 🚀 **DEPLOYMENT**

1. **Deploy Orchestrator**: `kubectl apply -f orchestrator-deployment.yaml`
2. **Start Analysis**: Call `/analyze/tenant` API
3. **Monitor Progress**: Check `/status/{tenant_id}`
4. **Review Results**: Fortress dashboard integration

## 💡 **KEY BENEFITS**

✅ **Non-Disruptive**: Performance-aware scheduling  
✅ **Progressive**: Escalates based on findings
✅ **Intelligent**: Local scans reduce cluster load
✅ **Safe**: Controlled exploit validation only
✅ **Scalable**: Handles multiple tenants/clusters
