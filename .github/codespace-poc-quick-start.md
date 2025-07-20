# MCP Security Platform - GitHub Codespaces Quick Start

## 🚀 **One-Command Setup for GitHub Codespaces**

This POC is optimized specifically for GitHub Codespaces with minimal resource usage and fast deployment.

### **Prerequisites**
- GitHub Codespace (2-core, 8GB recommended)
- All tools are pre-installed in the devcontainer

### **Quick Start (5 minutes)**

```bash
# 1. Navigate to project directory
cd mcp-security-platform/

# 2. Run the optimized setup script
./scripts/codespace-setup.sh

# 3. Run the demo (once setup completes)
./scripts/demo-poc.sh
```

### **What Gets Deployed**

**Lightweight Services (Optimized for Codespaces):**
- API Gateway (64Mi RAM, 50m CPU)
- Auth Service (64Mi RAM, 50m CPU)  
- Ingestion Service (64Mi RAM, 50m CPU)
- Enrichment Service (64Mi RAM, 50m CPU)
- Analysis Service (64Mi RAM, 50m CPU)

**Minimal Data Layer:**
- PostgreSQL (128Mi RAM, no persistence)
- Redis (64Mi RAM, no persistence)
- No Prometheus/Grafana (saves 1GB+ RAM)

### **Configuration Details**

**Resource Allocation:**
- Total RAM usage: ~500Mi (fits in 8GB Codespace)
- Total CPU usage: ~300m (fits in 2-core Codespace)
- No persistent storage (fast startup)
- 5-minute deployment timeout

**POC Features:**
- Sample SBOM with 4 critical vulnerabilities
- AI-powered risk assessment simulation
- Compliance mapping (SOC2, ISO27001)
- Executive-level reporting
- Interactive dashboard

### **Access URLs**

Once deployed, access the platform at:
- **API Gateway**: http://localhost:8000
- **Auth Service**: http://localhost:8001
- **Core Services**: http://localhost:8080
- **Health Checks**: All services have `/health` endpoints

### **Demo Credentials**
- **Username**: admin
- **Password**: admin123

### **Troubleshooting**

**If deployment times out:**
```bash
# Check pod status
kubectl get pods -n mcp-security

# Check resource usage
kubectl top nodes

# Force continue with partial deployment
kubectl port-forward -n mcp-security svc/mcp-platform-gateway 8000:8000 &
```

**If services don't respond:**
```bash
# Manual port forwarding
kubectl port-forward -n mcp-security svc/mcp-platform-auth 8001:8001 &
kubectl port-forward -n mcp-security svc/mcp-platform-correlation 8080:8080 &
```

**Resource constraints:**
```bash
# Scale down if needed
kubectl scale deployment mcp-platform-postgresql --replicas=0 -n mcp-security
kubectl scale deployment mcp-platform-redis-master --replicas=0 -n mcp-security
```

### **Demo Flow**

The demo script will:
1. ✅ Verify all services are running
2. ✅ Authenticate with the platform
3. ✅ Upload vulnerable SBOM (Express, Lodash, Axios, Nginx)
4. ✅ Trigger AI risk assessment
5. ✅ Display critical vulnerabilities (Log4Shell, SSRF, etc.)
6. ✅ Show compliance impact and remediation plan
7. ✅ Generate executive summary report

### **Expected Output**

**Risk Assessment Results:**
- Overall Risk Score: 8.7/10 (CRITICAL)
- Critical Vulnerabilities: 2
- High Vulnerabilities: 2
- Compliance Impact: HIGH (SOC2, ISO27001)
- Remediation Timeline: 24-48 hours for critical fixes

### **Performance Expectations**

**Codespace Performance:**
- Setup time: ~3-5 minutes
- Demo execution: ~2-3 minutes
- Memory usage: ~500Mi total
- Startup time: ~60 seconds for all services

### **Next Steps**

After successful POC:
1. Explore the interactive dashboard
2. Test API endpoints with Postman/curl
3. Upload additional SBOM files
4. Review generated risk reports
5. Experiment with different vulnerability scenarios

### **Support**

If you encounter issues:
1. Check the troubleshooting section above
2. Review pod logs: `kubectl logs -f deployment/mcp-platform-gateway -n mcp-security`
3. Verify resource constraints: `kubectl describe nodes`

**Enjoy exploring the MCP Security Platform! 🛡️**