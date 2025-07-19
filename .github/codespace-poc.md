# MCP Security Platform - Codespace POC Guide

Welcome to the MCP Security Platform Proof of Concept! This guide will walk you through the complete POC experience running in GitHub Codespaces.

## 🚀 Quick Start (5 Minutes to POC)

### Step 1: Launch Codespace

1. **Fork this repository** (if you haven't already)
2. **Click the green "Code" button** → **"Codespaces"** → **"Create codespace on main"**
3. **Wait for the environment to load** (2-3 minutes)
4. **The POC will auto-deploy** via postCreateCommand

When ready, you'll see:
```
🎉 MCP Security Platform POC is ready!
========================================

📍 Service Access URLs:
  🌐 API Gateway:     http://localhost:8000
  🔐 Auth Service:    http://localhost:8001  
  ⚙️  Core Services:   http://localhost:8080
  🗄️  MinIO Console:   http://localhost:9000
```

### Step 2: Verify Services

Open the terminal and run:
```bash
curl http://localhost:8000/health
curl http://localhost:8001/auth/health  
curl http://localhost:8080/health
```

All should return `{"status": "healthy"}`.

## 🧪 POC Walkthrough

### Architecture Overview

The POC includes:
- **Kind Kubernetes cluster** (local)
- **Core security services** (correlation, risk assessment, response)
- **Scanner plugins** (Trivy, Syft for SBOM)
- **Development databases** (PostgreSQL, Redis, MinIO)
- **RESTful APIs** with OpenAPI documentation

### API Endpoints to Test

#### 1. Health Checks
```bash
# Gateway health
curl http://localhost:8000/health

# Auth service health
curl http://localhost:8001/auth/health

# Core services health
curl http://localhost:8080/health
```

#### 2. Authentication
```bash
# Login (get JWT token)
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Example response:
# {"access_token": "eyJ...", "token_type": "bearer"}
```

#### 3. Security Scans
```bash
# Start a container scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "Demo Scan",
    "target": "alpine:3.17",
    "scanner": "trivy"
  }'

# List scan jobs
curl -X GET http://localhost:8000/api/v1/scans \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 4. SBOM Generation
```bash
# Generate SBOM
curl -X POST http://localhost:8000/api/v1/sbom \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "nginx:1.24",
    "format": "cyclone"
  }'
```

#### 5. Vulnerability Reports
```bash
# Get vulnerability summary
curl -X GET http://localhost:8000/api/v1/vulnerabilities/summary \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get detailed vulnerability report
curl -X GET http://localhost:8000/api/v1/vulnerabilities?severity=HIGH \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### 6. Compliance Checks
```bash
# Run compliance assessment
curl -X POST http://localhost:8000/api/v1/compliance/assess \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "framework": "NIST CSF",
    "target": "cluster"
  }'

# Get compliance status
curl -X GET http://localhost:8000/api/v1/compliance/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Sample Files for Testing

#### 1. Upload Sample SBOM
Create a test SBOM file:
```bash
cat > sample-sbom.json << 'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "serialNumber": "urn:uuid:demo-sbom-12345",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-19T10:00:00Z",
    "tools": [{"vendor": "MCP Security Platform", "name": "Demo Generator"}]
  },
  "components": [
    {
      "type": "library",
      "name": "openssl",
      "version": "1.1.1k",
      "purl": "pkg:generic/openssl@1.1.1k"
    },
    {
      "type": "library", 
      "name": "curl",
      "version": "7.68.0",
      "purl": "pkg:generic/curl@7.68.0"
    }
  ]
}
EOF

# Upload SBOM
curl -X POST http://localhost:8000/api/v1/sbom/upload \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@sample-sbom.json"
```

#### 2. Upload Sample CVE Report
```bash
cat > sample-cve.json << 'EOF'
{
  "scan_id": "demo-scan-001",
  "target": "alpine:3.17",
  "timestamp": "2024-01-19T10:00:00Z",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2023-1234",
      "severity": "HIGH",
      "score": 8.5,
      "package": "openssl",
      "version": "1.1.1k",
      "fixed_version": "1.1.1l",
      "description": "Demo vulnerability for POC testing"
    },
    {
      "cve_id": "CVE-2023-5678", 
      "severity": "MEDIUM",
      "score": 6.2,
      "package": "curl",
      "version": "7.68.0",
      "fixed_version": "7.68.1",
      "description": "Another demo vulnerability"
    }
  ]
}
EOF

# Upload CVE report
curl -X POST http://localhost:8000/api/v1/vulnerabilities/upload \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@sample-cve.json"
```

## 🔍 Exploring the Platform

### 1. Web UI Access
- **MinIO Console**: http://localhost:9000
  - Username: `minio_access_key`
  - Password: `minio_secret_key`

### 2. Database Access
```bash
# Connect to PostgreSQL
psql -h localhost -p 5432 -U mcp_user -d mcp_security

# Connect to Redis
redis-cli -h localhost -p 6379 -a redis_password
```

### 3. Kubernetes Resources
```bash
# View all MCP resources
kubectl get all -n mcp-security

# View logs
kubectl logs -f deployment/mcp-platform-correlation -n mcp-security

# Get service details
kubectl describe svc mcp-platform-gateway -n mcp-security
```

### 4. API Documentation
Once services are running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🛠️ Development Workflow

### 1. Code Changes
The devcontainer mounts your workspace, so any code changes are immediately available.

### 2. Rebuild and Deploy
```bash
# Rebuild a specific service
./scripts/build-service.sh correlation-engine

# Redeploy to Kind
./scripts/codespace-setup.sh
```

### 3. Debugging
```bash
# Port forward to specific pod
kubectl port-forward pod/mcp-platform-correlation-xxx 8080:8080 -n mcp-security

# Get pod logs
kubectl logs mcp-platform-correlation-xxx -n mcp-security -f

# Execute into pod
kubectl exec -it mcp-platform-correlation-xxx -n mcp-security -- bash
```

## 🧪 Advanced Testing Scenarios

### Scenario 1: Container Security Scanning
```bash
# Scan a vulnerable image
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "Vulnerable Image Scan",
    "target": "nginx:1.19",
    "scanner": "trivy",
    "options": {"severity": ["HIGH", "CRITICAL"]}
  }'
```

### Scenario 2: Supply Chain Analysis  
```bash
# Analyze supply chain
curl -X POST http://localhost:8000/api/v1/supply-chain/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "repository": "docker.io/library/node",
    "tag": "18-alpine"
  }'
```

### Scenario 3: Compliance Assessment
```bash
# Full NIST CSF assessment
curl -X POST http://localhost:8000/api/v1/compliance/assess \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "framework": "NIST CSF",
    "scope": "full",
    "target": {
      "type": "cluster",
      "namespace": "mcp-security"
    }
  }'
```

## 🔧 Customization

### Environment Variables
Edit `.devcontainer/poc-values.yaml` to customize:
- Resource limits
- Feature flags  
- Scanner configurations
- Database connections

### Adding New Services
1. Add to `services/` directory
2. Update `deployments/helm/mcp-platform/values.yaml`
3. Rebuild: `./scripts/codespace-setup.sh`

## 🐛 Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check pod status
kubectl get pods -n mcp-security

# Check events
kubectl get events -n mcp-security --sort-by=.metadata.creationTimestamp

# Check resource constraints
kubectl describe pod POD_NAME -n mcp-security
```

#### Port Forwarding Issues
```bash
# Kill existing forwards
pkill -f "kubectl port-forward"

# Restart setup
./scripts/codespace-setup.sh
```

#### Database Connection Issues
```bash
# Check external service connectivity
curl -v host.docker.internal:5432
curl -v host.docker.internal:6379
```

### Reset POC Environment
```bash
# Delete Kind cluster
kind delete cluster --name mcp-poc

# Restart setup
./scripts/codespace-setup.sh
```

## 📊 Performance Monitoring

### Resource Usage
```bash
# Pod resource usage
kubectl top pods -n mcp-security

# Node resource usage  
kubectl top nodes
```

### Service Metrics
```bash
# Health check all services
for port in 8000 8001 8080; do
  echo "=== Port $port ==="
  curl -s http://localhost:$port/health | jq .
done
```

## 🚀 Next Steps

After exploring the POC:

1. **Review Architecture**: See `docs/architecture/` for detailed design
2. **Production Deployment**: Check `deployments/production/`
3. **Plugin Development**: Explore `plugin-sdk/` for custom scanners
4. **Integration**: Review API documentation for integration options

## 📞 Support

- **Issues**: Create GitHub issues for bugs or questions
- **Discussions**: Use GitHub Discussions for general questions
- **Documentation**: See `docs/` directory for comprehensive guides

---

**Happy exploring! 🎉**

*The MCP Security Platform team*