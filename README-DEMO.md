# MCP Security Platform - One-Click POC Demo

## 🚀 Quick Start

Launch the complete POC demonstration with a single command:

```bash
./scripts/demo-poc.sh
```

## 📋 What the Demo Shows

The one-click demo demonstrates the complete MCP Security Platform workflow:

1. **🔧 Service Orchestration**: Starts all microservices and validates health
2. **📄 SBOM Upload**: Ingests a vulnerable application SBOM with known CVEs
3. **🤖 AI Risk Assessment**: LLM-powered analysis with business context
4. **📊 Risk Reporting**: Comprehensive security risk analysis and scoring
5. **🛡️ Dashboard Access**: Interactive security platform interface

## 🎯 Demo Workflow

### Step 1: Service Startup
- Automatically deploys the MCP platform in Kind cluster
- Validates all service health endpoints
- Sets up port forwarding for local access

### Step 2: Authentication
- Obtains JWT token for API access
- Demonstrates secure authentication flow

### Step 3: SBOM Analysis
- Uploads sample application SBOM containing:
  - 4 open source components (Express, Lodash, Axios, Nginx)
  - 4 critical/high vulnerabilities including Log4Shell
  - Complete dependency mapping

### Step 4: Risk Assessment
- Triggers AI-powered comprehensive risk analysis
- Generates business impact assessment
- Maps compliance implications (SOC2, ISO27001)
- Creates prioritized remediation roadmap

### Step 5: Results Display
- Shows executive-level risk summary
- Displays vulnerability breakdown and CVSS scores
- Provides actionable remediation timeline
- Highlights compliance control impacts

### Step 6: Dashboard Access
- Launches interactive security dashboard
- Provides API endpoint documentation
- Shows real-time service health status

## 📁 Demo Artifacts

After running the demo, find generated artifacts in `/workspace/demo-data/`:

- `vulnerable-app-sbom.json` - Sample SBOM with vulnerabilities
- `risk-assessment-report.json` - Complete AI-generated risk analysis
- `demo-summary.md` - Executive summary of findings

## 🔗 Access Points

Once the demo completes, access the platform via:

- **Dashboard UI**: http://localhost:3000
- **API Gateway**: http://localhost:8000/docs
- **Auth Service**: http://localhost:8001/docs  
- **Core Services**: http://localhost:8080/docs
- **MinIO Console**: http://localhost:9000

### Default Credentials
- **Username**: `admin`
- **Password**: `admin123`

## 🧪 Manual Testing

After the demo, test individual components:

### Health Checks
```bash
# Check all services
curl http://localhost:8000/health
curl http://localhost:8001/health
curl http://localhost:8080/health
```

### Authentication
```bash
# Get JWT token
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### SBOM Upload
```bash
# Upload custom SBOM
curl -X POST http://localhost:8000/api/v1/sbom/upload \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d @demo-data/sample-sbom-minimal.json
```

## 📊 Demo Data

### Sample Vulnerabilities Included

| CVE ID | Severity | CVSS | Component | Description |
|--------|----------|------|-----------|-------------|
| CVE-2021-44228 | CRITICAL | 10.0 | Express/Log4j | Log4Shell RCE |
| CVE-2021-3807 | CRITICAL | 9.1 | Axios | SSRF vulnerability |
| CVE-2021-23337 | HIGH | 7.2 | Lodash | Command injection |
| CVE-2021-23017 | HIGH | 7.7 | Nginx | Memory overwrite |

### Expected Risk Assessment Results

- **Overall Risk Score**: 8.7/10 (CRITICAL)
- **Business Impact**: Complete system compromise possible
- **Compliance Impact**: HIGH risk for SOC2 and ISO27001
- **Remediation Timeline**: 24-48 hours for critical patches

## 🛠️ Troubleshooting

### Services Not Starting
```bash
# Check Kind cluster
kind get clusters

# Restart the demo
./scripts/codespace-setup.sh
```

### Port Conflicts
```bash
# Check port usage
netstat -tlnp | grep :8000

# Kill conflicting processes if needed
sudo fuser -k 8000/tcp
```

### Demo Data Issues
```bash
# Recreate demo data directory
mkdir -p /workspace/demo-data
./scripts/demo-poc.sh
```

## 🔄 Running Multiple Demos

The demo can be run multiple times safely:

- Each run generates new demo data with timestamps
- Previous artifacts are preserved
- Services are reused if already healthy

## 📈 Performance

- **Demo Duration**: ~5 minutes
- **Platform Startup**: ~3 minutes  
- **Risk Assessment**: ~30 seconds
- **Resource Usage**: ~2GB RAM, 2 CPU cores

## 🎓 Educational Value

This demo showcases:

- Modern cloud-native security architecture
- AI/ML integration in cybersecurity workflows
- Compliance automation and mapping
- API-first security platform design
- Container-based microservices deployment
- Real-time vulnerability correlation and risk scoring

Perfect for:
- Security team evaluations
- Executive demonstrations
- Technical architecture reviews
- Proof-of-concept validations
- Training and education scenarios