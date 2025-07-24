# MCP Security Server

An implementation of Anthropic's Model Context Protocol (MCP) for security scanning and vulnerability analysis.

## Overview

This MCP server provides security professionals and AI assistants with access to comprehensive security scanning capabilities through a standardized protocol. It exposes container vulnerability scanning, SBOM generation, risk assessment, and compliance analysis tools via the MCP interface.

## Features

### 🔍 Security Tools (MCP Tools)
- **`scan_container_vulnerabilities`** - Scan container images using Grype, Trivy, or Syft
- **`generate_sbom`** - Generate Software Bill of Materials in SPDX, CycloneDX, or Syft formats
- **`assess_security_risk`** - AI-powered risk assessment of vulnerabilities
- **`analyze_compliance`** - Security compliance analysis against CIS, NIST, SOC2, and other frameworks

### 📊 Security Data Resources (MCP Resources)
- **`security://scans/recent`** - Recent vulnerability scan results
- **`security://vulnerabilities/critical`** - Critical severity vulnerabilities
- **`security://sboms/latest`** - Latest SBOM data
- **`security://compliance/status`** - Compliance status across frameworks
- **`security://metrics/dashboard`** - Security metrics and KPIs

### 🚀 Transport Support
- **stdio** - Command-line and IDE integration
- **WebSocket** - Real-time web applications
- **Server-Sent Events** - Web dashboard integration

## Installation

### Prerequisites
- Python 3.11+
- Docker (for container scanning)
- Security scanners: Grype, Trivy, Syft (optional, for real scanning)

### Install Dependencies
```bash
cd /path/to/mcp-security-platform
pip install -e .
# or with poetry
poetry install
```

### Install Security Scanners (Optional)
```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## Usage

### 1. Run the MCP Server

#### Stdio Transport (for CLI/IDE integration)
```bash
python -m services.mcp_server.main
```

#### As a Poetry Script
```bash
poetry run mcp-security-server
```

### 2. Connect Claude or MCP Clients

#### Claude Desktop Configuration
Add to your Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "security-platform": {
      "command": "python",
      "args": ["-m", "services.mcp_server.main"],
      "cwd": "/path/to/mcp-security-platform"
    }
  }
}
```

#### Manual MCP Client Connection
```python
import asyncio
from mcp.client import ClientSession
from mcp.client.stdio import stdio_client

async def connect_to_security_server():
    async with stdio_client(["python", "-m", "services.mcp_server.main"]) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("Available tools:", [tool.name for tool in tools])
            
            # Scan a container
            result = await session.call_tool(
                "scan_container_vulnerabilities",
                {"image": "redis:8.0.3", "scanner": "grype"}
            )
            print("Scan result:", result)

asyncio.run(connect_to_security_server())
```

### 3. Example Tool Usage

#### Vulnerability Scanning
```python
# Scan container with Grype
result = await session.call_tool(
    "scan_container_vulnerabilities",
    {
        "image": "nginx:latest",
        "scanner": "grype",
        "format": "json"
    }
)

# Scan with Trivy
result = await session.call_tool(
    "scan_container_vulnerabilities",
    {
        "image": "mysql:8.0",
        "scanner": "trivy",
        "format": "json"
    }
)
```

#### SBOM Generation
```python
# Generate SPDX SBOM
result = await session.call_tool(
    "generate_sbom",
    {
        "target": "alpine:latest",
        "format": "spdx",
        "output": "json"
    }
)

# Generate CycloneDX SBOM
result = await session.call_tool(
    "generate_sbom",
    {
        "target": "/path/to/project",
        "format": "cyclonedx",
        "output": "xml"
    }
)
```

#### Risk Assessment
```python
# AI-powered risk assessment
vulnerabilities = [
    {
        "cve_id": "CVE-2023-1234",
        "severity": "critical",
        "description": "Buffer overflow vulnerability",
        "package": "openssl"
    }
]

result = await session.call_tool(
    "assess_security_risk",
    {
        "vulnerabilities": vulnerabilities,
        "context": "production web application",
        "criteria": ["exploitability", "business_impact"]
    }
)
```

#### Compliance Analysis
```python
# CIS Kubernetes benchmark
result = await session.call_tool(
    "analyze_compliance",
    {
        "target": "kubernetes-cluster",
        "framework": "cis",
        "profile": "k8s-1.8"
    }
)

# NIST Cybersecurity Framework
result = await session.call_tool(
    "analyze_compliance",
    {
        "target": "production-environment",
        "framework": "nist"
    }
)
```

### 4. Resource Access

#### Get Recent Scans
```python
recent_scans = await session.read_resource("security://scans/recent")
```

#### Get Critical Vulnerabilities
```python
critical_vulns = await session.read_resource("security://vulnerabilities/critical")
```

#### Get Security Metrics
```python
metrics = await session.read_resource("security://metrics/dashboard")
```

## Testing

Run the test suite to verify functionality:

```bash
python test_mcp_server.py
```

Expected output:
```
MCP Security Server Test Suite
========================================
Testing Security Scanner Tool...
  ✓ Scan completed: [scan-id]
  ✓ SBOM generated: [sbom-id]

Testing Risk Assessor Tool...
  ✓ Assessment completed: [assessment-id]
  ✓ Overall risk level: critical

Testing Security Data Resource...
  ✓ Retrieved recent scans: 1 scans
  ✓ Retrieved critical vulnerabilities: 1 vulnerabilities

========================================
✓ All tests completed successfully!
```

## Architecture

### Directory Structure
```
services/mcp_server/
├── __init__.py
├── main.py                 # MCP server entry point
├── tools/                  # Security tools implementation
│   ├── security_scanner.py
│   ├── vulnerability_analyzer.py
│   └── risk_assessor.py
├── resources/              # Data access resources
│   └── security_data.py
├── schemas/                # Type definitions
│   └── security_types.py
└── README.md              # This file
```

### Tool Flow
1. **MCP Client Request** → Tool call with parameters
2. **Security Tool** → Execute scanner (Grype/Trivy/Syft)
3. **Result Processing** → Parse and structure data
4. **MCP Response** → Return JSON results to client

### Resource Flow
1. **MCP Client Request** → Resource URI
2. **Data Source** → Query cache/database
3. **Data Processing** → Format and aggregate
4. **MCP Response** → Return JSON data

## Configuration

### Environment Variables
- `LOG_LEVEL` - Logging level (default: INFO)
- `SCANNER_TIMEOUT` - Scanner timeout in seconds (default: 300)
- `CACHE_SIZE` - Result cache size (default: 1000)

### Scanner Configuration
The server automatically detects installed scanners:
- Grype: `grype` command in PATH
- Trivy: `trivy` command in PATH  
- Syft: `syft` command in PATH

If scanners are not installed, the server will return simulated results for demonstration purposes.

## Integration Examples

### Claude Desktop
Ask Claude: "Scan the redis:8.0.3 container for vulnerabilities and assess the security risk"

### VS Code Extension
Use the MCP tools directly in your IDE for security analysis during development.

### Security Dashboard
Integrate with web dashboards for real-time security monitoring.

### CI/CD Pipeline
Use in automated security scanning pipelines.

## Troubleshooting

### Common Issues

1. **Scanner not found**
   ```
   RuntimeError: Grype scan failed: grype: command not found
   ```
   Solution: Install the required scanner or use simulated mode.

2. **Import errors**
   ```
   ModuleNotFoundError: No module named 'mcp'
   ```
   Solution: Install MCP dependencies: `pip install mcp`

3. **Permission errors**
   ```
   PermissionError: [Errno 13] Permission denied
   ```
   Solution: Ensure Docker is running and accessible.

### Debug Mode
Enable debug logging:
```bash
export LOG_LEVEL=DEBUG
python -m services.mcp_server.main
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and support:
- Create an issue in the repository
- Check the troubleshooting section
- Review the test suite for examples