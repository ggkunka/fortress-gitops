# MCP Security Assessment Platform

A comprehensive, pluggable security assessment platform built with microservices architecture for Model Context Protocol (MCP) environments.

## Architecture Overview

The MCP Security Assessment Platform provides a robust, scalable solution for security scanning and vulnerability management in containerized environments. Built with a microservices architecture, it supports multiple Kubernetes flavors and provides comprehensive security analysis capabilities.

### Key Features

- **Pluggable Architecture**: Modular design supporting various security scanners
- **Multi-Kubernetes Support**: Compatible with OCP, EKS, AKS, and vanilla Kubernetes (v1.21-1.32)
- **Event-Driven Design**: Asynchronous processing with real-time notifications
- **Container-First**: Built with Buildah and Rocky Linux 9 base images
- **Comprehensive Scanning**: SBOM generation, vulnerability analysis, and compliance checking
- **RESTful APIs**: FastAPI-based services with OpenAPI documentation
- **State Persistence**: Maintains state across system restarts
- **Multi-Tenant**: Supports multiple organizations and projects

## Service Architecture

### Core Services

1. **Authentication Service** (`services/auth/`)
   - JWT-based authentication
   - Role-based access control (RBAC)
   - Multi-tenant support
   - API key management

2. **API Gateway** (`services/gateway/`)
   - Request routing and load balancing
   - Rate limiting and throttling
   - Authentication middleware
   - Request/response transformation

3. **Scanner Manager** (`services/scanner-manager/`)
   - Scanner orchestration and lifecycle management
   - Plugin system for security tools
   - Scan scheduling and queuing
   - Resource allocation and monitoring

4. **Vulnerability Analyzer** (`services/vulnerability-analyzer/`)
   - SBOM processing and analysis
   - CVE database integration
   - Risk scoring and prioritization
   - False positive management

5. **Report Generator** (`services/report-generator/`)
   - Multi-format report generation (JSON, PDF, HTML)
   - Customizable templates
   - Compliance reporting
   - Audit trail management

6. **Notification Service** (`services/notification/`)
   - Real-time alerts and notifications
   - Multi-channel support (email, Slack, webhooks)
   - Escalation policies
   - Event correlation

### Shared Components

- **Models** (`shared/models/`): Common data models and schemas
- **Utils** (`shared/utils/`): Shared utilities and helper functions
- **Middleware** (`shared/middleware/`): Common middleware components
- **Config** (`shared/config/`): Configuration management

## Technology Stack

- **Runtime**: Python 3.11+
- **Framework**: FastAPI with async support
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Message Queue**: Redis for caching and task queuing
- **Container**: Buildah with Rocky Linux 9 base
- **Orchestration**: Kubernetes with Helm 3 charts
- **Monitoring**: Prometheus, Grafana, and structured logging
- **Security**: OAuth2, JWT, RBAC, and secret management

## Quick Start

### Prerequisites

- Python 3.11+
- Docker or Podman
- Kubernetes cluster (1.21-1.32)
- Helm 3.x
- Git

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/mcp-security-platform.git
cd mcp-security-platform
```

2. Set up virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run development services:
```bash
./scripts/build/dev-setup.sh
./scripts/deploy/local-deploy.sh
```

### Production Deployment

1. Build container images:
```bash
./scripts/build/build-all.sh
```

2. Deploy to Kubernetes:
```bash
helm install mcp-security-platform ./deployments/helm/mcp-platform \
  --namespace mcp-security \
  --create-namespace
```

## API Documentation

Once deployed, access the API documentation at:
- Swagger UI: `http://your-domain/docs`
- ReDoc: `http://your-domain/redoc`

## Contributing

Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and submission process.

## Security

For security concerns, please review our [Security Policy](SECURITY.md) and report issues through appropriate channels.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/your-org/mcp-security-platform/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/mcp-security-platform/discussions)