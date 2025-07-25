# MCP Security Platform - GitOps Deployment

This directory contains the GitOps configuration for deploying the MCP Security Platform using ArgoCD. The deployment follows a layered approach with proper dependency management and environment-specific configurations.

## Architecture Overview

```
GitOps Deployment Layers:
┌─────────────────────────────────────────────────────────────────┐
│                    ArgoCD Control Plane                        │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                Infrastructure Layer                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │    Istio    │ │ Monitoring  │ │ Databases   │              │
│  │ Service     │ │   Stack     │ │ (PostgreSQL │              │
│  │    Mesh     │ │             │ │   Redis)    │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                 Platform Layer                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │   Core      │ │    Auth     │ │   Gateway   │              │
│  │ Services    │ │  Service    │ │   Service   │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│               Application Layer                                │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Scanner  │ │   Vuln   │ │ Analysis │ │ Reports  │          │
│  │ Manager  │ │Analyzer  │ │ Service  │ │Generator │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                      │
│  │   Web    │ │Plugin    │ │External  │                      │
│  │    UI    │ │Marketplace│ │Integrations                    │
│  └──────────┘ └──────────┘ └──────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
gitops/
├── bootstrap/
│   ├── argocd/                     # ArgoCD installation
│   └── root-app.yaml               # Root application (app-of-apps pattern)
├── infrastructure/
│   ├── istio/
│   │   ├── base/                   # Istio control plane
│   │   ├── gateways/               # Ingress gateways
│   │   └── security-policies/      # Security configurations
│   ├── monitoring/
│   │   ├── prometheus/             # Metrics collection
│   │   ├── grafana/                # Dashboards
│   │   ├── jaeger/                 # Distributed tracing
│   │   └── kiali/                  # Service mesh observability
│   └── databases/
│       ├── postgresql/             # Primary database
│       └── redis/                  # Cache and event bus
├── platform/
│   ├── core-services/
│   │   ├── mcp-server/             # MCP protocol server
│   │   ├── authentication/         # Auth service
│   │   ├── gateway/                # API gateway
│   │   └── notification/           # Notification service
│   └── data-services/
│       ├── ingestion/              # Data ingestion
│       └── enrichment/             # Data enrichment
├── applications/
│   ├── security-services/
│   │   ├── scanner-manager/        # Scan orchestration
│   │   ├── vulnerability-analyzer/ # Vulnerability analysis
│   │   ├── analysis-service/       # Multi-type analysis
│   │   ├── risk-assessment/        # Risk scoring
│   │   └── correlation-engine/     # Event correlation
│   ├── reporting/
│   │   └── report-generator/       # Report generation
│   ├── integrations/
│   │   └── external-integrations/  # SIEM, Cloud, Threat feeds
│   ├── marketplace/
│   │   └── plugin-marketplace/     # Plugin management
│   └── web-interface/
│       └── web-ui/                 # React web application
├── environments/
│   ├── development/
│   │   ├── kustomization.yaml      # Dev-specific overrides
│   │   └── values/                 # Dev environment values
│   ├── staging/
│   │   ├── kustomization.yaml      # Staging overrides
│   │   └── values/                 # Staging environment values
│   └── production/
│       ├── kustomization.yaml      # Production overrides
│       └── values/                 # Production environment values
└── apps/
    ├── infrastructure-apps.yaml    # Infrastructure layer app-of-apps
    ├── platform-apps.yaml          # Platform layer app-of-apps
    └── application-apps.yaml       # Application layer app-of-apps
```

## Deployment Flow

### 1. Bootstrap Phase
```bash
# Install ArgoCD
kubectl apply -k gitops/bootstrap/argocd/

# Deploy root application (app-of-apps)
kubectl apply -f gitops/bootstrap/root-app.yaml
```

### 2. Infrastructure Layer
ArgoCD automatically deploys:
- Istio service mesh with security policies
- Monitoring stack (Prometheus, Grafana, Jaeger, Kiali)
- Databases (PostgreSQL, Redis)

### 3. Platform Layer
ArgoCD deploys core platform services:
- MCP Server, Authentication, Gateway
- Data ingestion and enrichment services
- Notification service

### 4. Application Layer
ArgoCD deploys business applications:
- Security scanning and analysis services
- Reporting and visualization
- External integrations and plugin marketplace
- Web interface

## Environment Management

### Development Environment
- Single replica for all services
- Reduced resource limits
- Mock external integrations
- In-memory databases for testing

### Staging Environment
- Production-like configuration
- Scaled-down resources
- Real external integrations
- Full monitoring stack

### Production Environment
- High availability configuration
- Full resource allocation
- Complete security policies
- Full observability and alerting

## GitOps Workflow

### Making Changes
1. **Create feature branch**
   ```bash
   git checkout -b feature/update-scanner-config
   ```

2. **Make configuration changes**
   ```bash
   # Edit configuration files
   vim applications/security-services/scanner-manager/values.yaml
   ```

3. **Test changes** (if applicable)
   ```bash
   # Validate Kubernetes manifests
   kubectl apply --dry-run=client -k environments/staging/
   ```

4. **Commit and push**
   ```bash
   git add .
   git commit -m "Update scanner configuration for improved performance"
   git push origin feature/update-scanner-config
   ```

5. **Create Pull Request**
   - ArgoCD will automatically sync changes after merge
   - Changes deploy to staging first, then production

### Monitoring Deployments
- **ArgoCD UI**: Monitor sync status and health
- **Grafana**: View deployment metrics and performance
- **Slack/Email**: Receive deployment notifications

### Rolling Back Changes
```bash
# Revert to previous commit
git revert HEAD
git push origin main

# ArgoCD will automatically roll back the deployment
```

## Security Features

### GitOps Security Benefits
- **Audit Trail**: All changes tracked in Git
- **Access Control**: Git-based permissions
- **Immutable Infrastructure**: Declarative configurations
- **Secret Management**: Sealed secrets or external secret management

### ArgoCD Security
- **RBAC**: Role-based access control
- **SSO Integration**: OIDC/SAML authentication
- **Encrypted Communication**: TLS everywhere
- **Network Policies**: Restricted network access

## Monitoring and Observability

### Deployment Monitoring
- **ArgoCD Metrics**: Sync status, health checks
- **Application Metrics**: Custom business metrics
- **Infrastructure Metrics**: Resource utilization
- **Security Metrics**: Policy violations, failed authentications

### Alerting Rules
- Deployment failures
- Application health degradation
- Resource exhaustion
- Security policy violations

## Troubleshooting

### Common Issues

1. **Sync Failures**
   ```bash
   # Check ArgoCD application status
   argocd app get mcp-security-platform
   
   # Check sync details
   argocd app sync mcp-security-platform --dry-run
   ```

2. **Resource Conflicts**
   ```bash
   # Check for resource conflicts
   kubectl get all -n mcp-security -o wide
   
   # Check events
   kubectl get events -n mcp-security --sort-by='.lastTimestamp'
   ```

3. **Configuration Issues**
   ```bash
   # Validate Kustomize configuration
   kustomize build environments/production/ | kubectl apply --dry-run=client -f -
   ```

### Recovery Procedures

1. **Complete Platform Recovery**
   ```bash
   # Recreate from GitOps repository
   kubectl apply -k gitops/bootstrap/argocd/
   kubectl apply -f gitops/bootstrap/root-app.yaml
   ```

2. **Service-Specific Recovery**
   ```bash
   # Sync specific application
   argocd app sync mcp-security-scanner-manager
   ```

## Best Practices

### Configuration Management
- Use Kustomize for environment-specific overrides
- Keep secrets in external secret management systems
- Version all configuration changes
- Use semantic versioning for releases

### Deployment Strategy
- Deploy infrastructure changes first
- Use canary deployments for critical services
- Implement proper health checks
- Monitor deployment impact

### Security Practices
- Regular security scans of container images
- Keep ArgoCD and Kubernetes updated
- Implement network policies
- Use service mesh security features

This GitOps approach provides a robust, secure, and maintainable deployment strategy for the MCP Security Platform, ensuring consistent deployments across environments with full audit trails and easy rollback capabilities.