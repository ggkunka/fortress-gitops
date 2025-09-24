# MCP Security Platform - Production Deployment Guide

## 🚀 Quick Start

The MCP Security Platform is now **100% complete** and ready for production deployment. This guide will walk you through deploying the enterprise-grade security platform.

## 📋 Prerequisites

### Infrastructure Requirements

**Minimum Production Requirements:**
- Kubernetes cluster v1.24+ (3 master nodes, 6+ worker nodes)
- 500+ CPU cores, 2TB RAM across the cluster
- 100TB+ distributed storage (NFS/Ceph/Cloud storage)
- Load balancer (MetalLB/Cloud LB)
- DNS management capability

**Network Requirements:**
- Ingress controller (Nginx/Traefik/Cloud)
- SSL/TLS certificates (Let's Encrypt/Corporate CA)
- Service mesh support (Istio compatible)

### Software Dependencies

**Required Tools:**
```bash
# Install required CLI tools
kubectl version --client  # v1.24+
helm version              # v3.10+
argocd version           # v2.8+
vault version            # v1.14+
istioctl version         # v1.18+
```

**Optional but Recommended:**
```bash
terraform version        # v1.5+ (for infrastructure provisioning)
kustomize version       # v4.5+ (for manifest customization)
```

## 🏗️ Architecture Overview

The platform consists of:

### Core Services
- **Correlation Engine** - Advanced event correlation with ML
- **Risk Assessment** - LLM-powered risk analysis
- **Response Orchestrator** - Automated incident response
- **Reporting Service** - Comprehensive analytics and reporting

### Data Layer (9 Database Systems)
- **PostgreSQL** - Primary relational database
- **MongoDB** - SBOM and document storage
- **InfluxDB** - Time-series metrics
- **ClickHouse** - OLAP analytics
- **Neo4j** - Dependency graphs
- **Redis** - Distributed caching
- **MinIO** - S3-compatible object storage
- **Event Store** - Event sourcing and audit
- **Apache Spark** - Big data processing

### Plugin System
- **Scanner Plugins** - Trivy, Syft, Grype, OSV
- **Integration Plugins** - GitHub, GitLab, JIRA, Slack
- **Alert Plugins** - Email, Webhook, PagerDuty
- **Compliance Plugins** - NIST, ISO27001, SOC2

### Advanced Features
- **Complex Event Processing (CEP)** - Real-time pattern detection
- **Supply Chain Security** - SBOM analysis and vulnerability tracking
- **GraphQL API** - Modern query interface with subscriptions
- **WebSocket** - Real-time communication
- **gRPC** - High-performance inter-service communication

### Infrastructure
- **Service Mesh** - Istio with advanced traffic management
- **GitOps** - ArgoCD with multi-environment automation
- **Secrets Management** - HashiCorp Vault integration
- **Zero Trust** - Comprehensive security architecture

## 🚀 Deployment Methods

### Method 1: GitOps Deployment (Recommended)

```bash
# 1. Install ArgoCD
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 2. Apply MCP ArgoCD configuration
kubectl apply -f infrastructure/gitops/argocd-config.yaml

# 3. Sync applications
argocd app sync mcp-core-services
argocd app sync mcp-data-layer
argocd app sync mcp-plugins
argocd app sync mcp-security-infra
argocd app sync mcp-monitoring
```

### Method 2: Helm Deployment

```bash
# 1. Add Helm repositories
helm repo add mcp-platform https://charts.mcp-security-platform.local
helm repo update

# 2. Install core services
helm install mcp-core mcp-platform/mcp-core-services \
  --namespace mcp-security-platform \
  --create-namespace \
  --values deployments/core/values-production.yaml

# 3. Install data layer
helm install mcp-data mcp-platform/mcp-data-layer \
  --namespace mcp-data \
  --create-namespace \
  --values deployments/data/values-production.yaml
```

### Method 3: Kubernetes Manifests

```bash
# Apply all manifests in order
kubectl apply -f deployments/namespace.yaml
kubectl apply -f deployments/data/
kubectl apply -f deployments/core/
kubectl apply -f deployments/plugins/
kubectl apply -f deployments/security/
kubectl apply -f deployments/monitoring/
```

## 🔧 Configuration

### Environment Variables

Create a configuration file:

```yaml
# config/production.yaml
global:
  environment: production
  domain: mcp-security-platform.local
  tls:
    enabled: true
    certificateIssuer: letsencrypt-prod

security:
  vault:
    enabled: true
    address: https://vault.mcp-platform.local:8200
    authMethod: kubernetes
  
  zerotrust:
    enabled: true
    strictMode: true
    deviceCompliance: required

database:
  postgresql:
    host: postgresql.mcp-data.svc.cluster.local
    database: mcp_security
    ssl: require
    maxConnections: 100
  
  mongodb:
    uri: mongodb://mongodb.mcp-data.svc.cluster.local:27017
    database: mcp_sbom
    replicaSet: rs0
  
  redis:
    cluster:
      enabled: true
      nodes:
        - redis-0.mcp-data.svc.cluster.local:6379
        - redis-1.mcp-data.svc.cluster.local:6379
        - redis-2.mcp-data.svc.cluster.local:6379

observability:
  prometheus:
    enabled: true
    retention: 90d
  
  grafana:
    enabled: true
    adminPassword: ${GRAFANA_ADMIN_PASSWORD}
  
  jaeger:
    enabled: true
    collector: jaeger-collector.mcp-monitoring.svc.cluster.local:14268

plugins:
  registry:
    enabled: true
    hotReload: true
  
  scanners:
    trivy:
      enabled: true
      cacheSize: 10Gi
    
    syft:
      enabled: true
      
    grype:
      enabled: true
      
    osv:
      enabled: true

compliance:
  frameworks:
    nist:
      enabled: true
      version: "1.1"
    
    iso27001:
      enabled: true
      version: "2022"
    
    soc2:
      enabled: true
      assessmentType: type_ii
```

### Secrets Management

```bash
# 1. Initialize Vault (if not using managed service)
vault operator init
vault operator unseal

# 2. Enable auth methods
vault auth enable kubernetes
vault auth enable userpass

# 3. Create policies and roles
vault policy write mcp-admin - <<EOF
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# 4. Store secrets
vault kv put secret/mcp/database \
  postgresql_password="secure_password" \
  mongodb_password="secure_password"

vault kv put secret/mcp/api-keys \
  github_token="ghp_xxxxxxxxxxxx" \
  slack_webhook="https://hooks.slack.com/..."
```

## 🔒 Security Configuration

### TLS Certificates

```bash
# Using cert-manager for automatic certificates
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.12.0/cert-manager.yaml

# Create ClusterIssuer
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@yourdomain.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
EOF
```

### Network Policies

```bash
# Apply Istio service mesh configuration
kubectl apply -f infrastructure/service-mesh/istio-config.yaml

# Apply network security policies
kubectl apply -f deployments/security/network-policies.yaml
```

### RBAC Configuration

```bash
# Create service accounts and roles
kubectl apply -f deployments/security/rbac.yaml

# Configure Istio authorization policies
kubectl apply -f infrastructure/service-mesh/security-policies.yaml
```

## 📊 Monitoring Setup

### Prometheus & Grafana

```bash
# Install monitoring stack
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace mcp-monitoring \
  --create-namespace \
  --values deployments/monitoring/values-production.yaml

# Import MCP dashboards
kubectl apply -f deployments/monitoring/dashboards/
```

### Distributed Tracing

```bash
# Install Jaeger
helm install jaeger jaegertracing/jaeger \
  --namespace mcp-monitoring \
  --values deployments/monitoring/jaeger-values.yaml
```

### Log Aggregation

```bash
# Install ELK stack
helm install elasticsearch elastic/elasticsearch \
  --namespace mcp-monitoring \
  --values deployments/monitoring/elasticsearch-values.yaml

helm install kibana elastic/kibana \
  --namespace mcp-monitoring \
  --values deployments/monitoring/kibana-values.yaml
```

## 🧪 Verification

### Health Checks

```bash
# Check all services are running
kubectl get pods -n mcp-security-platform
kubectl get pods -n mcp-data
kubectl get pods -n mcp-monitoring

# Check service health endpoints
curl -k https://api.mcp-security-platform.local/health
curl -k https://api.mcp-security-platform.local/api/v1/health

# Check database connectivity
kubectl exec -it postgresql-0 -n mcp-data -- psql -c "SELECT 1"
kubectl exec -it mongodb-0 -n mcp-data -- mongo --eval "db.adminCommand('ping')"
```

### Functional Tests

```bash
# Run integration tests
kubectl apply -f tests/integration/test-suite.yaml

# Check test results
kubectl logs -f job/integration-tests -n mcp-security-platform

# Manual API tests
curl -X POST https://api.mcp-security-platform.local/api/v1/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/example/repo", "scanners": ["trivy", "syft"]}'
```

### Performance Tests

```bash
# Run load tests
kubectl apply -f tests/performance/load-test.yaml

# Monitor performance metrics
kubectl port-forward svc/grafana 3000:80 -n mcp-monitoring
# Open http://localhost:3000 and check MCP Performance dashboard
```

## 🔄 Maintenance

### Updates and Upgrades

```bash
# GitOps-based updates (recommended)
# 1. Update image tags in Git repository
# 2. ArgoCD will automatically sync changes

# Manual Helm upgrades
helm upgrade mcp-core mcp-platform/mcp-core-services \
  --namespace mcp-security-platform \
  --values deployments/core/values-production.yaml

# Rolling updates
kubectl rollout restart deployment/correlation-engine -n mcp-security-platform
kubectl rollout status deployment/correlation-engine -n mcp-security-platform
```

### Backup and Recovery

```bash
# Database backups
kubectl apply -f deployments/operations/backup-cronjobs.yaml

# Vault backup
vault operator raft snapshot save backup.snap

# Application configuration backup
kubectl get configmaps,secrets -o yaml > mcp-config-backup.yaml
```

### Scaling

```bash
# Horizontal scaling
kubectl scale deployment correlation-engine --replicas=5 -n mcp-security-platform

# Vertical scaling (using VPA)
kubectl apply -f deployments/operations/vertical-pod-autoscaler.yaml

# Database scaling
helm upgrade mongodb bitnami/mongodb \
  --set replicaSet.replicas.secondary=3 \
  --namespace mcp-data
```

## 🚨 Troubleshooting

### Common Issues

**Services not starting:**
```bash
# Check pod logs
kubectl logs -f deployment/correlation-engine -n mcp-security-platform

# Check events
kubectl get events --sort-by=.metadata.creationTimestamp -n mcp-security-platform

# Check resource constraints
kubectl describe pod <pod-name> -n mcp-security-platform
```

**Database connectivity issues:**
```bash
# Test database connections
kubectl exec -it deployment/correlation-engine -n mcp-security-platform -- \
  python -c "from shared.data.postgresql import PostgreSQLService; print('DB OK')"

# Check network policies
kubectl describe networkpolicy -n mcp-data
```

**Performance issues:**
```bash
# Check resource usage
kubectl top pods -n mcp-security-platform
kubectl top nodes

# Check metrics in Grafana
kubectl port-forward svc/grafana 3000:80 -n mcp-monitoring
```

## 📞 Support

### Getting Help

1. **Documentation**: Check `/docs` directory for detailed guides
2. **Logs**: Centralized logging in ELK stack
3. **Metrics**: Prometheus/Grafana dashboards
4. **Health Checks**: `/health` endpoints on all services

### Emergency Procedures

**Platform down:**
```bash
# Check cluster status
kubectl cluster-info
kubectl get nodes

# Restart core services
kubectl rollout restart deployment -n mcp-security-platform

# Check load balancer
kubectl get svc -n mcp-security-platform
```

**Data corruption:**
```bash
# Restore from backup
kubectl apply -f deployments/operations/restore-job.yaml

# Verify data integrity
kubectl exec -it postgresql-0 -n mcp-data -- psql -c "SELECT COUNT(*) FROM vulnerabilities"
```

## 🎯 Next Steps

After successful deployment:

1. **User Training** - Train security teams on platform capabilities
2. **Custom Plugins** - Develop organization-specific plugins
3. **Performance Tuning** - Optimize for your specific workloads
4. **Integration** - Connect with existing security tools
5. **Compliance Assessment** - Run initial compliance scans

## 📚 Additional Resources

- [User Guide](../user-guide/)
- [API Documentation](../api/)
- [Plugin Development](../plugins/)
- [Security Hardening](../security/)
- [Performance Tuning](../performance/)

---

🎉 **Congratulations!** You now have a fully functional, enterprise-grade MCP Security Platform deployed and ready for production use.