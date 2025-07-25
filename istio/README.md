# MCP Security Platform - Istio Service Mesh

This directory contains the complete Istio service mesh configuration for the MCP Security Platform, providing advanced traffic management, security policies, and observability for the microservices architecture.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Internet Traffic                             │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                 Istio Gateway                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │   HTTPS:443  │  │   HTTP:80    │  │ Internal:8443│         │
│  │   (Public)   │  │ (→ HTTPS)    │  │   (mTLS)     │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                Virtual Services                                 │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │ Web UI      │ │ API Routes  │ │ Internal    │              │
│  │ Routes      │ │ /api/v1/*   │ │ Services    │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│                Destination Rules                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │ Load        │ │ Circuit     │ │ Connection  │              │
│  │ Balancing   │ │ Breakers    │ │ Pooling     │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────┬───────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────────┐
│              Microservices (with Envoy Sidecars)               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │   Web    │ │   API    │ │  Scans   │ │  Vulns   │          │
│  │    UI    │ │ Gateway  │ │ Service  │ │ Service  │          │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                      │
│  │ Reports  │ │Integration│ │Dashboard │                      │
│  │ Service  │ │ Service   │ │ Service  │                      │
│  └──────────┘ └──────────┘ └──────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

## Security Features

### 🔐 **Mutual TLS (mTLS)**
- **Strict mTLS** enforced for all service-to-service communication
- **Automatic certificate management** by Istio
- **Zero-trust network** security model
- **Encryption in transit** for all internal traffic

### 🛡️ **Authorization Policies**
- **Role-based access control** (RBAC) for API endpoints
- **Service-to-service authorization** based on service accounts
- **Path-based access control** for different API routes
- **Deny-by-default** security model
- **Admin-only access** to sensitive endpoints

### 🔑 **Request Authentication**
- **JWT token validation** for API access
- **Multiple JWT issuers** support (internal + external OIDC)
- **Token forwarding** to backend services
- **Service-to-service tokens** for internal communication

### 🚫 **Web Application Firewall (WAF)**
- **SQL injection protection**
- **XSS attack prevention**
- **Malicious user-agent blocking**
- **Path traversal protection**
- **Rate limiting** per client

## Traffic Management

### 🌐 **Gateway Configuration**
- **HTTPS termination** with automatic redirect from HTTP
- **TLS certificate management** with cert-manager integration
- **Multi-host support** (security.company.com, api.security.company.com)
- **Internal gateway** for service-to-service communication

### 🔄 **Virtual Services**
- **Intelligent routing** based on URL patterns
- **Service-specific timeouts** and retries
- **Fault injection** for resilience testing
- **Header-based routing** for A/B testing
- **Traffic splitting** for canary deployments

### ⚖️ **Load Balancing & Resilience**
- **Multiple load balancing algorithms** (ROUND_ROBIN, LEAST_CONN, RANDOM)
- **Circuit breakers** with outlier detection
- **Connection pooling** with configurable limits
- **Retry policies** with exponential backoff
- **Health checks** and automatic failover

## Observability

### 📊 **Metrics Collection**
- **Prometheus metrics** for all services
- **Custom security metrics** (scan types, vulnerability severity)
- **Request tracing** with correlation IDs
- **Performance metrics** (latency, throughput, error rates)
- **Business metrics** (user activity, organization usage)

### 🔍 **Distributed Tracing**
- **Jaeger integration** for end-to-end tracing
- **Custom trace tags** for security context
- **Request correlation** across microservices
- **Performance bottleneck identification**

### 📝 **Access Logging**
- **Structured logging** in JSON format
- **Security event logging** (authentication, authorization)
- **Error logging** with stack traces
- **Audit trails** for compliance
- **Custom log fields** for security analysis

## Directory Structure

```
istio/
├── base/
│   └── namespace.yaml              # Namespaces with sidecar injection
├── gateway/
│   └── gateway.yaml                # Istio gateways (public & internal)
├── virtual-services/
│   └── virtual-service.yaml        # Traffic routing configuration
├── destination-rules/
│   └── destination-rules.yaml      # Load balancing & circuit breakers
├── security/
│   ├── peer-authentication.yaml    # mTLS configuration
│   ├── request-authentication.yaml # JWT authentication
│   └── authorization-policy.yaml   # RBAC and access control
├── observability/
│   └── telemetry.yaml             # Metrics, tracing, and logging
├── traffic-management/
│   ├── envoy-filter.yaml          # Custom Envoy filters (WAF, headers)
│   └── service-entry.yaml         # External service access
├── kustomization.yaml             # Kustomize configuration
└── README.md                      # This file
```

## Quick Start

### Prerequisites
- Kubernetes cluster (1.24+)
- kubectl configured
- Istio 1.19+ installed
- cert-manager (for TLS certificates)

### 1. Deploy Istio Service Mesh

```bash
# Run the automated deployment script
./scripts/deploy-istio.sh

# Or deploy manually
kustomize build istio/ | kubectl apply -f -
```

### 2. Verify Installation

```bash
# Check Istio control plane
istioctl verify-install

# Check proxy status
istioctl proxy-status

# Analyze configuration
istioctl analyze -n mcp-security
```

### 3. Access Observability Dashboards

```bash
# Kiali (Service mesh visualization)
kubectl port-forward svc/kiali 20001:20001 -n istio-system
# Access: http://localhost:20001

# Grafana (Metrics dashboards)
kubectl port-forward svc/grafana 3000:3000 -n istio-system
# Access: http://localhost:3000

# Jaeger (Distributed tracing)
kubectl port-forward svc/jaeger 16686:16686 -n istio-system
# Access: http://localhost:16686
```

## Configuration Details

### Gateway Configuration

```yaml
# External gateway for public traffic
spec:
  servers:
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: mcp-security-tls
    hosts:
    - "security.company.com"
    - "api.security.company.com"
```

### Security Policies

```yaml
# Strict mTLS for all services
spec:
  mtls:
    mode: STRICT

# JWT authentication
spec:
  jwtRules:
  - issuer: "https://security.company.com/auth"
    jwksUri: "https://security.company.com/auth/.well-known/jwks.json"
    audiences: ["mcp-security-api"]
```

### Traffic Rules

```yaml
# Circuit breaker configuration
spec:
  trafficPolicy:
    outlierDetection:
      consecutiveErrors: 3
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

## Security Considerations

### 🔒 **Network Security**
- All inter-service communication encrypted with mTLS
- Network policies restrict pod-to-pod communication
- External traffic only allowed through defined gateways
- Service mesh isolates application traffic from infrastructure

### 🔐 **Identity & Access Management**
- Kubernetes service accounts for service identity
- JWT tokens for user authentication
- Fine-grained authorization policies per service
- Automatic certificate rotation for service identity

### 🛡️ **Defense in Depth**
- WAF filters malicious requests at the edge
- Rate limiting prevents abuse
- Circuit breakers protect against cascading failures
- Security headers prevent common web vulnerabilities

### 📋 **Compliance & Auditing**
- All requests logged with security context
- Distributed tracing for security incident investigation
- Metrics collection for security monitoring
- Access patterns tracked for anomaly detection

## Monitoring & Alerting

### Key Metrics to Monitor

1. **Security Metrics**
   - Failed authentication attempts
   - Authorization denials
   - Rate limit violations
   - WAF blocks

2. **Performance Metrics**
   - Request latency (p50, p95, p99)
   - Error rates by service
   - Circuit breaker states
   - Connection pool utilization

3. **Business Metrics**
   - Active scans by organization
   - Vulnerability discovery rates
   - Report generation frequency
   - Integration health status

### Alerting Rules

```yaml
# Example Prometheus alerting rules
groups:
- name: mcp-security-istio
  rules:
  - alert: HighErrorRate
    expr: rate(istio_requests_total{response_code!~"2.."}[5m]) > 0.1
    labels:
      severity: warning
  
  - alert: AuthenticationFailures
    expr: rate(istio_requests_total{response_code="401"}[5m]) > 0.05
    labels:
      severity: critical
```

## Troubleshooting

### Common Issues

1. **Sidecar Injection Not Working**
   ```bash
   # Check namespace labels
   kubectl get namespace mcp-security --show-labels
   
   # Manual injection
   kubectl label namespace mcp-security istio-injection=enabled
   ```

2. **mTLS Connection Issues**
   ```bash
   # Check peer authentication
   istioctl authn tls-check pod-name.mcp-security
   
   # View certificates
   istioctl proxy-config secret pod-name.mcp-security
   ```

3. **Authorization Policy Denials**
   ```bash
   # Check authorization policies
   kubectl get authorizationpolicy -n mcp-security
   
   # View policy details
   istioctl analyze -n mcp-security
   ```

4. **Gateway Not Accessible**
   ```bash
   # Check gateway status
   kubectl get gateway -n mcp-security
   
   # Check ingress gateway
   kubectl get svc istio-ingressgateway -n istio-system
   ```

### Debug Commands

```bash
# Get proxy configuration
istioctl proxy-config all pod-name.mcp-security

# Check listeners
istioctl proxy-config listeners pod-name.mcp-security

# Check clusters
istioctl proxy-config clusters pod-name.mcp-security

# Check routes
istioctl proxy-config routes pod-name.mcp-security

# Get proxy logs
kubectl logs pod-name -c istio-proxy -n mcp-security
```

## Performance Tuning

### Resource Optimization

```yaml
# Sidecar resource requests/limits
annotations:
  sidecar.istio.io/proxyCPU: "100m"
  sidecar.istio.io/proxyMemory: "128Mi"
  sidecar.istio.io/proxyCPULimit: "200m"
  sidecar.istio.io/proxyMemoryLimit: "256Mi"
```

### Connection Pooling

```yaml
# Optimized connection pool settings
trafficPolicy:
  connectionPool:
    tcp:
      maxConnections: 100
      connectTimeout: 10s
    http:
      http1MaxPendingRequests: 50
      http2MaxRequests: 100
      maxRequestsPerConnection: 10
      maxRetries: 3
```

## Maintenance

### Regular Tasks

1. **Certificate Rotation**
   - Istio automatically rotates service certificates
   - Monitor certificate expiration
   - Ensure cert-manager is healthy for ingress certificates

2. **Configuration Validation**
   ```bash
   # Weekly configuration analysis
   istioctl analyze -A
   
   # Check proxy synchronization
   istioctl proxy-status
   ```

3. **Performance Monitoring**
   - Review service mesh overhead
   - Monitor resource usage
   - Optimize configuration based on traffic patterns

4. **Security Updates**
   - Keep Istio updated to latest stable version
   - Review and update security policies
   - Monitor security advisories

### Backup & Disaster Recovery

```bash
# Backup Istio configuration
kubectl get all,gateway,virtualservice,destinationrule,peerauthentication,authorizationpolicy,requestauthentication,telemetry -n mcp-security -o yaml > istio-backup.yaml

# Backup Istio control plane configuration
kubectl get all -n istio-system -o yaml > istio-system-backup.yaml
```

## Contributing

### Adding New Services

1. **Create Destination Rule**
   ```yaml
   apiVersion: networking.istio.io/v1beta1
   kind: DestinationRule
   metadata:
     name: new-service-dr
   spec:
     host: new-service
     trafficPolicy:
       tls:
         mode: ISTIO_MUTUAL
   ```

2. **Update Virtual Service**
   ```yaml
   # Add routing rules for new service
   - match:
     - uri:
         prefix: "/api/v1/new-service/"
     route:
     - destination:
         host: new-service
   ```

3. **Configure Authorization**
   ```yaml
   # Add authorization rules
   - from:
     - source:
         namespaces: ["mcp-security"]
     to:
     - operation:
         paths: ["/api/v1/new-service/*"]
   ```

### Testing Changes

```bash
# Validate configuration
istioctl analyze -n mcp-security

# Test in staging environment
kustomize build istio/ | kubectl apply --dry-run=client -f -

# Apply with verification
kustomize build istio/ | kubectl apply -f -
istioctl verify-install
```

This Istio service mesh implementation provides enterprise-grade security, observability, and traffic management for the MCP Security Platform, ensuring reliable and secure operation of all microservices.