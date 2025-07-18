# MCP Security Platform - Testing Infrastructure

Comprehensive testing suite for the MCP Security Platform, including integration tests, end-to-end data flow tests, performance testing, chaos engineering, security scanning, and contract testing.

## Overview

This testing infrastructure provides multiple layers of validation:

1. **Integration Tests** - Service health and basic connectivity
2. **End-to-End Tests** - Complete data flow validation
3. **Performance Tests** - Load testing and benchmarking
4. **Chaos Engineering** - Resilience and failure recovery testing
5. **Security Testing** - Vulnerability scanning and compliance checks
6. **Contract Testing** - Service-to-service communication validation

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Kubernetes cluster (for chaos and security tests)

### Running All Tests

```bash
# Start test environment
cd tests
docker-compose -f docker-compose.test.yml up -d

# Run all test suites
./scripts/run-tests.sh --type all

# Run specific test type
./scripts/run-tests.sh --type integration
./scripts/run-tests.sh --type e2e
./scripts/run-tests.sh --type performance
```

### Running Tests in CI/CD

The testing infrastructure is integrated into GitHub Actions workflows:

- `.github/workflows/ci.yml` - Basic CI pipeline
- `.github/workflows/security-testing.yml` - Comprehensive security scanning

## Test Types

### 1. Integration Tests

**Location**: `tests/integration/`
**Purpose**: Validate service health, connectivity, and basic functionality

```bash
# Run integration tests
python -m pytest integration/ -v

# Run with coverage
python -m pytest integration/ --cov=../services --cov-report=html
```

**Key Test Files**:
- `test_service_health.py` - Service health checks and connectivity
- `test_infrastructure.py` - Database and Redis connectivity
- `test_service_interaction.py` - Basic service-to-service communication

### 2. End-to-End Tests

**Location**: `tests/e2e/`
**Purpose**: Test complete data flow through the platform

```bash
# Run E2E tests
python -m pytest e2e/ -v

# Run specific data flow test
python -m pytest e2e/test_data_flow.py::TestDataIngestionFlow::test_sbom_ingestion_flow -v
```

**Key Test Files**:
- `test_data_flow.py` - Complete ingestion → enrichment → analysis → notification flow
- `test_cross_correlation.py` - Data correlation between different sources
- `test_risk_assessment.py` - End-to-end risk calculation

**Test Scenarios**:
- SBOM ingestion and vulnerability detection
- CVE data processing and correlation
- Runtime behavior analysis
- Risk assessment and notification escalation

### 3. Performance Tests

**Location**: `tests/performance/`
**Purpose**: Load testing, benchmarking, and performance validation

```bash
# Run load tests
python performance/run_load_tests.py \
  --host http://gateway-service:8081 \
  --scenario normal_load \
  --users 50 \
  --time 5m

# Run benchmarks
python performance/benchmark_tests.py --iterations 1000
```

**Load Test Scenarios**:
- `normal_load` - 50 users, 5 minutes
- `stress_test` - 200 users, 10 minutes
- `spike_test` - 500 users, 3 minutes
- `endurance_test` - 100 users, 30 minutes

**Performance Metrics**:
- Response times (average, P95, P99)
- Throughput (requests per second)
- Error rates
- Resource utilization

### 4. Chaos Engineering

**Location**: `tests/chaos/`
**Purpose**: Test system resilience and failure recovery

```bash
# Run chaos tests
python chaos/run_chaos_tests.py \
  --namespace default \
  --gateway-url http://gateway-service:8081

# Run specific chaos experiment
python chaos/run_chaos_tests.py --experiment pod_kill
```

**Chaos Experiments**:
- **Pod Kill** - Random pod termination
- **Network Partition** - Service isolation
- **Resource Exhaustion** - CPU/memory stress
- **Database Failure** - Database connection issues
- **Service Latency** - Artificial delays

### 5. Security Testing

**Location**: `tests/security/`
**Purpose**: Vulnerability scanning, compliance checks, and security validation

```bash
# Run security tests
python security/run_security_tests.py --output-dir /app/results/security

# Run specific security scans
trivy image mcp-platform/gateway:latest
bandit -r ../services/ -f json
```

**Security Test Types**:
- **Container Scanning** - Trivy vulnerability scanning
- **Static Code Analysis** - Bandit and Semgrep
- **Web Application Security** - OWASP ZAP scanning
- **Compliance Checks** - Kubernetes security standards
- **Secret Scanning** - Credential detection

### 6. Contract Testing

**Location**: `tests/contracts/`
**Purpose**: Service-to-service communication contract validation

```bash
# Run contract tests
python contracts/run_contract_tests.py --output-dir /app/results/contracts

# Verify pacts against provider
python contracts/run_contract_tests.py --verify http://auth-service:8085
```

**Contract Types**:
- Gateway ↔ Auth Service
- Gateway ↔ Ingestion Service
- Ingestion ↔ Enrichment Service
- Enrichment ↔ Analysis Service

## Test Environment

### Docker Compose Setup

The test environment uses Docker Compose to orchestrate all services:

```yaml
# Key services in docker-compose.test.yml
services:
  redis:           # Cache and message broker
  postgresql:      # Database
  gateway-service: # API gateway
  auth-service:    # Authentication
  ingestion-service: # Data ingestion
  enrichment-service: # Threat intelligence
  analysis-service: # Security analysis
  notification-service: # Alerting
  plugin-registry: # Plugin management
  test-runner:     # Test execution container
```

### Environment Variables

Configure tests using environment variables:

```bash
# Service URLs
export GATEWAY_URL=http://gateway-service:8081
export AUTH_SERVICE_URL=http://auth-service:8085
export DATABASE_URL=postgresql://mcp_user:mcp_test_password@postgresql:5432/mcp_test
export REDIS_URL=redis://redis:6379

# Test configuration
export TEST_TIMEOUT=300
export VERBOSE=true
export PARALLEL_WORKERS=4
```

## Test Data and Fixtures

### Test Data Generation

Test data is generated using factory classes and realistic samples:

```python
# SBOM test data
SAMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [...]
}

# CVE test data
SAMPLE_CVE = {
    "cve_id": "CVE-2023-12345",
    "severity": "HIGH",
    "cvss_score": 8.5
}
```

### Fixtures Directory

- `tests/fixtures/sql/` - Database initialization scripts
- `tests/fixtures/plugins/` - Test plugin configurations
- `tests/fixtures/prometheus/` - Monitoring configuration
- `tests/fixtures/grafana/` - Dashboard configurations

## Continuous Integration

### GitHub Actions Integration

Tests are automatically executed in CI/CD pipelines:

1. **Pull Request Validation**:
   - Integration tests
   - Security scanning
   - Contract validation

2. **Main Branch Testing**:
   - Full test suite
   - Performance benchmarks
   - Security compliance

3. **Scheduled Testing**:
   - Daily security scans
   - Weekly chaos engineering
   - Monthly performance regression

### Test Reporting

Test results are collected and reported:

- **JUnit XML** - For CI integration
- **HTML Reports** - For detailed analysis
- **JSON Reports** - For programmatic processing
- **SARIF Reports** - For security findings

## Performance Baselines

### Response Time Targets

| Endpoint | P95 Target | P99 Target |
|----------|------------|------------|
| Health checks | < 100ms | < 200ms |
| Authentication | < 500ms | < 1000ms |
| Data ingestion | < 2000ms | < 5000ms |
| Analysis queries | < 1000ms | < 2000ms |

### Throughput Targets

| Operation | Target RPS |
|-----------|------------|
| Health checks | > 1000 |
| Authentication | > 100 |
| SBOM ingestion | > 50 |
| Analysis queries | > 200 |

## Security Baselines

### Vulnerability Thresholds

- **Critical**: 0 allowed
- **High**: ≤ 5 allowed
- **Medium**: ≤ 20 allowed
- **Low**: No limit

### Compliance Requirements

- Pod Security Standards: Restricted
- Network Policies: Required
- RBAC: Least privilege
- Secrets: External secret stores

## Troubleshooting

### Common Issues

1. **Service Startup Timeouts**:
   ```bash
   # Check service logs
   docker-compose -f docker-compose.test.yml logs gateway-service
   
   # Verify health checks
   curl http://localhost:8081/health
   ```

2. **Database Connection Issues**:
   ```bash
   # Check PostgreSQL status
   docker-compose -f docker-compose.test.yml exec postgresql pg_isready
   
   # Verify credentials
   psql postgresql://mcp_user:mcp_test_password@localhost:5432/mcp_test
   ```

3. **Redis Connection Issues**:
   ```bash
   # Test Redis connectivity
   docker-compose -f docker-compose.test.yml exec redis redis-cli ping
   ```

4. **Performance Test Failures**:
   ```bash
   # Check resource utilization
   docker stats
   
   # Increase timeouts for slow environments
   export TEST_TIMEOUT=600
   ```

### Debug Mode

Enable verbose logging and debugging:

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
export PYTEST_VERBOSE=true

# Run tests with detailed output
./scripts/run-tests.sh --verbose --type integration
```

### Test Data Cleanup

Clean up test data between runs:

```bash
# Reset test environment
docker-compose -f docker-compose.test.yml down -v
docker-compose -f docker-compose.test.yml up -d

# Clean test databases
docker-compose -f docker-compose.test.yml exec postgresql \
  psql -U mcp_user -d mcp_test -c "TRUNCATE TABLE test_data CASCADE;"
```

## Contributing

### Adding New Tests

1. Create test files in appropriate directories
2. Follow naming convention: `test_*.py`
3. Use async/await for HTTP operations
4. Include proper error handling and cleanup
5. Add documentation and examples

### Test Guidelines

- **Independence**: Tests should not depend on each other
- **Idempotency**: Tests should be repeatable
- **Cleanup**: Always clean up resources
- **Timeouts**: Use reasonable timeouts
- **Assertions**: Clear and specific assertions

### Performance Considerations

- Use connection pooling for database tests
- Implement proper retry logic
- Cache expensive operations
- Parallelize independent tests
- Monitor resource usage

## Resources

- [Testing Best Practices](./docs/testing-best-practices.md)
- [Performance Testing Guide](./docs/performance-testing.md)
- [Security Testing Guide](./docs/security-testing.md)
- [Chaos Engineering Guide](./docs/chaos-engineering.md)