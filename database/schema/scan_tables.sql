-- Fortress Security Database - Scan Management Tables

-- Scan Configurations
CREATE TABLE scan_configurations (
    config_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cluster_id UUID REFERENCES clusters(cluster_id),
    config_name VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50) NOT NULL, -- reconnaissance, discovery, assessment, validation
    tool_name VARCHAR(50) NOT NULL, -- trivy, syft, kube-bench, falco
    scan_parameters JSONB,
    schedule_cron VARCHAR(100),
    performance_limits JSONB,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Scan Executions
CREATE TABLE scan_executions (
    execution_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_id UUID REFERENCES scan_configurations(config_id),
    cluster_id UUID REFERENCES clusters(cluster_id),
    namespace_id UUID REFERENCES namespaces(namespace_id),
    tenant_id VARCHAR(255),
    scan_phase VARCHAR(50), -- reconnaissance, discovery, assessment, validation
    scan_status VARCHAR(20) DEFAULT 'pending', -- pending, running, completed, failed
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    findings_count INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    performance_impact JSONB,
    error_message TEXT,
    report_location VARCHAR(500), -- MinIO path
    agent_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Performance Metrics
CREATE TABLE scan_performance_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID REFERENCES scan_executions(execution_id),
    cluster_id UUID REFERENCES clusters(cluster_id),
    cpu_usage FLOAT,
    memory_usage FLOAT,
    network_usage FLOAT,
    scan_overhead FLOAT,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- Scan Results Summary
CREATE TABLE scan_results (
    result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID REFERENCES scan_executions(execution_id),
    vulnerability_id UUID REFERENCES vulnerabilities(vulnerability_id),
    finding_type VARCHAR(50), -- vulnerability, misconfiguration, compliance_violation
    severity VARCHAR(20),
    confidence_score FLOAT,
    remediation_effort VARCHAR(20), -- low, medium, high
    business_impact VARCHAR(20), -- low, medium, high, critical
    created_at TIMESTAMP DEFAULT NOW()
);
