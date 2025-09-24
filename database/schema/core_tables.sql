-- Fortress Security Database - Core Tables
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Infrastructure
CREATE TABLE clusters (
    cluster_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cluster_name VARCHAR(255) NOT NULL UNIQUE,
    api_endpoint VARCHAR(500) NOT NULL,
    security_posture_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE namespaces (
    namespace_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cluster_id UUID REFERENCES clusters(cluster_id) ON DELETE CASCADE,
    namespace_name VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255),
    risk_score FLOAT DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(cluster_id, namespace_name)
);

CREATE TABLE workloads (
    workload_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    namespace_id UUID REFERENCES namespaces(namespace_id) ON DELETE CASCADE,
    workload_name VARCHAR(255) NOT NULL,
    workload_type VARCHAR(50) NOT NULL,
    image_list TEXT[],
    vulnerability_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Images & Components
CREATE TABLE container_images (
    image_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    image_name VARCHAR(500) NOT NULL,
    image_tag VARCHAR(255) NOT NULL,
    vulnerability_count INTEGER DEFAULT 0,
    scan_status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(image_name, image_tag)
);

CREATE TABLE sbom_components (
    component_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    image_id UUID REFERENCES container_images(image_id) ON DELETE CASCADE,
    component_name VARCHAR(255) NOT NULL,
    component_version VARCHAR(100),
    component_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- CVE & Vulnerabilities
CREATE TABLE cve_database (
    cve_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    cvss_v3_score FLOAT,
    severity VARCHAR(20) NOT NULL,
    exploit_available BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE vulnerabilities (
    vulnerability_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) REFERENCES cve_database(cve_id),
    image_id UUID REFERENCES container_images(image_id),
    workload_id UUID REFERENCES workloads(workload_id),
    component_name VARCHAR(255),
    vulnerability_source VARCHAR(50) NOT NULL,
    scan_timestamp TIMESTAMP NOT NULL,
    remediation_status VARCHAR(20) DEFAULT 'open',
    created_at TIMESTAMP DEFAULT NOW()
);
