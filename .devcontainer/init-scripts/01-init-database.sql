-- Initialize MCP Security Platform database
-- This script sets up the basic schema for development

-- Create additional schemas
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS scanning;
CREATE SCHEMA IF NOT EXISTS reporting;
CREATE SCHEMA IF NOT EXISTS compliance;

-- Grant permissions
GRANT ALL PRIVILEGES ON SCHEMA auth TO mcp_user;
GRANT ALL PRIVILEGES ON SCHEMA scanning TO mcp_user;
GRANT ALL PRIVILEGES ON SCHEMA reporting TO mcp_user;
GRANT ALL PRIVILEGES ON SCHEMA compliance TO mcp_user;

-- Create basic tables for POC

-- Users table
CREATE TABLE IF NOT EXISTS auth.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    is_superuser BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Scan jobs table
CREATE TABLE IF NOT EXISTS scanning.scan_jobs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target VARCHAR(255) NOT NULL,
    scanner_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_by INTEGER REFERENCES auth.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    results JSONB
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS scanning.vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50),
    severity VARCHAR(20),
    title TEXT,
    description TEXT,
    affected_package VARCHAR(255),
    fixed_version VARCHAR(100),
    scan_job_id INTEGER REFERENCES scanning.scan_jobs(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Compliance checks table
CREATE TABLE IF NOT EXISTS compliance.compliance_checks (
    id SERIAL PRIMARY KEY,
    framework VARCHAR(100) NOT NULL,
    control_id VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    score INTEGER DEFAULT 0,
    evidence JSONB,
    scan_job_id INTEGER REFERENCES scanning.scan_jobs(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert demo data for POC
INSERT INTO auth.users (username, email, password_hash, is_superuser) VALUES 
('admin', 'admin@mcp-security.local', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', true),
('demo_user', 'demo@mcp-security.local', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', false)
ON CONFLICT (username) DO NOTHING;

-- Insert sample scan job
INSERT INTO scanning.scan_jobs (name, target, scanner_type, status, created_by) VALUES 
('Demo Container Scan', 'alpine:3.17', 'trivy', 'completed', 1),
('Demo SBOM Analysis', 'nginx:1.24', 'syft', 'completed', 1)
ON CONFLICT DO NOTHING;

-- Insert sample vulnerabilities
INSERT INTO scanning.vulnerabilities (cve_id, severity, title, affected_package, scan_job_id) VALUES 
('CVE-2023-1234', 'HIGH', 'Demo vulnerability for POC', 'openssl', 1),
('CVE-2023-5678', 'MEDIUM', 'Another demo vulnerability', 'curl', 1)
ON CONFLICT DO NOTHING;

-- Insert sample compliance checks
INSERT INTO compliance.compliance_checks (framework, control_id, status, score, scan_job_id) VALUES 
('NIST CSF', 'ID.AM-1', 'passed', 85, 1),
('NIST CSF', 'PR.AC-1', 'failed', 45, 1),
('ISO 27001', 'A.8.1.1', 'passed', 90, 2)
ON CONFLICT DO NOTHING;