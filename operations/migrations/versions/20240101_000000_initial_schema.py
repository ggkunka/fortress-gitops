"""
Migration: Initial Schema
Version: 20240101_000000
Description: Create initial database schema for MCP Security Platform
Author: system
Created: 2024-01-01T00:00:00
"""

from datetime import datetime
from operations.migrations.migration_base import SQLMigration, MigrationMetadata


# Define the migration
migration = SQLMigration(
    metadata=MigrationMetadata(
        version="20240101_000000",
        name="Initial Schema",
        description="Create initial database schema for MCP Security Platform",
        author="system",
        created_at=datetime(2024, 1, 1, 0, 0, 0)
    ),
    up_sql="""
        -- Users table
        CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(255),
            is_active BOOLEAN DEFAULT true,
            is_superuser BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            metadata JSONB DEFAULT '{}'
        );

        -- API Keys table
        CREATE TABLE api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(255) NOT NULL,
            key_hash VARCHAR(255) UNIQUE NOT NULL,
            scopes TEXT[] DEFAULT '{}',
            is_active BOOLEAN DEFAULT true,
            expires_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            metadata JSONB DEFAULT '{}'
        );

        -- Security Events table
        CREATE TABLE security_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            event_type VARCHAR(100) NOT NULL,
            severity VARCHAR(20) NOT NULL,
            source VARCHAR(255) NOT NULL,
            title VARCHAR(500) NOT NULL,
            description TEXT,
            source_ip INET,
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            user_agent TEXT,
            metadata JSONB DEFAULT '{}',
            raw_data JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            resolved_by UUID REFERENCES users(id) ON DELETE SET NULL
        );

        -- Vulnerability Scans table
        CREATE TABLE vulnerability_scans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_type VARCHAR(100) NOT NULL,
            target VARCHAR(500) NOT NULL,
            status VARCHAR(50) NOT NULL,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            scan_duration_ms INTEGER,
            vulnerabilities_found INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            scan_config JSONB DEFAULT '{}',
            results JSONB DEFAULT '{}',
            metadata JSONB DEFAULT '{}'
        );

        -- Vulnerabilities table
        CREATE TABLE vulnerabilities (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            scan_id UUID REFERENCES vulnerability_scans(id) ON DELETE CASCADE,
            vulnerability_id VARCHAR(255) NOT NULL,
            title VARCHAR(500) NOT NULL,
            description TEXT,
            severity VARCHAR(20) NOT NULL,
            cvss_score DECIMAL(3,1),
            cve_ids TEXT[] DEFAULT '{}',
            affected_component VARCHAR(255),
            affected_version VARCHAR(100),
            fixed_version VARCHAR(100),
            solution TEXT,
            references TEXT[] DEFAULT '{}',
            category VARCHAR(100),
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(50) DEFAULT 'open',
            risk_score INTEGER,
            metadata JSONB DEFAULT '{}'
        );

        -- Audit Logs table
        CREATE TABLE audit_logs (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            action VARCHAR(255) NOT NULL,
            resource_type VARCHAR(100),
            resource_id VARCHAR(255),
            old_values JSONB,
            new_values JSONB,
            ip_address INET,
            user_agent TEXT,
            session_id VARCHAR(255),
            correlation_id VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata JSONB DEFAULT '{}'
        );

        -- Notifications table
        CREATE TABLE notifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            title VARCHAR(500) NOT NULL,
            message TEXT NOT NULL,
            notification_type VARCHAR(100) NOT NULL,
            priority VARCHAR(20) DEFAULT 'medium',
            is_read BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            read_at TIMESTAMP,
            expires_at TIMESTAMP,
            metadata JSONB DEFAULT '{}'
        );

        -- System Configuration table
        CREATE TABLE system_config (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            key VARCHAR(255) UNIQUE NOT NULL,
            value JSONB NOT NULL,
            description TEXT,
            is_sensitive BOOLEAN DEFAULT false,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by UUID REFERENCES users(id) ON DELETE SET NULL
        );

        -- Indexes for performance
        CREATE INDEX idx_users_username ON users(username);
        CREATE INDEX idx_users_email ON users(email);
        CREATE INDEX idx_users_active ON users(is_active);

        CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
        CREATE INDEX idx_api_keys_active ON api_keys(is_active);
        CREATE INDEX idx_api_keys_expires ON api_keys(expires_at);

        CREATE INDEX idx_security_events_type ON security_events(event_type);
        CREATE INDEX idx_security_events_severity ON security_events(severity);
        CREATE INDEX idx_security_events_source ON security_events(source);
        CREATE INDEX idx_security_events_created ON security_events(created_at);
        CREATE INDEX idx_security_events_user_id ON security_events(user_id);

        CREATE INDEX idx_vulnerability_scans_type ON vulnerability_scans(scan_type);
        CREATE INDEX idx_vulnerability_scans_status ON vulnerability_scans(status);
        CREATE INDEX idx_vulnerability_scans_started ON vulnerability_scans(started_at);

        CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
        CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
        CREATE INDEX idx_vulnerabilities_status ON vulnerabilities(status);
        CREATE INDEX idx_vulnerabilities_discovered ON vulnerabilities(discovered_at);

        CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
        CREATE INDEX idx_audit_logs_action ON audit_logs(action);
        CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
        CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);

        CREATE INDEX idx_notifications_user_id ON notifications(user_id);
        CREATE INDEX idx_notifications_type ON notifications(notification_type);
        CREATE INDEX idx_notifications_read ON notifications(is_read);
        CREATE INDEX idx_notifications_created ON notifications(created_at);

        CREATE INDEX idx_system_config_key ON system_config(key);

        -- Update triggers for updated_at columns
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';

        CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

        CREATE TRIGGER update_security_events_updated_at BEFORE UPDATE ON security_events
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

        CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON system_config
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    """,
    down_sql="""
        -- Drop triggers
        DROP TRIGGER IF EXISTS update_system_config_updated_at ON system_config;
        DROP TRIGGER IF EXISTS update_security_events_updated_at ON security_events;
        DROP TRIGGER IF EXISTS update_users_updated_at ON users;
        
        -- Drop function
        DROP FUNCTION IF EXISTS update_updated_at_column();

        -- Drop tables in reverse order (respecting foreign keys)
        DROP TABLE IF EXISTS system_config;
        DROP TABLE IF EXISTS notifications;
        DROP TABLE IF EXISTS audit_logs;
        DROP TABLE IF EXISTS vulnerabilities;
        DROP TABLE IF EXISTS vulnerability_scans;
        DROP TABLE IF EXISTS security_events;
        DROP TABLE IF EXISTS api_keys;
        DROP TABLE IF EXISTS users;
    """
)