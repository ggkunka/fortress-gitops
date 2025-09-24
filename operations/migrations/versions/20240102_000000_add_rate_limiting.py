"""
Migration: Add Rate Limiting Tables
Version: 20240102_000000
Description: Add tables for rate limiting and API throttling
Author: system
Created: 2024-01-02T00:00:00
"""

from datetime import datetime
from operations.migrations.migration_base import SQLMigration, MigrationMetadata


# Define the migration
migration = SQLMigration(
    metadata=MigrationMetadata(
        version="20240102_000000",
        name="Add Rate Limiting Tables",
        description="Add tables for rate limiting and API throttling",
        author="system",
        created_at=datetime(2024, 1, 2, 0, 0, 0)
    ),
    up_sql="""
        -- Rate Limit Rules table
        CREATE TABLE rate_limit_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) UNIQUE NOT NULL,
            description TEXT,
            pattern VARCHAR(500) NOT NULL,
            limit_count INTEGER NOT NULL,
            window_seconds INTEGER NOT NULL,
            scope VARCHAR(100) NOT NULL DEFAULT 'global',
            is_active BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata JSONB DEFAULT '{}'
        );

        -- Rate Limit Violations table
        CREATE TABLE rate_limit_violations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            rule_id UUID REFERENCES rate_limit_rules(id) ON DELETE CASCADE,
            identifier VARCHAR(255) NOT NULL,
            ip_address INET,
            user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            endpoint VARCHAR(500),
            method VARCHAR(10),
            user_agent TEXT,
            violation_count INTEGER DEFAULT 1,
            first_violation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_violation_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            window_start TIMESTAMP NOT NULL,
            window_end TIMESTAMP NOT NULL,
            metadata JSONB DEFAULT '{}'
        );

        -- API Usage Statistics table
        CREATE TABLE api_usage_stats (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID REFERENCES users(id) ON DELETE CASCADE,
            api_key_id UUID REFERENCES api_keys(id) ON DELETE CASCADE,
            endpoint VARCHAR(500) NOT NULL,
            method VARCHAR(10) NOT NULL,
            status_code INTEGER NOT NULL,
            request_count INTEGER DEFAULT 1,
            total_response_time_ms BIGINT DEFAULT 0,
            avg_response_time_ms INTEGER DEFAULT 0,
            date_hour TIMESTAMP NOT NULL, -- Hourly aggregation
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Indexes for rate limiting performance
        CREATE INDEX idx_rate_limit_rules_active ON rate_limit_rules(is_active);
        CREATE INDEX idx_rate_limit_rules_scope ON rate_limit_rules(scope);

        CREATE INDEX idx_rate_limit_violations_rule_id ON rate_limit_violations(rule_id);
        CREATE INDEX idx_rate_limit_violations_identifier ON rate_limit_violations(identifier);
        CREATE INDEX idx_rate_limit_violations_ip ON rate_limit_violations(ip_address);
        CREATE INDEX idx_rate_limit_violations_user_id ON rate_limit_violations(user_id);
        CREATE INDEX idx_rate_limit_violations_window ON rate_limit_violations(window_start, window_end);
        CREATE INDEX idx_rate_limit_violations_endpoint ON rate_limit_violations(endpoint);

        CREATE INDEX idx_api_usage_stats_user_id ON api_usage_stats(user_id);
        CREATE INDEX idx_api_usage_stats_api_key_id ON api_usage_stats(api_key_id);
        CREATE INDEX idx_api_usage_stats_endpoint ON api_usage_stats(endpoint);
        CREATE INDEX idx_api_usage_stats_date_hour ON api_usage_stats(date_hour);
        CREATE INDEX idx_api_usage_stats_status ON api_usage_stats(status_code);

        -- Unique constraint for stats aggregation
        CREATE UNIQUE INDEX idx_api_usage_stats_unique ON api_usage_stats(
            COALESCE(user_id, '00000000-0000-0000-0000-000000000000'),
            COALESCE(api_key_id, '00000000-0000-0000-0000-000000000000'),
            endpoint, 
            method, 
            status_code, 
            date_hour
        );

        -- Update trigger for rate_limit_rules
        CREATE TRIGGER update_rate_limit_rules_updated_at BEFORE UPDATE ON rate_limit_rules
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

        -- Update trigger for api_usage_stats
        CREATE TRIGGER update_api_usage_stats_updated_at BEFORE UPDATE ON api_usage_stats
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

        -- Insert default rate limiting rules
        INSERT INTO rate_limit_rules (name, description, pattern, limit_count, window_seconds, scope) VALUES
        ('default_ip_limit', 'Default rate limit per IP address', '{ip}', 1000, 3600, 'ip'),
        ('default_user_limit', 'Default rate limit per authenticated user', '{user_id}', 5000, 3600, 'user'),
        ('auth_endpoint_limit', 'Rate limit for authentication endpoints', '{ip}:auth', 10, 600, 'auth'),
        ('api_endpoint_limit', 'Rate limit for API endpoints', '{ip}:{endpoint}', 100, 300, 'endpoint');
    """,
    down_sql="""
        -- Drop triggers
        DROP TRIGGER IF EXISTS update_api_usage_stats_updated_at ON api_usage_stats;
        DROP TRIGGER IF EXISTS update_rate_limit_rules_updated_at ON rate_limit_rules;

        -- Drop tables
        DROP TABLE IF EXISTS api_usage_stats;
        DROP TABLE IF EXISTS rate_limit_violations;
        DROP TABLE IF EXISTS rate_limit_rules;
    """
)