# PostgreSQL Performance Tuning Guide

**Guide Version**: 1.0  
**Last Updated**: 2024-01-01  
**Target Audience**: Database Administrators, Backend Engineers  

## Overview

This guide provides comprehensive PostgreSQL performance optimization techniques for the MCP Security Platform, covering configuration tuning, query optimization, and monitoring.

## Database Configuration Optimization

### 1. Memory Settings

#### postgresql.conf Optimization
```sql
-- Memory Configuration
shared_buffers = '256MB'                    -- 25% of RAM for dedicated server
effective_cache_size = '1GB'                -- 75% of RAM
work_mem = '4MB'                            -- Per-operation memory
maintenance_work_mem = '64MB'               -- For maintenance operations
wal_buffers = '16MB'                        -- WAL buffer size
temp_buffers = '8MB'                        -- Temporary table buffer

-- Checkpoint Configuration
checkpoint_timeout = '10min'               -- Checkpoint frequency
checkpoint_completion_target = 0.9         -- Spread checkpoint I/O
max_wal_size = '1GB'                       -- Maximum WAL size
min_wal_size = '80MB'                      -- Minimum WAL size

-- Connection Settings
max_connections = 200                       -- Maximum concurrent connections
superuser_reserved_connections = 3         -- Reserved for superusers

-- Query Planner Settings
random_page_cost = 1.1                     -- For SSD storage
effective_io_concurrency = 200             -- Concurrent I/O operations
seq_page_cost = 1.0                        -- Sequential page cost
cpu_tuple_cost = 0.01                      -- CPU tuple processing cost
cpu_index_tuple_cost = 0.005              -- CPU index tuple cost
cpu_operator_cost = 0.0025                 -- CPU operator cost

-- Logging Configuration
log_min_duration_statement = 100           -- Log slow queries (100ms)
log_checkpoints = on                       -- Log checkpoint activity
log_connections = on                       -- Log new connections
log_disconnections = on                    -- Log disconnections
log_lock_waits = on                        -- Log lock waits
log_temp_files = 10MB                      -- Log large temp files
log_autovacuum_min_duration = 0            -- Log all autovacuum activity

-- Autovacuum Configuration
autovacuum = on                            -- Enable autovacuum
autovacuum_max_workers = 3                 -- Number of autovacuum workers
autovacuum_naptime = 1min                  -- Time between autovacuum runs
autovacuum_vacuum_threshold = 50           -- Minimum deleted tuples
autovacuum_vacuum_scale_factor = 0.2       -- Fraction of table size
autovacuum_analyze_threshold = 50          -- Minimum changed tuples
autovacuum_analyze_scale_factor = 0.1      -- Fraction for analyze

-- Background Writer
bgwriter_delay = 200ms                     -- Background writer delay
bgwriter_lru_maxpages = 100               -- Pages written per round
bgwriter_lru_multiplier = 2.0             -- Multiplier for next round
```

### 2. Connection Pool Optimization

#### PgBouncer Configuration
```ini
# pgbouncer.ini
[databases]
mcp_platform = host=localhost port=5432 dbname=mcp_platform
mcp_platform_read = host=replica-host port=5432 dbname=mcp_platform

[pgbouncer]
# Connection pooling
pool_mode = transaction                     # Transaction-level pooling
max_client_conn = 200                      # Maximum client connections
default_pool_size = 20                     # Default pool size
min_pool_size = 5                          # Minimum pool size
reserve_pool_size = 5                      # Reserve connections
reserve_pool_timeout = 5                   # Reserve timeout

# Timeouts
server_connect_timeout = 15                # Server connection timeout
server_login_retry = 15                    # Login retry interval
query_timeout = 0                          # Query timeout (0 = disabled)
query_wait_timeout = 120                   # Query wait timeout
client_idle_timeout = 0                    # Client idle timeout
server_idle_timeout = 600                 # Server idle timeout
server_lifetime = 3600                     # Server connection lifetime

# Authentication
auth_type = md5                            # Authentication method
auth_file = /etc/pgbouncer/userlist.txt   # User list file

# Logging
admin_users = postgres, admin              # Admin users
stats_users = postgres, admin, monitor     # Stats users
log_connections = 1                        # Log connections
log_disconnections = 1                     # Log disconnections
log_pooler_errors = 1                      # Log pooler errors
```

#### Application Connection Pool
```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool, NullPool
import asyncpg

# Primary database connection (write operations)
primary_engine = create_async_engine(
    "postgresql+asyncpg://user:password@primary-host:5432/mcp_platform",
    poolclass=QueuePool,
    pool_size=20,                          # Core connections
    max_overflow=30,                       # Additional connections
    pool_pre_ping=True,                    # Validate connections
    pool_recycle=3600,                     # Recycle after 1 hour
    pool_timeout=30,                       # Connection timeout
    echo=False,                            # Disable SQL logging in production
    connect_args={
        "server_settings": {
            "application_name": "mcp-api-primary",
            "jit": "off",                  # Disable JIT for predictability
        },
        "command_timeout": 30,             # Command timeout
        "connect_timeout": 10,             # Connect timeout
        "prepared_statement_cache_size": 100,  # Prepared statement cache
    }
)

# Read replica connection (read operations)
replica_engine = create_async_engine(
    "postgresql+asyncpg://user:password@replica-host:5432/mcp_platform",
    poolclass=QueuePool,
    pool_size=15,                          # Smaller pool for reads
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={
        "server_settings": {
            "application_name": "mcp-api-replica",
            "default_transaction_isolation": "repeatable_read",
        },
        "command_timeout": 30,
        "connect_timeout": 10,
    }
)

# Session factories
PrimarySession = sessionmaker(primary_engine, class_=AsyncSession, expire_on_commit=False)
ReplicaSession = sessionmaker(replica_engine, class_=AsyncSession, expire_on_commit=False)

class DatabaseManager:
    """Optimized database manager with read/write splitting."""
    
    @staticmethod
    async def get_write_session() -> AsyncSession:
        """Get session for write operations."""
        async with PrimarySession() as session:
            yield session
    
    @staticmethod
    async def get_read_session() -> AsyncSession:
        """Get session for read operations."""
        async with ReplicaSession() as session:
            yield session
```

## Index Optimization

### 3. Index Strategy

#### Core Indexes for MCP Platform
```sql
-- Users table indexes
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_username ON users(username);
CREATE INDEX CONCURRENTLY idx_users_active ON users(is_active) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_users_created_at ON users(created_at);
CREATE INDEX CONCURRENTLY idx_users_last_login ON users(last_login) WHERE last_login IS NOT NULL;

-- Security events indexes
CREATE INDEX CONCURRENTLY idx_security_events_type ON security_events(event_type);
CREATE INDEX CONCURRENTLY idx_security_events_severity ON security_events(severity);
CREATE INDEX CONCURRENTLY idx_security_events_user_id ON security_events(user_id);
CREATE INDEX CONCURRENTLY idx_security_events_created_at ON security_events(created_at);
CREATE INDEX CONCURRENTLY idx_security_events_source_ip ON security_events(source_ip);

-- Composite indexes for common queries
CREATE INDEX CONCURRENTLY idx_security_events_user_type_date 
ON security_events(user_id, event_type, created_at);

CREATE INDEX CONCURRENTLY idx_security_events_severity_date 
ON security_events(severity, created_at) 
WHERE severity IN ('high', 'critical');

-- Vulnerabilities table indexes
CREATE INDEX CONCURRENTLY idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX CONCURRENTLY idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX CONCURRENTLY idx_vulnerabilities_status ON vulnerabilities(status);
CREATE INDEX CONCURRENTLY idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score);
CREATE INDEX CONCURRENTLY idx_vulnerabilities_discovered_at ON vulnerabilities(discovered_at);

-- Vulnerability scans indexes
CREATE INDEX CONCURRENTLY idx_vulnerability_scans_status ON vulnerability_scans(status);
CREATE INDEX CONCURRENTLY idx_vulnerability_scans_type ON vulnerability_scans(scan_type);
CREATE INDEX CONCURRENTLY idx_vulnerability_scans_started_at ON vulnerability_scans(started_at);
CREATE INDEX CONCURRENTLY idx_vulnerability_scans_target ON vulnerability_scans(target);

-- API keys indexes
CREATE INDEX CONCURRENTLY idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX CONCURRENTLY idx_api_keys_active ON api_keys(is_active) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_api_keys_expires_at ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- Audit logs indexes
CREATE INDEX CONCURRENTLY idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX CONCURRENTLY idx_audit_logs_action ON audit_logs(action);
CREATE INDEX CONCURRENTLY idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX CONCURRENTLY idx_audit_logs_resource_type ON audit_logs(resource_type);

-- Partial indexes for specific use cases
CREATE INDEX CONCURRENTLY idx_recent_events 
ON security_events(created_at, event_type) 
WHERE created_at > NOW() - INTERVAL '30 days';

CREATE INDEX CONCURRENTLY idx_active_scans 
ON vulnerability_scans(started_at, scan_type) 
WHERE status IN ('running', 'pending');

-- JSONB indexes for metadata
CREATE INDEX CONCURRENTLY idx_security_events_metadata_gin 
ON security_events USING gin(metadata);

CREATE INDEX CONCURRENTLY idx_vulnerabilities_metadata_gin 
ON vulnerabilities USING gin(metadata);

-- Text search indexes
CREATE INDEX CONCURRENTLY idx_vulnerabilities_title_gin 
ON vulnerabilities USING gin(to_tsvector('english', title));

CREATE INDEX CONCURRENTLY idx_vulnerabilities_description_gin 
ON vulnerabilities USING gin(to_tsvector('english', description));
```

#### Index Maintenance
```sql
-- Monitor index usage
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_tup_read::float / NULLIF(idx_tup_fetch, 0) as selectivity
FROM pg_stat_user_indexes
ORDER BY idx_tup_read DESC;

-- Find unused indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) as size
FROM pg_stat_user_indexes
WHERE idx_scan < 10
ORDER BY pg_relation_size(indexrelid) DESC;

-- Reindex maintenance
REINDEX INDEX CONCURRENTLY idx_security_events_created_at;
REINDEX TABLE CONCURRENTLY security_events;

-- Analyze index effectiveness
EXPLAIN (ANALYZE, BUFFERS) 
SELECT * FROM security_events 
WHERE user_id = 123 AND event_type = 'login_failed' 
ORDER BY created_at DESC LIMIT 10;
```

## Query Optimization

### 4. Query Performance

#### Optimized Queries for Common Operations
```sql
-- Efficient user lookup with related data
WITH user_data AS (
    SELECT 
        u.id,
        u.username,
        u.email,
        u.is_active,
        u.created_at,
        u.last_login
    FROM users u
    WHERE u.id = $1 AND u.is_active = true
),
user_events AS (
    SELECT 
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_events,
        MAX(created_at) as last_event
    FROM security_events se
    WHERE se.user_id = $1 
    AND se.created_at > NOW() - INTERVAL '30 days'
),
user_scans AS (
    SELECT 
        COUNT(*) as total_scans,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_scans
    FROM vulnerability_scans vs
    WHERE vs.created_by = $1
    AND vs.started_at > NOW() - INTERVAL '30 days'
)
SELECT 
    ud.*,
    COALESCE(ue.total_events, 0) as total_events,
    COALESCE(ue.critical_events, 0) as critical_events,
    ue.last_event,
    COALESCE(us.total_scans, 0) as total_scans,
    COALESCE(us.completed_scans, 0) as completed_scans
FROM user_data ud
LEFT JOIN user_events ue ON true
LEFT JOIN user_scans us ON true;

-- Efficient vulnerability dashboard query
SELECT 
    v.id,
    v.title,
    v.severity,
    v.cvss_score,
    v.discovered_at,
    vs.scan_type,
    vs.target,
    COUNT(*) OVER() as total_count
FROM vulnerabilities v
JOIN vulnerability_scans vs ON v.scan_id = vs.id
WHERE 
    ($1::text IS NULL OR v.severity = $1)
    AND ($2::timestamp IS NULL OR v.discovered_at >= $2)
    AND ($3::text IS NULL OR vs.scan_type = $3)
ORDER BY 
    CASE v.severity 
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    v.cvss_score DESC NULLS LAST,
    v.discovered_at DESC
LIMIT $4 OFFSET $5;

-- Efficient aggregation query for statistics
SELECT 
    DATE_TRUNC('day', created_at) as date,
    event_type,
    severity,
    COUNT(*) as event_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT source_ip) as unique_ips
FROM security_events
WHERE created_at >= $1 AND created_at < $2
GROUP BY 
    DATE_TRUNC('day', created_at),
    event_type,
    severity
ORDER BY date DESC, event_count DESC;

-- Efficient search with full-text search
SELECT 
    v.id,
    v.title,
    v.description,
    v.severity,
    v.cvss_score,
    ts_rank(to_tsvector('english', v.title || ' ' || COALESCE(v.description, '')), query) as rank
FROM vulnerabilities v,
     to_tsquery('english', $1) query
WHERE to_tsvector('english', v.title || ' ' || COALESCE(v.description, '')) @@ query
ORDER BY rank DESC, v.cvss_score DESC NULLS LAST
LIMIT 50;
```

#### Query Optimization Techniques
```python
from sqlalchemy import select, func, and_, or_, text
from sqlalchemy.orm import selectinload, joinedload

class OptimizedQueries:
    """Collection of optimized database queries."""
    
    @staticmethod
    async def get_user_dashboard_data(session: AsyncSession, user_id: int):
        """Optimized user dashboard query with single database roundtrip."""
        
        # Use a single CTE query to fetch all related data
        query = text("""
        WITH user_stats AS (
            SELECT 
                u.id,
                u.username,
                u.email,
                u.last_login,
                COUNT(DISTINCT se.id) as total_events,
                COUNT(DISTINCT se.id) FILTER (WHERE se.severity = 'critical') as critical_events,
                COUNT(DISTINCT vs.id) as total_scans,
                COUNT(DISTINCT ak.id) as active_api_keys,
                MAX(se.created_at) as last_event_date
            FROM users u
            LEFT JOIN security_events se ON u.id = se.user_id 
                AND se.created_at > NOW() - INTERVAL '30 days'
            LEFT JOIN vulnerability_scans vs ON u.id = vs.created_by
                AND vs.started_at > NOW() - INTERVAL '30 days'
            LEFT JOIN api_keys ak ON u.id = ak.user_id 
                AND ak.is_active = true
            WHERE u.id = :user_id
            GROUP BY u.id, u.username, u.email, u.last_login
        )
        SELECT * FROM user_stats
        """)
        
        result = await session.execute(query, {"user_id": user_id})
        return result.fetchone()
    
    @staticmethod
    async def get_vulnerability_trends(
        session: AsyncSession, 
        days: int = 30
    ):
        """Optimized vulnerability trend analysis."""
        
        query = text("""
        WITH daily_stats AS (
            SELECT 
                DATE_TRUNC('day', discovered_at) as date,
                severity,
                COUNT(*) as vuln_count,
                AVG(cvss_score) as avg_cvss
            FROM vulnerabilities
            WHERE discovered_at >= NOW() - INTERVAL ':days days'
            GROUP BY DATE_TRUNC('day', discovered_at), severity
        ),
        severity_totals AS (
            SELECT 
                severity,
                SUM(vuln_count) as total_count
            FROM daily_stats
            GROUP BY severity
        )
        SELECT 
            ds.date,
            ds.severity,
            ds.vuln_count,
            ds.avg_cvss,
            st.total_count,
            ds.vuln_count::float / st.total_count as percentage
        FROM daily_stats ds
        JOIN severity_totals st ON ds.severity = st.severity
        ORDER BY ds.date DESC, 
                CASE ds.severity 
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                END
        """)
        
        result = await session.execute(query, {"days": days})
        return result.fetchall()
    
    @staticmethod
    async def bulk_update_scan_status(
        session: AsyncSession,
        scan_ids: List[int],
        status: str
    ):
        """Optimized bulk update operation."""
        
        query = text("""
        UPDATE vulnerability_scans 
        SET 
            status = :status,
            completed_at = CASE 
                WHEN :status IN ('completed', 'failed') THEN NOW()
                ELSE completed_at
            END,
            updated_at = NOW()
        WHERE id = ANY(:scan_ids)
        RETURNING id, status, completed_at
        """)
        
        result = await session.execute(query, {
            "status": status,
            "scan_ids": scan_ids
        })
        
        await session.commit()
        return result.fetchall()
```

## Monitoring and Maintenance

### 5. Performance Monitoring

#### Key Metrics to Monitor
```sql
-- Database size and growth
SELECT 
    pg_database.datname,
    pg_size_pretty(pg_database_size(pg_database.datname)) AS size,
    pg_size_pretty(pg_database_size(pg_database.datname) - 
        LAG(pg_database_size(pg_database.datname)) OVER (ORDER BY pg_database.datname)) AS growth
FROM pg_database
WHERE datname = 'mcp_platform';

-- Table sizes and bloat
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_indexes_size(schemaname||'.'||tablename)) as index_size,
    n_tup_ins + n_tup_upd + n_tup_del as total_operations,
    n_dead_tup,
    n_live_tup,
    CASE 
        WHEN n_live_tup > 0 
        THEN round(n_dead_tup::numeric / n_live_tup::numeric, 4) 
        ELSE 0 
    END as bloat_ratio
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Connection statistics
SELECT 
    state,
    COUNT(*) as connections,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
GROUP BY state
ORDER BY connections DESC;

-- Lock monitoring
SELECT 
    pg_class.relname,
    pg_locks.mode,
    pg_locks.granted,
    pg_stat_activity.query,
    pg_stat_activity.pid,
    pg_stat_activity.state,
    pg_stat_activity.query_start
FROM pg_locks
JOIN pg_class ON pg_locks.relation = pg_class.oid
JOIN pg_stat_activity ON pg_locks.pid = pg_stat_activity.pid
WHERE NOT pg_locks.granted
ORDER BY pg_stat_activity.query_start;

-- Slow query monitoring
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    stddev_time,
    min_time,
    max_time,
    rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 20;

-- Index effectiveness
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) as size,
    CASE 
        WHEN idx_tup_fetch > 0 
        THEN round(idx_tup_read::numeric / idx_tup_fetch::numeric, 2)
        ELSE 0
    END as selectivity
FROM pg_stat_user_indexes
ORDER BY idx_tup_read DESC;
```

#### Automated Monitoring Setup
```python
import asyncio
import asyncpg
from datetime import datetime, timedelta
import json

class DatabaseMonitor:
    """Automated database performance monitoring."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.metrics = {}
    
    async def collect_performance_metrics(self):
        """Collect comprehensive performance metrics."""
        
        conn = await asyncpg.connect(self.connection_string)
        
        try:
            # Database size metrics
            size_result = await conn.fetchrow("""
                SELECT pg_size_pretty(pg_database_size('mcp_platform')) as db_size
            """)
            
            # Connection metrics
            conn_result = await conn.fetch("""
                SELECT state, COUNT(*) as count
                FROM pg_stat_activity
                WHERE pid <> pg_backend_pid()
                GROUP BY state
            """)
            
            # Slow queries
            slow_queries = await conn.fetch("""
                SELECT query, calls, total_time, mean_time
                FROM pg_stat_statements
                WHERE mean_time > 100
                ORDER BY mean_time DESC
                LIMIT 10
            """)
            
            # Cache hit ratio
            cache_hit = await conn.fetchrow("""
                SELECT 
                    round(100.0 * sum(blks_hit) / (sum(blks_hit) + sum(blks_read)), 2) as hit_ratio
                FROM pg_stat_database
                WHERE datname = 'mcp_platform'
            """)
            
            # Lock monitoring
            locks = await conn.fetch("""
                SELECT mode, COUNT(*) as count
                FROM pg_locks
                GROUP BY mode
                ORDER BY count DESC
            """)
            
            self.metrics = {
                "timestamp": datetime.now().isoformat(),
                "database_size": size_result["db_size"],
                "connections": {row["state"]: row["count"] for row in conn_result},
                "cache_hit_ratio": float(cache_hit["hit_ratio"]),
                "slow_queries_count": len(slow_queries),
                "locks": {row["mode"]: row["count"] for row in locks}
            }
            
            # Check for alerts
            await self.check_alerts()
            
        finally:
            await conn.close()
    
    async def check_alerts(self):
        """Check for performance issues and alert."""
        
        alerts = []
        
        # Cache hit ratio alert
        if self.metrics["cache_hit_ratio"] < 95:
            alerts.append({
                "level": "warning",
                "message": f"Low cache hit ratio: {self.metrics['cache_hit_ratio']}%"
            })
        
        # Connection count alert
        total_connections = sum(self.metrics["connections"].values())
        if total_connections > 150:
            alerts.append({
                "level": "warning",
                "message": f"High connection count: {total_connections}"
            })
        
        # Slow queries alert
        if self.metrics["slow_queries_count"] > 5:
            alerts.append({
                "level": "warning",
                "message": f"Multiple slow queries detected: {self.metrics['slow_queries_count']}"
            })
        
        if alerts:
            await self.send_alerts(alerts)
    
    async def send_alerts(self, alerts: list):
        """Send performance alerts."""
        # Implementation for sending alerts (Slack, email, etc.)
        for alert in alerts:
            print(f"ALERT [{alert['level']}]: {alert['message']}")

# Monitoring job
async def run_monitoring():
    """Run continuous database monitoring."""
    monitor = DatabaseMonitor("postgresql://user:pass@host:5432/mcp_platform")
    
    while True:
        try:
            await monitor.collect_performance_metrics()
            await asyncio.sleep(60)  # Run every minute
        except Exception as e:
            print(f"Monitoring error: {e}")
            await asyncio.sleep(60)
```

### 6. Maintenance Operations

#### Automated Maintenance
```sql
-- Vacuum and analyze schedule
-- Run daily during low-traffic hours

-- Full vacuum for heavily updated tables
VACUUM (VERBOSE, ANALYZE) security_events;
VACUUM (VERBOSE, ANALYZE) audit_logs;
VACUUM (VERBOSE, ANALYZE) vulnerability_scans;

-- Analyze statistics for query planner
ANALYZE users;
ANALYZE vulnerabilities;
ANALYZE api_keys;

-- Reindex if needed (check for bloat first)
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) as size,
    pg_size_pretty(pg_relation_size(indexrelid) - pg_relation_size(indexrelid, 'fsm')) as bloat
FROM pg_stat_user_indexes
WHERE pg_relation_size(indexrelid) > 100 * 1024 * 1024  -- > 100MB
ORDER BY pg_relation_size(indexrelid) DESC;

-- Cleanup old data
DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days';
DELETE FROM security_events WHERE created_at < NOW() - INTERVAL '180 days' AND severity = 'info';

-- Update table statistics
UPDATE pg_class SET relpages = 0, reltuples = 0 WHERE relname IN ('security_events', 'audit_logs');
ANALYZE security_events;
ANALYZE audit_logs;
```

#### Backup Optimization
```bash
#!/bin/bash
# Optimized backup script

# Configuration
DB_NAME="mcp_platform"
BACKUP_DIR="/backups/postgresql"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=7

# Create backup with compression
pg_dump \
    --verbose \
    --format=custom \
    --compress=9 \
    --no-owner \
    --no-privileges \
    --exclude-table-data='audit_logs' \
    --exclude-table-data='security_events' \
    $DB_NAME > "${BACKUP_DIR}/mcp_platform_${DATE}.dump"

# Backup large tables separately with parallel jobs
pg_dump \
    --verbose \
    --format=directory \
    --jobs=4 \
    --compress=9 \
    --table=audit_logs \
    --table=security_events \
    $DB_NAME "${BACKUP_DIR}/large_tables_${DATE}"

# Cleanup old backups
find $BACKUP_DIR -name "*.dump" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "large_tables_*" -mtime +$RETENTION_DAYS -exec rm -rf {} \;

# Verify backup
pg_restore --list "${BACKUP_DIR}/mcp_platform_${DATE}.dump" > /dev/null
if [ $? -eq 0 ]; then
    echo "Backup verification successful"
else
    echo "Backup verification failed"
    exit 1
fi
```

---

**Performance Targets**:
- Query response time (P95): < 100ms
- Cache hit ratio: > 95%
- Connection utilization: < 80%
- Index hit ratio: > 99%

**Related Guides**:
- [Query Optimization](./05-query-optimization.md)
- [Connection Pool Tuning](./06-connection-pool-tuning.md)
- [Performance Monitoring](./13-performance-monitoring.md)