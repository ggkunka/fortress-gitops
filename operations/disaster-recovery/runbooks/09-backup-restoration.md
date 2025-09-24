# Backup Restoration - Disaster Recovery Runbook

**Incident Type**: Data Recovery  
**Severity**: 2-3 (Depends on scope)  
**Response Time**: 1 hour  
**Last Updated**: 2024-01-01  

## Overview

This runbook covers procedures for restoring data from backups in various scenarios including data corruption, accidental deletion, system failures, and disaster recovery situations.

## Pre-Restoration Checklist

### 1. Situation Assessment
- [ ] Identify what needs to be restored
- [ ] Determine scope of data loss
- [ ] Confirm backup availability
- [ ] Assess current system state
- [ ] Estimate restoration time

### 2. Risk Assessment
- [ ] Impact of current downtime
- [ ] Risk of restoration process
- [ ] Backup to current state before restore
- [ ] Identify rollback procedures
- [ ] Notify stakeholders

### 3. Backup Verification
```bash
# Check backup availability
python -m operations.backup.backup_manager list-backups

# Verify backup integrity
python -m operations.backup.backup_manager verify-backup --backup-id BACKUP_ID

# Check backup metadata
cat /operations/backups/metadata.json | jq '.backups[] | select(.backup_id=="BACKUP_ID")'
```

## Database Restoration

### 4. PostgreSQL Database Restore

#### Point-in-Time Recovery
```bash
# Stop application services first
kubectl scale deployment api-server --replicas=0
kubectl scale deployment web-server --replicas=0
kubectl scale deployment workers --replicas=0

# Backup current database state
pg_dump -h db-primary -U postgres -d mcp_platform > current-state-backup.sql

# Prepare for restoration
sudo systemctl stop postgresql

# Restore base backup
tar -xzf /backups/postgresql-base-backup.tar.gz -C /var/lib/postgresql/12/main/

# Configure recovery
cat > /var/lib/postgresql/12/main/recovery.conf << EOF
restore_command = 'cp /backups/wal/%f %p'
recovery_target_time = '2024-01-01 12:00:00'
recovery_target_inclusive = true
EOF

# Start database in recovery mode
sudo systemctl start postgresql

# Monitor recovery progress
tail -f /var/log/postgresql/postgresql-12-main.log
```

#### Full Database Restore
```bash
# Create new database instance
createdb -h db-primary -U postgres mcp_platform_restore

# Restore from backup
pg_restore -h db-primary -U postgres -d mcp_platform_restore \
  --verbose --clean --if-exists /backups/database_backup.dump

# Verify data integrity
psql -h db-primary -U postgres -d mcp_platform_restore -c "
SELECT 
  schemaname,
  tablename,
  n_tup_ins,
  n_tup_upd,
  n_tup_del
FROM pg_stat_user_tables
ORDER BY schemaname, tablename;
"

# Switch database (if verification successful)
psql -h db-primary -U postgres -c "
ALTER DATABASE mcp_platform RENAME TO mcp_platform_old;
ALTER DATABASE mcp_platform_restore RENAME TO mcp_platform;
"
```

### 5. MySQL Database Restore
```bash
# Stop application services
kubectl scale deployment api-server --replicas=0

# Create restore database
mysql -h db-primary -u root -p -e "CREATE DATABASE mcp_platform_restore;"

# Restore from backup
mysql -h db-primary -u root -p mcp_platform_restore < /backups/mysql_backup.sql

# Verify restoration
mysql -h db-primary -u root -p -e "
USE mcp_platform_restore;
SELECT 
  TABLE_SCHEMA,
  TABLE_NAME,
  TABLE_ROWS,
  DATA_LENGTH,
  INDEX_LENGTH
FROM information_schema.TABLES 
WHERE TABLE_SCHEMA = 'mcp_platform_restore'
ORDER BY TABLE_NAME;
"

# Switch databases
mysql -h db-primary -u root -p -e "
RENAME TABLE mcp_platform.users TO mcp_platform_old.users;
RENAME TABLE mcp_platform_restore.users TO mcp_platform.users;
-- Repeat for all tables
"
```

### 6. MongoDB Restore
```bash
# Stop application services
kubectl scale deployment api-server --replicas=0

# Extract backup
tar -xzf /backups/mongodb_backup.tar.gz -C /tmp/

# Restore database
mongorestore --host mongodb-primary:27017 \
  --db mcp_platform_restore \
  --drop /tmp/mongodb_backup/mcp_platform/

# Verify collections
mongo mongodb-primary:27017/mcp_platform_restore --eval "
db.runCommand('listCollections').cursor.firstBatch.forEach(
  function(collection) {
    print(collection.name + ': ' + db[collection.name].count() + ' documents');
  }
);
"

# Switch database
mongo mongodb-primary:27017/admin --eval "
db.runCommand({
  renameCollection: 'mcp_platform.users',
  to: 'mcp_platform_old.users'
});
db.runCommand({
  renameCollection: 'mcp_platform_restore.users',
  to: 'mcp_platform.users'
});
"
```

## File System Restoration

### 7. Application Files Restore
```bash
# Create restoration directory
mkdir -p /tmp/file-restore

# Extract file backup
tar -xzf /backups/files_backup.tar.gz -C /tmp/file-restore/

# Verify backup contents
find /tmp/file-restore -type f | head -20
ls -la /tmp/file-restore/

# Stop affected services
kubectl scale deployment api-server --replicas=0
kubectl scale deployment web-server --replicas=0

# Backup current files
tar -czf /tmp/current-files-backup.tar.gz /opt/app/

# Restore files
cp -r /tmp/file-restore/opt/app/* /opt/app/

# Fix permissions
chown -R app:app /opt/app/
chmod -R 755 /opt/app/

# Verify file integrity
find /opt/app -type f -name "*.py" | xargs python -m py_compile
```

### 8. Configuration Restore
```bash
# Extract configuration backup
tar -xzf /backups/config_backup.tar.gz -C /tmp/

# Backup current configurations
cp -r /etc/app/ /tmp/current-config-backup/

# Restore configurations
cp -r /tmp/config_backup/etc/app/* /etc/app/

# Update Kubernetes configurations
kubectl create configmap app-config --from-file=/etc/app/config.yaml --dry-run=client -o yaml | kubectl apply -f -

# Restart services to pick up new config
kubectl rollout restart deployment/api-server
kubectl rollout restart deployment/web-server
```

## Container and Orchestration Restore

### 9. Kubernetes State Restore
```bash
# Backup current Kubernetes state
kubectl get all --all-namespaces -o yaml > current-k8s-state.yaml

# Restore from backup
kubectl apply -f /backups/kubernetes-backup.yaml

# Verify deployments
kubectl get deployments --all-namespaces
kubectl get services --all-namespaces
kubectl get configmaps --all-namespaces

# Check pod status
kubectl get pods --all-namespaces | grep -v Running
```

### 10. Docker Volume Restore
```bash
# Stop containers using the volume
docker stop $(docker ps -q --filter volume=app-data)

# Create new volume from backup
docker volume create app-data-restored
docker run --rm -v app-data-restored:/restore -v /backups:/backup alpine sh -c "cd /restore && tar -xzf /backup/docker-volumes.tar.gz"

# Update container to use restored volume
docker run -d --name app-restored -v app-data-restored:/app/data myapp:latest

# Verify data
docker exec app-restored ls -la /app/data/
```

## Application-Specific Restoration

### 11. User Data Restoration
```sql
-- Restore user accounts
COPY users FROM '/backups/users.csv' WITH CSV HEADER;

-- Restore user sessions
COPY user_sessions FROM '/backups/sessions.csv' WITH CSV HEADER;

-- Restore API keys
COPY api_keys FROM '/backups/api_keys.csv' WITH CSV HEADER;

-- Verify user data integrity
SELECT 
  COUNT(*) as total_users,
  COUNT(CASE WHEN is_active THEN 1 END) as active_users,
  MAX(created_at) as latest_user
FROM users;
```

### 12. Security Events Restoration
```sql
-- Restore security events
COPY security_events FROM '/backups/security_events.csv' WITH CSV HEADER;

-- Restore vulnerability data
COPY vulnerabilities FROM '/backups/vulnerabilities.csv' WITH CSV HEADER;

-- Verify security data
SELECT 
  event_type,
  COUNT(*) as event_count,
  MAX(created_at) as latest_event
FROM security_events
GROUP BY event_type
ORDER BY event_count DESC;
```

## Verification and Testing

### 13. Data Integrity Checks
```bash
# Database integrity
psql -d mcp_platform -c "
-- Check for referential integrity
SELECT 
  tc.table_name,
  tc.constraint_name,
  tc.constraint_type
FROM information_schema.table_constraints tc
WHERE tc.constraint_type = 'FOREIGN KEY'
AND tc.table_schema = 'public';

-- Verify constraints
SELECT conname, confrelid::regclass, af.attname, cl.relname, a.attname
FROM pg_constraint pgc
JOIN pg_class cl ON cl.oid = pgc.conrelid
JOIN pg_attribute a ON a.attrelid = pgc.conrelid AND a.attnum = ANY(pgc.conkey)
JOIN pg_class fcl ON fcl.oid = pgc.confrelid
JOIN pg_attribute af ON af.attrelid = pgc.confrelid AND af.attnum = ANY(pgc.confkey)
WHERE pgc.contype = 'f';
"

# File system integrity
find /opt/app -type f -exec sha256sum {} + > /tmp/restored-checksums.txt
diff /backups/original-checksums.txt /tmp/restored-checksums.txt
```

### 14. Application Testing
```bash
# Start services gradually
kubectl scale deployment api-server --replicas=1
kubectl wait --for=condition=Ready pod -l app=api-server --timeout=300s

kubectl scale deployment web-server --replicas=1
kubectl wait --for=condition=Ready pod -l app=web-server --timeout=300s

# Run health checks
curl -f http://api-server:8000/health
curl -f http://web-server:3000/health

# Run smoke tests
cd /opt/app/tests
python -m pytest smoke_tests/ -v

# Verify core functionality
python test_restore_verification.py
```

### 15. User Acceptance Testing
- [ ] Test user authentication
- [ ] Verify data accessibility
- [ ] Check recent changes present
- [ ] Validate permissions
- [ ] Test critical user journeys

## Rollback Procedures

### 16. Restoration Rollback
```bash
# If restoration fails, rollback to pre-restore state

# Database rollback
psql -h db-primary -U postgres -c "
DROP DATABASE mcp_platform;
ALTER DATABASE mcp_platform_old RENAME TO mcp_platform;
"

# File system rollback
rm -rf /opt/app/*
tar -xzf /tmp/current-files-backup.tar.gz -C /

# Configuration rollback
rm -rf /etc/app/*
cp -r /tmp/current-config-backup/* /etc/app/

# Restart services
kubectl rollout restart deployment/api-server
kubectl rollout restart deployment/web-server
```

## Post-Restoration Activities

### 17. Service Restart
```bash
# Gradually scale up services
kubectl scale deployment api-server --replicas=3
kubectl scale deployment web-server --replicas=2
kubectl scale deployment workers --replicas=4

# Monitor for issues
kubectl get pods -w
kubectl logs -f deployment/api-server
```

### 18. Monitoring and Alerting
```bash
# Verify monitoring systems
curl http://prometheus:9090/api/v1/targets
curl http://grafana:3000/api/health

# Check alert status
curl http://alertmanager:9093/api/v1/alerts

# Verify metrics collection
curl "http://prometheus:9090/api/v1/query?query=up"
```

### 19. Documentation
- [ ] Document restoration process
- [ ] Record timeline and issues
- [ ] Update incident log
- [ ] Note lessons learned
- [ ] Update runbook if needed

## Automated Restoration Scripts

### 20. Full System Restore Script
```bash
#!/bin/bash
# full-restore.sh

set -e

BACKUP_ID=${1:?"Backup ID required"}
TARGET_TIME=${2:-"latest"}

echo "Starting full system restore..."
echo "Backup ID: $BACKUP_ID"
echo "Target Time: $TARGET_TIME"

# Pre-restore backup
echo "Creating pre-restore backup..."
python -m operations.backup.backup_manager create-backup --type=all

# Scale down services
echo "Scaling down services..."
kubectl scale deployment api-server --replicas=0
kubectl scale deployment web-server --replicas=0
kubectl scale deployment workers --replicas=0

# Restore database
echo "Restoring database..."
python -m operations.backup.restore_manager restore \
  --backup-id=$BACKUP_ID \
  --type=database \
  --target-time="$TARGET_TIME"

# Restore files
echo "Restoring files..."
python -m operations.backup.restore_manager restore \
  --backup-id=$BACKUP_ID \
  --type=files

# Restore configuration
echo "Restoring configuration..."
python -m operations.backup.restore_manager restore \
  --backup-id=$BACKUP_ID \
  --type=config

# Scale up services
echo "Scaling up services..."
kubectl scale deployment api-server --replicas=3
kubectl scale deployment web-server --replicas=2
kubectl scale deployment workers --replicas=4

# Wait for services
echo "Waiting for services to be ready..."
kubectl wait --for=condition=Ready pod -l app=api-server --timeout=300s
kubectl wait --for=condition=Ready pod -l app=web-server --timeout=300s

# Run verification
echo "Running verification tests..."
python -m tests.restore_verification

echo "Restoration completed successfully!"
```

## Backup Types and Procedures

### 21. Database Backups
- **Full backup**: Complete database dump
- **Incremental**: WAL/binlog segments
- **Point-in-time**: PITR capabilities
- **Logical**: Schema + data
- **Physical**: Raw database files

### 22. File System Backups
- **Application code**: Source files
- **User uploads**: Media files
- **Configuration**: Settings files
- **Logs**: Historical data
- **Certificates**: SSL/TLS certs

### 23. System State Backups
- **Container images**: Docker registry
- **Kubernetes objects**: YAML manifests
- **Secrets**: Encrypted credentials
- **Network configuration**: Routing rules
- **Monitoring setup**: Alerts and dashboards

## Recovery Time Objectives

| Component | RTO | RPO | Priority |
|-----------|-----|-----|----------|
| Database | 1 hour | 15 minutes | Critical |
| API Services | 30 minutes | 1 hour | High |
| Web Application | 30 minutes | 1 hour | High |
| Background Workers | 2 hours | 4 hours | Medium |
| Monitoring | 1 hour | 24 hours | Medium |

## Success Criteria

- [ ] All services operational
- [ ] Data integrity verified
- [ ] User access restored
- [ ] Monitoring functional
- [ ] No data loss beyond RPO
- [ ] Performance within SLA

---

**Next Review Date**: [DATE]  
**Runbook Owner**: Operations Team  
**Emergency Contact**: ops@mcpsecurity.com