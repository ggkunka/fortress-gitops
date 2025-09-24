# Data Breach Response - Disaster Recovery Runbook

**Incident Type**: Security Incident  
**Severity**: 1 (Critical)  
**Response Time**: 15 minutes  
**Last Updated**: 2024-01-01  

## Overview

This runbook provides step-by-step procedures for responding to a confirmed or suspected data breach. This includes unauthorized access to customer data, internal systems, or sensitive information.

⚠️ **CRITICAL**: Data breaches have legal, regulatory, and reputational implications. Follow this runbook carefully and escalate immediately.

## Immediate Actions (0-15 minutes)

### 1. Incident Declaration
- [ ] Declare Severity 1 security incident
- [ ] Page security incident commander
- [ ] Create secure incident channel: `#security-incident-YYYYMMDD`
- [ ] **DO NOT** update public status page initially
- [ ] Notify legal team immediately

### 2. Initial Containment
- [ ] Preserve evidence - DO NOT clean up yet
- [ ] Isolate affected systems if safe to do so
- [ ] Document everything with timestamps
- [ ] Secure incident communication channels

### 3. Team Assembly
- [ ] Page CISO or Security Lead
- [ ] Page Legal Counsel
- [ ] Page Privacy Officer
- [ ] Page Communications Lead
- [ ] Page Technical Lead

## Investigation Phase (15-60 minutes)

### 4. Evidence Preservation
```bash
# Create forensic snapshots BEFORE any changes
aws ec2 create-snapshot --volume-id vol-xxxxx --description "Security incident snapshot"

# Preserve logs
kubectl logs -l app=api-server --since=24h > incident-api-logs.txt
kubectl logs -l app=auth-service --since=24h > incident-auth-logs.txt

# Export database audit logs
psql -c "COPY (SELECT * FROM audit_logs WHERE created_at > NOW() - INTERVAL '7 days') TO '/tmp/audit_export.csv' CSV HEADER;"

# Capture network traffic if still ongoing
tcpdump -w incident-capture.pcap -i eth0
```

### 5. Initial Assessment
- [ ] Determine attack vector
- [ ] Identify affected systems
- [ ] Estimate scope of data accessed
- [ ] Timeline of unauthorized access
- [ ] Current threat status (ongoing/contained)

### 6. System Forensics
```bash
# Check for unauthorized access
grep -r "AUTHENTICATION_FAILED\|UNAUTHORIZED" /var/log/
journalctl -u ssh --since "24 hours ago" | grep -i fail

# Check for privilege escalation
ausearch -m avc,user_acct,cred_acq -ts today
grep -r "sudo\|su " /var/log/auth.log

# Check for data exfiltration
netstat -an | grep :443
ss -tuln | grep -E "(:443|:80|:22)"
lsof -i -P | grep -E "(ESTABLISHED|LISTEN)"

# Check file access
find /var/lib/postgresql -type f -mtime -1 -ls
find /opt/app/data -type f -mtime -1 -ls
```

## Containment Actions

### 7. Immediate Containment
```bash
# Block suspicious IP addresses
iptables -A INPUT -s SUSPICIOUS_IP -j DROP
kubectl patch networkpolicy default-deny -p '{"spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"TRUSTED_CIDR"}}]}]}}'

# Disable compromised accounts
kubectl patch secret user-credentials -p '{"data":{"COMPROMISED_USER":""}}'
psql -c "UPDATE users SET is_active = false WHERE username IN ('compromised_user1', 'compromised_user2');"

# Revoke API keys
psql -c "UPDATE api_keys SET is_active = false WHERE created_at > 'SUSPICIOUS_TIMESTAMP';"

# Isolate affected servers
# Only if absolutely necessary and after evidence preservation
kubectl cordon NODE_NAME
kubectl drain NODE_NAME --ignore-daemonsets
```

### 8. Access Control Hardening
```bash
# Force password reset for all users
psql -c "UPDATE users SET force_password_reset = true;"

# Revoke all active sessions
redis-cli FLUSHDB 1  # Session storage

# Regenerate JWT signing keys
openssl rand -base64 32 > new-jwt-secret.key
kubectl create secret generic jwt-secret --from-file=key=new-jwt-secret.key --dry-run=client -o yaml | kubectl apply -f -

# Update API rate limits
kubectl patch configmap rate-limit-config -p '{"data":{"default_limit":"10"}}'
```

## Investigation Deep Dive

### 9. Forensic Analysis
```bash
# Analyze authentication logs
awk '/AUTHENTICATION_FAILED/ {print $1, $2, $3, $NF}' /var/log/auth.log | sort | uniq -c | sort -nr

# Check database access patterns
psql -c "
SELECT 
    user_id, 
    action, 
    resource_type,
    COUNT(*) as access_count,
    MIN(created_at) as first_access,
    MAX(created_at) as last_access
FROM audit_logs 
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY user_id, action, resource_type
HAVING COUNT(*) > 100
ORDER BY access_count DESC;
"

# Analyze API access patterns
grep -E "POST|PUT|DELETE" /var/log/nginx/access.log | \
awk '{print $1, $7, $9}' | sort | uniq -c | sort -nr | head -20
```

### 10. Data Impact Assessment
```sql
-- Identify potentially accessed customer data
SELECT 
    table_name,
    column_name,
    data_type
FROM information_schema.columns 
WHERE table_name IN (
    'users', 'security_events', 'vulnerabilities', 
    'api_keys', 'audit_logs', 'notifications'
)
AND column_name LIKE '%email%' OR column_name LIKE '%name%' 
OR column_name LIKE '%phone%' OR column_name LIKE '%address%';

-- Count affected records
SELECT 
    'users' as table_name, COUNT(*) as record_count 
FROM users 
WHERE updated_at > 'INCIDENT_START_TIME'
UNION ALL
SELECT 
    'security_events', COUNT(*) 
FROM security_events 
WHERE created_at > 'INCIDENT_START_TIME';
```

### 11. Attack Vector Analysis
- [ ] SQL injection attempts
- [ ] Authentication bypass
- [ ] Privilege escalation
- [ ] Social engineering
- [ ] Insider threat
- [ ] Third-party compromise
- [ ] Misconfigured security

## Notification Requirements

### 12. Legal and Regulatory Notifications

**GDPR Requirements** (if EU data affected):
- [ ] Notify supervisory authority within 72 hours
- [ ] Notify affected individuals if high risk
- [ ] Document breach details and response

**CCPA Requirements** (if California residents affected):
- [ ] Notify California Attorney General
- [ ] Notify affected individuals without unreasonable delay

**Other Regulations**:
- [ ] HIPAA (if health data affected)
- [ ] SOX (if financial data affected)
- [ ] State breach notification laws

### 13. Customer Communication
```
Subject: Important Security Notice - MCP Security Platform

We are writing to inform you of a security incident that may have affected your account information.

What Happened:
On [DATE], we discovered unauthorized access to [SPECIFIC SYSTEMS]. We immediately took action to secure our systems and began an investigation.

What Information Was Involved:
[SPECIFIC DATA TYPES - be precise and honest]

What We Are Doing:
- We have secured the affected systems
- We are working with cybersecurity experts and law enforcement
- We are implementing additional security measures
- We are providing [SPECIFIC PROTECTIVE MEASURES]

What You Can Do:
- Change your password immediately
- Monitor your accounts for unusual activity
- Enable two-factor authentication
- Contact us with any concerns

We sincerely apologize for this incident and any inconvenience it may cause.

Contact Information:
security@mcpsecurity.com
1-800-XXX-XXXX (dedicated incident line)
```

## Recovery and Remediation

### 14. System Hardening
```bash
# Update all systems
apt update && apt upgrade -y
yum update -y

# Patch vulnerabilities
kubectl set image deployment/api-server api-server=mcpsecurity/api:patched-version
kubectl set image deployment/auth-service auth-service=mcpsecurity/auth:patched-version

# Update security configurations
kubectl apply -f security/network-policies/
kubectl apply -f security/pod-security-policies/

# Enhance monitoring
kubectl apply -f monitoring/security-monitoring.yaml
```

### 15. Access Control Review
```sql
-- Review all user permissions
SELECT 
    u.username,
    u.is_superuser,
    u.last_login,
    COUNT(ak.id) as api_key_count
FROM users u
LEFT JOIN api_keys ak ON u.id = ak.user_id
GROUP BY u.id, u.username, u.is_superuser, u.last_login
ORDER BY u.is_superuser DESC, u.last_login DESC;

-- Audit recent permission changes
SELECT * FROM audit_logs 
WHERE action IN ('PERMISSION_GRANTED', 'ROLE_ASSIGNED', 'USER_CREATED')
AND created_at > NOW() - INTERVAL '30 days'
ORDER BY created_at DESC;
```

### 16. Security Enhancements
- [ ] Implement additional access controls
- [ ] Enhance monitoring and alerting
- [ ] Add data loss prevention (DLP)
- [ ] Improve encryption at rest and in transit
- [ ] Conduct security awareness training
- [ ] Schedule penetration testing

## Post-Incident Activities

### 17. Incident Documentation
- [ ] Complete incident timeline
- [ ] Document all evidence collected
- [ ] Record all actions taken
- [ ] Preserve forensic images
- [ ] Create technical post-mortem

### 18. Regulatory Reporting
- [ ] File required breach notifications
- [ ] Provide documentation to authorities
- [ ] Respond to regulatory inquiries
- [ ] Update privacy impact assessments

### 19. Business Impact Assessment
- [ ] Calculate financial impact
- [ ] Assess reputational damage
- [ ] Review insurance coverage
- [ ] Evaluate legal exposure
- [ ] Plan recovery investments

## Prevention and Improvement

### 20. Security Program Enhancements
- [ ] Update security policies
- [ ] Enhance employee training
- [ ] Improve incident response procedures
- [ ] Strengthen access controls
- [ ] Implement zero-trust architecture

### 21. Technical Improvements
```bash
# Implement advanced monitoring
kubectl apply -f security/falco-rules.yaml
kubectl apply -f security/opa-policies.yaml

# Add honeypots and canaries
kubectl apply -f security/honeypot-deployment.yaml

# Enhance data encryption
kubectl create secret generic encryption-key --from-literal=key=$(openssl rand -base64 32)
```

## Legal Considerations

### Evidence Handling
- [ ] Maintain chain of custody
- [ ] Document all forensic procedures
- [ ] Preserve original evidence
- [ ] Create forensic copies for analysis

### Communication Guidelines
- [ ] All external communications through legal
- [ ] Do not admit fault or liability
- [ ] Be factual and transparent with customers
- [ ] Coordinate with PR team

### Law Enforcement
- [ ] Consider involving FBI/law enforcement
- [ ] Preserve evidence for potential prosecution
- [ ] Cooperate with investigations
- [ ] Document all law enforcement interactions

## Escalation Matrix

**Immediate Escalation Required**:
- Any customer data accessed
- Payment card information involved
- Ongoing data exfiltration
- Media attention likely

**Executive Notification**:
- CISO: Immediately
- CEO: Within 1 hour
- Board: Within 24 hours (if material)

**External Parties**:
- Legal counsel: Immediately
- Cyber insurance: Within 4 hours
- Law enforcement: As advised by legal
- Regulators: Per legal requirements

## Success Criteria

- [ ] Threat contained and eliminated
- [ ] All evidence preserved
- [ ] Notifications completed
- [ ] Systems hardened
- [ ] Customers protected
- [ ] Regulatory compliance maintained

## Recovery Metrics

- Time to detection: ___ minutes
- Time to containment: ___ minutes
- Time to notification: ___ hours
- Customer impact: ___ users affected
- Data volume: ___ records accessed

---

**Next Review Date**: Immediately after incident  
**Runbook Owner**: Security Team  
**Emergency Contact**: security@mcpsecurity.com  
**Legal Contact**: legal@mcpsecurity.com