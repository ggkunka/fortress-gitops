"""
GraphQL Schema for Fortress Security Platform
Complete implementation for Phase 4.1: GraphQL Implementation
"""
import graphene
from graphene import ObjectType, String, Int, Float, List, Boolean, Field, DateTime
import asyncio
import asyncpg
import redis
import json
from datetime import datetime

# Database connection helper
async def get_db_connection():
    return await asyncpg.connect(
        "postgresql://fortress_user:fortress_secure_password@fortress-postgresql:5432/fortress_security"
    )

# Redis connection helper
def get_redis_connection():
    return redis.Redis(host='fortress-redis', port=6379, decode_responses=True)

# GraphQL Types
class SecurityScore(ObjectType):
    overall_score = Float()
    vulnerability_score = Float()
    compliance_score = Float()
    threat_score = Float()
    last_updated = DateTime()

class Vulnerability(ObjectType):
    id = String()
    cve_id = String()
    title = String()
    description = String()
    severity = String()
    cvss_score = Float()
    cvss_version = String()
    affected_component = String()
    remediation = String()
    discovered_at = DateTime()
    status = String()

class Cluster(ObjectType):
    id = String()
    name = String()
    status = String()
    version = String()
    nodes = Int()
    pods = Int()
    namespaces = Int()
    cpu_usage = Float()
    memory_usage = Float()
    last_scan = DateTime()

class Pod(ObjectType):
    id = String()
    name = String()
    namespace = String()
    cluster_id = String()
    status = String()
    image = String()
    cpu_usage = Float()
    memory_usage = Float()
    restart_count = Int()
    created_at = DateTime()

class ThreatEvent(ObjectType):
    id = String()
    title = String()
    description = String()
    severity = String()
    source = String()
    destination = String()
    event_time = DateTime()
    mitre_technique = String()
    status = String()

class ComplianceFramework(ObjectType):
    id = String()
    name = String()
    version = String()
    compliance_percentage = Float()
    total_controls = Int()
    passed_controls = Int()
    failed_controls = Int()
    last_assessment = DateTime()

class ScanResult(ObjectType):
    id = String()
    cluster_id = String()
    scan_type = String()
    status = String()
    started_at = DateTime()
    completed_at = DateTime()
    vulnerabilities_found = Int()
    critical_issues = Int()
    summary = String()
