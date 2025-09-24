#!/usr/bin/env python3
"""
GraphQL Gateway Service for MCP Security Platform
Provides unified GraphQL API for all security data and operations
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from graphene import ObjectType, String, Int, Float, DateTime, List as GrapheneList, Schema, Field
from starlette_graphene3 import GraphQLApp, make_graphiql_handler
import httpx
import redis.asyncio as redis
from prometheus_client import Counter, Histogram, generate_latest
from prometheus_fastapi_instrumentator import Instrumentator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Metrics
graphql_requests = Counter('graphql_requests_total', 'Total GraphQL requests', ['operation_type'])
graphql_duration = Histogram('graphql_request_duration_seconds', 'GraphQL request duration')

# GraphQL Types
class VulnerabilityType(ObjectType):
    id = String()
    cve_id = String()
    severity = String()
    cvss_score = Float()
    description = String()
    affected_package = String()
    fixed_version = String()
    discovered_at = DateTime()
    status = String()

class ScanResultType(ObjectType):
    id = String()
    scan_id = String()
    target = String()
    scan_type = String()
    status = String()
    started_at = DateTime()
    completed_at = DateTime()
    vulnerabilities = GrapheneList(VulnerabilityType)
    summary = String()

class SecurityEventType(ObjectType):
    id = String()
    event_type = String()
    severity = String()
    source = String()
    message = String()
    timestamp = DateTime()
    metadata = String()

class ServiceHealthType(ObjectType):
    service_name = String()
    status = String()
    last_check = DateTime()
    response_time = Float()
    error_count = Int()

class SecurityMetricsType(ObjectType):
    total_vulnerabilities = Int()
    critical_vulnerabilities = Int()
    high_vulnerabilities = Int()
    medium_vulnerabilities = Int()
    low_vulnerabilities = Int()
    active_scans = Int()
    completed_scans = Int()
    failed_scans = Int()

# GraphQL Queries
class Query(ObjectType):
    # Vulnerability queries
    vulnerabilities = GrapheneList(
        VulnerabilityType,
        severity=String(),
        limit=Int(default_value=50),
        offset=Int(default_value=0)
    )
    vulnerability = Field(VulnerabilityType, id=String(required=True))
    
    # Scan result queries
    scan_results = GrapheneList(
        ScanResultType,
        status=String(),
        limit=Int(default_value=50),
        offset=Int(default_value=0)
    )
    scan_result = Field(ScanResultType, id=String(required=True))
    
    # Security event queries
    security_events = GrapheneList(
        SecurityEventType,
        event_type=String(),
        severity=String(),
        limit=Int(default_value=100),
        offset=Int(default_value=0)
    )
    
    # Service health queries
    service_health = GrapheneList(ServiceHealthType)
    
    # Security metrics
    security_metrics = Field(SecurityMetricsType)

    async def resolve_vulnerabilities(self, info, severity=None, limit=50, offset=0):
        """Resolve vulnerabilities from vulnerability analyzer service"""
        try:
            async with httpx.AsyncClient() as client:
                params = {"limit": limit, "offset": offset}
                if severity:
                    params["severity"] = severity
                
                response = await client.get(
                    "http://vulnerability-analyzer:8083/api/v1/vulnerabilities",
                    params=params,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return [VulnerabilityType(**vuln) for vuln in data.get("vulnerabilities", [])]
                else:
                    logger.error(f"Failed to fetch vulnerabilities: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities: {e}")
            return []

    async def resolve_vulnerability(self, info, id):
        """Resolve single vulnerability by ID"""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://vulnerability-analyzer:8083/api/v1/vulnerabilities/{id}",
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return VulnerabilityType(**data)
                else:
                    return None
        except Exception as e:
            logger.error(f"Error fetching vulnerability {id}: {e}")
            return None

    async def resolve_scan_results(self, info, status=None, limit=50, offset=0):
        """Resolve scan results from scanner manager"""
        try:
            async with httpx.AsyncClient() as client:
                params = {"limit": limit, "offset": offset}
                if status:
                    params["status"] = status
                
                response = await client.get(
                    "http://scanner-manager:8082/api/v1/scans",
                    params=params,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return [ScanResultType(**scan) for scan in data.get("scans", [])]
                else:
                    logger.error(f"Failed to fetch scan results: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching scan results: {e}")
            return []

    async def resolve_security_events(self, info, event_type=None, severity=None, limit=100, offset=0):
        """Resolve security events from Elasticsearch"""
        try:
            # Query Elasticsearch for security events
            query = {
                "query": {
                    "bool": {
                        "must": []
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": limit,
                "from": offset
            }
            
            if event_type:
                query["query"]["bool"]["must"].append({"term": {"event_type": event_type}})
            if severity:
                query["query"]["bool"]["must"].append({"term": {"severity": severity}})
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://elasticsearch:9200/mcp-security-events/_search",
                    json=query,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    events = []
                    for hit in data.get("hits", {}).get("hits", []):
                        event_data = hit["_source"]
                        event_data["id"] = hit["_id"]
                        events.append(SecurityEventType(**event_data))
                    return events
                else:
                    logger.error(f"Failed to fetch security events: {response.status_code}")
                    return []
        except Exception as e:
            logger.error(f"Error fetching security events: {e}")
            return []

    async def resolve_service_health(self, info):
        """Resolve service health status"""
        services = [
            "auth-service",
            "gateway-service", 
            "scanner-manager",
            "vulnerability-analyzer",
            "report-generator",
            "notification-service"
        ]
        
        health_status = []
        
        for service in services:
            try:
                async with httpx.AsyncClient() as client:
                    start_time = datetime.now()
                    response = await client.get(
                        f"http://{service}:808{services.index(service)}/health",
                        timeout=5.0
                    )
                    response_time = (datetime.now() - start_time).total_seconds()
                    
                    status = "healthy" if response.status_code == 200 else "unhealthy"
                    
                    health_status.append(ServiceHealthType(
                        service_name=service,
                        status=status,
                        last_check=datetime.now(),
                        response_time=response_time,
                        error_count=0 if status == "healthy" else 1
                    ))
            except Exception as e:
                logger.error(f"Health check failed for {service}: {e}")
                health_status.append(ServiceHealthType(
                    service_name=service,
                    status="unhealthy",
                    last_check=datetime.now(),
                    response_time=5.0,
                    error_count=1
                ))
        
        return health_status

    async def resolve_security_metrics(self, info):
        """Resolve security metrics summary"""
        try:
            # Get vulnerability counts
            async with httpx.AsyncClient() as client:
                vuln_response = await client.get(
                    "http://vulnerability-analyzer:8083/api/v1/vulnerabilities/summary",
                    timeout=30.0
                )
                
                scan_response = await client.get(
                    "http://scanner-manager:8082/api/v1/scans/summary", 
                    timeout=30.0
                )
                
                vuln_data = vuln_response.json() if vuln_response.status_code == 200 else {}
                scan_data = scan_response.json() if scan_response.status_code == 200 else {}
                
                return SecurityMetricsType(
                    total_vulnerabilities=vuln_data.get("total", 0),
                    critical_vulnerabilities=vuln_data.get("critical", 0),
                    high_vulnerabilities=vuln_data.get("high", 0),
                    medium_vulnerabilities=vuln_data.get("medium", 0),
                    low_vulnerabilities=vuln_data.get("low", 0),
                    active_scans=scan_data.get("active", 0),
                    completed_scans=scan_data.get("completed", 0),
                    failed_scans=scan_data.get("failed", 0)
                )
        except Exception as e:
            logger.error(f"Error fetching security metrics: {e}")
            return SecurityMetricsType(
                total_vulnerabilities=0,
                critical_vulnerabilities=0,
                high_vulnerabilities=0,
                medium_vulnerabilities=0,
                low_vulnerabilities=0,
                active_scans=0,
                completed_scans=0,
                failed_scans=0
            )

# Create GraphQL schema
schema = Schema(query=Query)

# FastAPI app
app = FastAPI(
    title="MCP Security Platform - GraphQL Gateway",
    description="Unified GraphQL API for security data and operations",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add Prometheus metrics
instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app)

# GraphQL endpoint
app.add_route("/graphql", GraphQLApp(schema=schema))
app.add_route("/graphiql", make_graphiql_handler())

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "graphql-gateway",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8087,
        log_level="info",
        reload=False
    )
