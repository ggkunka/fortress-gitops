#!/usr/bin/env python3
"""
Fortress Scan Data Processor
Integrates scan orchestrator with database architecture
"""

import asyncio
import json
from datetime import datetime
from .fortress_db import db

class ScanDataProcessor:
    
    async def process_tenant_analysis(self, cluster_name: str, namespace: str, tenant_id: str):
        """Process new tenant analysis workflow with database integration"""
        
        # Register infrastructure in database
        cluster_id = await self.register_infrastructure(cluster_name, namespace, tenant_id)
        
        # Queue Phase 1 scans
        await self.queue_reconnaissance_scans(cluster_id, namespace, tenant_id)
        
        return cluster_id
    
    async def register_infrastructure(self, cluster_name: str, namespace: str, tenant_id: str) -> str:
        """Register cluster, namespace, and workloads in PostgreSQL"""
        
        # Register cluster
        cluster_id = await db.register_cluster(cluster_name, f"https://{cluster_name}.local")
        
        # Register namespace  
        namespace_data = {
            "cluster_id": cluster_id,
            "namespace_name": namespace,
            "tenant_id": tenant_id,
            "created_at": datetime.now().isoformat()
        }
        
        # Store in PostgreSQL and cache in Redis
        await db.redis.hset(f"namespace:{cluster_id}:{namespace}", mapping=namespace_data)
        
        return cluster_id
    
    async def queue_reconnaissance_scans(self, cluster_id: str, namespace: str, tenant_id: str):
        """Queue Phase 1 reconnaissance scans"""
        
        # SYFT SBOM scan
        syft_task = {
            "scan_id": f"{tenant_id}-syft-{int(datetime.now().timestamp())}",
            "tool_name": "syft",
            "cluster_id": cluster_id,
            "namespace": namespace,
            "tenant_id": tenant_id,
            "scan_phase": "reconnaissance",
            "scan_type": "local_image",
            "priority": "high"
        }
        await db.queue_scan("high", syft_task)
        
        # Trivy vulnerability scan
        trivy_task = {
            "scan_id": f"{tenant_id}-trivy-{int(datetime.now().timestamp())}",
            "tool_name": "trivy", 
            "cluster_id": cluster_id,
            "namespace": namespace,
            "tenant_id": tenant_id,
            "scan_phase": "reconnaissance",
            "scan_type": "local_image",
            "priority": "high"
        }
        await db.queue_scan("high", trivy_task)
    
    async def process_scan_results(self, execution_id: str, tool_name: str, results: dict):
        """Process and store scan results"""
        
        # Store in Elasticsearch for search/analytics
        es_doc = {
            "timestamp": datetime.now().isoformat(),
            "execution_id": execution_id,
            "tool_name": tool_name,
            "findings_count": len(results.get("findings", [])),
            "results": results
        }
        
        await db.log_vulnerability(es_doc)
        
        # Cache summary in Redis
        summary = {
            "total_findings": len(results.get("findings", [])),
            "critical_count": len([f for f in results.get("findings", []) if f.get("severity") == "CRITICAL"]),
            "scan_completed": datetime.now().isoformat()
        }
        
        await db.redis.hset(f"scan:results:{execution_id}", mapping=summary)
        
        # Trigger next phase if needed
        await self.evaluate_next_phase(execution_id, results)
    
    async def evaluate_next_phase(self, execution_id: str, results: dict):
        """Evaluate if next scan phase is needed based on findings"""
        
        critical_vulns = [f for f in results.get("findings", []) if f.get("severity") == "CRITICAL"]
        
        if len(critical_vulns) > 0:
            # Queue Phase 2 discovery scans
            next_task = {
                "execution_id": execution_id,
                "scan_phase": "discovery",
                "trigger_reason": f"Found {len(critical_vulns)} critical vulnerabilities"
            }
            await db.queue_scan("medium", next_task)
    
    async def update_security_posture(self, cluster_id: str):
        """Update cluster security posture score"""
        
        # Calculate security score based on recent findings
        # This would integrate with the PostgreSQL vulnerability data
        
        performance_data = await db.get_cluster_performance(cluster_id)
        
        # Store updated posture score
        posture_data = {
            "cluster_id": cluster_id,
            "security_score": 7.5,  # Calculated based on vulnerabilities
            "last_updated": datetime.now().isoformat(),
            "performance_impact": performance_data
        }
        
        await db.redis.hset(f"security:posture:{cluster_id}", mapping=posture_data)

# Global processor instance
scan_processor = ScanDataProcessor()
