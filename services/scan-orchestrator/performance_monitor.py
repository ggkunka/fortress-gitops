#!/usr/bin/env python3
"""
Performance-Aware Scan Manager
Ensures scans don't impact target cluster performance
"""

import asyncio
import logging
from kubernetes import client
from typing import Dict, Any
import json
import requests

logger = logging.getLogger(__name__)

class PerformanceMonitor:
    def __init__(self):
        self.performance_cache = {}
        self.thresholds = {
            "cpu_usage": 0.7,      # 70% max CPU
            "memory_usage": 0.8,   # 80% max memory  
            "pod_restart_rate": 5, # 5 restarts/hour max
            "scan_concurrency": 2  # Max 2 concurrent scans
        }
    
    async def check_cluster_readiness(self, cluster_name: str, namespace: str) -> bool:
        """Check if cluster can handle additional scan load"""
        
        try:
            # Get cluster metrics
            metrics = await self.get_cluster_metrics(cluster_name, namespace)
            
            # Check CPU/Memory usage
            if metrics["cpu_usage"] > self.thresholds["cpu_usage"]:
                logger.warning(f"CPU usage {metrics['cpu_usage']:.1%} exceeds threshold")
                return False
                
            if metrics["memory_usage"] > self.thresholds["memory_usage"]:
                logger.warning(f"Memory usage {metrics['memory_usage']:.1%} exceeds threshold")
                return False
            
            # Check active scan count
            active_scans = await self.get_active_scan_count(cluster_name)
            if active_scans >= self.thresholds["scan_concurrency"]:
                logger.warning(f"Max concurrent scans ({active_scans}) reached")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Performance check failed: {e}")
            return False
    
    async def get_cluster_metrics(self, cluster_name: str, namespace: str) -> Dict[str, float]:
        """Get real-time cluster performance metrics"""
        
        try:
            # Connect to Prometheus metrics (from existing Fortress setup)
            prometheus_url = "http://prometheus:9090/api/v1/query"
            
            # CPU usage query
            cpu_query = f'avg(rate(container_cpu_usage_seconds_total{{namespace="{namespace}"}}[5m]))'
            cpu_response = requests.get(prometheus_url, params={"query": cpu_query})
            cpu_usage = float(cpu_response.json()["data"]["result"][0]["value"][1])
            
            # Memory usage query  
            mem_query = f'avg(container_memory_working_set_bytes{{namespace="{namespace}"}}) / avg(container_spec_memory_limit_bytes{{namespace="{namespace}"}})'
            mem_response = requests.get(prometheus_url, params={"query": mem_query})
            mem_usage = float(mem_response.json()["data"]["result"][0]["value"][1])
            
            return {
                "cpu_usage": cpu_usage,
                "memory_usage": mem_usage,
                "timestamp": asyncio.get_event_loop().time()
            }
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            # Return safe defaults if metrics unavailable
            return {"cpu_usage": 0.5, "memory_usage": 0.5, "timestamp": 0}
    
    async def get_active_scan_count(self, cluster_name: str) -> int:
        """Count active fortress scan jobs in cluster"""
        
        try:
            k8s_client = await self.get_cluster_client(cluster_name)
            batch_v1 = client.BatchV1Api(k8s_client)
            
            # Count jobs with fortress labels
            jobs = batch_v1.list_job_for_all_namespaces(
                label_selector="fortress.scan.active=true"
            )
            
            active_count = len([job for job in jobs.items if job.status.active])
            return active_count
            
        except Exception as e:
            logger.error(f"Failed to count active scans: {e}")
            return 0
    
    async def adaptive_scan_scheduling(self, scan_requests: list) -> list:
        """Intelligently schedule scans based on cluster load"""
        
        scheduled_scans = []
        
        for scan in scan_requests:
            cluster = scan["cluster_name"]
            namespace = scan["namespace"]
            
            # Check if cluster ready
            if await self.check_cluster_readiness(cluster, namespace):
                scan["scheduled_time"] = asyncio.get_event_loop().time()
                scheduled_scans.append(scan)
            else:
                # Delay scan by 5 minutes
                scan["scheduled_time"] = asyncio.get_event_loop().time() + 300
                scheduled_scans.append(scan)
                logger.info(f"Delayed scan for {scan['tool_name']} due to performance")
        
        return scheduled_scans
    
    async def get_cluster_client(self, cluster_name: str):
        """Get Kubernetes client for specific cluster"""
        # Implementation depends on how multiple clusters are configured
        # For now, assume single cluster setup
        config.load_incluster_config()
        return client.ApiClient()

# Global performance monitor instance
performance_monitor = PerformanceMonitor()
