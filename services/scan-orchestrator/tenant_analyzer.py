#!/usr/bin/env python3
"""
Fortress Tenant Security Analyzer - Progressive Scanning
"""

import asyncio
import logging
from kubernetes import client
from typing import Dict, List
import requests

logger = logging.getLogger(__name__)

class TenantAnalyzer:
    def __init__(self):
        self.fortress_api = "http://fortress-core:8000"
        self.harbor_registry = "10.63.89.182:30500"
        
    async def analyze_tenant(self, cluster_name: str, namespace: str, tenant_id: str):
        """Main tenant security analysis workflow"""
        
        logger.info(f"🎯 Analyzing tenant {tenant_id} in {namespace}")
        
        # Phase 1: Discovery & Local Scanning
        images = await self.discover_images(cluster_name, namespace)
        await self.local_image_scans(tenant_id, images)
        
        # Phase 2: Progressive Agent Scans (Performance-Aware)
        scan_results = await self.get_scan_results(tenant_id)
        
        if self.has_vulnerabilities(scan_results):
            await self.schedule_config_scans(tenant_id, cluster_name, namespace)
        
        if self.has_critical_issues(scan_results):
            await self.schedule_runtime_scans(tenant_id, cluster_name, namespace)
            
        if self.needs_validation(scan_results):
            await self.schedule_exploit_validation(tenant_id, cluster_name, namespace)
    
    async def discover_images(self, cluster_name: str, namespace: str) -> List[str]:
        """Discover all images in target namespace"""
        config.load_incluster_config()
        v1 = client.CoreV1Api()
        
        pods = v1.list_namespaced_pod(namespace=namespace)
        images = set()
        
        for pod in pods.items:
            for container in pod.spec.containers:
                images.add(container.image)
        
        logger.info(f"📊 Found {len(images)} unique images")
        return list(images)
    
    async def local_image_scans(self, tenant_id: str, images: List[str]):
        """Perform local SBOM + vulnerability scans on Fortress"""
        
        for i, image in enumerate(images[:5]):  # Limit initial batch
            # Pull image locally to Fortress
            await self.pull_image_locally(image)
            
            # SYFT scan (local)
            await self.local_syft_scan(tenant_id, image)
            await asyncio.sleep(60)  # 1 min spacing
            
            # Trivy scan (local)  
            await self.local_trivy_scan(tenant_id, image)
            await asyncio.sleep(60)
    
    async def schedule_config_scans(self, tenant_id: str, cluster: str, namespace: str):
        """Schedule configuration scans via agent"""
        
        # Check cluster performance first
        if await self.check_performance(cluster, namespace):
            await self.request_agent_scan("kube-bench", tenant_id, cluster, namespace)
            await asyncio.sleep(180)  # 3 min spacing
            await self.request_agent_scan("polaris", tenant_id, cluster, namespace)
    
    async def request_agent_scan(self, tool: str, tenant_id: str, cluster: str, namespace: str):
        """Request scan via Fortress agent"""
        
        agent_url = f"http://{cluster}-agent:8000/scan/execute"
        
        request = {
            "scan_id": f"{tenant_id}-{tool}",
            "tool_name": tool,
            "target_namespace": namespace,
            "tenant_id": tenant_id
        }
        
        response = requests.post(agent_url, json=request)
        logger.info(f"🔄 Requested {tool} scan: {response.status_code}")
    
    def has_vulnerabilities(self, results: Dict) -> bool:
        return len(results.get("vulnerabilities", [])) > 0
    
    def has_critical_issues(self, results: Dict) -> bool:
        return any(v["severity"] == "CRITICAL" for v in results.get("vulnerabilities", []))
    
    def needs_validation(self, results: Dict) -> bool:
        return any(v.get("exploitable", False) for v in results.get("vulnerabilities", []))

# Initialize analyzer
analyzer = TenantAnalyzer()
