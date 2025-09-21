#!/usr/bin/env python3
"""
Fortress Scan Orchestrator API
Main interface for intelligent security scanning
"""

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import asyncio
import logging
from .tenant_analyzer import TenantAnalyzer
from .performance_monitor import PerformanceMonitor

app = FastAPI(title="Fortress Scan Orchestrator")
logger = logging.getLogger(__name__)

class TenantRequest(BaseModel):
    cluster_name: str
    namespace: str
    tenant_id: str
    registry_access: str = None

class ScanStatus(BaseModel):
    tenant_id: str
    phase: str
    progress: float
    findings: int

# Initialize components
analyzer = TenantAnalyzer()
performance_monitor = PerformanceMonitor()

@app.post("/analyze/tenant")
async def analyze_tenant(request: TenantRequest, background_tasks: BackgroundTasks):
    """Start progressive security analysis for new tenant"""
    
    logger.info(f"🚀 Starting tenant analysis: {request.tenant_id}")
    
    # Start background analysis
    background_tasks.add_task(
        analyzer.analyze_tenant,
        request.cluster_name,
        request.namespace, 
        request.tenant_id
    )
    
    return {
        "message": f"Security analysis started for tenant {request.tenant_id}",
        "tenant_id": request.tenant_id,
        "status": "initiated"
    }

@app.get("/status/{tenant_id}")
async def get_analysis_status(tenant_id: str):
    """Get current analysis status for tenant"""
    
    # Mock status - real implementation would track actual progress
    return ScanStatus(
        tenant_id=tenant_id,
        phase="reconnaissance", 
        progress=0.3,
        findings=5
    )

@app.post("/scan/schedule")
async def schedule_scan(scan_request: dict):
    """Schedule individual scan with performance awareness"""
    
    cluster = scan_request["cluster_name"]
    namespace = scan_request["namespace"]
    
    # Check performance before scheduling
    ready = await performance_monitor.check_cluster_readiness(cluster, namespace)
    
    if ready:
        # Schedule immediately
        return {"status": "scheduled", "delay": 0}
    else:
        # Delay based on performance
        return {"status": "delayed", "delay": 300}  # 5 min delay

@app.get("/performance/{cluster_name}/{namespace}")
async def get_cluster_performance(cluster_name: str, namespace: str):
    """Get real-time cluster performance metrics"""
    
    metrics = await performance_monitor.get_cluster_metrics(cluster_name, namespace)
    return metrics

@app.post("/exploit/validate")
async def validate_exploit(validation_request: dict):
    """Request controlled exploit validation"""
    
    tenant_id = validation_request["tenant_id"]
    cve_id = validation_request["cve_id"]
    
    logger.info(f"🔍 Validation requested for {cve_id}")
    
    # Only validate if safe method exists
    safe_cves = ["CVE-2021-44228", "CVE-2022-0847", "CVE-2021-3156"]
    
    if cve_id in safe_cves:
        return {"status": "scheduled", "validation_id": f"val-{tenant_id}-{cve_id}"}
    else:
        return {"status": "skipped", "reason": "No safe validation method"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
