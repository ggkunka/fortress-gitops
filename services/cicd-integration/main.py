#!/usr/bin/env python3
"""
CI/CD Integration Service for MCP Security Platform
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Optional

import uvicorn
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanRequest(BaseModel):
    repository_url: str
    branch: str = "main"
    commit_sha: str
    pipeline_type: str
    pipeline_id: str

app = FastAPI(title="MCP CI/CD Integration", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/v1/scan")
async def trigger_scan(scan_request: ScanRequest):
    """Trigger security scan for CI/CD pipeline"""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://scanner-manager:8082/api/v1/scans",
                json={
                    "target": scan_request.repository_url,
                    "scan_type": "comprehensive",
                    "metadata": {
                        "branch": scan_request.branch,
                        "commit_sha": scan_request.commit_sha,
                        "pipeline_type": scan_request.pipeline_type
                    }
                },
                timeout=30.0
            )
            
            if response.status_code == 201:
                return {"status": "success", "scan_id": response.json().get("scan_id")}
            else:
                return {"status": "error", "message": "Failed to start scan"}
                
    except Exception as e:
        logger.error(f"Error triggering scan: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/webhooks/github")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """Handle GitHub webhook events"""
    try:
        data = await request.json()
        event_type = request.headers.get('X-GitHub-Event', '')
        
        if event_type == "push" and data.get("ref") == "refs/heads/main":
            scan_request = ScanRequest(
                repository_url=data["repository"]["clone_url"],
                branch="main",
                commit_sha=data["after"],
                pipeline_id=str(data["repository"]["id"]),
                pipeline_type="github"
            )
            
            result = await trigger_scan(scan_request)
            return {"status": "webhook_processed", "scan_result": result}
        
        return {"status": "webhook_received"}
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cicd-integration"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8089, log_level="info")
