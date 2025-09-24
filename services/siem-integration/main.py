#!/usr/bin/env python3
"""
SIEM Integration Service for MCP Security Platform
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List

import uvicorn
from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityEvent(BaseModel):
    event_id: str
    event_type: str
    severity: str
    source_service: str
    title: str
    description: str
    timestamp: datetime = datetime.now()

class SIEMService:
    def __init__(self):
        self.siem_configs = {
            "splunk": {
                "endpoint": "https://splunk.company.com:8088/services/collector/event",
                "token": "your-hec-token",
                "enabled": False
            },
            "elastic": {
                "endpoint": "http://elasticsearch:9200/mcp-security-events/_doc",
                "enabled": True
            }
        }
    
    async def send_to_elastic(self, event: SecurityEvent):
        """Send event to Elasticsearch"""
        try:
            doc = {
                "@timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "source_service": event.source_service,
                "title": event.title,
                "description": event.description,
                "platform": "mcp-security"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.siem_configs["elastic"]["endpoint"],
                    json=doc,
                    timeout=10.0
                )
                
                if response.status_code in [200, 201]:
                    logger.info(f"Sent event {event.event_id} to Elasticsearch")
                    return True
                else:
                    logger.error(f"Elasticsearch error: {response.status_code}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to Elasticsearch: {e}")
            return False
    
    async def send_to_splunk(self, event: SecurityEvent):
        """Send event to Splunk HEC"""
        if not self.siem_configs["splunk"]["enabled"]:
            return False
            
        try:
            splunk_event = {
                "time": int(event.timestamp.timestamp()),
                "source": "mcp-security-platform",
                "sourcetype": "mcp:security:event",
                "event": {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "source_service": event.source_service,
                    "title": event.title,
                    "description": event.description
                }
            }
            
            headers = {
                "Authorization": f"Splunk {self.siem_configs['splunk']['token']}",
                "Content-Type": "application/json"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.siem_configs["splunk"]["endpoint"],
                    json=splunk_event,
                    headers=headers,
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    logger.info(f"Sent event {event.event_id} to Splunk")
                    return True
                else:
                    logger.error(f"Splunk error: {response.status_code}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to Splunk: {e}")
            return False
    
    async def process_event(self, event: SecurityEvent):
        """Process security event and send to configured SIEMs"""
        results = {}
        
        # Send to Elasticsearch
        if self.siem_configs["elastic"]["enabled"]:
            results["elastic"] = await self.send_to_elastic(event)
        
        # Send to Splunk
        if self.siem_configs["splunk"]["enabled"]:
            results["splunk"] = await self.send_to_splunk(event)
        
        return results

# Initialize service
siem_service = SIEMService()

# FastAPI app
app = FastAPI(title="MCP SIEM Integration", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/v1/events")
async def receive_security_event(event: SecurityEvent, background_tasks: BackgroundTasks):
    """Receive and process security event"""
    background_tasks.add_task(siem_service.process_event, event)
    return {"status": "accepted", "event_id": event.event_id}

@app.get("/api/v1/config")
async def get_siem_config():
    """Get SIEM configuration status"""
    return {
        "siems": {
            name: {"enabled": config["enabled"]}
            for name, config in siem_service.siem_configs.items()
        }
    }

@app.post("/api/v1/config/{siem_name}/enable")
async def enable_siem(siem_name: str):
    """Enable SIEM integration"""
    if siem_name in siem_service.siem_configs:
        siem_service.siem_configs[siem_name]["enabled"] = True
        return {"status": "enabled", "siem": siem_name}
    else:
        return {"status": "error", "message": "SIEM not found"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "siem-integration"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8090, log_level="info")
