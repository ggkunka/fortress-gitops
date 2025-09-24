#!/usr/bin/env python3
"""
ML Engine Service for MCP Security Platform
"""

import logging
from datetime import datetime
from typing import Dict, List
import numpy as np

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyResult(BaseModel):
    is_anomaly: bool
    risk_level: str
    confidence: float

class RiskAssessment(BaseModel):
    vulnerability_id: str
    overall_risk_score: float
    risk_category: str
    recommendations: List[str]

class MLEngine:
    def detect_anomaly(self, data: Dict) -> AnomalyResult:
        """Simple rule-based anomaly detection"""
        score = 0
        
        # Check suspicious indicators
        if data.get("port", 0) in [22, 23, 445, 3389]:
            score += 30
        if data.get("bytes_transferred", 0) > 10_000_000:
            score += 25
        if data.get("timestamp", datetime.now()).hour < 6:
            score += 20
        
        is_anomaly = score > 50
        risk_level = "high" if score > 70 else "medium" if score > 30 else "low"
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            risk_level=risk_level,
            confidence=min(score, 100)
        )
    
    def assess_risk(self, vuln_data: Dict) -> RiskAssessment:
        """Assess vulnerability risk"""
        cvss = vuln_data.get("cvss_score", 0.0)
        
        if cvss >= 9.0:
            category = "critical"
            recommendations = ["Immediate patching required"]
        elif cvss >= 7.0:
            category = "high"
            recommendations = ["Patch within 7 days"]
        elif cvss >= 4.0:
            category = "medium"
            recommendations = ["Patch within 30 days"]
        else:
            category = "low"
            recommendations = ["Regular maintenance cycle"]
        
        return RiskAssessment(
            vulnerability_id=vuln_data.get("id", "unknown"),
            overall_risk_score=cvss,
            risk_category=category,
            recommendations=recommendations
        )

ml_engine = MLEngine()

app = FastAPI(title="MCP ML Engine", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/v1/detect-anomaly")
async def detect_anomaly(data: Dict) -> AnomalyResult:
    return ml_engine.detect_anomaly(data)

@app.post("/api/v1/assess-risk")
async def assess_risk(vuln_data: Dict) -> RiskAssessment:
    return ml_engine.assess_risk(vuln_data)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ml-engine"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8092, log_level="info")
