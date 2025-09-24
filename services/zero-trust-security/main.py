#!/usr/bin/env python3
"""
Zero Trust Security Service for MCP Security Platform
Implements Zero Trust architecture with policy enforcement
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx
import jwt
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PolicyDecision(BaseModel):
    allow: bool
    reason: str
    conditions: List[str] = []
    ttl: int = 300  # 5 minutes default

class AccessRequest(BaseModel):
    user_id: str
    service: str
    action: str
    resource: str
    context: Dict = {}

class ZeroTrustService:
    def __init__(self):
        self.policies = self._load_default_policies()
        self.vault_client = None
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
    
    def _load_default_policies(self) -> Dict:
        """Load default Zero Trust policies"""
        return {
            "default_deny": True,
            "require_mfa": True,
            "max_session_duration": 3600,  # 1 hour
            "allowed_services": [
                "auth-service",
                "gateway-service",
                "scanner-manager",
                "vulnerability-analyzer",
                "report-generator",
                "notification-service"
            ],
            "admin_services": [
                "vault-integration",
                "zero-trust-security"
            ],
            "network_policies": {
                "internal_only": [
                    "postgresql",
                    "redis-master",
                    "elasticsearch"
                ]
            }
        }
    
    async def init_vault_client(self):
        """Initialize HashiCorp Vault client"""
        try:
            # In production, use proper Vault authentication
            vault_url = "http://vault:8200"
            vault_token = "dev-token"  # Use proper auth in production
            
            self.vault_client = {
                "url": vault_url,
                "token": vault_token,
                "initialized": True
            }
            
            logger.info("Vault client initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault: {e}")
    
    async def get_secret(self, path: str) -> Optional[Dict]:
        """Retrieve secret from Vault"""
        if not self.vault_client:
            return None
            
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.vault_client['url']}/v1/secret/data/{path}",
                    headers={"X-Vault-Token": self.vault_client["token"]},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("data", {}).get("data", {})
                else:
                    logger.error(f"Vault error: {response.status_code}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error retrieving secret: {e}")
            return None
    
    async def store_secret(self, path: str, secret: Dict) -> bool:
        """Store secret in Vault"""
        if not self.vault_client:
            return False
            
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.vault_client['url']}/v1/secret/data/{path}",
                    headers={"X-Vault-Token": self.vault_client["token"]},
                    json={"data": secret},
                    timeout=10.0
                )
                
                return response.status_code in [200, 204]
                
        except Exception as e:
            logger.error(f"Error storing secret: {e}")
            return False
    
    def evaluate_access_policy(self, request: AccessRequest) -> PolicyDecision:
        """Evaluate Zero Trust access policy"""
        reasons = []
        conditions = []
        
        # Default deny
        if self.policies["default_deny"]:
            allow = False
            reasons.append("Default deny policy")
        else:
            allow = True
        
        # Check if service is allowed
        if request.service in self.policies["allowed_services"]:
            allow = True
            reasons.append(f"Service {request.service} is in allowed list")
        elif request.service in self.policies["admin_services"]:
            # Admin services require additional checks
            if request.context.get("role") == "admin":
                allow = True
                reasons.append("Admin access granted")
            else:
                allow = False
                reasons.append("Admin role required")
        
        # Check network policies
        if request.service in self.policies["network_policies"]["internal_only"]:
            if not request.context.get("internal_network", False):
                allow = False
                reasons.append("Internal network access required")
        
        # MFA requirement
        if self.policies["require_mfa"] and not request.context.get("mfa_verified", False):
            conditions.append("MFA verification required")
        
        # Time-based access
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            conditions.append("Outside business hours - additional verification required")
        
        # Risk-based decisions
        risk_score = self._calculate_risk_score(request)
        if risk_score > 70:
            allow = False
            reasons.append(f"High risk score: {risk_score}")
        elif risk_score > 50:
            conditions.append("Medium risk - additional monitoring required")
        
        return PolicyDecision(
            allow=allow,
            reason="; ".join(reasons) if reasons else "Policy evaluation completed",
            conditions=conditions,
            ttl=self.policies["max_session_duration"]
        )
    
    def _calculate_risk_score(self, request: AccessRequest) -> int:
        """Calculate risk score for access request"""
        score = 0
        
        # Location-based risk
        if request.context.get("location") == "unknown":
            score += 30
        
        # Time-based risk
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:
            score += 20
        
        # Device-based risk
        if not request.context.get("trusted_device", False):
            score += 25
        
        # Behavioral risk
        if request.context.get("unusual_activity", False):
            score += 40
        
        # Service sensitivity
        if request.service in self.policies["admin_services"]:
            score += 15
        
        return min(score, 100)  # Cap at 100
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    async def audit_access_attempt(self, request: AccessRequest, decision: PolicyDecision):
        """Audit access attempt for compliance"""
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": request.user_id,
            "service": request.service,
            "action": request.action,
            "resource": request.resource,
            "decision": decision.allow,
            "reason": decision.reason,
            "conditions": decision.conditions,
            "context": request.context
        }
        
        # Store audit log (in production, send to secure audit system)
        logger.info(f"AUDIT: {json.dumps(audit_entry)}")
        
        # Send to SIEM if available
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "http://siem-integration:8090/api/v1/events",
                    json={
                        "event_id": f"zt-audit-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        "event_type": "zero_trust_access",
                        "severity": "high" if not decision.allow else "info",
                        "source_service": "zero-trust-security",
                        "title": f"Zero Trust Access Decision",
                        "description": f"User {request.user_id} access to {request.service}: {'ALLOWED' if decision.allow else 'DENIED'}"
                    },
                    timeout=5.0
                )
        except Exception as e:
            logger.error(f"Failed to send audit to SIEM: {e}")

# Initialize service
zt_service = ZeroTrustService()

# FastAPI app
app = FastAPI(title="MCP Zero Trust Security", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

@app.on_event("startup")
async def startup_event():
    await zt_service.init_vault_client()

@app.post("/api/v1/authorize")
async def authorize_access(request: AccessRequest) -> PolicyDecision:
    """Authorize access request using Zero Trust policies"""
    decision = zt_service.evaluate_access_policy(request)
    
    # Audit the access attempt
    await zt_service.audit_access_attempt(request, decision)
    
    return decision

@app.get("/api/v1/policies")
async def get_policies():
    """Get current Zero Trust policies"""
    return {"policies": zt_service.policies}

@app.post("/api/v1/secrets/{path}")
async def store_secret(path: str, secret: Dict):
    """Store secret in Vault"""
    success = await zt_service.store_secret(path, secret)
    return {"status": "success" if success else "error", "path": path}

@app.get("/api/v1/secrets/{path}")
async def get_secret(path: str):
    """Retrieve secret from Vault"""
    secret = await zt_service.get_secret(path)
    if secret:
        return {"status": "success", "data": secret}
    else:
        raise HTTPException(status_code=404, detail="Secret not found")

@app.post("/api/v1/encrypt")
async def encrypt_data(data: Dict):
    """Encrypt sensitive data"""
    encrypted = zt_service.encrypt_sensitive_data(data["plaintext"])
    return {"encrypted": encrypted}

@app.post("/api/v1/decrypt")
async def decrypt_data(data: Dict):
    """Decrypt sensitive data"""
    try:
        decrypted = zt_service.decrypt_sensitive_data(data["encrypted"])
        return {"decrypted": decrypted}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "zero-trust-security",
        "vault_connected": zt_service.vault_client is not None
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8091, log_level="info")
