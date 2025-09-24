#!/usr/bin/env python3
"""
Zero Trust Networking Service - Phase 5.2
Policy-Based Access Control & Secrets Management with HashiCorp Vault Integration
"""
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import hashlib
import json
from datetime import datetime, timedelta
import secrets
import base64
from cryptography.fernet import Fernet
import uvicorn

app = FastAPI(title="Fortress Zero Trust Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Encryption key for vault secrets
VAULT_KEY = Fernet.generate_key()
cipher_suite = Fernet(VAULT_KEY)

# Zero Trust Policy Models
class ZeroTrustRule(BaseModel):
    action: str  # ALLOW, DENY, LOG_AND_ALLOW
    sources: List[str]
    destinations: List[str]
    protocols: List[str]
    conditions: Dict[str, Any] = {}
    priority: int = 1000

class ZeroTrustPolicy(BaseModel):
    id: str
    name: str
    description: str
    rules: List[ZeroTrustRule]
    active: bool = True
    created_at: datetime = datetime.now()
    updated_at: datetime = datetime.now()

class AccessRequest(BaseModel):
    source: str
    destination: str
    protocol: str = "tcp/80"
    user: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = {}

class VaultSecret(BaseModel):
    path: str
    value: str
    metadata: Dict[str, Any] = {}
    ttl: Optional[int] = None

# Policy Database with comprehensive Zero Trust policies
policies_db: Dict[str, ZeroTrustPolicy] = {
    "fortress-core-services": ZeroTrustPolicy(
        id="fortress-core-services",
        name="Fortress Core Services Communication",
        description="Allow secure communication between core Fortress microservices",
        rules=[
            ZeroTrustRule(
                action="ALLOW",
                sources=["fortress-system/fortress-auth", "fortress-system/fortress-gateway"],
                destinations=["fortress-system/fortress-postgresql", "fortress-system/fortress-redis"],
                protocols=["tcp/5432", "tcp/6379"],
                priority=50
            ),
            ZeroTrustRule(
                action="ALLOW", 
                sources=["fortress-system/*"],
                destinations=["fortress-system/*"],
                protocols=["tcp/80", "tcp/443", "tcp/8080", "tcp/8081"],
                priority=100
            )
        ]
    ),
    "fortress-external-api": ZeroTrustPolicy(
        id="fortress-external-api",
        name="External API Access Control",
        description="Control external access to Fortress APIs",
        rules=[
            ZeroTrustRule(
                action="LOG_AND_ALLOW",
                sources=["external/*"],
                destinations=["fortress-system/fortress-gateway"],
                protocols=["tcp/80", "tcp/443"],
                conditions={"rate_limit": 1000, "require_auth": True},
                priority=200
            )
        ]
    ),
    "fortress-admin-access": ZeroTrustPolicy(
        id="fortress-admin-access",
        name="Administrative Access Policy",
        description="Zero Trust policy for administrative access",
        rules=[
            ZeroTrustRule(
                action="ALLOW",
                sources=["user:admin", "role:administrator"],
                destinations=["fortress-system/*"],
                protocols=["*"],
                conditions={"mfa_required": True, "source_ip_whitelist": ["10.0.0.0/8"]},
                priority=10
            )
        ]
    ),
    "default-deny": ZeroTrustPolicy(
        id="default-deny",
        name="Default Deny All Policy",
        description="Default zero trust policy - deny all unmatched traffic",
        rules=[
            ZeroTrustRule(
                action="DENY",
                sources=["*"],
                destinations=["*"],
                protocols=["*"],
                priority=1000
            )
        ]
    )
}

# Mock secrets vault
secrets_vault = {
    "database/fortress/username": {
        "value": "fortress_user",
        "created_at": datetime.now(),
        "version": 1,
        "metadata": {"type": "database_credential"}
    },
    "database/fortress/password": {
        "value": "fortress_secure_password",
        "created_at": datetime.now(), 
        "version": 1,
        "metadata": {"type": "database_credential"}
    },
    "api/external/threat-intel": {
        "value": "ti_api_key_12345",
        "created_at": datetime.now(),
        "version": 1,
        "metadata": {"type": "api_key"}
    }
}

class ZeroTrustEngine:
    def __init__(self):
        self.trust_scores = {}
    
    def evaluate_request(self, source: str, destination: str, protocol: str, user: str = None):
        """Evaluate access request against zero trust policies"""
        
        # Calculate trust score
        trust_score = self.calculate_trust_score(source, user)
        
        # Apply policies
        decision = self.apply_policies(source, destination, protocol)
        
        # Log decision
        self.log_decision(source, destination, protocol, decision, trust_score)
        
        return {
            "decision": decision,
            "trust_score": trust_score,
            "timestamp": datetime.now().isoformat(),
            "reason": f"Policy evaluation for {source} -> {destination}:{protocol}"
        }
    
    def calculate_trust_score(self, source: str, user: str = None):
        """Calculate trust score based on multiple factors"""
        base_score = 50
        
        # Source-based scoring
        if source.startswith("fortress-system/"):
            base_score += 30
        
        # User-based scoring
        if user == "admin":
            base_score += 20
        elif user == "service-account":
            base_score += 15
        
        return min(base_score, 100)
    
    def apply_policies(self, source: str, destination: str, protocol: str):
        """Apply zero trust policies in priority order"""
        
        # Sort policies by priority
        sorted_policies = []
        for policy in policies_db.values():
            if policy["active"]:
                for rule in policy["rules"]:
                    sorted_policies.append((rule["priority"], rule))
        
        sorted_policies.sort(key=lambda x: x[0])
        
        # Apply first matching rule
        for priority, rule in sorted_policies:
            if self.rule_matches(rule, source, destination, protocol):
                return rule["action"]
        
        return "DENY"  # Default deny
    
    def rule_matches(self, rule: dict, source: str, destination: str, protocol: str):
        """Check if rule matches the request"""
        
        # Check source
        if not self.matches_pattern(rule["sources"], source):
            return False
        
        # Check destination
        if not self.matches_pattern(rule["destinations"], destination):
            return False
        
        # Check protocol
        if not self.matches_pattern(rule["protocols"], protocol):
            return False
        
        return True
    
    def matches_pattern(self, patterns: List[str], value: str):
        """Check if value matches any pattern"""
        for pattern in patterns:
            if pattern == "*" or pattern == value:
                return True
            if pattern.endswith("/*") and value.startswith(pattern[:-2]):
                return True
        return False
    
    def log_decision(self, source: str, destination: str, protocol: str, decision: str, trust_score: float):
        """Log access decision for audit"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "decision": decision,
            "trust_score": trust_score
        }
        print(f"ZERO_TRUST_LOG: {json.dumps(log_entry)}")

zt_engine = ZeroTrustEngine()

@app.post("/evaluate")
async def evaluate_access(request: dict):
    """Evaluate access request against zero trust policies"""
    source = request.get("source")
    destination = request.get("destination") 
    protocol = request.get("protocol", "tcp/80")
    user = request.get("user")
    
    if not source or not destination:
        raise HTTPException(status_code=400, detail="Source and destination required")
    
    result = zt_engine.evaluate_request(source, destination, protocol, user)
    return result

@app.get("/policies")
async def list_policies():
    """List all zero trust policies"""
    return {"policies": list(policies_db.values())}

@app.post("/policies")
async def create_policy(policy: dict):
    """Create new zero trust policy"""
    policy_id = policy.get("id")
    if not policy_id:
        raise HTTPException(status_code=400, detail="Policy ID required")
    
    policies_db[policy_id] = policy
    return {"message": "Policy created", "id": policy_id}

@app.get("/secrets/{secret_path:path}")
async def get_secret(secret_path: str):
    """Get secret from vault"""
    if secret_path not in secrets_vault:
        raise HTTPException(status_code=404, detail="Secret not found")
    
    secret = secrets_vault[secret_path]
    return {
        "path": secret_path,
        "value": secret["value"],
        "metadata": secret["metadata"],
        "version": secret["version"]
    }

@app.post("/secrets/{secret_path:path}")
async def store_secret(secret_path: str, secret_data: dict):
    """Store secret in vault"""
    secrets_vault[secret_path] = {
        "value": secret_data.get("value"),
        "created_at": datetime.now(),
        "version": secrets_vault.get(secret_path, {}).get("version", 0) + 1,
        "metadata": secret_data.get("metadata", {})
    }
    return {"message": "Secret stored", "path": secret_path}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "zero-trust-service"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8091)
