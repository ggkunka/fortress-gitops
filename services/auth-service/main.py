"""Main application for the authentication service."""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import uvicorn
import structlog
import jwt
import hashlib
import uuid

# Initialize logger
logger = structlog.get_logger()

# JWT Configuration
JWT_SECRET = "mcp-security-jwt-secret-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# In-memory user store for POC
users_db = {
    "admin@mcp.local": {
        "id": "admin-user-id",
        "email": "admin@mcp.local",
        "username": "admin",
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "first_name": "Admin",
        "last_name": "User",
        "is_active": True,
        "is_verified": True,
        "roles": ["admin", "user"]
    },
    "user@mcp.local": {
        "id": "regular-user-id", 
        "email": "user@mcp.local",
        "username": "user",
        "password_hash": hashlib.sha256("user123".encode()).hexdigest(),
        "first_name": "Regular",
        "last_name": "User",
        "is_active": True,
        "is_verified": True,
        "roles": ["user"]
    }
}

# Request/Response Models
class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: Dict[str, Any]

class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    first_name: str
    last_name: str
    roles: list
    is_active: bool

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    try:
        logger.info("Starting authentication service")
        logger.info("Default users created", users=list(users_db.keys()))
        yield
    except Exception as e:
        logger.error("Failed to start authentication service", error=str(e))
        raise
    finally:
        logger.info("Shutting down authentication service")

# Create FastAPI application
app = FastAPI(
    title="MCP Security Platform - Authentication Service",
    description="Authentication and authorization service with JWT tokens",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def create_jwt_token(user_data: Dict[str, Any]) -> str:
    """Create JWT token for user."""
    payload = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "username": user_data["username"],
        "roles": user_data["roles"],
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user."""
    token = credentials.credentials
    payload = verify_jwt_token(token)
    
    user_email = payload.get("email")
    if user_email not in users_db:
        raise HTTPException(status_code=401, detail="User not found")
    
    return users_db[user_email]

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "auth",
        "version": "1.0.0",
        "status": "running",
        "description": "Authentication and authorization service",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """Authenticate user and return JWT token."""
    try:
        # Find user by email
        user = users_db.get(request.email.lower())
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Verify password
        password_hash = hashlib.sha256(request.password.encode()).hexdigest()
        if password_hash != user["password_hash"]:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Check if user is active
        if not user["is_active"]:
            raise HTTPException(status_code=401, detail="Account disabled")
        
        # Create JWT token
        access_token = create_jwt_token(user)
        
        logger.info("User logged in successfully", email=request.email)
        
        return LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=JWT_EXPIRATION_HOURS * 3600,
            user={
                "id": user["id"],
                "email": user["email"],
                "username": user["username"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "roles": user["roles"]
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login failed", error=str(e))
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.get("/api/v1/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get current user information."""
    return UserResponse(
        id=current_user["id"],
        email=current_user["email"],
        username=current_user["username"],
        first_name=current_user["first_name"],
        last_name=current_user["last_name"],
        roles=current_user["roles"],
        is_active=current_user["is_active"]
    )

@app.post("/api/v1/auth/verify")
async def verify_token(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Verify JWT token validity."""
    return {
        "valid": True,
        "user_id": current_user["id"],
        "roles": current_user["roles"],
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/v1/users")
async def list_users(current_user: Dict[str, Any] = Depends(get_current_user)):
    """List all users (admin only)."""
    if "admin" not in current_user["roles"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = []
    for user in users_db.values():
        users.append({
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
            "roles": user["roles"],
            "is_active": user["is_active"]
        })
    
    return {"users": users, "total": len(users)}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "auth",
        "version": "1.0.0",
        "users_count": len(users_db),
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health/live")
async def liveness_probe():
    """Kubernetes liveness probe."""
    return {"status": "alive"}

@app.get("/health/ready")
async def readiness_probe():
    """Kubernetes readiness probe."""
    return {"status": "ready"}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return {
        "service": "auth",
        "users_total": len(users_db),
        "active_users": len([u for u in users_db.values() if u["is_active"]]),
        "timestamp": datetime.utcnow().isoformat()
    }

def main():
    """Main function to run the auth service."""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting authentication service", port=8081)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8081,
        workers=1,
        log_level="info",
        reload=False,
        access_log=True,
    )

if __name__ == "__main__":
    main()
