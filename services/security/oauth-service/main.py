#!/usr/bin/env python3
"""
OAuth 2.0/OIDC Authentication Service - Phase 5.1
Complete Authentication & Authorization
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import secrets
import uvicorn

# Configuration
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Fortress OAuth Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock user database
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),
        "roles": ["admin", "user"],
        "mfa_enabled": True,
        "mfa_secret": "JBSWY3DPEHPK3PXP"
    },
    "user": {
        "username": "user", 
        "hashed_password": pwd_context.hash("user123"),
        "roles": ["user"],
        "mfa_enabled": False,
        "mfa_secret": None
    }
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "roles": user["roles"]},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "username": user["username"],
            "roles": user["roles"],
            "mfa_required": user["mfa_enabled"]
        }
    }

@app.get("/userinfo")
async def get_user_info(current_user: dict = Depends(get_current_user)):
    return {
        "sub": current_user["username"],
        "roles": current_user["roles"],
        "mfa_enabled": current_user["mfa_enabled"]
    }

@app.post("/mfa/verify")
async def verify_mfa(token: str, current_user: dict = Depends(get_current_user)):
    # Mock MFA verification - in production, use TOTP library
    if current_user["mfa_enabled"] and token == "123456":
        return {"verified": True, "message": "MFA verification successful"}
    return {"verified": False, "message": "Invalid MFA token"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "oauth-service"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090)
