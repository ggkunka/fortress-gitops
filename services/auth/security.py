"""Security utilities for the authentication service."""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

import bcrypt
from jose import JWTError, jwt
from passlib.context import CryptContext

from shared.config import get_settings

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SecurityManager:
    """Security manager for authentication operations."""
    
    def __init__(self):
        self.secret_key = settings.jwt_secret
        self.algorithm = settings.jwt_algorithm
        self.access_token_expire_minutes = settings.jwt_access_token_expire_minutes
        self.refresh_token_expire_days = settings.jwt_refresh_token_expire_days
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "type": "access"})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def create_refresh_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT refresh token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        to_encode.update({"exp": expire, "type": "refresh"})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError:
            return None
    
    def get_token_subject(self, token: str) -> Optional[str]:
        """Get the subject from a JWT token."""
        payload = self.verify_token(token)
        if payload:
            return payload.get("sub")
        return None
    
    def get_token_type(self, token: str) -> Optional[str]:
        """Get the type from a JWT token."""
        payload = self.verify_token(token)
        if payload:
            return payload.get("type")
        return None
    
    def is_token_expired(self, token: str) -> bool:
        """Check if a JWT token is expired."""
        payload = self.verify_token(token)
        if payload:
            exp = payload.get("exp")
            if exp:
                return datetime.utcnow() > datetime.fromtimestamp(exp)
        return True
    
    def hash_token(self, token: str) -> str:
        """Hash a token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def generate_api_key(self, prefix: str = "mcp_") -> tuple[str, str]:
        """Generate an API key with prefix and return (full_key, hash)."""
        key_part = secrets.token_urlsafe(32)
        full_key = f"{prefix}{key_part}"
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()
        return full_key, key_hash
    
    def verify_api_key(self, api_key: str, stored_hash: str) -> bool:
        """Verify an API key against its stored hash."""
        return hashlib.sha256(api_key.encode()).hexdigest() == stored_hash
    
    def generate_mfa_secret(self) -> str:
        """Generate a MFA secret."""
        return secrets.token_urlsafe(32)
    
    def generate_backup_codes(self, count: int = 10) -> list[str]:
        """Generate MFA backup codes."""
        return [secrets.token_hex(8) for _ in range(count)]
    
    def hash_backup_codes(self, codes: list[str]) -> list[str]:
        """Hash MFA backup codes."""
        return [hashlib.sha256(code.encode()).hexdigest() for code in codes]
    
    def verify_backup_code(self, code: str, hashed_codes: list[str]) -> bool:
        """Verify a backup code against hashed codes."""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        return code_hash in hashed_codes
    
    def generate_verification_token(self) -> str:
        """Generate a verification token."""
        return secrets.token_urlsafe(32)
    
    def generate_reset_token(self) -> str:
        """Generate a password reset token."""
        return secrets.token_urlsafe(32)
    
    def constant_time_compare(self, a: str, b: str) -> bool:
        """Constant time string comparison to prevent timing attacks."""
        return secrets.compare_digest(a, b)


class PasswordValidator:
    """Password strength validator."""
    
    def __init__(self):
        self.min_length = settings.password_min_length
        self.require_uppercase = settings.password_require_uppercase
        self.require_lowercase = settings.password_require_lowercase
        self.require_numbers = settings.password_require_numbers
        self.require_symbols = settings.password_require_symbols
    
    def validate(self, password: str) -> tuple[bool, list[str]]:
        """Validate password strength."""
        errors = []
        
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if self.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if self.require_symbols and not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def get_strength_score(self, password: str) -> int:
        """Get password strength score (0-100)."""
        score = 0
        
        # Length score (max 25 points)
        if len(password) >= 8:
            score += min(25, len(password) * 2)
        
        # Character variety score (max 75 points)
        if any(c.isupper() for c in password):
            score += 15
        if any(c.islower() for c in password):
            score += 15
        if any(c.isdigit() for c in password):
            score += 15
        if any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            score += 15
        
        # Additional complexity (max 15 points)
        unique_chars = len(set(password))
        if unique_chars >= 8:
            score += 15
        elif unique_chars >= 6:
            score += 10
        elif unique_chars >= 4:
            score += 5
        
        return min(100, score)


class RateLimiter:
    """Rate limiter for authentication attempts."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.max_attempts = settings.auth_max_login_attempts
        self.lockout_duration = settings.auth_lockout_duration
    
    async def is_rate_limited(self, identifier: str) -> bool:
        """Check if an identifier is rate limited."""
        key = f"rate_limit:auth:{identifier}"
        attempts = await self.redis.get(key)
        
        if attempts is None:
            return False
        
        return int(attempts) >= self.max_attempts
    
    async def record_attempt(self, identifier: str, success: bool = False) -> None:
        """Record an authentication attempt."""
        key = f"rate_limit:auth:{identifier}"
        
        if success:
            # Clear rate limit on successful authentication
            await self.redis.delete(key)
        else:
            # Increment failed attempts
            attempts = await self.redis.incr(key)
            if attempts == 1:
                # Set expiry on first attempt
                await self.redis.expire(key, self.lockout_duration)
    
    async def get_remaining_attempts(self, identifier: str) -> int:
        """Get remaining attempts before lockout."""
        key = f"rate_limit:auth:{identifier}"
        attempts = await self.redis.get(key)
        
        if attempts is None:
            return self.max_attempts
        
        return max(0, self.max_attempts - int(attempts))
    
    async def get_lockout_time(self, identifier: str) -> int:
        """Get remaining lockout time in seconds."""
        key = f"rate_limit:auth:{identifier}"
        ttl = await self.redis.ttl(key)
        
        if ttl == -1:  # No expiry set
            return 0
        elif ttl == -2:  # Key doesn't exist
            return 0
        else:
            return ttl


# Global security manager instance
security_manager = SecurityManager()
password_validator = PasswordValidator()