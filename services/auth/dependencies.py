"""FastAPI dependencies for the authentication service."""

from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from .database import get_db_session
from .models import User, Token, ApiKey, OrganizationMembership
from .security import security_manager

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db_session),
) -> User:
    """Get current authenticated user from JWT token."""
    token = credentials.credentials
    
    # Verify token
    payload = security_manager.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check token type
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user ID from token
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if token is in database and not revoked
    token_hash = security_manager.hash_token(token)
    stmt = select(Token).where(
        Token.token_hash == token_hash,
        Token.is_revoked == False,
    )
    result = await db.execute(stmt)
    db_token = result.scalar_one_or_none()
    
    if not db_token or not db_token.is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Get user from database
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )
    
    # Check if user is locked
    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is locked",
        )
    
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get current active user."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is disabled",
        )
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user),
) -> User:
    """Get current verified user."""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User email is not verified",
        )
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_verified_user),
) -> User:
    """Get current superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user


async def get_user_from_api_key(
    api_key: str,
    db: AsyncSession = Depends(get_db_session),
) -> Optional[User]:
    """Get user from API key."""
    if not api_key:
        return None
    
    # Hash the API key
    key_hash = security_manager.hash_token(api_key)
    
    # Get API key from database
    stmt = select(ApiKey).where(ApiKey.key_hash == key_hash)
    result = await db.execute(stmt)
    db_api_key = result.scalar_one_or_none()
    
    if not db_api_key or not db_api_key.is_valid:
        return None
    
    # Get user from API key
    stmt = select(User).where(User.id == db_api_key.user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        return None
    
    # Update last used timestamp
    db_api_key.last_used_at = db.utcnow()
    await db.commit()
    
    return user


def require_permission(permission: str):
    """Dependency factory for permission checking."""
    
    async def check_permission(
        current_user: User = Depends(get_current_verified_user),
    ) -> User:
        """Check if user has required permission."""
        user_permissions = []
        
        # Get all permissions from user's roles
        for user_role in current_user.user_roles:
            if not user_role.is_expired:
                user_permissions.extend(user_role.role.permissions)
        
        # Check if user has the required permission
        if permission not in user_permissions and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required",
            )
        
        return current_user
    
    return check_permission


def require_role(role: str):
    """Dependency factory for role checking."""
    
    async def check_role(
        current_user: User = Depends(get_current_verified_user),
    ) -> User:
        """Check if user has required role."""
        user_roles = current_user.roles
        
        # Check if user has the required role
        if role not in user_roles and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' required",
            )
        
        return current_user
    
    return check_role


def require_organization_membership(organization_id: UUID, role: Optional[str] = None):
    """Dependency factory for organization membership checking."""
    
    async def check_membership(
        current_user: User = Depends(get_current_verified_user),
        db: AsyncSession = Depends(get_db_session),
    ) -> User:
        """Check if user is a member of the organization."""
        # Check organization membership
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == current_user.id,
            OrganizationMembership.is_active == True,
        )
        result = await db.execute(stmt)
        membership = result.scalar_one_or_none()
        
        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this organization",
            )
        
        # Check role if specified
        if role and membership.role != role and not current_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Organization role '{role}' required",
            )
        
        return current_user
    
    return check_membership


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db_session),
) -> Optional[User]:
    """Get current user if authenticated, otherwise None."""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None