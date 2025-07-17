"""CRUD operations for the authentication service."""

import json
from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID

from sqlalchemy import and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from .models import (
    User, Role, Permission, UserRole, RolePermission, Token, ApiKey,
    AuditLog, Organization, OrganizationMembership
)
from .schemas import (
    UserCreate, UserUpdate, RoleCreate, RoleUpdate, PermissionCreate,
    PermissionUpdate, ApiKeyCreate, ApiKeyUpdate, OrganizationCreate,
    OrganizationUpdate, OrganizationMembershipCreate, OrganizationMembershipUpdate
)
from .security import security_manager


class UserCRUD:
    """CRUD operations for User model."""
    
    @staticmethod
    async def get_by_id(db: AsyncSession, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(User.id == user_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email."""
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(User.email == email)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_username(db: AsyncSession, username: str) -> Optional[User]:
        """Get user by username."""
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(User.username == username)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_username_or_email(db: AsyncSession, identifier: str) -> Optional[User]:
        """Get user by username or email."""
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).where(or_(User.username == identifier, User.email == identifier))
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_multi(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        is_active: Optional[bool] = None,
        is_verified: Optional[bool] = None,
    ) -> List[User]:
        """Get multiple users."""
        stmt = select(User).options(
            selectinload(User.user_roles).selectinload(UserRole.role)
        ).offset(skip).limit(limit)
        
        if is_active is not None:
            stmt = stmt.where(User.is_active == is_active)
        if is_verified is not None:
            stmt = stmt.where(User.is_verified == is_verified)
        
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def create(db: AsyncSession, user_create: UserCreate) -> User:
        """Create a new user."""
        password_hash = security_manager.hash_password(user_create.password)
        
        db_user = User(
            email=user_create.email,
            username=user_create.username,
            password_hash=password_hash,
            first_name=user_create.first_name,
            last_name=user_create.last_name,
        )
        
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        
        # Assign default role if exists
        default_role = await RoleCRUD.get_default_role(db)
        if default_role:
            await UserCRUD.assign_role(db, db_user.id, default_role.id)
        
        return db_user
    
    @staticmethod
    async def update(db: AsyncSession, user_id: UUID, user_update: UserUpdate) -> Optional[User]:
        """Update a user."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return None
        
        update_data = user_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_user, field, value)
        
        await db.commit()
        await db.refresh(db_user)
        return db_user
    
    @staticmethod
    async def delete(db: AsyncSession, user_id: UUID) -> bool:
        """Delete a user."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return False
        
        await db.delete(db_user)
        await db.commit()
        return True
    
    @staticmethod
    async def assign_role(db: AsyncSession, user_id: UUID, role_id: UUID) -> Optional[UserRole]:
        """Assign a role to a user."""
        # Check if assignment already exists
        stmt = select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            return existing
        
        user_role = UserRole(user_id=user_id, role_id=role_id)
        db.add(user_role)
        await db.commit()
        await db.refresh(user_role)
        return user_role
    
    @staticmethod
    async def remove_role(db: AsyncSession, user_id: UUID, role_id: UUID) -> bool:
        """Remove a role from a user."""
        stmt = select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id,
        )
        result = await db.execute(stmt)
        user_role = result.scalar_one_or_none()
        
        if not user_role:
            return False
        
        await db.delete(user_role)
        await db.commit()
        return True
    
    @staticmethod
    async def update_password(db: AsyncSession, user_id: UUID, new_password: str) -> bool:
        """Update user password."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return False
        
        db_user.password_hash = security_manager.hash_password(new_password)
        db_user.password_changed_at = datetime.utcnow()
        
        await db.commit()
        return True
    
    @staticmethod
    async def verify_email(db: AsyncSession, user_id: UUID) -> bool:
        """Verify user email."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return False
        
        db_user.is_verified = True
        await db.commit()
        return True
    
    @staticmethod
    async def lock_user(db: AsyncSession, user_id: UUID, duration: int = 900) -> bool:
        """Lock user account."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return False
        
        db_user.locked_until = datetime.utcnow() + timedelta(seconds=duration)
        await db.commit()
        return True
    
    @staticmethod
    async def unlock_user(db: AsyncSession, user_id: UUID) -> bool:
        """Unlock user account."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return False
        
        db_user.locked_until = None
        db_user.failed_login_attempts = 0
        await db.commit()
        return True
    
    @staticmethod
    async def record_login_attempt(
        db: AsyncSession,
        user_id: UUID,
        success: bool,
        ip_address: Optional[str] = None,
    ) -> None:
        """Record a login attempt."""
        db_user = await UserCRUD.get_by_id(db, user_id)
        if not db_user:
            return
        
        if success:
            db_user.failed_login_attempts = 0
            db_user.last_login_at = datetime.utcnow()
            db_user.last_login_ip = ip_address
        else:
            db_user.failed_login_attempts += 1
        
        await db.commit()


class RoleCRUD:
    """CRUD operations for Role model."""
    
    @staticmethod
    async def get_by_id(db: AsyncSession, role_id: UUID) -> Optional[Role]:
        """Get role by ID."""
        stmt = select(Role).options(
            selectinload(Role.role_permissions).selectinload(RolePermission.permission)
        ).where(Role.id == role_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_name(db: AsyncSession, name: str) -> Optional[Role]:
        """Get role by name."""
        stmt = select(Role).options(
            selectinload(Role.role_permissions).selectinload(RolePermission.permission)
        ).where(Role.name == name)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_default_role(db: AsyncSession) -> Optional[Role]:
        """Get default role."""
        stmt = select(Role).where(Role.is_default == True)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_multi(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[Role]:
        """Get multiple roles."""
        stmt = select(Role).options(
            selectinload(Role.role_permissions).selectinload(RolePermission.permission)
        ).offset(skip).limit(limit)
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def create(db: AsyncSession, role_create: RoleCreate) -> Role:
        """Create a new role."""
        db_role = Role(
            name=role_create.name,
            description=role_create.description,
        )
        
        db.add(db_role)
        await db.commit()
        await db.refresh(db_role)
        
        # Assign permissions
        for permission_name in role_create.permissions:
            permission = await PermissionCRUD.get_by_name(db, permission_name)
            if permission:
                await RoleCRUD.assign_permission(db, db_role.id, permission.id)
        
        return db_role
    
    @staticmethod
    async def update(db: AsyncSession, role_id: UUID, role_update: RoleUpdate) -> Optional[Role]:
        """Update a role."""
        db_role = await RoleCRUD.get_by_id(db, role_id)
        if not db_role:
            return None
        
        update_data = role_update.model_dump(exclude_unset=True, exclude={'permissions'})
        for field, value in update_data.items():
            setattr(db_role, field, value)
        
        # Update permissions if provided
        if role_update.permissions is not None:
            # Remove existing permissions
            stmt = select(RolePermission).where(RolePermission.role_id == role_id)
            result = await db.execute(stmt)
            existing_permissions = result.scalars().all()
            
            for role_perm in existing_permissions:
                await db.delete(role_perm)
            
            # Add new permissions
            for permission_name in role_update.permissions:
                permission = await PermissionCRUD.get_by_name(db, permission_name)
                if permission:
                    await RoleCRUD.assign_permission(db, role_id, permission.id)
        
        await db.commit()
        await db.refresh(db_role)
        return db_role
    
    @staticmethod
    async def delete(db: AsyncSession, role_id: UUID) -> bool:
        """Delete a role."""
        db_role = await RoleCRUD.get_by_id(db, role_id)
        if not db_role or db_role.is_system:
            return False
        
        await db.delete(db_role)
        await db.commit()
        return True
    
    @staticmethod
    async def assign_permission(db: AsyncSession, role_id: UUID, permission_id: UUID) -> Optional[RolePermission]:
        """Assign a permission to a role."""
        # Check if assignment already exists
        stmt = select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            return existing
        
        role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
        db.add(role_permission)
        await db.commit()
        await db.refresh(role_permission)
        return role_permission
    
    @staticmethod
    async def remove_permission(db: AsyncSession, role_id: UUID, permission_id: UUID) -> bool:
        """Remove a permission from a role."""
        stmt = select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
        )
        result = await db.execute(stmt)
        role_permission = result.scalar_one_or_none()
        
        if not role_permission:
            return False
        
        await db.delete(role_permission)
        await db.commit()
        return True


class PermissionCRUD:
    """CRUD operations for Permission model."""
    
    @staticmethod
    async def get_by_id(db: AsyncSession, permission_id: UUID) -> Optional[Permission]:
        """Get permission by ID."""
        stmt = select(Permission).where(Permission.id == permission_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_name(db: AsyncSession, name: str) -> Optional[Permission]:
        """Get permission by name."""
        stmt = select(Permission).where(Permission.name == name)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_multi(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[Permission]:
        """Get multiple permissions."""
        stmt = select(Permission).offset(skip).limit(limit)
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def create(db: AsyncSession, permission_create: PermissionCreate) -> Permission:
        """Create a new permission."""
        db_permission = Permission(
            name=permission_create.name,
            description=permission_create.description,
            resource=permission_create.resource,
            action=permission_create.action,
        )
        
        db.add(db_permission)
        await db.commit()
        await db.refresh(db_permission)
        return db_permission
    
    @staticmethod
    async def update(db: AsyncSession, permission_id: UUID, permission_update: PermissionUpdate) -> Optional[Permission]:
        """Update a permission."""
        db_permission = await PermissionCRUD.get_by_id(db, permission_id)
        if not db_permission:
            return None
        
        update_data = permission_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_permission, field, value)
        
        await db.commit()
        await db.refresh(db_permission)
        return db_permission
    
    @staticmethod
    async def delete(db: AsyncSession, permission_id: UUID) -> bool:
        """Delete a permission."""
        db_permission = await PermissionCRUD.get_by_id(db, permission_id)
        if not db_permission:
            return False
        
        await db.delete(db_permission)
        await db.commit()
        return True


class TokenCRUD:
    """CRUD operations for Token model."""
    
    @staticmethod
    async def create(
        db: AsyncSession,
        user_id: UUID,
        token: str,
        token_type: str,
        expires_at: datetime,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Token:
        """Create a new token."""
        token_hash = security_manager.hash_token(token)
        
        db_token = Token(
            user_id=user_id,
            token_type=token_type,
            token_hash=token_hash,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        db.add(db_token)
        await db.commit()
        await db.refresh(db_token)
        return db_token
    
    @staticmethod
    async def get_by_hash(db: AsyncSession, token_hash: str) -> Optional[Token]:
        """Get token by hash."""
        stmt = select(Token).where(Token.token_hash == token_hash)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def revoke_token(db: AsyncSession, token_hash: str) -> bool:
        """Revoke a token."""
        db_token = await TokenCRUD.get_by_hash(db, token_hash)
        if not db_token:
            return False
        
        db_token.is_revoked = True
        db_token.revoked_at = datetime.utcnow()
        await db.commit()
        return True
    
    @staticmethod
    async def revoke_user_tokens(db: AsyncSession, user_id: UUID, token_type: Optional[str] = None) -> int:
        """Revoke all tokens for a user."""
        stmt = select(Token).where(Token.user_id == user_id, Token.is_revoked == False)
        
        if token_type:
            stmt = stmt.where(Token.token_type == token_type)
        
        result = await db.execute(stmt)
        tokens = result.scalars().all()
        
        count = 0
        for token in tokens:
            token.is_revoked = True
            token.revoked_at = datetime.utcnow()
            count += 1
        
        await db.commit()
        return count
    
    @staticmethod
    async def cleanup_expired_tokens(db: AsyncSession) -> int:
        """Clean up expired tokens."""
        stmt = select(Token).where(Token.expires_at < datetime.utcnow())
        result = await db.execute(stmt)
        tokens = result.scalars().all()
        
        count = 0
        for token in tokens:
            await db.delete(token)
            count += 1
        
        await db.commit()
        return count


class ApiKeyCRUD:
    """CRUD operations for ApiKey model."""
    
    @staticmethod
    async def create(
        db: AsyncSession,
        user_id: UUID,
        api_key_create: ApiKeyCreate,
    ) -> tuple[ApiKey, str]:
        """Create a new API key."""
        api_key, key_hash = security_manager.generate_api_key()
        prefix = api_key.split('_')[0] + '_'
        
        db_api_key = ApiKey(
            user_id=user_id,
            name=api_key_create.name,
            key_hash=key_hash,
            prefix=prefix,
            expires_at=api_key_create.expires_at,
            scopes=json.dumps(api_key_create.scopes) if api_key_create.scopes else None,
        )
        
        db.add(db_api_key)
        await db.commit()
        await db.refresh(db_api_key)
        return db_api_key, api_key
    
    @staticmethod
    async def get_by_id(db: AsyncSession, api_key_id: UUID) -> Optional[ApiKey]:
        """Get API key by ID."""
        stmt = select(ApiKey).where(ApiKey.id == api_key_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_hash(db: AsyncSession, key_hash: str) -> Optional[ApiKey]:
        """Get API key by hash."""
        stmt = select(ApiKey).where(ApiKey.key_hash == key_hash)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_user_api_keys(db: AsyncSession, user_id: UUID) -> List[ApiKey]:
        """Get all API keys for a user."""
        stmt = select(ApiKey).where(ApiKey.user_id == user_id)
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def update(db: AsyncSession, api_key_id: UUID, api_key_update: ApiKeyUpdate) -> Optional[ApiKey]:
        """Update an API key."""
        db_api_key = await ApiKeyCRUD.get_by_id(db, api_key_id)
        if not db_api_key:
            return None
        
        update_data = api_key_update.model_dump(exclude_unset=True, exclude={'scopes'})
        for field, value in update_data.items():
            setattr(db_api_key, field, value)
        
        if api_key_update.scopes is not None:
            db_api_key.scopes = json.dumps(api_key_update.scopes)
        
        await db.commit()
        await db.refresh(db_api_key)
        return db_api_key
    
    @staticmethod
    async def delete(db: AsyncSession, api_key_id: UUID) -> bool:
        """Delete an API key."""
        db_api_key = await ApiKeyCRUD.get_by_id(db, api_key_id)
        if not db_api_key:
            return False
        
        await db.delete(db_api_key)
        await db.commit()
        return True


class AuditLogCRUD:
    """CRUD operations for AuditLog model."""
    
    @staticmethod
    async def create(
        db: AsyncSession,
        user_id: Optional[UUID],
        event_type: str,
        event_category: str,
        action: str,
        outcome: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        message: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> AuditLog:
        """Create a new audit log entry."""
        db_audit_log = AuditLog(
            user_id=user_id,
            event_type=event_type,
            event_category=event_category,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            outcome=outcome,
            message=message,
            details=json.dumps(details) if details else None,
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )
        
        db.add(db_audit_log)
        await db.commit()
        await db.refresh(db_audit_log)
        return db_audit_log
    
    @staticmethod
    async def get_multi(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        user_id: Optional[UUID] = None,
        event_type: Optional[str] = None,
        event_category: Optional[str] = None,
        outcome: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> List[AuditLog]:
        """Get multiple audit log entries."""
        stmt = select(AuditLog).offset(skip).limit(limit).order_by(AuditLog.timestamp.desc())
        
        if user_id:
            stmt = stmt.where(AuditLog.user_id == user_id)
        if event_type:
            stmt = stmt.where(AuditLog.event_type == event_type)
        if event_category:
            stmt = stmt.where(AuditLog.event_category == event_category)
        if outcome:
            stmt = stmt.where(AuditLog.outcome == outcome)
        if start_date:
            stmt = stmt.where(AuditLog.timestamp >= start_date)
        if end_date:
            stmt = stmt.where(AuditLog.timestamp <= end_date)
        
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def cleanup_old_logs(db: AsyncSession, days: int = 90) -> int:
        """Clean up old audit logs."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        stmt = select(AuditLog).where(AuditLog.timestamp < cutoff_date)
        result = await db.execute(stmt)
        logs = result.scalars().all()
        
        count = 0
        for log in logs:
            await db.delete(log)
            count += 1
        
        await db.commit()
        return count


class OrganizationCRUD:
    """CRUD operations for Organization model."""
    
    @staticmethod
    async def get_by_id(db: AsyncSession, org_id: UUID) -> Optional[Organization]:
        """Get organization by ID."""
        stmt = select(Organization).where(Organization.id == org_id)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_by_slug(db: AsyncSession, slug: str) -> Optional[Organization]:
        """Get organization by slug."""
        stmt = select(Organization).where(Organization.slug == slug)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()
    
    @staticmethod
    async def get_multi(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[Organization]:
        """Get multiple organizations."""
        stmt = select(Organization).offset(skip).limit(limit)
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def create(db: AsyncSession, org_create: OrganizationCreate) -> Organization:
        """Create a new organization."""
        db_org = Organization(
            name=org_create.name,
            slug=org_create.slug,
            description=org_create.description,
        )
        
        db.add(db_org)
        await db.commit()
        await db.refresh(db_org)
        return db_org
    
    @staticmethod
    async def update(db: AsyncSession, org_id: UUID, org_update: OrganizationUpdate) -> Optional[Organization]:
        """Update an organization."""
        db_org = await OrganizationCRUD.get_by_id(db, org_id)
        if not db_org:
            return None
        
        update_data = org_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_org, field, value)
        
        await db.commit()
        await db.refresh(db_org)
        return db_org
    
    @staticmethod
    async def delete(db: AsyncSession, org_id: UUID) -> bool:
        """Delete an organization."""
        db_org = await OrganizationCRUD.get_by_id(db, org_id)
        if not db_org:
            return False
        
        await db.delete(db_org)
        await db.commit()
        return True
    
    @staticmethod
    async def add_member(
        db: AsyncSession,
        org_id: UUID,
        membership_create: OrganizationMembershipCreate,
    ) -> Optional[OrganizationMembership]:
        """Add a member to an organization."""
        # Check if membership already exists
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == membership_create.user_id,
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            return existing
        
        membership = OrganizationMembership(
            organization_id=org_id,
            user_id=membership_create.user_id,
            role=membership_create.role,
        )
        
        db.add(membership)
        await db.commit()
        await db.refresh(membership)
        return membership
    
    @staticmethod
    async def update_member(
        db: AsyncSession,
        org_id: UUID,
        user_id: UUID,
        membership_update: OrganizationMembershipUpdate,
    ) -> Optional[OrganizationMembership]:
        """Update organization membership."""
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == user_id,
        )
        result = await db.execute(stmt)
        membership = result.scalar_one_or_none()
        
        if not membership:
            return None
        
        update_data = membership_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(membership, field, value)
        
        await db.commit()
        await db.refresh(membership)
        return membership
    
    @staticmethod
    async def remove_member(db: AsyncSession, org_id: UUID, user_id: UUID) -> bool:
        """Remove a member from an organization."""
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == user_id,
        )
        result = await db.execute(stmt)
        membership = result.scalar_one_or_none()
        
        if not membership:
            return False
        
        await db.delete(membership)
        await db.commit()
        return True
    
    @staticmethod
    async def get_members(db: AsyncSession, org_id: UUID) -> List[OrganizationMembership]:
        """Get all members of an organization."""
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id
        ).options(selectinload(OrganizationMembership.user))
        result = await db.execute(stmt)
        return result.scalars().all()
    
    @staticmethod
    async def get_user_organizations(db: AsyncSession, user_id: UUID) -> List[OrganizationMembership]:
        """Get all organizations a user is a member of."""
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id
        ).options(selectinload(OrganizationMembership.organization))
        result = await db.execute(stmt)
        return result.scalars().all()