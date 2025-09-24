"""
User Management Models

Database models for users, roles, permissions, and access control.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Table, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"
    LOCKED = "locked"


class RoleType(str, Enum):
    """Types of roles."""
    SYSTEM = "system"
    ORGANIZATION = "organization"
    PROJECT = "project"
    CUSTOM = "custom"


class PermissionScope(str, Enum):
    """Permission scope levels."""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    PROJECT = "project"
    RESOURCE = "resource"


class ActionType(str, Enum):
    """Available actions for permissions."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    MANAGE = "manage"
    ADMIN = "admin"


# Association table for many-to-many relationship between users and roles
user_roles = Table(
    'user_roles',
    BaseModel.metadata,
    Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'), primary_key=True),
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id'), primary_key=True),
    Column('granted_by', UUID(as_uuid=True), nullable=True),
    Column('granted_at', JSON, nullable=False),
    Column('expires_at', JSON, nullable=True),
    Column('metadata', JSONB, default=dict, nullable=False)
)

# Association table for many-to-many relationship between roles and permissions
role_permissions = Table(
    'role_permissions',
    BaseModel.metadata,
    Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id'), primary_key=True),
    Column('permission_id', UUID(as_uuid=True), ForeignKey('permissions.id'), primary_key=True),
    Column('granted_by', UUID(as_uuid=True), nullable=True),
    Column('granted_at', JSON, nullable=False),
    Column('metadata', JSONB, default=dict, nullable=False)
)


class User(BaseModel):
    """User account entity."""
    
    __tablename__ = "users"
    
    # Basic user information
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(200), nullable=False)
    display_name = Column(String(100), nullable=True)
    
    # Authentication
    password_hash = Column(String(255), nullable=True)  # Can be null for SSO users
    salt = Column(String(100), nullable=True)
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(100), nullable=True)
    
    # Account status
    status = Column(SQLEnum(UserStatus), default=UserStatus.PENDING, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)
    email_verification_token = Column(String(100), nullable=True)
    
    # Profile information
    avatar_url = Column(String(500), nullable=True)
    bio = Column(Text, nullable=True)
    location = Column(String(200), nullable=True)
    timezone = Column(String(50), nullable=True)
    language = Column(String(10), default="en", nullable=False)
    
    # Authentication tracking
    last_login = Column(JSON, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    login_count = Column(Integer, default=0, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login = Column(JSON, nullable=True)
    password_changed_at = Column(JSON, nullable=True)
    
    # Security settings
    session_timeout = Column(Integer, default=3600, nullable=False)  # seconds
    password_reset_token = Column(String(100), nullable=True)
    password_reset_expires = Column(JSON, nullable=True)
    api_key_hash = Column(String(255), nullable=True)
    
    # Preferences
    preferences = Column(JSONB, default=dict, nullable=False)
    notification_settings = Column(JSONB, default=dict, nullable=False)
    
    # Organization context
    primary_organization_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Audit information
    terms_accepted_at = Column(JSON, nullable=True)
    privacy_policy_accepted_at = Column(JSON, nullable=True)
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    
    def _validate(self) -> List[str]:
        """Custom validation for user model."""
        errors = []
        
        if not self.username or len(self.username.strip()) == 0:
            errors.append("Username cannot be empty")
        
        if not self.email or "@" not in self.email:
            errors.append("Valid email address required")
        
        if not self.full_name or len(self.full_name.strip()) == 0:
            errors.append("Full name cannot be empty")
        
        if self.session_timeout <= 0:
            errors.append("Session timeout must be positive")
            
        return errors
    
    def has_permission(self, action: str, resource: str, context: Optional[Dict] = None) -> bool:
        """Check if user has specific permission."""
        for role in self.roles:
            if role.has_permission(action, resource, context):
                return True
        return False
    
    def has_role(self, role_name: str) -> bool:
        """Check if user has specific role."""
        return any(role.name == role_name for role in self.roles)
    
    def is_admin(self) -> bool:
        """Check if user has admin privileges."""
        return self.has_role("admin") or self.has_role("system_admin")
    
    def get_permissions(self) -> List[str]:
        """Get all permissions for user."""
        permissions = set()
        for role in self.roles:
            for permission in role.permissions:
                permissions.add(f"{permission.action}:{permission.resource}")
        return list(permissions)
    
    def can_access_organization(self, org_id: str) -> bool:
        """Check if user can access specific organization."""
        if self.is_admin():
            return True
        
        # Check if user has any role in the organization
        for role in self.roles:
            if role.scope_type == "organization" and role.scope_id == org_id:
                return True
        
        return False
    
    def update_login_tracking(self, ip_address: str):
        """Update login tracking information."""
        self.last_login = datetime.utcnow().isoformat()
        self.last_login_ip = ip_address
        self.login_count += 1
        self.failed_login_attempts = 0  # Reset on successful login
    
    def record_failed_login(self):
        """Record failed login attempt."""
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow().isoformat()
    
    def is_locked(self) -> bool:
        """Check if account is locked."""
        return self.status == UserStatus.LOCKED or self.failed_login_attempts >= 5


class Role(BaseModel):
    """Role entity for role-based access control."""
    
    __tablename__ = "roles"
    
    # Role identification
    name = Column(String(100), nullable=False)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    role_type = Column(SQLEnum(RoleType), nullable=False)
    
    # Role scope
    scope_type = Column(String(50), nullable=True)  # organization, project, global
    scope_id = Column(String(100), nullable=True)  # ID of the scoped resource
    
    # Role properties
    is_default = Column(Boolean, default=False, nullable=False)
    is_system = Column(Boolean, default=False, nullable=False)
    priority = Column(Integer, default=0, nullable=False)  # Higher number = higher priority
    
    # Configuration
    configuration = Column(JSONB, default=dict, nullable=False)
    constraints = Column(JSONB, default=dict, nullable=False)
    
    # Unique constraint for role names within scope
    __table_args__ = (
        UniqueConstraint('name', 'scope_type', 'scope_id', name='uq_role_scope'),
    )
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")
    
    def _validate(self) -> List[str]:
        """Custom validation for role model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Role name cannot be empty")
        
        if not self.display_name or len(self.display_name.strip()) == 0:
            errors.append("Display name cannot be empty")
            
        return errors
    
    def has_permission(self, action: str, resource: str, context: Optional[Dict] = None) -> bool:
        """Check if role has specific permission."""
        for permission in self.permissions:
            if permission.matches(action, resource, context):
                return True
        return False
    
    def add_permission(self, permission: "Permission", granted_by: Optional[str] = None):
        """Add permission to role."""
        if permission not in self.permissions:
            self.permissions.append(permission)
    
    def remove_permission(self, permission: "Permission"):
        """Remove permission from role."""
        if permission in self.permissions:
            self.permissions.remove(permission)
    
    def get_effective_permissions(self) -> List[str]:
        """Get all effective permissions for this role."""
        return [f"{p.action}:{p.resource}" for p in self.permissions]


class Permission(BaseModel):
    """Permission entity defining specific access rights."""
    
    __tablename__ = "permissions"
    
    # Permission identification
    name = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Permission details
    action = Column(SQLEnum(ActionType), nullable=False)
    resource = Column(String(100), nullable=False)  # scans, vulnerabilities, users, etc.
    scope = Column(SQLEnum(PermissionScope), default=PermissionScope.RESOURCE, nullable=False)
    
    # Permission constraints
    conditions = Column(JSONB, default=dict, nullable=False)  # Additional conditions
    resource_filters = Column(JSONB, default=dict, nullable=False)  # Resource-specific filters
    
    # System properties
    is_system = Column(Boolean, default=False, nullable=False)
    category = Column(String(50), nullable=True)  # Group permissions by category
    
    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")
    
    def _validate(self) -> List[str]:
        """Custom validation for permission model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Permission name cannot be empty")
        
        if not self.resource or len(self.resource.strip()) == 0:
            errors.append("Resource cannot be empty")
            
        return errors
    
    def matches(self, action: str, resource: str, context: Optional[Dict] = None) -> bool:
        """Check if permission matches the requested action and resource."""
        # Check action match
        if self.action.value != action and self.action != ActionType.ADMIN:
            return False
        
        # Check resource match
        if self.resource != resource and self.resource != "*":
            return False
        
        # Check additional conditions if context provided
        if context and self.conditions:
            for condition, value in self.conditions.items():
                if condition not in context or context[condition] != value:
                    return False
        
        return True
    
    def get_permission_string(self) -> str:
        """Get string representation of permission."""
        return f"{self.action.value}:{self.resource}"
    
    def is_administrative(self) -> bool:
        """Check if this is an administrative permission."""
        return self.action in [ActionType.ADMIN, ActionType.MANAGE]


class UserRole(BaseModel):
    """Extended user-role relationship with additional metadata."""
    
    __tablename__ = "user_role_assignments"
    
    # Foreign keys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    
    # Assignment details
    granted_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    granted_at = Column(JSON, nullable=False)
    expires_at = Column(JSON, nullable=True)
    
    # Assignment context
    assignment_reason = Column(Text, nullable=True)
    assignment_metadata = Column(JSONB, default=dict, nullable=False)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    revoked_at = Column(JSON, nullable=True)
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    revocation_reason = Column(Text, nullable=True)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='uq_user_role'),
    )
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    role = relationship("Role", foreign_keys=[role_id])
    granter = relationship("User", foreign_keys=[granted_by])
    revoker = relationship("User", foreign_keys=[revoked_by])
    
    def _validate(self) -> List[str]:
        """Custom validation for user role assignment."""
        errors = []
        
        if self.expires_at and self.granted_at:
            granted_dt = datetime.fromisoformat(self.granted_at.replace('Z', '+00:00'))
            expires_dt = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
            if expires_dt <= granted_dt:
                errors.append("Expiration date must be after grant date")
                
        return errors
    
    def is_expired(self) -> bool:
        """Check if role assignment has expired."""
        if not self.expires_at:
            return False
        
        expires_dt = datetime.fromisoformat(self.expires_at.replace('Z', '+00:00'))
        return datetime.utcnow() > expires_dt.replace(tzinfo=None)
    
    def is_valid(self) -> bool:
        """Check if role assignment is currently valid."""
        return self.is_active and not self.is_expired() and not self.revoked_at
    
    def revoke(self, revoked_by: str, reason: Optional[str] = None):
        """Revoke the role assignment."""
        self.is_active = False
        self.revoked_at = datetime.utcnow().isoformat()
        self.revoked_by = revoked_by
        self.revocation_reason = reason