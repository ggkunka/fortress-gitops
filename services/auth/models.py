"""Database models for the authentication service."""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    """User model for authentication."""
    
    __tablename__ = "users"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    
    # Account status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)
    
    # Security fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=func.now(), nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    
    # MFA fields
    mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255), nullable=True)
    mfa_backup_codes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    tokens = relationship("Token", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    user_roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")
    
    @property
    def full_name(self) -> str:
        """Get user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_locked(self) -> bool:
        """Check if user account is locked."""
        return self.locked_until and self.locked_until > datetime.utcnow()
    
    @property
    def roles(self) -> List[str]:
        """Get user roles."""
        return [user_role.role.name for user_role in self.user_roles]
    
    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Role(Base):
    """Role model for authorization."""
    
    __tablename__ = "roles"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    
    # Role settings
    is_default = Column(Boolean, default=False, nullable=False)
    is_system = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user_roles = relationship("UserRole", back_populates="role", cascade="all, delete-orphan")
    role_permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    
    @property
    def permissions(self) -> List[str]:
        """Get role permissions."""
        return [role_perm.permission.name for role_perm in self.role_permissions]
    
    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class Permission(Base):
    """Permission model for fine-grained access control."""
    
    __tablename__ = "permissions"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    resource = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    role_permissions = relationship("RolePermission", back_populates="permission", cascade="all, delete-orphan")
    
    __table_args__ = (
        UniqueConstraint("resource", "action", name="uq_resource_action"),
    )
    
    def __repr__(self) -> str:
        return f"<Permission {self.name}>"


class UserRole(Base):
    """User-Role association table."""
    
    __tablename__ = "user_roles"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PostgresUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    role_id = Column(PostgresUUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    
    # Assignment details
    assigned_by = Column(PostgresUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    assigned_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="user_roles", foreign_keys=[user_id])
    role = relationship("Role", back_populates="user_roles")
    assigner = relationship("User", foreign_keys=[assigned_by])
    
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", name="uq_user_role"),
    )
    
    @property
    def is_expired(self) -> bool:
        """Check if role assignment is expired."""
        return self.expires_at and self.expires_at < datetime.utcnow()
    
    def __repr__(self) -> str:
        return f"<UserRole {self.user.username}:{self.role.name}>"


class RolePermission(Base):
    """Role-Permission association table."""
    
    __tablename__ = "role_permissions"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    role_id = Column(PostgresUUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    permission_id = Column(PostgresUUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    role = relationship("Role", back_populates="role_permissions")
    permission = relationship("Permission", back_populates="role_permissions")
    
    __table_args__ = (
        UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
    )
    
    def __repr__(self) -> str:
        return f"<RolePermission {self.role.name}:{self.permission.name}>"


class Token(Base):
    """Token model for JWT and refresh tokens."""
    
    __tablename__ = "tokens"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PostgresUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_type = Column(String(20), nullable=False)  # 'access', 'refresh'
    token_hash = Column(String(255), nullable=False, unique=True)
    
    # Token metadata
    issued_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    
    # Request metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="tokens")
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return self.expires_at < datetime.utcnow()
    
    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not revoked)."""
        return not self.is_expired and not self.is_revoked
    
    def __repr__(self) -> str:
        return f"<Token {self.token_type}:{self.user.username}>"


class ApiKey(Base):
    """API key model for programmatic access."""
    
    __tablename__ = "api_keys"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PostgresUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), nullable=False, unique=True)
    prefix = Column(String(20), nullable=False)
    
    # API key settings
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    
    # Rate limiting
    rate_limit_requests = Column(Integer, nullable=True)
    rate_limit_window = Column(Integer, nullable=True)
    
    # Scopes and permissions
    scopes = Column(Text, nullable=True)  # JSON array of scopes
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="api_keys")
    
    @property
    def is_expired(self) -> bool:
        """Check if API key is expired."""
        return self.expires_at and self.expires_at < datetime.utcnow()
    
    @property
    def is_valid(self) -> bool:
        """Check if API key is valid (active and not expired)."""
        return self.is_active and not self.is_expired
    
    def __repr__(self) -> str:
        return f"<ApiKey {self.name}:{self.user.username}>"


class AuditLog(Base):
    """Audit log model for tracking user actions."""
    
    __tablename__ = "audit_logs"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id = Column(PostgresUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    
    # Event details
    event_type = Column(String(50), nullable=False)
    event_category = Column(String(50), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(255), nullable=True)
    
    # Action details
    action = Column(String(50), nullable=False)
    outcome = Column(String(20), nullable=False)  # 'success', 'failure', 'error'
    message = Column(Text, nullable=True)
    details = Column(Text, nullable=True)  # JSON data
    
    # Request metadata
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    request_id = Column(String(100), nullable=True)
    
    # Timestamps
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    def __repr__(self) -> str:
        return f"<AuditLog {self.event_type}:{self.action}>"


class Organization(Base):
    """Organization model for multi-tenancy."""
    
    __tablename__ = "organizations"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(100), nullable=False)
    slug = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Organization settings
    is_active = Column(Boolean, default=True, nullable=False)
    max_users = Column(Integer, default=100, nullable=False)
    max_projects = Column(Integer, default=10, nullable=False)
    
    # Billing information
    plan = Column(String(20), default="free", nullable=False)
    billing_email = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    memberships = relationship("OrganizationMembership", back_populates="organization", cascade="all, delete-orphan")
    
    def __repr__(self) -> str:
        return f"<Organization {self.name}>"


class OrganizationMembership(Base):
    """Organization membership model."""
    
    __tablename__ = "organization_memberships"
    
    id = Column(PostgresUUID(as_uuid=True), primary_key=True, default=uuid4)
    organization_id = Column(PostgresUUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(PostgresUUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Membership details
    role = Column(String(20), default="member", nullable=False)  # 'owner', 'admin', 'member'
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Timestamps
    joined_at = Column(DateTime, default=func.now(), nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    organization = relationship("Organization", back_populates="memberships")
    user = relationship("User")
    
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_user"),
    )
    
    def __repr__(self) -> str:
        return f"<OrganizationMembership {self.user.username}:{self.organization.name}>"