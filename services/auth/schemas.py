"""Pydantic schemas for the authentication service."""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, validator


class UserBase(BaseModel):
    """Base user schema."""
    
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)


class UserCreate(UserBase):
    """User creation schema."""
    
    password: str = Field(..., min_length=8)
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in v)
        
        if not has_upper:
            raise ValueError('Password must contain at least one uppercase letter')
        if not has_lower:
            raise ValueError('Password must contain at least one lowercase letter')
        if not has_digit:
            raise ValueError('Password must contain at least one digit')
        if not has_special:
            raise ValueError('Password must contain at least one special character')
        
        return v


class UserUpdate(BaseModel):
    """User update schema."""
    
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=100)
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    """User response schema."""
    
    id: UUID
    is_active: bool
    is_verified: bool
    is_superuser: bool
    mfa_enabled: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    roles: List[str] = []
    
    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    """User login schema."""
    
    username: str
    password: str
    mfa_code: Optional[str] = None


class PasswordChange(BaseModel):
    """Password change schema."""
    
    current_password: str
    new_password: str = Field(..., min_length=8)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in v)
        
        if not has_upper:
            raise ValueError('Password must contain at least one uppercase letter')
        if not has_lower:
            raise ValueError('Password must contain at least one lowercase letter')
        if not has_digit:
            raise ValueError('Password must contain at least one digit')
        if not has_special:
            raise ValueError('Password must contain at least one special character')
        
        return v


class PasswordReset(BaseModel):
    """Password reset schema."""
    
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Password reset confirmation schema."""
    
    token: str
    new_password: str = Field(..., min_length=8)
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in v)
        
        if not has_upper:
            raise ValueError('Password must contain at least one uppercase letter')
        if not has_lower:
            raise ValueError('Password must contain at least one lowercase letter')
        if not has_digit:
            raise ValueError('Password must contain at least one digit')
        if not has_special:
            raise ValueError('Password must contain at least one special character')
        
        return v


class TokenResponse(BaseModel):
    """Token response schema."""
    
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenRefresh(BaseModel):
    """Token refresh schema."""
    
    refresh_token: str


class RoleBase(BaseModel):
    """Base role schema."""
    
    name: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)


class RoleCreate(RoleBase):
    """Role creation schema."""
    
    permissions: List[str] = []


class RoleUpdate(BaseModel):
    """Role update schema."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    permissions: Optional[List[str]] = None


class RoleResponse(RoleBase):
    """Role response schema."""
    
    id: UUID
    is_default: bool
    is_system: bool
    permissions: List[str] = []
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PermissionBase(BaseModel):
    """Base permission schema."""
    
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    resource: str = Field(..., min_length=1, max_length=50)
    action: str = Field(..., min_length=1, max_length=50)


class PermissionCreate(PermissionBase):
    """Permission creation schema."""
    pass


class PermissionUpdate(BaseModel):
    """Permission update schema."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    resource: Optional[str] = Field(None, min_length=1, max_length=50)
    action: Optional[str] = Field(None, min_length=1, max_length=50)


class PermissionResponse(PermissionBase):
    """Permission response schema."""
    
    id: UUID
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ApiKeyBase(BaseModel):
    """Base API key schema."""
    
    name: str = Field(..., min_length=1, max_length=100)
    expires_at: Optional[datetime] = None
    scopes: Optional[List[str]] = None


class ApiKeyCreate(ApiKeyBase):
    """API key creation schema."""
    pass


class ApiKeyUpdate(BaseModel):
    """API key update schema."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    expires_at: Optional[datetime] = None
    scopes: Optional[List[str]] = None


class ApiKeyResponse(ApiKeyBase):
    """API key response schema."""
    
    id: UUID
    prefix: str
    is_active: bool
    last_used_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ApiKeyWithSecret(ApiKeyResponse):
    """API key response with secret (only returned on creation)."""
    
    key: str


class OrganizationBase(BaseModel):
    """Base organization schema."""
    
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    """Organization creation schema."""
    
    @validator('slug')
    def validate_slug(cls, v):
        """Validate organization slug."""
        if not v.replace('-', '').replace('_', '').isalnum():
            raise ValueError('Slug must contain only alphanumeric characters, hyphens, and underscores')
        return v


class OrganizationUpdate(BaseModel):
    """Organization update schema."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    max_users: Optional[int] = Field(None, ge=1)
    max_projects: Optional[int] = Field(None, ge=1)


class OrganizationResponse(OrganizationBase):
    """Organization response schema."""
    
    id: UUID
    is_active: bool
    max_users: int
    max_projects: int
    plan: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class OrganizationMembershipBase(BaseModel):
    """Base organization membership schema."""
    
    role: str = Field(..., regex=r'^(owner|admin|member)$')


class OrganizationMembershipCreate(OrganizationMembershipBase):
    """Organization membership creation schema."""
    
    user_id: UUID


class OrganizationMembershipUpdate(BaseModel):
    """Organization membership update schema."""
    
    role: Optional[str] = Field(None, regex=r'^(owner|admin|member)$')
    is_active: Optional[bool] = None


class OrganizationMembershipResponse(OrganizationMembershipBase):
    """Organization membership response schema."""
    
    id: UUID
    user_id: UUID
    organization_id: UUID
    is_active: bool
    joined_at: datetime
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AuditLogResponse(BaseModel):
    """Audit log response schema."""
    
    id: UUID
    user_id: Optional[UUID] = None
    event_type: str
    event_category: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: str
    outcome: str
    message: Optional[str] = None
    details: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True


class MFASetupResponse(BaseModel):
    """MFA setup response schema."""
    
    secret: str
    qr_code: str
    backup_codes: List[str]


class MFAVerify(BaseModel):
    """MFA verification schema."""
    
    code: str = Field(..., min_length=6, max_length=6)


class MFADisable(BaseModel):
    """MFA disable schema."""
    
    password: str
    code: str = Field(..., min_length=6, max_length=6)


class ErrorResponse(BaseModel):
    """Error response schema."""
    
    error: str
    message: str
    details: Optional[dict] = None


class SuccessResponse(BaseModel):
    """Success response schema."""
    
    message: str
    data: Optional[dict] = None