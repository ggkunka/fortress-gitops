"""
Organization Models

Database models for organizations, teams, projects, and organizational hierarchy.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Integer, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class OrganizationStatus(str, Enum):
    """Organization account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    EXPIRED = "expired"


class SubscriptionTier(str, Enum):
    """Subscription tiers."""
    FREE = "free"
    BASIC = "basic"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class ProjectStatus(str, Enum):
    """Project status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    DRAFT = "draft"


class TeamType(str, Enum):
    """Team types."""
    SECURITY = "security"
    DEVELOPMENT = "development"
    DEVOPS = "devops"
    COMPLIANCE = "compliance"
    MANAGEMENT = "management"
    CUSTOM = "custom"


class Organization(BaseModel):
    """Organization entity."""
    
    __tablename__ = "organizations"
    
    # Basic information
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    
    # Contact information
    website = Column(String(500), nullable=True)
    support_email = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    
    # Address information
    address_line1 = Column(String(200), nullable=True)
    address_line2 = Column(String(200), nullable=True)
    city = Column(String(100), nullable=True)
    state = Column(String(100), nullable=True)
    postal_code = Column(String(20), nullable=True)
    country = Column(String(100), nullable=True)
    
    # Organization details
    industry = Column(String(100), nullable=True)
    company_size = Column(String(50), nullable=True)  # 1-10, 11-50, 51-200, etc.
    founded_year = Column(Integer, nullable=True)
    
    # Status and subscription
    status = Column(SQLEnum(OrganizationStatus), default=OrganizationStatus.TRIAL, nullable=False)
    subscription_tier = Column(SQLEnum(SubscriptionTier), default=SubscriptionTier.FREE, nullable=False)
    subscription_expires = Column(JSON, nullable=True)
    
    # Branding
    logo_url = Column(String(500), nullable=True)
    primary_color = Column(String(7), nullable=True)  # Hex color
    secondary_color = Column(String(7), nullable=True)
    
    # Settings and preferences
    settings = Column(JSONB, default=dict, nullable=False)
    features_enabled = Column(JSONB, default=list, nullable=False)
    integrations_config = Column(JSONB, default=dict, nullable=False)
    
    # Security settings
    sso_enabled = Column(Boolean, default=False, nullable=False)
    sso_config = Column(JSONB, default=dict, nullable=False)
    mfa_required = Column(Boolean, default=False, nullable=False)
    ip_whitelist = Column(JSONB, default=list, nullable=False)
    session_timeout = Column(Integer, default=3600, nullable=False)  # seconds
    
    # Compliance and governance
    compliance_frameworks = Column(JSONB, default=list, nullable=False)
    data_retention_days = Column(Integer, default=365, nullable=False)
    audit_enabled = Column(Boolean, default=True, nullable=False)
    
    # Usage and limits
    user_limit = Column(Integer, nullable=True)
    project_limit = Column(Integer, nullable=True)
    scan_limit_monthly = Column(Integer, nullable=True)
    storage_limit_gb = Column(Float, nullable=True)
    
    # Usage tracking
    current_users = Column(Integer, default=0, nullable=False)
    current_projects = Column(Integer, default=0, nullable=False)
    scans_this_month = Column(Integer, default=0, nullable=False)
    storage_used_gb = Column(Float, default=0.0, nullable=False)
    
    # Billing information
    billing_email = Column(String(255), nullable=True)
    tax_id = Column(String(100), nullable=True)
    billing_address_same = Column(Boolean, default=True, nullable=False)
    
    # API and external integration
    api_key_hash = Column(String(255), nullable=True)
    webhook_endpoints = Column(JSONB, default=list, nullable=False)
    external_ids = Column(JSONB, default=dict, nullable=False)  # IDs in external systems
    
    # Relationships
    teams = relationship("Team", back_populates="organization", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")
    
    def _validate(self) -> List[str]:
        """Custom validation for organization model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Organization name cannot be empty")
        
        if not self.slug or len(self.slug.strip()) == 0:
            errors.append("Organization slug cannot be empty")
        
        if self.user_limit and self.user_limit <= 0:
            errors.append("User limit must be positive")
        
        if self.session_timeout <= 0:
            errors.append("Session timeout must be positive")
            
        return errors
    
    def is_active(self) -> bool:
        """Check if organization is active."""
        return self.status == OrganizationStatus.ACTIVE
    
    def is_subscription_active(self) -> bool:
        """Check if subscription is active."""
        if not self.subscription_expires:
            return True  # No expiration means active
        
        expires_dt = datetime.fromisoformat(self.subscription_expires.replace('Z', '+00:00'))
        return datetime.utcnow() < expires_dt.replace(tzinfo=None)
    
    def can_add_user(self) -> bool:
        """Check if organization can add more users."""
        if not self.user_limit:
            return True
        return self.current_users < self.user_limit
    
    def can_add_project(self) -> bool:
        """Check if organization can add more projects."""
        if not self.project_limit:
            return True
        return self.current_projects < self.project_limit
    
    def can_run_scan(self) -> bool:
        """Check if organization can run more scans this month."""
        if not self.scan_limit_monthly:
            return True
        return self.scans_this_month < self.scan_limit_monthly
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get organization usage summary."""
        return {
            "users": {
                "current": self.current_users,
                "limit": self.user_limit,
                "percentage": (self.current_users / self.user_limit * 100) if self.user_limit else 0
            },
            "projects": {
                "current": self.current_projects,
                "limit": self.project_limit,
                "percentage": (self.current_projects / self.project_limit * 100) if self.project_limit else 0
            },
            "scans": {
                "current": self.scans_this_month,
                "limit": self.scan_limit_monthly,
                "percentage": (self.scans_this_month / self.scan_limit_monthly * 100) if self.scan_limit_monthly else 0
            },
            "storage": {
                "current": self.storage_used_gb,
                "limit": self.storage_limit_gb,
                "percentage": (self.storage_used_gb / self.storage_limit_gb * 100) if self.storage_limit_gb else 0
            }
        }


class Team(BaseModel):
    """Team entity within an organization."""
    
    __tablename__ = "teams"
    
    # Relationship to organization
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    
    # Basic information
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    team_type = Column(SQLEnum(TeamType), default=TeamType.CUSTOM, nullable=False)
    
    # Team configuration
    is_default = Column(Boolean, default=False, nullable=False)
    parent_team_id = Column(UUID(as_uuid=True), ForeignKey("teams.id"), nullable=True)
    
    # Settings
    settings = Column(JSONB, default=dict, nullable=False)
    permissions = Column(JSONB, default=list, nullable=False)
    
    # Contact information
    lead_email = Column(String(255), nullable=True)
    slack_channel = Column(String(100), nullable=True)
    
    # Statistics
    member_count = Column(Integer, default=0, nullable=False)
    project_count = Column(Integer, default=0, nullable=False)
    
    # Unique constraint within organization
    __table_args__ = (
        UniqueConstraint('organization_id', 'name', name='uq_team_org_name'),
    )
    
    # Relationships
    organization = relationship("Organization", back_populates="teams")
    parent_team = relationship("Team", remote_side="Team.id")
    projects = relationship("Project", back_populates="team")
    
    def _validate(self) -> List[str]:
        """Custom validation for team model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Team name cannot be empty")
            
        return errors
    
    def get_full_path(self) -> str:
        """Get full hierarchical path of team."""
        if self.parent_team:
            return f"{self.parent_team.get_full_path()}/{self.name}"
        return self.name
    
    def is_child_of(self, team_id: str) -> bool:
        """Check if this team is a child of another team."""
        if not self.parent_team_id:
            return False
        if str(self.parent_team_id) == team_id:
            return True
        if self.parent_team:
            return self.parent_team.is_child_of(team_id)
        return False


class Project(BaseModel):
    """Project entity for organizing security assessments."""
    
    __tablename__ = "projects"
    
    # Relationships
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey("teams.id"), nullable=True)
    
    # Basic information
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    slug = Column(String(100), nullable=False)
    
    # Project details
    status = Column(SQLEnum(ProjectStatus), default=ProjectStatus.ACTIVE, nullable=False)
    project_type = Column(String(100), nullable=True)  # web-app, api, container, etc.
    tags = Column(JSONB, default=list, nullable=False)
    
    # Repository information
    repository_url = Column(String(500), nullable=True)
    repository_branch = Column(String(100), nullable=True)
    repository_path = Column(String(500), nullable=True)
    
    # Container/artifact information
    container_registry = Column(String(200), nullable=True)
    container_image = Column(String(300), nullable=True)
    artifact_locations = Column(JSONB, default=list, nullable=False)
    
    # Configuration
    scan_config = Column(JSONB, default=dict, nullable=False)
    notification_config = Column(JSONB, default=dict, nullable=False)
    compliance_frameworks = Column(JSONB, default=list, nullable=False)
    
    # Risk and security settings
    risk_threshold = Column(String(20), default="medium", nullable=False)
    auto_scan_enabled = Column(Boolean, default=False, nullable=False)
    scan_schedule = Column(String(100), nullable=True)  # Cron expression
    
    # Statistics
    total_scans = Column(Integer, default=0, nullable=False)
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    open_vulnerabilities = Column(Integer, default=0, nullable=False)
    last_scan_date = Column(JSON, nullable=True)
    risk_score = Column(Float, nullable=True)
    
    # Access control
    visibility = Column(String(20), default="private", nullable=False)  # private, internal, public
    access_control = Column(JSONB, default=dict, nullable=False)
    
    # Integration settings
    ci_cd_integration = Column(JSONB, default=dict, nullable=False)
    issue_tracker_config = Column(JSONB, default=dict, nullable=False)
    
    # Unique constraint within organization
    __table_args__ = (
        UniqueConstraint('organization_id', 'slug', name='uq_project_org_slug'),
    )
    
    # Relationships
    organization = relationship("Organization", back_populates="projects")
    team = relationship("Team", back_populates="projects")
    
    def _validate(self) -> List[str]:
        """Custom validation for project model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Project name cannot be empty")
        
        if not self.slug or len(self.slug.strip()) == 0:
            errors.append("Project slug cannot be empty")
            
        return errors
    
    def is_active(self) -> bool:
        """Check if project is active."""
        return self.status == ProjectStatus.ACTIVE
    
    def get_risk_level(self) -> str:
        """Get project risk level."""
        if not self.risk_score:
            return "unknown"
        
        if self.risk_score >= 8.0:
            return "critical"
        elif self.risk_score >= 6.0:
            return "high"
        elif self.risk_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    def calculate_risk_score(self) -> float:
        """Calculate project risk score based on vulnerabilities."""
        if self.total_vulnerabilities == 0:
            self.risk_score = 0.0
            return self.risk_score
        
        # Simple risk calculation based on open vulnerabilities
        open_ratio = self.open_vulnerabilities / self.total_vulnerabilities
        base_score = min(open_ratio * 10, 10.0)
        
        # Adjust based on total count
        if self.total_vulnerabilities > 100:
            base_score = min(base_score * 1.2, 10.0)
        elif self.total_vulnerabilities > 50:
            base_score = min(base_score * 1.1, 10.0)
        
        self.risk_score = round(base_score, 2)
        return self.risk_score
    
    def needs_scan(self) -> bool:
        """Check if project needs scanning."""
        if not self.last_scan_date:
            return True
        
        last_scan = datetime.fromisoformat(self.last_scan_date.replace('Z', '+00:00'))
        days_since_scan = (datetime.utcnow() - last_scan.replace(tzinfo=None)).days
        
        # Scan if more than 7 days old
        return days_since_scan > 7
    
    def get_full_identifier(self) -> str:
        """Get full project identifier including organization."""
        return f"{self.organization.slug}/{self.slug}"
    
    def update_scan_statistics(self, vulnerability_count: int):
        """Update scan statistics after a scan."""
        self.total_scans += 1
        self.total_vulnerabilities = vulnerability_count
        self.last_scan_date = datetime.utcnow().isoformat()
        self.calculate_risk_score()