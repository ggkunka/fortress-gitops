"""
Report Models

Database models for reports, report templates, and dashboards.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Integer, Float, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class ReportType(str, Enum):
    """Types of reports."""
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    SECURITY_POSTURE = "security_posture"
    RISK_ASSESSMENT = "risk_assessment"
    AUDIT = "audit"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_DETAIL = "technical_detail"
    TREND_ANALYSIS = "trend_analysis"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    """Report output formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    XLSX = "xlsx"
    DOCX = "docx"
    XML = "xml"


class ReportStatus(str, Enum):
    """Report generation status."""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


class TemplateType(str, Enum):
    """Types of report templates."""
    STANDARD = "standard"
    CUSTOM = "custom"
    REGULATORY = "regulatory"
    EXECUTIVE = "executive"
    TECHNICAL = "technical"


class DashboardType(str, Enum):
    """Types of dashboards."""
    OPERATIONAL = "operational"
    EXECUTIVE = "executive"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    ANALYTICS = "analytics"
    CUSTOM = "custom"


class Report(BaseModel):
    """Report entity."""
    
    __tablename__ = "reports"
    
    # Report identification
    report_id = Column(String(100), unique=True, nullable=False)
    name = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    report_type = Column(SQLEnum(ReportType), nullable=False)
    
    # Report configuration
    template_id = Column(UUID(as_uuid=True), ForeignKey("report_templates.id"), nullable=True)
    format = Column(SQLEnum(ReportFormat), default=ReportFormat.PDF, nullable=False)
    
    # Report scope and filters
    scope = Column(JSONB, default=dict, nullable=False)  # What data to include
    filters = Column(JSONB, default=dict, nullable=False)  # Data filters
    date_range = Column(JSONB, default=dict, nullable=False)  # Time period
    
    # Generation details
    status = Column(SQLEnum(ReportStatus), default=ReportStatus.PENDING, nullable=False)
    generation_started = Column(JSON, nullable=True)
    generation_completed = Column(JSON, nullable=True)
    generation_duration_seconds = Column(Integer, nullable=True)
    
    # Report content
    report_data = Column(JSONB, default=dict, nullable=False)  # Raw data
    rendered_content = Column(Text, nullable=True)  # Formatted report
    summary = Column(JSONB, default=dict, nullable=False)  # Key findings
    
    # File information
    file_path = Column(String(500), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    file_hash = Column(String(64), nullable=True)
    download_count = Column(Integer, default=0, nullable=False)
    
    # Report metadata
    version = Column(String(50), default="1.0", nullable=False)
    language = Column(String(10), default="en", nullable=False)
    timezone = Column(String(50), default="UTC", nullable=False)
    
    # Access control
    visibility = Column(String(20), default="private", nullable=False)  # private, internal, public
    access_permissions = Column(JSONB, default=list, nullable=False)
    
    # Scheduling and automation
    is_scheduled = Column(Boolean, default=False, nullable=False)
    schedule_expression = Column(String(100), nullable=True)  # Cron expression
    next_generation = Column(JSON, nullable=True)
    auto_distribution = Column(JSONB, default=list, nullable=False)  # Email list
    
    # Quality metrics
    accuracy_score = Column(Float, nullable=True)
    completeness_score = Column(Float, nullable=True)
    freshness_score = Column(Float, nullable=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    requested_by = Column(UUID(as_uuid=True), nullable=True)
    
    # External references
    external_id = Column(String(200), nullable=True)
    compliance_mapping = Column(JSONB, default=dict, nullable=False)
    regulatory_requirements = Column(JSONB, default=list, nullable=False)
    
    # Archive settings
    retention_days = Column(Integer, default=365, nullable=False)
    archive_after_days = Column(Integer, default=90, nullable=False)
    
    # Relationships
    template = relationship("ReportTemplate", back_populates="reports")
    
    def _validate(self) -> List[str]:
        """Custom validation for report model."""
        errors = []
        
        if not self.report_id or len(self.report_id.strip()) == 0:
            errors.append("Report ID cannot be empty")
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Report name cannot be empty")
        
        if self.retry_count > self.max_retries:
            errors.append("Retry count cannot exceed max retries")
            
        return errors
    
    def start_generation(self):
        """Mark report generation as started."""
        self.status = ReportStatus.GENERATING
        self.generation_started = datetime.utcnow().isoformat()
    
    def complete_generation(self, file_path: Optional[str] = None, file_size: Optional[int] = None):
        """Mark report generation as completed."""
        self.status = ReportStatus.COMPLETED
        self.generation_completed = datetime.utcnow().isoformat()
        
        if self.generation_started:
            start_time = datetime.fromisoformat(self.generation_started.replace('Z', '+00:00'))
            duration = (datetime.utcnow() - start_time.replace(tzinfo=None)).total_seconds()
            self.generation_duration_seconds = int(duration)
        
        if file_path:
            self.file_path = file_path
        if file_size:
            self.file_size_bytes = file_size
    
    def fail_generation(self, error_message: str):
        """Mark report generation as failed."""
        self.status = ReportStatus.FAILED
        self.error_message = error_message
        self.retry_count += 1
        
        if self.retry_count < self.max_retries:
            self.status = ReportStatus.PENDING  # Allow retry
    
    def calculate_quality_scores(self):
        """Calculate report quality metrics."""
        # Accuracy based on data validation
        self.accuracy_score = self._calculate_accuracy()
        
        # Completeness based on required sections
        self.completeness_score = self._calculate_completeness()
        
        # Freshness based on data age
        self.freshness_score = self._calculate_freshness()
    
    def _calculate_accuracy(self) -> float:
        """Calculate report accuracy score."""
        # Placeholder implementation
        return 1.0
    
    def _calculate_completeness(self) -> float:
        """Calculate report completeness score."""
        required_sections = self.template.required_sections if self.template else []
        if not required_sections:
            return 1.0
        
        present_sections = list(self.report_data.keys())
        completed_sections = sum(1 for section in required_sections if section in present_sections)
        
        return completed_sections / len(required_sections)
    
    def _calculate_freshness(self) -> float:
        """Calculate report data freshness score."""
        if not self.date_range.get('end_date'):
            return 0.5
        
        end_date = datetime.fromisoformat(self.date_range['end_date'].replace('Z', '+00:00'))
        days_old = (datetime.utcnow() - end_date.replace(tzinfo=None)).days
        
        # Fresher data gets higher score
        if days_old <= 1:
            return 1.0
        elif days_old <= 7:
            return 0.8
        elif days_old <= 30:
            return 0.6
        else:
            return 0.4
    
    def is_expired(self) -> bool:
        """Check if report has expired."""
        if not self.generation_completed:
            return False
        
        completed_dt = datetime.fromisoformat(self.generation_completed.replace('Z', '+00:00'))
        days_old = (datetime.utcnow() - completed_dt.replace(tzinfo=None)).days
        
        return days_old > self.retention_days
    
    def should_archive(self) -> bool:
        """Check if report should be archived."""
        if not self.generation_completed:
            return False
        
        completed_dt = datetime.fromisoformat(self.generation_completed.replace('Z', '+00:00'))
        days_old = (datetime.utcnow() - completed_dt.replace(tzinfo=None)).days
        
        return days_old > self.archive_after_days
    
    def record_download(self):
        """Record a download of this report."""
        self.download_count += 1


class ReportTemplate(BaseModel):
    """Report template entity."""
    
    __tablename__ = "report_templates"
    
    # Template identification
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    template_type = Column(SQLEnum(TemplateType), nullable=False)
    
    # Template configuration
    report_types = Column(JSONB, default=list, nullable=False)  # Supported report types
    supported_formats = Column(JSONB, default=list, nullable=False)  # Supported output formats
    
    # Template structure
    sections = Column(JSONB, default=list, nullable=False)  # Report sections
    required_sections = Column(JSONB, default=list, nullable=False)  # Mandatory sections
    layout_config = Column(JSONB, default=dict, nullable=False)  # Layout settings
    
    # Template content
    header_template = Column(Text, nullable=True)
    footer_template = Column(Text, nullable=True)
    section_templates = Column(JSONB, default=dict, nullable=False)
    style_config = Column(JSONB, default=dict, nullable=False)
    
    # Data requirements
    required_data_sources = Column(JSONB, default=list, nullable=False)
    data_mapping = Column(JSONB, default=dict, nullable=False)
    filter_definitions = Column(JSONB, default=list, nullable=False)
    
    # Template metadata
    version = Column(String(50), default="1.0", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)
    
    # Compliance and regulatory
    compliance_frameworks = Column(JSONB, default=list, nullable=False)
    regulatory_standards = Column(JSONB, default=list, nullable=False)
    certification_requirements = Column(JSONB, default=list, nullable=False)
    
    # Usage statistics
    usage_count = Column(Integer, default=0, nullable=False)
    last_used = Column(JSON, nullable=True)
    average_generation_time = Column(Integer, nullable=True)  # seconds
    
    # Customization settings
    customizable_sections = Column(JSONB, default=list, nullable=False)
    parameter_definitions = Column(JSONB, default=list, nullable=False)
    
    # Organization scope
    organization_id = Column(UUID(as_uuid=True), nullable=True)  # null = global template
    created_by = Column(UUID(as_uuid=True), nullable=True)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('name', 'organization_id', name='uq_template_org_name'),
    )
    
    # Relationships
    reports = relationship("Report", back_populates="template")
    
    def _validate(self) -> List[str]:
        """Custom validation for report template model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Template name cannot be empty")
        
        if not self.report_types:
            errors.append("Template must support at least one report type")
        
        if not self.supported_formats:
            errors.append("Template must support at least one output format")
            
        return errors
    
    def is_compatible_with(self, report_type: ReportType, format: ReportFormat) -> bool:
        """Check if template is compatible with report type and format."""
        return (
            report_type.value in self.report_types and
            format.value in self.supported_formats
        )
    
    def get_required_parameters(self) -> List[Dict[str, Any]]:
        """Get list of required parameters for this template."""
        return [param for param in self.parameter_definitions if param.get('required', False)]
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> List[str]:
        """Validate provided parameters against template requirements."""
        errors = []
        required_params = self.get_required_parameters()
        
        for param in required_params:
            param_name = param['name']
            if param_name not in parameters:
                errors.append(f"Required parameter '{param_name}' is missing")
            else:
                # Validate parameter type and constraints
                param_value = parameters[param_name]
                param_type = param.get('type', 'string')
                
                if param_type == 'integer' and not isinstance(param_value, int):
                    errors.append(f"Parameter '{param_name}' must be an integer")
                elif param_type == 'boolean' and not isinstance(param_value, bool):
                    errors.append(f"Parameter '{param_name}' must be a boolean")
                elif param_type == 'list' and not isinstance(param_value, list):
                    errors.append(f"Parameter '{param_name}' must be a list")
        
        return errors
    
    def record_usage(self, generation_time_seconds: Optional[int] = None):
        """Record template usage."""
        self.usage_count += 1
        self.last_used = datetime.utcnow().isoformat()
        
        if generation_time_seconds and self.average_generation_time:
            self.average_generation_time = (self.average_generation_time + generation_time_seconds) // 2
        elif generation_time_seconds:
            self.average_generation_time = generation_time_seconds


class Dashboard(BaseModel):
    """Dashboard entity for interactive data visualization."""
    
    __tablename__ = "dashboards"
    
    # Dashboard identification
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    dashboard_type = Column(SQLEnum(DashboardType), nullable=False)
    
    # Dashboard configuration
    layout = Column(JSONB, default=dict, nullable=False)  # Grid layout config
    widgets = Column(JSONB, default=list, nullable=False)  # Widget definitions
    theme = Column(String(50), default="default", nullable=False)
    
    # Data sources and refresh
    data_sources = Column(JSONB, default=list, nullable=False)
    refresh_interval = Column(Integer, default=300, nullable=False)  # seconds
    auto_refresh = Column(Boolean, default=True, nullable=False)
    last_refreshed = Column(JSON, nullable=True)
    
    # Filters and parameters
    global_filters = Column(JSONB, default=dict, nullable=False)
    parameter_definitions = Column(JSONB, default=list, nullable=False)
    default_parameters = Column(JSONB, default=dict, nullable=False)
    
    # Access control
    visibility = Column(String(20), default="private", nullable=False)
    shared_with = Column(JSONB, default=list, nullable=False)  # User/role IDs
    public_url = Column(String(500), nullable=True)
    
    # Dashboard state
    is_active = Column(Boolean, default=True, nullable=False)
    is_favorite = Column(Boolean, default=False, nullable=False)
    view_count = Column(Integer, default=0, nullable=False)
    last_viewed = Column(JSON, nullable=True)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    created_by = Column(UUID(as_uuid=True), nullable=True)
    
    # Dashboard metadata
    tags = Column(JSONB, default=list, nullable=False)
    category = Column(String(100), nullable=True)
    version = Column(String(50), default="1.0", nullable=False)
    
    # Performance metrics
    average_load_time = Column(Float, nullable=True)  # seconds
    cache_hit_rate = Column(Float, nullable=True)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('name', 'organization_id', name='uq_dashboard_org_name'),
    )
    
    def _validate(self) -> List[str]:
        """Custom validation for dashboard model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Dashboard name cannot be empty")
        
        if self.refresh_interval <= 0:
            errors.append("Refresh interval must be positive")
            
        return errors
    
    def record_view(self, load_time_seconds: Optional[float] = None):
        """Record dashboard view."""
        self.view_count += 1
        self.last_viewed = datetime.utcnow().isoformat()
        
        if load_time_seconds and self.average_load_time:
            self.average_load_time = (self.average_load_time + load_time_seconds) / 2
        elif load_time_seconds:
            self.average_load_time = load_time_seconds
    
    def needs_refresh(self) -> bool:
        """Check if dashboard data needs refresh."""
        if not self.auto_refresh or not self.last_refreshed:
            return True
        
        last_refresh = datetime.fromisoformat(self.last_refreshed.replace('Z', '+00:00'))
        seconds_since_refresh = (datetime.utcnow() - last_refresh.replace(tzinfo=None)).total_seconds()
        
        return seconds_since_refresh >= self.refresh_interval
    
    def mark_refreshed(self):
        """Mark dashboard as refreshed."""
        self.last_refreshed = datetime.utcnow().isoformat()
    
    def add_widget(self, widget_config: Dict[str, Any]):
        """Add widget to dashboard."""
        if self.widgets is None:
            self.widgets = []
        
        widget_config['id'] = str(uuid.uuid4())
        widget_config['created_at'] = datetime.utcnow().isoformat()
        self.widgets.append(widget_config)
    
    def remove_widget(self, widget_id: str):
        """Remove widget from dashboard."""
        if self.widgets:
            self.widgets = [w for w in self.widgets if w.get('id') != widget_id]
    
    def get_widget_by_id(self, widget_id: str) -> Optional[Dict[str, Any]]:
        """Get widget configuration by ID."""
        if not self.widgets:
            return None
        
        for widget in self.widgets:
            if widget.get('id') == widget_id:
                return widget
        
        return None
    
    def is_accessible_by(self, user_id: str, user_roles: List[str]) -> bool:
        """Check if dashboard is accessible by user."""
        if self.visibility == "public":
            return True
        
        if str(self.created_by) == user_id:
            return True
        
        # Check shared access
        for share_config in self.shared_with:
            if share_config.get('type') == 'user' and share_config.get('id') == user_id:
                return True
            if share_config.get('type') == 'role' and share_config.get('id') in user_roles:
                return True
        
        return False