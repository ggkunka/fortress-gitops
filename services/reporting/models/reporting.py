"""
Reporting Service Models - Database models for reporting and analytics
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from enum import Enum

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.engine import create_engine

from shared.database.connection import get_db_session

Base = declarative_base()


class ReportType(str, Enum):
    """Report types."""
    SECURITY_DASHBOARD = "security_dashboard"
    RISK_ASSESSMENT = "risk_assessment"
    INCIDENT_ANALYSIS = "incident_analysis"
    COMPLIANCE_REPORT = "compliance_report"
    THREAT_INTELLIGENCE = "threat_intelligence"
    PERFORMANCE_METRICS = "performance_metrics"
    EXECUTIVE_SUMMARY = "executive_summary"
    FORENSIC_ANALYSIS = "forensic_analysis"
    VULNERABILITY_REPORT = "vulnerability_report"
    CUSTOM = "custom"


class ReportStatus(str, Enum):
    """Report status."""
    DRAFT = "draft"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    ARCHIVED = "archived"


class ReportFormat(str, Enum):
    """Report formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"
    POWERPOINT = "powerpoint"


class ScheduleFrequency(str, Enum):
    """Schedule frequencies."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"


class Report(Base):
    """Report model."""
    __tablename__ = "reports"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Basic report info
    title = Column(String(255), nullable=False)
    description = Column(Text)
    report_type = Column(String(50), nullable=False)  # ReportType enum
    format = Column(String(20), nullable=False)  # ReportFormat enum
    
    # Report configuration
    template_id = Column(PGUUID(as_uuid=True), ForeignKey("report_templates.id"))
    data_sources = Column(JSON)  # List of data sources
    filters = Column(JSON)  # Report filters
    parameters = Column(JSON)  # Report parameters
    
    # Time range
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    timezone = Column(String(50), default="UTC")
    
    # Status and generation
    status = Column(String(20), default=ReportStatus.DRAFT)
    generation_started_at = Column(DateTime)
    generation_completed_at = Column(DateTime)
    generation_duration = Column(Float)  # seconds
    
    # Content and storage
    content = Column(JSON)  # Report content/data
    file_path = Column(String(500))  # Path to generated file
    file_size = Column(Integer)  # File size in bytes
    file_hash = Column(String(64))  # SHA-256 hash
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    updated_by = Column(String(255))
    
    # Access control
    visibility = Column(String(20), default="private")  # private, shared, public
    shared_with = Column(JSON)  # List of users/groups with access
    
    # Metrics
    view_count = Column(Integer, default=0)
    download_count = Column(Integer, default=0)
    last_accessed = Column(DateTime)
    
    # Relationships
    template = relationship("ReportTemplate", back_populates="reports")
    schedules = relationship("ReportSchedule", back_populates="report")
    
    __table_args__ = (
        Index("idx_reports_type_status", "report_type", "status"),
        Index("idx_reports_created_at", "created_at"),
        Index("idx_reports_created_by", "created_by"),
    )


class ReportTemplate(Base):
    """Report template model."""
    __tablename__ = "report_templates"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Template info
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    report_type = Column(String(50), nullable=False)
    
    # Template configuration
    template_config = Column(JSON, nullable=False)
    default_parameters = Column(JSON)
    required_parameters = Column(JSON)
    
    # Layout and styling
    layout_config = Column(JSON)
    style_config = Column(JSON)
    chart_configs = Column(JSON)
    
    # Data configuration
    data_sources = Column(JSON)  # Required data sources
    data_queries = Column(JSON)  # Pre-defined queries
    data_transformations = Column(JSON)  # Data transformation rules
    
    # Validation
    validation_rules = Column(JSON)
    sample_data = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_public = Column(Boolean, default=False)
    version = Column(String(20), default="1.0")
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    updated_by = Column(String(255))
    
    # Usage metrics
    usage_count = Column(Integer, default=0)
    last_used = Column(DateTime)
    
    # Relationships
    reports = relationship("Report", back_populates="template")
    
    __table_args__ = (
        Index("idx_report_templates_type", "report_type"),
        Index("idx_report_templates_category", "category"),
        Index("idx_report_templates_active", "is_active"),
    )


class ReportSchedule(Base):
    """Report schedule model."""
    __tablename__ = "report_schedules"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    report_id = Column(PGUUID(as_uuid=True), ForeignKey("reports.id"), nullable=False)
    
    # Schedule configuration
    name = Column(String(255), nullable=False)
    frequency = Column(String(20), nullable=False)  # ScheduleFrequency enum
    cron_expression = Column(String(100))  # Custom cron expression
    
    # Timing
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    next_run = Column(DateTime)
    last_run = Column(DateTime)
    
    # Recipients
    recipients = Column(JSON)  # List of email addresses
    recipient_groups = Column(JSON)  # List of groups
    
    # Delivery configuration
    delivery_method = Column(String(20), default="email")  # email, slack, webhook
    delivery_config = Column(JSON)  # Method-specific configuration
    
    # Status
    is_active = Column(Boolean, default=True)
    is_running = Column(Boolean, default=False)
    
    # Execution tracking
    execution_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    last_error = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    # Relationships
    report = relationship("Report", back_populates="schedules")
    
    __table_args__ = (
        Index("idx_report_schedules_report_id", "report_id"),
        Index("idx_report_schedules_next_run", "next_run"),
        Index("idx_report_schedules_active", "is_active"),
    )


class Dashboard(Base):
    """Dashboard model."""
    __tablename__ = "dashboards"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Dashboard info
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    
    # Layout and widgets
    layout = Column(JSON, nullable=False)  # Dashboard layout configuration
    widgets = Column(JSON, nullable=False)  # Widget configurations
    
    # Data refresh
    refresh_interval = Column(Integer, default=300)  # seconds
    auto_refresh = Column(Boolean, default=True)
    last_refreshed = Column(DateTime)
    
    # Access control
    visibility = Column(String(20), default="private")
    shared_with = Column(JSON)
    is_default = Column(Boolean, default=False)
    
    # Customization
    theme = Column(String(50), default="default")
    custom_css = Column(Text)
    custom_js = Column(Text)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    updated_by = Column(String(255))
    
    # Usage metrics
    view_count = Column(Integer, default=0)
    last_viewed = Column(DateTime)
    
    __table_args__ = (
        Index("idx_dashboards_category", "category"),
        Index("idx_dashboards_created_by", "created_by"),
        Index("idx_dashboards_active", "is_active"),
    )


class Widget(Base):
    """Widget model."""
    __tablename__ = "widgets"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Widget info
    name = Column(String(255), nullable=False)
    description = Column(Text)
    widget_type = Column(String(50), nullable=False)  # chart, table, metric, etc.
    
    # Configuration
    config = Column(JSON, nullable=False)  # Widget-specific configuration
    data_source = Column(String(100))  # Data source identifier
    query = Column(JSON)  # Data query configuration
    
    # Visualization
    chart_type = Column(String(50))  # bar, line, pie, gauge, etc.
    chart_config = Column(JSON)  # Chart-specific configuration
    
    # Data refresh
    refresh_interval = Column(Integer, default=300)
    cache_duration = Column(Integer, default=300)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        Index("idx_widgets_type", "widget_type"),
        Index("idx_widgets_data_source", "data_source"),
        Index("idx_widgets_active", "is_active"),
    )


class ReportData(Base):
    """Report data cache model."""
    __tablename__ = "report_data"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Data identification
    data_key = Column(String(255), nullable=False, unique=True)
    data_source = Column(String(100), nullable=False)
    data_type = Column(String(50), nullable=False)
    
    # Data content
    data = Column(JSON, nullable=False)
    metadata = Column(JSON)
    
    # Caching
    generated_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime)
    is_cached = Column(Boolean, default=True)
    
    # Versioning
    version = Column(Integer, default=1)
    checksum = Column(String(64))
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    __table_args__ = (
        Index("idx_report_data_key", "data_key"),
        Index("idx_report_data_source", "data_source"),
        Index("idx_report_data_expires_at", "expires_at"),
    )


class ReportExecution(Base):
    """Report execution tracking model."""
    __tablename__ = "report_executions"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    report_id = Column(PGUUID(as_uuid=True), ForeignKey("reports.id"), nullable=False)
    schedule_id = Column(PGUUID(as_uuid=True), ForeignKey("report_schedules.id"))
    
    # Execution details
    execution_type = Column(String(20), nullable=False)  # manual, scheduled, api
    triggered_by = Column(String(255))
    
    # Status tracking
    status = Column(String(20), default="pending")
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration = Column(Float)  # seconds
    
    # Results
    output_file = Column(String(500))
    output_size = Column(Integer)
    record_count = Column(Integer)
    
    # Error handling
    error_message = Column(Text)
    error_details = Column(JSON)
    retry_count = Column(Integer, default=0)
    
    # Resource usage
    memory_used = Column(Float)  # MB
    cpu_time = Column(Float)  # seconds
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    metadata = Column(JSON)
    
    __table_args__ = (
        Index("idx_report_executions_report_id", "report_id"),
        Index("idx_report_executions_status", "status"),
        Index("idx_report_executions_started_at", "started_at"),
    )


class ReportAlert(Base):
    """Report alert model."""
    __tablename__ = "report_alerts"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Alert configuration
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Trigger conditions
    data_source = Column(String(100), nullable=False)
    metric_name = Column(String(255), nullable=False)
    condition = Column(String(20), nullable=False)  # gt, lt, eq, etc.
    threshold = Column(Float, nullable=False)
    
    # Alert rules
    alert_rules = Column(JSON)
    evaluation_interval = Column(Integer, default=300)  # seconds
    
    # Notification
    notification_channels = Column(JSON)  # List of channels
    notification_template = Column(String(255))
    
    # Status
    is_active = Column(Boolean, default=True)
    last_triggered = Column(DateTime)
    trigger_count = Column(Integer, default=0)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        Index("idx_report_alerts_data_source", "data_source"),
        Index("idx_report_alerts_active", "is_active"),
        Index("idx_report_alerts_last_triggered", "last_triggered"),
    )


class ReportMetrics(Base):
    """Report metrics model."""
    __tablename__ = "report_metrics"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Time period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Report metrics
    total_reports = Column(Integer, default=0)
    reports_generated = Column(Integer, default=0)
    reports_failed = Column(Integer, default=0)
    
    # Performance metrics
    avg_generation_time = Column(Float, default=0.0)
    max_generation_time = Column(Float, default=0.0)
    total_generation_time = Column(Float, default=0.0)
    
    # Usage metrics
    total_views = Column(Integer, default=0)
    total_downloads = Column(Integer, default=0)
    unique_users = Column(Integer, default=0)
    
    # Resource metrics
    total_data_processed = Column(Float, default=0.0)  # MB
    avg_memory_usage = Column(Float, default=0.0)  # MB
    peak_memory_usage = Column(Float, default=0.0)  # MB
    
    # Popular reports
    popular_reports = Column(JSON)
    popular_templates = Column(JSON)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    metadata = Column(JSON)
    
    __table_args__ = (
        Index("idx_report_metrics_period", "period_start", "period_end"),
    )


# Database utility functions
def create_report(
    title: str,
    report_type: ReportType,
    format: ReportFormat,
    created_by: str,
    description: Optional[str] = None,
    **kwargs
) -> Report:
    """Create a new report."""
    report = Report(
        title=title,
        report_type=report_type,
        format=format,
        created_by=created_by,
        description=description,
        **kwargs
    )
    return report


def create_report_template(
    name: str,
    report_type: ReportType,
    template_config: Dict[str, Any],
    created_by: str,
    description: Optional[str] = None,
    **kwargs
) -> ReportTemplate:
    """Create a new report template."""
    template = ReportTemplate(
        name=name,
        report_type=report_type,
        template_config=template_config,
        created_by=created_by,
        description=description,
        **kwargs
    )
    return template


def create_dashboard(
    name: str,
    layout: Dict[str, Any],
    widgets: List[Dict[str, Any]],
    created_by: str,
    description: Optional[str] = None,
    **kwargs
) -> Dashboard:
    """Create a new dashboard."""
    dashboard = Dashboard(
        name=name,
        layout=layout,
        widgets=widgets,
        created_by=created_by,
        description=description,
        **kwargs
    )
    return dashboard


def get_db() -> Session:
    """Get database session."""
    return get_db_session()