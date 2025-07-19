"""
Reporting API - REST endpoints for reporting operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.reporting import (
    Report, ReportTemplate, Dashboard, Widget, ReportSchedule,
    ReportType, ReportFormat, ReportStatus, ScheduleFrequency,
    create_report, create_report_template, create_dashboard, get_db
)
from ..services.report_generator import ReportGenerator
from ..main import get_report_generator

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


class CreateReportRequest(BaseModel):
    """Request model for creating reports."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    report_type: ReportType = Field(...)
    format: ReportFormat = Field(...)
    template_id: Optional[UUID] = None
    data_sources: Optional[List[str]] = Field(default_factory=list)
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    start_date: datetime = Field(...)
    end_date: datetime = Field(...)
    timezone: str = Field("UTC", max_length=50)
    visibility: str = Field("private", regex="^(private|shared|public)$")
    shared_with: Optional[List[str]] = Field(default_factory=list)


class UpdateReportRequest(BaseModel):
    """Request model for updating reports."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    filters: Optional[Dict[str, Any]] = None
    parameters: Optional[Dict[str, Any]] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    visibility: Optional[str] = Field(None, regex="^(private|shared|public)$")
    shared_with: Optional[List[str]] = None
    updated_by: str = Field(..., min_length=1, max_length=255)


class CreateTemplateRequest(BaseModel):
    """Request model for creating report templates."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[str] = Field(None, max_length=100)
    report_type: ReportType = Field(...)
    template_config: Dict[str, Any] = Field(...)
    default_parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    required_parameters: Optional[List[str]] = Field(default_factory=list)
    data_sources: Optional[List[str]] = Field(default_factory=list)
    is_public: bool = Field(False)


class CreateDashboardRequest(BaseModel):
    """Request model for creating dashboards."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[str] = Field(None, max_length=100)
    layout: Dict[str, Any] = Field(...)
    widgets: List[Dict[str, Any]] = Field(...)
    refresh_interval: int = Field(300, ge=60, le=3600)
    auto_refresh: bool = Field(True)
    visibility: str = Field("private", regex="^(private|shared|public)$")
    shared_with: Optional[List[str]] = Field(default_factory=list)
    theme: str = Field("default", max_length=50)


class CreateScheduleRequest(BaseModel):
    """Request model for creating report schedules."""
    name: str = Field(..., min_length=1, max_length=255)
    frequency: ScheduleFrequency = Field(...)
    cron_expression: Optional[str] = Field(None, max_length=100)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    recipients: List[str] = Field(..., min_items=1)
    recipient_groups: Optional[List[str]] = Field(default_factory=list)
    delivery_method: str = Field("email", regex="^(email|slack|webhook)$")
    delivery_config: Optional[Dict[str, Any]] = Field(default_factory=dict)


@router.get("/reports")
@traced("reporting_api_get_reports")
async def get_reports(
    report_type: Optional[ReportType] = None,
    status: Optional[ReportStatus] = None,
    format: Optional[ReportFormat] = None,
    visibility: Optional[str] = Query(None, regex="^(private|shared|public)$"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get reports with filtering and pagination."""
    try:
        query = db.query(Report)
        
        # Apply filters
        if report_type:
            query = query.filter(Report.report_type == report_type)
        
        if status:
            query = query.filter(Report.status == status)
        
        if format:
            query = query.filter(Report.format == format)
        
        if visibility:
            query = query.filter(Report.visibility == visibility)
        
        if start_date:
            query = query.filter(Report.created_at >= start_date)
        
        if end_date:
            query = query.filter(Report.created_at <= end_date)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        reports = query.order_by(
            Report.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_reports = []
        for report in reports:
            formatted_reports.append({
                "id": str(report.id),
                "title": report.title,
                "description": report.description,
                "report_type": report.report_type,
                "format": report.format,
                "status": report.status,
                "created_at": report.created_at.isoformat(),
                "updated_at": report.updated_at.isoformat(),
                "created_by": report.created_by,
                "file_size": report.file_size,
                "visibility": report.visibility,
                "view_count": report.view_count,
                "download_count": report.download_count
            })
        
        return {
            "reports": formatted_reports,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting reports: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/reports/{report_id}")
@traced("reporting_api_get_report")
async def get_report(
    report_id: UUID,
    db: Session = Depends(get_db)
):
    """Get a specific report with details."""
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Update view count
        report.view_count += 1
        report.last_accessed = datetime.now()
        db.commit()
        
        # Get schedules
        schedules = db.query(ReportSchedule).filter(
            ReportSchedule.report_id == report_id
        ).all()
        
        # Format schedules
        formatted_schedules = []
        for schedule in schedules:
            formatted_schedules.append({
                "id": str(schedule.id),
                "name": schedule.name,
                "frequency": schedule.frequency,
                "is_active": schedule.is_active,
                "next_run": schedule.next_run.isoformat() if schedule.next_run else None,
                "last_run": schedule.last_run.isoformat() if schedule.last_run else None,
                "recipients": schedule.recipients,
                "delivery_method": schedule.delivery_method
            })
        
        return {
            "id": str(report.id),
            "title": report.title,
            "description": report.description,
            "report_type": report.report_type,
            "format": report.format,
            "template_id": str(report.template_id) if report.template_id else None,
            "data_sources": report.data_sources,
            "filters": report.filters,
            "parameters": report.parameters,
            "start_date": report.start_date.isoformat() if report.start_date else None,
            "end_date": report.end_date.isoformat() if report.end_date else None,
            "timezone": report.timezone,
            "status": report.status,
            "generation_started_at": report.generation_started_at.isoformat() if report.generation_started_at else None,
            "generation_completed_at": report.generation_completed_at.isoformat() if report.generation_completed_at else None,
            "generation_duration": report.generation_duration,
            "content": report.content,
            "file_path": report.file_path,
            "file_size": report.file_size,
            "file_hash": report.file_hash,
            "created_at": report.created_at.isoformat(),
            "updated_at": report.updated_at.isoformat(),
            "created_by": report.created_by,
            "updated_by": report.updated_by,
            "visibility": report.visibility,
            "shared_with": report.shared_with,
            "view_count": report.view_count,
            "download_count": report.download_count,
            "last_accessed": report.last_accessed.isoformat() if report.last_accessed else None,
            "schedules": formatted_schedules
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting report {report_id}: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/reports")
@traced("reporting_api_create_report")
async def create_report_endpoint(
    request: CreateReportRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    generator: ReportGenerator = Depends(get_report_generator)
):
    """Create a new report."""
    try:
        # Sanitize inputs
        title = sanitize_input(request.title, max_length=255)
        description = sanitize_input(request.description, max_length=1000) if request.description else None
        
        # Validate date range
        if request.start_date >= request.end_date:
            raise HTTPException(status_code=400, detail="Start date must be before end date")
        
        # Create report
        report = create_report(
            title=title,
            report_type=request.report_type,
            format=request.format,
            created_by="api_user",  # In real implementation, get from JWT
            description=description,
            template_id=request.template_id,
            data_sources=request.data_sources,
            filters=request.filters,
            parameters=request.parameters,
            start_date=request.start_date,
            end_date=request.end_date,
            timezone=request.timezone,
            visibility=request.visibility,
            shared_with=request.shared_with
        )
        
        db.add(report)
        db.commit()
        db.refresh(report)
        
        # Queue report generation
        background_tasks.add_task(generator.generate_report, report.id)
        
        logger.info(f"Report created and queued for generation: {report.id}")
        metrics.reporting_api_reports_created.inc()
        
        return {
            "id": str(report.id),
            "title": report.title,
            "report_type": report.report_type,
            "format": report.format,
            "status": report.status,
            "created_at": report.created_at.isoformat(),
            "created_by": report.created_by,
            "message": "Report created and queued for generation"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating report: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/reports/{report_id}")
@traced("reporting_api_update_report")
async def update_report(
    report_id: UUID,
    request: UpdateReportRequest,
    db: Session = Depends(get_db)
):
    """Update a report."""
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Sanitize inputs
        updated_by = sanitize_input(request.updated_by, max_length=255)
        
        # Update fields
        if request.title is not None:
            report.title = sanitize_input(request.title, max_length=255)
        
        if request.description is not None:
            report.description = sanitize_input(request.description, max_length=1000)
        
        if request.filters is not None:
            report.filters = request.filters
        
        if request.parameters is not None:
            report.parameters = request.parameters
        
        if request.start_date is not None:
            report.start_date = request.start_date
        
        if request.end_date is not None:
            report.end_date = request.end_date
        
        if request.visibility is not None:
            report.visibility = request.visibility
        
        if request.shared_with is not None:
            report.shared_with = request.shared_with
        
        # Update metadata
        report.updated_by = updated_by
        report.updated_at = datetime.now()
        
        db.commit()
        
        logger.info(f"Report updated: {report_id}")
        metrics.reporting_api_reports_updated.inc()
        
        return {
            "id": str(report.id),
            "title": report.title,
            "updated_at": report.updated_at.isoformat(),
            "updated_by": report.updated_by
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating report: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/reports/{report_id}/regenerate")
@traced("reporting_api_regenerate_report")
async def regenerate_report(
    report_id: UUID,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    generator: ReportGenerator = Depends(get_report_generator)
):
    """Regenerate a report."""
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Reset report status
        report.status = ReportStatus.GENERATING
        report.generation_started_at = datetime.now()
        report.generation_completed_at = None
        report.generation_duration = None
        
        db.commit()
        
        # Queue report generation
        background_tasks.add_task(generator.generate_report, report.id)
        
        logger.info(f"Report regeneration queued: {report_id}")
        metrics.reporting_api_reports_regenerated.inc()
        
        return {
            "id": str(report.id),
            "status": report.status,
            "generation_started_at": report.generation_started_at.isoformat(),
            "message": "Report regeneration queued"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error regenerating report: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/templates")
@traced("reporting_api_get_templates")
async def get_report_templates(
    report_type: Optional[ReportType] = None,
    category: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_public: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get report templates with filtering and pagination."""
    try:
        query = db.query(ReportTemplate)
        
        # Apply filters
        if report_type:
            query = query.filter(ReportTemplate.report_type == report_type)
        
        if category:
            query = query.filter(ReportTemplate.category == category)
        
        if is_active is not None:
            query = query.filter(ReportTemplate.is_active == is_active)
        
        if is_public is not None:
            query = query.filter(ReportTemplate.is_public == is_public)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        templates = query.order_by(
            ReportTemplate.usage_count.desc(),
            ReportTemplate.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_templates = []
        for template in templates:
            formatted_templates.append({
                "id": str(template.id),
                "name": template.name,
                "description": template.description,
                "category": template.category,
                "report_type": template.report_type,
                "is_active": template.is_active,
                "is_public": template.is_public,
                "version": template.version,
                "usage_count": template.usage_count,
                "created_at": template.created_at.isoformat(),
                "created_by": template.created_by,
                "last_used": template.last_used.isoformat() if template.last_used else None
            })
        
        return {
            "templates": formatted_templates,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting report templates: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/templates")
@traced("reporting_api_create_template")
async def create_report_template_endpoint(
    request: CreateTemplateRequest,
    db: Session = Depends(get_db)
):
    """Create a new report template."""
    try:
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        description = sanitize_input(request.description, max_length=1000) if request.description else None
        
        # Create template
        template = create_report_template(
            name=name,
            report_type=request.report_type,
            template_config=request.template_config,
            created_by="api_user",  # In real implementation, get from JWT
            description=description,
            category=request.category,
            default_parameters=request.default_parameters,
            required_parameters=request.required_parameters,
            data_sources=request.data_sources,
            is_public=request.is_public
        )
        
        db.add(template)
        db.commit()
        db.refresh(template)
        
        logger.info(f"Report template created: {template.id}")
        metrics.reporting_api_templates_created.inc()
        
        return {
            "id": str(template.id),
            "name": template.name,
            "report_type": template.report_type,
            "is_active": template.is_active,
            "is_public": template.is_public,
            "created_at": template.created_at.isoformat(),
            "created_by": template.created_by
        }
        
    except Exception as e:
        logger.error(f"Error creating report template: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/dashboards")
@traced("reporting_api_get_dashboards")
async def get_dashboards(
    category: Optional[str] = None,
    visibility: Optional[str] = Query(None, regex="^(private|shared|public)$"),
    is_active: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get dashboards with filtering and pagination."""
    try:
        query = db.query(Dashboard)
        
        # Apply filters
        if category:
            query = query.filter(Dashboard.category == category)
        
        if visibility:
            query = query.filter(Dashboard.visibility == visibility)
        
        if is_active is not None:
            query = query.filter(Dashboard.is_active == is_active)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        dashboards = query.order_by(
            Dashboard.view_count.desc(),
            Dashboard.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_dashboards = []
        for dashboard in dashboards:
            formatted_dashboards.append({
                "id": str(dashboard.id),
                "name": dashboard.name,
                "description": dashboard.description,
                "category": dashboard.category,
                "visibility": dashboard.visibility,
                "is_active": dashboard.is_active,
                "is_default": dashboard.is_default,
                "theme": dashboard.theme,
                "refresh_interval": dashboard.refresh_interval,
                "auto_refresh": dashboard.auto_refresh,
                "view_count": dashboard.view_count,
                "created_at": dashboard.created_at.isoformat(),
                "created_by": dashboard.created_by,
                "last_viewed": dashboard.last_viewed.isoformat() if dashboard.last_viewed else None,
                "last_refreshed": dashboard.last_refreshed.isoformat() if dashboard.last_refreshed else None
            })
        
        return {
            "dashboards": formatted_dashboards,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboards: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/dashboards")
@traced("reporting_api_create_dashboard")
async def create_dashboard_endpoint(
    request: CreateDashboardRequest,
    db: Session = Depends(get_db)
):
    """Create a new dashboard."""
    try:
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        description = sanitize_input(request.description, max_length=1000) if request.description else None
        
        # Create dashboard
        dashboard = create_dashboard(
            name=name,
            layout=request.layout,
            widgets=request.widgets,
            created_by="api_user",  # In real implementation, get from JWT
            description=description,
            category=request.category,
            refresh_interval=request.refresh_interval,
            auto_refresh=request.auto_refresh,
            visibility=request.visibility,
            shared_with=request.shared_with,
            theme=request.theme
        )
        
        db.add(dashboard)
        db.commit()
        db.refresh(dashboard)
        
        logger.info(f"Dashboard created: {dashboard.id}")
        metrics.reporting_api_dashboards_created.inc()
        
        return {
            "id": str(dashboard.id),
            "name": dashboard.name,
            "category": dashboard.category,
            "visibility": dashboard.visibility,
            "is_active": dashboard.is_active,
            "created_at": dashboard.created_at.isoformat(),
            "created_by": dashboard.created_by
        }
        
    except Exception as e:
        logger.error(f"Error creating dashboard: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics")
@traced("reporting_api_get_statistics")
async def get_reporting_statistics(
    time_range: str = Query("24h", regex="^(1h|6h|24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Get reporting statistics."""
    try:
        # Parse time range
        time_delta_map = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30)
        }
        
        time_delta = time_delta_map.get(time_range, timedelta(hours=24))
        start_time = datetime.now() - time_delta
        
        # Get report statistics
        total_reports = db.query(Report).filter(
            Report.created_at >= start_time
        ).count()
        
        completed_reports = db.query(Report).filter(
            Report.created_at >= start_time,
            Report.status == ReportStatus.COMPLETED
        ).count()
        
        failed_reports = db.query(Report).filter(
            Report.created_at >= start_time,
            Report.status == ReportStatus.FAILED
        ).count()
        
        # Get reports by type
        type_stats = {}
        for report_type in ReportType:
            count = db.query(Report).filter(
                Report.created_at >= start_time,
                Report.report_type == report_type
            ).count()
            type_stats[report_type.value] = count
        
        # Get reports by format
        format_stats = {}
        for format_type in ReportFormat:
            count = db.query(Report).filter(
                Report.created_at >= start_time,
                Report.format == format_type
            ).count()
            format_stats[format_type.value] = count
        
        # Get template usage
        template_usage = db.query(ReportTemplate).filter(
            ReportTemplate.last_used >= start_time
        ).count()
        
        # Get dashboard views
        dashboard_views = db.query(Dashboard).filter(
            Dashboard.last_viewed >= start_time
        ).count()
        
        return {
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_reports": total_reports,
            "completed_reports": completed_reports,
            "failed_reports": failed_reports,
            "success_rate": (completed_reports / max(total_reports, 1)) * 100,
            "type_breakdown": type_stats,
            "format_breakdown": format_stats,
            "template_usage": template_usage,
            "dashboard_views": dashboard_views
        }
        
    except Exception as e:
        logger.error(f"Error getting reporting statistics: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/reports/{report_id}")
@traced("reporting_api_delete_report")
async def delete_report(
    report_id: UUID,
    user_id: str = Query(..., description="User ID performing the deletion"),
    db: Session = Depends(get_db)
):
    """Delete a report."""
    try:
        # Sanitize input
        user_id = sanitize_input(user_id, max_length=255)
        
        report = db.query(Report).filter(Report.id == report_id).first()
        
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        # Log deletion for audit
        logger.info(f"Deleting report {report_id} by user {user_id}")
        
        # Delete associated schedules
        db.query(ReportSchedule).filter(
            ReportSchedule.report_id == report_id
        ).delete()
        
        # Delete report
        db.delete(report)
        db.commit()
        
        # Delete file if exists
        if report.file_path:
            import os
            try:
                os.remove(report.file_path)
            except OSError:
                pass
        
        metrics.reporting_api_reports_deleted.inc()
        
        return {
            "message": "Report deleted successfully",
            "report_id": str(report_id),
            "deleted_by": user_id,
            "deleted_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting report: {e}")
        metrics.reporting_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")