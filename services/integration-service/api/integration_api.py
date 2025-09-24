"""
Integration API - REST endpoints for external system integrations
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

from ..models.integration import (
    Integration, IntegrationConnectionLog, IntegrationSyncLog, IntegrationWebhook,
    IntegrationTemplate, IntegrationType, IntegrationStatus, ConnectionStatus,
    DataSyncStatus, IntegrationCreate, IntegrationUpdate, IntegrationResponse,
    WebhookCreate, WebhookResponse, ConnectionLogResponse, SyncLogResponse,
    create_integration, create_webhook, get_db
)
from ..main import get_integration_manager

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


class TestConnectionRequest(BaseModel):
    """Request model for testing integration connections."""
    integration_type: IntegrationType
    provider: str = Field(..., min_length=1, max_length=100)
    config: Dict[str, Any] = Field(default_factory=dict)
    credentials: Dict[str, Any] = Field(..., description="Integration credentials for testing")


class SyncRequest(BaseModel):
    """Request model for triggering data synchronization."""
    sync_type: str = Field("pull", regex="^(pull|push|bidirectional)$")
    data: Optional[Dict[str, Any]] = Field(None, description="Data to push (required for push sync)")


@router.get("/integrations")
@traced("integration_api_get_integrations")
async def get_integrations(
    integration_type: Optional[IntegrationType] = None,
    provider: Optional[str] = None,
    status: Optional[IntegrationStatus] = None,
    is_enabled: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get integrations with filtering and pagination."""
    try:
        query = db.query(Integration)
        
        # Apply filters
        if integration_type:
            query = query.filter(Integration.integration_type == integration_type)
        
        if provider:
            query = query.filter(Integration.provider.ilike(f"%{provider}%"))
        
        if status:
            query = query.filter(Integration.status == status)
        
        if is_enabled is not None:
            query = query.filter(Integration.is_enabled == is_enabled)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        integrations = query.order_by(
            Integration.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_integrations = []
        for integration in integrations:
            formatted_integrations.append(IntegrationResponse.from_orm(integration))
        
        return {
            "integrations": formatted_integrations,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting integrations: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/integrations/{integration_id}")
@traced("integration_api_get_integration")
async def get_integration(
    integration_id: UUID,
    db: Session = Depends(get_db)
):
    """Get a specific integration with details."""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Get recent connection logs
        connection_logs = db.query(IntegrationConnectionLog).filter(
            IntegrationConnectionLog.integration_id == integration_id
        ).order_by(IntegrationConnectionLog.attempt_at.desc()).limit(10).all()
        
        # Get recent sync logs
        sync_logs = db.query(IntegrationSyncLog).filter(
            IntegrationSyncLog.integration_id == integration_id
        ).order_by(IntegrationSyncLog.started_at.desc()).limit(10).all()
        
        # Get webhooks
        webhooks = db.query(IntegrationWebhook).filter(
            IntegrationWebhook.integration_id == integration_id
        ).all()
        
        # Format response
        response_data = IntegrationResponse.from_orm(integration).dict()
        response_data.update({
            "connection_logs": [ConnectionLogResponse.from_orm(log) for log in connection_logs],
            "sync_logs": [SyncLogResponse.from_orm(log) for log in sync_logs],
            "webhooks": [WebhookResponse.from_orm(webhook) for webhook in webhooks]
        })
        
        return response_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting integration {integration_id}: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/integrations")
@traced("integration_api_create_integration")
async def create_integration_endpoint(
    request: IntegrationCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    integration_manager = Depends(get_integration_manager)
):
    """Create a new integration."""
    try:
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        description = sanitize_input(request.description, max_length=1000) if request.description else None
        provider = sanitize_input(request.provider, max_length=100)
        created_by = sanitize_input(request.created_by, max_length=255)
        
        # Create integration
        integration = create_integration(
            name=name,
            integration_type=request.integration_type,
            provider=provider,
            config=request.config,
            credentials=request.credentials,  # Note: Should be encrypted in production
            created_by=created_by,
            description=description,
            version=request.version,
            capabilities=request.capabilities,
            settings=request.settings,
            is_enabled=request.is_enabled,
            is_bidirectional=request.is_bidirectional,
            priority=request.priority,
            health_check_interval=request.health_check_interval,
            status=IntegrationStatus.PENDING  # Will be updated after connection test
        )
        
        db.add(integration)
        db.commit()
        db.refresh(integration)
        
        # Trigger connection test in background
        background_tasks.add_task(
            _initialize_integration_background,
            integration.id,
            integration_manager
        )
        
        logger.info(f"Integration created: {integration.id}")
        metrics.integration_api_integrations_created.inc()
        
        return IntegrationResponse.from_orm(integration)
        
    except Exception as e:
        logger.error(f"Error creating integration: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/integrations/{integration_id}")
@traced("integration_api_update_integration")
async def update_integration(
    integration_id: UUID,
    request: IntegrationUpdate,
    db: Session = Depends(get_db)
):
    """Update an integration."""
    try:
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Sanitize inputs
        updated_by = sanitize_input(request.updated_by, max_length=255)
        
        # Update fields
        if request.name is not None:
            integration.name = sanitize_input(request.name, max_length=255)
        
        if request.description is not None:
            integration.description = sanitize_input(request.description, max_length=1000)
        
        if request.config is not None:
            integration.config = request.config
        
        if request.credentials is not None:
            integration.credentials = request.credentials  # Should be encrypted
        
        if request.settings is not None:
            integration.settings = request.settings
        
        if request.is_enabled is not None:
            integration.is_enabled = request.is_enabled
        
        if request.is_bidirectional is not None:
            integration.is_bidirectional = request.is_bidirectional
        
        if request.priority is not None:
            integration.priority = request.priority
        
        if request.health_check_interval is not None:
            integration.health_check_interval = request.health_check_interval
        
        # Update metadata
        integration.updated_by = updated_by
        integration.updated_at = datetime.utcnow()
        
        db.commit()
        
        # Publish update event
        # In production, this would use the event bus
        logger.info(f"Integration updated: {integration_id}")
        metrics.integration_api_integrations_updated.inc()
        
        return IntegrationResponse.from_orm(integration)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating integration: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/integrations/{integration_id}")
@traced("integration_api_delete_integration")
async def delete_integration(
    integration_id: UUID,
    user_id: str = Query(..., description="User ID performing the deletion"),
    db: Session = Depends(get_db)
):
    """Delete an integration."""
    try:
        # Sanitize input
        user_id = sanitize_input(user_id, max_length=255)
        
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Log deletion for audit
        logger.info(f"Deleting integration {integration_id} by user {user_id}")
        
        # Delete related records (cascading should handle this)
        db.delete(integration)
        db.commit()
        
        metrics.integration_api_integrations_deleted.inc()
        
        return {
            "message": "Integration deleted successfully",
            "integration_id": str(integration_id),
            "deleted_by": user_id,
            "deleted_at": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting integration: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/integrations/{integration_id}/test")
@traced("integration_api_test_integration")
async def test_integration(
    integration_id: UUID,
    integration_manager = Depends(get_integration_manager)
):
    """Test an integration connection."""
    try:
        result = await integration_manager.test_integration(integration_id)
        
        if result.get("success"):
            metrics.integration_api_tests_successful.inc()
        else:
            metrics.integration_api_tests_failed.inc()
        
        return result
        
    except Exception as e:
        logger.error(f"Error testing integration {integration_id}: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/integrations/test-connection")
@traced("integration_api_test_connection")
async def test_connection(
    request: TestConnectionRequest,
    integration_manager = Depends(get_integration_manager)
):
    """Test a connection without creating an integration."""
    try:
        # Create temporary integration object for testing
        temp_integration = Integration(
            name="temp-test",
            integration_type=request.integration_type,
            provider=request.provider,
            config=request.config,
            credentials=request.credentials,
            created_by="api_test"
        )
        
        # Get appropriate connector
        connector = integration_manager.connectors.get(request.integration_type)
        if not connector:
            return {
                "success": False,
                "error": f"No connector available for type: {request.integration_type}"
            }
        
        # Test connection
        result = await connector.test_connection(temp_integration)
        
        if result.get("success"):
            metrics.integration_api_connection_tests_successful.inc()
        else:
            metrics.integration_api_connection_tests_failed.inc()
        
        return result
        
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/integrations/{integration_id}/sync")
@traced("integration_api_trigger_sync")
async def trigger_sync(
    integration_id: UUID,
    request: SyncRequest,
    integration_manager = Depends(get_integration_manager)
):
    """Trigger data synchronization for an integration."""
    try:
        await integration_manager.request_sync(
            integration_id=integration_id,
            sync_type=request.sync_type,
            data=request.data
        )
        
        metrics.integration_api_syncs_triggered.inc()
        
        return {
            "message": "Synchronization triggered successfully",
            "integration_id": str(integration_id),
            "sync_type": request.sync_type,
            "triggered_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error triggering sync for integration {integration_id}: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/integrations/{integration_id}/logs/connections")
@traced("integration_api_get_connection_logs")
async def get_connection_logs(
    integration_id: UUID,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get connection logs for an integration."""
    try:
        # Verify integration exists
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Get connection logs
        query = db.query(IntegrationConnectionLog).filter(
            IntegrationConnectionLog.integration_id == integration_id
        )
        
        total = query.count()
        
        logs = query.order_by(
            IntegrationConnectionLog.attempt_at.desc()
        ).offset(offset).limit(limit).all()
        
        return {
            "logs": [ConnectionLogResponse.from_orm(log) for log in logs],
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting connection logs: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/integrations/{integration_id}/logs/sync")
@traced("integration_api_get_sync_logs")
async def get_sync_logs(
    integration_id: UUID,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get synchronization logs for an integration."""
    try:
        # Verify integration exists
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Get sync logs
        query = db.query(IntegrationSyncLog).filter(
            IntegrationSyncLog.integration_id == integration_id
        )
        
        total = query.count()
        
        logs = query.order_by(
            IntegrationSyncLog.started_at.desc()
        ).offset(offset).limit(limit).all()
        
        return {
            "logs": [SyncLogResponse.from_orm(log) for log in logs],
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting sync logs: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/integrations/{integration_id}/webhooks")
@traced("integration_api_create_webhook")
async def create_webhook_endpoint(
    integration_id: UUID,
    request: WebhookCreate,
    db: Session = Depends(get_db)
):
    """Create a webhook for an integration."""
    try:
        # Verify integration exists
        integration = db.query(Integration).filter(Integration.id == integration_id).first()
        if not integration:
            raise HTTPException(status_code=404, detail="Integration not found")
        
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        description = sanitize_input(request.description, max_length=1000) if request.description else None
        created_by = sanitize_input(request.created_by, max_length=255)
        
        # Create webhook
        webhook = create_webhook(
            integration_id=integration_id,
            name=name,
            webhook_url=request.webhook_url,
            events=request.events,
            created_by=created_by,
            description=description,
            secret_token=request.secret_token,
            headers=request.headers,
            payload_template=request.payload_template,
            timeout=request.timeout
        )
        
        db.add(webhook)
        db.commit()
        db.refresh(webhook)
        
        logger.info(f"Webhook created for integration {integration_id}: {webhook.id}")
        metrics.integration_api_webhooks_created.inc()
        
        return WebhookResponse.from_orm(webhook)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating webhook: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/templates")
@traced("integration_api_get_templates")
async def get_integration_templates(
    integration_type: Optional[IntegrationType] = None,
    provider: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get integration templates."""
    try:
        query = db.query(IntegrationTemplate)
        
        # Apply filters
        if integration_type:
            query = query.filter(IntegrationTemplate.integration_type == integration_type)
        
        if provider:
            query = query.filter(IntegrationTemplate.provider.ilike(f"%{provider}%"))
        
        if is_active is not None:
            query = query.filter(IntegrationTemplate.is_active == is_active)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        templates = query.order_by(
            IntegrationTemplate.usage_count.desc(),
            IntegrationTemplate.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_templates = []
        for template in templates:
            formatted_templates.append({
                "id": str(template.id),
                "name": template.name,
                "description": template.description,
                "integration_type": template.integration_type,
                "provider": template.provider,
                "version": template.version,
                "is_active": template.is_active,
                "is_community": template.is_community,
                "usage_count": template.usage_count,
                "required_fields": template.required_fields,
                "optional_fields": template.optional_fields,
                "capabilities": template.capabilities,
                "created_at": template.created_at.isoformat(),
                "created_by": template.created_by
            })
        
        return {
            "templates": formatted_templates,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting integration templates: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics")
@traced("integration_api_get_statistics")
async def get_integration_statistics(
    time_range: str = Query("24h", regex="^(1h|6h|24h|7d|30d)$"),
    db: Session = Depends(get_db),
    integration_manager = Depends(get_integration_manager)
):
    """Get integration statistics."""
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
        start_time = datetime.utcnow() - time_delta
        
        # Get database statistics
        total_integrations = db.query(Integration).count()
        active_integrations = db.query(Integration).filter(
            Integration.is_enabled == True,
            Integration.status == IntegrationStatus.ACTIVE
        ).count()
        
        recent_connections = db.query(IntegrationConnectionLog).filter(
            IntegrationConnectionLog.attempt_at >= start_time
        ).count()
        
        successful_connections = db.query(IntegrationConnectionLog).filter(
            IntegrationConnectionLog.attempt_at >= start_time,
            IntegrationConnectionLog.connection_status == ConnectionStatus.CONNECTED
        ).count()
        
        recent_syncs = db.query(IntegrationSyncLog).filter(
            IntegrationSyncLog.started_at >= start_time
        ).count()
        
        successful_syncs = db.query(IntegrationSyncLog).filter(
            IntegrationSyncLog.started_at >= start_time,
            IntegrationSyncLog.status == DataSyncStatus.SYNCHRONIZED
        ).count()
        
        # Get integrations by type
        type_stats = {}
        for integration_type in IntegrationType:
            count = db.query(Integration).filter(
                Integration.integration_type == integration_type
            ).count()
            type_stats[integration_type.value] = count
        
        # Get integrations by status
        status_stats = {}
        for status in IntegrationStatus:
            count = db.query(Integration).filter(
                Integration.status == status
            ).count()
            status_stats[status.value] = count
        
        # Get manager statistics
        manager_stats = integration_manager.get_stats()
        
        return {
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "total_integrations": total_integrations,
            "active_integrations": active_integrations,
            "recent_connections": recent_connections,
            "successful_connections": successful_connections,
            "connection_success_rate": (successful_connections / max(recent_connections, 1)) * 100,
            "recent_syncs": recent_syncs,
            "successful_syncs": successful_syncs,
            "sync_success_rate": (successful_syncs / max(recent_syncs, 1)) * 100,
            "type_breakdown": type_stats,
            "status_breakdown": status_stats,
            "manager_stats": manager_stats
        }
        
    except Exception as e:
        logger.error(f"Error getting integration statistics: {e}")
        metrics.integration_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


# Background task helper
async def _initialize_integration_background(integration_id: UUID, integration_manager):
    """Background task to initialize an integration."""
    try:
        # Trigger integration initialization
        # This would normally be handled by the integration manager
        # when it receives the integration.created event
        logger.info(f"Initializing integration in background: {integration_id}")
        
        # In a real implementation, this would publish an event
        # await event_bus.publish("integration.created", {"integration_id": str(integration_id)})
        
    except Exception as e:
        logger.error(f"Error in background integration initialization: {e}")