"""
SBOM API - REST endpoints for SBOM document operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, File, UploadFile, BackgroundTasks
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.sbom import (
    SBOMDocument, SBOMFormat, SBOMStatus, ComponentType,
    SBOMQuery, SBOMStats, ComponentQuery, create_sbom_document
)
from ..services.sbom_repository import SBOMRepository
from ..services.sbom_processor import SBOMProcessor

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
sbom_repository = None
sbom_processor = None


class CreateSBOMRequest(BaseModel):
    """Request model for creating SBOM documents."""
    name: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=50)
    format: SBOMFormat = Field(...)
    spec_version: str = Field(..., min_length=1, max_length=20)
    source: str = Field(..., min_length=1, max_length=255)
    source_reference: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    data_license: Optional[str] = Field(None, max_length=100)
    document_namespace: Optional[str] = Field(None, max_length=500)
    category: Optional[str] = Field(None, max_length=100)
    environment: Optional[str] = Field(None, max_length=50)
    tags: Optional[List[str]] = Field(default_factory=list)


class UpdateSBOMRequest(BaseModel):
    """Request model for updating SBOM documents."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    version: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=1000)
    category: Optional[str] = Field(None, max_length=100)
    environment: Optional[str] = Field(None, max_length=50)
    tags: Optional[List[str]] = None
    updated_by: str = Field(..., min_length=1, max_length=255)


class SBOMSearchRequest(BaseModel):
    """Request model for SBOM search."""
    name: Optional[str] = None
    version: Optional[str] = None
    format: Optional[SBOMFormat] = None
    status: Optional[SBOMStatus] = None
    created_by: Optional[str] = None
    source: Optional[str] = None
    has_vulnerabilities: Optional[bool] = None
    severity_threshold: Optional[str] = None
    component_name: Optional[str] = None
    tag: Optional[str] = None
    category: Optional[str] = None
    environment: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)
    sort_by: str = Field("created_at", max_length=50)
    sort_order: str = Field("desc", regex="^(asc|desc)$")


class ComponentSearchRequest(BaseModel):
    """Request model for component search."""
    name: Optional[str] = None
    version: Optional[str] = None
    type: Optional[ComponentType] = None
    supplier: Optional[str] = None
    has_vulnerabilities: Optional[bool] = None
    license_name: Optional[str] = None
    purl: Optional[str] = None
    limit: int = Field(100, ge=1, le=1000)
    offset: int = Field(0, ge=0)
    sort_by: str = Field("name", max_length=50)
    sort_order: str = Field("asc", regex="^(asc|desc)$")


def get_sbom_repository() -> SBOMRepository:
    """Get SBOM repository instance."""
    global sbom_repository
    if sbom_repository is None:
        raise RuntimeError("SBOM repository not initialized")
    return sbom_repository


def get_sbom_processor() -> SBOMProcessor:
    """Get SBOM processor instance."""
    global sbom_processor
    if sbom_processor is None:
        raise RuntimeError("SBOM processor not initialized")
    return sbom_processor


@router.post("/sboms", response_model=Dict[str, Any])
@traced("sbom_api_create_sbom")
async def create_sbom(
    request: CreateSBOMRequest,
    background_tasks: BackgroundTasks,
    repository: SBOMRepository = Depends(get_sbom_repository),
    processor: SBOMProcessor = Depends(get_sbom_processor)
):
    """Create a new SBOM document with content."""
    try:
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        version = sanitize_input(request.version, max_length=50)
        source = sanitize_input(request.source, max_length=255)
        
        # Create SBOM document
        sbom = create_sbom_document(
            name=name,
            version=version,
            format=request.format,
            spec_version=request.spec_version,
            raw_content="",  # Content will be uploaded separately
            created_by="api_user",  # In real implementation, get from JWT
            source=source,
            source_reference=request.source_reference,
            description=request.description,
            data_license=request.data_license,
            document_namespace=request.document_namespace,
            category=request.category,
            environment=request.environment,
            tags=request.tags or []
        )
        
        # Store in repository
        created_sbom = await repository.create_sbom(sbom)
        
        logger.info(f"SBOM document created: {created_sbom.id}")
        metrics.sbom_api_documents_created.inc()
        
        return {
            "id": created_sbom.id,
            "name": created_sbom.name,
            "version": created_sbom.version,
            "format": created_sbom.format,
            "status": created_sbom.status,
            "created_at": created_sbom.created_at.isoformat(),
            "created_by": created_sbom.created_by,
            "message": "SBOM document created successfully"
        }
        
    except Exception as e:
        logger.error(f"Error creating SBOM document: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/sboms/{sbom_id}/upload", response_model=Dict[str, Any])
@traced("sbom_api_upload_content")
async def upload_sbom_content(
    sbom_id: str,
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks,
    repository: SBOMRepository = Depends(get_sbom_repository),
    processor: SBOMProcessor = Depends(get_sbom_processor)
):
    """Upload SBOM content and trigger processing."""
    try:
        # Get SBOM document
        sbom = await repository.get_sbom(sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM document not found")
        
        # Read file content
        content = await file.read()
        raw_content = content.decode('utf-8')
        
        # Update SBOM with content
        updated_sbom = await repository.update_sbom(sbom_id, {
            "raw_content": raw_content,
            "file_size": len(content),
            "status": SBOMStatus.PENDING
        })
        
        # Queue processing
        background_tasks.add_task(processor.process_sbom, updated_sbom)
        
        logger.info(f"SBOM content uploaded and queued for processing: {sbom_id}")
        metrics.sbom_api_content_uploaded.inc()
        
        return {
            "sbom_id": sbom_id,
            "file_size": len(content),
            "status": SBOMStatus.PENDING,
            "message": "SBOM content uploaded and queued for processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading SBOM content: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sboms/{sbom_id}", response_model=Dict[str, Any])
@traced("sbom_api_get_sbom")
async def get_sbom(
    sbom_id: str,
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Get SBOM document by ID."""
    try:
        sbom = await repository.get_sbom(sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM document not found")
        
        return {
            "id": sbom.id,
            "name": sbom.name,
            "version": sbom.version,
            "format": sbom.format,
            "spec_version": sbom.spec_version,
            "status": sbom.status,
            "description": sbom.description,
            "source": sbom.source,
            "source_reference": sbom.source_reference,
            "total_components": sbom.total_components,
            "vulnerable_components": sbom.vulnerable_components,
            "high_severity_vulnerabilities": sbom.high_severity_vulnerabilities,
            "medium_severity_vulnerabilities": sbom.medium_severity_vulnerabilities,
            "low_severity_vulnerabilities": sbom.low_severity_vulnerabilities,
            "license_risks": sbom.license_risks,
            "category": sbom.category,
            "environment": sbom.environment,
            "tags": sbom.tags,
            "created_at": sbom.created_at.isoformat(),
            "updated_at": sbom.updated_at.isoformat(),
            "created_by": sbom.created_by,
            "processing_started_at": sbom.processing_started_at.isoformat() if sbom.processing_started_at else None,
            "processing_completed_at": sbom.processing_completed_at.isoformat() if sbom.processing_completed_at else None,
            "processing_duration": sbom.processing_duration,
            "error_message": sbom.error_message,
            "file_size": sbom.file_size,
            "file_hash": sbom.file_hash
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving SBOM document: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/sboms/search", response_model=Dict[str, Any])
@traced("sbom_api_search_sboms")
async def search_sboms(
    request: SBOMSearchRequest,
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Search SBOM documents with filtering and pagination."""
    try:
        # Create query object
        query = SBOMQuery(
            name=request.name,
            version=request.version,
            format=request.format,
            status=request.status,
            created_by=request.created_by,
            source=request.source,
            has_vulnerabilities=request.has_vulnerabilities,
            severity_threshold=request.severity_threshold,
            component_name=request.component_name,
            tag=request.tag,
            category=request.category,
            environment=request.environment,
            date_from=request.date_from,
            date_to=request.date_to,
            limit=request.limit,
            offset=request.offset,
            sort_by=request.sort_by,
            sort_order=request.sort_order
        )
        
        # Execute search
        sboms, total_count = await repository.search_sboms(query)
        
        # Format results
        formatted_sboms = []
        for sbom in sboms:
            formatted_sboms.append({
                "id": sbom.id,
                "name": sbom.name,
                "version": sbom.version,
                "format": sbom.format,
                "status": sbom.status,
                "source": sbom.source,
                "total_components": sbom.total_components,
                "vulnerable_components": sbom.vulnerable_components,
                "high_severity_vulnerabilities": sbom.high_severity_vulnerabilities,
                "category": sbom.category,
                "environment": sbom.environment,
                "tags": sbom.tags,
                "created_at": sbom.created_at.isoformat(),
                "created_by": sbom.created_by
            })
        
        return {
            "sboms": formatted_sboms,
            "total": total_count,
            "limit": request.limit,
            "offset": request.offset,
            "query": request.dict()
        }
        
    except Exception as e:
        logger.error(f"Error searching SBOM documents: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sboms/{sbom_id}/components", response_model=Dict[str, Any])
@traced("sbom_api_get_components")
async def get_sbom_components(
    sbom_id: str,
    name: Optional[str] = None,
    version: Optional[str] = None,
    component_type: Optional[ComponentType] = None,
    has_vulnerabilities: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Get components from SBOM with filtering."""
    try:
        # Create component query
        query = ComponentQuery(
            name=name,
            version=version,
            type=component_type,
            has_vulnerabilities=has_vulnerabilities,
            limit=limit,
            offset=offset
        )
        
        # Get components
        components, total_count = await repository.get_components(sbom_id, query)
        
        # Format results
        formatted_components = []
        for component in components:
            formatted_components.append({
                "id": component.id,
                "name": component.name,
                "version": component.version,
                "type": component.type,
                "supplier": component.supplier,
                "description": component.description,
                "package_url": component.package_url,
                "licenses": [{"name": lic.name, "id": lic.id} for lic in component.licenses],
                "vulnerabilities": [{"id": vuln.id, "severity": vuln.severity} for vuln in component.vulnerabilities],
                "created_at": component.created_at.isoformat()
            })
        
        return {
            "components": formatted_components,
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "sbom_id": sbom_id
        }
        
    except Exception as e:
        logger.error(f"Error getting components for SBOM {sbom_id}: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sboms/{sbom_id}/vulnerabilities", response_model=Dict[str, Any])
@traced("sbom_api_get_vulnerabilities")
async def get_sbom_vulnerabilities(
    sbom_id: str,
    severity: Optional[str] = None,
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Get vulnerabilities from SBOM components."""
    try:
        vulnerabilities = await repository.get_vulnerabilities(sbom_id, severity)
        
        # Format results
        formatted_vulnerabilities = []
        for vuln in vulnerabilities:
            formatted_vulnerabilities.append({
                "id": vuln.id,
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "score": vuln.score,
                "description": vuln.description,
                "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
                "references": vuln.references,
                "affected_versions": vuln.affected_versions,
                "fixed_versions": vuln.fixed_versions
            })
        
        return {
            "vulnerabilities": formatted_vulnerabilities,
            "total": len(formatted_vulnerabilities),
            "sbom_id": sbom_id,
            "severity_filter": severity
        }
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities for SBOM {sbom_id}: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/sboms/{sbom_id}/licenses", response_model=Dict[str, Any])
@traced("sbom_api_get_licenses")
async def get_sbom_licenses(
    sbom_id: str,
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Get licenses from SBOM components."""
    try:
        licenses = await repository.get_licenses(sbom_id)
        
        # Format results
        formatted_licenses = []
        for license in licenses:
            formatted_licenses.append({
                "id": license.id,
                "name": license.name,
                "url": license.url,
                "is_osi_approved": license.is_osi_approved,
                "is_deprecated": license.is_deprecated
            })
        
        return {
            "licenses": formatted_licenses,
            "total": len(formatted_licenses),
            "sbom_id": sbom_id
        }
        
    except Exception as e:
        logger.error(f"Error getting licenses for SBOM {sbom_id}: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/sboms/{sbom_id}", response_model=Dict[str, Any])
@traced("sbom_api_update_sbom")
async def update_sbom(
    sbom_id: str,
    request: UpdateSBOMRequest,
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Update SBOM document."""
    try:
        # Sanitize inputs
        updated_by = sanitize_input(request.updated_by, max_length=255)
        
        # Build updates
        updates = {"updated_by": updated_by}
        
        if request.name is not None:
            updates["name"] = sanitize_input(request.name, max_length=255)
        
        if request.version is not None:
            updates["version"] = sanitize_input(request.version, max_length=50)
        
        if request.description is not None:
            updates["description"] = sanitize_input(request.description, max_length=1000)
        
        if request.category is not None:
            updates["category"] = request.category
        
        if request.environment is not None:
            updates["environment"] = request.environment
        
        if request.tags is not None:
            updates["tags"] = request.tags
        
        # Update SBOM
        updated_sbom = await repository.update_sbom(sbom_id, updates)
        
        if not updated_sbom:
            raise HTTPException(status_code=404, detail="SBOM document not found")
        
        logger.info(f"SBOM document updated: {sbom_id}")
        metrics.sbom_api_documents_updated.inc()
        
        return {
            "id": updated_sbom.id,
            "name": updated_sbom.name,
            "version": updated_sbom.version,
            "updated_at": updated_sbom.updated_at.isoformat(),
            "updated_by": updated_sbom.updated_by
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating SBOM document: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/sboms/{sbom_id}", response_model=Dict[str, Any])
@traced("sbom_api_delete_sbom")
async def delete_sbom(
    sbom_id: str,
    user_id: str = Query(..., description="User ID performing the deletion"),
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Delete SBOM document."""
    try:
        # Sanitize input
        user_id = sanitize_input(user_id, max_length=255)
        
        # Delete SBOM
        deleted = await repository.delete_sbom(sbom_id)
        
        if not deleted:
            raise HTTPException(status_code=404, detail="SBOM document not found")
        
        logger.info(f"SBOM document deleted: {sbom_id} by {user_id}")
        metrics.sbom_api_documents_deleted.inc()
        
        return {
            "message": "SBOM document deleted successfully",
            "sbom_id": sbom_id,
            "deleted_by": user_id,
            "deleted_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting SBOM document: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("sbom_api_get_statistics")
async def get_statistics(
    time_range: str = Query("24h", regex="^(1h|6h|24h|7d|30d)$"),
    repository: SBOMRepository = Depends(get_sbom_repository)
):
    """Get SBOM statistics."""
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
        end_time = datetime.now()
        
        # Get statistics
        stats = await repository.get_statistics((start_time, end_time))
        
        return {
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "total_sboms": stats.total_sboms,
            "total_components": stats.total_components,
            "total_vulnerabilities": stats.total_vulnerabilities,
            "vulnerabilities_by_severity": stats.vulnerabilities_by_severity,
            "sboms_by_status": stats.sboms_by_status,
            "sboms_by_format": stats.sboms_by_format,
            "sboms_by_environment": stats.sboms_by_environment,
            "top_vulnerable_components": stats.top_vulnerable_components,
            "license_distribution": stats.license_distribution
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/sboms/{sbom_id}/reprocess", response_model=Dict[str, Any])
@traced("sbom_api_reprocess_sbom")
async def reprocess_sbom(
    sbom_id: str,
    background_tasks: BackgroundTasks,
    repository: SBOMRepository = Depends(get_sbom_repository),
    processor: SBOMProcessor = Depends(get_sbom_processor)
):
    """Reprocess SBOM document."""
    try:
        # Get SBOM document
        sbom = await repository.get_sbom(sbom_id)
        if not sbom:
            raise HTTPException(status_code=404, detail="SBOM document not found")
        
        # Reset processing status
        await repository.update_processing_status(sbom_id, SBOMStatus.PENDING)
        
        # Queue reprocessing
        background_tasks.add_task(processor.process_sbom, sbom)
        
        logger.info(f"SBOM document queued for reprocessing: {sbom_id}")
        metrics.sbom_api_documents_reprocessed.inc()
        
        return {
            "sbom_id": sbom_id,
            "status": SBOMStatus.PENDING,
            "message": "SBOM document queued for reprocessing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reprocessing SBOM document: {e}")
        metrics.sbom_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")