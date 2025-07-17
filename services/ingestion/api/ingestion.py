"""Ingestion API endpoints."""

import json
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
import structlog

from ..schemas import SBOMSchema, CVESchema, RuntimeBehaviorSchema
from ..services.event_bus import EventBusService
from ..services.validation import ValidationService
from ..services.metrics import MetricsService

router = APIRouter(prefix="/api/v1/ingestion", tags=["ingestion"])
logger = structlog.get_logger()

# Service instances - these will be initialized in main.py
event_bus: Optional[EventBusService] = None
validation_service: Optional[ValidationService] = None
metrics_service: Optional[MetricsService] = None


def get_event_bus() -> EventBusService:
    """Get event bus service instance."""
    if event_bus is None:
        raise HTTPException(status_code=500, detail="Event bus service not initialized")
    return event_bus


def get_validation_service() -> ValidationService:
    """Get validation service instance."""
    if validation_service is None:
        raise HTTPException(status_code=500, detail="Validation service not initialized")
    return validation_service


def get_metrics_service() -> MetricsService:
    """Get metrics service instance."""
    if metrics_service is None:
        raise HTTPException(status_code=500, detail="Metrics service not initialized")
    return metrics_service


async def process_ingestion_async(
    data: Dict[str, Any],
    data_type: str,
    ingestion_id: str,
    source_system: Optional[str],
    eb_service: EventBusService,
    val_service: ValidationService,
    met_service: MetricsService,
):
    """Process ingestion asynchronously."""
    try:
        # Validate data
        start_time = time.time()
        validation_result = await val_service.validate_data_type(data, data_type)
        validation_duration = time.time() - start_time
        
        met_service.record_validation_duration(data_type, validation_duration)
        
        if validation_result.is_valid:
            met_service.record_validation_result(data_type, "valid")
            
            # Publish event
            event_start_time = time.time()
            
            if data_type == "sbom":
                success = await eb_service.publish_sbom_ingested(
                    validation_result.data, ingestion_id, source_system
                )
            elif data_type == "cve":
                success = await eb_service.publish_cve_ingested(
                    validation_result.data, ingestion_id, source_system
                )
            elif data_type == "runtime":
                success = await eb_service.publish_runtime_ingested(
                    validation_result.data, ingestion_id, source_system
                )
            else:
                success = False
            
            event_duration = time.time() - event_start_time
            met_service.record_event_publishing_duration(f"{data_type}.ingested", event_duration)
            
            if success:
                met_service.record_event_publication(f"{data_type}.ingested", "success")
                logger.info(
                    "Data ingestion completed successfully",
                    data_type=data_type,
                    ingestion_id=ingestion_id,
                    source_system=source_system,
                )
            else:
                met_service.record_event_publication(f"{data_type}.ingested", "failed")
                await eb_service.publish_ingestion_error(
                    "event_publication_failed",
                    f"Failed to publish {data_type} ingested event",
                    ingestion_id,
                    {"data_type": data_type, "source_system": source_system},
                )
        else:
            met_service.record_validation_result(data_type, "invalid")
            
            # Publish validation failed event
            await eb_service.publish_validation_failed(
                data_type, validation_result.errors, ingestion_id, data
            )
            
            logger.warning(
                "Data validation failed during async processing",
                data_type=data_type,
                ingestion_id=ingestion_id,
                error_count=len(validation_result.errors),
            )
    
    except Exception as e:
        met_service.record_error("async_processing", "ingestion")
        await eb_service.publish_ingestion_error(
            "async_processing_error",
            str(e),
            ingestion_id,
            {"data_type": data_type, "source_system": source_system},
        )
        
        logger.error(
            "Error during async ingestion processing",
            data_type=data_type,
            ingestion_id=ingestion_id,
            error=str(e),
        )


@router.post("/sbom")
async def ingest_sbom(
    request: Request,
    background_tasks: BackgroundTasks,
    source_system: Optional[str] = None,
    async_processing: bool = False,
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Ingest SBOM data."""
    ingestion_id = str(uuid4())
    start_time = time.time()
    
    try:
        # Get request body
        body = await request.body()
        data_size = len(body)
        met_service.record_data_size("sbom", data_size)
        
        # Parse JSON
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            met_service.record_error("json_parsing", "sbom")
            met_service.record_ingestion_request("sbom", "failed")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON: {str(e)}"
            )
        
        # Add ingestion metadata
        data["ingestion_id"] = ingestion_id
        data["source_system"] = source_system
        
        if async_processing:
            # Process asynchronously
            background_tasks.add_task(
                process_ingestion_async,
                data, "sbom", ingestion_id, source_system,
                eb_service, val_service, met_service
            )
            
            met_service.record_ingestion_request("sbom", "accepted")
            
            duration = time.time() - start_time
            met_service.record_request_duration("sbom", "ingest", duration)
            
            return JSONResponse(
                status_code=202,
                content={
                    "message": "SBOM data accepted for processing",
                    "ingestion_id": ingestion_id,
                    "processing_mode": "async",
                }
            )
        else:
            # Process synchronously
            validation_result = await val_service.validate_sbom(data)
            
            if not validation_result.is_valid:
                met_service.record_validation_result("sbom", "invalid")
                met_service.record_ingestion_request("sbom", "failed")
                
                # Publish validation failed event
                await eb_service.publish_validation_failed(
                    "sbom", validation_result.errors, ingestion_id, data
                )
                
                duration = time.time() - start_time
                met_service.record_request_duration("sbom", "ingest", duration)
                
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "SBOM validation failed",
                        "ingestion_id": ingestion_id,
                        "errors": validation_result.errors,
                    }
                )
            
            met_service.record_validation_result("sbom", "valid")
            
            # Publish event
            success = await eb_service.publish_sbom_ingested(
                validation_result.data, ingestion_id, source_system
            )
            
            if success:
                met_service.record_event_publication("sbom.ingested", "success")
                met_service.record_ingestion_request("sbom", "success")
                
                duration = time.time() - start_time
                met_service.record_request_duration("sbom", "ingest", duration)
                
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "SBOM data ingested successfully",
                        "ingestion_id": ingestion_id,
                        "processing_mode": "sync",
                        "components_count": len(validation_result.data.get("components", [])),
                        "vulnerabilities_count": len(validation_result.data.get("vulnerabilities", [])),
                    }
                )
            else:
                met_service.record_event_publication("sbom.ingested", "failed")
                met_service.record_ingestion_request("sbom", "failed")
                
                duration = time.time() - start_time
                met_service.record_request_duration("sbom", "ingest", duration)
                
                raise HTTPException(
                    status_code=500,
                    detail={
                        "message": "Failed to publish SBOM event",
                        "ingestion_id": ingestion_id,
                    }
                )
    
    except HTTPException:
        raise
    except Exception as e:
        met_service.record_error("unexpected", "sbom")
        met_service.record_ingestion_request("sbom", "error")
        
        duration = time.time() - start_time
        met_service.record_request_duration("sbom", "ingest", duration)
        
        await eb_service.publish_ingestion_error(
            "unexpected_error", str(e), ingestion_id, {"data_type": "sbom"}
        )
        
        logger.error(
            "Unexpected error during SBOM ingestion",
            ingestion_id=ingestion_id,
            error=str(e),
        )
        
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unexpected error during SBOM ingestion",
                "ingestion_id": ingestion_id,
            }
        )


@router.post("/cve")
async def ingest_cve(
    request: Request,
    background_tasks: BackgroundTasks,
    source_system: Optional[str] = None,
    async_processing: bool = False,
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Ingest CVE data."""
    ingestion_id = str(uuid4())
    start_time = time.time()
    
    try:
        # Get request body
        body = await request.body()
        data_size = len(body)
        met_service.record_data_size("cve", data_size)
        
        # Parse JSON
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            met_service.record_error("json_parsing", "cve")
            met_service.record_ingestion_request("cve", "failed")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON: {str(e)}"
            )
        
        # Add ingestion metadata
        data["ingestion_id"] = ingestion_id
        data["source_system"] = source_system
        
        if async_processing:
            # Process asynchronously
            background_tasks.add_task(
                process_ingestion_async,
                data, "cve", ingestion_id, source_system,
                eb_service, val_service, met_service
            )
            
            met_service.record_ingestion_request("cve", "accepted")
            
            duration = time.time() - start_time
            met_service.record_request_duration("cve", "ingest", duration)
            
            return JSONResponse(
                status_code=202,
                content={
                    "message": "CVE data accepted for processing",
                    "ingestion_id": ingestion_id,
                    "processing_mode": "async",
                }
            )
        else:
            # Process synchronously
            validation_result = await val_service.validate_cve(data)
            
            if not validation_result.is_valid:
                met_service.record_validation_result("cve", "invalid")
                met_service.record_ingestion_request("cve", "failed")
                
                # Publish validation failed event
                await eb_service.publish_validation_failed(
                    "cve", validation_result.errors, ingestion_id, data
                )
                
                duration = time.time() - start_time
                met_service.record_request_duration("cve", "ingest", duration)
                
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "CVE validation failed",
                        "ingestion_id": ingestion_id,
                        "errors": validation_result.errors,
                    }
                )
            
            met_service.record_validation_result("cve", "valid")
            
            # Publish event
            success = await eb_service.publish_cve_ingested(
                validation_result.data, ingestion_id, source_system
            )
            
            if success:
                met_service.record_event_publication("cve.ingested", "success")
                met_service.record_ingestion_request("cve", "success")
                
                duration = time.time() - start_time
                met_service.record_request_duration("cve", "ingest", duration)
                
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "CVE data ingested successfully",
                        "ingestion_id": ingestion_id,
                        "processing_mode": "sync",
                        "cve_id": validation_result.data.get("cve_id"),
                        "severity": validation_result.data.get("metrics", {}).get("cvss_v3", {}).get("baseSeverity"),
                    }
                )
            else:
                met_service.record_event_publication("cve.ingested", "failed")
                met_service.record_ingestion_request("cve", "failed")
                
                duration = time.time() - start_time
                met_service.record_request_duration("cve", "ingest", duration)
                
                raise HTTPException(
                    status_code=500,
                    detail={
                        "message": "Failed to publish CVE event",
                        "ingestion_id": ingestion_id,
                    }
                )
    
    except HTTPException:
        raise
    except Exception as e:
        met_service.record_error("unexpected", "cve")
        met_service.record_ingestion_request("cve", "error")
        
        duration = time.time() - start_time
        met_service.record_request_duration("cve", "ingest", duration)
        
        await eb_service.publish_ingestion_error(
            "unexpected_error", str(e), ingestion_id, {"data_type": "cve"}
        )
        
        logger.error(
            "Unexpected error during CVE ingestion",
            ingestion_id=ingestion_id,
            error=str(e),
        )
        
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unexpected error during CVE ingestion",
                "ingestion_id": ingestion_id,
            }
        )


@router.post("/runtime")
async def ingest_runtime(
    request: Request,
    background_tasks: BackgroundTasks,
    source_system: Optional[str] = None,
    async_processing: bool = False,
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Ingest runtime behavior data."""
    ingestion_id = str(uuid4())
    start_time = time.time()
    
    try:
        # Get request body
        body = await request.body()
        data_size = len(body)
        met_service.record_data_size("runtime", data_size)
        
        # Parse JSON
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            met_service.record_error("json_parsing", "runtime")
            met_service.record_ingestion_request("runtime", "failed")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON: {str(e)}"
            )
        
        # Add ingestion metadata
        data["ingestion_id"] = ingestion_id
        data["source_system"] = source_system
        
        if async_processing:
            # Process asynchronously
            background_tasks.add_task(
                process_ingestion_async,
                data, "runtime", ingestion_id, source_system,
                eb_service, val_service, met_service
            )
            
            met_service.record_ingestion_request("runtime", "accepted")
            
            duration = time.time() - start_time
            met_service.record_request_duration("runtime", "ingest", duration)
            
            return JSONResponse(
                status_code=202,
                content={
                    "message": "Runtime data accepted for processing",
                    "ingestion_id": ingestion_id,
                    "processing_mode": "async",
                }
            )
        else:
            # Process synchronously
            validation_result = await val_service.validate_runtime(data)
            
            if not validation_result.is_valid:
                met_service.record_validation_result("runtime", "invalid")
                met_service.record_ingestion_request("runtime", "failed")
                
                # Publish validation failed event
                await eb_service.publish_validation_failed(
                    "runtime", validation_result.errors, ingestion_id, data
                )
                
                duration = time.time() - start_time
                met_service.record_request_duration("runtime", "ingest", duration)
                
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": "Runtime data validation failed",
                        "ingestion_id": ingestion_id,
                        "errors": validation_result.errors,
                    }
                )
            
            met_service.record_validation_result("runtime", "valid")
            
            # Publish event
            success = await eb_service.publish_runtime_ingested(
                validation_result.data, ingestion_id, source_system
            )
            
            if success:
                met_service.record_event_publication("runtime.ingested", "success")
                met_service.record_ingestion_request("runtime", "success")
                
                duration = time.time() - start_time
                met_service.record_request_duration("runtime", "ingest", duration)
                
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "Runtime data ingested successfully",
                        "ingestion_id": ingestion_id,
                        "processing_mode": "sync",
                        "session_id": validation_result.data.get("session_id"),
                        "host_name": validation_result.data.get("host_name"),
                        "events_count": len(validation_result.data.get("events", [])),
                    }
                )
            else:
                met_service.record_event_publication("runtime.ingested", "failed")
                met_service.record_ingestion_request("runtime", "failed")
                
                duration = time.time() - start_time
                met_service.record_request_duration("runtime", "ingest", duration)
                
                raise HTTPException(
                    status_code=500,
                    detail={
                        "message": "Failed to publish runtime event",
                        "ingestion_id": ingestion_id,
                    }
                )
    
    except HTTPException:
        raise
    except Exception as e:
        met_service.record_error("unexpected", "runtime")
        met_service.record_ingestion_request("runtime", "error")
        
        duration = time.time() - start_time
        met_service.record_request_duration("runtime", "ingest", duration)
        
        await eb_service.publish_ingestion_error(
            "unexpected_error", str(e), ingestion_id, {"data_type": "runtime"}
        )
        
        logger.error(
            "Unexpected error during runtime ingestion",
            ingestion_id=ingestion_id,
            error=str(e),
        )
        
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Unexpected error during runtime ingestion",
                "ingestion_id": ingestion_id,
            }
        )


@router.post("/batch")
async def ingest_batch(
    request: Request,
    background_tasks: BackgroundTasks,
    data_type: str,
    source_system: Optional[str] = None,
    async_processing: bool = True,
    stop_on_first_error: bool = False,
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Ingest batch data."""
    ingestion_id = str(uuid4())
    start_time = time.time()
    
    try:
        # Get request body
        body = await request.body()
        data_size = len(body)
        met_service.record_data_size(f"{data_type}_batch", data_size)
        
        # Parse JSON
        try:
            batch_data = json.loads(body)
        except json.JSONDecodeError as e:
            met_service.record_error("json_parsing", f"{data_type}_batch")
            met_service.record_ingestion_request(f"{data_type}_batch", "failed")
            raise HTTPException(
                status_code=400,
                detail=f"Invalid JSON: {str(e)}"
            )
        
        if not isinstance(batch_data, list):
            met_service.record_error("invalid_format", f"{data_type}_batch")
            met_service.record_ingestion_request(f"{data_type}_batch", "failed")
            raise HTTPException(
                status_code=400,
                detail="Batch data must be a JSON array"
            )
        
        if not batch_data:
            met_service.record_error("empty_batch", f"{data_type}_batch")
            met_service.record_ingestion_request(f"{data_type}_batch", "failed")
            raise HTTPException(
                status_code=400,
                detail="Batch cannot be empty"
            )
        
        # Add ingestion metadata to each item
        for item in batch_data:
            item["ingestion_id"] = f"{ingestion_id}_{batch_data.index(item)}"
            item["source_system"] = source_system
        
        if async_processing:
            # Process batch asynchronously
            for item in batch_data:
                background_tasks.add_task(
                    process_ingestion_async,
                    item, data_type, item["ingestion_id"], source_system,
                    eb_service, val_service, met_service
                )
            
            met_service.record_ingestion_request(f"{data_type}_batch", "accepted")
            
            duration = time.time() - start_time
            met_service.record_request_duration(f"{data_type}_batch", "ingest", duration)
            
            return JSONResponse(
                status_code=202,
                content={
                    "message": f"Batch {data_type} data accepted for processing",
                    "ingestion_id": ingestion_id,
                    "batch_size": len(batch_data),
                    "processing_mode": "async",
                }
            )
        else:
            # Process batch synchronously
            validation_results = await val_service.validate_batch(
                batch_data, data_type, stop_on_first_error
            )
            
            if validation_results["invalid"] > 0:
                met_service.record_validation_result(f"{data_type}_batch", "invalid")
                met_service.record_ingestion_request(f"{data_type}_batch", "failed")
                
                duration = time.time() - start_time
                met_service.record_request_duration(f"{data_type}_batch", "ingest", duration)
                
                raise HTTPException(
                    status_code=400,
                    detail={
                        "message": f"Batch {data_type} validation failed",
                        "ingestion_id": ingestion_id,
                        "validation_results": validation_results,
                    }
                )
            
            met_service.record_validation_result(f"{data_type}_batch", "valid")
            
            # Publish events for valid items
            success_count = 0
            for result in validation_results["results"]:
                if result["is_valid"]:
                    if data_type == "sbom":
                        success = await eb_service.publish_sbom_ingested(
                            result["data"], result["data"]["ingestion_id"], source_system
                        )
                    elif data_type == "cve":
                        success = await eb_service.publish_cve_ingested(
                            result["data"], result["data"]["ingestion_id"], source_system
                        )
                    elif data_type == "runtime":
                        success = await eb_service.publish_runtime_ingested(
                            result["data"], result["data"]["ingestion_id"], source_system
                        )
                    else:
                        success = False
                    
                    if success:
                        success_count += 1
            
            met_service.record_event_publication(f"{data_type}_batch.ingested", "success")
            met_service.record_ingestion_request(f"{data_type}_batch", "success")
            
            duration = time.time() - start_time
            met_service.record_request_duration(f"{data_type}_batch", "ingest", duration)
            
            return JSONResponse(
                status_code=200,
                content={
                    "message": f"Batch {data_type} data ingested successfully",
                    "ingestion_id": ingestion_id,
                    "batch_size": len(batch_data),
                    "processing_mode": "sync",
                    "success_count": success_count,
                    "validation_results": validation_results,
                }
            )
    
    except HTTPException:
        raise
    except Exception as e:
        met_service.record_error("unexpected", f"{data_type}_batch")
        met_service.record_ingestion_request(f"{data_type}_batch", "error")
        
        duration = time.time() - start_time
        met_service.record_request_duration(f"{data_type}_batch", "ingest", duration)
        
        await eb_service.publish_ingestion_error(
            "unexpected_error", str(e), ingestion_id, {"data_type": f"{data_type}_batch"}
        )
        
        logger.error(
            "Unexpected error during batch ingestion",
            ingestion_id=ingestion_id,
            data_type=data_type,
            error=str(e),
        )
        
        raise HTTPException(
            status_code=500,
            detail={
                "message": f"Unexpected error during batch {data_type} ingestion",
                "ingestion_id": ingestion_id,
            }
        )


@router.get("/schemas")
async def get_schemas(
    val_service: ValidationService = Depends(get_validation_service),
):
    """Get supported data schemas."""
    return JSONResponse(
        status_code=200,
        content={
            "message": "Supported data schemas",
            "schemas": val_service.get_all_schema_info(),
        }
    )


@router.get("/schemas/{data_type}")
async def get_schema(
    data_type: str,
    val_service: ValidationService = Depends(get_validation_service),
):
    """Get schema for a specific data type."""
    schema_info = val_service.get_schema_info(data_type)
    
    if not schema_info:
        raise HTTPException(
            status_code=404,
            detail=f"Schema not found for data type: {data_type}"
        )
    
    return JSONResponse(
        status_code=200,
        content={
            "message": f"Schema for {data_type}",
            "schema": schema_info,
        }
    )