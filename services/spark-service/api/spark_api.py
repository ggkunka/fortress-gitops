"""
Spark API - REST endpoints for big data processing operations

This service provides comprehensive big data processing capabilities using Apache Spark
for large-scale security analytics, machine learning, and batch processing.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID
import json

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks, UploadFile, File
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse, StreamingResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.spark import (
    SparkJob, SparkApplication, DataSource, DataTransformation, MLModel,
    JobType, JobStatus, DataFormat, MLAlgorithm,
    create_spark_job, create_data_source
)
from ..services.spark_manager import SparkManager
from ..services.job_scheduler import JobScheduler
from ..services.ml_pipeline import MLPipelineManager

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
spark_manager = None
job_scheduler = None
ml_pipeline_manager = None


class CreateJobRequest(BaseModel):
    """Request model for creating Spark jobs."""
    job_name: str = Field(..., min_length=1, max_length=255)
    job_type: JobType = Field(...)
    description: Optional[str] = Field(None, max_length=500)
    
    # Job configuration
    main_class: Optional[str] = Field(None, max_length=255)
    application_file: Optional[str] = Field(None, max_length=500)
    arguments: Optional[List[str]] = Field(default_factory=list)
    
    # Spark configuration
    driver_memory: str = Field(default="2g")
    executor_memory: str = Field(default="2g")
    executor_cores: int = Field(default=2, ge=1, le=32)
    num_executors: int = Field(default=2, ge=1, le=100)
    
    # Data sources
    input_sources: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    output_destination: Optional[Dict[str, Any]] = None
    
    # Scheduling
    schedule_expression: Optional[str] = Field(None, max_length=100)
    
    # Configuration
    spark_config: Optional[Dict[str, str]] = Field(default_factory=dict)
    environment_variables: Optional[Dict[str, str]] = Field(default_factory=dict)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)


class CreateMLJobRequest(BaseModel):
    """Request model for creating ML jobs."""
    job_name: str = Field(..., min_length=1, max_length=255)
    algorithm: MLAlgorithm = Field(...)
    description: Optional[str] = Field(None, max_length=500)
    
    # ML configuration
    training_data_source: Dict[str, Any] = Field(...)
    validation_data_source: Optional[Dict[str, Any]] = None
    test_data_source: Optional[Dict[str, Any]] = None
    
    # Model configuration
    target_column: str = Field(..., min_length=1)
    feature_columns: List[str] = Field(..., min_items=1)
    hyperparameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    
    # Training configuration
    max_iterations: int = Field(default=100, ge=1, le=10000)
    cross_validation_folds: int = Field(default=5, ge=2, le=20)
    
    # Output configuration
    model_output_path: str = Field(..., min_length=1)
    
    # Configuration
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)


class CreateDataSourceRequest(BaseModel):
    """Request model for creating data sources."""
    source_name: str = Field(..., min_length=1, max_length=255)
    source_type: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(None, max_length=500)
    
    # Connection configuration
    connection_string: str = Field(..., min_length=1)
    format: DataFormat = Field(...)
    
    # Schema and options
    schema: Optional[Dict[str, Any]] = None
    options: Optional[Dict[str, str]] = Field(default_factory=dict)
    
    # Partitioning
    partition_columns: Optional[List[str]] = Field(default_factory=list)
    
    # Metadata
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)


class TransformDataRequest(BaseModel):
    """Request model for data transformation jobs."""
    transformation_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=500)
    
    # Source and destination
    input_source: Dict[str, Any] = Field(...)
    output_destination: Dict[str, Any] = Field(...)
    
    # Transformation logic
    sql_query: Optional[str] = Field(None, max_length=10000)
    transformation_steps: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    
    # Configuration
    repartition_count: Optional[int] = Field(None, ge=1, le=1000)
    cache_intermediate: bool = Field(default=False)
    
    # Metadata
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)


def get_spark_manager() -> SparkManager:
    """Get Spark manager instance."""
    global spark_manager
    if spark_manager is None:
        raise RuntimeError("Spark manager not initialized")
    return spark_manager


def get_job_scheduler() -> JobScheduler:
    """Get job scheduler instance."""
    global job_scheduler
    if job_scheduler is None:
        raise RuntimeError("Job scheduler not initialized")
    return job_scheduler


def get_ml_pipeline_manager() -> MLPipelineManager:
    """Get ML pipeline manager instance."""
    global ml_pipeline_manager
    if ml_pipeline_manager is None:
        raise RuntimeError("ML pipeline manager not initialized")
    return ml_pipeline_manager


@router.post("/jobs", response_model=Dict[str, Any])
@traced("spark_api_create_job")
async def create_job(
    request: CreateJobRequest,
    background_tasks: BackgroundTasks,
    manager: SparkManager = Depends(get_spark_manager),
    scheduler: JobScheduler = Depends(get_job_scheduler)
):
    """Create a new Spark job."""
    try:
        # Sanitize inputs
        job_name = sanitize_input(request.job_name, max_length=255)
        
        # Create Spark job
        job = create_spark_job(
            job_name=job_name,
            job_type=request.job_type,
            description=request.description,
            main_class=request.main_class,
            application_file=request.application_file,
            arguments=request.arguments or [],
            driver_memory=request.driver_memory,
            executor_memory=request.executor_memory,
            executor_cores=request.executor_cores,
            num_executors=request.num_executors,
            spark_config=request.spark_config or {},
            environment_variables=request.environment_variables or {},
            tags=request.tags or {}
        )
        
        # Set data sources
        if request.input_sources:
            job.input_sources = request.input_sources
        if request.output_destination:
            job.output_destination = request.output_destination
        
        # Submit job
        job_id = await manager.submit_job(job)
        
        # Schedule if needed
        if request.schedule_expression:
            await scheduler.schedule_job(job_id, request.schedule_expression)
        
        logger.info(f"Spark job created: {job_id}")
        metrics.spark_api_jobs_created.inc()
        
        return {
            "message": "Spark job created successfully",
            "job_id": job_id,
            "job_name": job_name,
            "job_type": request.job_type,
            "status": job.status,
            "timestamp": job.created_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating Spark job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/jobs/ml", response_model=Dict[str, Any])
@traced("spark_api_create_ml_job")
async def create_ml_job(
    request: CreateMLJobRequest,
    background_tasks: BackgroundTasks,
    ml_manager: MLPipelineManager = Depends(get_ml_pipeline_manager)
):
    """Create a new ML training job."""
    try:
        # Sanitize inputs
        job_name = sanitize_input(request.job_name, max_length=255)
        target_column = sanitize_input(request.target_column, max_length=255)
        
        # Create ML job
        job_id = await ml_manager.create_training_job(
            job_name=job_name,
            algorithm=request.algorithm,
            training_data_source=request.training_data_source,
            target_column=target_column,
            feature_columns=request.feature_columns,
            hyperparameters=request.hyperparameters or {},
            validation_data_source=request.validation_data_source,
            test_data_source=request.test_data_source,
            max_iterations=request.max_iterations,
            cross_validation_folds=request.cross_validation_folds,
            model_output_path=request.model_output_path,
            description=request.description,
            tags=request.tags or {}
        )
        
        logger.info(f"ML job created: {job_id}")
        metrics.spark_api_ml_jobs_created.inc()
        
        return {
            "message": "ML job created successfully",
            "job_id": job_id,
            "job_name": job_name,
            "algorithm": request.algorithm,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating ML job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/data-sources", response_model=Dict[str, Any])
@traced("spark_api_create_data_source")
async def create_data_source(
    request: CreateDataSourceRequest,
    manager: SparkManager = Depends(get_spark_manager)
):
    """Create a new data source configuration."""
    try:
        # Sanitize inputs
        source_name = sanitize_input(request.source_name, max_length=255)
        connection_string = sanitize_input(request.connection_string, max_length=1000)
        
        # Create data source
        data_source = create_data_source(
            source_name=source_name,
            source_type=request.source_type,
            connection_string=connection_string,
            format=request.format,
            description=request.description,
            schema=request.schema,
            options=request.options or {},
            partition_columns=request.partition_columns or [],
            tags=request.tags or {}
        )
        
        # Register data source
        source_id = await manager.register_data_source(data_source)
        
        logger.info(f"Data source created: {source_id}")
        metrics.spark_api_data_sources_created.inc()
        
        return {
            "message": "Data source created successfully",
            "source_id": source_id,
            "source_name": source_name,
            "source_type": request.source_type,
            "format": request.format,
            "timestamp": data_source.created_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating data source: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/transformations", response_model=Dict[str, Any])
@traced("spark_api_transform_data")
async def transform_data(
    request: TransformDataRequest,
    background_tasks: BackgroundTasks,
    manager: SparkManager = Depends(get_spark_manager)
):
    """Create a data transformation job."""
    try:
        # Sanitize inputs
        transformation_name = sanitize_input(request.transformation_name, max_length=255)
        
        # Create transformation job
        job_id = await manager.create_transformation_job(
            transformation_name=transformation_name,
            input_source=request.input_source,
            output_destination=request.output_destination,
            sql_query=request.sql_query,
            transformation_steps=request.transformation_steps or [],
            repartition_count=request.repartition_count,
            cache_intermediate=request.cache_intermediate,
            description=request.description,
            tags=request.tags or {}
        )
        
        logger.info(f"Data transformation job created: {job_id}")
        metrics.spark_api_transformations_created.inc()
        
        return {
            "message": "Data transformation job created successfully",
            "job_id": job_id,
            "transformation_name": transformation_name,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating data transformation: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/jobs", response_model=Dict[str, Any])
@traced("spark_api_list_jobs")
async def list_jobs(
    job_type: Optional[JobType] = Query(None),
    status: Optional[JobStatus] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    manager: SparkManager = Depends(get_spark_manager)
):
    """List Spark jobs with filtering."""
    try:
        jobs = await manager.list_jobs(
            job_type=job_type,
            status=status,
            limit=limit,
            offset=offset
        )
        
        total_count = await manager.count_jobs(job_type=job_type, status=status)
        
        return {
            "jobs": [job.dict() for job in jobs],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "filters": {
                "job_type": job_type,
                "status": status
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing jobs: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/jobs/{job_id}", response_model=Dict[str, Any])
@traced("spark_api_get_job")
async def get_job(
    job_id: str,
    include_logs: bool = Query(False),
    manager: SparkManager = Depends(get_spark_manager)
):
    """Get job details and status."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        
        job = await manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        result = job.dict()
        
        if include_logs:
            logs = await manager.get_job_logs(job_id)
            result["logs"] = logs
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/jobs/{job_id}/start", response_model=Dict[str, Any])
@traced("spark_api_start_job")
async def start_job(
    job_id: str,
    manager: SparkManager = Depends(get_spark_manager)
):
    """Start a Spark job."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        
        success = await manager.start_job(job_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Job not found or cannot be started")
        
        logger.info(f"Job started: {job_id}")
        metrics.spark_api_jobs_started.inc()
        
        return {
            "message": "Job started successfully",
            "job_id": job_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/jobs/{job_id}/stop", response_model=Dict[str, Any])
@traced("spark_api_stop_job")
async def stop_job(
    job_id: str,
    force: bool = Query(False, description="Force stop the job"),
    manager: SparkManager = Depends(get_spark_manager)
):
    """Stop a running Spark job."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        
        success = await manager.stop_job(job_id, force=force)
        
        if not success:
            raise HTTPException(status_code=404, detail="Job not found or cannot be stopped")
        
        logger.info(f"Job stopped: {job_id}")
        metrics.spark_api_jobs_stopped.inc()
        
        return {
            "message": "Job stopped successfully",
            "job_id": job_id,
            "force": force,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/jobs/{job_id}/logs", response_model=Dict[str, Any])
@traced("spark_api_get_job_logs")
async def get_job_logs(
    job_id: str,
    log_type: str = Query("all", regex="^(all|driver|executor|stderr|stdout)$"),
    lines: int = Query(1000, ge=1, le=10000),
    manager: SparkManager = Depends(get_spark_manager)
):
    """Get job execution logs."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        
        logs = await manager.get_job_logs(job_id, log_type=log_type, lines=lines)
        
        return {
            "job_id": job_id,
            "log_type": log_type,
            "logs": logs,
            "lines_returned": len(logs),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting job logs: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/jobs/{job_id}/metrics", response_model=Dict[str, Any])
@traced("spark_api_get_job_metrics")
async def get_job_metrics(
    job_id: str,
    manager: SparkManager = Depends(get_spark_manager)
):
    """Get job execution metrics."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        
        metrics_data = await manager.get_job_metrics(job_id)
        
        return {
            "job_id": job_id,
            "metrics": metrics_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting job metrics: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/data-sources", response_model=Dict[str, Any])
@traced("spark_api_list_data_sources")
async def list_data_sources(
    source_type: Optional[str] = Query(None),
    format: Optional[DataFormat] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    manager: SparkManager = Depends(get_spark_manager)
):
    """List registered data sources."""
    try:
        data_sources = await manager.list_data_sources(
            source_type=source_type,
            format=format,
            limit=limit,
            offset=offset
        )
        
        total_count = await manager.count_data_sources(
            source_type=source_type,
            format=format
        )
        
        return {
            "data_sources": [ds.dict() for ds in data_sources],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "filters": {
                "source_type": source_type,
                "format": format
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing data sources: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/applications", response_model=Dict[str, Any])
@traced("spark_api_list_applications")
async def list_applications(
    manager: SparkManager = Depends(get_spark_manager)
):
    """List running Spark applications."""
    try:
        applications = await manager.list_applications()
        
        return {
            "applications": [app.dict() for app in applications],
            "total_count": len(applications),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing applications: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/cluster/status", response_model=Dict[str, Any])
@traced("spark_api_get_cluster_status")
async def get_cluster_status(
    manager: SparkManager = Depends(get_spark_manager)
):
    """Get Spark cluster status and resource utilization."""
    try:
        cluster_status = await manager.get_cluster_status()
        
        return {
            "cluster_status": cluster_status,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting cluster status: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/jobs/{job_id}/schedule", response_model=Dict[str, Any])
@traced("spark_api_schedule_job")
async def schedule_job(
    job_id: str,
    schedule_expression: str = Query(..., min_length=1, max_length=100),
    scheduler: JobScheduler = Depends(get_job_scheduler)
):
    """Schedule a job for recurring execution."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        schedule_expression = sanitize_input(schedule_expression, max_length=100)
        
        schedule_id = await scheduler.schedule_job(job_id, schedule_expression)
        
        logger.info(f"Job scheduled: {job_id}")
        metrics.spark_api_jobs_scheduled.inc()
        
        return {
            "message": "Job scheduled successfully",
            "job_id": job_id,
            "schedule_id": schedule_id,
            "schedule_expression": schedule_expression,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error scheduling job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/models", response_model=Dict[str, Any])
@traced("spark_api_list_models")
async def list_models(
    algorithm: Optional[MLAlgorithm] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    ml_manager: MLPipelineManager = Depends(get_ml_pipeline_manager)
):
    """List trained ML models."""
    try:
        models = await ml_manager.list_models(
            algorithm=algorithm,
            limit=limit,
            offset=offset
        )
        
        total_count = await ml_manager.count_models(algorithm=algorithm)
        
        return {
            "models": [model.dict() for model in models],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "filters": {
                "algorithm": algorithm
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("spark_api_get_statistics")
async def get_statistics(
    manager: SparkManager = Depends(get_spark_manager),
    scheduler: JobScheduler = Depends(get_job_scheduler),
    ml_manager: MLPipelineManager = Depends(get_ml_pipeline_manager)
):
    """Get comprehensive Spark service statistics."""
    try:
        manager_stats = manager.get_stats()
        scheduler_stats = scheduler.get_stats()
        ml_stats = ml_manager.get_stats()
        
        return {
            "service": "spark-service",
            "manager": manager_stats,
            "scheduler": scheduler_stats,
            "ml_pipeline": ml_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/jobs/{job_id}", response_model=Dict[str, Any])
@traced("spark_api_delete_job")
async def delete_job(
    job_id: str,
    force: bool = Query(False, description="Force delete running job"),
    manager: SparkManager = Depends(get_spark_manager)
):
    """Delete a Spark job."""
    try:
        # Sanitize inputs
        job_id = sanitize_input(job_id, max_length=255)
        
        success = await manager.delete_job(job_id, force=force)
        
        if not success:
            raise HTTPException(status_code=404, detail="Job not found")
        
        logger.info(f"Job deleted: {job_id}")
        
        return {
            "message": "Job deleted successfully",
            "job_id": job_id,
            "force": force,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting job: {e}")
        metrics.spark_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")