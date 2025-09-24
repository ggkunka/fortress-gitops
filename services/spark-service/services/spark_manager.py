"""
Spark Manager Service - Apache Spark cluster management and job orchestration

This service provides comprehensive Spark cluster management including job submission,
monitoring, resource allocation, and data processing coordination.
"""

import asyncio
import json
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
import uuid
import os
import tempfile

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.spark import (
    SparkJob, SparkApplication, DataSource, DataTransformation,
    JobType, JobStatus, DataFormat, SparkConfig
)

logger = get_logger(__name__)
metrics = get_metrics()


class SparkManager:
    """
    Spark cluster manager for big data processing.
    
    This manager provides:
    1. Job submission and lifecycle management
    2. Cluster resource monitoring
    3. Data source registration and management
    4. Application monitoring and metrics
    5. Configuration management
    6. Error handling and recovery
    """
    
    def __init__(self):
        self.settings = get_settings()
        
        # Spark configuration
        self.spark_home = getattr(self.settings, 'spark_home', '/opt/spark')
        self.spark_master = getattr(self.settings, 'spark_master', 'spark://localhost:7077')
        self.spark_submit_path = os.path.join(self.spark_home, 'bin', 'spark-submit')
        
        # Cluster configuration
        self.default_driver_memory = "2g"
        self.default_executor_memory = "2g"
        self.default_executor_cores = 2
        self.default_num_executors = 2
        
        # Storage paths
        self.job_storage_path = getattr(self.settings, 'spark_job_storage', '/tmp/spark-jobs')
        self.checkpoint_path = getattr(self.settings, 'spark_checkpoint_path', '/tmp/spark-checkpoints')
        
        # Job tracking
        self.active_jobs: Dict[str, SparkJob] = {}
        self.job_history: Dict[str, SparkJob] = {}
        self.data_sources: Dict[str, DataSource] = {}
        self.applications: Dict[str, SparkApplication] = {}
        
        # Configuration
        self.max_concurrent_jobs = 10
        self.job_timeout_seconds = 3600  # 1 hour default
        self.cleanup_interval_hours = 24
        
        logger.info("Spark manager initialized")
    
    async def initialize(self):
        """Initialize Spark manager."""
        try:
            # Verify Spark installation
            await self._verify_spark_installation()
            
            # Create necessary directories
            os.makedirs(self.job_storage_path, exist_ok=True)
            os.makedirs(self.checkpoint_path, exist_ok=True)
            
            # Start background tasks
            asyncio.create_task(self._monitor_jobs())
            asyncio.create_task(self._cleanup_completed_jobs())
            
            logger.info("Spark manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Spark manager: {e}")
            raise
    
    @traced("spark_manager_submit_job")
    async def submit_job(self, job: SparkJob) -> str:
        """Submit a Spark job for execution."""
        try:
            # Check concurrent job limit
            if len(self.active_jobs) >= self.max_concurrent_jobs:
                raise RuntimeError(f"Maximum concurrent jobs limit reached: {self.max_concurrent_jobs}")
            
            # Generate job configuration
            job_config = await self._generate_job_config(job)
            
            # Prepare job submission
            submit_command = await self._build_submit_command(job, job_config)
            
            # Submit job
            job.status = JobStatus.SUBMITTED
            job.submitted_at = datetime.now(timezone.utc)
            
            # Execute submission
            process = await asyncio.create_subprocess_exec(
                *submit_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.job_storage_path
            )
            
            # Store process information
            job.spark_application_id = f"app-{job.id}"
            job.process_id = process.pid
            
            # Track job
            self.active_jobs[job.id] = job
            
            # Start monitoring
            asyncio.create_task(self._monitor_job_execution(job, process))
            
            logger.info(f"Spark job submitted: {job.id}")
            metrics.spark_manager_jobs_submitted.inc()
            
            return job.id
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            logger.error(f"Error submitting Spark job: {e}")
            metrics.spark_manager_errors.inc()
            raise
    
    @traced("spark_manager_get_job")
    async def get_job(self, job_id: str) -> Optional[SparkJob]:
        """Get job by ID."""
        try:
            # Check active jobs first
            if job_id in self.active_jobs:
                return self.active_jobs[job_id]
            
            # Check job history
            if job_id in self.job_history:
                return self.job_history[job_id]
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting job: {e}")
            raise
    
    @traced("spark_manager_list_jobs")
    async def list_jobs(
        self,
        job_type: Optional[JobType] = None,
        status: Optional[JobStatus] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[SparkJob]:
        """List jobs with filtering."""
        try:
            all_jobs = list(self.active_jobs.values()) + list(self.job_history.values())
            
            # Apply filters
            filtered_jobs = []
            for job in all_jobs:
                if job_type and job.job_type != job_type:
                    continue
                if status and job.status != status:
                    continue
                filtered_jobs.append(job)
            
            # Sort by creation time (newest first)
            filtered_jobs.sort(key=lambda j: j.created_at, reverse=True)
            
            # Apply pagination
            return filtered_jobs[offset:offset + limit]
            
        except Exception as e:
            logger.error(f"Error listing jobs: {e}")
            raise
    
    @traced("spark_manager_count_jobs")
    async def count_jobs(
        self,
        job_type: Optional[JobType] = None,
        status: Optional[JobStatus] = None
    ) -> int:
        """Count jobs with filtering."""
        try:
            all_jobs = list(self.active_jobs.values()) + list(self.job_history.values())
            
            count = 0
            for job in all_jobs:
                if job_type and job.job_type != job_type:
                    continue
                if status and job.status != status:
                    continue
                count += 1
            
            return count
            
        except Exception as e:
            logger.error(f"Error counting jobs: {e}")
            raise
    
    @traced("spark_manager_start_job")
    async def start_job(self, job_id: str) -> bool:
        """Start a job (for scheduled or paused jobs)."""
        try:
            job = await self.get_job(job_id)
            if not job:
                return False
            
            if job.status not in [JobStatus.CREATED, JobStatus.PAUSED]:
                logger.warning(f"Cannot start job in status: {job.status}")
                return False
            
            # Submit the job
            await self.submit_job(job)
            
            logger.info(f"Job started: {job_id}")
            metrics.spark_manager_jobs_started.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error starting job: {e}")
            return False
    
    @traced("spark_manager_stop_job")
    async def stop_job(self, job_id: str, force: bool = False) -> bool:
        """Stop a running job."""
        try:
            job = self.active_jobs.get(job_id)
            if not job:
                return False
            
            if job.status not in [JobStatus.RUNNING, JobStatus.SUBMITTED]:
                logger.warning(f"Cannot stop job in status: {job.status}")
                return False
            
            # Kill the process
            if job.process_id:
                try:
                    if force:
                        os.kill(job.process_id, 9)  # SIGKILL
                    else:
                        os.kill(job.process_id, 15)  # SIGTERM
                except ProcessLookupError:
                    pass  # Process already terminated
            
            # Update job status
            job.status = JobStatus.CANCELLED
            job.finished_at = datetime.now(timezone.utc)
            
            # Move to history
            self.job_history[job_id] = job
            del self.active_jobs[job_id]
            
            logger.info(f"Job stopped: {job_id}")
            metrics.spark_manager_jobs_stopped.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error stopping job: {e}")
            return False
    
    @traced("spark_manager_delete_job")
    async def delete_job(self, job_id: str, force: bool = False) -> bool:
        """Delete a job."""
        try:
            # Stop if running
            if job_id in self.active_jobs:
                if not force:
                    return False
                await self.stop_job(job_id, force=True)
            
            # Remove from history
            if job_id in self.job_history:
                del self.job_history[job_id]
            
            # Clean up job files
            job_dir = os.path.join(self.job_storage_path, job_id)
            if os.path.exists(job_dir):
                import shutil
                shutil.rmtree(job_dir)
            
            logger.info(f"Job deleted: {job_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting job: {e}")
            return False
    
    @traced("spark_manager_get_job_logs")
    async def get_job_logs(
        self, 
        job_id: str, 
        log_type: str = "all", 
        lines: int = 1000
    ) -> List[str]:
        """Get job execution logs."""
        try:
            job_log_dir = os.path.join(self.job_storage_path, job_id, "logs")
            
            if not os.path.exists(job_log_dir):
                return []
            
            logs = []
            
            if log_type == "all" or log_type == "driver":
                driver_log = os.path.join(job_log_dir, "driver.log")
                if os.path.exists(driver_log):
                    logs.extend(self._read_log_file(driver_log, lines))
            
            if log_type == "all" or log_type == "executor":
                executor_log = os.path.join(job_log_dir, "executor.log")
                if os.path.exists(executor_log):
                    logs.extend(self._read_log_file(executor_log, lines))
            
            return logs[-lines:] if logs else []
            
        except Exception as e:
            logger.error(f"Error getting job logs: {e}")
            return []
    
    @traced("spark_manager_get_job_metrics")
    async def get_job_metrics(self, job_id: str) -> Dict[str, Any]:
        """Get job execution metrics."""
        try:
            job = await self.get_job(job_id)
            if not job:
                return {}
            
            metrics_data = {
                "job_id": job_id,
                "status": job.status,
                "duration_seconds": 0,
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "input_records": 0,
                "output_records": 0,
                "shuffle_read_bytes": 0,
                "shuffle_write_bytes": 0
            }
            
            # Calculate duration
            if job.started_at and job.finished_at:
                duration = job.finished_at - job.started_at
                metrics_data["duration_seconds"] = duration.total_seconds()
            elif job.started_at:
                duration = datetime.now(timezone.utc) - job.started_at
                metrics_data["duration_seconds"] = duration.total_seconds()
            
            # Get Spark application metrics if available
            if job.spark_application_id and job.spark_application_id in self.applications:
                app = self.applications[job.spark_application_id]
                metrics_data.update({
                    "cpu_usage": app.cpu_usage,
                    "memory_usage": app.memory_usage,
                    "input_records": app.input_records,
                    "output_records": app.output_records,
                    "shuffle_read_bytes": app.shuffle_read_bytes,
                    "shuffle_write_bytes": app.shuffle_write_bytes
                })
            
            return metrics_data
            
        except Exception as e:
            logger.error(f"Error getting job metrics: {e}")
            return {}
    
    @traced("spark_manager_register_data_source")
    async def register_data_source(self, data_source: DataSource) -> str:
        """Register a data source."""
        try:
            # Validate connection
            await self._validate_data_source(data_source)
            
            # Store data source
            self.data_sources[data_source.id] = data_source
            
            logger.info(f"Data source registered: {data_source.id}")
            metrics.spark_manager_data_sources_registered.inc()
            
            return data_source.id
            
        except Exception as e:
            logger.error(f"Error registering data source: {e}")
            metrics.spark_manager_errors.inc()
            raise
    
    @traced("spark_manager_list_data_sources")
    async def list_data_sources(
        self,
        source_type: Optional[str] = None,
        format: Optional[DataFormat] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[DataSource]:
        """List registered data sources."""
        try:
            sources = list(self.data_sources.values())
            
            # Apply filters
            filtered_sources = []
            for source in sources:
                if source_type and source.source_type != source_type:
                    continue
                if format and source.format != format:
                    continue
                filtered_sources.append(source)
            
            # Sort by creation time
            filtered_sources.sort(key=lambda s: s.created_at, reverse=True)
            
            # Apply pagination
            return filtered_sources[offset:offset + limit]
            
        except Exception as e:
            logger.error(f"Error listing data sources: {e}")
            raise
    
    @traced("spark_manager_count_data_sources")
    async def count_data_sources(
        self,
        source_type: Optional[str] = None,
        format: Optional[DataFormat] = None
    ) -> int:
        """Count data sources."""
        try:
            sources = list(self.data_sources.values())
            
            count = 0
            for source in sources:
                if source_type and source.source_type != source_type:
                    continue
                if format and source.format != format:
                    continue
                count += 1
            
            return count
            
        except Exception as e:
            logger.error(f"Error counting data sources: {e}")
            raise
    
    @traced("spark_manager_create_transformation_job")
    async def create_transformation_job(
        self,
        transformation_name: str,
        input_source: Dict[str, Any],
        output_destination: Dict[str, Any],
        sql_query: Optional[str] = None,
        transformation_steps: Optional[List[Dict[str, Any]]] = None,
        repartition_count: Optional[int] = None,
        cache_intermediate: bool = False,
        **kwargs
    ) -> str:
        """Create a data transformation job."""
        try:
            # Create transformation job
            transformation = DataTransformation(
                transformation_name=transformation_name,
                input_source=input_source,
                output_destination=output_destination,
                sql_query=sql_query,
                transformation_steps=transformation_steps or [],
                repartition_count=repartition_count,
                cache_intermediate=cache_intermediate,
                **kwargs
            )
            
            # Create Spark job for transformation
            job = SparkJob(
                job_name=transformation_name,
                job_type=JobType.DATA_TRANSFORMATION,
                main_class="org.apache.spark.sql.DataTransformationJob",
                input_sources=[input_source],
                output_destination=output_destination,
                spark_config={
                    "spark.sql.adaptive.enabled": "true",
                    "spark.sql.adaptive.coalescePartitions.enabled": "true"
                }
            )
            
            # Submit job
            job_id = await self.submit_job(job)
            
            logger.info(f"Data transformation job created: {job_id}")
            
            return job_id
            
        except Exception as e:
            logger.error(f"Error creating transformation job: {e}")
            raise
    
    @traced("spark_manager_list_applications")
    async def list_applications(self) -> List[SparkApplication]:
        """List running Spark applications."""
        try:
            # In a real implementation, this would query the Spark master
            return list(self.applications.values())
            
        except Exception as e:
            logger.error(f"Error listing applications: {e}")
            raise
    
    @traced("spark_manager_get_cluster_status")
    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get Spark cluster status."""
        try:
            # In a real implementation, this would query the Spark master API
            cluster_status = {
                "master_url": self.spark_master,
                "status": "alive",
                "workers": 2,
                "cores_total": 8,
                "cores_used": 4,
                "memory_total": "8GB",
                "memory_used": "4GB",
                "applications_running": len(self.applications),
                "applications_completed": len(self.job_history),
                "version": "3.5.0"
            }
            
            return cluster_status
            
        except Exception as e:
            logger.error(f"Error getting cluster status: {e}")
            raise
    
    async def _verify_spark_installation(self):
        """Verify Spark installation."""
        try:
            if not os.path.exists(self.spark_submit_path):
                raise RuntimeError(f"Spark not found at: {self.spark_submit_path}")
            
            # Test spark-submit
            result = subprocess.run(
                [self.spark_submit_path, "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Spark installation verification failed: {result.stderr}")
            
            logger.info("Spark installation verified")
            
        except Exception as e:
            logger.error(f"Spark installation verification failed: {e}")
            raise
    
    async def _generate_job_config(self, job: SparkJob) -> Dict[str, Any]:
        """Generate job configuration."""
        config = {
            "spark.app.name": job.job_name,
            "spark.driver.memory": job.driver_memory,
            "spark.executor.memory": job.executor_memory,
            "spark.executor.cores": str(job.executor_cores),
            "spark.executor.instances": str(job.num_executors),
            "spark.sql.warehouse.dir": self.checkpoint_path,
            "spark.serializer": "org.apache.spark.serializer.KryoSerializer",
            "spark.sql.adaptive.enabled": "true"
        }
        
        # Add custom configuration
        config.update(job.spark_config)
        
        return config
    
    async def _build_submit_command(self, job: SparkJob, config: Dict[str, Any]) -> List[str]:
        """Build spark-submit command."""
        command = [
            self.spark_submit_path,
            "--master", self.spark_master,
            "--deploy-mode", "client"
        ]
        
        # Add configuration
        for key, value in config.items():
            command.extend(["--conf", f"{key}={value}"])
        
        # Add main class if specified
        if job.main_class:
            command.extend(["--class", job.main_class])
        
        # Add application file or built-in job
        if job.application_file:
            command.append(job.application_file)
        else:
            # Use built-in job types
            command.append(self._get_builtin_job_jar(job.job_type))
        
        # Add arguments
        command.extend(job.arguments)
        
        return command
    
    def _get_builtin_job_jar(self, job_type: JobType) -> str:
        """Get built-in job JAR path."""
        # In a real implementation, these would be actual JAR files
        builtin_jars = {
            JobType.BATCH_PROCESSING: f"{self.spark_home}/jars/batch-processing.jar",
            JobType.STREAM_PROCESSING: f"{self.spark_home}/jars/stream-processing.jar",
            JobType.DATA_TRANSFORMATION: f"{self.spark_home}/jars/data-transformation.jar",
            JobType.ML_TRAINING: f"{self.spark_home}/jars/ml-training.jar",
            JobType.SQL_QUERY: f"{self.spark_home}/jars/sql-query.jar"
        }
        
        return builtin_jars.get(job_type, f"{self.spark_home}/jars/generic-job.jar")
    
    async def _monitor_job_execution(self, job: SparkJob, process):
        """Monitor job execution."""
        try:
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(timezone.utc)
            
            # Wait for process completion
            stdout, stderr = await process.communicate()
            
            # Update job status
            if process.returncode == 0:
                job.status = JobStatus.COMPLETED
            else:
                job.status = JobStatus.FAILED
                job.error_message = stderr.decode() if stderr else "Unknown error"
            
            job.finished_at = datetime.now(timezone.utc)
            
            # Move to history
            self.job_history[job.id] = job
            if job.id in self.active_jobs:
                del self.active_jobs[job.id]
            
            logger.info(f"Job completed: {job.id} with status {job.status}")
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            job.finished_at = datetime.now(timezone.utc)
            
            logger.error(f"Error monitoring job: {e}")
    
    async def _monitor_jobs(self):
        """Background task to monitor job status."""
        while True:
            try:
                # Check for timed out jobs
                current_time = datetime.now(timezone.utc)
                
                for job_id, job in list(self.active_jobs.items()):
                    if job.started_at:
                        runtime = current_time - job.started_at
                        if runtime.total_seconds() > self.job_timeout_seconds:
                            logger.warning(f"Job timeout: {job_id}")
                            await self.stop_job(job_id, force=True)
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in job monitoring: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_completed_jobs(self):
        """Background task to cleanup old completed jobs."""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                cleanup_before = current_time - timedelta(hours=self.cleanup_interval_hours)
                
                # Clean up old jobs from history
                jobs_to_remove = []
                for job_id, job in self.job_history.items():
                    if job.finished_at and job.finished_at < cleanup_before:
                        jobs_to_remove.append(job_id)
                
                for job_id in jobs_to_remove:
                    del self.job_history[job_id]
                    logger.info(f"Cleaned up old job: {job_id}")
                
                await asyncio.sleep(3600)  # Run every hour
                
            except Exception as e:
                logger.error(f"Error in job cleanup: {e}")
                await asyncio.sleep(3600)
    
    async def _validate_data_source(self, data_source: DataSource):
        """Validate data source connection."""
        try:
            # Simple validation - in production would test actual connection
            if not data_source.connection_string:
                raise ValueError("Connection string is required")
            
            if data_source.format not in [DataFormat.PARQUET, DataFormat.JSON, DataFormat.CSV, 
                                         DataFormat.AVRO, DataFormat.DELTA, DataFormat.JDBC]:
                raise ValueError(f"Unsupported format: {data_source.format}")
            
            logger.debug(f"Data source validated: {data_source.source_name}")
            
        except Exception as e:
            logger.error(f"Data source validation failed: {e}")
            raise
    
    def _read_log_file(self, file_path: str, lines: int) -> List[str]:
        """Read log file with line limit."""
        try:
            with open(file_path, 'r') as f:
                log_lines = f.readlines()
                return [line.strip() for line in log_lines[-lines:]]
        except Exception as e:
            logger.error(f"Error reading log file {file_path}: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        return {
            "spark_home": self.spark_home,
            "spark_master": self.spark_master,
            "active_jobs": len(self.active_jobs),
            "completed_jobs": len(self.job_history),
            "registered_data_sources": len(self.data_sources),
            "running_applications": len(self.applications),
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "job_timeout_seconds": self.job_timeout_seconds,
            "operations": [
                "submit_job", "get_job", "list_jobs", "start_job", "stop_job",
                "delete_job", "get_job_logs", "get_job_metrics", "register_data_source",
                "list_data_sources", "create_transformation_job", "list_applications",
                "get_cluster_status"
            ]
        }