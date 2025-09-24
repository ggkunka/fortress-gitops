"""
Apache Spark Models for Big Data Processing

This module defines the data models and structures for Apache Spark
big data processing, including jobs, applications, and ML pipelines.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, validator
import uuid

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class JobType(str, Enum):
    """Types of Spark jobs."""
    BATCH_PROCESSING = "batch_processing"
    STREAM_PROCESSING = "stream_processing"
    DATA_TRANSFORMATION = "data_transformation"
    ML_TRAINING = "ml_training"
    ML_INFERENCE = "ml_inference"
    SQL_QUERY = "sql_query"
    ETL = "etl"
    ANALYTICS = "analytics"
    DATA_VALIDATION = "data_validation"
    CUSTOM = "custom"


class JobStatus(str, Enum):
    """Spark job status."""
    CREATED = "created"
    SUBMITTED = "submitted"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"
    RETRYING = "retrying"


class DataFormat(str, Enum):
    """Supported data formats."""
    PARQUET = "parquet"
    JSON = "json"
    CSV = "csv"
    AVRO = "avro"
    ORC = "orc"
    DELTA = "delta"
    JDBC = "jdbc"
    ELASTICSEARCH = "elasticsearch"
    KAFKA = "kafka"
    CASSANDRA = "cassandra"
    HBASE = "hbase"
    TEXT = "text"


class MLAlgorithm(str, Enum):
    """Machine learning algorithms."""
    LINEAR_REGRESSION = "linear_regression"
    LOGISTIC_REGRESSION = "logistic_regression"
    RANDOM_FOREST = "random_forest"
    GRADIENT_BOOSTING = "gradient_boosting"
    SVM = "svm"
    NAIVE_BAYES = "naive_bayes"
    K_MEANS = "k_means"
    DECISION_TREE = "decision_tree"
    NEURAL_NETWORK = "neural_network"
    ANOMALY_DETECTION = "anomaly_detection"
    COLLABORATIVE_FILTERING = "collaborative_filtering"
    ASSOCIATION_RULES = "association_rules"


class BaseSparkModel(BaseModel):
    """Base model for Spark entities."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @validator('created_at', 'updated_at')
    def validate_timestamps(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v
    
    class Config:
        use_enum_values = True


class SparkConfig(BaseModel):
    """Spark configuration model."""
    driver_memory: str = Field(default="2g")
    executor_memory: str = Field(default="2g")
    executor_cores: int = Field(default=2, ge=1, le=32)
    num_executors: int = Field(default=2, ge=1, le=1000)
    
    # Advanced configuration
    dynamic_allocation: bool = Field(default=False)
    max_executors: Optional[int] = Field(None, ge=1, le=1000)
    min_executors: Optional[int] = Field(None, ge=0, le=100)
    
    # Memory configuration
    driver_max_result_size: str = Field(default="1g")
    executor_memory_fraction: float = Field(default=0.8, ge=0.1, le=0.9)
    
    # Serialization
    serializer: str = Field(default="org.apache.spark.serializer.KryoSerializer")
    
    # SQL configuration
    sql_adaptive_enabled: bool = Field(default=True)
    sql_adaptive_coalesce_partitions: bool = Field(default=True)
    
    # Shuffle configuration
    shuffle_partitions: int = Field(default=200, ge=1, le=10000)
    
    # Custom configuration
    custom_configs: Dict[str, str] = Field(default_factory=dict)


class SparkJob(BaseSparkModel):
    """Spark job model."""
    job_name: str = Field(...)
    job_type: JobType = Field(...)
    description: Optional[str] = None
    
    # Job execution
    main_class: Optional[str] = None
    application_file: Optional[str] = None
    arguments: List[str] = Field(default_factory=list)
    
    # Resource configuration
    driver_memory: str = Field(default="2g")
    executor_memory: str = Field(default="2g")
    executor_cores: int = Field(default=2, ge=1, le=32)
    num_executors: int = Field(default=2, ge=1, le=100)
    
    # Data sources
    input_sources: List[Dict[str, Any]] = Field(default_factory=list)
    output_destination: Optional[Dict[str, Any]] = None
    
    # Configuration
    spark_config: Dict[str, str] = Field(default_factory=dict)
    environment_variables: Dict[str, str] = Field(default_factory=dict)
    
    # Job status
    status: JobStatus = Field(default=JobStatus.CREATED)
    submitted_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    
    # Execution information
    spark_application_id: Optional[str] = None
    spark_ui_url: Optional[str] = None
    process_id: Optional[int] = None
    
    # Error handling
    error_message: Optional[str] = None
    retry_count: int = Field(default=0, ge=0)
    max_retries: int = Field(default=3, ge=0, le=10)
    
    # Scheduling
    schedule_expression: Optional[str] = None
    next_run_time: Optional[datetime] = None
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    labels: List[str] = Field(default_factory=list)
    
    # Resource usage
    total_cores: Optional[int] = None
    total_memory: Optional[str] = None
    
    @validator('submitted_at', 'started_at', 'finished_at', 'next_run_time')
    def validate_optional_timestamps(cls, v):
        if v and v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v


class SparkApplication(BaseSparkModel):
    """Spark application model."""
    application_id: str = Field(...)
    application_name: str = Field(...)
    
    # Application state
    state: str = Field(...)  # SUBMITTED, RUNNING, FINISHED, FAILED, KILLED
    final_status: Optional[str] = None  # SUCCEEDED, FAILED, KILLED, UNDEFINED
    
    # Resource information
    cores: int = Field(default=0, ge=0)
    memory_per_executor: str = Field(default="1g")
    max_cores: Optional[int] = None
    
    # Timing
    start_time: datetime = Field(...)
    end_time: Optional[datetime] = None
    duration: Optional[int] = None  # milliseconds
    
    # Tracking URLs
    tracking_url: Optional[str] = None
    spark_ui_url: Optional[str] = None
    
    # Driver information
    driver_host: Optional[str] = None
    driver_port: Optional[int] = None
    
    # Executor information
    executors: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metrics
    cpu_usage: float = Field(default=0.0, ge=0.0)
    memory_usage: float = Field(default=0.0, ge=0.0)
    input_records: int = Field(default=0, ge=0)
    output_records: int = Field(default=0, ge=0)
    shuffle_read_bytes: int = Field(default=0, ge=0)
    shuffle_write_bytes: int = Field(default=0, ge=0)
    
    # Configuration
    spark_properties: Dict[str, str] = Field(default_factory=dict)


class DataSource(BaseSparkModel):
    """Data source configuration model."""
    source_name: str = Field(...)
    source_type: str = Field(...)  # file, database, stream, etc.
    description: Optional[str] = None
    
    # Connection information
    connection_string: str = Field(...)
    format: DataFormat = Field(...)
    
    # Schema and structure
    schema: Optional[Dict[str, Any]] = None
    columns: List[str] = Field(default_factory=list)
    
    # Connection options
    options: Dict[str, str] = Field(default_factory=dict)
    
    # Partitioning
    partition_columns: List[str] = Field(default_factory=list)
    num_partitions: Optional[int] = Field(None, ge=1, le=10000)
    
    # Data characteristics
    estimated_size_bytes: Optional[int] = Field(None, ge=0)
    estimated_records: Optional[int] = Field(None, ge=0)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    
    # Validation
    is_validated: bool = Field(default=False)
    last_validated: Optional[datetime] = None


class DataTransformation(BaseSparkModel):
    """Data transformation configuration model."""
    transformation_name: str = Field(...)
    description: Optional[str] = None
    
    # Source and destination
    input_source: Dict[str, Any] = Field(...)
    output_destination: Dict[str, Any] = Field(...)
    
    # Transformation logic
    sql_query: Optional[str] = None
    transformation_steps: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Processing configuration
    repartition_count: Optional[int] = Field(None, ge=1, le=10000)
    coalesce_count: Optional[int] = Field(None, ge=1, le=10000)
    cache_intermediate: bool = Field(default=False)
    persist_storage_level: str = Field(default="MEMORY_AND_DISK")
    
    # Quality checks
    validation_rules: List[Dict[str, Any]] = Field(default_factory=list)
    enable_data_quality_checks: bool = Field(default=True)
    
    # Performance
    broadcast_threshold: Optional[int] = Field(None, ge=0)
    bucketing_enabled: bool = Field(default=False)
    bucket_columns: List[str] = Field(default_factory=list)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)


class MLModel(BaseSparkModel):
    """Machine learning model model."""
    model_name: str = Field(...)
    algorithm: MLAlgorithm = Field(...)
    description: Optional[str] = None
    
    # Model artifacts
    model_path: str = Field(...)
    model_format: str = Field(default="spark_ml")
    model_version: str = Field(default="1.0.0")
    
    # Training information
    training_job_id: Optional[str] = None
    training_dataset: Optional[str] = None
    validation_dataset: Optional[str] = None
    test_dataset: Optional[str] = None
    
    # Model configuration
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    feature_columns: List[str] = Field(default_factory=list)
    target_column: Optional[str] = None
    
    # Model performance
    training_metrics: Dict[str, float] = Field(default_factory=dict)
    validation_metrics: Dict[str, float] = Field(default_factory=dict)
    test_metrics: Dict[str, float] = Field(default_factory=dict)
    
    # Model status
    status: str = Field(default="training")  # training, trained, deployed, deprecated
    is_production: bool = Field(default=False)
    
    # Deployment information
    deployment_endpoint: Optional[str] = None
    prediction_count: int = Field(default=0, ge=0)
    last_prediction: Optional[datetime] = None
    
    # Model lineage
    parent_models: List[str] = Field(default_factory=list)
    derived_models: List[str] = Field(default_factory=list)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)


class JobSchedule(BaseSparkModel):
    """Job scheduling configuration model."""
    schedule_name: str = Field(...)
    job_id: str = Field(...)
    
    # Schedule configuration
    cron_expression: str = Field(...)
    timezone: str = Field(default="UTC")
    
    # Schedule state
    is_active: bool = Field(default=True)
    next_run_time: Optional[datetime] = None
    last_run_time: Optional[datetime] = None
    
    # Execution history
    run_count: int = Field(default=0, ge=0)
    success_count: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    
    # Configuration
    max_concurrent_runs: int = Field(default=1, ge=1, le=10)
    retry_on_failure: bool = Field(default=True)
    
    # Metadata
    description: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class StreamingJob(BaseSparkModel):
    """Streaming job configuration model."""
    stream_name: str = Field(...)
    description: Optional[str] = None
    
    # Source configuration
    source_type: str = Field(...)  # kafka, kinesis, tcp, file
    source_config: Dict[str, Any] = Field(...)
    
    # Sink configuration
    sink_type: str = Field(...)  # kafka, console, file, database
    sink_config: Dict[str, Any] = Field(...)
    
    # Processing configuration
    trigger_mode: str = Field(default="ProcessingTime")  # ProcessingTime, Once, Continuous
    trigger_interval: str = Field(default="10 seconds")
    
    # Checkpointing
    checkpoint_location: str = Field(...)
    checkpoint_interval: str = Field(default="10 seconds")
    
    # Watermarking
    watermark_column: Optional[str] = None
    watermark_delay: Optional[str] = None
    
    # Query information
    query_name: str = Field(...)
    output_mode: str = Field(default="append")  # append, update, complete
    
    # State management
    state_timeout: Optional[str] = None
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)


# Factory functions for creating Spark models
def create_spark_job(
    job_name: str,
    job_type: JobType,
    **kwargs
) -> SparkJob:
    """Create a Spark job."""
    return SparkJob(
        job_name=job_name,
        job_type=job_type,
        **kwargs
    )


def create_data_source(
    source_name: str,
    source_type: str,
    connection_string: str,
    format: DataFormat,
    **kwargs
) -> DataSource:
    """Create a data source."""
    return DataSource(
        source_name=source_name,
        source_type=source_type,
        connection_string=connection_string,
        format=format,
        **kwargs
    )


def create_ml_model(
    model_name: str,
    algorithm: MLAlgorithm,
    model_path: str,
    **kwargs
) -> MLModel:
    """Create an ML model."""
    return MLModel(
        model_name=model_name,
        algorithm=algorithm,
        model_path=model_path,
        **kwargs
    )


def create_data_transformation(
    transformation_name: str,
    input_source: Dict[str, Any],
    output_destination: Dict[str, Any],
    **kwargs
) -> DataTransformation:
    """Create a data transformation."""
    return DataTransformation(
        transformation_name=transformation_name,
        input_source=input_source,
        output_destination=output_destination,
        **kwargs
    )


def create_job_schedule(
    schedule_name: str,
    job_id: str,
    cron_expression: str,
    **kwargs
) -> JobSchedule:
    """Create a job schedule."""
    return JobSchedule(
        schedule_name=schedule_name,
        job_id=job_id,
        cron_expression=cron_expression,
        **kwargs
    )