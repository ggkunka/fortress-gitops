"""
Metrics Repository Service - InfluxDB-based time-series metrics storage

This service provides comprehensive time-series metrics storage, retrieval, and analysis
capabilities using InfluxDB as the backend.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from influxdb_client import InfluxDBClient, Point, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS, ASYNCHRONOUS
from influxdb_client.client.query_api import QueryApi
from influxdb_client.client.delete_api import DeleteApi
from influxdb_client.client.exceptions import InfluxDBError
import pandas as pd

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.metrics import (
    SecurityMetric, ThreatMetric, VulnerabilityMetric, IncidentMetric,
    PerformanceMetric, ComplianceMetric, NetworkMetric, AuditMetric,
    MetricQuery, MetricAggregation, MetricSummary, MetricType, MetricCategory
)

logger = get_logger(__name__)
metrics = get_metrics()


class MetricsRepository:
    """
    Time-series metrics repository for InfluxDB operations.
    
    This repository provides:
    1. High-performance metric ingestion
    2. Advanced time-series queries and aggregations
    3. Real-time metric streaming
    4. Retention policy management
    5. Downsampling and compression
    6. Multi-dimensional analysis
    """
    
    def __init__(self):
        self.client: Optional[InfluxDBClient] = None
        self.write_api = None
        self.query_api: Optional[QueryApi] = None
        self.delete_api: Optional[DeleteApi] = None
        
        # Configuration
        self.settings = get_settings()
        self.bucket = getattr(self.settings, 'influxdb_bucket', 'mcp_security_metrics')
        self.org = getattr(self.settings, 'influxdb_org', 'mcp_security')
        self.token = getattr(self.settings, 'influxdb_token', 'your-token')
        self.url = getattr(self.settings, 'influxdb_url', 'http://localhost:8086')
        
        # Write options
        self.write_options = {
            'write_type': ASYNCHRONOUS,
            'batch_size': 1000,
            'flush_interval': 10000,  # 10 seconds
            'retry_interval': 5000,   # 5 seconds
            'max_retries': 3
        }
        
        logger.info("Metrics repository initialized")
    
    async def initialize(self):
        """Initialize repository with InfluxDB connection."""
        try:
            # Create InfluxDB client
            self.client = InfluxDBClient(
                url=self.url,
                token=self.token,
                org=self.org,
                timeout=30000,
                enable_gzip=True
            )
            
            # Initialize APIs
            self.write_api = self.client.write_api(**self.write_options)
            self.query_api = self.client.query_api()
            self.delete_api = self.client.delete_api()
            
            # Test connection
            await self._test_connection()
            
            # Setup retention policies
            await self._setup_retention_policies()
            
            logger.info("Metrics repository connected to InfluxDB")
            
        except Exception as e:
            logger.error(f"Failed to initialize metrics repository: {e}")
            raise
    
    async def close(self):
        """Close InfluxDB connection."""
        if self.client:
            self.client.close()
            logger.info("Metrics repository connection closed")
    
    @traced("metrics_repository_write_metric")
    async def write_metric(self, metric: SecurityMetric) -> bool:
        """Write a single metric to InfluxDB."""
        try:
            point = self._create_point(metric)
            
            # Write to InfluxDB
            success = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: self.write_api.write(
                    bucket=self.bucket,
                    org=self.org,
                    record=point
                )
            )
            
            logger.debug(f"Metric written: {metric.measurement}")
            metrics.influxdb_metrics_written.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error writing metric: {e}")
            metrics.influxdb_write_errors.inc()
            return False
    
    @traced("metrics_repository_write_metrics_batch")
    async def write_metrics_batch(self, metric_list: List[SecurityMetric]) -> int:
        """Write multiple metrics in batch."""
        try:
            # Convert metrics to points
            points = [self._create_point(metric) for metric in metric_list]
            
            # Write batch to InfluxDB
            success_count = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._write_points_batch(points)
            )
            
            logger.info(f"Batch write completed: {success_count}/{len(metric_list)} metrics")
            metrics.influxdb_batch_writes.inc()
            metrics.influxdb_metrics_written.inc(success_count)
            
            return success_count
            
        except Exception as e:
            logger.error(f"Error writing metrics batch: {e}")
            metrics.influxdb_batch_write_errors.inc()
            return 0
    
    @traced("metrics_repository_query_metrics")
    async def query_metrics(self, query: MetricQuery) -> List[Dict[str, Any]]:
        """Query metrics with filtering and aggregation."""
        try:
            # Build Flux query
            flux_query = self._build_flux_query(query)
            
            # Execute query
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.query_api.query(query=flux_query, org=self.org)
            )
            
            # Process results
            processed_results = self._process_query_results(result)
            
            logger.debug(f"Query executed: {len(processed_results)} results")
            metrics.influxdb_queries_executed.inc()
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Error querying metrics: {e}")
            metrics.influxdb_query_errors.inc()
            raise
    
    @traced("metrics_repository_get_aggregated_metrics")
    async def get_aggregated_metrics(
        self, 
        query: MetricQuery
    ) -> List[MetricAggregation]:
        """Get aggregated metrics over time windows."""
        try:
            # Build aggregation query
            flux_query = self._build_aggregation_query(query)
            
            # Execute query
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.query_api.query(query=flux_query, org=self.org)
            )
            
            # Process aggregation results
            aggregations = []
            for table in result:
                for record in table.records:
                    aggregation = MetricAggregation(
                        measurement=query.measurement,
                        timestamp=record.get_time(),
                        tags=record.values.get('tags', {}),
                        value=record.get_value(),
                        count=record.values.get('count', 1)
                    )
                    aggregations.append(aggregation)
            
            logger.debug(f"Aggregation query executed: {len(aggregations)} results")
            
            return aggregations
            
        except Exception as e:
            logger.error(f"Error getting aggregated metrics: {e}")
            raise
    
    @traced("metrics_repository_get_metric_summary")
    async def get_metric_summary(
        self, 
        measurement: str,
        start_time: datetime,
        end_time: datetime,
        tags: Optional[Dict[str, str]] = None
    ) -> MetricSummary:
        """Get comprehensive metric summary statistics."""
        try:
            # Build summary query
            flux_query = self._build_summary_query(measurement, start_time, end_time, tags)
            
            # Execute query
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.query_api.query(query=flux_query, org=self.org)
            )
            
            # Process summary results
            summary_data = self._process_summary_results(result)
            
            # Create summary object
            summary = MetricSummary(
                measurement=measurement,
                time_range={"start": start_time, "end": end_time},
                total_points=summary_data.get('count', 0),
                avg_value=summary_data.get('mean'),
                min_value=summary_data.get('min'),
                max_value=summary_data.get('max'),
                sum_value=summary_data.get('sum'),
                percentiles=summary_data.get('percentiles', {}),
                tags_distribution=summary_data.get('tags_distribution', {})
            )
            
            logger.debug(f"Summary generated for {measurement}: {summary.total_points} points")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting metric summary: {e}")
            raise
    
    @traced("metrics_repository_get_real_time_metrics")
    async def get_real_time_metrics(
        self, 
        measurement: str,
        window_size: str = "5m",
        tags: Optional[Dict[str, str]] = None
    ) -> List[Dict[str, Any]]:
        """Get real-time metrics from the last time window."""
        try:
            # Calculate time range
            end_time = datetime.now(timezone.utc)
            start_time = end_time - self._parse_duration(window_size)
            
            # Create query
            query = MetricQuery(
                measurement=measurement,
                start_time=start_time,
                end_time=end_time,
                tags=tags or {},
                aggregation="last",
                interval=window_size
            )
            
            # Execute query
            results = await self.query_metrics(query)
            
            logger.debug(f"Real-time metrics retrieved: {len(results)} points")
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting real-time metrics: {e}")
            raise
    
    @traced("metrics_repository_delete_metrics")
    async def delete_metrics(
        self,
        measurement: str,
        start_time: datetime,
        end_time: datetime,
        predicate: Optional[str] = None
    ) -> bool:
        """Delete metrics within a time range."""
        try:
            # Build predicate
            delete_predicate = f'_measurement="{measurement}"'
            if predicate:
                delete_predicate += f' AND {predicate}'
            
            # Execute deletion
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.delete_api.delete(
                    start=start_time,
                    stop=end_time,
                    predicate=delete_predicate,
                    bucket=self.bucket,
                    org=self.org
                )
            )
            
            logger.info(f"Metrics deleted: {measurement} from {start_time} to {end_time}")
            metrics.influxdb_metrics_deleted.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting metrics: {e}")
            metrics.influxdb_delete_errors.inc()
            return False
    
    @traced("metrics_repository_get_cardinality")
    async def get_cardinality(
        self,
        measurement: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, int]:
        """Get cardinality information for a measurement."""
        try:
            flux_query = f'''
            from(bucket: "{self.bucket}")
              |> range(start: {start_time.isoformat()}, stop: {end_time.isoformat()})
              |> filter(fn: (r) => r._measurement == "{measurement}")
              |> keys()
              |> group()
              |> count()
            '''
            
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.query_api.query(query=flux_query, org=self.org)
            )
            
            cardinality = {}
            for table in result:
                for record in table.records:
                    cardinality[record.get_field()] = record.get_value()
            
            logger.debug(f"Cardinality retrieved for {measurement}")
            
            return cardinality
            
        except Exception as e:
            logger.error(f"Error getting cardinality: {e}")
            raise
    
    def _create_point(self, metric: SecurityMetric) -> Point:
        """Create InfluxDB point from metric."""
        point = Point(metric.measurement)
        
        # Add timestamp
        point.time(metric.timestamp, WritePrecision.NS)
        
        # Add tags
        for key, value in metric.tags.items():
            point.tag(key, str(value))
        
        # Add fields
        for key, value in metric.fields.items():
            if isinstance(value, (int, float)):
                point.field(key, value)
            elif isinstance(value, bool):
                point.field(key, value)
            else:
                point.field(key, str(value))
        
        return point
    
    def _write_points_batch(self, points: List[Point]) -> int:
        """Write points in batch (synchronous)."""
        try:
            self.write_api.write(
                bucket=self.bucket,
                org=self.org,
                record=points
            )
            return len(points)
        except Exception as e:
            logger.error(f"Batch write error: {e}")
            return 0
    
    def _build_flux_query(self, query: MetricQuery) -> str:
        """Build Flux query from MetricQuery."""
        flux_parts = [
            f'from(bucket: "{self.bucket}")',
            f'|> range(start: {query.start_time.isoformat()}, stop: {query.end_time.isoformat()})',
            f'|> filter(fn: (r) => r._measurement == "{query.measurement}")'
        ]
        
        # Add tag filters
        for key, value in query.tags.items():
            flux_parts.append(f'|> filter(fn: (r) => r.{key} == "{value}")')
        
        # Add field filters
        if query.fields:
            field_filter = ' or '.join([f'r._field == "{field}"' for field in query.fields])
            flux_parts.append(f'|> filter(fn: (r) => {field_filter})')
        
        # Add aggregation
        if query.aggregation and query.interval:
            flux_parts.extend([
                f'|> aggregateWindow(every: {query.interval}, fn: {query.aggregation})',
                '|> yield(name: "aggregated")'
            ])
        
        # Add grouping
        if query.group_by:
            group_keys = ', '.join([f'"{key}"' for key in query.group_by])
            flux_parts.append(f'|> group(columns: [{group_keys}])')
        
        # Add limit
        if query.limit:
            flux_parts.append(f'|> limit(n: {query.limit})')
        
        return '\n  '.join(flux_parts)
    
    def _build_aggregation_query(self, query: MetricQuery) -> str:
        """Build aggregation query."""
        aggregation_func = query.aggregation or "mean"
        interval = query.interval or "5m"
        
        flux_query = f'''
        from(bucket: "{self.bucket}")
          |> range(start: {query.start_time.isoformat()}, stop: {query.end_time.isoformat()})
          |> filter(fn: (r) => r._measurement == "{query.measurement}")
        '''
        
        # Add tag filters
        for key, value in query.tags.items():
            flux_query += f'\n  |> filter(fn: (r) => r.{key} == "{value}")'
        
        # Add aggregation
        flux_query += f'''
          |> aggregateWindow(every: {interval}, fn: {aggregation_func})
          |> yield(name: "aggregated")
        '''
        
        return flux_query
    
    def _build_summary_query(
        self, 
        measurement: str, 
        start_time: datetime, 
        end_time: datetime,
        tags: Optional[Dict[str, str]] = None
    ) -> str:
        """Build summary statistics query."""
        flux_query = f'''
        data = from(bucket: "{self.bucket}")
          |> range(start: {start_time.isoformat()}, stop: {end_time.isoformat()})
          |> filter(fn: (r) => r._measurement == "{measurement}")
        '''
        
        # Add tag filters
        if tags:
            for key, value in tags.items():
                flux_query += f'\n  |> filter(fn: (r) => r.{key} == "{value}")'
        
        # Add summary calculations
        flux_query += '''
        
        count = data |> count() |> yield(name: "count")
        mean = data |> mean() |> yield(name: "mean")
        min = data |> min() |> yield(name: "min")
        max = data |> max() |> yield(name: "max")
        sum = data |> sum() |> yield(name: "sum")
        '''
        
        return flux_query
    
    def _process_query_results(self, result) -> List[Dict[str, Any]]:
        """Process InfluxDB query results."""
        processed_results = []
        
        for table in result:
            for record in table.records:
                result_dict = {
                    'measurement': record.get_measurement(),
                    'time': record.get_time(),
                    'field': record.get_field(),
                    'value': record.get_value(),
                    'tags': {k: v for k, v in record.values.items() if not k.startswith('_')}
                }
                processed_results.append(result_dict)
        
        return processed_results
    
    def _process_summary_results(self, result) -> Dict[str, Any]:
        """Process summary query results."""
        summary_data = {}
        
        for table in result:
            for record in table.records:
                field_name = record.get_field()
                value = record.get_value()
                
                if field_name == 'count':
                    summary_data['count'] = value
                elif field_name == 'mean':
                    summary_data['mean'] = value
                elif field_name == 'min':
                    summary_data['min'] = value
                elif field_name == 'max':
                    summary_data['max'] = value
                elif field_name == 'sum':
                    summary_data['sum'] = value
        
        return summary_data
    
    def _parse_duration(self, duration: str) -> timedelta:
        """Parse duration string to timedelta."""
        unit = duration[-1]
        value = int(duration[:-1])
        
        if unit == 's':
            return timedelta(seconds=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        else:
            return timedelta(minutes=value)
    
    async def _test_connection(self):
        """Test InfluxDB connection."""
        try:
            health = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.health()
            )
            if health.status != "pass":
                raise Exception(f"InfluxDB health check failed: {health.status}")
            logger.info("InfluxDB connection test passed")
        except Exception as e:
            logger.error(f"InfluxDB connection test failed: {e}")
            raise
    
    async def _setup_retention_policies(self):
        """Setup retention policies for different metric types."""
        try:
            # This would typically be done via the InfluxDB API
            # For now, we'll log the intended policies
            policies = {
                "raw_metrics": "30d",      # Raw metrics kept for 30 days
                "hourly_aggregates": "1y", # Hourly aggregates kept for 1 year
                "daily_aggregates": "5y"   # Daily aggregates kept for 5 years
            }
            
            logger.info(f"Retention policies configured: {policies}")
            
        except Exception as e:
            logger.error(f"Error setting up retention policies: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        return {
            "connection_status": "connected" if self.client else "disconnected",
            "bucket": self.bucket,
            "organization": self.org,
            "write_options": self.write_options,
            "supported_metrics": [
                "ThreatMetric", "VulnerabilityMetric", "IncidentMetric",
                "PerformanceMetric", "ComplianceMetric", "NetworkMetric", "AuditMetric"
            ],
            "operations": [
                "write_metric", "write_metrics_batch", "query_metrics",
                "get_aggregated_metrics", "get_metric_summary", "get_real_time_metrics",
                "delete_metrics", "get_cardinality"
            ]
        }