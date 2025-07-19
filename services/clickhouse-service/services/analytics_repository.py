"""
Analytics Repository Service - ClickHouse-based OLAP analytics storage

This service provides comprehensive analytics data storage, retrieval, and analysis
capabilities using ClickHouse as the backend for high-performance OLAP queries.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from clickhouse_driver import Client
from clickhouse_driver.errors import Error as ClickHouseError
import pandas as pd

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.analytics import (
    SecurityEvent, ThreatIntelligence, VulnerabilityAnalysis, NetworkFlow,
    UserBehavior, ComplianceAudit, IncidentAnalysis, BaseAnalyticsModel,
    AnalyticsTable, AnalyticsQuery, AnalyticsResult
)

logger = get_logger(__name__)
metrics = get_metrics()


class AnalyticsRepository:
    """
    Analytics repository for ClickHouse OLAP operations.
    
    This repository provides:
    1. High-performance analytics data ingestion
    2. Complex OLAP queries and aggregations
    3. Real-time analytics capabilities
    4. Data partitioning and optimization
    5. Multi-dimensional analysis
    6. Distributed query processing
    """
    
    def __init__(self):
        self.client: Optional[Client] = None
        self.settings = get_settings()
        
        # ClickHouse connection settings
        self.host = getattr(self.settings, 'clickhouse_host', 'localhost')
        self.port = getattr(self.settings, 'clickhouse_port', 9000)
        self.database = getattr(self.settings, 'clickhouse_database', 'mcp_analytics')
        self.user = getattr(self.settings, 'clickhouse_user', 'default')
        self.password = getattr(self.settings, 'clickhouse_password', '')
        
        # Performance settings
        self.batch_size = 10000
        self.max_block_size = 1048576
        self.max_query_size = 262144
        
        # Table schemas
        self.table_schemas = {
            AnalyticsTable.SECURITY_EVENTS: self._get_security_events_schema(),
            AnalyticsTable.THREAT_INTELLIGENCE: self._get_threat_intelligence_schema(),
            AnalyticsTable.VULNERABILITY_ANALYSIS: self._get_vulnerability_analysis_schema(),
            AnalyticsTable.NETWORK_FLOWS: self._get_network_flows_schema(),
            AnalyticsTable.USER_BEHAVIOR: self._get_user_behavior_schema(),
            AnalyticsTable.COMPLIANCE_AUDIT: self._get_compliance_audit_schema(),
            AnalyticsTable.INCIDENT_ANALYSIS: self._get_incident_analysis_schema(),
        }
        
        logger.info("Analytics repository initialized")
    
    async def initialize(self):
        """Initialize repository with ClickHouse connection."""
        try:
            # Create ClickHouse client
            self.client = Client(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                settings={
                    'max_block_size': self.max_block_size,
                    'max_query_size': self.max_query_size,
                    'connect_timeout': 30,
                    'send_receive_timeout': 300
                }
            )
            
            # Test connection
            await self._test_connection()
            
            # Create database if not exists
            await self._create_database()
            
            # Create tables
            await self._create_tables()
            
            # Setup materialized views
            await self._create_materialized_views()
            
            logger.info("Analytics repository connected to ClickHouse")
            
        except Exception as e:
            logger.error(f"Failed to initialize analytics repository: {e}")
            raise
    
    async def close(self):
        """Close ClickHouse connection."""
        if self.client:
            self.client.disconnect()
            logger.info("Analytics repository connection closed")
    
    @traced("analytics_repository_insert_security_event")
    async def insert_security_event(self, event: SecurityEvent) -> bool:
        """Insert a security event."""
        try:
            data = self._convert_model_to_dict(event)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(
                    f"INSERT INTO {AnalyticsTable.SECURITY_EVENTS} VALUES",
                    [data]
                )
            )
            
            logger.debug(f"Security event inserted: {event.id}")
            metrics.clickhouse_security_events_inserted.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error inserting security event: {e}")
            metrics.clickhouse_insert_errors.inc()
            return False
    
    @traced("analytics_repository_insert_threat_intelligence")
    async def insert_threat_intelligence(self, threat: ThreatIntelligence) -> bool:
        """Insert threat intelligence data."""
        try:
            data = self._convert_model_to_dict(threat)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(
                    f"INSERT INTO {AnalyticsTable.THREAT_INTELLIGENCE} VALUES",
                    [data]
                )
            )
            
            logger.debug(f"Threat intelligence inserted: {threat.id}")
            metrics.clickhouse_threat_intel_inserted.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error inserting threat intelligence: {e}")
            metrics.clickhouse_insert_errors.inc()
            return False
    
    @traced("analytics_repository_insert_vulnerability_analysis")
    async def insert_vulnerability_analysis(self, vuln: VulnerabilityAnalysis) -> bool:
        """Insert vulnerability analysis data."""
        try:
            data = self._convert_model_to_dict(vuln)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(
                    f"INSERT INTO {AnalyticsTable.VULNERABILITY_ANALYSIS} VALUES",
                    [data]
                )
            )
            
            logger.debug(f"Vulnerability analysis inserted: {vuln.id}")
            metrics.clickhouse_vulnerability_analysis_inserted.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error inserting vulnerability analysis: {e}")
            metrics.clickhouse_insert_errors.inc()
            return False
    
    @traced("analytics_repository_insert_network_flow")
    async def insert_network_flow(self, flow: NetworkFlow) -> bool:
        """Insert network flow data."""
        try:
            data = self._convert_model_to_dict(flow)
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(
                    f"INSERT INTO {AnalyticsTable.NETWORK_FLOWS} VALUES",
                    [data]
                )
            )
            
            logger.debug(f"Network flow inserted: {flow.id}")
            metrics.clickhouse_network_flows_inserted.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error inserting network flow: {e}")
            metrics.clickhouse_insert_errors.inc()
            return False
    
    @traced("analytics_repository_batch_insert")
    async def batch_insert(self, table: AnalyticsTable, records: List[BaseAnalyticsModel]) -> int:
        """Insert multiple records in batch."""
        try:
            if not records:
                return 0
            
            # Convert models to dictionaries
            data = [self._convert_model_to_dict(record) for record in records]
            
            # Execute batch insert
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(
                    f"INSERT INTO {table} VALUES",
                    data
                )
            )
            
            logger.info(f"Batch insert completed: {len(records)} records to {table}")
            metrics.clickhouse_batch_inserts.inc()
            metrics.clickhouse_records_inserted.inc(len(records))
            
            return len(records)
            
        except Exception as e:
            logger.error(f"Error in batch insert: {e}")
            metrics.clickhouse_batch_insert_errors.inc()
            return 0
    
    @traced("analytics_repository_execute_query")
    async def execute_query(self, query: AnalyticsQuery) -> AnalyticsResult:
        """Execute an analytics query."""
        try:
            start_time = datetime.now()
            
            # Build SQL query
            sql_query = self._build_sql_query(query)
            
            # Execute query
            result_data = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(sql_query, with_column_types=True)
            )
            
            # Process results
            rows, columns = result_data
            column_names = [col[0] for col in columns]
            
            # Convert to list of dictionaries
            data = []
            for row in rows:
                data.append(dict(zip(column_names, row)))
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Get total rows for pagination
            total_rows = len(data)
            if query.limit:
                count_query = self._build_count_query(query)
                total_result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.execute(count_query)
                )
                total_rows = total_result[0][0] if total_result else 0
            
            result = AnalyticsResult(
                query=query,
                data=data,
                total_rows=total_rows,
                execution_time=execution_time,
                metadata={
                    "sql_query": sql_query,
                    "column_count": len(column_names),
                    "row_count": len(data)
                }
            )
            
            logger.debug(f"Query executed: {len(data)} rows in {execution_time:.3f}s")
            metrics.clickhouse_queries_executed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            metrics.clickhouse_query_errors.inc()
            raise
    
    @traced("analytics_repository_get_security_events")
    async def get_security_events(
        self,
        start_time: datetime,
        end_time: datetime,
        event_types: Optional[List[str]] = None,
        threat_levels: Optional[List[str]] = None,
        source_ips: Optional[List[str]] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get security events with filtering."""
        try:
            conditions = [
                f"timestamp >= '{start_time.isoformat()}'",
                f"timestamp <= '{end_time.isoformat()}'"
            ]
            
            if event_types:
                event_types_str = "', '".join(event_types)
                conditions.append(f"event_type IN ('{event_types_str}')")
            
            if threat_levels:
                threat_levels_str = "', '".join(threat_levels)
                conditions.append(f"threat_level IN ('{threat_levels_str}')")
            
            if source_ips:
                source_ips_str = "', '".join(source_ips)
                conditions.append(f"source_ip IN ('{source_ips_str}')")
            
            query = AnalyticsQuery(
                table=AnalyticsTable.SECURITY_EVENTS,
                where_conditions=conditions,
                order_by=['timestamp DESC'],
                limit=limit
            )
            
            result = await self.execute_query(query)
            return result.data
            
        except Exception as e:
            logger.error(f"Error getting security events: {e}")
            raise
    
    @traced("analytics_repository_get_threat_statistics")
    async def get_threat_statistics(
        self,
        start_time: datetime,
        end_time: datetime,
        group_by: str = "threat_level"
    ) -> List[Dict[str, Any]]:
        """Get threat statistics with grouping."""
        try:
            query = AnalyticsQuery(
                table=AnalyticsTable.SECURITY_EVENTS,
                select_fields=[group_by, "count(*) as count"],
                where_conditions=[
                    f"timestamp >= '{start_time.isoformat()}'",
                    f"timestamp <= '{end_time.isoformat()}'"
                ],
                group_by=[group_by],
                order_by=["count DESC"]
            )
            
            result = await self.execute_query(query)
            return result.data
            
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            raise
    
    @traced("analytics_repository_get_vulnerability_trends")
    async def get_vulnerability_trends(
        self,
        start_time: datetime,
        end_time: datetime,
        time_bucket: str = "1 DAY"
    ) -> List[Dict[str, Any]]:
        """Get vulnerability trends over time."""
        try:
            conditions = [
                f"timestamp >= '{start_time.isoformat()}'",
                f"timestamp <= '{end_time.isoformat()}'"
            ]
            
            query = AnalyticsQuery(
                table=AnalyticsTable.VULNERABILITY_ANALYSIS,
                select_fields=[
                    f"toStartOfInterval(timestamp, INTERVAL {time_bucket}) as time_bucket",
                    "severity_level",
                    "count(*) as count",
                    "avg(risk_score) as avg_risk_score"
                ],
                where_conditions=conditions,
                group_by=["time_bucket", "severity_level"],
                order_by=["time_bucket ASC", "severity_level"]
            )
            
            result = await self.execute_query(query)
            return result.data
            
        except Exception as e:
            logger.error(f"Error getting vulnerability trends: {e}")
            raise
    
    @traced("analytics_repository_get_network_traffic_analysis")
    async def get_network_traffic_analysis(
        self,
        start_time: datetime,
        end_time: datetime,
        aggregation_level: str = "source_ip"
    ) -> List[Dict[str, Any]]:
        """Get network traffic analysis."""
        try:
            conditions = [
                f"timestamp >= '{start_time.isoformat()}'",
                f"timestamp <= '{end_time.isoformat()}'"
            ]
            
            query = AnalyticsQuery(
                table=AnalyticsTable.NETWORK_FLOWS,
                select_fields=[
                    aggregation_level,
                    "count(*) as flow_count",
                    "sum(bytes_sent + bytes_received) as total_bytes",
                    "sum(packets_sent + packets_received) as total_packets",
                    "avg(threat_score) as avg_threat_score",
                    "max(threat_score) as max_threat_score"
                ],
                where_conditions=conditions,
                group_by=[aggregation_level],
                order_by=["total_bytes DESC"],
                limit=100
            )
            
            result = await self.execute_query(query)
            return result.data
            
        except Exception as e:
            logger.error(f"Error getting network traffic analysis: {e}")
            raise
    
    @traced("analytics_repository_get_user_risk_analysis")
    async def get_user_risk_analysis(
        self,
        start_time: datetime,
        end_time: datetime,
        min_risk_score: float = 5.0
    ) -> List[Dict[str, Any]]:
        """Get user risk analysis."""
        try:
            conditions = [
                f"timestamp >= '{start_time.isoformat()}'",
                f"timestamp <= '{end_time.isoformat()}'",
                f"risk_score >= {min_risk_score}"
            ]
            
            query = AnalyticsQuery(
                table=AnalyticsTable.USER_BEHAVIOR,
                select_fields=[
                    "user_id",
                    "username",
                    "department",
                    "avg(risk_score) as avg_risk_score",
                    "max(risk_score) as max_risk_score",
                    "count(*) as activity_count",
                    "sum(data_transfer_bytes) as total_data_transfer"
                ],
                where_conditions=conditions,
                group_by=["user_id", "username", "department"],
                order_by=["avg_risk_score DESC"],
                limit=50
            )
            
            result = await self.execute_query(query)
            return result.data
            
        except Exception as e:
            logger.error(f"Error getting user risk analysis: {e}")
            raise
    
    @traced("analytics_repository_get_compliance_dashboard")
    async def get_compliance_dashboard(
        self,
        framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get compliance dashboard data."""
        try:
            conditions = []
            if framework:
                conditions.append(f"framework = '{framework}'")
            
            # Overall compliance score
            score_query = AnalyticsQuery(
                table=AnalyticsTable.COMPLIANCE_AUDIT,
                select_fields=["avg(compliance_score) as avg_score"],
                where_conditions=conditions
            )
            
            # Compliance by framework
            framework_query = AnalyticsQuery(
                table=AnalyticsTable.COMPLIANCE_AUDIT,
                select_fields=[
                    "framework",
                    "avg(compliance_score) as avg_score",
                    "count(*) as audit_count"
                ],
                group_by=["framework"],
                order_by=["avg_score DESC"]
            )
            
            # Recent findings
            findings_query = AnalyticsQuery(
                table=AnalyticsTable.COMPLIANCE_AUDIT,
                select_fields=[
                    "framework",
                    "control_id",
                    "compliance_status",
                    "critical_findings",
                    "high_findings",
                    "timestamp"
                ],
                where_conditions=conditions + [
                    "timestamp >= now() - INTERVAL 30 DAY"
                ],
                order_by=["timestamp DESC"],
                limit=20
            )
            
            # Execute queries
            score_result = await self.execute_query(score_query)
            framework_result = await self.execute_query(framework_query)
            findings_result = await self.execute_query(findings_query)
            
            return {
                "overall_score": score_result.data[0]["avg_score"] if score_result.data else 0,
                "framework_scores": framework_result.data,
                "recent_findings": findings_result.data
            }
            
        except Exception as e:
            logger.error(f"Error getting compliance dashboard: {e}")
            raise
    
    async def _test_connection(self):
        """Test ClickHouse connection."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute("SELECT 1")
            )
            logger.info("ClickHouse connection test passed")
        except Exception as e:
            logger.error(f"ClickHouse connection test failed: {e}")
            raise
    
    async def _create_database(self):
        """Create database if not exists."""
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            )
            logger.info(f"Database {self.database} created/verified")
        except Exception as e:
            logger.error(f"Error creating database: {e}")
            raise
    
    async def _create_tables(self):
        """Create all analytics tables."""
        try:
            for table, schema in self.table_schemas.items():
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda s=schema: self.client.execute(s)
                )
                logger.info(f"Table {table} created/verified")
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            raise
    
    async def _create_materialized_views(self):
        """Create materialized views for common queries."""
        try:
            # Hourly security events summary
            hourly_events_view = f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {self.database}.security_events_hourly
            ENGINE = SummingMergeTree()
            PARTITION BY toYYYYMM(hour_bucket)
            ORDER BY (hour_bucket, event_type, threat_level)
            AS SELECT
                toStartOfHour(timestamp) as hour_bucket,
                event_type,
                threat_level,
                count() as event_count,
                avg(confidence_score) as avg_confidence
            FROM {self.database}.{AnalyticsTable.SECURITY_EVENTS}
            GROUP BY hour_bucket, event_type, threat_level
            """
            
            # Daily vulnerability summary
            daily_vulns_view = f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {self.database}.vulnerability_daily
            ENGINE = SummingMergeTree()
            PARTITION BY toYYYYMM(day_bucket)
            ORDER BY (day_bucket, severity_level, asset_type)
            AS SELECT
                toDate(timestamp) as day_bucket,
                severity_level,
                asset_type,
                count() as vuln_count,
                avg(risk_score) as avg_risk_score
            FROM {self.database}.{AnalyticsTable.VULNERABILITY_ANALYSIS}
            GROUP BY day_bucket, severity_level, asset_type
            """
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(hourly_events_view)
            )
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.execute(daily_vulns_view)
            )
            
            logger.info("Materialized views created/verified")
            
        except Exception as e:
            logger.error(f"Error creating materialized views: {e}")
    
    def _build_sql_query(self, query: AnalyticsQuery) -> str:
        """Build SQL query from AnalyticsQuery."""
        # SELECT clause
        if query.select_fields:
            select_clause = ", ".join(query.select_fields)
        else:
            select_clause = "*"
        
        # Build aggregations
        if query.aggregations:
            agg_fields = []
            for field, func in query.aggregations.items():
                agg_fields.append(f"{func}({field}) as {field}_{func}")
            if agg_fields:
                select_clause += ", " + ", ".join(agg_fields)
        
        sql = f"SELECT {select_clause} FROM {self.database}.{query.table}"
        
        # WHERE clause
        if query.where_conditions or query.start_time or query.end_time or query.filters:
            conditions = []
            
            # Add explicit conditions
            conditions.extend(query.where_conditions)
            
            # Add time range
            if query.start_time:
                conditions.append(f"timestamp >= '{query.start_time.isoformat()}'")
            if query.end_time:
                conditions.append(f"timestamp <= '{query.end_time.isoformat()}'")
            
            # Add filters
            for field, value in query.filters.items():
                if isinstance(value, list):
                    value_str = "', '".join(str(v) for v in value)
                    conditions.append(f"{field} IN ('{value_str}')")
                else:
                    conditions.append(f"{field} = '{value}'")
            
            if conditions:
                sql += " WHERE " + " AND ".join(conditions)
        
        # GROUP BY clause
        if query.group_by:
            sql += " GROUP BY " + ", ".join(query.group_by)
        
        # ORDER BY clause
        if query.order_by:
            sql += " ORDER BY " + ", ".join(query.order_by)
        
        # LIMIT clause
        if query.limit:
            if query.offset:
                sql += f" LIMIT {query.offset}, {query.limit}"
            else:
                sql += f" LIMIT {query.limit}"
        
        return sql
    
    def _build_count_query(self, query: AnalyticsQuery) -> str:
        """Build count query for pagination."""
        sql = f"SELECT count(*) FROM {self.database}.{query.table}"
        
        if query.where_conditions or query.start_time or query.end_time or query.filters:
            conditions = []
            conditions.extend(query.where_conditions)
            
            if query.start_time:
                conditions.append(f"timestamp >= '{query.start_time.isoformat()}'")
            if query.end_time:
                conditions.append(f"timestamp <= '{query.end_time.isoformat()}'")
            
            for field, value in query.filters.items():
                if isinstance(value, list):
                    value_str = "', '".join(str(v) for v in value)
                    conditions.append(f"{field} IN ('{value_str}')")
                else:
                    conditions.append(f"{field} = '{value}'")
            
            if conditions:
                sql += " WHERE " + " AND ".join(conditions)
        
        return sql
    
    def _convert_model_to_dict(self, model: BaseAnalyticsModel) -> Dict[str, Any]:
        """Convert Pydantic model to dictionary for ClickHouse."""
        data = model.dict()
        
        # Convert datetime objects to strings
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
            elif isinstance(value, (dict, list)) and value:
                data[key] = json.dumps(value)
            elif value is None:
                data[key] = ""
        
        return data
    
    def _get_security_events_schema(self) -> str:
        """Get security events table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.SECURITY_EVENTS} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            event_type String,
            source_ip String,
            destination_ip String,
            source_port Nullable(UInt16),
            destination_port Nullable(UInt16),
            protocol String,
            user_id String,
            username String,
            user_agent String,
            session_id String,
            asset_id String,
            asset_name String,
            asset_type String,
            resource String,
            action String,
            result String,
            threat_level String,
            confidence_score Float32,
            raw_log String,
            tags String,
            attributes String,
            source_country String,
            source_city String,
            source_latitude Nullable(Float32),
            source_longitude Nullable(Float32),
            detection_method String,
            detection_rule String,
            false_positive_probability Nullable(Float32),
            blocked UInt8,
            quarantined UInt8,
            investigated UInt8,
            resolved UInt8,
            processing_time Nullable(Float32),
            detection_time Nullable(Float32),
            response_time Nullable(Float32)
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (timestamp, event_type, threat_level, source_ip)
        TTL timestamp + INTERVAL 2 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def _get_threat_intelligence_schema(self) -> str:
        """Get threat intelligence table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.THREAT_INTELLIGENCE} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            threat_type String,
            threat_family String,
            threat_actor String,
            campaign String,
            ioc_type String,
            ioc_value String,
            confidence_score Float32,
            threat_level String,
            source String,
            source_reliability String,
            first_seen DateTime64(3),
            last_seen DateTime64(3),
            description String,
            ttps String,
            kill_chain_phases String,
            tags String,
            attributes String,
            is_active UInt8,
            is_whitelisted UInt8,
            validation_status String
        ) ENGINE = ReplacingMergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (ioc_type, ioc_value, source)
        TTL timestamp + INTERVAL 5 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def _get_vulnerability_analysis_schema(self) -> str:
        """Get vulnerability analysis table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.VULNERABILITY_ANALYSIS} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            cve_id String,
            vulnerability_id String,
            title String,
            description String,
            cvss_base_score Nullable(Float32),
            cvss_temporal_score Nullable(Float32),
            cvss_environmental_score Nullable(Float32),
            severity_level String,
            asset_id String,
            asset_name String,
            asset_type String,
            asset_criticality String,
            component_name String,
            component_version String,
            component_vendor String,
            status String,
            discovery_date DateTime64(3),
            patch_available UInt8,
            patch_date Nullable(DateTime64(3)),
            remediation_date Nullable(DateTime64(3)),
            exploitability String,
            impact String,
            risk_score Float32,
            business_impact String,
            exploit_available UInt8,
            exploit_in_wild UInt8,
            weaponized UInt8,
            compliance_violations String,
            regulatory_requirements String,
            tags String,
            attributes String
        ) ENGINE = ReplacingMergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (asset_id, vulnerability_id, discovery_date)
        TTL timestamp + INTERVAL 7 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def _get_network_flows_schema(self) -> str:
        """Get network flows table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.NETWORK_FLOWS} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            flow_id String,
            source_ip String,
            destination_ip String,
            source_port UInt16,
            destination_port UInt16,
            protocol String,
            bytes_sent UInt64,
            bytes_received UInt64,
            packets_sent UInt64,
            packets_received UInt64,
            duration Float32,
            flow_direction String,
            flow_type String,
            tcp_flags String,
            is_malicious UInt8,
            is_suspicious UInt8,
            is_encrypted UInt8,
            threat_score Float32,
            source_country String,
            source_asn String,
            destination_country String,
            destination_asn String,
            application_protocol String,
            http_method String,
            http_status_code Nullable(UInt16),
            http_user_agent String,
            dns_query String,
            tls_sni String,
            detection_rules String,
            blocked_by_firewall UInt8,
            blocked_by_ips UInt8,
            tags String,
            attributes String
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (timestamp, source_ip, destination_ip, destination_port)
        TTL timestamp + INTERVAL 1 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def _get_user_behavior_schema(self) -> str:
        """Get user behavior table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.USER_BEHAVIOR} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            user_id String,
            username String,
            user_type String,
            department String,
            role String,
            session_id String,
            session_duration Nullable(Float32),
            source_ip String,
            source_location String,
            device_id String,
            device_type String,
            user_agent String,
            login_count UInt32,
            failed_login_count UInt32,
            resource_access_count UInt32,
            data_transfer_bytes UInt64,
            off_hours_activity UInt8,
            unusual_location UInt8,
            privilege_escalation UInt8,
            data_exfiltration_risk UInt8,
            risk_score Float32,
            anomaly_score Float32,
            baseline_deviation Float32,
            actions_performed String,
            resources_accessed String,
            permissions_used String,
            tags String,
            attributes String
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (timestamp, user_id, source_ip)
        TTL timestamp + INTERVAL 3 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def _get_compliance_audit_schema(self) -> str:
        """Get compliance audit table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.COMPLIANCE_AUDIT} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            audit_id String,
            framework String,
            control_id String,
            control_name String,
            control_category String,
            audit_type String,
            auditor String,
            audit_scope String,
            compliance_status String,
            compliance_score Float32,
            findings_count UInt32,
            critical_findings UInt32,
            high_findings UInt32,
            medium_findings UInt32,
            low_findings UInt32,
            evidence_collected String,
            evidence_quality String,
            remediation_required UInt8,
            remediation_deadline Nullable(DateTime64(3)),
            remediation_status String,
            remediation_effort String,
            risk_level String,
            business_impact String,
            regulatory_impact String,
            tags String,
            attributes String
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (timestamp, framework, control_id)
        TTL timestamp + INTERVAL 10 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def _get_incident_analysis_schema(self) -> str:
        """Get incident analysis table schema."""
        return f"""
        CREATE TABLE IF NOT EXISTS {self.database}.{AnalyticsTable.INCIDENT_ANALYSIS} (
            id String,
            timestamp DateTime64(3),
            date Date,
            hour UInt8,
            incident_id String,
            incident_type String,
            incident_category String,
            title String,
            description String,
            severity String,
            priority String,
            status String,
            created_at DateTime64(3),
            first_response_at Nullable(DateTime64(3)),
            escalated_at Nullable(DateTime64(3)),
            resolved_at Nullable(DateTime64(3)),
            closed_at Nullable(DateTime64(3)),
            detection_time Nullable(Float32),
            response_time Nullable(Float32),
            containment_time Nullable(Float32),
            resolution_time Nullable(Float32),
            affected_systems String,
            affected_users String,
            affected_data String,
            business_impact String,
            financial_impact Nullable(Float32),
            assigned_to String,
            response_team String,
            escalation_level UInt8,
            root_cause String,
            contributing_factors String,
            lessons_learned String,
            remediation_actions String,
            preventive_measures String,
            tags String,
            attributes String
        ) ENGINE = ReplacingMergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (incident_id, timestamp)
        TTL timestamp + INTERVAL 7 YEAR
        SETTINGS index_granularity = 8192
        """
    
    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        return {
            "connection_status": "connected" if self.client else "disconnected",
            "database": self.database,
            "host": self.host,
            "port": self.port,
            "batch_size": self.batch_size,
            "supported_tables": list(self.table_schemas.keys()),
            "operations": [
                "insert_security_event", "insert_threat_intelligence",
                "insert_vulnerability_analysis", "insert_network_flow",
                "batch_insert", "execute_query", "get_security_events",
                "get_threat_statistics", "get_vulnerability_trends",
                "get_network_traffic_analysis", "get_user_risk_analysis",
                "get_compliance_dashboard"
            ]
        }