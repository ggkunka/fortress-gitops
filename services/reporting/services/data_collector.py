"""
Data Collector - Data Collection and Aggregation Service

This service collects data from various sources for report generation,
including correlation results, risk assessments, incidents, and metrics.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID

import asyncpg
import aioredis
from elasticsearch import AsyncElasticsearch
import httpx

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.reporting import ReportTemplate, ReportData, get_db

logger = get_logger(__name__)
metrics = get_metrics()


class DataCollector:
    """
    Data collection service that aggregates data from multiple sources
    for report generation.
    
    This collector:
    1. Connects to various data sources
    2. Executes queries and aggregations
    3. Caches results for performance
    4. Transforms data for reporting
    """
    
    def __init__(self):
        self.settings = get_settings()
        
        # Database connections
        self.pg_pool = None
        self.redis_client = None
        self.es_client = None
        
        # HTTP client for API calls
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # Data cache
        self.cache_ttl = 300  # 5 minutes
        
        logger.info("Data collector initialized")
    
    async def start(self):
        """Start data collector connections."""
        try:
            # Initialize PostgreSQL connection pool
            self.pg_pool = await asyncpg.create_pool(
                self.settings.database_url,
                min_size=5,
                max_size=20
            )
            
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            
            # Initialize Elasticsearch client
            if hasattr(self.settings, 'elasticsearch_url'):
                self.es_client = AsyncElasticsearch([self.settings.elasticsearch_url])
            
            logger.info("Data collector started")
            
        except Exception as e:
            logger.error(f"Error starting data collector: {e}")
            raise
    
    async def stop(self):
        """Stop data collector connections."""
        if self.pg_pool:
            await self.pg_pool.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        if self.es_client:
            await self.es_client.close()
        
        await self.http_client.aclose()
        
        logger.info("Data collector stopped")
    
    @traced("data_collector_collect_security_metrics")
    async def collect_security_metrics(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect security metrics data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"security_metrics:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # Collect correlation data
            correlation_data = await self._collect_correlation_data(start_date, end_date, filters)
            
            # Collect incident data
            incident_data = await self._collect_incident_data(start_date, end_date, filters)
            
            # Collect risk data
            risk_data = await self._collect_risk_data(start_date, end_date, filters)
            
            # Aggregate security metrics
            security_metrics = {
                "total_incidents": incident_data.get("total_incidents", 0),
                "high_severity_incidents": incident_data.get("high_severity_incidents", 0),
                "avg_response_time": incident_data.get("avg_response_time", 0),
                "security_score": self._calculate_security_score(correlation_data, incident_data, risk_data),
                "correlation_results": correlation_data.get("total_correlations", 0),
                "risk_assessments": risk_data.get("total_assessments", 0),
                "incident_severity": incident_data.get("severity_distribution", {}),
                "incident_trend": incident_data.get("trend_data", []),
                "attack_types": incident_data.get("attack_types", {}),
                "top_threats": correlation_data.get("top_threats", []),
                "detection_rate": correlation_data.get("detection_rate", 0),
                "false_positive_rate": correlation_data.get("false_positive_rate", 0)
            }
            
            # Cache the result
            await self._cache_data(cache_key, security_metrics)
            
            return security_metrics
            
        except Exception as e:
            logger.error(f"Error collecting security metrics: {e}")
            raise
    
    @traced("data_collector_collect_risk_assessment_data")
    async def collect_risk_assessment_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect risk assessment data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"risk_assessment_data:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # Query risk assessments
            async with self.pg_pool.acquire() as conn:
                # Get risk assessments
                assessments_query = """
                    SELECT id, title, risk_level, risk_score, confidence_score, 
                           risk_category, created_at, status
                    FROM risk_assessments 
                    WHERE created_at >= $1 AND created_at <= $2
                """
                
                params = [start_date, end_date]
                
                # Apply filters
                if filters.get("risk_level"):
                    assessments_query += " AND risk_level = $3"
                    params.append(filters["risk_level"])
                
                if filters.get("risk_category"):
                    assessments_query += f" AND risk_category = ${len(params) + 1}"
                    params.append(filters["risk_category"])
                
                assessments = await conn.fetch(assessments_query, *params)
                
                # Get risk metrics
                metrics_query = """
                    SELECT 
                        COUNT(*) as total_assessments,
                        COUNT(CASE WHEN risk_level IN ('high', 'critical') THEN 1 END) as high_risk_items,
                        AVG(risk_score) as avg_risk_score,
                        MIN(risk_score) as min_risk_score,
                        MAX(risk_score) as max_risk_score
                    FROM risk_assessments 
                    WHERE created_at >= $1 AND created_at <= $2
                """
                
                risk_metrics = await conn.fetchrow(metrics_query, start_date, end_date)
                
                # Get risk distribution
                distribution_query = """
                    SELECT risk_level, COUNT(*) as count
                    FROM risk_assessments 
                    WHERE created_at >= $1 AND created_at <= $2
                    GROUP BY risk_level
                """
                
                risk_distribution = await conn.fetch(distribution_query, start_date, end_date)
                
                # Get risk trend
                trend_query = """
                    SELECT DATE_TRUNC('day', created_at) as date, AVG(risk_score) as avg_score
                    FROM risk_assessments 
                    WHERE created_at >= $1 AND created_at <= $2
                    GROUP BY DATE_TRUNC('day', created_at)
                    ORDER BY date
                """
                
                risk_trend = await conn.fetch(trend_query, start_date, end_date)
                
                # Get recommendations
                recommendations_query = """
                    SELECT rm.mitigation_name, rm.description, rm.effectiveness_score, rm.priority
                    FROM risk_mitigations rm
                    JOIN risk_assessments ra ON rm.assessment_id = ra.id
                    WHERE ra.created_at >= $1 AND ra.created_at <= $2
                    AND rm.status = 'recommended'
                    ORDER BY rm.priority DESC, rm.effectiveness_score DESC
                    LIMIT 20
                """
                
                recommendations = await conn.fetch(recommendations_query, start_date, end_date)
            
            # Format data
            risk_data = {
                "total_assessments": risk_metrics["total_assessments"],
                "high_risk_items": risk_metrics["high_risk_items"],
                "avg_risk_score": float(risk_metrics["avg_risk_score"]) if risk_metrics["avg_risk_score"] else 0,
                "min_risk_score": float(risk_metrics["min_risk_score"]) if risk_metrics["min_risk_score"] else 0,
                "max_risk_score": float(risk_metrics["max_risk_score"]) if risk_metrics["max_risk_score"] else 0,
                "risk_trend": self._calculate_risk_trend(risk_trend),
                "risk_distribution": {row["risk_level"]: row["count"] for row in risk_distribution},
                "assessments": [dict(row) for row in assessments],
                "recommendations": [dict(row) for row in recommendations]
            }
            
            # Cache the result
            await self._cache_data(cache_key, risk_data)
            
            return risk_data
            
        except Exception as e:
            logger.error(f"Error collecting risk assessment data: {e}")
            raise
    
    @traced("data_collector_collect_incident_data")
    async def collect_incident_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect incident data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"incident_data:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # Query incidents
            async with self.pg_pool.acquire() as conn:
                # Get incidents
                incidents_query = """
                    SELECT id, title, severity, status, incident_type, 
                           detected_at, acknowledged_at, resolved_at, 
                           response_time, resolution_time, impact_score
                    FROM incidents 
                    WHERE detected_at >= $1 AND detected_at <= $2
                """
                
                params = [start_date, end_date]
                
                # Apply filters
                if filters.get("severity"):
                    incidents_query += " AND severity = $3"
                    params.append(filters["severity"])
                
                if filters.get("status"):
                    incidents_query += f" AND status = ${len(params) + 1}"
                    params.append(filters["status"])
                
                incidents = await conn.fetch(incidents_query, *params)
                
                # Get incident metrics
                metrics_query = """
                    SELECT 
                        COUNT(*) as total_incidents,
                        COUNT(CASE WHEN severity IN ('high', 'critical') THEN 1 END) as high_severity_incidents,
                        COUNT(CASE WHEN status = 'resolved' THEN 1 END) as resolved_incidents,
                        AVG(response_time) as avg_response_time,
                        AVG(resolution_time) as avg_resolution_time
                    FROM incidents 
                    WHERE detected_at >= $1 AND detected_at <= $2
                """
                
                incident_metrics = await conn.fetchrow(metrics_query, start_date, end_date)
                
                # Get severity distribution
                severity_query = """
                    SELECT severity, COUNT(*) as count
                    FROM incidents 
                    WHERE detected_at >= $1 AND detected_at <= $2
                    GROUP BY severity
                """
                
                severity_distribution = await conn.fetch(severity_query, start_date, end_date)
                
                # Get incident trend
                trend_query = """
                    SELECT DATE_TRUNC('day', detected_at) as date, COUNT(*) as count
                    FROM incidents 
                    WHERE detected_at >= $1 AND detected_at <= $2
                    GROUP BY DATE_TRUNC('day', detected_at)
                    ORDER BY date
                """
                
                incident_trend = await conn.fetch(trend_query, start_date, end_date)
                
                # Get attack types
                attack_types_query = """
                    SELECT incident_type, COUNT(*) as count
                    FROM incidents 
                    WHERE detected_at >= $1 AND detected_at <= $2
                    GROUP BY incident_type
                    ORDER BY count DESC
                    LIMIT 10
                """
                
                attack_types = await conn.fetch(attack_types_query, start_date, end_date)
            
            # Format data
            incident_data = {
                "total_incidents": incident_metrics["total_incidents"],
                "high_severity_incidents": incident_metrics["high_severity_incidents"],
                "resolved_incidents": incident_metrics["resolved_incidents"],
                "avg_response_time": float(incident_metrics["avg_response_time"]) if incident_metrics["avg_response_time"] else 0,
                "avg_resolution_time": float(incident_metrics["avg_resolution_time"]) if incident_metrics["avg_resolution_time"] else 0,
                "mttr": float(incident_metrics["avg_resolution_time"]) if incident_metrics["avg_resolution_time"] else 0,
                "severity_distribution": {row["severity"]: row["count"] for row in severity_distribution},
                "trend_data": [{"date": row["date"], "count": row["count"]} for row in incident_trend],
                "attack_types": {row["incident_type"]: row["count"] for row in attack_types},
                "incidents": [dict(row) for row in incidents]
            }
            
            # Cache the result
            await self._cache_data(cache_key, incident_data)
            
            return incident_data
            
        except Exception as e:
            logger.error(f"Error collecting incident data: {e}")
            raise
    
    @traced("data_collector_collect_compliance_data")
    async def collect_compliance_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect compliance data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"compliance_data:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # For now, return sample compliance data
            # In a real implementation, this would query compliance monitoring systems
            compliance_data = {
                "overall_score": 85,
                "frameworks": ["SOC2", "ISO27001", "GDPR"],
                "violations": 5,
                "remediation_items": 12,
                "compliance_score": 85,
                "control_effectiveness": 78,
                "audit_findings": 3,
                "remediation_rate": 90,
                "compliance_items": [
                    {"framework": "SOC2", "control": "CC6.1", "status": "compliant"},
                    {"framework": "ISO27001", "control": "A.12.1.1", "status": "non-compliant"},
                    {"framework": "GDPR", "control": "Art.32", "status": "compliant"}
                ],
                "violation_details": [
                    {"control": "A.12.1.1", "description": "Change management process", "severity": "medium"},
                    {"control": "CC6.3", "description": "Logical access controls", "severity": "high"}
                ],
                "remediation_plan": [
                    {"item": "Implement change management", "priority": "high", "due_date": "2024-02-15"},
                    {"item": "Review access controls", "priority": "medium", "due_date": "2024-02-28"}
                ]
            }
            
            # Cache the result
            await self._cache_data(cache_key, compliance_data)
            
            return compliance_data
            
        except Exception as e:
            logger.error(f"Error collecting compliance data: {e}")
            raise
    
    @traced("data_collector_collect_threat_intelligence_data")
    async def collect_threat_intelligence_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect threat intelligence data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"threat_intelligence_data:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # For now, return sample threat intelligence data
            # In a real implementation, this would query threat intelligence feeds
            threat_data = {
                "active_threats": 25,
                "new_threats": 5,
                "threat_level": "medium",
                "campaigns": ["APT29", "Lazarus", "FIN7"],
                "threats": [
                    {"name": "APT29", "severity": "high", "last_seen": "2024-01-15"},
                    {"name": "Lazarus", "severity": "critical", "last_seen": "2024-01-10"},
                    {"name": "FIN7", "severity": "medium", "last_seen": "2024-01-12"}
                ],
                "iocs": [
                    {"type": "ip", "value": "192.168.1.100", "confidence": 85},
                    {"type": "domain", "value": "malicious.com", "confidence": 90},
                    {"type": "hash", "value": "abc123def456", "confidence": 95}
                ],
                "ttps": [
                    {"id": "T1566", "technique": "Phishing", "count": 15},
                    {"id": "T1055", "technique": "Process Injection", "count": 8},
                    {"id": "T1059", "technique": "Command and Scripting", "count": 12}
                ],
                "recommendations": [
                    {"priority": "high", "description": "Update email security policies"},
                    {"priority": "medium", "description": "Enhance endpoint detection"}
                ]
            }
            
            # Cache the result
            await self._cache_data(cache_key, threat_data)
            
            return threat_data
            
        except Exception as e:
            logger.error(f"Error collecting threat intelligence data: {e}")
            raise
    
    @traced("data_collector_collect_performance_data")
    async def collect_performance_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect performance data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"performance_data:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # For now, return sample performance data
            # In a real implementation, this would query monitoring systems
            performance_data = {
                "avg_response_time": 250,  # ms
                "throughput": 1000,  # requests/second
                "error_rate": 0.5,  # percentage
                "availability": 99.9,  # percentage
                "metrics": [
                    {"timestamp": "2024-01-15T10:00:00Z", "response_time": 245, "throughput": 1050},
                    {"timestamp": "2024-01-15T11:00:00Z", "response_time": 255, "throughput": 950}
                ],
                "sla_metrics": {
                    "response_time_sla": 500,  # ms
                    "availability_sla": 99.5,  # percentage
                    "sla_compliance": 98.5  # percentage
                },
                "capacity_planning": {
                    "current_utilization": 65,  # percentage
                    "projected_growth": 15,  # percentage
                    "capacity_headroom": 20  # percentage
                }
            }
            
            # Cache the result
            await self._cache_data(cache_key, performance_data)
            
            return performance_data
            
        except Exception as e:
            logger.error(f"Error collecting performance data: {e}")
            raise
    
    @traced("data_collector_collect_executive_summary_data")
    async def collect_executive_summary_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect executive summary data."""
        try:
            filters = filters or {}
            
            # Check cache first
            cache_key = f"executive_summary_data:{start_date}:{end_date}:{hash(str(filters))}"
            cached_data = await self._get_cached_data(cache_key)
            if cached_data:
                return cached_data
            
            # Collect data from various sources
            security_data = await self.collect_security_metrics(start_date, end_date, filters)
            risk_data = await self.collect_risk_assessment_data(start_date, end_date, filters)
            incident_data = await self.collect_incident_data(start_date, end_date, filters)
            
            # Generate executive summary
            executive_data = {
                "security_posture": self._assess_security_posture(security_data),
                "risk_level": self._assess_risk_level(risk_data),
                "key_achievements": [
                    f"Resolved {incident_data['resolved_incidents']} incidents",
                    f"Maintained {security_data['security_score']}% security score",
                    f"Completed {risk_data['total_assessments']} risk assessments"
                ],
                "critical_issues": [
                    f"{incident_data['high_severity_incidents']} high-severity incidents",
                    f"{risk_data['high_risk_items']} high-risk items identified"
                ],
                "kpis": {
                    "security_score": security_data["security_score"],
                    "incident_resolution_rate": incident_data["resolved_incidents"] / max(incident_data["total_incidents"], 1) * 100,
                    "avg_response_time": incident_data["avg_response_time"],
                    "risk_reduction": 15  # percentage
                },
                "recommendations": [
                    "Enhance threat detection capabilities",
                    "Improve incident response procedures",
                    "Strengthen access controls"
                ]
            }
            
            # Cache the result
            await self._cache_data(cache_key, executive_data)
            
            return executive_data
            
        except Exception as e:
            logger.error(f"Error collecting executive summary data: {e}")
            raise
    
    async def collect_template_data(
        self,
        template: ReportTemplate,
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect data based on template configuration."""
        try:
            # Execute template-specific data collection
            # This would use template.data_queries and template.data_sources
            # For now, return empty data
            return {"records": [], "metadata": {}}
            
        except Exception as e:
            logger.error(f"Error collecting template data: {e}")
            raise
    
    async def collect_custom_data(
        self,
        data_sources: List[str],
        start_date: datetime,
        end_date: datetime,
        filters: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Collect custom data from specified sources."""
        try:
            # Execute custom data collection
            # This would query the specified data sources
            # For now, return empty data
            return {"records": [], "metadata": {}}
            
        except Exception as e:
            logger.error(f"Error collecting custom data: {e}")
            raise
    
    # Helper methods
    async def _collect_correlation_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Collect correlation data."""
        try:
            async with self.pg_pool.acquire() as conn:
                # Query correlation results
                query = """
                    SELECT COUNT(*) as total_correlations,
                           COUNT(CASE WHEN severity IN ('high', 'critical') THEN 1 END) as high_severity_correlations,
                           AVG(confidence) as avg_confidence,
                           COUNT(CASE WHEN status = 'false_positive' THEN 1 END) as false_positives
                    FROM correlation_results 
                    WHERE created_at >= $1 AND created_at <= $2
                """
                
                result = await conn.fetchrow(query, start_date, end_date)
                
                return {
                    "total_correlations": result["total_correlations"],
                    "high_severity_correlations": result["high_severity_correlations"],
                    "avg_confidence": float(result["avg_confidence"]) if result["avg_confidence"] else 0,
                    "false_positives": result["false_positives"],
                    "detection_rate": 95,  # placeholder
                    "false_positive_rate": 5,  # placeholder
                    "top_threats": ["Brute Force", "Port Scan", "Malware"]
                }
                
        except Exception as e:
            logger.error(f"Error collecting correlation data: {e}")
            return {}
    
    async def _collect_risk_data(
        self,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Collect risk data."""
        try:
            async with self.pg_pool.acquire() as conn:
                query = """
                    SELECT COUNT(*) as total_assessments,
                           AVG(risk_score) as avg_risk_score
                    FROM risk_assessments 
                    WHERE created_at >= $1 AND created_at <= $2
                """
                
                result = await conn.fetchrow(query, start_date, end_date)
                
                return {
                    "total_assessments": result["total_assessments"],
                    "avg_risk_score": float(result["avg_risk_score"]) if result["avg_risk_score"] else 0
                }
                
        except Exception as e:
            logger.error(f"Error collecting risk data: {e}")
            return {}
    
    async def _get_cached_data(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data."""
        try:
            if self.redis_client:
                cached = await self.redis_client.get(key)
                if cached:
                    import json
                    return json.loads(cached)
            return None
        except Exception as e:
            logger.warning(f"Error getting cached data: {e}")
            return None
    
    async def _cache_data(self, key: str, data: Dict[str, Any]):
        """Cache data."""
        try:
            if self.redis_client:
                import json
                await self.redis_client.setex(
                    key,
                    self.cache_ttl,
                    json.dumps(data, default=str)
                )
        except Exception as e:
            logger.warning(f"Error caching data: {e}")
    
    def _calculate_security_score(
        self,
        correlation_data: Dict[str, Any],
        incident_data: Dict[str, Any],
        risk_data: Dict[str, Any]
    ) -> float:
        """Calculate overall security score."""
        try:
            # Simple scoring algorithm
            base_score = 100
            
            # Deduct points for high severity incidents
            high_incidents = incident_data.get("high_severity_incidents", 0)
            base_score -= high_incidents * 5
            
            # Deduct points for low detection rate
            detection_rate = correlation_data.get("detection_rate", 100)
            base_score -= (100 - detection_rate) * 0.5
            
            # Deduct points for high false positive rate
            fp_rate = correlation_data.get("false_positive_rate", 0)
            base_score -= fp_rate * 0.3
            
            return max(0, min(100, base_score))
            
        except Exception as e:
            logger.error(f"Error calculating security score: {e}")
            return 75  # default score
    
    def _calculate_risk_trend(self, trend_data: List[Dict[str, Any]]) -> str:
        """Calculate risk trend."""
        try:
            if len(trend_data) < 2:
                return "stable"
            
            # Compare first and last values
            first_score = trend_data[0]["avg_score"]
            last_score = trend_data[-1]["avg_score"]
            
            if last_score > first_score * 1.1:
                return "increasing"
            elif last_score < first_score * 0.9:
                return "decreasing"
            else:
                return "stable"
                
        except Exception as e:
            logger.error(f"Error calculating risk trend: {e}")
            return "stable"
    
    def _assess_security_posture(self, security_data: Dict[str, Any]) -> str:
        """Assess security posture."""
        score = security_data.get("security_score", 0)
        
        if score >= 90:
            return "excellent"
        elif score >= 75:
            return "good"
        elif score >= 60:
            return "fair"
        else:
            return "poor"
    
    def _assess_risk_level(self, risk_data: Dict[str, Any]) -> str:
        """Assess overall risk level."""
        avg_score = risk_data.get("avg_risk_score", 0)
        
        if avg_score >= 80:
            return "high"
        elif avg_score >= 60:
            return "medium"
        else:
            return "low"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics."""
        return {
            "cache_ttl": self.cache_ttl,
            "has_postgres": self.pg_pool is not None,
            "has_redis": self.redis_client is not None,
            "has_elasticsearch": self.es_client is not None
        }