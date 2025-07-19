"""
Analytics Processor Service - Real-time analytics processing and aggregation

This service handles real-time processing, aggregation, and analysis of security analytics data.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import statistics
import numpy as np
from collections import defaultdict, deque

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.analytics import (
    SecurityEvent, ThreatIntelligence, VulnerabilityAnalysis, NetworkFlow,
    UserBehavior, ComplianceAudit, IncidentAnalysis, BaseAnalyticsModel,
    AnalyticsTable, AnalyticsQuery, EventType, ThreatLevel
)
from .analytics_repository import AnalyticsRepository

logger = get_logger(__name__)
metrics = get_metrics()


class ProcessingMode(str, Enum):
    """Analytics processing modes."""
    REAL_TIME = "real_time"
    BATCH = "batch"
    STREAMING = "streaming"
    HYBRID = "hybrid"


class AggregationLevel(str, Enum):
    """Aggregation time levels."""
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


@dataclass
class ProcessingRule:
    """Analytics processing rule."""
    name: str
    condition: str
    action: str
    priority: int = 1
    enabled: bool = True
    parameters: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


@dataclass
class AggregationRule:
    """Data aggregation rule."""
    source_table: AnalyticsTable
    target_table: str
    aggregation_level: AggregationLevel
    fields: Dict[str, str]  # field_name: aggregation_function
    group_by: List[str]
    filters: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.filters is None:
            self.filters = {}


class AnalyticsProcessor:
    """
    Real-time analytics processor for security data.
    
    This processor:
    1. Processes analytics data in real-time
    2. Performs data enrichment and normalization
    3. Executes aggregation rules
    4. Triggers analytics alerts
    5. Manages data lifecycle
    6. Provides streaming analytics
    """
    
    def __init__(self, repository: AnalyticsRepository, event_bus: EventBus):
        self.repository = repository
        self.event_bus = event_bus
        
        # Processing state
        self.is_running = False
        self.processing_tasks = []
        self.processing_mode = ProcessingMode.HYBRID
        
        # Processing rules
        self.processing_rules: List[ProcessingRule] = []
        self.aggregation_rules: List[AggregationRule] = []
        
        # Data buffers
        self.event_buffers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.batch_buffers: Dict[AnalyticsTable, List[BaseAnalyticsModel]] = defaultdict(list)
        
        # Processing statistics
        self.processing_stats = {
            "events_processed": 0,
            "events_enriched": 0,
            "aggregations_computed": 0,
            "alerts_triggered": 0,
            "processing_errors": 0
        }
        
        # Configuration
        self.batch_size = 1000
        self.batch_timeout = 30  # seconds
        self.enrichment_enabled = True
        self.aggregation_enabled = True
        
        # Initialize default rules
        self._initialize_default_rules()
        
        logger.info("Analytics processor initialized")
    
    async def start(self):
        """Start the analytics processor."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start processing tasks
        if self.processing_mode in [ProcessingMode.REAL_TIME, ProcessingMode.HYBRID]:
            self.processing_tasks.append(asyncio.create_task(self._real_time_processing_loop()))
        
        if self.processing_mode in [ProcessingMode.BATCH, ProcessingMode.HYBRID]:
            self.processing_tasks.append(asyncio.create_task(self._batch_processing_loop()))
        
        if self.processing_mode in [ProcessingMode.STREAMING, ProcessingMode.HYBRID]:
            self.processing_tasks.append(asyncio.create_task(self._streaming_processing_loop()))
        
        # Start aggregation task
        if self.aggregation_enabled:
            self.processing_tasks.append(asyncio.create_task(self._aggregation_loop()))
        
        logger.info(f"Analytics processor started in {self.processing_mode} mode")
    
    async def stop(self):
        """Stop the analytics processor."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        # Cancel all processing tasks
        for task in self.processing_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        # Flush remaining data
        await self._flush_all_buffers()
        
        logger.info("Analytics processor stopped")
    
    @traced("analytics_processor_process_security_event")
    async def process_security_event(self, event: SecurityEvent):
        """Process a security event."""
        try:
            # Apply processing rules
            await self._apply_processing_rules(event)
            
            # Enrich event data
            if self.enrichment_enabled:
                await self._enrich_security_event(event)
            
            # Store in appropriate buffer
            if self.processing_mode == ProcessingMode.REAL_TIME:
                await self.repository.insert_security_event(event)
            else:
                self.batch_buffers[AnalyticsTable.SECURITY_EVENTS].append(event)
            
            # Update statistics
            self.processing_stats["events_processed"] += 1
            
            logger.debug(f"Security event processed: {event.id}")
            metrics.analytics_processor_events_processed.inc()
            
        except Exception as e:
            logger.error(f"Error processing security event: {e}")
            self.processing_stats["processing_errors"] += 1
            metrics.analytics_processor_errors.inc()
    
    @traced("analytics_processor_process_threat_intelligence")
    async def process_threat_intelligence(self, threat: ThreatIntelligence):
        """Process threat intelligence data."""
        try:
            # Apply processing rules
            await self._apply_processing_rules(threat)
            
            # Enrich threat data
            if self.enrichment_enabled:
                await self._enrich_threat_intelligence(threat)
            
            # Store in appropriate buffer
            if self.processing_mode == ProcessingMode.REAL_TIME:
                await self.repository.insert_threat_intelligence(threat)
            else:
                self.batch_buffers[AnalyticsTable.THREAT_INTELLIGENCE].append(threat)
            
            # Update statistics
            self.processing_stats["events_processed"] += 1
            
            logger.debug(f"Threat intelligence processed: {threat.id}")
            metrics.analytics_processor_events_processed.inc()
            
        except Exception as e:
            logger.error(f"Error processing threat intelligence: {e}")
            self.processing_stats["processing_errors"] += 1
            metrics.analytics_processor_errors.inc()
    
    @traced("analytics_processor_process_vulnerability_analysis")
    async def process_vulnerability_analysis(self, vuln: VulnerabilityAnalysis):
        """Process vulnerability analysis data."""
        try:
            # Apply processing rules
            await self._apply_processing_rules(vuln)
            
            # Enrich vulnerability data
            if self.enrichment_enabled:
                await self._enrich_vulnerability_analysis(vuln)
            
            # Store in appropriate buffer
            if self.processing_mode == ProcessingMode.REAL_TIME:
                await self.repository.insert_vulnerability_analysis(vuln)
            else:
                self.batch_buffers[AnalyticsTable.VULNERABILITY_ANALYSIS].append(vuln)
            
            # Update statistics
            self.processing_stats["events_processed"] += 1
            
            logger.debug(f"Vulnerability analysis processed: {vuln.id}")
            metrics.analytics_processor_events_processed.inc()
            
        except Exception as e:
            logger.error(f"Error processing vulnerability analysis: {e}")
            self.processing_stats["processing_errors"] += 1
            metrics.analytics_processor_errors.inc()
    
    @traced("analytics_processor_process_network_flow")
    async def process_network_flow(self, flow: NetworkFlow):
        """Process network flow data."""
        try:
            # Apply processing rules
            await self._apply_processing_rules(flow)
            
            # Enrich network flow data
            if self.enrichment_enabled:
                await self._enrich_network_flow(flow)
            
            # Store in appropriate buffer
            if self.processing_mode == ProcessingMode.REAL_TIME:
                await self.repository.insert_network_flow(flow)
            else:
                self.batch_buffers[AnalyticsTable.NETWORK_FLOWS].append(flow)
            
            # Update statistics
            self.processing_stats["events_processed"] += 1
            
            logger.debug(f"Network flow processed: {flow.id}")
            metrics.analytics_processor_events_processed.inc()
            
        except Exception as e:
            logger.error(f"Error processing network flow: {e}")
            self.processing_stats["processing_errors"] += 1
            metrics.analytics_processor_errors.inc()
    
    @traced("analytics_processor_execute_analytics_query")
    async def execute_analytics_query(self, query: AnalyticsQuery) -> List[Dict[str, Any]]:
        """Execute an analytics query."""
        try:
            result = await self.repository.execute_query(query)
            
            logger.debug(f"Analytics query executed: {len(result.data)} rows")
            metrics.analytics_processor_queries_executed.inc()
            
            return result.data
            
        except Exception as e:
            logger.error(f"Error executing analytics query: {e}")
            metrics.analytics_processor_query_errors.inc()
            raise
    
    @traced("analytics_processor_get_security_dashboard")
    async def get_security_dashboard(
        self,
        time_range: str = "24h",
        include_trends: bool = True
    ) -> Dict[str, Any]:
        """Get comprehensive security dashboard data."""
        try:
            # Parse time range
            end_time = datetime.now(timezone.utc)
            if time_range == "1h":
                start_time = end_time - timedelta(hours=1)
            elif time_range == "24h":
                start_time = end_time - timedelta(hours=24)
            elif time_range == "7d":
                start_time = end_time - timedelta(days=7)
            elif time_range == "30d":
                start_time = end_time - timedelta(days=30)
            else:
                start_time = end_time - timedelta(hours=24)
            
            # Get security events statistics
            events_stats = await self.repository.get_threat_statistics(
                start_time, end_time, "threat_level"
            )
            
            # Get vulnerability trends
            vuln_trends = []
            if include_trends:
                vuln_trends = await self.repository.get_vulnerability_trends(
                    start_time, end_time, "1 HOUR" if time_range == "24h" else "1 DAY"
                )
            
            # Get network traffic analysis
            network_stats = await self.repository.get_network_traffic_analysis(
                start_time, end_time, "destination_port"
            )
            
            # Get compliance dashboard
            compliance_data = await self.repository.get_compliance_dashboard()
            
            # Build dashboard
            dashboard = {
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                    "duration": time_range
                },
                "security_events": {
                    "total": sum(stat["count"] for stat in events_stats),
                    "by_threat_level": events_stats
                },
                "vulnerabilities": {
                    "trends": vuln_trends
                },
                "network": {
                    "top_destinations": network_stats[:10]
                },
                "compliance": compliance_data,
                "processing_stats": self.processing_stats
            }
            
            logger.debug("Security dashboard generated")
            
            return dashboard
            
        except Exception as e:
            logger.error(f"Error generating security dashboard: {e}")
            raise
    
    async def _real_time_processing_loop(self):
        """Real-time processing loop."""
        while self.is_running:
            try:
                # Process events from buffers
                await self._process_real_time_events()
                
                # Small delay to prevent CPU overload
                await asyncio.sleep(0.1)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in real-time processing loop: {e}")
                await asyncio.sleep(1)
    
    async def _batch_processing_loop(self):
        """Batch processing loop."""
        while self.is_running:
            try:
                # Process batches
                await self._process_batches()
                
                # Wait for batch timeout
                await asyncio.sleep(self.batch_timeout)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processing loop: {e}")
                await asyncio.sleep(5)
    
    async def _streaming_processing_loop(self):
        """Streaming processing loop."""
        while self.is_running:
            try:
                # Process streaming data
                await self._process_streaming_data()
                
                # Process interval
                await asyncio.sleep(5)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in streaming processing loop: {e}")
                await asyncio.sleep(5)
    
    async def _aggregation_loop(self):
        """Aggregation processing loop."""
        while self.is_running:
            try:
                # Execute aggregation rules
                await self._execute_aggregation_rules()
                
                # Run aggregations every 5 minutes
                await asyncio.sleep(300)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in aggregation loop: {e}")
                await asyncio.sleep(60)
    
    async def _process_real_time_events(self):
        """Process events in real-time mode."""
        # This would process events from a queue or stream
        # For now, we'll just log the functionality
        pass
    
    async def _process_batches(self):
        """Process data in batches."""
        try:
            for table, buffer in self.batch_buffers.items():
                if len(buffer) >= self.batch_size or self._should_flush_buffer(table):
                    # Process batch
                    batch = buffer[:self.batch_size]
                    buffer[:self.batch_size] = []
                    
                    if batch:
                        success_count = await self.repository.batch_insert(table, batch)
                        logger.info(f"Batch processed: {success_count}/{len(batch)} records to {table}")
                        
        except Exception as e:
            logger.error(f"Error processing batches: {e}")
    
    async def _process_streaming_data(self):
        """Process streaming analytics data."""
        # This would implement streaming analytics
        # For now, we'll just log the functionality
        pass
    
    async def _execute_aggregation_rules(self):
        """Execute all aggregation rules."""
        try:
            for rule in self.aggregation_rules:
                if rule.source_table and rule.target_table:
                    await self._execute_aggregation_rule(rule)
            
            self.processing_stats["aggregations_computed"] += len(self.aggregation_rules)
            
        except Exception as e:
            logger.error(f"Error executing aggregation rules: {e}")
    
    async def _execute_aggregation_rule(self, rule: AggregationRule):
        """Execute a single aggregation rule."""
        try:
            # This would implement the aggregation logic
            # For now, we'll just log the functionality
            logger.debug(f"Executing aggregation rule: {rule.source_table} -> {rule.target_table}")
            
        except Exception as e:
            logger.error(f"Error executing aggregation rule: {e}")
    
    async def _apply_processing_rules(self, event: BaseAnalyticsModel):
        """Apply processing rules to an event."""
        try:
            for rule in self.processing_rules:
                if rule.enabled and self._evaluate_rule_condition(rule, event):
                    await self._execute_rule_action(rule, event)
                    
        except Exception as e:
            logger.error(f"Error applying processing rules: {e}")
    
    def _evaluate_rule_condition(self, rule: ProcessingRule, event: BaseAnalyticsModel) -> bool:
        """Evaluate if a rule condition is met."""
        try:
            # Simple condition evaluation
            # In production, this would be more sophisticated
            if rule.condition == "always":
                return True
            elif rule.condition == "high_threat":
                return hasattr(event, 'threat_level') and event.threat_level in ['high', 'critical']
            elif rule.condition == "suspicious_activity":
                return hasattr(event, 'is_suspicious') and event.is_suspicious
            
            return False
            
        except Exception as e:
            logger.error(f"Error evaluating rule condition: {e}")
            return False
    
    async def _execute_rule_action(self, rule: ProcessingRule, event: BaseAnalyticsModel):
        """Execute a rule action."""
        try:
            if rule.action == "enrich":
                await self._enrich_event(event)
            elif rule.action == "alert":
                await self._trigger_alert(rule, event)
            elif rule.action == "tag":
                await self._tag_event(rule, event)
                
        except Exception as e:
            logger.error(f"Error executing rule action: {e}")
    
    async def _enrich_security_event(self, event: SecurityEvent):
        """Enrich security event with additional data."""
        try:
            # Geolocation enrichment
            if event.source_ip and not event.source_country:
                geo_data = await self._get_geolocation_data(event.source_ip)
                if geo_data:
                    event.source_country = geo_data.get("country")
                    event.source_city = geo_data.get("city")
                    event.source_latitude = geo_data.get("latitude")
                    event.source_longitude = geo_data.get("longitude")
            
            # Threat intelligence enrichment
            if event.source_ip:
                threat_data = await self._get_threat_intelligence(event.source_ip)
                if threat_data:
                    event.threat_level = threat_data.get("threat_level", event.threat_level)
                    event.confidence_score = max(event.confidence_score, threat_data.get("confidence", 0))
            
            self.processing_stats["events_enriched"] += 1
            
        except Exception as e:
            logger.error(f"Error enriching security event: {e}")
    
    async def _enrich_threat_intelligence(self, threat: ThreatIntelligence):
        """Enrich threat intelligence with additional data."""
        try:
            # Attribution enrichment
            if threat.threat_actor and not threat.campaign:
                campaign_data = await self._get_campaign_data(threat.threat_actor)
                if campaign_data:
                    threat.campaign = campaign_data.get("campaign")
            
            self.processing_stats["events_enriched"] += 1
            
        except Exception as e:
            logger.error(f"Error enriching threat intelligence: {e}")
    
    async def _enrich_vulnerability_analysis(self, vuln: VulnerabilityAnalysis):
        """Enrich vulnerability analysis with additional data."""
        try:
            # CVSS scoring enrichment
            if vuln.cve_id and not vuln.cvss_base_score:
                cvss_data = await self._get_cvss_data(vuln.cve_id)
                if cvss_data:
                    vuln.cvss_base_score = cvss_data.get("base_score")
                    vuln.cvss_temporal_score = cvss_data.get("temporal_score")
            
            # Exploit intelligence enrichment
            if vuln.cve_id:
                exploit_data = await self._get_exploit_intelligence(vuln.cve_id)
                if exploit_data:
                    vuln.exploit_available = exploit_data.get("exploit_available", False)
                    vuln.exploit_in_wild = exploit_data.get("exploit_in_wild", False)
            
            self.processing_stats["events_enriched"] += 1
            
        except Exception as e:
            logger.error(f"Error enriching vulnerability analysis: {e}")
    
    async def _enrich_network_flow(self, flow: NetworkFlow):
        """Enrich network flow with additional data."""
        try:
            # Geolocation enrichment
            if flow.source_ip and not flow.source_country:
                geo_data = await self._get_geolocation_data(flow.source_ip)
                if geo_data:
                    flow.source_country = geo_data.get("country")
                    flow.source_asn = geo_data.get("asn")
            
            if flow.destination_ip and not flow.destination_country:
                geo_data = await self._get_geolocation_data(flow.destination_ip)
                if geo_data:
                    flow.destination_country = geo_data.get("country")
                    flow.destination_asn = geo_data.get("asn")
            
            # Application protocol detection
            if not flow.application_protocol:
                app_protocol = await self._detect_application_protocol(flow)
                if app_protocol:
                    flow.application_protocol = app_protocol
            
            self.processing_stats["events_enriched"] += 1
            
        except Exception as e:
            logger.error(f"Error enriching network flow: {e}")
    
    async def _enrich_event(self, event: BaseAnalyticsModel):
        """Generic event enrichment."""
        if isinstance(event, SecurityEvent):
            await self._enrich_security_event(event)
        elif isinstance(event, ThreatIntelligence):
            await self._enrich_threat_intelligence(event)
        elif isinstance(event, VulnerabilityAnalysis):
            await self._enrich_vulnerability_analysis(event)
        elif isinstance(event, NetworkFlow):
            await self._enrich_network_flow(event)
    
    async def _trigger_alert(self, rule: ProcessingRule, event: BaseAnalyticsModel):
        """Trigger an alert based on a rule."""
        try:
            alert_data = {
                "rule_name": rule.name,
                "event_id": event.id,
                "event_type": type(event).__name__,
                "timestamp": event.timestamp.isoformat(),
                "priority": rule.priority,
                "parameters": rule.parameters
            }
            
            # Publish alert event
            await self.event_bus.publish("analytics.alert", alert_data)
            
            self.processing_stats["alerts_triggered"] += 1
            logger.info(f"Alert triggered: {rule.name} for event {event.id}")
            
        except Exception as e:
            logger.error(f"Error triggering alert: {e}")
    
    async def _tag_event(self, rule: ProcessingRule, event: BaseAnalyticsModel):
        """Tag an event based on a rule."""
        try:
            tag_name = rule.parameters.get("tag_name", "processed")
            tag_value = rule.parameters.get("tag_value", "true")
            
            if hasattr(event, 'tags') and isinstance(event.tags, dict):
                event.tags[tag_name] = tag_value
            
        except Exception as e:
            logger.error(f"Error tagging event: {e}")
    
    async def _get_geolocation_data(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geolocation data for IP address."""
        # This would integrate with a geolocation service
        # For now, return mock data
        return {
            "country": "US",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "asn": "AS15169"
        }
    
    async def _get_threat_intelligence(self, ioc: str) -> Optional[Dict[str, Any]]:
        """Get threat intelligence for IOC."""
        # This would integrate with threat intelligence feeds
        # For now, return mock data
        return {
            "threat_level": "medium",
            "confidence": 0.7,
            "last_seen": datetime.now(timezone.utc).isoformat()
        }
    
    async def _get_cvss_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVSS data for CVE."""
        # This would integrate with vulnerability databases
        # For now, return mock data
        return {
            "base_score": 7.5,
            "temporal_score": 6.8,
            "environmental_score": 7.2
        }
    
    async def _get_exploit_intelligence(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get exploit intelligence for CVE."""
        # This would integrate with exploit databases
        # For now, return mock data
        return {
            "exploit_available": True,
            "exploit_in_wild": False,
            "weaponized": False
        }
    
    async def _get_campaign_data(self, threat_actor: str) -> Optional[Dict[str, Any]]:
        """Get campaign data for threat actor."""
        # This would integrate with threat actor databases
        # For now, return mock data
        return {
            "campaign": "APT-Campaign-2024",
            "active": True
        }
    
    async def _detect_application_protocol(self, flow: NetworkFlow) -> Optional[str]:
        """Detect application protocol from network flow."""
        # Simple protocol detection based on port
        port_protocols = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            110: "POP3",
            143: "IMAP"
        }
        
        return port_protocols.get(flow.destination_port)
    
    def _should_flush_buffer(self, table: AnalyticsTable) -> bool:
        """Check if buffer should be flushed."""
        # Check if buffer has been waiting too long
        return len(self.batch_buffers[table]) > 0
    
    async def _flush_all_buffers(self):
        """Flush all remaining data in buffers."""
        for table, buffer in self.batch_buffers.items():
            if buffer:
                await self.repository.batch_insert(table, buffer)
                buffer.clear()
    
    def _initialize_default_rules(self):
        """Initialize default processing rules."""
        # High threat level alert rule
        self.processing_rules.append(ProcessingRule(
            name="high_threat_alert",
            condition="high_threat",
            action="alert",
            priority=1,
            parameters={"alert_type": "security", "severity": "high"}
        ))
        
        # Suspicious activity tagging rule
        self.processing_rules.append(ProcessingRule(
            name="suspicious_activity_tag",
            condition="suspicious_activity",
            action="tag",
            priority=2,
            parameters={"tag_name": "suspicious", "tag_value": "true"}
        ))
        
        # Default aggregation rules
        self.aggregation_rules.append(AggregationRule(
            source_table=AnalyticsTable.SECURITY_EVENTS,
            target_table="security_events_hourly",
            aggregation_level=AggregationLevel.HOUR,
            fields={"event_count": "count", "avg_confidence": "avg"},
            group_by=["event_type", "threat_level"]
        ))
    
    def add_processing_rule(self, rule: ProcessingRule):
        """Add a processing rule."""
        self.processing_rules.append(rule)
        logger.info(f"Processing rule added: {rule.name}")
    
    def add_aggregation_rule(self, rule: AggregationRule):
        """Add an aggregation rule."""
        self.aggregation_rules.append(rule)
        logger.info(f"Aggregation rule added: {rule.source_table} -> {rule.target_table}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            "running": self.is_running,
            "processing_mode": self.processing_mode,
            "processing_stats": self.processing_stats,
            "processing_rules": len(self.processing_rules),
            "aggregation_rules": len(self.aggregation_rules),
            "batch_size": self.batch_size,
            "batch_timeout": self.batch_timeout,
            "enrichment_enabled": self.enrichment_enabled,
            "aggregation_enabled": self.aggregation_enabled,
            "buffer_sizes": {
                table.value: len(buffer) 
                for table, buffer in self.batch_buffers.items()
            }
        }