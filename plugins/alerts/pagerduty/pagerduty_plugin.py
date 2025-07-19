"""
PagerDuty Alert Plugin - Incident management and on-call notification integration

This plugin integrates with PagerDuty's Events API to create incidents,
send alerts to on-call engineers, and manage incident lifecycle.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import aiohttp
from urllib.parse import urljoin

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseAlertPlugin, AlertConfig, AlertResult

logger = get_logger(__name__)
metrics = get_metrics()


class PagerDutyConfig(AlertConfig):
    """PagerDuty alert configuration."""
    # API settings
    integration_key: str  # Required: Events API integration key
    api_endpoint: str = "https://events.pagerduty.com"
    api_version: str = "v2"
    
    # Service settings
    default_service_id: Optional[str] = None
    routing_key: Optional[str] = None  # Alternative to integration_key for v2 API
    
    # Escalation policies
    escalation_policies: Dict[str, str] = {}  # priority -> policy_id mapping
    
    # Severity mapping
    severity_mapping: Dict[str, str] = {
        "critical": "critical",
        "high": "error",
        "medium": "warning",
        "low": "info",
        "unknown": "info"
    }
    
    # Alert settings
    auto_resolve: bool = True
    auto_resolve_timeout_minutes: int = 60
    dedupe_alerts: bool = True
    
    # Incident settings
    incident_urgency_mapping: Dict[str, str] = {
        "critical": "high",
        "high": "high",
        "medium": "low",
        "low": "low"
    }
    
    # Notification settings
    send_to_teams: List[str] = []  # Team IDs to notify
    send_to_users: List[str] = []  # User IDs to notify
    
    # Rate limiting
    max_requests_per_minute: int = 120  # PagerDuty allows higher rates
    
    # Request settings
    timeout_seconds: int = 30
    retry_count: int = 3
    retry_delay_seconds: int = 5
    
    # Custom fields
    custom_details: Dict[str, Any] = {}
    include_links: bool = True
    include_images: bool = False


class PagerDutyPlugin(BaseAlertPlugin):
    """
    PagerDuty alert plugin.
    
    Provides PagerDuty integration for:
    - Security incident creation
    - On-call engineer notifications
    - Incident escalation and management
    - Alert deduplication and correlation
    - Incident lifecycle management
    - Integration with response teams
    """
    
    def __init__(self, config: PagerDutyConfig):
        super().__init__(config)
        self.config = config
        self.name = "pagerduty"
        self.version = "1.0.0"
        self.description = "PagerDuty incident management and on-call notification integration"
        
        # Supported alert types
        self.supported_alert_types = [
            "security_incident",
            "critical_vulnerability",
            "system_outage",
            "breach_detection",
            "compliance_violation",
            "service_degradation",
            "custom_incident"
        ]
        
        # HTTP session
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Event tracking
        self.active_incidents: Dict[str, Dict[str, Any]] = {}
        
        # Rate limiting
        self.request_count = 0
        self.last_reset = datetime.now(timezone.utc)
        
        logger.info("PagerDuty plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the PagerDuty plugin."""
        try:
            # Create HTTP session
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/vnd.pagerduty+json;version=2",
                "User-Agent": "MCP-Security-Platform/1.0"
            }
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=50)
            )
            
            # Test API connection
            await self._test_connection()
            
            logger.info("PagerDuty plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize PagerDuty plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup PagerDuty plugin resources."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
            
            logger.info("PagerDuty plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup PagerDuty plugin: {e}")
            return False
    
    @traced("pagerduty_plugin_send_alert")
    async def send_alert(
        self, 
        alert_type: str, 
        recipient: str, 
        subject: str, 
        message: str,
        priority: str = "medium",
        data: Optional[Dict[str, Any]] = None
    ) -> AlertResult:
        """Send a PagerDuty alert."""
        try:
            # Validate alert type
            if alert_type not in self.supported_alert_types:
                raise ValueError(f"Unsupported alert type: {alert_type}")
            
            # Check rate limiting
            await self._check_rate_limit()
            
            # Create incident
            incident_data = await self._create_incident_event(
                alert_type=alert_type,
                subject=subject,
                message=message,
                priority=priority,
                data=data or {}
            )
            
            # Send to PagerDuty
            alert_id = f"pd-{datetime.now(timezone.utc).timestamp()}"
            
            success, response_data = await self._send_event(incident_data)
            
            # Track incident if successful
            if success and response_data:
                dedup_key = response_data.get("dedup_key")
                if dedup_key:
                    self.active_incidents[dedup_key] = {
                        "alert_id": alert_id,
                        "alert_type": alert_type,
                        "priority": priority,
                        "created_at": datetime.now(timezone.utc),
                        "pagerduty_data": response_data
                    }
            
            result = AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=alert_id,
                recipient=recipient,
                alert_type=alert_type,
                priority=priority,
                delivered=success,
                delivery_attempts=1,
                status="success" if success else "failed",
                metadata=response_data if response_data else None
            )
            
            if success:
                logger.info(f"PagerDuty incident created successfully: {alert_id}")
                metrics.pagerduty_incidents_created.inc()
            else:
                logger.error(f"Failed to create PagerDuty incident: {alert_id}")
                metrics.pagerduty_failures.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            metrics.pagerduty_plugin_errors.inc()
            
            return AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=f"pd-error-{datetime.now(timezone.utc).timestamp()}",
                recipient=recipient,
                alert_type=alert_type,
                priority=priority,
                delivered=False,
                delivery_attempts=1,
                status="failed",
                error_message=str(e)
            )
    
    @traced("pagerduty_plugin_create_security_incident")
    async def create_security_incident(
        self,
        vulnerability_id: str,
        severity: str,
        title: str,
        description: str,
        affected_systems: Optional[List[str]] = None,
        remediation: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None,
        escalation_policy: Optional[str] = None
    ) -> AlertResult:
        """Create a security incident in PagerDuty."""
        try:
            # Build incident data
            incident_data = {
                "vulnerability_id": vulnerability_id,
                "severity": severity,
                "title": title,
                "description": description,
                "affected_systems": affected_systems or [],
                "remediation": remediation,
                "scan_result": scan_result,
                "escalation_policy": escalation_policy or self.config.escalation_policies.get(severity.lower()),
                "incident_type": "security_incident",
                "urgency": self.config.incident_urgency_mapping.get(severity.lower(), "low")
            }
            
            return await self.send_alert(
                alert_type="security_incident",
                recipient="security-team",
                subject=f"Security Incident: {title}",
                message=description,
                priority=severity.lower(),
                data=incident_data
            )
            
        except Exception as e:
            logger.error(f"Failed to create security incident: {e}")
            return AlertResult(
                plugin_name=self.name,
                plugin_version=self.version,
                alert_id=f"security-incident-error-{datetime.now(timezone.utc).timestamp()}",
                recipient="security-team",
                alert_type="security_incident",
                priority=severity.lower(),
                delivered=False,
                delivery_attempts=1,
                status="failed",
                error_message=str(e)
            )
    
    @traced("pagerduty_plugin_resolve_incident")
    async def resolve_incident(
        self, 
        incident_key: str, 
        resolution_note: Optional[str] = None
    ) -> bool:
        """Resolve a PagerDuty incident."""
        try:
            # Build resolve event
            resolve_event = {
                "routing_key": self.config.routing_key or self.config.integration_key,
                "event_action": "resolve",
                "dedup_key": incident_key
            }
            
            if resolution_note:
                resolve_event["payload"] = {
                    "summary": "Incident resolved",
                    "source": "MCP Security Platform",
                    "severity": "info",
                    "custom_details": {
                        "resolution_note": resolution_note,
                        "resolved_by": "MCP Security Platform",
                        "resolved_at": datetime.now(timezone.utc).isoformat()
                    }
                }
            
            success, response = await self._send_event(resolve_event)
            
            if success:
                # Remove from active incidents
                if incident_key in self.active_incidents:
                    del self.active_incidents[incident_key]
                
                logger.info(f"PagerDuty incident resolved: {incident_key}")
                metrics.pagerduty_incidents_resolved.inc()
                return True
            else:
                logger.error(f"Failed to resolve PagerDuty incident: {incident_key}")
                return False
                
        except Exception as e:
            logger.error(f"Error resolving PagerDuty incident: {e}")
            return False
    
    async def get_alert_status(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert delivery status."""
        try:
            # Find incident by alert_id
            for dedup_key, incident_info in self.active_incidents.items():
                if incident_info.get("alert_id") == alert_id:
                    return {
                        "alert_id": alert_id,
                        "dedup_key": dedup_key,
                        "status": "active",
                        "created_at": incident_info.get("created_at"),
                        "pagerduty_data": incident_info.get("pagerduty_data")
                    }
            
            # Not found in active incidents
            return {
                "alert_id": alert_id,
                "status": "unknown",
                "message": "Incident not found in active incidents"
            }
            
        except Exception as e:
            logger.error(f"Failed to get alert status: {e}")
            return None
    
    async def _create_incident_event(
        self,
        alert_type: str,
        subject: str,
        message: str,
        priority: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create PagerDuty incident event payload."""
        try:
            # Generate dedup key for alert deduplication
            if self.config.dedupe_alerts:
                dedup_components = [
                    alert_type,
                    data.get("vulnerability_id", ""),
                    data.get("affected_systems", [""])[0] if data.get("affected_systems") else ""
                ]
                dedup_key = f"mcp-{'-'.join(filter(None, dedup_components))}"
            else:
                dedup_key = f"mcp-{datetime.now(timezone.utc).timestamp()}"
            
            # Map priority to PagerDuty severity
            severity = self.config.severity_mapping.get(priority, "info")
            
            # Build event payload
            event = {
                "routing_key": self.config.routing_key or self.config.integration_key,
                "event_action": "trigger",
                "dedup_key": dedup_key,
                "payload": {
                    "summary": subject,
                    "source": "MCP Security Platform",
                    "severity": severity,
                    "component": data.get("component", "Security Scanner"),
                    "group": data.get("group", "Security"),
                    "class": alert_type,
                    "custom_details": {
                        "alert_type": alert_type,
                        "priority": priority,
                        "message": message,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        **data,
                        **self.config.custom_details
                    }
                }
            }
            
            # Add links if configured
            if self.config.include_links:
                links = []
                
                # Add vulnerability details link if available
                if data.get("vulnerability_id"):
                    links.append({
                        "href": f"https://mcp-security-platform.local/vulnerabilities/{data['vulnerability_id']}",
                        "text": f"View Vulnerability {data['vulnerability_id']}"
                    })
                
                # Add scan results link if available
                if data.get("scan_result"):
                    links.append({
                        "href": f"https://mcp-security-platform.local/scans/{data.get('scan_id', 'latest')}",
                        "text": "View Scan Results"
                    })
                
                if links:
                    event["links"] = links
            
            # Add images if configured
            if self.config.include_images:
                images = []
                
                # Add severity badge
                severity_colors = {
                    "critical": "red",
                    "high": "orange", 
                    "medium": "yellow",
                    "low": "green"
                }
                color = severity_colors.get(priority, "gray")
                
                images.append({
                    "src": f"https://img.shields.io/badge/Severity-{priority.upper()}-{color}",
                    "alt": f"Severity: {priority.upper()}"
                })
                
                if images:
                    event["images"] = images
            
            return event
            
        except Exception as e:
            logger.error(f"Failed to create incident event: {e}")
            raise
    
    async def _send_event(self, event_data: Dict[str, Any]) -> tuple[bool, Optional[Dict[str, Any]]]:
        """Send event to PagerDuty Events API."""
        try:
            if not self.session:
                raise RuntimeError("PagerDuty session not initialized")
            
            url = f"{self.config.api_endpoint}/{self.config.api_version}/enqueue"
            
            # Send request with retries
            for attempt in range(self.config.retry_count + 1):
                try:
                    async with self.session.post(url, json=event_data) as response:
                        response_data = await response.json()
                        
                        if response.status in [200, 201, 202]:
                            logger.debug(f"PagerDuty event sent successfully")
                            return True, response_data
                        else:
                            logger.warning(f"PagerDuty API returned status {response.status}: {response_data}")
                            
                            # Don't retry for client errors
                            if 400 <= response.status < 500:
                                return False, response_data
                            
                            # Retry for server errors
                            if attempt < self.config.retry_count:
                                await asyncio.sleep(self.config.retry_delay_seconds)
                                continue
                            
                            return False, response_data
                            
                except Exception as e:
                    if attempt < self.config.retry_count:
                        logger.warning(f"PagerDuty request failed (attempt {attempt + 1}): {e}")
                        await asyncio.sleep(self.config.retry_delay_seconds)
                        continue
                    raise
            
            return False, None
            
        except Exception as e:
            logger.error(f"Failed to send PagerDuty event: {e}")
            return False, {"error": str(e)}
    
    async def _check_rate_limit(self):
        """Check and enforce rate limiting."""
        now = datetime.now(timezone.utc)
        
        # Reset counter if minute has passed
        if (now - self.last_reset).total_seconds() >= 60:
            self.request_count = 0
            self.last_reset = now
        
        # Check if rate limit exceeded
        if self.request_count >= self.config.max_requests_per_minute:
            wait_time = 60 - (now - self.last_reset).total_seconds()
            if wait_time > 0:
                logger.warning(f"PagerDuty rate limit exceeded, waiting {wait_time} seconds")
                await asyncio.sleep(wait_time)
                self.request_count = 0
                self.last_reset = datetime.now(timezone.utc)
        
        self.request_count += 1
    
    async def _test_connection(self):
        """Test PagerDuty API connection."""
        try:
            # Send a test event that will be immediately resolved
            test_event = {
                "routing_key": self.config.routing_key or self.config.integration_key,
                "event_action": "trigger",
                "dedup_key": f"mcp-test-{datetime.now(timezone.utc).timestamp()}",
                "payload": {
                    "summary": "MCP Security Platform connection test",
                    "source": "MCP Security Platform",
                    "severity": "info",
                    "custom_details": {
                        "test": True,
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
            }
            
            success, response = await self._send_event(test_event)
            
            if success:
                # Immediately resolve the test incident
                resolve_event = {
                    "routing_key": self.config.routing_key or self.config.integration_key,
                    "event_action": "resolve",
                    "dedup_key": test_event["dedup_key"]
                }
                await self._send_event(resolve_event)
                
                logger.info("PagerDuty API connection test successful")
            else:
                logger.error(f"PagerDuty API connection test failed: {response}")
                raise RuntimeError("PagerDuty API connection test failed")
                
        except Exception as e:
            logger.error(f"PagerDuty API connection test error: {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_alert_types": self.supported_alert_types,
            "api_endpoint": self.config.api_endpoint,
            "auto_resolve": self.config.auto_resolve,
            "dedupe_alerts": self.config.dedupe_alerts,
            "max_requests_per_minute": self.config.max_requests_per_minute,
            "active_incidents": len(self.active_incidents)
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": self.session is not None and not self.session.closed,
                "session_active": self.session is not None,
                "active_incidents": len(self.active_incidents),
                "requests_this_minute": self.request_count,
                "rate_limit": self.config.max_requests_per_minute,
                "last_error": self.last_error
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }