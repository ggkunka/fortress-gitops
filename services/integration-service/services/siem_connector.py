"""
SIEM Connector - Integration with Security Information and Event Management systems

This connector provides integration capabilities with popular SIEM platforms
including Splunk, QRadar, ArcSight, Elastic Security, and others.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import httpx
from urllib.parse import urljoin

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.integration import Integration

logger = get_logger(__name__)
metrics = get_metrics()


class SIEMConnector:
    """
    SIEM integration connector supporting multiple SIEM platforms.
    
    Supported SIEM platforms:
    - Splunk Enterprise/Cloud
    - IBM QRadar
    - Micro Focus ArcSight
    - Elastic Security (ELK Stack)
    - Microsoft Sentinel
    - LogRhythm
    - Sumo Logic
    - Custom REST API SIEMs
    """
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)
        self.supported_providers = {
            "splunk": self._handle_splunk,
            "qradar": self._handle_qradar,
            "arcsight": self._handle_arcsight,
            "elastic": self._handle_elastic,
            "sentinel": self._handle_sentinel,
            "logrhythm": self._handle_logrhythm,
            "sumologic": self._handle_sumologic,
            "custom": self._handle_custom_rest
        }
        logger.info("SIEM connector initialized")
    
    @traced("siem_connector_connect")
    async def connect(self, integration: Integration) -> Dict[str, Any]:
        """Establish connection to SIEM platform."""
        try:
            provider = integration.provider.lower()
            if provider not in self.supported_providers:
                return {
                    "success": False,
                    "error": f"Unsupported SIEM provider: {provider}",
                    "provider": provider
                }
            
            # Get provider-specific handler
            handler = self.supported_providers[provider]
            
            # Attempt connection
            start_time = datetime.now()
            result = await handler("connect", integration)
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result.update({
                "response_time": response_time,
                "provider": provider,
                "connected_at": datetime.now().isoformat()
            })
            
            if result.get("success"):
                logger.info(f"Successfully connected to {provider} SIEM: {integration.name}")
                metrics.siem_connector_connections_successful.inc()
            else:
                logger.error(f"Failed to connect to {provider} SIEM: {integration.name}")
                metrics.siem_connector_connections_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error connecting to SIEM {integration.name}: {e}")
            metrics.siem_connector_errors.inc()
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("siem_connector_health_check")
    async def health_check(self, integration: Integration) -> Dict[str, Any]:
        """Perform health check on SIEM connection."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"healthy": False, "error": "Unsupported provider"}
            
            start_time = datetime.now()
            result = await handler("health_check", integration)
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            result.update({
                "response_time": response_time,
                "checked_at": datetime.now().isoformat()
            })
            
            metrics.siem_connector_health_checks.inc()
            return result
            
        except Exception as e:
            logger.error(f"Error checking SIEM health {integration.name}: {e}")
            return {
                "healthy": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("siem_connector_pull_data")
    async def pull_data(self, integration: Integration) -> Dict[str, Any]:
        """Pull security events and alerts from SIEM."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("pull_data", integration)
            
            if result.get("success"):
                logger.info(f"Successfully pulled data from {provider} SIEM: {integration.name}")
                metrics.siem_connector_data_pulls_successful.inc()
            else:
                logger.error(f"Failed to pull data from {provider} SIEM: {integration.name}")
                metrics.siem_connector_data_pulls_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pulling data from SIEM {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    @traced("siem_connector_push_data")
    async def push_data(self, integration: Integration, data: Dict[str, Any]) -> Dict[str, Any]:
        """Push security events to SIEM."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("push_data", integration, data)
            
            if result.get("success"):
                logger.info(f"Successfully pushed data to {provider} SIEM: {integration.name}")
                metrics.siem_connector_data_pushes_successful.inc()
            else:
                logger.error(f"Failed to push data to {provider} SIEM: {integration.name}")
                metrics.siem_connector_data_pushes_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pushing data to SIEM {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    @traced("siem_connector_send_event")
    async def send_event(self, integration: Integration, event_type: str, event_data: Dict[str, Any]):
        """Send security event to SIEM."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                logger.warning(f"Cannot send event to unsupported SIEM provider: {provider}")
                return
            
            # Format event for SIEM
            formatted_event = self._format_event_for_siem(provider, event_type, event_data)
            
            result = await handler("send_event", integration, formatted_event)
            
            if result.get("success"):
                logger.info(f"Successfully sent {event_type} event to {provider} SIEM")
                metrics.siem_connector_events_sent.inc()
            else:
                logger.error(f"Failed to send {event_type} event to {provider} SIEM")
                metrics.siem_connector_events_failed.inc()
            
        except Exception as e:
            logger.error(f"Error sending event to SIEM {integration.name}: {e}")
            metrics.siem_connector_errors.inc()
    
    async def test_connection(self, integration: Integration) -> Dict[str, Any]:
        """Test SIEM connection."""
        return await self.health_check(integration)
    
    async def disconnect(self, integration: Integration):
        """Disconnect from SIEM."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if handler:
                await handler("disconnect", integration)
            
            logger.info(f"Disconnected from {provider} SIEM: {integration.name}")
            
        except Exception as e:
            logger.error(f"Error disconnecting from SIEM {integration.name}: {e}")
    
    # Provider-specific handlers
    
    async def _handle_splunk(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Splunk SIEM operations."""
        try:
            config = integration.config
            credentials = integration.credentials
            
            base_url = config.get("url", "").rstrip("/")
            username = credentials.get("username")
            password = credentials.get("password")
            token = credentials.get("token")
            
            if not base_url:
                return {"success": False, "error": "Splunk URL not configured"}
            
            # Prepare authentication
            auth_headers = {}
            if token:
                auth_headers["Authorization"] = f"Bearer {token}"
            elif username and password:
                auth_headers["Authorization"] = f"Basic {httpx._utils.to_bytes(f'{username}:{password}').decode()}"
            else:
                return {"success": False, "error": "No authentication credentials provided"}
            
            if action == "connect":
                # Test connection to Splunk
                response = await self.http_client.get(
                    f"{base_url}/services/server/info",
                    headers=auth_headers
                )
                
                if response.status_code == 200:
                    server_info = response.json()
                    return {
                        "success": True,
                        "version": server_info.get("entry", [{}])[0].get("content", {}).get("version"),
                        "capabilities": ["search", "alerts", "dashboards", "reports"],
                        "supports_pull": True,
                        "supports_push": True
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text}"
                    }
            
            elif action == "health_check":
                response = await self.http_client.get(
                    f"{base_url}/services/server/info",
                    headers=auth_headers
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code,
                    "health_data": {"service_status": "running" if response.status_code == 200 else "error"}
                }
            
            elif action == "pull_data":
                # Pull recent security events from Splunk
                search_query = config.get("search_query", "search index=security earliest=-1h")
                
                search_response = await self.http_client.post(
                    f"{base_url}/services/search/jobs",
                    headers=auth_headers,
                    data={"search": search_query, "output_mode": "json"}
                )
                
                if search_response.status_code != 201:
                    return {"success": False, "error": "Failed to create search job"}
                
                # Get search job SID
                job_info = search_response.json()
                sid = job_info.get("sid")
                
                if not sid:
                    return {"success": False, "error": "No search job ID returned"}
                
                # Wait for search to complete and get results
                await asyncio.sleep(2)  # Give search time to complete
                
                results_response = await self.http_client.get(
                    f"{base_url}/services/search/jobs/{sid}/results",
                    headers=auth_headers,
                    params={"output_mode": "json"}
                )
                
                if results_response.status_code == 200:
                    results = results_response.json()
                    events = results.get("results", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(events),
                        "records_successful": len(events),
                        "records_failed": 0,
                        "data": events,
                        "metadata": {"search_sid": sid, "search_query": search_query}
                    }
                else:
                    return {"success": False, "error": "Failed to retrieve search results"}
            
            elif action == "push_data":
                # Push data to Splunk via HTTP Event Collector
                hec_token = credentials.get("hec_token")
                if not hec_token:
                    return {"success": False, "error": "HEC token not configured"}
                
                hec_url = f"{base_url}/services/collector"
                hec_headers = {"Authorization": f"Splunk {hec_token}"}
                
                events_data = data.get("events", [])
                successful_count = 0
                failed_count = 0
                
                for event in events_data:
                    event_payload = {
                        "time": event.get("timestamp", datetime.now().timestamp()),
                        "source": "mcp-security-platform",
                        "sourcetype": event.get("source_type", "security_event"),
                        "event": event
                    }
                    
                    response = await self.http_client.post(
                        hec_url,
                        headers=hec_headers,
                        json=event_payload
                    )
                    
                    if response.status_code == 200:
                        successful_count += 1
                    else:
                        failed_count += 1
                
                return {
                    "success": failed_count == 0,
                    "records_processed": len(events_data),
                    "records_successful": successful_count,
                    "records_failed": failed_count
                }
            
            elif action == "send_event":
                # Send single event to Splunk
                hec_token = credentials.get("hec_token")
                if not hec_token:
                    logger.warning("HEC token not configured for event sending")
                    return {"success": False, "error": "HEC token not configured"}
                
                hec_url = f"{base_url}/services/collector"
                hec_headers = {"Authorization": f"Splunk {hec_token}"}
                
                event_payload = {
                    "time": datetime.now().timestamp(),
                    "source": "mcp-security-platform",
                    "sourcetype": "mcp_security_event",
                    "event": data
                }
                
                response = await self.http_client.post(
                    hec_url,
                    headers=hec_headers,
                    json=event_payload
                )
                
                return {"success": response.status_code == 200}
            
            elif action == "disconnect":
                # Cleanup any active sessions if needed
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
                
        except Exception as e:
            logger.error(f"Error in Splunk handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_elastic(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Elastic Security SIEM operations."""
        try:
            config = integration.config
            credentials = integration.credentials
            
            base_url = config.get("url", "").rstrip("/")
            username = credentials.get("username")
            password = credentials.get("password")
            api_key = credentials.get("api_key")
            
            if not base_url:
                return {"success": False, "error": "Elasticsearch URL not configured"}
            
            # Prepare authentication
            auth_headers = {}
            if api_key:
                auth_headers["Authorization"] = f"ApiKey {api_key}"
            elif username and password:
                import base64
                auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
                auth_headers["Authorization"] = f"Basic {auth_string}"
            else:
                return {"success": False, "error": "No authentication credentials provided"}
            
            auth_headers["Content-Type"] = "application/json"
            
            if action == "connect":
                # Test connection to Elasticsearch
                response = await self.http_client.get(
                    f"{base_url}/",
                    headers=auth_headers
                )
                
                if response.status_code == 200:
                    cluster_info = response.json()
                    return {
                        "success": True,
                        "version": cluster_info.get("version", {}).get("number"),
                        "capabilities": ["search", "alerts", "visualizations", "machine_learning"],
                        "supports_pull": True,
                        "supports_push": True
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text}"
                    }
            
            elif action == "health_check":
                response = await self.http_client.get(
                    f"{base_url}/_cluster/health",
                    headers=auth_headers
                )
                
                health_data = {}
                if response.status_code == 200:
                    health_data = response.json()
                
                return {
                    "healthy": response.status_code == 200 and health_data.get("status") in ["green", "yellow"],
                    "status_code": response.status_code,
                    "health_data": health_data
                }
            
            elif action == "pull_data":
                # Pull recent security events from Elastic
                index_pattern = config.get("index_pattern", "security-*")
                
                # Query for recent security events
                query = {
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"gte": "now-1h"}}}
                            ]
                        }
                    },
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "size": config.get("max_results", 1000)
                }
                
                response = await self.http_client.post(
                    f"{base_url}/{index_pattern}/_search",
                    headers=auth_headers,
                    json=query
                )
                
                if response.status_code == 200:
                    results = response.json()
                    hits = results.get("hits", {}).get("hits", [])
                    events = [hit["_source"] for hit in hits]
                    
                    return {
                        "success": True,
                        "records_processed": len(events),
                        "records_successful": len(events),
                        "records_failed": 0,
                        "data": events,
                        "metadata": {"total_hits": results.get("hits", {}).get("total", {}).get("value", 0)}
                    }
                else:
                    return {"success": False, "error": f"Search failed: {response.text}"}
            
            elif action == "push_data":
                # Push data to Elasticsearch
                index_name = config.get("security_index", "mcp-security-events")
                events_data = data.get("events", [])
                
                successful_count = 0
                failed_count = 0
                
                for event in events_data:
                    # Add timestamp if not present
                    if "@timestamp" not in event:
                        event["@timestamp"] = datetime.now().isoformat()
                    
                    response = await self.http_client.post(
                        f"{base_url}/{index_name}/_doc",
                        headers=auth_headers,
                        json=event
                    )
                    
                    if response.status_code in [200, 201]:
                        successful_count += 1
                    else:
                        failed_count += 1
                
                return {
                    "success": failed_count == 0,
                    "records_processed": len(events_data),
                    "records_successful": successful_count,
                    "records_failed": failed_count
                }
            
            elif action == "send_event":
                # Send single event to Elasticsearch
                index_name = config.get("security_index", "mcp-security-events")
                
                event_data = data.copy()
                if "@timestamp" not in event_data:
                    event_data["@timestamp"] = datetime.now().isoformat()
                
                response = await self.http_client.post(
                    f"{base_url}/{index_name}/_doc",
                    headers=auth_headers,
                    json=event_data
                )
                
                return {"success": response.status_code in [200, 201]}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
                
        except Exception as e:
            logger.error(f"Error in Elastic handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_qradar(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle IBM QRadar SIEM operations."""
        # Placeholder implementation - would implement QRadar REST API calls
        return {"success": False, "error": "QRadar integration not yet implemented"}
    
    async def _handle_arcsight(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Micro Focus ArcSight SIEM operations."""
        # Placeholder implementation - would implement ArcSight API calls
        return {"success": False, "error": "ArcSight integration not yet implemented"}
    
    async def _handle_sentinel(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Microsoft Sentinel SIEM operations."""
        # Placeholder implementation - would implement Sentinel REST API calls
        return {"success": False, "error": "Microsoft Sentinel integration not yet implemented"}
    
    async def _handle_logrhythm(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle LogRhythm SIEM operations."""
        # Placeholder implementation - would implement LogRhythm API calls
        return {"success": False, "error": "LogRhythm integration not yet implemented"}
    
    async def _handle_sumologic(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Sumo Logic SIEM operations."""
        # Placeholder implementation - would implement Sumo Logic API calls
        return {"success": False, "error": "Sumo Logic integration not yet implemented"}
    
    async def _handle_custom_rest(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle custom REST API SIEM operations."""
        try:
            config = integration.config
            credentials = integration.credentials
            
            base_url = config.get("url", "").rstrip("/")
            api_key = credentials.get("api_key")
            token = credentials.get("token")
            
            if not base_url:
                return {"success": False, "error": "API URL not configured"}
            
            # Prepare authentication headers
            auth_headers = {"Content-Type": "application/json"}
            if api_key:
                auth_headers["X-API-Key"] = api_key
            elif token:
                auth_headers["Authorization"] = f"Bearer {token}"
            
            if action == "connect":
                # Test connection to custom API
                health_endpoint = config.get("health_endpoint", "/health")
                response = await self.http_client.get(
                    f"{base_url}{health_endpoint}",
                    headers=auth_headers
                )
                
                return {
                    "success": response.status_code == 200,
                    "version": "custom",
                    "capabilities": config.get("capabilities", ["events"]),
                    "supports_pull": config.get("supports_pull", False),
                    "supports_push": config.get("supports_push", True)
                }
            
            elif action == "health_check":
                health_endpoint = config.get("health_endpoint", "/health")
                response = await self.http_client.get(
                    f"{base_url}{health_endpoint}",
                    headers=auth_headers
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code
                }
            
            elif action == "send_event":
                # Send event to custom API
                events_endpoint = config.get("events_endpoint", "/events")
                response = await self.http_client.post(
                    f"{base_url}{events_endpoint}",
                    headers=auth_headers,
                    json=data
                )
                
                return {"success": response.status_code in [200, 201, 202]}
            
            else:
                return {"success": False, "error": f"Action {action} not supported for custom REST API"}
                
        except Exception as e:
            logger.error(f"Error in custom REST handler: {e}")
            return {"success": False, "error": str(e)}
    
    def _format_event_for_siem(self, provider: str, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format event data for specific SIEM platform."""
        base_event = {
            "timestamp": datetime.now().isoformat(),
            "source": "mcp-security-platform",
            "event_type": event_type,
            "data": event_data
        }
        
        if provider == "splunk":
            return {
                "time": datetime.now().timestamp(),
                "source": "mcp-security-platform",
                "sourcetype": f"mcp_{event_type}",
                "event": base_event
            }
        elif provider == "elastic":
            base_event["@timestamp"] = datetime.now().isoformat()
            return base_event
        else:
            return base_event
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.aclose()