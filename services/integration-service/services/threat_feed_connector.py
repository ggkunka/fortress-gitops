"""
Threat Feed Connector - Integration with Threat Intelligence Feeds

This connector provides integration capabilities with threat intelligence
platforms and feeds including commercial and open source threat intelligence.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import httpx
import hashlib
from urllib.parse import urljoin

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.integration import Integration

logger = get_logger(__name__)
metrics = get_metrics()


class ThreatFeedConnector:
    """
    Threat intelligence feed connector supporting multiple threat intelligence platforms.
    
    Supported threat intelligence platforms:
    - MISP (Malware Information Sharing Platform)
    - OpenCTI (Open Cyber Threat Intelligence)
    - ThreatConnect
    - Anomali ThreatStream
    - Recorded Future
    - VirusTotal
    - AlienVault OTX (Open Threat Exchange)
    - Shodan
    - IBM X-Force Exchange
    - Custom TAXII feeds
    - STIX/TAXII 2.1 compliant feeds
    """
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=60.0)  # Longer timeout for threat feeds
        self.supported_providers = {
            "misp": self._handle_misp,
            "opencti": self._handle_opencti,
            "threatconnect": self._handle_threatconnect,
            "anomali": self._handle_anomali,
            "recorded_future": self._handle_recorded_future,
            "virustotal": self._handle_virustotal,
            "otx": self._handle_alienvault_otx,
            "shodan": self._handle_shodan,
            "xforce": self._handle_xforce,
            "taxii": self._handle_taxii,
            "custom": self._handle_custom_feed
        }
        
        # Cache for feed data to avoid excessive API calls
        self.feed_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        logger.info("Threat feed connector initialized")
    
    @traced("threat_feed_connector_connect")
    async def connect(self, integration: Integration) -> Dict[str, Any]:
        """Establish connection to threat intelligence platform."""
        try:
            provider = integration.provider.lower()
            if provider not in self.supported_providers:
                return {
                    "success": False,
                    "error": f"Unsupported threat intelligence provider: {provider}",
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
                logger.info(f"Successfully connected to {provider} threat feed: {integration.name}")
                metrics.threat_feed_connector_connections_successful.inc()
            else:
                logger.error(f"Failed to connect to {provider} threat feed: {integration.name}")
                metrics.threat_feed_connector_connections_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error connecting to threat feed {integration.name}: {e}")
            metrics.threat_feed_connector_errors.inc()
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("threat_feed_connector_health_check")
    async def health_check(self, integration: Integration) -> Dict[str, Any]:
        """Perform health check on threat feed connection."""
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
            
            metrics.threat_feed_connector_health_checks.inc()
            return result
            
        except Exception as e:
            logger.error(f"Error checking threat feed health {integration.name}: {e}")
            return {
                "healthy": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("threat_feed_connector_pull_data")
    async def pull_data(self, integration: Integration) -> Dict[str, Any]:
        """Pull threat intelligence data from feed."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            # Check cache first
            cache_key = f"{integration.id}_{provider}_pull"
            cached_data = self._get_cached_data(cache_key)
            if cached_data:
                logger.info(f"Returning cached threat data for {provider}: {integration.name}")
                return cached_data
            
            result = await handler("pull_data", integration)
            
            if result.get("success"):
                # Cache the result
                self._cache_data(cache_key, result)
                
                logger.info(f"Successfully pulled threat data from {provider}: {integration.name}")
                metrics.threat_feed_connector_data_pulls_successful.inc()
            else:
                logger.error(f"Failed to pull threat data from {provider}: {integration.name}")
                metrics.threat_feed_connector_data_pulls_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pulling threat data from {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    @traced("threat_feed_connector_push_data")
    async def push_data(self, integration: Integration, data: Dict[str, Any]) -> Dict[str, Any]:
        """Push threat intelligence data to feed (if supported)."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("push_data", integration, data)
            
            if result.get("success"):
                logger.info(f"Successfully pushed threat data to {provider}: {integration.name}")
                metrics.threat_feed_connector_data_pushes_successful.inc()
            else:
                logger.error(f"Failed to push threat data to {provider}: {integration.name}")
                metrics.threat_feed_connector_data_pushes_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pushing threat data to {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    @traced("threat_feed_connector_send_event")
    async def send_event(self, integration: Integration, event_type: str, event_data: Dict[str, Any]):
        """Send threat event to threat intelligence platform."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                logger.warning(f"Cannot send event to unsupported threat feed provider: {provider}")
                return
            
            # Format event for threat intelligence platform
            formatted_event = self._format_event_for_threat_feed(provider, event_type, event_data)
            
            result = await handler("send_event", integration, formatted_event)
            
            if result.get("success"):
                logger.info(f"Successfully sent {event_type} event to {provider} threat feed")
                metrics.threat_feed_connector_events_sent.inc()
            else:
                logger.error(f"Failed to send {event_type} event to {provider} threat feed")
                metrics.threat_feed_connector_events_failed.inc()
            
        except Exception as e:
            logger.error(f"Error sending event to threat feed {integration.name}: {e}")
            metrics.threat_feed_connector_errors.inc()
    
    async def test_connection(self, integration: Integration) -> Dict[str, Any]:
        """Test threat feed connection."""
        return await self.health_check(integration)
    
    async def disconnect(self, integration: Integration):
        """Disconnect from threat feed."""
        try:
            provider = integration.provider.lower()
            
            # Clear cache for this integration
            cache_keys_to_remove = [
                key for key in self.feed_cache.keys() 
                if key.startswith(str(integration.id))
            ]
            for key in cache_keys_to_remove:
                self.feed_cache.pop(key, None)
            
            logger.info(f"Disconnected from {provider} threat feed: {integration.name}")
            
        except Exception as e:
            logger.error(f"Error disconnecting from threat feed {integration.name}: {e}")
    
    # Provider-specific handlers
    
    async def _handle_misp(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle MISP (Malware Information Sharing Platform) operations."""
        try:
            config = integration.config
            credentials = integration.credentials
            
            base_url = config.get("url", "").rstrip("/")
            api_key = credentials.get("api_key")
            verify_ssl = config.get("verify_ssl", True)
            
            if not base_url or not api_key:
                return {"success": False, "error": "MISP URL or API key not configured"}
            
            headers = {
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            
            if action == "connect":
                # Test connection by getting server version
                response = await self.http_client.get(
                    f"{base_url}/servers/getVersion.json",
                    headers=headers,
                    verify=verify_ssl
                )
                
                if response.status_code == 200:
                    version_info = response.json()
                    return {
                        "success": True,
                        "version": version_info.get("version"),
                        "capabilities": ["events", "attributes", "objects", "sharing"],
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
                    f"{base_url}/servers/getVersion.json",
                    headers=headers,
                    verify=verify_ssl
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code,
                    "health_data": {"api_accessible": response.status_code == 200}
                }
            
            elif action == "pull_data":
                # Pull recent events from MISP
                days_back = config.get("days_back", 1)
                
                params = {
                    "last": f"{days_back}d",
                    "limit": config.get("max_results", 100),
                    "published": 1,  # Only published events
                    "includeDecayScore": 1
                }
                
                response = await self.http_client.get(
                    f"{base_url}/events/index.json",
                    headers=headers,
                    params=params,
                    verify=verify_ssl
                )
                
                if response.status_code == 200:
                    events_data = response.json()
                    events = events_data if isinstance(events_data, list) else []
                    
                    # Get detailed event information
                    detailed_events = []
                    for event in events[:10]:  # Limit to 10 detailed events to avoid rate limits
                        event_id = event.get("Event", {}).get("id")
                        if event_id:
                            detail_response = await self.http_client.get(
                                f"{base_url}/events/view/{event_id}.json",
                                headers=headers,
                                verify=verify_ssl
                            )
                            if detail_response.status_code == 200:
                                detailed_events.append(detail_response.json())
                    
                    return {
                        "success": True,
                        "records_processed": len(events),
                        "records_successful": len(events),
                        "records_failed": 0,
                        "data": {
                            "events": events,
                            "detailed_events": detailed_events
                        },
                        "metadata": {"query_params": params}
                    }
                else:
                    return {"success": False, "error": f"Failed to retrieve events: {response.text}"}
            
            elif action == "push_data":
                # Push threat indicators to MISP
                indicators = data.get("indicators", [])
                
                if not indicators:
                    return {"success": True, "records_processed": 0, "records_successful": 0, "records_failed": 0}
                
                # Create MISP event
                event_data = {
                    "Event": {
                        "info": data.get("event_info", "Threat indicators from MCP Security Platform"),
                        "threat_level_id": data.get("threat_level", 3),  # 3 = Medium
                        "analysis": data.get("analysis_level", 0),  # 0 = Initial
                        "distribution": data.get("distribution", 1),  # 1 = Community only
                        "Attribute": []
                    }
                }
                
                # Add indicators as attributes
                for indicator in indicators:
                    attribute = {
                        "type": indicator.get("type", "other"),
                        "value": indicator.get("value", ""),
                        "category": indicator.get("category", "Other"),
                        "to_ids": indicator.get("to_ids", True),
                        "comment": indicator.get("comment", "")
                    }
                    event_data["Event"]["Attribute"].append(attribute)
                
                response = await self.http_client.post(
                    f"{base_url}/events/add.json",
                    headers=headers,
                    json=event_data,
                    verify=verify_ssl
                )
                
                if response.status_code in [200, 201]:
                    return {
                        "success": True,
                        "records_processed": len(indicators),
                        "records_successful": len(indicators),
                        "records_failed": 0,
                        "event_id": response.json().get("Event", {}).get("id")
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Failed to create MISP event: {response.text}",
                        "records_processed": len(indicators),
                        "records_successful": 0,
                        "records_failed": len(indicators)
                    }
            
            elif action == "send_event":
                # Send individual threat event to MISP
                event_info = f"Threat Event: {data.get('event_type', 'Unknown')}"
                
                event_data = {
                    "Event": {
                        "info": event_info,
                        "threat_level_id": self._map_severity_to_misp_threat_level(data.get("severity", "medium")),
                        "analysis": 0,  # Initial
                        "distribution": 1,  # Community only
                        "Attribute": []
                    }
                }
                
                # Add event data as attributes
                if "indicators" in data:
                    for indicator in data["indicators"]:
                        attribute = {
                            "type": indicator.get("type", "other"),
                            "value": indicator.get("value", ""),
                            "category": "External analysis",
                            "comment": f"From MCP Security Platform: {data.get('description', '')}"
                        }
                        event_data["Event"]["Attribute"].append(attribute)
                
                response = await self.http_client.post(
                    f"{base_url}/events/add.json",
                    headers=headers,
                    json=event_data,
                    verify=verify_ssl
                )
                
                return {"success": response.status_code in [200, 201]}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
                
        except Exception as e:
            logger.error(f"Error in MISP handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_virustotal(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle VirusTotal operations."""
        try:
            credentials = integration.credentials
            config = integration.config
            
            api_key = credentials.get("api_key")
            if not api_key:
                return {"success": False, "error": "VirusTotal API key not configured"}
            
            headers = {"x-apikey": api_key}
            base_url = "https://www.virustotal.com/api/v3"
            
            if action == "connect":
                # Test connection by getting API key info
                response = await self.http_client.get(
                    f"{base_url}/users/{api_key}",
                    headers=headers
                )
                
                if response.status_code == 200:
                    user_info = response.json()
                    return {
                        "success": True,
                        "user_id": user_info.get("data", {}).get("id"),
                        "capabilities": ["file_scan", "url_scan", "domain_lookup", "ip_lookup"],
                        "supports_pull": True,
                        "supports_push": False,  # VirusTotal is primarily read-only for most users
                        "quotas": user_info.get("data", {}).get("attributes", {}).get("quotas", {})
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text}"
                    }
            
            elif action == "health_check":
                response = await self.http_client.get(
                    f"{base_url}/users/{api_key}",
                    headers=headers
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code,
                    "health_data": {"api_accessible": response.status_code == 200}
                }
            
            elif action == "pull_data":
                # Pull recent file reports
                max_results = config.get("max_results", 50)
                
                # Get recent analyses (this requires premium API access)
                response = await self.http_client.get(
                    f"{base_url}/intelligence/search",
                    headers=headers,
                    params={
                        "query": "type:file",
                        "limit": max_results,
                        "order": "last_analysis_date-"
                    }
                )
                
                if response.status_code == 200:
                    results = response.json()
                    files_data = results.get("data", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(files_data),
                        "records_successful": len(files_data),
                        "records_failed": 0,
                        "data": files_data,
                        "metadata": {"query": "type:file"}
                    }
                elif response.status_code == 403:
                    # Fallback to basic quota information if premium features not available
                    quota_response = await self.http_client.get(
                        f"{base_url}/users/{api_key}",
                        headers=headers
                    )
                    
                    if quota_response.status_code == 200:
                        user_data = quota_response.json()
                        return {
                            "success": True,
                            "records_processed": 0,
                            "records_successful": 0,
                            "records_failed": 0,
                            "data": [],
                            "metadata": {
                                "message": "Premium features required for search",
                                "quotas": user_data.get("data", {}).get("attributes", {}).get("quotas", {})
                            }
                        }
                    else:
                        return {"success": False, "error": "Failed to access VirusTotal API"}
                else:
                    return {"success": False, "error": f"Failed to search files: {response.text}"}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Action {action} not supported for VirusTotal"}
                
        except Exception as e:
            logger.error(f"Error in VirusTotal handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_alienvault_otx(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle AlienVault OTX (Open Threat Exchange) operations."""
        try:
            credentials = integration.credentials
            config = integration.config
            
            api_key = credentials.get("api_key")
            if not api_key:
                return {"success": False, "error": "OTX API key not configured"}
            
            headers = {"X-OTX-API-KEY": api_key}
            base_url = "https://otx.alienvault.com/api/v1"
            
            if action == "connect":
                # Test connection by getting user info
                response = await self.http_client.get(
                    f"{base_url}/user/me",
                    headers=headers
                )
                
                if response.status_code == 200:
                    user_info = response.json()
                    return {
                        "success": True,
                        "username": user_info.get("username"),
                        "capabilities": ["pulses", "indicators", "subscriptions"],
                        "supports_pull": True,
                        "supports_push": True,
                        "member_since": user_info.get("member_since")
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text}"
                    }
            
            elif action == "health_check":
                response = await self.http_client.get(
                    f"{base_url}/user/me",
                    headers=headers
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code,
                    "health_data": {"api_accessible": response.status_code == 200}
                }
            
            elif action == "pull_data":
                # Pull recent pulses (threat intelligence reports)
                days_back = config.get("days_back", 1)
                limit = config.get("max_results", 50)
                
                response = await self.http_client.get(
                    f"{base_url}/pulses/subscribed",
                    headers=headers,
                    params={
                        "limit": limit,
                        "modified_since": (datetime.now() - timedelta(days=days_back)).isoformat()
                    }
                )
                
                if response.status_code == 200:
                    pulses_data = response.json()
                    pulses = pulses_data.get("results", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(pulses),
                        "records_successful": len(pulses),
                        "records_failed": 0,
                        "data": pulses,
                        "metadata": {
                            "count": pulses_data.get("count", 0),
                            "next": pulses_data.get("next")
                        }
                    }
                else:
                    return {"success": False, "error": f"Failed to retrieve pulses: {response.text}"}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Action {action} not supported for OTX"}
                
        except Exception as e:
            logger.error(f"Error in OTX handler: {e}")
            return {"success": False, "error": str(e)}
    
    # Placeholder handlers for other providers
    
    async def _handle_opencti(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle OpenCTI operations."""
        return {"success": False, "error": "OpenCTI integration not yet implemented"}
    
    async def _handle_threatconnect(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle ThreatConnect operations."""
        return {"success": False, "error": "ThreatConnect integration not yet implemented"}
    
    async def _handle_anomali(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Anomali ThreatStream operations."""
        return {"success": False, "error": "Anomali ThreatStream integration not yet implemented"}
    
    async def _handle_recorded_future(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Recorded Future operations."""
        return {"success": False, "error": "Recorded Future integration not yet implemented"}
    
    async def _handle_shodan(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Shodan operations."""
        return {"success": False, "error": "Shodan integration not yet implemented"}
    
    async def _handle_xforce(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle IBM X-Force Exchange operations."""
        return {"success": False, "error": "IBM X-Force Exchange integration not yet implemented"}
    
    async def _handle_taxii(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle TAXII feed operations."""
        return {"success": False, "error": "TAXII feed integration not yet implemented"}
    
    async def _handle_custom_feed(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle custom threat feed operations."""
        return {"success": False, "error": "Custom threat feed integration not yet implemented"}
    
    # Helper methods
    
    def _get_cached_data(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached feed data."""
        cached_entry = self.feed_cache.get(cache_key)
        if cached_entry:
            cached_time, cached_data = cached_entry
            if (datetime.now() - cached_time).total_seconds() < self.cache_ttl:
                return cached_data
            else:
                # Remove expired entry
                self.feed_cache.pop(cache_key, None)
        return None
    
    def _cache_data(self, cache_key: str, data: Dict[str, Any]):
        """Cache feed data."""
        self.feed_cache[cache_key] = (datetime.now(), data)
        
        # Clean up old cache entries periodically
        if len(self.feed_cache) > 100:  # Limit cache size
            current_time = datetime.now()
            expired_keys = [
                key for key, (cached_time, _) in self.feed_cache.items()
                if (current_time - cached_time).total_seconds() > self.cache_ttl
            ]
            for key in expired_keys:
                self.feed_cache.pop(key, None)
    
    def _map_severity_to_misp_threat_level(self, severity: str) -> int:
        """Map severity to MISP threat level."""
        mapping = {
            "low": 4,      # Low
            "medium": 3,   # Medium
            "high": 2,     # High
            "critical": 1  # High (MISP doesn't have critical)
        }
        return mapping.get(severity.lower(), 3)
    
    def _format_event_for_threat_feed(self, provider: str, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format event data for specific threat intelligence platform."""
        base_event = {
            "timestamp": datetime.now().isoformat(),
            "source": "mcp-security-platform",
            "event_type": event_type,
            "data": event_data
        }
        
        if provider == "misp":
            return {
                "info": f"MCP Security Event: {event_type}",
                "threat_level_id": self._map_severity_to_misp_threat_level(event_data.get("severity", "medium")),
                "analysis": 0,  # Initial
                "distribution": 1,  # Community only
                "data": base_event
            }
        elif provider == "otx":
            return {
                "name": f"MCP Security Event: {event_type}",
                "description": event_data.get("description", "Security event from MCP Security Platform"),
                "tags": event_data.get("tags", []),
                "indicators": event_data.get("indicators", []),
                "data": base_event
            }
        else:
            return base_event
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.aclose()