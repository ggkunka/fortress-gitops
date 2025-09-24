"""
Ticketing Connector - Integration with IT Service Management and Ticketing Systems

This connector provides integration capabilities with popular ticketing
and ITSM platforms for automated incident and vulnerability ticket creation.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import httpx
from urllib.parse import urljoin
import base64

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.integration import Integration

logger = get_logger(__name__)
metrics = get_metrics()


class TicketingConnector:
    """
    Ticketing system connector supporting multiple ITSM and ticketing platforms.
    
    Supported ticketing platforms:
    - Jira (Atlassian)
    - ServiceNow
    - Remedy (BMC)
    - Zendesk
    - Freshservice
    - PagerDuty
    - Linear
    - GitHub Issues
    - GitLab Issues
    - Custom ticketing systems
    """
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=30.0)
        self.supported_providers = {
            "jira": self._handle_jira,
            "servicenow": self._handle_servicenow,
            "remedy": self._handle_remedy,
            "zendesk": self._handle_zendesk,
            "freshservice": self._handle_freshservice,
            "pagerduty": self._handle_pagerduty,
            "linear": self._handle_linear,
            "github": self._handle_github_issues,
            "gitlab": self._handle_gitlab_issues,
            "custom": self._handle_custom_ticketing
        }
        
        logger.info("Ticketing connector initialized")
    
    @traced("ticketing_connector_connect")
    async def connect(self, integration: Integration) -> Dict[str, Any]:
        """Establish connection to ticketing platform."""
        try:
            provider = integration.provider.lower()
            if provider not in self.supported_providers:
                return {
                    "success": False,
                    "error": f"Unsupported ticketing provider: {provider}",
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
                logger.info(f"Successfully connected to {provider} ticketing: {integration.name}")
                metrics.ticketing_connector_connections_successful.inc()
            else:
                logger.error(f"Failed to connect to {provider} ticketing: {integration.name}")
                metrics.ticketing_connector_connections_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error connecting to ticketing system {integration.name}: {e}")
            metrics.ticketing_connector_errors.inc()
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("ticketing_connector_health_check")
    async def health_check(self, integration: Integration) -> Dict[str, Any]:
        """Perform health check on ticketing system connection."""
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
            
            metrics.ticketing_connector_health_checks.inc()
            return result
            
        except Exception as e:
            logger.error(f"Error checking ticketing system health {integration.name}: {e}")
            return {
                "healthy": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
    
    @traced("ticketing_connector_create_ticket")
    async def create_ticket(self, integration: Integration, event_type: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a ticket in the ticketing system."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            # Format ticket data for the platform
            ticket_data = self._format_ticket_data(provider, event_type, event_data, integration)
            
            result = await handler("create_ticket", integration, ticket_data)
            
            if result.get("success"):
                logger.info(f"Successfully created ticket in {provider}: {integration.name}")
                metrics.ticketing_connector_tickets_created.inc()
            else:
                logger.error(f"Failed to create ticket in {provider}: {integration.name}")
                metrics.ticketing_connector_tickets_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error creating ticket in {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    @traced("ticketing_connector_update_ticket")
    async def update_ticket(self, integration: Integration, ticket_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing ticket."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("update_ticket", integration, {"ticket_id": ticket_id, "update_data": update_data})
            
            if result.get("success"):
                logger.info(f"Successfully updated ticket {ticket_id} in {provider}: {integration.name}")
                metrics.ticketing_connector_tickets_updated.inc()
            else:
                logger.error(f"Failed to update ticket {ticket_id} in {provider}: {integration.name}")
                metrics.ticketing_connector_update_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error updating ticket in {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    @traced("ticketing_connector_pull_data")
    async def pull_data(self, integration: Integration) -> Dict[str, Any]:
        """Pull ticket data from ticketing system."""
        try:
            provider = integration.provider.lower()
            handler = self.supported_providers.get(provider)
            
            if not handler:
                return {"success": False, "error": "Unsupported provider"}
            
            result = await handler("pull_data", integration)
            
            if result.get("success"):
                logger.info(f"Successfully pulled ticket data from {provider}: {integration.name}")
                metrics.ticketing_connector_data_pulls_successful.inc()
            else:
                logger.error(f"Failed to pull ticket data from {provider}: {integration.name}")
                metrics.ticketing_connector_data_pulls_failed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Error pulling ticket data from {integration.name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "records_processed": 0
            }
    
    async def test_connection(self, integration: Integration) -> Dict[str, Any]:
        """Test ticketing system connection."""
        return await self.health_check(integration)
    
    async def disconnect(self, integration: Integration):
        """Disconnect from ticketing system."""
        try:
            provider = integration.provider.lower()
            logger.info(f"Disconnected from {provider} ticketing: {integration.name}")
            
        except Exception as e:
            logger.error(f"Error disconnecting from ticketing system {integration.name}: {e}")
    
    # Provider-specific handlers
    
    async def _handle_jira(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Jira operations."""
        try:
            config = integration.config
            credentials = integration.credentials
            
            base_url = config.get("url", "").rstrip("/")
            username = credentials.get("username")
            api_token = credentials.get("api_token")
            
            if not base_url or not username or not api_token:
                return {"success": False, "error": "Jira URL, username, and API token required"}
            
            # Prepare authentication
            auth_string = base64.b64encode(f"{username}:{api_token}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/json"
            }
            
            if action == "connect":
                # Test connection by getting user info
                response = await self.http_client.get(
                    f"{base_url}/rest/api/2/myself",
                    headers=headers
                )
                
                if response.status_code == 200:
                    user_info = response.json()
                    return {
                        "success": True,
                        "user": user_info.get("displayName"),
                        "capabilities": ["issues", "projects", "workflows", "comments"],
                        "supports_pull": True,
                        "supports_push": True,
                        "instance_type": "jira"
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text}"
                    }
            
            elif action == "health_check":
                response = await self.http_client.get(
                    f"{base_url}/rest/api/2/myself",
                    headers=headers
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code,
                    "health_data": {"api_accessible": response.status_code == 200}
                }
            
            elif action == "create_ticket":
                # Create Jira issue
                project_key = config.get("project_key")
                issue_type = config.get("default_issue_type", "Bug")
                
                if not project_key:
                    return {"success": False, "error": "Jira project key not configured"}
                
                issue_data = {
                    "fields": {
                        "project": {"key": project_key},
                        "summary": data.get("title", "Security Issue from MCP Platform"),
                        "description": data.get("description", "Security issue detected by MCP Security Platform"),
                        "issuetype": {"name": issue_type},
                        "priority": {"name": self._map_severity_to_jira_priority(data.get("severity", "medium"))},
                        "labels": data.get("labels", ["mcp-security", "automated"])
                    }
                }
                
                # Add custom fields if configured
                custom_fields = config.get("custom_fields", {})
                for field_id, field_value in custom_fields.items():
                    issue_data["fields"][field_id] = field_value
                
                response = await self.http_client.post(
                    f"{base_url}/rest/api/2/issue",
                    headers=headers,
                    json=issue_data
                )
                
                if response.status_code == 201:
                    issue_response = response.json()
                    issue_key = issue_response.get("key")
                    
                    return {
                        "success": True,
                        "ticket_id": issue_key,
                        "ticket_url": f"{base_url}/browse/{issue_key}",
                        "provider_response": issue_response
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Failed to create issue: {response.text}"
                    }
            
            elif action == "update_ticket":
                # Update Jira issue
                ticket_id = data.get("ticket_id")
                update_data = data.get("update_data", {})
                
                if not ticket_id:
                    return {"success": False, "error": "Ticket ID required"}
                
                # Prepare update payload
                update_payload = {"fields": {}}
                
                if "status" in update_data:
                    # Handle status transitions
                    transition_id = self._get_jira_transition_id(update_data["status"])
                    if transition_id:
                        transition_response = await self.http_client.post(
                            f"{base_url}/rest/api/2/issue/{ticket_id}/transitions",
                            headers=headers,
                            json={"transition": {"id": transition_id}}
                        )
                        if transition_response.status_code != 204:
                            logger.warning(f"Failed to transition issue status: {transition_response.text}")
                
                if "comment" in update_data:
                    # Add comment
                    comment_response = await self.http_client.post(
                        f"{base_url}/rest/api/2/issue/{ticket_id}/comment",
                        headers=headers,
                        json={"body": update_data["comment"]}
                    )
                    if comment_response.status_code != 201:
                        logger.warning(f"Failed to add comment: {comment_response.text}")
                
                # Update other fields
                if "priority" in update_data:
                    update_payload["fields"]["priority"] = {"name": update_data["priority"]}
                
                if "assignee" in update_data:
                    update_payload["fields"]["assignee"] = {"name": update_data["assignee"]}
                
                if update_payload["fields"]:
                    response = await self.http_client.put(
                        f"{base_url}/rest/api/2/issue/{ticket_id}",
                        headers=headers,
                        json=update_payload
                    )
                    
                    return {"success": response.status_code == 204}
                else:
                    return {"success": True, "message": "No field updates required"}
            
            elif action == "pull_data":
                # Pull recent issues
                project_key = config.get("project_key")
                days_back = config.get("days_back", 7)
                max_results = config.get("max_results", 50)
                
                # Build JQL query
                jql_parts = []
                if project_key:
                    jql_parts.append(f"project = {project_key}")
                
                if days_back:
                    jql_parts.append(f"created >= -{days_back}d")
                
                # Add security-related filters
                jql_parts.append("(labels in (mcp-security) OR summary ~ 'security' OR summary ~ 'vulnerability')")
                
                jql = " AND ".join(jql_parts)
                
                params = {
                    "jql": jql,
                    "maxResults": max_results,
                    "fields": "summary,status,priority,created,updated,assignee,reporter,labels"
                }
                
                response = await self.http_client.get(
                    f"{base_url}/rest/api/2/search",
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    search_results = response.json()
                    issues = search_results.get("issues", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(issues),
                        "records_successful": len(issues),
                        "records_failed": 0,
                        "data": issues,
                        "metadata": {
                            "total": search_results.get("total", 0),
                            "jql": jql
                        }
                    }
                else:
                    return {"success": False, "error": f"Failed to search issues: {response.text}"}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
                
        except Exception as e:
            logger.error(f"Error in Jira handler: {e}")
            return {"success": False, "error": str(e)}
    
    async def _handle_servicenow(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle ServiceNow operations."""
        try:
            config = integration.config
            credentials = integration.credentials
            
            instance_url = config.get("instance_url", "").rstrip("/")
            username = credentials.get("username")
            password = credentials.get("password")
            
            if not instance_url or not username or not password:
                return {"success": False, "error": "ServiceNow instance URL, username, and password required"}
            
            # Prepare authentication
            auth_string = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers = {
                "Authorization": f"Basic {auth_string}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            if action == "connect":
                # Test connection by getting user info
                response = await self.http_client.get(
                    f"{instance_url}/api/now/table/sys_user",
                    headers=headers,
                    params={"sysparm_limit": 1}
                )
                
                if response.status_code == 200:
                    return {
                        "success": True,
                        "instance": instance_url,
                        "capabilities": ["incidents", "change_requests", "problems", "tasks"],
                        "supports_pull": True,
                        "supports_push": True,
                        "instance_type": "servicenow"
                    }
                else:
                    return {
                        "success": False,
                        "error": f"HTTP {response.status_code}: {response.text}"
                    }
            
            elif action == "health_check":
                response = await self.http_client.get(
                    f"{instance_url}/api/now/table/sys_user",
                    headers=headers,
                    params={"sysparm_limit": 1}
                )
                
                return {
                    "healthy": response.status_code == 200,
                    "status_code": response.status_code,
                    "health_data": {"api_accessible": response.status_code == 200}
                }
            
            elif action == "create_ticket":
                # Create ServiceNow incident
                table_name = config.get("table_name", "incident")
                
                incident_data = {
                    "short_description": data.get("title", "Security Issue from MCP Platform"),
                    "description": data.get("description", "Security issue detected by MCP Security Platform"),
                    "category": config.get("default_category", "Security"),
                    "subcategory": config.get("default_subcategory", "Security Incident"),
                    "priority": self._map_severity_to_servicenow_priority(data.get("severity", "medium")),
                    "impact": self._map_severity_to_servicenow_impact(data.get("severity", "medium")),
                    "urgency": self._map_severity_to_servicenow_urgency(data.get("severity", "medium")),
                    "caller_id": config.get("default_caller"),
                    "assignment_group": config.get("default_assignment_group")
                }
                
                # Remove None values
                incident_data = {k: v for k, v in incident_data.items() if v is not None}
                
                response = await self.http_client.post(
                    f"{instance_url}/api/now/table/{table_name}",
                    headers=headers,
                    json=incident_data
                )
                
                if response.status_code == 201:
                    incident_response = response.json()
                    incident_result = incident_response.get("result", {})
                    incident_number = incident_result.get("number")
                    
                    return {
                        "success": True,
                        "ticket_id": incident_number,
                        "ticket_url": f"{instance_url}/{table_name}.do?sys_id={incident_result.get('sys_id')}",
                        "provider_response": incident_result
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Failed to create incident: {response.text}"
                    }
            
            elif action == "pull_data":
                # Pull recent incidents
                table_name = config.get("table_name", "incident")
                days_back = config.get("days_back", 7)
                max_results = config.get("max_results", 50)
                
                # Calculate date filter
                cutoff_date = (datetime.now() - timedelta(days=days_back)).strftime("%Y-%m-%d")
                
                params = {
                    "sysparm_query": f"opened_at>=javascript:gs.dateGenerate('{cutoff_date}','00:00:00')^categoryLIKEsecurity",
                    "sysparm_limit": max_results,
                    "sysparm_fields": "number,short_description,state,priority,category,opened_at,resolved_at,assigned_to"
                }
                
                response = await self.http_client.get(
                    f"{instance_url}/api/now/table/{table_name}",
                    headers=headers,
                    params=params
                )
                
                if response.status_code == 200:
                    incidents_response = response.json()
                    incidents = incidents_response.get("result", [])
                    
                    return {
                        "success": True,
                        "records_processed": len(incidents),
                        "records_successful": len(incidents),
                        "records_failed": 0,
                        "data": incidents,
                        "metadata": {"table": table_name, "days_back": days_back}
                    }
                else:
                    return {"success": False, "error": f"Failed to retrieve incidents: {response.text}"}
            
            elif action == "disconnect":
                return {"success": True}
            
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
                
        except Exception as e:
            logger.error(f"Error in ServiceNow handler: {e}")
            return {"success": False, "error": str(e)}
    
    # Placeholder handlers for other providers
    
    async def _handle_remedy(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle BMC Remedy operations."""
        return {"success": False, "error": "BMC Remedy integration not yet implemented"}
    
    async def _handle_zendesk(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Zendesk operations."""
        return {"success": False, "error": "Zendesk integration not yet implemented"}
    
    async def _handle_freshservice(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Freshservice operations."""
        return {"success": False, "error": "Freshservice integration not yet implemented"}
    
    async def _handle_pagerduty(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle PagerDuty operations."""
        return {"success": False, "error": "PagerDuty integration not yet implemented"}
    
    async def _handle_linear(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle Linear operations."""
        return {"success": False, "error": "Linear integration not yet implemented"}
    
    async def _handle_github_issues(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle GitHub Issues operations."""
        return {"success": False, "error": "GitHub Issues integration not yet implemented"}
    
    async def _handle_gitlab_issues(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle GitLab Issues operations."""
        return {"success": False, "error": "GitLab Issues integration not yet implemented"}
    
    async def _handle_custom_ticketing(self, action: str, integration: Integration, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Handle custom ticketing system operations."""
        return {"success": False, "error": "Custom ticketing integration not yet implemented"}
    
    # Helper methods
    
    def _format_ticket_data(self, provider: str, event_type: str, event_data: Dict[str, Any], integration: Integration) -> Dict[str, Any]:
        """Format ticket data for specific ticketing platform."""
        # Extract relevant information from event data
        title = f"Security Alert: {event_type}"
        description = event_data.get("description", f"Security event of type '{event_type}' detected by MCP Security Platform")
        severity = event_data.get("severity", "medium")
        
        # Add event details to description
        if "details" in event_data:
            description += f"\n\nDetails:\n{json.dumps(event_data['details'], indent=2)}"
        
        # Add indicators if present
        if "indicators" in event_data:
            description += f"\n\nIndicators:\n{json.dumps(event_data['indicators'], indent=2)}"
        
        # Add source information
        description += f"\n\nSource: MCP Security Platform\nEvent ID: {event_data.get('id', 'N/A')}\nTimestamp: {datetime.now().isoformat()}"
        
        base_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "event_type": event_type,
            "labels": ["mcp-security", "automated", event_type.replace("_", "-")]
        }
        
        return base_data
    
    def _map_severity_to_jira_priority(self, severity: str) -> str:
        """Map MCP severity to Jira priority."""
        mapping = {
            "low": "Low",
            "medium": "Medium", 
            "high": "High",
            "critical": "Highest"
        }
        return mapping.get(severity.lower(), "Medium")
    
    def _map_severity_to_servicenow_priority(self, severity: str) -> str:
        """Map MCP severity to ServiceNow priority."""
        mapping = {
            "low": "4",     # Low
            "medium": "3",  # Moderate
            "high": "2",    # High
            "critical": "1" # Critical
        }
        return mapping.get(severity.lower(), "3")
    
    def _map_severity_to_servicenow_impact(self, severity: str) -> str:
        """Map MCP severity to ServiceNow impact."""
        mapping = {
            "low": "3",     # Low
            "medium": "2",  # Medium
            "high": "2",    # Medium
            "critical": "1" # High
        }
        return mapping.get(severity.lower(), "2")
    
    def _map_severity_to_servicenow_urgency(self, severity: str) -> str:
        """Map MCP severity to ServiceNow urgency."""
        mapping = {
            "low": "3",     # Low
            "medium": "2",  # Medium
            "high": "2",    # Medium
            "critical": "1" # High
        }
        return mapping.get(severity.lower(), "2")
    
    def _get_jira_transition_id(self, status: str) -> Optional[str]:
        """Get Jira transition ID for status change."""
        # This would need to be configurable per Jira instance
        # Common transition IDs (these vary by workflow)
        transitions = {
            "in_progress": "4",
            "resolved": "5",
            "closed": "6",
            "reopened": "3"
        }
        return transitions.get(status.lower())
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_client.aclose()