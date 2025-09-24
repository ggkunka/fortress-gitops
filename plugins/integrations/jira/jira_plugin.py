"""
JIRA Integration Plugin - Issue tracking and project management integration

This plugin integrates with Atlassian JIRA to provide issue creation, tracking,
and project management capabilities for security findings and incidents.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import aiohttp
from urllib.parse import urljoin
import base64

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseIntegrationPlugin, IntegrationConfig, IntegrationResult

logger = get_logger(__name__)
metrics = get_metrics()


class JiraConfig(IntegrationConfig):
    """JIRA integration configuration."""
    api_endpoint: str  # Required: JIRA instance URL
    username: str  # Required for basic auth
    api_token: str  # Required: API token or password
    
    # Default project settings
    default_project_key: Optional[str] = None
    default_issue_type: str = "Bug"
    default_priority: str = "Medium"
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 300  # Conservative limit
    
    # API options
    api_version: str = "3"  # JIRA Cloud API version
    user_agent: str = "MCP-Security-Platform/1.0"
    
    # Security issue mapping
    severity_to_priority_mapping: Dict[str, str] = {
        "CRITICAL": "Highest",
        "HIGH": "High", 
        "MEDIUM": "Medium",
        "LOW": "Low",
        "UNKNOWN": "Lowest"
    }
    
    # Custom fields mapping
    custom_fields: Dict[str, str] = {}  # Map custom field names to IDs
    
    # Workflow settings
    auto_assign: bool = False
    default_assignee: Optional[str] = None
    
    # Labels and components
    security_labels: List[str] = ["security", "vulnerability"]
    default_components: List[str] = []


class JiraPlugin(BaseIntegrationPlugin):
    """
    JIRA integration plugin.
    
    Provides integration with JIRA for:
    - Security issue creation and tracking
    - Vulnerability management
    - Incident response workflow
    - Project and epic management
    - Custom field management
    - Automated workflows
    """
    
    def __init__(self, config: JiraConfig):
        super().__init__(config)
        self.config = config
        self.name = "jira"
        self.version = "1.0.0"
        self.description = "JIRA issue tracking and project management integration"
        
        # Supported operations
        self.supported_operations = [
            "create_issue",
            "update_issue",
            "get_issue",
            "search_issues",
            "create_project",
            "get_project",
            "list_projects",
            "add_comment",
            "transition_issue",
            "create_epic",
            "link_issues",
            "add_attachment"
        ]
        
        # API session
        self.session: Optional[aiohttp.ClientSession] = None
        
        logger.info("JIRA plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the JIRA plugin."""
        try:
            # Create basic auth header
            auth_string = f"{self.config.username}:{self.config.api_token}"
            auth_bytes = auth_string.encode('ascii')
            auth_header = base64.b64encode(auth_bytes).decode('ascii')
            
            # Create HTTP session with authentication
            headers = {
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": self.config.user_agent
            }
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=50)
            )
            
            # Test API connection
            await self._test_connection()
            
            logger.info("JIRA plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize JIRA plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup JIRA plugin resources."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
            
            logger.info("JIRA plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup JIRA plugin: {e}")
            return False
    
    @traced("jira_plugin_create_issue")
    async def create_issue(
        self, 
        project_key: str, 
        summary: str, 
        description: str,
        issue_type: Optional[str] = None,
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
        labels: Optional[List[str]] = None,
        components: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a JIRA issue."""
        try:
            issue_type = issue_type or self.config.default_issue_type
            priority = priority or self.config.default_priority
            
            # Build issue data
            issue_data = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": summary,
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "text": description,
                                        "type": "text"
                                    }
                                ]
                            }
                        ]
                    },
                    "issuetype": {"name": issue_type},
                    "priority": {"name": priority}
                }
            }
            
            # Add assignee
            if assignee or (self.config.auto_assign and self.config.default_assignee):
                assignee_name = assignee or self.config.default_assignee
                issue_data["fields"]["assignee"] = {"name": assignee_name}
            
            # Add labels
            if labels:
                issue_data["fields"]["labels"] = labels
            elif self.config.security_labels:
                issue_data["fields"]["labels"] = self.config.security_labels
            
            # Add components
            if components:
                issue_data["fields"]["components"] = [{"name": comp} for comp in components]
            elif self.config.default_components:
                issue_data["fields"]["components"] = [{"name": comp} for comp in self.config.default_components]
            
            # Add custom fields
            if custom_fields:
                for field_name, value in custom_fields.items():
                    field_id = self.config.custom_fields.get(field_name, field_name)
                    issue_data["fields"][field_id] = value
            
            url = "/rest/api/3/issue"
            response = await self._make_request("POST", url, json=issue_data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="issue",
                resource_id=response.get("key"),
                status="success",
                data=response
            )
            
            logger.info(f"Created JIRA issue {response.get('key')} in project {project_key}")
            metrics.jira_issues_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create JIRA issue: {e}")
            metrics.jira_api_errors.inc()
            
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="issue",
                status="failed",
                error_message=str(e)
            )
    
    @traced("jira_plugin_create_security_issue")
    async def create_security_issue(
        self, 
        project_key: str, 
        vulnerability_id: str,
        severity: str,
        description: str,
        affected_component: Optional[str] = None,
        cve_id: Optional[str] = None,
        scan_result: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a security-specific JIRA issue."""
        try:
            # Map severity to priority
            priority = self.config.severity_to_priority_mapping.get(severity.upper(), "Medium")
            
            # Build summary
            summary = f"Security Vulnerability: {vulnerability_id}"
            if cve_id:
                summary += f" ({cve_id})"
            
            # Build detailed description
            description_parts = [
                f"**Vulnerability ID:** {vulnerability_id}",
                f"**Severity:** {severity}",
                f"**Description:** {description}"
            ]
            
            if affected_component:
                description_parts.append(f"**Affected Component:** {affected_component}")
            
            if cve_id:
                description_parts.append(f"**CVE ID:** {cve_id}")
            
            if scan_result:
                description_parts.append("**Scan Details:**")
                description_parts.append(f"```json\n{json.dumps(scan_result, indent=2)}\n```")
            
            full_description = "\n\n".join(description_parts)
            
            # Create labels
            labels = self.config.security_labels.copy()
            labels.extend([severity.lower(), "vulnerability"])
            if cve_id:
                labels.append(cve_id.lower())
            
            # Custom fields for security issues
            custom_fields = {
                "Vulnerability ID": vulnerability_id,
                "Severity Level": severity,
                "CVE ID": cve_id
            }
            
            return await self.create_issue(
                project_key=project_key,
                summary=summary,
                description=full_description,
                issue_type="Security Bug",
                priority=priority,
                labels=labels,
                custom_fields=custom_fields
            )
            
        except Exception as e:
            logger.error(f"Failed to create security issue: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="security_issue",
                status="failed",
                error_message=str(e)
            )
    
    async def create_resource(
        self, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a JIRA resource."""
        try:
            if resource_type == "issue":
                return await self.create_issue(
                    project_key=data["project_key"],
                    summary=data["summary"],
                    description=data["description"],
                    issue_type=data.get("issue_type"),
                    priority=data.get("priority"),
                    assignee=data.get("assignee"),
                    labels=data.get("labels"),
                    components=data.get("components"),
                    custom_fields=data.get("custom_fields")
                )
            elif resource_type == "security_issue":
                return await self.create_security_issue(
                    project_key=data["project_key"],
                    vulnerability_id=data["vulnerability_id"],
                    severity=data["severity"],
                    description=data["description"],
                    affected_component=data.get("affected_component"),
                    cve_id=data.get("cve_id"),
                    scan_result=data.get("scan_result")
                )
            elif resource_type == "comment":
                return await self.add_comment(
                    issue_key=data["issue_key"],
                    comment=data["comment"]
                )
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to create JIRA resource: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type=resource_type,
                status="failed",
                error_message=str(e)
            )
    
    async def update_resource(
        self, 
        resource_id: str, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Update a JIRA resource."""
        try:
            if resource_type == "issue":
                url = f"/rest/api/3/issue/{resource_id}"
                
                # Build update data
                update_data = {"fields": {}}
                
                if "summary" in data:
                    update_data["fields"]["summary"] = data["summary"]
                if "description" in data:
                    update_data["fields"]["description"] = {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "text": data["description"],
                                        "type": "text"
                                    }
                                ]
                            }
                        ]
                    }
                if "priority" in data:
                    update_data["fields"]["priority"] = {"name": data["priority"]}
                if "labels" in data:
                    update_data["fields"]["labels"] = data["labels"]
                
                response = await self._make_request("PUT", url, json=update_data)
                
                result = IntegrationResult(
                    plugin_name=self.name,
                    plugin_version=self.version,
                    operation_type="update",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status="success",
                    data={"message": "Issue updated successfully"}
                )
                
                logger.info(f"Updated JIRA issue {resource_id}")
                
                return result
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to update JIRA resource: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="update",
                resource_type=resource_type,
                resource_id=resource_id,
                status="failed",
                error_message=str(e)
            )
    
    async def delete_resource(
        self, 
        resource_id: str, 
        resource_type: str,
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Delete a JIRA resource."""
        try:
            if resource_type == "issue":
                url = f"/rest/api/3/issue/{resource_id}"
                response = await self._make_request("DELETE", url)
                
                result = IntegrationResult(
                    plugin_name=self.name,
                    plugin_version=self.version,
                    operation_type="delete",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status="success",
                    data={"message": "Issue deleted successfully"}
                )
                
                logger.info(f"Deleted JIRA issue {resource_id}")
                return result
            else:
                raise ValueError(f"Cannot delete resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to delete JIRA resource: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="delete",
                resource_type=resource_type,
                resource_id=resource_id,
                status="failed",
                error_message=str(e)
            )
    
    async def query_resources(
        self, 
        resource_type: str, 
        filters: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Query JIRA resources."""
        try:
            filters = filters or {}
            options = options or {}
            
            if resource_type == "issues":
                jql = self._build_jql_query(filters)
                response = await self.search_issues(
                    jql=jql,
                    max_results=options.get("max_results", 50),
                    start_at=options.get("start_at", 0)
                )
            elif resource_type == "projects":
                response = await self.get_projects()
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="query",
                resource_type=resource_type,
                status="success",
                data=response
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to query JIRA resources: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="query",
                resource_type=resource_type,
                status="failed",
                error_message=str(e)
            )
    
    @traced("jira_plugin_search_issues")
    async def search_issues(
        self, 
        jql: str, 
        max_results: int = 50,
        start_at: int = 0,
        fields: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Search issues using JQL."""
        try:
            data = {
                "jql": jql,
                "maxResults": max_results,
                "startAt": start_at
            }
            
            if fields:
                data["fields"] = fields
            
            url = "/rest/api/3/search"
            response = await self._make_request("POST", url, json=data)
            
            logger.info(f"Searched JIRA issues: {response.get('total', 0)} results")
            metrics.jira_searches_performed.inc()
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to search JIRA issues: {e}")
            raise
    
    @traced("jira_plugin_add_comment")
    async def add_comment(self, issue_key: str, comment: str) -> IntegrationResult:
        """Add comment to JIRA issue."""
        try:
            comment_data = {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "text": comment,
                                    "type": "text"
                                }
                            ]
                        }
                    ]
                }
            }
            
            url = f"/rest/api/3/issue/{issue_key}/comment"
            response = await self._make_request("POST", url, json=comment_data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="comment",
                resource_id=response.get("id"),
                status="success",
                data=response
            )
            
            logger.info(f"Added comment to JIRA issue {issue_key}")
            metrics.jira_comments_added.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="comment",
                status="failed",
                error_message=str(e)
            )
    
    @traced("jira_plugin_get_projects")
    async def get_projects(self) -> List[Dict[str, Any]]:
        """Get JIRA projects."""
        try:
            url = "/rest/api/3/project"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved {len(response)} JIRA projects")
            metrics.jira_projects_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get projects: {e}")
            raise
    
    def _build_jql_query(self, filters: Dict[str, Any]) -> str:
        """Build JQL query from filters."""
        conditions = []
        
        if "project" in filters:
            conditions.append(f"project = {filters['project']}")
        
        if "status" in filters:
            if isinstance(filters["status"], list):
                statuses = ", ".join([f'"{s}"' for s in filters["status"]])
                conditions.append(f"status IN ({statuses})")
            else:
                conditions.append(f'status = "{filters["status"]}"')
        
        if "assignee" in filters:
            conditions.append(f'assignee = "{filters["assignee"]}"')
        
        if "labels" in filters:
            if isinstance(filters["labels"], list):
                for label in filters["labels"]:
                    conditions.append(f'labels = "{label}"')
            else:
                conditions.append(f'labels = "{filters["labels"]}"')
        
        if "created" in filters:
            conditions.append(f'created >= "{filters["created"]}"')
        
        if "updated" in filters:
            conditions.append(f'updated >= "{filters["updated"]}"')
        
        if "text" in filters:
            conditions.append(f'text ~ "{filters["text"]}"')
        
        jql = " AND ".join(conditions) if conditions else "project is not EMPTY"
        
        # Add order by
        order_by = filters.get("order_by", "created DESC")
        jql += f" ORDER BY {order_by}"
        
        return jql
    
    async def _test_connection(self):
        """Test JIRA API connection."""
        try:
            response = await self._make_request("GET", "/rest/api/3/myself")
            logger.info(f"JIRA API connection successful (user: {response.get('displayName')})")
        except Exception as e:
            logger.error(f"JIRA API connection failed: {e}")
            raise
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Make JIRA API request."""
        try:
            if not self.session:
                raise RuntimeError("JIRA session not initialized")
            
            full_url = urljoin(self.config.api_endpoint, url)
            
            async with self.session.request(
                method, 
                full_url, 
                json=json, 
                params=params
            ) as response:
                
                response.raise_for_status()
                
                if response.content_type == "application/json":
                    return await response.json()
                else:
                    return await response.text()
                    
        except Exception as e:
            logger.error(f"JIRA API request failed: {method} {url} - {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_operations": self.supported_operations,
            "api_endpoint": self.config.api_endpoint,
            "default_project": self.config.default_project_key,
            "rate_limit": self.config.rate_limit_requests_per_minute
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": self.session is not None and not self.session.closed,
                "session_active": self.session is not None,
                "api_endpoint": self.config.api_endpoint,
                "last_error": self.last_error
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }