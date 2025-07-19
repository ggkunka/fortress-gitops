"""
GitLab Integration Plugin - Repository and security management integration

This plugin integrates with GitLab's REST API to provide repository management,
security scanning, and issue tracking capabilities.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
import aiohttp
from urllib.parse import urljoin, quote

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseIntegrationPlugin, IntegrationConfig, IntegrationResult

logger = get_logger(__name__)
metrics = get_metrics()


class GitLabConfig(IntegrationConfig):
    """GitLab integration configuration."""
    api_endpoint: str = "https://gitlab.com/api/v4"
    api_token: str  # Required for GitLab API (personal access token)
    group_id: Optional[int] = None
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 2000  # GitLab allows 2000/minute for authenticated
    
    # API options
    user_agent: str = "MCP-Security-Platform/1.0"
    
    # Security scanning options
    enable_sast: bool = True
    enable_dependency_scanning: bool = True
    enable_container_scanning: bool = True
    enable_secret_detection: bool = True
    enable_license_scanning: bool = True
    
    # Webhook options
    webhook_token: Optional[str] = None
    webhook_events: List[str] = [
        "push_events", "issues_events", "merge_requests_events",
        "pipeline_events", "job_events", "deployment_events"
    ]


class GitLabPlugin(BaseIntegrationPlugin):
    """
    GitLab integration plugin.
    
    Provides integration with GitLab for:
    - Repository management
    - Security scanning and vulnerability reports
    - Issue and MR management
    - Pipeline and job management
    - Dependency scanning
    - Container scanning
    - Secret detection
    """
    
    def __init__(self, config: GitLabConfig):
        super().__init__(config)
        self.config = config
        self.name = "gitlab"
        self.version = "1.0.0"
        self.description = "GitLab repository and security integration"
        
        # Supported operations
        self.supported_operations = [
            "create_issue",
            "update_issue",
            "create_merge_request",
            "update_merge_request",
            "get_project",
            "list_projects",
            "get_vulnerabilities",
            "get_vulnerability_findings",
            "get_pipeline_security_report",
            "create_webhook",
            "get_dependencies",
            "trigger_pipeline"
        ]
        
        # API session
        self.session: Optional[aiohttp.ClientSession] = None
        
        logger.info("GitLab plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the GitLab plugin."""
        try:
            # Create HTTP session with authentication
            headers = {
                "Authorization": f"Bearer {self.config.api_token}",
                "Content-Type": "application/json",
                "User-Agent": self.config.user_agent
            }
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self.session = aiohttp.ClientSession(
                headers=headers,
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=100)
            )
            
            # Test API connection
            await self._test_connection()
            
            logger.info("GitLab plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GitLab plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup GitLab plugin resources."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
            
            logger.info("GitLab plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup GitLab plugin: {e}")
            return False
    
    @traced("gitlab_plugin_create_issue")
    async def create_issue(
        self, 
        project_id: Union[int, str], 
        title: str, 
        description: str,
        labels: Optional[List[str]] = None,
        assignee_ids: Optional[List[int]] = None,
        milestone_id: Optional[int] = None,
        confidential: bool = False
    ) -> IntegrationResult:
        """Create a GitLab issue."""
        try:
            data = {
                "title": title,
                "description": description,
                "confidential": confidential
            }
            
            if labels:
                data["labels"] = ",".join(labels)
            if assignee_ids:
                data["assignee_ids"] = assignee_ids
            if milestone_id:
                data["milestone_id"] = milestone_id
            
            url = f"/projects/{quote(str(project_id), safe='')}/issues"
            response = await self._make_request("POST", url, json=data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="issue",
                resource_id=str(response.get("iid")),
                status="success",
                data=response
            )
            
            logger.info(f"Created GitLab issue #{response.get('iid')} in project {project_id}")
            metrics.gitlab_issues_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create GitLab issue: {e}")
            metrics.gitlab_api_errors.inc()
            
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="issue",
                status="failed",
                error_message=str(e)
            )
    
    @traced("gitlab_plugin_create_merge_request")
    async def create_merge_request(
        self, 
        project_id: Union[int, str], 
        title: str, 
        source_branch: str, 
        target_branch: str,
        description: Optional[str] = None,
        assignee_ids: Optional[List[int]] = None,
        reviewer_ids: Optional[List[int]] = None,
        remove_source_branch: bool = False
    ) -> IntegrationResult:
        """Create a GitLab merge request."""
        try:
            data = {
                "title": title,
                "source_branch": source_branch,
                "target_branch": target_branch,
                "remove_source_branch": remove_source_branch
            }
            
            if description:
                data["description"] = description
            if assignee_ids:
                data["assignee_ids"] = assignee_ids
            if reviewer_ids:
                data["reviewer_ids"] = reviewer_ids
            
            url = f"/projects/{quote(str(project_id), safe='')}/merge_requests"
            response = await self._make_request("POST", url, json=data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="merge_request",
                resource_id=str(response.get("iid")),
                status="success",
                data=response
            )
            
            logger.info(f"Created GitLab MR #{response.get('iid')} in project {project_id}")
            metrics.gitlab_merge_requests_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create GitLab MR: {e}")
            metrics.gitlab_api_errors.inc()
            
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="merge_request",
                status="failed",
                error_message=str(e)
            )
    
    async def create_resource(
        self, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a GitLab resource."""
        try:
            if resource_type == "issue":
                return await self.create_issue(
                    project_id=data["project_id"],
                    title=data["title"],
                    description=data.get("description", ""),
                    labels=data.get("labels"),
                    assignee_ids=data.get("assignee_ids"),
                    milestone_id=data.get("milestone_id"),
                    confidential=data.get("confidential", False)
                )
            elif resource_type == "merge_request":
                return await self.create_merge_request(
                    project_id=data["project_id"],
                    title=data["title"],
                    source_branch=data["source_branch"],
                    target_branch=data["target_branch"],
                    description=data.get("description"),
                    assignee_ids=data.get("assignee_ids"),
                    reviewer_ids=data.get("reviewer_ids"),
                    remove_source_branch=data.get("remove_source_branch", False)
                )
            elif resource_type == "webhook":
                return await self.create_webhook(
                    project_id=data["project_id"],
                    url=data["url"],
                    events=data.get("events", self.config.webhook_events)
                )
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to create GitLab resource: {e}")
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
        """Update a GitLab resource."""
        try:
            project_id = data.get("project_id")
            if not project_id:
                raise ValueError("Project ID is required")
            
            encoded_project_id = quote(str(project_id), safe='')
            
            if resource_type == "issue":
                url = f"/projects/{encoded_project_id}/issues/{resource_id}"
                response = await self._make_request("PUT", url, json=data)
            elif resource_type == "merge_request":
                url = f"/projects/{encoded_project_id}/merge_requests/{resource_id}"
                response = await self._make_request("PUT", url, json=data)
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="update",
                resource_type=resource_type,
                resource_id=resource_id,
                status="success",
                data=response
            )
            
            logger.info(f"Updated GitLab {resource_type} #{resource_id} in project {project_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to update GitLab resource: {e}")
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
        """Delete a GitLab resource."""
        try:
            project_id = options.get("project_id") if options else None
            if not project_id:
                raise ValueError("Project ID is required")
            
            encoded_project_id = quote(str(project_id), safe='')
            
            if resource_type == "issue":
                # Close the issue
                data = {"state_event": "close"}
                url = f"/projects/{encoded_project_id}/issues/{resource_id}"
                response = await self._make_request("PUT", url, json=data)
            elif resource_type == "merge_request":
                # Close the merge request
                data = {"state_event": "close"}
                url = f"/projects/{encoded_project_id}/merge_requests/{resource_id}"
                response = await self._make_request("PUT", url, json=data)
            elif resource_type == "webhook":
                # Delete the webhook
                url = f"/projects/{encoded_project_id}/hooks/{resource_id}"
                response = await self._make_request("DELETE", url)
            else:
                raise ValueError(f"Cannot delete resource type: {resource_type}")
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="delete",
                resource_type=resource_type,
                resource_id=resource_id,
                status="success",
                data=response if resource_type == "webhook" else {"state": "closed"}
            )
            
            action = "Deleted" if resource_type == "webhook" else "Closed"
            logger.info(f"{action} GitLab {resource_type} #{resource_id}")
            return result
                
        except Exception as e:
            logger.error(f"Failed to delete GitLab resource: {e}")
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
        """Query GitLab resources."""
        try:
            filters = filters or {}
            options = options or {}
            
            if resource_type == "projects":
                response = await self.get_projects(
                    group_id=filters.get("group_id"),
                    visibility=filters.get("visibility", "private"),
                    order_by=filters.get("order_by", "last_activity_at"),
                    per_page=options.get("per_page", 20)
                )
            elif resource_type == "vulnerabilities":
                project_id = filters.get("project_id")
                if not project_id:
                    raise ValueError("Project ID is required for vulnerability queries")
                response = await self.get_vulnerabilities(project_id)
            elif resource_type == "vulnerability_findings":
                project_id = filters.get("project_id")
                if not project_id:
                    raise ValueError("Project ID is required for vulnerability finding queries")
                response = await self.get_vulnerability_findings(project_id)
            elif resource_type == "security_reports":
                project_id = filters.get("project_id")
                pipeline_id = filters.get("pipeline_id")
                if not project_id or not pipeline_id:
                    raise ValueError("Project ID and Pipeline ID are required for security report queries")
                response = await self.get_pipeline_security_report(project_id, pipeline_id)
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
            logger.error(f"Failed to query GitLab resources: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="query",
                resource_type=resource_type,
                status="failed",
                error_message=str(e)
            )
    
    @traced("gitlab_plugin_get_projects")
    async def get_projects(
        self, 
        group_id: Optional[int] = None,
        visibility: str = "private",
        order_by: str = "last_activity_at",
        per_page: int = 20
    ) -> List[Dict[str, Any]]:
        """Get GitLab projects."""
        try:
            if group_id or self.config.group_id:
                gid = group_id or self.config.group_id
                url = f"/groups/{gid}/projects"
            else:
                url = "/projects"
            
            params = {
                "visibility": visibility,
                "order_by": order_by,
                "sort": "desc",
                "per_page": per_page,
                "membership": True
            }
            
            response = await self._make_request("GET", url, params=params)
            
            logger.info(f"Retrieved {len(response)} projects")
            metrics.gitlab_projects_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get projects: {e}")
            raise
    
    @traced("gitlab_plugin_get_vulnerabilities")
    async def get_vulnerabilities(self, project_id: Union[int, str]) -> List[Dict[str, Any]]:
        """Get project vulnerabilities."""
        try:
            encoded_project_id = quote(str(project_id), safe='')
            url = f"/projects/{encoded_project_id}/vulnerabilities"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved {len(response)} vulnerabilities for project {project_id}")
            metrics.gitlab_vulnerabilities_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get vulnerabilities: {e}")
            raise
    
    @traced("gitlab_plugin_get_vulnerability_findings")
    async def get_vulnerability_findings(self, project_id: Union[int, str]) -> List[Dict[str, Any]]:
        """Get vulnerability findings from security reports."""
        try:
            encoded_project_id = quote(str(project_id), safe='')
            url = f"/projects/{encoded_project_id}/vulnerability_findings"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved {len(response)} vulnerability findings for project {project_id}")
            metrics.gitlab_vulnerability_findings_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability findings: {e}")
            raise
    
    @traced("gitlab_plugin_get_pipeline_security_report")
    async def get_pipeline_security_report(
        self, 
        project_id: Union[int, str], 
        pipeline_id: int
    ) -> Dict[str, Any]:
        """Get pipeline security report."""
        try:
            encoded_project_id = quote(str(project_id), safe='')
            url = f"/projects/{encoded_project_id}/pipelines/{pipeline_id}/security_report_summary"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved security report for pipeline {pipeline_id} in project {project_id}")
            metrics.gitlab_security_reports_fetched.inc()
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get pipeline security report: {e}")
            raise
    
    @traced("gitlab_plugin_create_webhook")
    async def create_webhook(
        self, 
        project_id: Union[int, str], 
        url: str, 
        events: Optional[List[str]] = None
    ) -> IntegrationResult:
        """Create a webhook."""
        try:
            events = events or self.config.webhook_events
            
            # Convert event list to webhook parameters
            webhook_data = {
                "url": url,
                "enable_ssl_verification": True
            }
            
            # Add event flags
            for event in events:
                webhook_data[event] = True
            
            if self.config.webhook_token:
                webhook_data["token"] = self.config.webhook_token
            
            encoded_project_id = quote(str(project_id), safe='')
            webhook_url = f"/projects/{encoded_project_id}/hooks"
            response = await self._make_request("POST", webhook_url, json=webhook_data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="webhook",
                resource_id=str(response.get("id")),
                status="success",
                data=response
            )
            
            logger.info(f"Created webhook for project {project_id}")
            metrics.gitlab_webhooks_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create webhook: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="webhook",
                status="failed",
                error_message=str(e)
            )
    
    async def _test_connection(self):
        """Test GitLab API connection."""
        try:
            response = await self._make_request("GET", "/user")
            logger.info(f"GitLab API connection successful (user: {response.get('username')})")
        except Exception as e:
            logger.error(f"GitLab API connection failed: {e}")
            raise
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Make GitLab API request."""
        try:
            if not self.session:
                raise RuntimeError("GitLab session not initialized")
            
            full_url = urljoin(self.config.api_endpoint, url)
            
            async with self.session.request(
                method, 
                full_url, 
                json=json, 
                params=params
            ) as response:
                
                # Handle rate limiting
                if response.status == 429:
                    logger.warning("GitLab rate limit exceeded")
                    raise RuntimeError("GitLab API rate limit exceeded")
                
                response.raise_for_status()
                
                if response.content_type == "application/json":
                    return await response.json()
                else:
                    return await response.text()
                    
        except Exception as e:
            logger.error(f"GitLab API request failed: {method} {url} - {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_operations": self.supported_operations,
            "api_endpoint": self.config.api_endpoint,
            "group_id": self.config.group_id,
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