"""
GitHub Integration Plugin - Repository and security management integration

This plugin integrates with GitHub's REST and GraphQL APIs to provide
repository management, security scanning, and issue tracking capabilities.
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
from shared.plugins.base import BaseIntegrationPlugin, IntegrationConfig, IntegrationResult

logger = get_logger(__name__)
metrics = get_metrics()


class GitHubConfig(IntegrationConfig):
    """GitHub integration configuration."""
    api_endpoint: str = "https://api.github.com"
    api_token: str  # Required for GitHub API
    organization: Optional[str] = None
    
    # Rate limiting
    rate_limit_requests_per_minute: int = 5000  # GitHub allows 5000/hour for authenticated
    
    # API options
    api_version: str = "2022-11-28"
    user_agent: str = "MCP-Security-Platform/1.0"
    
    # Security scanning options
    enable_secret_scanning: bool = True
    enable_dependency_review: bool = True
    enable_code_scanning: bool = True
    
    # Webhook options
    webhook_secret: Optional[str] = None
    webhook_events: List[str] = [
        "push", "pull_request", "issues", "repository_vulnerability_alert",
        "security_advisory", "dependabot_alert"
    ]


class GitHubPlugin(BaseIntegrationPlugin):
    """
    GitHub integration plugin.
    
    Provides integration with GitHub for:
    - Repository management
    - Security scanning and alerts
    - Issue and PR management
    - Dependency management
    - Secret scanning
    - Code scanning results
    """
    
    def __init__(self, config: GitHubConfig):
        super().__init__(config)
        self.config = config
        self.name = "github"
        self.version = "1.0.0"
        self.description = "GitHub repository and security integration"
        
        # Supported operations
        self.supported_operations = [
            "create_issue",
            "update_issue", 
            "create_pr",
            "update_pr",
            "get_repository",
            "list_repositories",
            "get_vulnerabilities",
            "get_secrets_alerts",
            "get_code_scanning_alerts",
            "create_webhook",
            "get_dependencies",
            "create_security_advisory"
        ]
        
        # API session
        self.session: Optional[aiohttp.ClientSession] = None
        
        logger.info("GitHub plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the GitHub plugin."""
        try:
            # Create HTTP session with authentication
            headers = {
                "Authorization": f"Bearer {self.config.api_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": self.config.api_version,
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
            
            logger.info("GitHub plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GitHub plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup GitHub plugin resources."""
        try:
            if self.session:
                await self.session.close()
                self.session = None
            
            logger.info("GitHub plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup GitHub plugin: {e}")
            return False
    
    @traced("github_plugin_create_issue")
    async def create_issue(
        self, 
        repository: str, 
        title: str, 
        body: str,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
        milestone: Optional[int] = None
    ) -> IntegrationResult:
        """Create a GitHub issue."""
        try:
            data = {
                "title": title,
                "body": body
            }
            
            if labels:
                data["labels"] = labels
            if assignees:
                data["assignees"] = assignees
            if milestone:
                data["milestone"] = milestone
            
            url = f"/repos/{repository}/issues"
            response = await self._make_request("POST", url, json=data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="issue",
                resource_id=str(response.get("number")),
                status="success",
                data=response
            )
            
            logger.info(f"Created GitHub issue #{response.get('number')} in {repository}")
            metrics.github_issues_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create GitHub issue: {e}")
            metrics.github_api_errors.inc()
            
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="issue",
                status="failed",
                error_message=str(e)
            )
    
    @traced("github_plugin_create_pr")
    async def create_pull_request(
        self, 
        repository: str, 
        title: str, 
        head: str, 
        base: str,
        body: Optional[str] = None,
        draft: bool = False
    ) -> IntegrationResult:
        """Create a GitHub pull request."""
        try:
            data = {
                "title": title,
                "head": head,
                "base": base,
                "draft": draft
            }
            
            if body:
                data["body"] = body
            
            url = f"/repos/{repository}/pulls"
            response = await self._make_request("POST", url, json=data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="pull_request",
                resource_id=str(response.get("number")),
                status="success",
                data=response
            )
            
            logger.info(f"Created GitHub PR #{response.get('number')} in {repository}")
            metrics.github_prs_created.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to create GitHub PR: {e}")
            metrics.github_api_errors.inc()
            
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="pull_request",
                status="failed",
                error_message=str(e)
            )
    
    async def create_resource(
        self, 
        resource_type: str, 
        data: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> IntegrationResult:
        """Create a GitHub resource."""
        try:
            if resource_type == "issue":
                return await self.create_issue(
                    repository=data["repository"],
                    title=data["title"],
                    body=data.get("body", ""),
                    labels=data.get("labels"),
                    assignees=data.get("assignees"),
                    milestone=data.get("milestone")
                )
            elif resource_type == "pull_request":
                return await self.create_pull_request(
                    repository=data["repository"],
                    title=data["title"],
                    head=data["head"],
                    base=data["base"],
                    body=data.get("body"),
                    draft=data.get("draft", False)
                )
            elif resource_type == "webhook":
                return await self.create_webhook(
                    repository=data["repository"],
                    url=data["url"],
                    events=data.get("events", self.config.webhook_events)
                )
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to create GitHub resource: {e}")
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
        """Update a GitHub resource."""
        try:
            repository = data.get("repository")
            if not repository:
                raise ValueError("Repository is required")
            
            if resource_type == "issue":
                url = f"/repos/{repository}/issues/{resource_id}"
                response = await self._make_request("PATCH", url, json=data)
            elif resource_type == "pull_request":
                url = f"/repos/{repository}/pulls/{resource_id}"
                response = await self._make_request("PATCH", url, json=data)
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
            
            logger.info(f"Updated GitHub {resource_type} #{resource_id} in {repository}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to update GitHub resource: {e}")
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
        """Delete a GitHub resource."""
        try:
            # Most GitHub resources cannot be deleted via API (issues, PRs)
            # But we can close them
            if resource_type in ["issue", "pull_request"]:
                repository = options.get("repository") if options else None
                if not repository:
                    raise ValueError("Repository is required")
                
                data = {"state": "closed"}
                url = f"/repos/{repository}/{resource_type}s/{resource_id}"
                response = await self._make_request("PATCH", url, json=data)
                
                result = IntegrationResult(
                    plugin_name=self.name,
                    plugin_version=self.version,
                    operation_type="delete",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    status="success",
                    data=response
                )
                
                logger.info(f"Closed GitHub {resource_type} #{resource_id}")
                return result
            else:
                raise ValueError(f"Cannot delete resource type: {resource_type}")
                
        except Exception as e:
            logger.error(f"Failed to delete GitHub resource: {e}")
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
        """Query GitHub resources."""
        try:
            filters = filters or {}
            options = options or {}
            
            if resource_type == "repositories":
                response = await self.get_repositories(
                    organization=filters.get("organization"),
                    type=filters.get("type", "all"),
                    sort=filters.get("sort", "updated"),
                    per_page=options.get("per_page", 30)
                )
            elif resource_type == "vulnerabilities":
                repository = filters.get("repository")
                if not repository:
                    raise ValueError("Repository is required for vulnerability queries")
                response = await self.get_vulnerability_alerts(repository)
            elif resource_type == "secret_alerts":
                repository = filters.get("repository")
                if not repository:
                    raise ValueError("Repository is required for secret alert queries")
                response = await self.get_secret_scanning_alerts(repository)
            elif resource_type == "code_scanning_alerts":
                repository = filters.get("repository")
                if not repository:
                    raise ValueError("Repository is required for code scanning alert queries")
                response = await self.get_code_scanning_alerts(repository)
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
            logger.error(f"Failed to query GitHub resources: {e}")
            return IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="query",
                resource_type=resource_type,
                status="failed",
                error_message=str(e)
            )
    
    @traced("github_plugin_get_repositories")
    async def get_repositories(
        self, 
        organization: Optional[str] = None,
        type: str = "all",
        sort: str = "updated",
        per_page: int = 30
    ) -> List[Dict[str, Any]]:
        """Get repositories."""
        try:
            if organization or self.config.organization:
                org = organization or self.config.organization
                url = f"/orgs/{org}/repos"
            else:
                url = "/user/repos"
            
            params = {
                "type": type,
                "sort": sort,
                "per_page": per_page
            }
            
            response = await self._make_request("GET", url, params=params)
            
            logger.info(f"Retrieved {len(response)} repositories")
            metrics.github_repositories_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get repositories: {e}")
            raise
    
    @traced("github_plugin_get_vulnerability_alerts")
    async def get_vulnerability_alerts(self, repository: str) -> List[Dict[str, Any]]:
        """Get Dependabot vulnerability alerts."""
        try:
            url = f"/repos/{repository}/dependabot/alerts"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved {len(response)} vulnerability alerts for {repository}")
            metrics.github_vulnerability_alerts_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability alerts: {e}")
            raise
    
    @traced("github_plugin_get_secret_scanning_alerts")
    async def get_secret_scanning_alerts(self, repository: str) -> List[Dict[str, Any]]:
        """Get secret scanning alerts."""
        try:
            url = f"/repos/{repository}/secret-scanning/alerts"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved {len(response)} secret scanning alerts for {repository}")
            metrics.github_secret_alerts_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get secret scanning alerts: {e}")
            raise
    
    @traced("github_plugin_get_code_scanning_alerts")
    async def get_code_scanning_alerts(self, repository: str) -> List[Dict[str, Any]]:
        """Get code scanning alerts."""
        try:
            url = f"/repos/{repository}/code-scanning/alerts"
            response = await self._make_request("GET", url)
            
            logger.info(f"Retrieved {len(response)} code scanning alerts for {repository}")
            metrics.github_code_scanning_alerts_fetched.inc(len(response))
            
            return response
            
        except Exception as e:
            logger.error(f"Failed to get code scanning alerts: {e}")
            raise
    
    @traced("github_plugin_create_webhook")
    async def create_webhook(
        self, 
        repository: str, 
        url: str, 
        events: Optional[List[str]] = None
    ) -> IntegrationResult:
        """Create a webhook."""
        try:
            events = events or self.config.webhook_events
            
            data = {
                "name": "web",
                "active": True,
                "events": events,
                "config": {
                    "url": url,
                    "content_type": "json"
                }
            }
            
            if self.config.webhook_secret:
                data["config"]["secret"] = self.config.webhook_secret
            
            webhook_url = f"/repos/{repository}/hooks"
            response = await self._make_request("POST", webhook_url, json=data)
            
            result = IntegrationResult(
                plugin_name=self.name,
                plugin_version=self.version,
                operation_type="create",
                resource_type="webhook",
                resource_id=str(response.get("id")),
                status="success",
                data=response
            )
            
            logger.info(f"Created webhook for {repository}")
            metrics.github_webhooks_created.inc()
            
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
        """Test GitHub API connection."""
        try:
            response = await self._make_request("GET", "/user")
            logger.info(f"GitHub API connection successful (user: {response.get('login')})")
        except Exception as e:
            logger.error(f"GitHub API connection failed: {e}")
            raise
    
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Make GitHub API request."""
        try:
            if not self.session:
                raise RuntimeError("GitHub session not initialized")
            
            full_url = urljoin(self.config.api_endpoint, url)
            
            async with self.session.request(
                method, 
                full_url, 
                json=json, 
                params=params
            ) as response:
                
                # Handle rate limiting
                if response.status == 403:
                    rate_limit_remaining = response.headers.get("X-RateLimit-Remaining", "0")
                    if rate_limit_remaining == "0":
                        reset_time = response.headers.get("X-RateLimit-Reset", "0")
                        logger.warning(f"GitHub rate limit exceeded. Reset at: {reset_time}")
                        raise RuntimeError("GitHub API rate limit exceeded")
                
                response.raise_for_status()
                
                if response.content_type == "application/json":
                    return await response.json()
                else:
                    return await response.text()
                    
        except Exception as e:
            logger.error(f"GitHub API request failed: {method} {url} - {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_operations": self.supported_operations,
            "api_endpoint": self.config.api_endpoint,
            "organization": self.config.organization,
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