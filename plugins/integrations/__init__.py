"""
Integration Plugins Package

This package contains integration plugins for external services and platforms
that the MCP Security Platform can interact with for workflow automation,
issue tracking, and team collaboration.

Available Integration Plugins:
- GitHub: Repository and security management integration
- GitLab: Repository and security management integration
- JIRA: Issue tracking and project management integration
- Slack: Team communication and notification integration

Usage:
    from plugins.integrations.github.github_plugin import GitHubPlugin, GitHubConfig
    from plugins.integrations.gitlab.gitlab_plugin import GitLabPlugin, GitLabConfig
    from plugins.integrations.jira.jira_plugin import JiraPlugin, JiraConfig
    from plugins.integrations.slack.slack_plugin import SlackPlugin, SlackConfig
    
    # Initialize integration
    github_config = GitHubConfig(api_token="your_token")
    github = GitHubPlugin(github_config)
    await github.initialize()
    
    # Create resource
    result = await github.create_resource("issue", {
        "repository": "owner/repo",
        "title": "Security Issue",
        "body": "Description of the issue"
    })
"""

from .github.github_plugin import GitHubPlugin, GitHubConfig
from .gitlab.gitlab_plugin import GitLabPlugin, GitLabConfig
from .jira.jira_plugin import JiraPlugin, JiraConfig
from .slack.slack_plugin import SlackPlugin, SlackConfig

__all__ = [
    "GitHubPlugin",
    "GitHubConfig",
    "GitLabPlugin", 
    "GitLabConfig",
    "JiraPlugin",
    "JiraConfig",
    "SlackPlugin",
    "SlackConfig"
]