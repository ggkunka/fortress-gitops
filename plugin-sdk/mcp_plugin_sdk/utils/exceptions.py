"""
Custom exceptions for the plugin SDK.
"""


class PluginError(Exception):
    """Base exception for plugin-related errors."""
    pass


class ConfigurationError(PluginError):
    """Exception for configuration-related errors."""
    pass


class EventError(PluginError):
    """Exception for event system errors."""
    pass


class SecurityError(PluginError):
    """Exception for security-related errors."""
    pass


class ValidationError(PluginError):
    """Exception for validation errors."""
    pass


class LifecycleError(PluginError):
    """Exception for plugin lifecycle errors."""
    pass


class CompatibilityError(PluginError):
    """Exception for plugin compatibility errors."""
    pass


class ResourceError(PluginError):
    """Exception for resource-related errors."""
    pass


class TimeoutError(PluginError):
    """Exception for timeout errors."""
    pass