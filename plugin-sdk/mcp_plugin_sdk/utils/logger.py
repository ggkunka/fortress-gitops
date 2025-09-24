"""
Logging utilities for plugins.
"""

import logging
import sys
from typing import Optional

import structlog


def get_logger(name: str, level: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structured logger for a plugin or component.
    
    Args:
        name: Logger name
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured structured logger
    """
    # Configure structlog if not already done
    if not structlog.is_configured():
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    # Get stdlib logger
    stdlib_logger = logging.getLogger(name)
    
    # Set level if provided
    if level:
        stdlib_logger.setLevel(getattr(logging, level.upper()))
    
    # Ensure handler exists
    if not stdlib_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('%(message)s'))
        stdlib_logger.addHandler(handler)
        stdlib_logger.setLevel(logging.INFO)
    
    # Return structured logger
    return structlog.get_logger(name)