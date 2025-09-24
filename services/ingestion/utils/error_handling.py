"""Error handling utilities for the ingestion service."""

import traceback
from typing import Any, Dict, Optional, List
from datetime import datetime
from enum import Enum

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import ValidationError
import structlog

from .logging import IngestionLogger

logger = structlog.get_logger()
ingestion_logger = IngestionLogger()


class ErrorType(Enum):
    """Error type enumeration."""
    VALIDATION_ERROR = "validation_error"
    JSON_PARSE_ERROR = "json_parse_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    RATE_LIMIT_ERROR = "rate_limit_error"
    DEPENDENCY_ERROR = "dependency_error"
    INTERNAL_ERROR = "internal_error"
    TIMEOUT_ERROR = "timeout_error"
    RESOURCE_NOT_FOUND = "resource_not_found"
    CONFLICT_ERROR = "conflict_error"
    BAD_REQUEST = "bad_request"
    SERVICE_UNAVAILABLE = "service_unavailable"


class IngestionError(Exception):
    """Base exception for ingestion service errors."""
    
    def __init__(
        self,
        message: str,
        error_type: ErrorType,
        details: Optional[Dict[str, Any]] = None,
        status_code: int = 500,
        ingestion_id: Optional[str] = None,
        data_type: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_type = error_type
        self.details = details or {}
        self.status_code = status_code
        self.ingestion_id = ingestion_id
        self.data_type = data_type
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary representation."""
        return {
            "error_type": self.error_type.value,
            "message": self.message,
            "details": self.details,
            "status_code": self.status_code,
            "ingestion_id": self.ingestion_id,
            "data_type": self.data_type,
            "timestamp": self.timestamp.isoformat(),
        }


class ValidationFailedError(IngestionError):
    """Exception for validation failures."""
    
    def __init__(
        self,
        message: str,
        validation_errors: List[str],
        ingestion_id: Optional[str] = None,
        data_type: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            error_type=ErrorType.VALIDATION_ERROR,
            details={"validation_errors": validation_errors},
            status_code=400,
            ingestion_id=ingestion_id,
            data_type=data_type,
        )
        self.validation_errors = validation_errors


class JSONParseError(IngestionError):
    """Exception for JSON parsing errors."""
    
    def __init__(
        self,
        message: str,
        parse_error: str,
        ingestion_id: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            error_type=ErrorType.JSON_PARSE_ERROR,
            details={"parse_error": parse_error},
            status_code=400,
            ingestion_id=ingestion_id,
        )


class DependencyError(IngestionError):
    """Exception for dependency-related errors."""
    
    def __init__(
        self,
        message: str,
        dependency: str,
        operation: str,
        ingestion_id: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            error_type=ErrorType.DEPENDENCY_ERROR,
            details={"dependency": dependency, "operation": operation},
            status_code=503,
            ingestion_id=ingestion_id,
        )


class RateLimitError(IngestionError):
    """Exception for rate limit errors."""
    
    def __init__(
        self,
        message: str,
        limit: int,
        window: str,
        client_id: str,
    ):
        super().__init__(
            message=message,
            error_type=ErrorType.RATE_LIMIT_ERROR,
            details={"limit": limit, "window": window, "client_id": client_id},
            status_code=429,
        )


class TimeoutError(IngestionError):
    """Exception for timeout errors."""
    
    def __init__(
        self,
        message: str,
        operation: str,
        timeout_seconds: float,
        ingestion_id: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            error_type=ErrorType.TIMEOUT_ERROR,
            details={"operation": operation, "timeout_seconds": timeout_seconds},
            status_code=504,
            ingestion_id=ingestion_id,
        )


class ErrorHandler:
    """Centralized error handling for the ingestion service."""
    
    def __init__(self):
        self.logger = ingestion_logger
    
    def handle_validation_error(
        self,
        error: ValidationError,
        ingestion_id: Optional[str] = None,
        data_type: Optional[str] = None,
    ) -> ValidationFailedError:
        """Handle Pydantic validation errors."""
        validation_errors = []
        for err in error.errors():
            field_path = " -> ".join(str(loc) for loc in err["loc"])
            error_msg = f"{field_path}: {err['msg']}"
            validation_errors.append(error_msg)
        
        exc = ValidationFailedError(
            message=f"Data validation failed with {len(validation_errors)} errors",
            validation_errors=validation_errors,
            ingestion_id=ingestion_id,
            data_type=data_type,
        )
        
        self.logger.log_validation_failure(
            data_type=data_type or "unknown",
            ingestion_id=ingestion_id or "unknown",
            errors=validation_errors,
        )
        
        return exc
    
    def handle_json_parse_error(
        self,
        error: Exception,
        ingestion_id: Optional[str] = None,
    ) -> JSONParseError:
        """Handle JSON parsing errors."""
        exc = JSONParseError(
            message="Invalid JSON format",
            parse_error=str(error),
            ingestion_id=ingestion_id,
        )
        
        self.logger.log_ingestion_error(
            data_type="unknown",
            ingestion_id=ingestion_id or "unknown",
            error=str(error),
            error_type="json_parse_error",
        )
        
        return exc
    
    def handle_dependency_error(
        self,
        error: Exception,
        dependency: str,
        operation: str,
        ingestion_id: Optional[str] = None,
    ) -> DependencyError:
        """Handle dependency-related errors."""
        exc = DependencyError(
            message=f"Dependency '{dependency}' failed during '{operation}'",
            dependency=dependency,
            operation=operation,
            ingestion_id=ingestion_id,
        )
        
        self.logger.log_dependency_issue(
            dependency=dependency,
            issue_type="connection_error",
            error=str(error),
        )
        
        return exc
    
    def handle_generic_error(
        self,
        error: Exception,
        ingestion_id: Optional[str] = None,
        data_type: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> IngestionError:
        """Handle generic exceptions."""
        exc = IngestionError(
            message=f"Unexpected error during {operation or 'operation'}",
            error_type=ErrorType.INTERNAL_ERROR,
            details={
                "exception_type": type(error).__name__,
                "exception_message": str(error),
                "traceback": traceback.format_exc(),
            },
            status_code=500,
            ingestion_id=ingestion_id,
            data_type=data_type,
        )
        
        self.logger.log_ingestion_error(
            data_type=data_type or "unknown",
            ingestion_id=ingestion_id or "unknown",
            error=str(error),
            error_type="internal_error",
            additional_data={"operation": operation},
        )
        
        return exc
    
    def create_error_response(
        self,
        error: IngestionError,
        include_details: bool = True,
        include_traceback: bool = False,
    ) -> JSONResponse:
        """Create a JSON error response."""
        error_dict = error.to_dict()
        
        if not include_details:
            error_dict.pop("details", None)
        
        if not include_traceback and "traceback" in error_dict.get("details", {}):
            error_dict["details"].pop("traceback", None)
        
        return JSONResponse(
            status_code=error.status_code,
            content=error_dict,
        )
    
    def log_error_metrics(
        self,
        error: IngestionError,
        metrics_service: Any,
    ) -> None:
        """Log error metrics."""
        if metrics_service:
            metrics_service.record_error(
                error_type=error.error_type.value,
                component=error.data_type or "unknown",
            )


async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """FastAPI exception handler for validation errors."""
    error_handler = ErrorHandler()
    
    # Extract ingestion ID from request if available
    ingestion_id = getattr(request.state, "ingestion_id", None)
    data_type = getattr(request.state, "data_type", None)
    
    error = error_handler.handle_validation_error(
        error=exc,
        ingestion_id=ingestion_id,
        data_type=data_type,
    )
    
    return error_handler.create_error_response(error)


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """FastAPI exception handler for HTTP exceptions."""
    error_dict = {
        "error_type": "http_error",
        "message": exc.detail,
        "status_code": exc.status_code,
        "timestamp": datetime.utcnow().isoformat(),
    }
    
    # Add headers if present
    if hasattr(exc, "headers") and exc.headers:
        error_dict["headers"] = exc.headers
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_dict,
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """FastAPI exception handler for generic exceptions."""
    error_handler = ErrorHandler()
    
    # Extract request context
    ingestion_id = getattr(request.state, "ingestion_id", None)
    data_type = getattr(request.state, "data_type", None)
    
    error = error_handler.handle_generic_error(
        error=exc,
        ingestion_id=ingestion_id,
        data_type=data_type,
        operation=f"{request.method} {request.url.path}",
    )
    
    return error_handler.create_error_response(
        error=error,
        include_traceback=False,  # Don't expose internal details
    )


def setup_error_handlers(app):
    """Set up error handlers for the FastAPI application."""
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)


class CircuitBreaker:
    """Circuit breaker for external service calls."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func, *args, **kwargs):
        """Call function with circuit breaker protection."""
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
            else:
                raise DependencyError(
                    message="Circuit breaker is OPEN",
                    dependency="external_service",
                    operation="call",
                )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt to reset."""
        if self.last_failure_time is None:
            return True
        
        return (
            datetime.utcnow() - self.last_failure_time
        ).total_seconds() > self.recovery_timeout
    
    def _on_success(self):
        """Handle successful call."""
        self.failure_count = 0
        self.state = "CLOSED"
    
    def _on_failure(self):
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


class RetryHandler:
    """Retry handler for transient failures."""
    
    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        max_backoff: float = 60.0,
    ):
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
    
    async def retry_async(self, func, *args, **kwargs):
        """Retry async function with exponential backoff."""
        import asyncio
        
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                
                if attempt < self.max_retries:
                    delay = min(
                        self.backoff_factor * (2 ** attempt),
                        self.max_backoff
                    )
                    
                    logger.warning(
                        "Retrying operation after failure",
                        attempt=attempt + 1,
                        max_retries=self.max_retries,
                        delay=delay,
                        error=str(e),
                    )
                    
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        "All retry attempts failed",
                        attempts=self.max_retries + 1,
                        final_error=str(e),
                    )
        
        raise last_exception