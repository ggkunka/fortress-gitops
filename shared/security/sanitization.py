"""
Input sanitization and validation for MCP Security Platform.
"""

import re
import html
import json
import base64
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Callable, Pattern
from dataclasses import dataclass, field
from enum import Enum
import bleach
from sqlalchemy.sql import text

from ..observability.logging import get_logger, SecurityLogger


class ValidationSeverity(Enum):
    """Severity levels for validation failures."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class ValidationRule:
    """Input validation rule."""
    name: str
    pattern: Union[str, Pattern]
    severity: ValidationSeverity
    description: str
    allow_empty: bool = False
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    custom_validator: Optional[Callable] = None


@dataclass
class SanitizationConfig:
    """Configuration for input sanitization."""
    # HTML sanitization
    allowed_html_tags: List[str] = field(default_factory=lambda: [
        'p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    ])
    allowed_html_attributes: Dict[str, List[str]] = field(default_factory=dict)
    
    # SQL injection prevention
    enable_sql_injection_detection: bool = True
    sql_keywords: List[str] = field(default_factory=lambda: [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'UNION', 'OR', 'AND', 'WHERE', 'FROM', 'INTO', 'VALUES', 'SET',
        'EXEC', 'EXECUTE', 'DECLARE', '--', ';', '/*', '*/', 'xp_'
    ])
    
    # XSS prevention
    enable_xss_detection: bool = True
    xss_patterns: List[str] = field(default_factory=lambda: [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'expression\s*\(',
        r'eval\s*\(',
        r'String\.fromCharCode'
    ])
    
    # Command injection prevention
    enable_command_injection_detection: bool = True
    command_patterns: List[str] = field(default_factory=lambda: [
        r';\s*(rm|del|format|fdisk)',
        r'\|\s*(nc|netcat|telnet)',
        r'&&\s*(wget|curl)',
        r'`[^`]*`',
        r'\$\([^)]*\)',
        r'>\s*/dev/',
        r'<\s*/etc/'
    ])
    
    # Path traversal prevention
    enable_path_traversal_detection: bool = True
    path_traversal_patterns: List[str] = field(default_factory=lambda: [
        r'\.\./+',
        r'\.\.\\+',
        r'/etc/passwd',
        r'/proc/',
        r'\\windows\\system32',
        r'%2e%2e%2f',
        r'%2e%2e%5c'
    ])
    
    # File upload restrictions
    allowed_file_extensions: List[str] = field(default_factory=lambda: [
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg'
    ])
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    
    # Content length limits
    max_json_size: int = 1024 * 1024  # 1MB
    max_string_length: int = 10000
    max_array_length: int = 1000
    max_object_depth: int = 10


class InputSanitizer:
    """Main input sanitization class."""
    
    def __init__(self, config: SanitizationConfig = None):
        self.config = config or SanitizationConfig()
        self.logger = get_logger("input_sanitizer")
        self.security_logger = SecurityLogger("input_sanitizer")
        
        # Compile regex patterns for performance
        self._compile_patterns()
        
        # Setup HTML sanitizer
        self._setup_html_sanitizer()
    
    def _compile_patterns(self):
        """Compile regex patterns for better performance."""
        self.xss_patterns = [
            re.compile(pattern, re.IGNORECASE | re.DOTALL)
            for pattern in self.config.xss_patterns
        ]
        
        self.command_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.command_patterns
        ]
        
        self.path_traversal_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.config.path_traversal_patterns
        ]
        
        # SQL injection pattern
        sql_pattern = '|'.join([re.escape(keyword) for keyword in self.config.sql_keywords])
        self.sql_injection_pattern = re.compile(f'({sql_pattern})', re.IGNORECASE)
    
    def _setup_html_sanitizer(self):
        """Setup HTML sanitizer with allowed tags and attributes."""
        self.html_sanitizer = bleach.Cleaner(
            tags=self.config.allowed_html_tags,
            attributes=self.config.allowed_html_attributes,
            strip=True,
            strip_comments=True
        )
    
    def sanitize_string(self, 
                       value: str, 
                       max_length: Optional[int] = None,
                       allow_html: bool = False,
                       strict: bool = True) -> str:
        """
        Sanitize a string input.
        
        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length
            allow_html: Whether to allow HTML tags
            strict: Whether to apply strict sanitization
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            value = str(value)
        
        # Check length
        max_len = max_length or self.config.max_string_length
        if len(value) > max_len:
            self.security_logger.log_input_validation_failure(
                "string_length", "oversized_input",
                length=len(value), max_length=max_len
            )
            value = value[:max_len]
        
        # Detect potential attacks
        self._detect_attacks(value, "string")
        
        # HTML sanitization
        if allow_html:
            value = self.html_sanitizer.clean(value)
        else:
            value = html.escape(value, quote=True)
        
        # Additional sanitization for strict mode
        if strict:
            # Remove null bytes
            value = value.replace('\x00', '')
            
            # Normalize whitespace
            value = re.sub(r'\s+', ' ', value).strip()
            
            # Remove control characters except newlines and tabs
            value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        return value
    
    def sanitize_json(self, data: Any, max_depth: int = None) -> Any:
        """
        Sanitize JSON data recursively.
        
        Args:
            data: JSON data to sanitize
            max_depth: Maximum nesting depth
            
        Returns:
            Sanitized JSON data
        """
        max_depth = max_depth or self.config.max_object_depth
        
        return self._sanitize_json_recursive(data, max_depth, current_depth=0)
    
    def _sanitize_json_recursive(self, data: Any, max_depth: int, current_depth: int) -> Any:
        """Recursively sanitize JSON data."""
        if current_depth > max_depth:
            self.security_logger.log_input_validation_failure(
                "json_depth", "excessive_nesting",
                depth=current_depth, max_depth=max_depth
            )
            return None
        
        if isinstance(data, dict):
            if len(data) > self.config.max_array_length:
                self.security_logger.log_input_validation_failure(
                    "object_size", "oversized_object",
                    size=len(data), max_size=self.config.max_array_length
                )
                # Truncate to allowed size
                data = dict(list(data.items())[:self.config.max_array_length])
            
            sanitized = {}
            for key, value in data.items():
                # Sanitize key
                sanitized_key = self.sanitize_string(str(key), max_length=100, strict=True)
                
                # Sanitize value
                sanitized_value = self._sanitize_json_recursive(
                    value, max_depth, current_depth + 1
                )
                
                sanitized[sanitized_key] = sanitized_value
            
            return sanitized
        
        elif isinstance(data, list):
            if len(data) > self.config.max_array_length:
                self.security_logger.log_input_validation_failure(
                    "array_size", "oversized_array",
                    size=len(data), max_size=self.config.max_array_length
                )
                # Truncate to allowed size
                data = data[:self.config.max_array_length]
            
            return [
                self._sanitize_json_recursive(item, max_depth, current_depth + 1)
                for item in data
            ]
        
        elif isinstance(data, str):
            return self.sanitize_string(data)
        
        elif isinstance(data, (int, float, bool)) or data is None:
            return data
        
        else:
            # Convert unknown types to string and sanitize
            return self.sanitize_string(str(data))
    
    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for safe storage.
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        if not filename:
            return "unnamed_file"
        
        # Remove path components
        filename = filename.split('/')[-1].split('\\')[-1]
        
        # Remove dangerous characters
        filename = re.sub(r'[^\w\-_\.]', '_', filename)
        
        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            max_name_len = 250 - len(ext)
            filename = name[:max_name_len] + ('.' + ext if ext else '')
        
        # Ensure it doesn't start with dot or dash
        filename = re.sub(r'^[.-]+', '', filename)
        
        # Ensure it's not empty after sanitization
        if not filename:
            filename = "sanitized_file"
        
        return filename
    
    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL to prevent malicious redirects.
        
        Args:
            url: URL to sanitize
            
        Returns:
            Sanitized URL
        """
        if not url:
            return ""
        
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as e:
            self.security_logger.log_input_validation_failure(
                "url_parsing", "invalid_url",
                url=url[:100], error=str(e)
            )
            return ""
        
        # Check scheme
        allowed_schemes = ['http', 'https', 'ftp', 'ftps']
        if parsed.scheme.lower() not in allowed_schemes:
            self.security_logger.log_input_validation_failure(
                "url_scheme", "disallowed_scheme",
                scheme=parsed.scheme, url=url[:100]
            )
            return ""
        
        # Check for dangerous patterns
        full_url = url.lower()
        dangerous_patterns = [
            'javascript:', 'vbscript:', 'data:', 'file:', 'about:',
            'chrome:', 'chrome-extension:', 'moz-extension:'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in full_url:
                self.security_logger.log_input_validation_failure(
                    "url_pattern", "dangerous_url_pattern",
                    pattern=pattern, url=url[:100]
                )
                return ""
        
        # Rebuild URL to normalize it
        try:
            sanitized_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            return sanitized_url
        except Exception:
            return ""
    
    def _detect_attacks(self, value: str, field_type: str = "unknown"):
        """Detect potential security attacks in input."""
        
        # SQL injection detection
        if self.config.enable_sql_injection_detection:
            if self.sql_injection_pattern.search(value):
                self.security_logger.log_input_validation_failure(
                    "sql_injection", "potential_sql_injection",
                    field_type=field_type, value_preview=value[:100]
                )
        
        # XSS detection
        if self.config.enable_xss_detection:
            for pattern in self.xss_patterns:
                if pattern.search(value):
                    self.security_logger.log_input_validation_failure(
                        "xss_attempt", "potential_xss",
                        field_type=field_type, value_preview=value[:100]
                    )
                    break
        
        # Command injection detection
        if self.config.enable_command_injection_detection:
            for pattern in self.command_patterns:
                if pattern.search(value):
                    self.security_logger.log_input_validation_failure(
                        "command_injection", "potential_command_injection",
                        field_type=field_type, value_preview=value[:100]
                    )
                    break
        
        # Path traversal detection
        if self.config.enable_path_traversal_detection:
            for pattern in self.path_traversal_patterns:
                if pattern.search(value):
                    self.security_logger.log_input_validation_failure(
                        "path_traversal", "potential_path_traversal",
                        field_type=field_type, value_preview=value[:100]
                    )
                    break
    
    def validate_file_upload(self, 
                           filename: str, 
                           content: bytes,
                           content_type: str = None) -> Dict[str, Any]:
        """
        Validate file upload for security.
        
        Args:
            filename: Name of uploaded file
            content: File content bytes
            content_type: MIME content type
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "sanitized_filename": "",
            "size": len(content)
        }
        
        # Sanitize filename
        result["sanitized_filename"] = self.sanitize_filename(filename)
        
        # Check file size
        if len(content) > self.config.max_file_size:
            result["valid"] = False
            result["errors"].append(f"File size {len(content)} exceeds maximum {self.config.max_file_size}")
        
        # Check file extension
        if filename:
            _, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            ext = '.' + ext.lower()
            
            if ext not in self.config.allowed_file_extensions:
                result["valid"] = False
                result["errors"].append(f"File extension {ext} not allowed")
        
        # Check for embedded threats in content
        content_str = content.decode('utf-8', errors='ignore')[:1000]  # Check first 1KB
        self._detect_attacks(content_str, "file_content")
        
        # Check for script tags in content
        if b'<script' in content.lower() or b'javascript:' in content.lower():
            result["warnings"].append("Potentially dangerous script content detected")
        
        # Check for executable signatures
        executable_signatures = [
            b'MZ',  # DOS/Windows executable
            b'\x7fELF',  # Linux executable
            b'\xca\xfe\xba\xbe',  # Java class file
            b'PK',  # ZIP/JAR files (could contain executables)
        ]
        
        for sig in executable_signatures:
            if content.startswith(sig):
                result["valid"] = False
                result["errors"].append("Executable file content detected")
                break
        
        return result


class SecurityValidator:
    """Advanced security validation with custom rules."""
    
    def __init__(self, rules: List[ValidationRule] = None):
        self.rules = rules or []
        self.logger = get_logger("security_validator")
        self.security_logger = SecurityLogger("security_validator")
        
        # Add default security rules
        self._add_default_rules()
    
    def _add_default_rules(self):
        """Add default security validation rules."""
        default_rules = [
            ValidationRule(
                name="email_format",
                pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                severity=ValidationSeverity.ERROR,
                description="Invalid email format",
                max_length=254
            ),
            ValidationRule(
                name="phone_number",
                pattern=r'^\+?[1-9]\d{1,14}$',
                severity=ValidationSeverity.WARNING,
                description="Invalid phone number format",
                max_length=15
            ),
            ValidationRule(
                name="ip_address",
                pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                severity=ValidationSeverity.ERROR,
                description="Invalid IP address format"
            ),
            ValidationRule(
                name="uuid",
                pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
                severity=ValidationSeverity.ERROR,
                description="Invalid UUID format"
            ),
            ValidationRule(
                name="alphanumeric_only",
                pattern=r'^[a-zA-Z0-9]+$',
                severity=ValidationSeverity.WARNING,
                description="Only alphanumeric characters allowed"
            ),
            ValidationRule(
                name="no_special_chars",
                pattern=r'^[a-zA-Z0-9\s\-_.]+$',
                severity=ValidationSeverity.WARNING,
                description="Special characters not allowed"
            )
        ]
        
        self.rules.extend(default_rules)
    
    def add_rule(self, rule: ValidationRule):
        """Add a custom validation rule."""
        self.rules.append(rule)
    
    def validate(self, value: Any, rule_names: List[str] = None) -> Dict[str, Any]:
        """
        Validate value against specified rules.
        
        Args:
            value: Value to validate
            rule_names: List of rule names to apply (None for all)
            
        Returns:
            Validation result dictionary
        """
        result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "info": [],
            "rules_checked": []
        }
        
        # Convert value to string for pattern matching
        str_value = str(value) if value is not None else ""
        
        # Filter rules if specified
        rules_to_check = self.rules
        if rule_names:
            rules_to_check = [r for r in self.rules if r.name in rule_names]
        
        for rule in rules_to_check:
            rule_result = self._validate_rule(str_value, rule)
            result["rules_checked"].append(rule.name)
            
            if not rule_result["valid"]:
                if rule.severity == ValidationSeverity.ERROR:
                    result["valid"] = False
                    result["errors"].append(rule_result["message"])
                elif rule.severity == ValidationSeverity.WARNING:
                    result["warnings"].append(rule_result["message"])
                elif rule.severity == ValidationSeverity.CRITICAL:
                    result["valid"] = False
                    result["errors"].append(rule_result["message"])
                    # Log critical validation failure
                    self.security_logger.log_input_validation_failure(
                        rule.name, "critical_validation_failure",
                        value_preview=str_value[:100]
                    )
                else:
                    result["info"].append(rule_result["message"])
        
        return result
    
    def _validate_rule(self, value: str, rule: ValidationRule) -> Dict[str, Any]:
        """Validate value against a single rule."""
        result = {"valid": True, "message": ""}
        
        # Check if empty value is allowed
        if not value.strip() and not rule.allow_empty:
            return {"valid": False, "message": f"{rule.name}: Empty value not allowed"}
        
        # Check length constraints
        if rule.min_length and len(value) < rule.min_length:
            return {
                "valid": False, 
                "message": f"{rule.name}: Value too short (min: {rule.min_length})"
            }
        
        if rule.max_length and len(value) > rule.max_length:
            return {
                "valid": False,
                "message": f"{rule.name}: Value too long (max: {rule.max_length})"
            }
        
        # Check custom validator first
        if rule.custom_validator:
            try:
                if not rule.custom_validator(value):
                    return {"valid": False, "message": f"{rule.name}: Custom validation failed"}
            except Exception as e:
                self.logger.error(f"Custom validator error for rule {rule.name}: {e}")
                return {"valid": False, "message": f"{rule.name}: Validation error"}
        
        # Check pattern
        pattern = rule.pattern
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        
        if not pattern.match(value):
            return {"valid": False, "message": f"{rule.name}: {rule.description}"}
        
        return result
    
    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength."""
        result = {
            "valid": True,
            "score": 0,
            "feedback": []
        }
        
        if len(password) < 8:
            result["valid"] = False
            result["feedback"].append("Password must be at least 8 characters")
        else:
            result["score"] += 1
        
        if len(password) >= 12:
            result["score"] += 1
        
        if re.search(r'[a-z]', password):
            result["score"] += 1
        else:
            result["feedback"].append("Add lowercase letters")
        
        if re.search(r'[A-Z]', password):
            result["score"] += 1
        else:
            result["feedback"].append("Add uppercase letters")
        
        if re.search(r'\d', password):
            result["score"] += 1
        else:
            result["feedback"].append("Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            result["score"] += 1
        else:
            result["feedback"].append("Add special characters")
        
        # Check for common patterns
        common_patterns = [
            r'12345', r'qwerty', r'password', r'admin', r'letmein',
            r'welcome', r'monkey', r'dragon'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                result["valid"] = False
                result["feedback"].append("Avoid common passwords")
                break
        
        # Overall strength
        if result["score"] >= 5:
            result["strength"] = "strong"
        elif result["score"] >= 3:
            result["strength"] = "medium"
        else:
            result["strength"] = "weak"
            result["valid"] = False
        
        return result


def create_sanitization_middleware(config: SanitizationConfig = None):
    """Create middleware for automatic input sanitization."""
    sanitizer = InputSanitizer(config)
    
    async def sanitization_middleware(request, call_next):
        # This would be implemented as FastAPI middleware
        # to automatically sanitize request bodies
        pass
    
    return sanitization_middleware