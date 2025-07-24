"""
Database Models

SQLAlchemy and Pydantic models for all platform entities.
"""

from .base import Base
from .scans import Scan, ScanResult, ScannerPlugin
from .vulnerabilities import Vulnerability, CVE, Package, VulnerabilityMatch
from .sboms import SBOM, Component, License, Dependency
from .users import User, Role, Permission, UserRole
from .organizations import Organization, Team, Project
from .policies import Policy, PolicyRule, PolicyViolation
from .compliance import ComplianceFramework, ComplianceCheck, ComplianceResult
from .events import Event, EventLog, Notification
from .reports import Report, ReportTemplate, Dashboard
from .analytics import Metric, Trend, Anomaly, Baseline

__all__ = [
    "Base",
    # Scan models
    "Scan", "ScanResult", "ScannerPlugin",
    # Vulnerability models
    "Vulnerability", "CVE", "Package", "VulnerabilityMatch",
    # SBOM models
    "SBOM", "Component", "License", "Dependency",
    # User management
    "User", "Role", "Permission", "UserRole",
    # Organization models
    "Organization", "Team", "Project",
    # Policy models
    "Policy", "PolicyRule", "PolicyViolation",
    # Compliance models
    "ComplianceFramework", "ComplianceCheck", "ComplianceResult",
    # Event models
    "Event", "EventLog", "Notification",
    # Report models
    "Report", "ReportTemplate", "Dashboard",
    # Analytics models
    "Metric", "Trend", "Anomaly", "Baseline",
]