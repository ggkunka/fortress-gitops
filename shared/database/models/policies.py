"""
Policy Models

Database models for security policies, policy rules, and policy violations.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Integer, Float, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class PolicyType(str, Enum):
    """Types of security policies."""
    VULNERABILITY = "vulnerability"
    LICENSE = "license"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    QUALITY = "quality"
    DEPENDENCY = "dependency"
    CONTAINER = "container"
    CUSTOM = "custom"


class PolicySeverity(str, Enum):
    """Policy violation severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PolicyStatus(str, Enum):
    """Policy status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"
    DEPRECATED = "deprecated"


class RuleOperator(str, Enum):
    """Rule comparison operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX_MATCH = "regex_match"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class ViolationStatus(str, Enum):
    """Policy violation status."""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Policy(BaseModel):
    """Security policy entity."""
    
    __tablename__ = "policies"
    
    # Basic information
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    policy_type = Column(SQLEnum(PolicyType), nullable=False)
    
    # Policy configuration
    status = Column(SQLEnum(PolicyStatus), default=PolicyStatus.DRAFT, nullable=False)
    severity = Column(SQLEnum(PolicySeverity), default=PolicySeverity.MEDIUM, nullable=False)
    version = Column(String(50), default="1.0", nullable=False)
    
    # Scope and targeting
    scope = Column(String(50), default="global", nullable=False)  # global, organization, project
    scope_id = Column(UUID(as_uuid=True), nullable=True)  # ID of scoped resource
    target_types = Column(JSONB, default=list, nullable=False)  # What this policy applies to
    
    # Policy logic
    logic_operator = Column(String(10), default="AND", nullable=False)  # AND, OR
    conditions = Column(JSONB, default=list, nullable=False)  # List of conditions
    
    # Actions and remediation
    enforcement_mode = Column(String(20), default="monitor", nullable=False)  # monitor, block, warn
    auto_remediation = Column(Boolean, default=False, nullable=False)
    remediation_steps = Column(JSONB, default=list, nullable=False)
    
    # Metadata
    tags = Column(JSONB, default=list, nullable=False)
    category = Column(String(100), nullable=True)
    documentation_url = Column(String(500), nullable=True)
    
    # Compliance mapping
    compliance_frameworks = Column(JSONB, default=list, nullable=False)  # SOC2, PCI-DSS, etc.
    regulatory_requirements = Column(JSONB, default=list, nullable=False)
    
    # Statistics
    violation_count = Column(Integer, default=0, nullable=False)
    last_triggered = Column(JSON, nullable=True)
    effectiveness_score = Column(Float, nullable=True)
    
    # Scheduling and notifications
    evaluation_schedule = Column(String(100), nullable=True)  # Cron expression
    notification_config = Column(JSONB, default=dict, nullable=False)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    created_by_user_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('name', 'organization_id', name='uq_policy_org_name'),
    )
    
    # Relationships
    rules = relationship("PolicyRule", back_populates="policy", cascade="all, delete-orphan")
    violations = relationship("PolicyViolation", back_populates="policy")
    
    def _validate(self) -> List[str]:
        """Custom validation for policy model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Policy name cannot be empty")
        
        if not self.target_types:
            errors.append("Policy must specify target types")
        
        if self.logic_operator not in ["AND", "OR"]:
            errors.append("Logic operator must be AND or OR")
        
        if self.enforcement_mode not in ["monitor", "block", "warn"]:
            errors.append("Invalid enforcement mode")
            
        return errors
    
    def is_active(self) -> bool:
        """Check if policy is active."""
        return self.status == PolicyStatus.ACTIVE
    
    def evaluate(self, target_data: Dict[str, Any]) -> bool:
        """Evaluate policy against target data."""
        if not self.is_active() or not self.rules:
            return True  # No violations if inactive or no rules
        
        rule_results = []
        for rule in self.rules:
            result = rule.evaluate(target_data)
            rule_results.append(result)
        
        # Apply logic operator
        if self.logic_operator == "AND":
            return all(rule_results)
        else:  # OR
            return any(rule_results)
    
    def get_violation_summary(self) -> Dict[str, Any]:
        """Get summary of policy violations."""
        open_violations = sum(1 for v in self.violations if v.status == ViolationStatus.OPEN)
        return {
            "total": self.violation_count,
            "open": open_violations,
            "resolved": sum(1 for v in self.violations if v.status == ViolationStatus.RESOLVED),
            "suppressed": sum(1 for v in self.violations if v.status == ViolationStatus.SUPPRESSED)
        }
    
    def calculate_effectiveness_score(self) -> float:
        """Calculate policy effectiveness score."""
        if self.violation_count == 0:
            self.effectiveness_score = 1.0
            return self.effectiveness_score
        
        resolved_count = sum(1 for v in self.violations if v.status == ViolationStatus.RESOLVED)
        self.effectiveness_score = resolved_count / self.violation_count
        return self.effectiveness_score


class PolicyRule(BaseModel):
    """Individual rule within a policy."""
    
    __tablename__ = "policy_rules"
    
    # Relationship to policy
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=False)
    
    # Rule identification
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    rule_order = Column(Integer, nullable=False)
    
    # Rule logic
    field_path = Column(String(200), nullable=False)  # JSON path to field
    operator = Column(SQLEnum(RuleOperator), nullable=False)
    value = Column(JSONB, nullable=False)  # Expected value(s)
    
    # Rule configuration
    case_sensitive = Column(Boolean, default=True, nullable=False)
    negate_result = Column(Boolean, default=False, nullable=False)
    
    # Conditional logic
    conditions = Column(JSONB, default=list, nullable=False)  # Additional conditions
    
    # Rule metadata
    severity_override = Column(SQLEnum(PolicySeverity), nullable=True)
    message_template = Column(Text, nullable=True)
    remediation_hint = Column(Text, nullable=True)
    
    # Statistics
    evaluation_count = Column(Integer, default=0, nullable=False)
    match_count = Column(Integer, default=0, nullable=False)
    last_matched = Column(JSON, nullable=True)
    
    # Relationships
    policy = relationship("Policy", back_populates="rules")
    
    def _validate(self) -> List[str]:
        """Custom validation for policy rule model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Rule name cannot be empty")
        
        if not self.field_path or len(self.field_path.strip()) == 0:
            errors.append("Field path cannot be empty")
        
        if self.rule_order < 0:
            errors.append("Rule order must be non-negative")
            
        return errors
    
    def evaluate(self, data: Dict[str, Any]) -> bool:
        """Evaluate rule against data."""
        self.evaluation_count += 1
        
        # Extract field value using JSON path
        field_value = self._extract_field_value(data, self.field_path)
        
        # Apply operator
        result = self._apply_operator(field_value, self.operator, self.value)
        
        # Apply case sensitivity
        if isinstance(field_value, str) and isinstance(self.value, str) and not self.case_sensitive:
            result = self._apply_operator(field_value.lower(), self.operator, self.value.lower())
        
        # Apply negation
        if self.negate_result:
            result = not result
        
        # Record match
        if result:
            self.match_count += 1
            self.last_matched = datetime.utcnow().isoformat()
        
        return result
    
    def _extract_field_value(self, data: Dict[str, Any], path: str) -> Any:
        """Extract value from data using JSON path."""
        try:
            keys = path.split('.')
            value = data
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                elif isinstance(value, list) and key.isdigit():
                    index = int(key)
                    value = value[index] if index < len(value) else None
                else:
                    return None
            return value
        except (KeyError, IndexError, TypeError):
            return None
    
    def _apply_operator(self, field_value: Any, operator: RuleOperator, expected_value: Any) -> bool:
        """Apply comparison operator."""
        if operator == RuleOperator.EQUALS:
            return field_value == expected_value
        elif operator == RuleOperator.NOT_EQUALS:
            return field_value != expected_value
        elif operator == RuleOperator.GREATER_THAN:
            return field_value > expected_value
        elif operator == RuleOperator.GREATER_THAN_OR_EQUAL:
            return field_value >= expected_value
        elif operator == RuleOperator.LESS_THAN:
            return field_value < expected_value
        elif operator == RuleOperator.LESS_THAN_OR_EQUAL:
            return field_value <= expected_value
        elif operator == RuleOperator.CONTAINS:
            return expected_value in str(field_value) if field_value else False
        elif operator == RuleOperator.NOT_CONTAINS:
            return expected_value not in str(field_value) if field_value else True
        elif operator == RuleOperator.STARTS_WITH:
            return str(field_value).startswith(str(expected_value)) if field_value else False
        elif operator == RuleOperator.ENDS_WITH:
            return str(field_value).endswith(str(expected_value)) if field_value else False
        elif operator == RuleOperator.IN_LIST:
            return field_value in expected_value if isinstance(expected_value, list) else False
        elif operator == RuleOperator.NOT_IN_LIST:
            return field_value not in expected_value if isinstance(expected_value, list) else True
        elif operator == RuleOperator.EXISTS:
            return field_value is not None
        elif operator == RuleOperator.NOT_EXISTS:
            return field_value is None
        elif operator == RuleOperator.REGEX_MATCH:
            import re
            return bool(re.match(str(expected_value), str(field_value))) if field_value else False
        else:
            return False
    
    def get_match_rate(self) -> float:
        """Get rule match rate."""
        if self.evaluation_count == 0:
            return 0.0
        return self.match_count / self.evaluation_count


class PolicyViolation(BaseModel):
    """Policy violation instance."""
    
    __tablename__ = "policy_violations"
    
    # Relationships
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=False)
    
    # Violation details
    violation_id = Column(String(100), unique=True, nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(PolicySeverity), nullable=False)
    
    # Status and resolution
    status = Column(SQLEnum(ViolationStatus), default=ViolationStatus.OPEN, nullable=False)
    resolution_notes = Column(Text, nullable=True)
    resolved_by = Column(UUID(as_uuid=True), nullable=True)
    resolved_at = Column(JSON, nullable=True)
    
    # Target information
    target_type = Column(String(100), nullable=False)
    target_id = Column(String(200), nullable=False)
    target_name = Column(String(300), nullable=True)
    target_metadata = Column(JSONB, default=dict, nullable=False)
    
    # Violation context
    rule_violations = Column(JSONB, default=list, nullable=False)  # Which rules were violated
    evidence = Column(JSONB, default=dict, nullable=False)  # Supporting evidence
    risk_score = Column(Float, nullable=True)
    
    # Timeline
    first_detected = Column(JSON, nullable=False)
    last_detected = Column(JSON, nullable=False)
    detection_count = Column(Integer, default=1, nullable=False)
    
    # Remediation
    remediation_required = Column(Boolean, default=True, nullable=False)
    remediation_steps = Column(JSONB, default=list, nullable=False)
    remediation_deadline = Column(JSON, nullable=True)
    auto_remediation_attempted = Column(Boolean, default=False, nullable=False)
    
    # Assignment and tracking
    assigned_to = Column(UUID(as_uuid=True), nullable=True)
    assigned_at = Column(JSON, nullable=True)
    priority_score = Column(Float, nullable=True)
    
    # Compliance impact
    compliance_impact = Column(JSONB, default=list, nullable=False)
    regulatory_notes = Column(Text, nullable=True)
    
    # Suppression
    suppression_reason = Column(Text, nullable=True)
    suppressed_by = Column(UUID(as_uuid=True), nullable=True)
    suppressed_until = Column(JSON, nullable=True)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Relationships
    policy = relationship("Policy", back_populates="violations")
    
    def _validate(self) -> List[str]:
        """Custom validation for policy violation model."""
        errors = []
        
        if not self.violation_id or len(self.violation_id.strip()) == 0:
            errors.append("Violation ID cannot be empty")
        
        if not self.title or len(self.title.strip()) == 0:
            errors.append("Violation title cannot be empty")
        
        if not self.target_type or len(self.target_type.strip()) == 0:
            errors.append("Target type cannot be empty")
        
        if not self.target_id or len(self.target_id.strip()) == 0:
            errors.append("Target ID cannot be empty")
            
        return errors
    
    def is_open(self) -> bool:
        """Check if violation is open."""
        return self.status == ViolationStatus.OPEN
    
    def is_overdue(self) -> bool:
        """Check if violation is past its remediation deadline."""
        if not self.remediation_deadline:
            return False
        
        deadline_dt = datetime.fromisoformat(self.remediation_deadline.replace('Z', '+00:00'))
        return datetime.utcnow() > deadline_dt.replace(tzinfo=None)
    
    def calculate_risk_score(self) -> float:
        """Calculate violation risk score."""
        base_scores = {
            PolicySeverity.CRITICAL: 9.0,
            PolicySeverity.HIGH: 7.0,
            PolicySeverity.MEDIUM: 5.0,
            PolicySeverity.LOW: 3.0,
            PolicySeverity.INFO: 1.0
        }
        
        base_score = base_scores.get(self.severity, 5.0)
        
        # Adjust for detection frequency
        frequency_factor = min(self.detection_count / 10, 2.0)
        
        # Adjust for overdue status
        overdue_factor = 1.5 if self.is_overdue() else 1.0
        
        self.risk_score = min(base_score * frequency_factor * overdue_factor, 10.0)
        return self.risk_score
    
    def calculate_priority_score(self) -> float:
        """Calculate violation priority score for triage."""
        risk_score = self.calculate_risk_score()
        
        # Business impact factor
        compliance_factor = 1.2 if self.compliance_impact else 1.0
        
        # Remediation urgency
        urgency_factor = 1.0
        if self.remediation_deadline:
            deadline_dt = datetime.fromisoformat(self.remediation_deadline.replace('Z', '+00:00'))
            days_until_deadline = (deadline_dt.replace(tzinfo=None) - datetime.utcnow()).days
            if days_until_deadline <= 1:
                urgency_factor = 2.0
            elif days_until_deadline <= 7:
                urgency_factor = 1.5
        
        self.priority_score = min(risk_score * compliance_factor * urgency_factor, 10.0)
        return self.priority_score
    
    def resolve(self, resolved_by: str, notes: Optional[str] = None):
        """Mark violation as resolved."""
        self.status = ViolationStatus.RESOLVED
        self.resolved_by = resolved_by
        self.resolved_at = datetime.utcnow().isoformat()
        self.resolution_notes = notes
    
    def suppress(self, suppressed_by: str, reason: str, until: Optional[datetime] = None):
        """Suppress violation."""
        self.status = ViolationStatus.SUPPRESSED
        self.suppressed_by = suppressed_by
        self.suppression_reason = reason
        if until:
            self.suppressed_until = until.isoformat()
    
    def record_detection(self):
        """Record another detection of this violation."""
        self.last_detected = datetime.utcnow().isoformat()
        self.detection_count += 1