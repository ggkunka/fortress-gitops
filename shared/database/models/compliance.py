"""
Compliance Models

Database models for compliance frameworks, checks, and results.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Integer, Float, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class FrameworkType(str, Enum):
    """Types of compliance frameworks."""
    REGULATORY = "regulatory"
    INDUSTRY = "industry"
    INTERNAL = "internal"
    SECURITY = "security"
    PRIVACY = "privacy"
    QUALITY = "quality"


class ComplianceStatus(str, Enum):
    """Compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"
    IN_PROGRESS = "in_progress"
    EXEMPT = "exempt"


class CheckType(str, Enum):
    """Types of compliance checks."""
    AUTOMATED = "automated"
    MANUAL = "manual"
    HYBRID = "hybrid"
    DOCUMENTARY = "documentary"


class CheckStatus(str, Enum):
    """Status of individual compliance checks."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIP = "skip"
    ERROR = "error"
    MANUAL_REVIEW = "manual_review"


class ResultStatus(str, Enum):
    """Status of compliance assessment results."""
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class ComplianceFramework(BaseModel):
    """Compliance framework definition."""
    
    __tablename__ = "compliance_frameworks"
    
    # Framework identification
    name = Column(String(200), unique=True, nullable=False)
    display_name = Column(String(250), nullable=True)
    acronym = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    framework_type = Column(SQLEnum(FrameworkType), nullable=False)
    
    # Framework details
    version = Column(String(50), nullable=False)
    authority = Column(String(200), nullable=True)  # Regulatory body or standards org
    jurisdiction = Column(String(100), nullable=True)  # Geographic scope
    industry = Column(String(100), nullable=True)  # Industry scope
    
    # Framework metadata
    official_url = Column(String(500), nullable=True)
    documentation_url = Column(String(500), nullable=True)
    last_updated = Column(JSON, nullable=True)
    effective_date = Column(JSON, nullable=True)
    
    # Framework structure
    domains = Column(JSONB, default=list, nullable=False)  # High-level categories
    control_families = Column(JSONB, default=list, nullable=False)  # Control groupings
    maturity_levels = Column(JSONB, default=list, nullable=False)  # Maturity model
    
    # Implementation details
    assessment_frequency = Column(String(50), nullable=True)  # annual, quarterly, etc.
    certification_required = Column(Boolean, default=False, nullable=False)
    external_audit_required = Column(Boolean, default=False, nullable=False)
    
    # Framework configuration
    is_active = Column(Boolean, default=True, nullable=False)
    is_mandatory = Column(Boolean, default=False, nullable=False)
    priority = Column(Integer, default=0, nullable=False)
    
    # Statistics
    total_checks = Column(Integer, default=0, nullable=False)
    automated_checks = Column(Integer, default=0, nullable=False)
    manual_checks = Column(Integer, default=0, nullable=False)
    
    # Relationships
    checks = relationship("ComplianceCheck", back_populates="framework", cascade="all, delete-orphan")
    results = relationship("ComplianceResult", back_populates="framework")
    
    def _validate(self) -> List[str]:
        """Custom validation for compliance framework model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Framework name cannot be empty")
        
        if not self.version or len(self.version.strip()) == 0:
            errors.append("Framework version cannot be empty")
            
        return errors
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance summary for this framework."""
        total_results = len(self.results)
        if total_results == 0:
            return {"status": "not_assessed", "score": 0, "total_checks": self.total_checks}
        
        latest_result = max(self.results, key=lambda r: r.assessment_date)
        return {
            "status": latest_result.overall_status.value,
            "score": latest_result.compliance_score,
            "total_checks": self.total_checks,
            "passing_checks": latest_result.passing_checks,
            "failing_checks": latest_result.failing_checks,
            "last_assessment": latest_result.assessment_date
        }
    
    def calculate_automation_percentage(self) -> float:
        """Calculate percentage of automated checks."""
        if self.total_checks == 0:
            return 0.0
        return (self.automated_checks / self.total_checks) * 100


class ComplianceCheck(BaseModel):
    """Individual compliance check within a framework."""
    
    __tablename__ = "compliance_checks"
    
    # Relationship to framework
    framework_id = Column(UUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    
    # Check identification
    check_id = Column(String(100), nullable=False)  # Framework-specific ID
    name = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    check_type = Column(SQLEnum(CheckType), nullable=False)
    
    # Check categorization
    domain = Column(String(100), nullable=True)
    control_family = Column(String(100), nullable=True)
    control_id = Column(String(50), nullable=True)
    
    # Check details
    objective = Column(Text, nullable=True)
    requirements = Column(JSONB, default=list, nullable=False)
    guidance = Column(Text, nullable=True)
    references = Column(JSONB, default=list, nullable=False)
    
    # Implementation
    check_procedure = Column(Text, nullable=True)
    automation_script = Column(Text, nullable=True)
    evidence_requirements = Column(JSONB, default=list, nullable=False)
    
    # Scoring and weighting
    weight = Column(Float, default=1.0, nullable=False)
    criticality = Column(String(20), default="medium", nullable=False)
    risk_impact = Column(String(20), nullable=True)
    
    # Check configuration
    is_active = Column(Boolean, default=True, nullable=False)
    is_automated = Column(Boolean, default=False, nullable=False)
    automation_confidence = Column(Float, nullable=True)
    
    # Execution settings
    execution_frequency = Column(String(50), nullable=True)
    timeout_seconds = Column(Integer, default=300, nullable=False)
    retry_count = Column(Integer, default=3, nullable=False)
    
    # Dependencies
    depends_on = Column(JSONB, default=list, nullable=False)  # Other check IDs
    prerequisites = Column(JSONB, default=list, nullable=False)
    
    # Statistics
    execution_count = Column(Integer, default=0, nullable=False)
    success_count = Column(Integer, default=0, nullable=False)
    failure_count = Column(Integer, default=0, nullable=False)
    last_executed = Column(JSON, nullable=True)
    average_execution_time = Column(Float, nullable=True)
    
    # Unique constraint within framework
    __table_args__ = (
        UniqueConstraint('framework_id', 'check_id', name='uq_check_framework_id'),
    )
    
    # Relationships
    framework = relationship("ComplianceFramework", back_populates="checks")
    
    def _validate(self) -> List[str]:
        """Custom validation for compliance check model."""
        errors = []
        
        if not self.check_id or len(self.check_id.strip()) == 0:
            errors.append("Check ID cannot be empty")
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Check name cannot be empty")
        
        if self.weight <= 0:
            errors.append("Check weight must be positive")
        
        if self.timeout_seconds <= 0:
            errors.append("Timeout must be positive")
            
        return errors
    
    def execute(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute compliance check."""
        self.execution_count += 1
        start_time = datetime.utcnow()
        
        try:
            if self.is_automated and self.automation_script:
                result = self._execute_automated_check(target_data)
            else:
                result = self._execute_manual_check(target_data)
            
            # Update statistics
            if result["status"] == CheckStatus.PASS:
                self.success_count += 1
            else:
                self.failure_count += 1
            
            # Update execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            if self.average_execution_time:
                self.average_execution_time = (self.average_execution_time + execution_time) / 2
            else:
                self.average_execution_time = execution_time
            
            self.last_executed = datetime.utcnow().isoformat()
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            return {
                "status": CheckStatus.ERROR,
                "message": str(e),
                "evidence": {},
                "recommendations": []
            }
    
    def _execute_automated_check(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automated compliance check."""
        # This would implement the actual automation logic
        # For now, return a placeholder result
        return {
            "status": CheckStatus.PASS,
            "message": "Automated check passed",
            "evidence": target_data,
            "recommendations": []
        }
    
    def _execute_manual_check(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute manual compliance check."""
        return {
            "status": CheckStatus.MANUAL_REVIEW,
            "message": "Manual review required",
            "evidence": {},
            "recommendations": ["Schedule manual review of this control"]
        }
    
    def get_success_rate(self) -> float:
        """Calculate check success rate."""
        if self.execution_count == 0:
            return 0.0
        return (self.success_count / self.execution_count) * 100
    
    def is_critical(self) -> bool:
        """Check if this is a critical compliance check."""
        return self.criticality in ["critical", "high"]


class ComplianceResult(BaseModel):
    """Compliance assessment result for a framework."""
    
    __tablename__ = "compliance_results"
    
    # Relationships
    framework_id = Column(UUID(as_uuid=True), ForeignKey("compliance_frameworks.id"), nullable=False)
    
    # Assessment details
    assessment_id = Column(String(100), unique=True, nullable=False)
    assessment_name = Column(String(200), nullable=False)
    assessment_date = Column(JSON, nullable=False)
    assessment_period_start = Column(JSON, nullable=True)
    assessment_period_end = Column(JSON, nullable=True)
    
    # Scope and context
    scope_description = Column(Text, nullable=True)
    target_systems = Column(JSONB, default=list, nullable=False)
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Overall results
    overall_status = Column(SQLEnum(ComplianceStatus), nullable=False)
    compliance_score = Column(Float, nullable=False)  # 0-100 percentage
    maturity_level = Column(String(50), nullable=True)
    
    # Check results summary
    total_checks = Column(Integer, nullable=False)
    passing_checks = Column(Integer, nullable=False)
    failing_checks = Column(Integer, nullable=False)
    warning_checks = Column(Integer, nullable=False)
    skipped_checks = Column(Integer, nullable=False)
    manual_checks = Column(Integer, nullable=False)
    
    # Detailed results
    check_results = Column(JSONB, default=list, nullable=False)  # Individual check outcomes
    exceptions = Column(JSONB, default=list, nullable=False)  # Approved exceptions
    remediation_items = Column(JSONB, default=list, nullable=False)  # Required fixes
    
    # Assessment metadata
    assessor_name = Column(String(200), nullable=True)
    assessor_organization = Column(String(200), nullable=True)
    assessment_method = Column(String(100), nullable=True)
    tools_used = Column(JSONB, default=list, nullable=False)
    
    # Status and approval
    result_status = Column(SQLEnum(ResultStatus), default=ResultStatus.DRAFT, nullable=False)
    reviewed_by = Column(UUID(as_uuid=True), nullable=True)
    reviewed_at = Column(JSON, nullable=True)
    approved_by = Column(UUID(as_uuid=True), nullable=True)
    approved_at = Column(JSON, nullable=True)
    
    # Risk and impact assessment
    risk_rating = Column(String(20), nullable=True)
    business_impact = Column(Text, nullable=True)
    regulatory_impact = Column(Text, nullable=True)
    
    # Remediation tracking
    remediation_deadline = Column(JSON, nullable=True)
    remediation_plan = Column(Text, nullable=True)
    remediation_owner = Column(UUID(as_uuid=True), nullable=True)
    
    # Certification and reporting
    certification_required = Column(Boolean, default=False, nullable=False)
    report_generated = Column(Boolean, default=False, nullable=False)
    report_url = Column(String(500), nullable=True)
    
    # Next assessment
    next_assessment_due = Column(JSON, nullable=True)
    continuous_monitoring = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    framework = relationship("ComplianceFramework", back_populates="results")
    
    def _validate(self) -> List[str]:
        """Custom validation for compliance result model."""
        errors = []
        
        if not self.assessment_id or len(self.assessment_id.strip()) == 0:
            errors.append("Assessment ID cannot be empty")
        
        if not self.assessment_name or len(self.assessment_name.strip()) == 0:
            errors.append("Assessment name cannot be empty")
        
        if self.compliance_score < 0 or self.compliance_score > 100:
            errors.append("Compliance score must be between 0 and 100")
        
        if self.total_checks != (self.passing_checks + self.failing_checks + 
                               self.warning_checks + self.skipped_checks):
            errors.append("Check counts do not add up to total")
            
        return errors
    
    def calculate_compliance_score(self) -> float:
        """Calculate compliance score based on check results."""
        if self.total_checks == 0:
            self.compliance_score = 0.0
            return self.compliance_score
        
        # Weight calculation
        weighted_score = 0.0
        total_weight = 0.0
        
        for check_result in self.check_results:
            weight = check_result.get("weight", 1.0)
            status = check_result.get("status")
            
            if status == CheckStatus.PASS.value:
                weighted_score += weight
            elif status == CheckStatus.WARNING.value:
                weighted_score += weight * 0.5  # Partial credit for warnings
            # FAIL, SKIP, ERROR get 0 points
            
            total_weight += weight
        
        if total_weight > 0:
            self.compliance_score = (weighted_score / total_weight) * 100
        else:
            self.compliance_score = 0.0
        
        return self.compliance_score
    
    def determine_overall_status(self) -> ComplianceStatus:
        """Determine overall compliance status based on score and failures."""
        score = self.compliance_score
        
        if self.failing_checks == 0 and score >= 95:
            self.overall_status = ComplianceStatus.COMPLIANT
        elif score >= 80:
            self.overall_status = ComplianceStatus.PARTIALLY_COMPLIANT
        elif score > 0:
            self.overall_status = ComplianceStatus.NON_COMPLIANT
        else:
            self.overall_status = ComplianceStatus.NOT_ASSESSED
        
        return self.overall_status
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get risk summary based on compliance results."""
        critical_failures = sum(1 for r in self.check_results 
                              if r.get("status") == CheckStatus.FAIL.value and 
                              r.get("criticality") == "critical")
        
        return {
            "overall_risk": self.risk_rating or "unknown",
            "critical_failures": critical_failures,
            "compliance_score": self.compliance_score,
            "remediation_required": self.failing_checks > 0,
            "certification_impact": critical_failures > 0 if self.certification_required else False
        }
    
    def generate_remediation_plan(self) -> List[Dict[str, Any]]:
        """Generate remediation plan based on failed checks."""
        remediation_items = []
        
        for check_result in self.check_results:
            if check_result.get("status") == CheckStatus.FAIL.value:
                remediation_items.append({
                    "check_id": check_result.get("check_id"),
                    "check_name": check_result.get("check_name"),
                    "criticality": check_result.get("criticality", "medium"),
                    "recommendations": check_result.get("recommendations", []),
                    "estimated_effort": check_result.get("estimated_effort"),
                    "priority": self._calculate_remediation_priority(check_result)
                })
        
        # Sort by priority (critical first, then by compliance impact)
        remediation_items.sort(key=lambda x: (
            0 if x["criticality"] == "critical" else 1,
            -x["priority"]
        ))
        
        self.remediation_items = remediation_items
        return remediation_items
    
    def _calculate_remediation_priority(self, check_result: Dict[str, Any]) -> int:
        """Calculate remediation priority score (1-10)."""
        base_score = 5
        
        # Criticality impact
        if check_result.get("criticality") == "critical":
            base_score += 3
        elif check_result.get("criticality") == "high":
            base_score += 2
        elif check_result.get("criticality") == "low":
            base_score -= 1
        
        # Regulatory impact
        if check_result.get("regulatory_impact"):
            base_score += 2
        
        # Business impact
        if check_result.get("business_impact") == "high":
            base_score += 1
        
        return min(max(base_score, 1), 10)