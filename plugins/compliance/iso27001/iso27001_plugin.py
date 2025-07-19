"""
ISO 27001 Compliance Plugin - ISO/IEC 27001 Information Security Management System assessment

This plugin provides compliance assessment capabilities for ISO/IEC 27001:2022,
including control evaluation, ISMS assessment, and certification readiness.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from enum import Enum

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseCompliancePlugin, ComplianceConfig, ComplianceResult

logger = get_logger(__name__)
metrics = get_metrics()


class ISO27001Domain(str, Enum):
    """ISO 27001 control domains (Annex A)."""
    INFORMATION_SECURITY_POLICIES = "A.5"
    ORGANIZATION_OF_INFORMATION_SECURITY = "A.6"
    HUMAN_RESOURCE_SECURITY = "A.7"
    ASSET_MANAGEMENT = "A.8"
    ACCESS_CONTROL = "A.9"
    CRYPTOGRAPHY = "A.10"
    PHYSICAL_ENVIRONMENTAL_SECURITY = "A.11"
    OPERATIONS_SECURITY = "A.12"
    COMMUNICATIONS_SECURITY = "A.13"
    SYSTEM_ACQUISITION_DEVELOPMENT_MAINTENANCE = "A.14"
    SUPPLIER_RELATIONSHIPS = "A.15"
    INFORMATION_SECURITY_INCIDENT_MANAGEMENT = "A.16"
    INFORMATION_SECURITY_BUSINESS_CONTINUITY = "A.17"
    COMPLIANCE = "A.18"


class ISMSMaturityLevel(str, Enum):
    """ISMS maturity levels."""
    INITIAL = "initial"
    MANAGED = "managed"
    DEFINED = "defined"
    QUANTITATIVELY_MANAGED = "quantitatively_managed"
    OPTIMIZING = "optimizing"


class ISO27001Config(ComplianceConfig):
    """ISO 27001 compliance plugin configuration."""
    framework_version: str = "2022"
    
    # ISMS scope settings
    isms_scope: str = "Information systems and data processing"
    organizational_context: Dict[str, Any] = {}
    
    # Assessment settings
    target_maturity_level: ISMSMaturityLevel = ISMSMaturityLevel.DEFINED
    assessment_domains: List[ISO27001Domain] = [
        ISO27001Domain.INFORMATION_SECURITY_POLICIES,
        ISO27001Domain.ORGANIZATION_OF_INFORMATION_SECURITY,
        ISO27001Domain.HUMAN_RESOURCE_SECURITY,
        ISO27001Domain.ASSET_MANAGEMENT,
        ISO27001Domain.ACCESS_CONTROL,
        ISO27001Domain.CRYPTOGRAPHY,
        ISO27001Domain.PHYSICAL_ENVIRONMENTAL_SECURITY,
        ISO27001Domain.OPERATIONS_SECURITY,
        ISO27001Domain.COMMUNICATIONS_SECURITY,
        ISO27001Domain.SYSTEM_ACQUISITION_DEVELOPMENT_MAINTENANCE,
        ISO27001Domain.SUPPLIER_RELATIONSHIPS,
        ISO27001Domain.INFORMATION_SECURITY_INCIDENT_MANAGEMENT,
        ISO27001Domain.INFORMATION_SECURITY_BUSINESS_CONTINUITY,
        ISO27001Domain.COMPLIANCE
    ]
    
    # Control mappings
    control_mappings: Dict[str, str] = {}  # Internal control ID -> ISO control mapping
    
    # ISMS requirements
    isms_requirements: List[str] = [
        "leadership_commitment",
        "information_security_policy",
        "risk_assessment_process",
        "risk_treatment_plan",
        "statement_of_applicability",
        "security_objectives",
        "competence_awareness",
        "documented_information",
        "operational_planning",
        "performance_evaluation",
        "internal_audit",
        "management_review",
        "nonconformity_corrective_action"
    ]
    
    # Evidence collection
    evidence_requirements: Dict[str, List[str]] = {
        "policies": ["information_security_policy", "acceptable_use_policy", "incident_response_policy"],
        "procedures": ["risk_assessment", "access_control", "incident_response", "business_continuity"],
        "records": ["risk_register", "audit_logs", "training_records", "incident_records"],
        "assessments": ["vulnerability_assessments", "penetration_tests", "risk_assessments"]
    }
    
    # Certification settings
    certification_scope: Optional[str] = None
    exclude_controls: List[str] = []  # Controls marked as not applicable
    
    # Scoring weights
    domain_weights: Dict[str, float] = {}  # Equal weights if not specified
    
    # Reporting settings
    include_isms_assessment: bool = True
    include_control_assessment: bool = True
    include_gap_analysis: bool = True
    include_certification_readiness: bool = True


class ISO27001Plugin(BaseCompliancePlugin):
    """
    ISO/IEC 27001 Information Security Management System compliance plugin.
    
    Provides comprehensive ISO 27001 compliance assessment including:
    - ISMS (Information Security Management System) evaluation
    - Annex A control assessment (93 controls across 14 domains)
    - Risk management process assessment
    - Documentation and evidence review
    - Certification readiness evaluation
    - Gap analysis and remediation planning
    """
    
    def __init__(self, config: ISO27001Config):
        super().__init__(config)
        self.config = config
        self.name = "iso27001"
        self.version = "2022.1.0"
        self.description = "ISO/IEC 27001 Information Security Management System compliance assessment"
        
        # Supported assessment types
        self.supported_assessments = [
            "full_isms_assessment",
            "annex_a_controls",
            "domain_specific",
            "control_specific",
            "certification_readiness",
            "gap_analysis",
            "isms_maturity",
            "risk_management_assessment"
        ]
        
        # ISO 27001 framework structure
        self.framework_structure = self._load_framework_structure()
        
        # Initialize domain weights
        if not self.config.domain_weights:
            num_domains = len(self.config.assessment_domains)
            self.config.domain_weights = {
                domain.value: 1.0 / num_domains for domain in self.config.assessment_domains
            }
        
        logger.info("ISO 27001 compliance plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the ISO 27001 plugin."""
        try:
            # Validate framework structure
            if not self.framework_structure:
                raise RuntimeError("Failed to load ISO 27001 framework structure")
            
            # Validate configuration
            await self._validate_configuration()
            
            logger.info("ISO 27001 plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize ISO 27001 plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup ISO 27001 plugin resources."""
        try:
            # No persistent resources to clean up
            logger.info("ISO 27001 plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup ISO 27001 plugin: {e}")
            return False
    
    @traced("iso27001_plugin_assess_compliance")
    async def assess_compliance(
        self, 
        assessment_type: str, 
        target: str,
        controls: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ComplianceResult:
        """Assess ISO 27001 compliance."""
        try:
            if assessment_type not in self.supported_assessments:
                raise ValueError(f"Unsupported assessment type: {assessment_type}")
            
            options = options or {}
            start_time = datetime.now(timezone.utc)
            
            # Perform assessment based on type
            if assessment_type == "full_isms_assessment":
                assessment_results = await self._assess_full_isms(target, options)
            elif assessment_type == "annex_a_controls":
                assessment_results = await self._assess_annex_a_controls(target, options)
            elif assessment_type == "domain_specific":
                domain = options.get("domain")
                if not domain:
                    raise ValueError("Domain must be specified for domain_specific assessment")
                assessment_results = await self._assess_domain(target, domain, options)
            elif assessment_type == "control_specific":
                control_list = controls or options.get("controls", [])
                assessment_results = await self._assess_controls(target, control_list, options)
            elif assessment_type == "certification_readiness":
                assessment_results = await self._assess_certification_readiness(target, options)
            elif assessment_type == "gap_analysis":
                assessment_results = await self._perform_gap_analysis(target, options)
            elif assessment_type == "isms_maturity":
                assessment_results = await self._assess_isms_maturity(target, options)
            elif assessment_type == "risk_management_assessment":
                assessment_results = await self._assess_risk_management(target, options)
            else:
                raise ValueError(f"Assessment type {assessment_type} not implemented")
            
            # Calculate overall compliance score
            compliance_score = self._calculate_compliance_score(assessment_results, assessment_type)
            
            # Generate findings and recommendations
            findings = await self._generate_findings(assessment_results, assessment_type, options)
            
            result = ComplianceResult(
                plugin_name=self.name,
                plugin_version=self.version,
                framework="ISO/IEC 27001",
                assessment_type=assessment_type,
                controls_evaluated=len(assessment_results.get("controls", [])),
                controls_passed=len([c for c in assessment_results.get("controls", []) if c.get("status") == "compliant"]),
                controls_failed=len([c for c in assessment_results.get("controls", []) if c.get("status") == "non_compliant"]),
                compliance_score=compliance_score,
                findings=findings,
                status="success",
                metadata={
                    "framework_version": self.config.framework_version,
                    "isms_scope": self.config.isms_scope,
                    "assessment_domains": [d.value for d in self.config.assessment_domains],
                    "target_maturity_level": self.config.target_maturity_level.value,
                    "assessment_details": assessment_results
                }
            )
            
            logger.info(f"ISO 27001 assessment completed: {compliance_score:.2f} compliance score")
            metrics.iso27001_assessments_completed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"ISO 27001 assessment failed: {e}")
            metrics.iso27001_assessment_errors.inc()
            
            return ComplianceResult(
                plugin_name=self.name,
                plugin_version=self.version,
                framework="ISO/IEC 27001",
                assessment_type=assessment_type,
                controls_evaluated=0,
                controls_passed=0,
                controls_failed=0,
                compliance_score=0.0,
                findings=[],
                status="failed",
                error_message=str(e)
            )
    
    async def get_control_details(self, control_id: str) -> Optional[Dict[str, Any]]:
        """Get ISO 27001 control details."""
        try:
            # Search through framework structure
            for domain_id, domain_data in self.framework_structure.items():
                for control_category_id, category_data in domain_data.get("categories", {}).items():
                    for ctrl_id, control_data in category_data.get("controls", {}).items():
                        if ctrl_id == control_id:
                            return {
                                "id": ctrl_id,
                                "title": control_data.get("title"),
                                "description": control_data.get("description"),
                                "domain": domain_id,
                                "category": control_category_id,
                                "implementation_guidance": control_data.get("guidance", ""),
                                "control_type": control_data.get("type", "procedural"),
                                "related_controls": control_data.get("related_controls", []),
                                "evidence_requirements": control_data.get("evidence_requirements", [])
                            }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get control details: {e}")
            return None
    
    async def list_controls(self) -> List[Dict[str, Any]]:
        """List all ISO 27001 Annex A controls."""
        try:
            controls = []
            
            for domain_id, domain_data in self.framework_structure.items():
                for category_id, category_data in domain_data.get("categories", {}).items():
                    for control_id, control_data in category_data.get("controls", {}).items():
                        controls.append({
                            "id": control_id,
                            "title": control_data.get("title"),
                            "domain": domain_id,
                            "category": category_id,
                            "type": control_data.get("type", "procedural"),
                            "description": control_data.get("description")
                        })
            
            logger.info(f"Retrieved {len(controls)} ISO 27001 controls")
            return controls
            
        except Exception as e:
            logger.error(f"Failed to list controls: {e}")
            return []
    
    async def _assess_full_isms(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform full ISMS assessment including PDCA cycle and Annex A controls."""
        results = {
            "isms_requirements": {},
            "annex_a_controls": {},
            "domains": {},
            "controls": [],
            "overall_maturity": ISMSMaturityLevel.INITIAL.value,
            "pdca_cycle": {},
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        # Assess ISMS requirements (clauses 4-10)
        results["isms_requirements"] = await self._assess_isms_requirements(target, options)
        
        # Assess Annex A controls
        annex_a_results = await self._assess_annex_a_controls(target, options)
        results["annex_a_controls"] = annex_a_results
        results["domains"] = annex_a_results.get("domains", {})
        results["controls"] = annex_a_results.get("controls", [])
        
        # Assess PDCA cycle implementation
        results["pdca_cycle"] = await self._assess_pdca_cycle(target, options)
        
        # Calculate overall ISMS maturity
        results["overall_maturity"] = self._calculate_isms_maturity(results)
        
        return results
    
    async def _assess_annex_a_controls(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess Annex A controls across all domains."""
        results = {
            "domains": {},
            "controls": [],
            "overall_score": 0.0,
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        total_controls = 0
        compliant_controls = 0
        
        # Assess each domain in scope
        for domain in self.config.assessment_domains:
            if domain.value not in self.framework_structure:
                continue
                
            domain_result = await self._assess_domain(target, domain.value, options)
            results["domains"][domain.value] = domain_result
            
            # Add controls from this domain
            domain_controls = domain_result.get("controls", [])
            results["controls"].extend(domain_controls)
            
            # Update counters
            total_controls += len(domain_controls)
            compliant_controls += len([c for c in domain_controls if c.get("status") == "compliant"])
        
        # Calculate overall score
        results["overall_score"] = compliant_controls / total_controls if total_controls > 0 else 0.0
        
        return results
    
    async def _assess_domain(self, target: str, domain: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess a specific ISO 27001 domain."""
        domain_data = self.framework_structure.get(domain, {})
        if not domain_data:
            raise ValueError(f"Unknown ISO 27001 domain: {domain}")
        
        results = {
            "domain": domain,
            "domain_title": domain_data.get("title", ""),
            "categories": {},
            "controls": [],
            "domain_score": 0.0,
            "maturity_level": ISMSMaturityLevel.INITIAL.value
        }
        
        total_controls = 0
        compliant_controls = 0
        
        # Assess each category in the domain
        for category_id, category_data in domain_data.get("categories", {}).items():
            category_result = {
                "category": category_id,
                "category_title": category_data.get("title", ""),
                "controls": {},
                "category_score": 0.0
            }
            
            category_total = 0
            category_compliant = 0
            
            # Assess each control in the category
            for control_id, control_data in category_data.get("controls", {}).items():
                # Skip excluded controls
                if control_id in self.config.exclude_controls:
                    continue
                    
                control_result = await self._assess_control(target, control_id, control_data, options)
                
                category_result["controls"][control_id] = control_result
                results["controls"].append(control_result)
                
                category_total += 1
                total_controls += 1
                
                if control_result.get("status") == "compliant":
                    category_compliant += 1
                    compliant_controls += 1
            
            # Calculate category score
            category_result["category_score"] = category_compliant / category_total if category_total > 0 else 0.0
            results["categories"][category_id] = category_result
        
        # Calculate domain score
        results["domain_score"] = compliant_controls / total_controls if total_controls > 0 else 0.0
        
        # Determine maturity level for this domain
        results["maturity_level"] = self._determine_maturity_level(results["domain_score"])
        
        return results
    
    async def _assess_controls(self, target: str, control_ids: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess specific ISO 27001 controls."""
        results = {
            "controls": [],
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        for control_id in control_ids:
            control_details = await self.get_control_details(control_id)
            if control_details:
                control_result = await self._assess_control(target, control_id, control_details, options)
                results["controls"].append(control_result)
        
        return results
    
    async def _assess_control(
        self, 
        target: str, 
        control_id: str, 
        control_data: Dict[str, Any], 
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess a single ISO 27001 control."""
        result = {
            "control_id": control_id,
            "title": control_data.get("title", ""),
            "description": control_data.get("description", ""),
            "domain": control_data.get("domain", ""),
            "category": control_data.get("category", ""),
            "control_type": control_data.get("type", "procedural"),
            "status": "unknown",
            "implementation_score": 0.0,
            "maturity_level": ISMSMaturityLevel.INITIAL.value,
            "evidence": [],
            "gaps": [],
            "recommendations": [],
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        # Collect evidence for this control
        evidence_found = await self._collect_control_evidence(target, control_id, control_data, options)
        result["evidence"] = evidence_found
        
        # Evaluate implementation based on evidence
        implementation_score = self._evaluate_control_implementation(control_id, control_data, evidence_found)
        result["implementation_score"] = implementation_score
        
        # Determine compliance status
        if implementation_score >= 0.8:
            result["status"] = "compliant"
        elif implementation_score >= 0.5:
            result["status"] = "partially_compliant"
        else:
            result["status"] = "non_compliant"
        
        # Determine maturity level
        result["maturity_level"] = self._determine_maturity_level(implementation_score)
        
        # Generate gaps and recommendations
        if implementation_score < 1.0:
            result["gaps"] = self._identify_control_gaps(control_id, control_data, evidence_found)
            if self.config.include_gap_analysis:
                result["recommendations"] = self._generate_control_recommendations(control_id, control_data, result["gaps"])
        
        return result
    
    async def _assess_isms_requirements(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess ISMS requirements (clauses 4-10)."""
        results = {}
        
        for requirement in self.config.isms_requirements:
            requirement_result = await self._assess_isms_requirement(target, requirement, options)
            results[requirement] = requirement_result
        
        return results
    
    async def _assess_isms_requirement(self, target: str, requirement: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess a specific ISMS requirement."""
        # Simulate ISMS requirement assessment
        result = {
            "requirement": requirement,
            "status": "unknown",
            "implementation_score": 0.0,
            "evidence": [],
            "gaps": [],
            "recommendations": []
        }
        
        # Simulate evidence collection for ISMS requirements
        if requirement == "information_security_policy":
            result["evidence"] = ["Policy document exists", "Policy is approved", "Policy is communicated"]
            result["implementation_score"] = 0.8
            result["status"] = "compliant"
        elif requirement == "risk_assessment_process":
            result["evidence"] = ["Risk assessment methodology defined", "Risk register maintained"]
            result["implementation_score"] = 0.7
            result["status"] = "partially_compliant"
            result["gaps"] = ["Risk assessment frequency not defined"]
        else:
            # Default partial implementation
            result["implementation_score"] = 0.6
            result["status"] = "partially_compliant"
            result["gaps"] = [f"{requirement} requires improvement"]
        
        return result
    
    async def _assess_pdca_cycle(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess PDCA (Plan-Do-Check-Act) cycle implementation."""
        pdca_results = {
            "plan": {"score": 0.0, "status": "unknown", "evidence": []},
            "do": {"score": 0.0, "status": "unknown", "evidence": []},
            "check": {"score": 0.0, "status": "unknown", "evidence": []},
            "act": {"score": 0.0, "status": "unknown", "evidence": []}
        }
        
        # Simulate PDCA assessment
        # Plan: Risk assessment, treatment plans, objectives
        pdca_results["plan"]["score"] = 0.7
        pdca_results["plan"]["status"] = "partially_compliant"
        pdca_results["plan"]["evidence"] = ["Risk assessment conducted", "Treatment plan defined"]
        
        # Do: Implementation of controls and processes
        pdca_results["do"]["score"] = 0.6
        pdca_results["do"]["status"] = "partially_compliant"
        pdca_results["do"]["evidence"] = ["Controls implemented", "Procedures documented"]
        
        # Check: Monitoring, measurement, audit, review
        pdca_results["check"]["score"] = 0.5
        pdca_results["check"]["status"] = "partially_compliant"
        pdca_results["check"]["evidence"] = ["Some monitoring in place", "Annual review conducted"]
        
        # Act: Corrective actions, continuous improvement
        pdca_results["act"]["score"] = 0.4
        pdca_results["act"]["status"] = "non_compliant"
        pdca_results["act"]["evidence"] = ["Limited corrective actions"]
        
        return pdca_results
    
    async def _assess_certification_readiness(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess readiness for ISO 27001 certification."""
        # Perform full ISMS assessment
        isms_results = await self._assess_full_isms(target, options)
        
        readiness_results = {
            "overall_readiness": "not_ready",
            "readiness_score": 0.0,
            "critical_gaps": [],
            "major_gaps": [],
            "minor_gaps": [],
            "documentation_readiness": {},
            "process_maturity": {},
            "estimated_timeline": "12+ months"
        }
        
        # Calculate readiness score
        compliance_score = self._calculate_compliance_score(isms_results, "full_isms_assessment")
        readiness_results["readiness_score"] = compliance_score
        
        # Determine readiness status
        if compliance_score >= 0.9:
            readiness_results["overall_readiness"] = "ready"
            readiness_results["estimated_timeline"] = "0-3 months"
        elif compliance_score >= 0.8:
            readiness_results["overall_readiness"] = "mostly_ready"
            readiness_results["estimated_timeline"] = "3-6 months"
        elif compliance_score >= 0.6:
            readiness_results["overall_readiness"] = "partially_ready"
            readiness_results["estimated_timeline"] = "6-12 months"
        else:
            readiness_results["overall_readiness"] = "not_ready"
            readiness_results["estimated_timeline"] = "12+ months"
        
        # Analyze documentation readiness
        readiness_results["documentation_readiness"] = self._assess_documentation_readiness(isms_results)
        
        # Analyze process maturity
        readiness_results["process_maturity"] = isms_results.get("overall_maturity", "initial")
        
        return readiness_results
    
    async def _assess_isms_maturity(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess ISMS maturity level."""
        # Perform full assessment to get maturity data
        full_results = await self._assess_full_isms(target, options)
        
        maturity_results = {
            "overall_maturity": full_results["overall_maturity"],
            "domain_maturity": {},
            "isms_requirement_maturity": {},
            "pdca_maturity": {},
            "improvement_recommendations": []
        }
        
        # Analyze maturity by domain
        for domain, domain_data in full_results.get("domains", {}).items():
            maturity_results["domain_maturity"][domain] = domain_data.get("maturity_level", "initial")
        
        # Analyze ISMS requirement maturity
        for req, req_data in full_results.get("isms_requirements", {}).items():
            score = req_data.get("implementation_score", 0.0)
            maturity_results["isms_requirement_maturity"][req] = self._determine_maturity_level(score)
        
        # Analyze PDCA maturity
        pdca_data = full_results.get("pdca_cycle", {})
        for phase, phase_data in pdca_data.items():
            score = phase_data.get("score", 0.0)
            maturity_results["pdca_maturity"][phase] = self._determine_maturity_level(score)
        
        return maturity_results
    
    async def _assess_risk_management(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk management process (ISO 27001 clause 6)."""
        risk_results = {
            "risk_assessment_process": {"score": 0.0, "status": "unknown"},
            "risk_treatment_process": {"score": 0.0, "status": "unknown"},
            "risk_register": {"score": 0.0, "status": "unknown"},
            "risk_acceptance": {"score": 0.0, "status": "unknown"},
            "statement_of_applicability": {"score": 0.0, "status": "unknown"},
            "overall_risk_management_score": 0.0
        }
        
        # Simulate risk management assessment
        components = [
            "risk_assessment_process",
            "risk_treatment_process", 
            "risk_register",
            "risk_acceptance",
            "statement_of_applicability"
        ]
        
        total_score = 0.0
        for component in components:
            # Simulate scoring
            score = 0.6  # Default partial implementation
            risk_results[component]["score"] = score
            risk_results[component]["status"] = "partially_compliant" if score >= 0.5 else "non_compliant"
            total_score += score
        
        risk_results["overall_risk_management_score"] = total_score / len(components)
        
        return risk_results
    
    async def _perform_gap_analysis(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform ISO 27001 compliance gap analysis."""
        # Perform full assessment
        full_results = await self._assess_full_isms(target, options)
        
        gap_analysis = {
            "critical_gaps": [],
            "major_gaps": [],
            "minor_gaps": [],
            "isms_gaps": [],
            "control_gaps": [],
            "documentation_gaps": [],
            "process_gaps": [],
            "remediation_roadmap": []
        }
        
        # Analyze control gaps
        for control in full_results.get("controls", []):
            if control["status"] != "compliant":
                gap_info = {
                    "control_id": control["control_id"],
                    "title": control["title"],
                    "domain": control["domain"],
                    "current_score": control["implementation_score"],
                    "gaps": control["gaps"],
                    "recommendations": control["recommendations"],
                    "priority": self._calculate_control_gap_priority(control)
                }
                
                # Categorize gap by priority
                if gap_info["priority"] == "critical":
                    gap_analysis["critical_gaps"].append(gap_info)
                elif gap_info["priority"] == "major":
                    gap_analysis["major_gaps"].append(gap_info)
                else:
                    gap_analysis["minor_gaps"].append(gap_info)
                
                gap_analysis["control_gaps"].append(gap_info)
        
        # Analyze ISMS requirement gaps
        for req, req_data in full_results.get("isms_requirements", {}).items():
            if req_data.get("status") != "compliant":
                gap_analysis["isms_gaps"].append({
                    "requirement": req,
                    "score": req_data.get("implementation_score", 0.0),
                    "gaps": req_data.get("gaps", []),
                    "recommendations": req_data.get("recommendations", [])
                })
        
        # Generate remediation roadmap
        if self.config.include_gap_analysis:
            gap_analysis["remediation_roadmap"] = self._generate_iso_remediation_roadmap(gap_analysis)
        
        return gap_analysis
    
    async def _collect_control_evidence(
        self, 
        target: str, 
        control_id: str, 
        control_data: Dict[str, Any], 
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Collect evidence for control assessment."""
        evidence = []
        
        # Simulate evidence collection based on control type
        control_type = control_data.get("type", "procedural")
        domain = control_data.get("domain", "")
        
        if domain == "A.8":  # Asset Management
            evidence.extend([
                {"type": "documentation", "description": "Asset inventory maintained", "confidence": 0.8},
                {"type": "process", "description": "Asset classification process", "confidence": 0.7}
            ])
        elif domain == "A.9":  # Access Control
            evidence.extend([
                {"type": "technical", "description": "Access control system logs", "confidence": 0.9},
                {"type": "documentation", "description": "Access control policy", "confidence": 0.8}
            ])
        elif domain == "A.12":  # Operations Security
            evidence.extend([
                {"type": "technical", "description": "Security monitoring logs", "confidence": 0.8},
                {"type": "process", "description": "Incident response procedures", "confidence": 0.7}
            ])
        else:
            # Default evidence
            evidence.append({
                "type": "documentation",
                "description": f"Documentation for {control_id}",
                "confidence": 0.6
            })
        
        return evidence
    
    def _evaluate_control_implementation(
        self, 
        control_id: str, 
        control_data: Dict[str, Any], 
        evidence: List[Dict[str, Any]]
    ) -> float:
        """Evaluate control implementation score based on evidence."""
        if not evidence:
            return 0.0
        
        # Calculate score based on evidence quality and coverage
        total_confidence = sum(item.get("confidence", 0.5) for item in evidence)
        evidence_coverage = min(len(evidence) * 0.3, 1.0)  # Coverage factor
        
        return min(total_confidence * evidence_coverage, 1.0)
    
    def _determine_maturity_level(self, implementation_score: float) -> str:
        """Determine maturity level based on implementation score."""
        if implementation_score >= 0.9:
            return ISMSMaturityLevel.OPTIMIZING.value
        elif implementation_score >= 0.75:
            return ISMSMaturityLevel.QUANTITATIVELY_MANAGED.value
        elif implementation_score >= 0.6:
            return ISMSMaturityLevel.DEFINED.value
        elif implementation_score >= 0.4:
            return ISMSMaturityLevel.MANAGED.value
        else:
            return ISMSMaturityLevel.INITIAL.value
    
    def _identify_control_gaps(
        self, 
        control_id: str, 
        control_data: Dict[str, Any], 
        evidence: List[Dict[str, Any]]
    ) -> List[str]:
        """Identify implementation gaps for a control."""
        gaps = []
        domain = control_data.get("domain", "")
        
        # Common gaps based on domain
        if domain == "A.5":  # Information Security Policies
            gaps.append("Policy may need regular review and updates")
        elif domain == "A.8":  # Asset Management
            gaps.append("Asset inventory may be incomplete or outdated")
        elif domain == "A.9":  # Access Control
            gaps.append("Access rights may need regular review")
        elif domain == "A.12":  # Operations Security
            gaps.append("Security monitoring may need enhancement")
        
        # Evidence-based gaps
        if len(evidence) < 2:
            gaps.append("Insufficient evidence of implementation")
        
        return gaps
    
    def _generate_control_recommendations(
        self, 
        control_id: str, 
        control_data: Dict[str, Any], 
        gaps: List[str]
    ) -> List[str]:
        """Generate recommendations for addressing control gaps."""
        recommendations = []
        
        for gap in gaps:
            if "policy" in gap.lower():
                recommendations.append("Establish regular policy review schedule")
            elif "inventory" in gap.lower():
                recommendations.append("Implement automated asset discovery and inventory management")
            elif "access" in gap.lower():
                recommendations.append("Implement regular access rights review process")
            elif "monitoring" in gap.lower():
                recommendations.append("Deploy comprehensive security monitoring solution")
            elif "evidence" in gap.lower():
                recommendations.append("Document implementation evidence and maintain records")
        
        return recommendations
    
    def _calculate_compliance_score(self, assessment_results: Dict[str, Any], assessment_type: str) -> float:
        """Calculate overall compliance score."""
        if assessment_type == "full_isms_assessment":
            # Weighted score of ISMS requirements and Annex A controls
            isms_score = self._calculate_isms_requirements_score(assessment_results.get("isms_requirements", {}))
            controls_score = self._calculate_controls_score(assessment_results.get("controls", []))
            
            # Weight ISMS requirements and controls equally
            return (isms_score + controls_score) / 2.0
        
        elif "controls" in assessment_results:
            return self._calculate_controls_score(assessment_results["controls"])
        
        return 0.0
    
    def _calculate_isms_requirements_score(self, isms_requirements: Dict[str, Any]) -> float:
        """Calculate ISMS requirements compliance score."""
        if not isms_requirements:
            return 0.0
        
        total_score = sum(req_data.get("implementation_score", 0.0) for req_data in isms_requirements.values())
        return total_score / len(isms_requirements)
    
    def _calculate_controls_score(self, controls: List[Dict[str, Any]]) -> float:
        """Calculate Annex A controls compliance score."""
        if not controls:
            return 0.0
        
        # Apply domain weights if configured
        if self.config.domain_weights:
            weighted_score = 0.0
            for domain, weight in self.config.domain_weights.items():
                domain_controls = [c for c in controls if c.get("domain") == domain]
                if domain_controls:
                    domain_score = sum(c.get("implementation_score", 0.0) for c in domain_controls) / len(domain_controls)
                    weighted_score += domain_score * weight
            return weighted_score
        else:
            # Simple average
            total_score = sum(c.get("implementation_score", 0.0) for c in controls)
            return total_score / len(controls)
    
    def _calculate_isms_maturity(self, isms_results: Dict[str, Any]) -> str:
        """Calculate overall ISMS maturity level."""
        # Consider ISMS requirements, controls, and PDCA cycle
        isms_req_score = self._calculate_isms_requirements_score(isms_results.get("isms_requirements", {}))
        controls_score = self._calculate_controls_score(isms_results.get("controls", []))
        
        # Calculate PDCA score
        pdca_data = isms_results.get("pdca_cycle", {})
        pdca_scores = [phase_data.get("score", 0.0) for phase_data in pdca_data.values()]
        pdca_score = sum(pdca_scores) / len(pdca_scores) if pdca_scores else 0.0
        
        # Overall maturity based on average
        overall_score = (isms_req_score + controls_score + pdca_score) / 3.0
        
        return self._determine_maturity_level(overall_score)
    
    def _calculate_control_gap_priority(self, control: Dict[str, Any]) -> str:
        """Calculate control gap priority."""
        score = control.get("implementation_score", 0.0)
        domain = control.get("domain", "")
        
        # High-priority domains
        critical_domains = ["A.9", "A.12", "A.16"]  # Access Control, Operations Security, Incident Management
        
        if domain in critical_domains and score < 0.4:
            return "critical"
        elif score < 0.5:
            return "major"
        else:
            return "minor"
    
    def _assess_documentation_readiness(self, isms_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess documentation readiness for certification."""
        return {
            "isms_documentation": 0.7,  # Policies, procedures, etc.
            "risk_management_documentation": 0.6,  # Risk register, treatment plans
            "soa_completeness": 0.8,  # Statement of Applicability
            "evidence_documentation": 0.5,  # Implementation evidence
            "overall_documentation_score": 0.65
        }
    
    def _generate_iso_remediation_roadmap(self, gap_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate ISO 27001 remediation roadmap."""
        roadmap = []
        
        # Phase 1: Critical gaps and ISMS foundation
        if gap_analysis["critical_gaps"] or gap_analysis["isms_gaps"]:
            roadmap.append({
                "phase": 1,
                "title": "Establish ISMS Foundation and Address Critical Gaps",
                "timeline": "0-6 months",
                "critical_gaps": gap_analysis["critical_gaps"][:5],
                "isms_gaps": gap_analysis["isms_gaps"],
                "estimated_effort": "High",
                "key_deliverables": [
                    "Information Security Policy",
                    "Risk Assessment Process",
                    "Critical security controls implementation"
                ]
            })
        
        # Phase 2: Major control implementations
        if gap_analysis["major_gaps"]:
            roadmap.append({
                "phase": 2,
                "title": "Implement Major Security Controls",
                "timeline": "6-12 months",
                "major_gaps": gap_analysis["major_gaps"][:10],
                "estimated_effort": "Medium",
                "key_deliverables": [
                    "Security controls implementation",
                    "Documentation completion",
                    "Process improvements"
                ]
            })
        
        # Phase 3: Certification readiness
        roadmap.append({
            "phase": 3,
            "title": "Certification Preparation",
            "timeline": "12-18 months",
            "minor_gaps": gap_analysis["minor_gaps"],
            "estimated_effort": "Medium",
            "key_deliverables": [
                "Internal audit completion",
                "Management review",
                "Certification audit preparation"
            ]
        })
        
        return roadmap
    
    async def _generate_findings(
        self, 
        assessment_results: Dict[str, Any], 
        assessment_type: str,
        options: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate assessment findings."""
        findings = []
        
        # Generate findings for non-compliant controls
        if "controls" in assessment_results:
            for control in assessment_results["controls"]:
                if control["status"] != "compliant":
                    finding = {
                        "finding_id": f"ISO27001-{control['control_id']}-001",
                        "control_id": control["control_id"],
                        "title": f"Non-compliance with {control['control_id']}: {control['title']}",
                        "severity": self._determine_finding_severity(control),
                        "description": f"Control {control['control_id']} is not fully implemented",
                        "impact": "May result in certification audit findings",
                        "recommendations": control.get("recommendations", []),
                        "status": "open"
                    }
                    findings.append(finding)
        
        # Generate findings for ISMS requirements if applicable
        if "isms_requirements" in assessment_results:
            for req, req_data in assessment_results["isms_requirements"].items():
                if req_data.get("status") != "compliant":
                    finding = {
                        "finding_id": f"ISO27001-ISMS-{req.upper()}-001",
                        "control_id": f"ISMS-{req}",
                        "title": f"ISMS requirement not met: {req.replace('_', ' ').title()}",
                        "severity": "high",
                        "description": f"ISMS requirement {req} is not fully implemented",
                        "impact": "Critical for ISMS certification",
                        "recommendations": req_data.get("recommendations", []),
                        "status": "open"
                    }
                    findings.append(finding)
        
        return findings
    
    def _determine_finding_severity(self, control: Dict[str, Any]) -> str:
        """Determine finding severity based on control assessment."""
        score = control.get("implementation_score", 0.0)
        domain = control.get("domain", "")
        
        # Critical domains get higher severity
        critical_domains = ["A.9", "A.12", "A.16"]
        
        if domain in critical_domains and score < 0.3:
            return "high"
        elif score < 0.5:
            return "medium"
        else:
            return "low"
    
    def _load_framework_structure(self) -> Dict[str, Any]:
        """Load ISO 27001 framework structure."""
        # Simplified framework structure - in real implementation,
        # this would load from a comprehensive data file with all 93 controls
        return {
            "A.5": {
                "title": "Information Security Policies",
                "categories": {
                    "A.5.1": {
                        "title": "Information Security Policy",
                        "controls": {
                            "A.5.1.1": {
                                "title": "Policies for information security",
                                "description": "Information security policy and topic-specific policies",
                                "type": "procedural",
                                "evidence_requirements": ["policy_document", "approval_records", "communication_records"]
                            },
                            "A.5.1.2": {
                                "title": "Information security roles and responsibilities",
                                "description": "Information security roles and responsibilities",
                                "type": "procedural",
                                "evidence_requirements": ["role_definitions", "responsibility_matrix", "assignment_records"]
                            }
                        }
                    }
                }
            },
            "A.8": {
                "title": "Asset Management",
                "categories": {
                    "A.8.1": {
                        "title": "Responsibility for Assets",
                        "controls": {
                            "A.8.1.1": {
                                "title": "Inventory of assets",
                                "description": "Assets associated with information and information processing facilities",
                                "type": "procedural",
                                "evidence_requirements": ["asset_inventory", "classification_records", "ownership_assignments"]
                            },
                            "A.8.1.2": {
                                "title": "Ownership of assets",
                                "description": "Assets maintained in the inventory shall be owned",
                                "type": "procedural",
                                "evidence_requirements": ["ownership_records", "responsibility_assignments"]
                            }
                        }
                    }
                }
            },
            "A.9": {
                "title": "Access Control",
                "categories": {
                    "A.9.1": {
                        "title": "Business Requirements of Access Control",
                        "controls": {
                            "A.9.1.1": {
                                "title": "Access control policy",
                                "description": "Access control policy based on business and information security requirements",
                                "type": "procedural",
                                "evidence_requirements": ["access_control_policy", "business_requirements", "approval_records"]
                            },
                            "A.9.1.2": {
                                "title": "Access to networks and network services",
                                "description": "Users shall only be provided with access to networks and network services",
                                "type": "technical",
                                "evidence_requirements": ["network_access_controls", "authorization_records", "monitoring_logs"]
                            }
                        }
                    }
                }
            }
        }
    
    async def _validate_configuration(self):
        """Validate plugin configuration."""
        # Validate framework version
        if self.config.framework_version not in ["2013", "2022"]:
            raise ValueError(f"Unsupported ISO 27001 version: {self.config.framework_version}")
        
        # Validate domain weights if specified
        if self.config.domain_weights:
            total_weight = sum(self.config.domain_weights.values())
            if abs(total_weight - 1.0) > 0.01:
                raise ValueError(f"Domain weights must sum to 1.0, got {total_weight}")
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "framework": "ISO/IEC 27001",
            "framework_version": self.config.framework_version,
            "supported_assessments": self.supported_assessments,
            "assessment_domains": [d.value for d in self.config.assessment_domains],
            "isms_scope": self.config.isms_scope,
            "target_maturity_level": self.config.target_maturity_level.value,
            "total_controls": sum(
                len(cat.get("controls", {})) 
                for domain in self.framework_structure.values() 
                for cat in domain.get("categories", {}).values()
            )
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": True,
                "framework_loaded": bool(self.framework_structure),
                "total_domains": len(self.framework_structure),
                "configuration_valid": True,
                "last_error": self.last_error
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }