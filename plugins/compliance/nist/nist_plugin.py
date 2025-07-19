"""
NIST Compliance Plugin - NIST Cybersecurity Framework assessment and monitoring

This plugin provides compliance assessment capabilities for the NIST Cybersecurity Framework,
including control evaluation, gap analysis, and continuous monitoring.
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


class NISTFunction(str, Enum):
    """NIST Cybersecurity Framework Functions."""
    IDENTIFY = "identify"
    PROTECT = "protect"
    DETECT = "detect"
    RESPOND = "respond"
    RECOVER = "recover"


class NISTMaturityLevel(str, Enum):
    """NIST implementation maturity levels."""
    PARTIAL = "partial"
    RISK_INFORMED = "risk_informed"
    REPEATABLE = "repeatable"
    ADAPTIVE = "adaptive"


class NISTConfig(ComplianceConfig):
    """NIST compliance plugin configuration."""
    framework_version: str = "1.1"
    
    # Assessment settings
    maturity_level_target: NISTMaturityLevel = NISTMaturityLevel.REPEATABLE
    assessment_scope: List[NISTFunction] = [
        NISTFunction.IDENTIFY,
        NISTFunction.PROTECT,
        NISTFunction.DETECT,
        NISTFunction.RESPOND,
        NISTFunction.RECOVER
    ]
    
    # Control mappings
    control_mappings: Dict[str, str] = {}  # Internal control ID -> NIST subcategory mapping
    
    # Evidence collection
    evidence_sources: List[str] = [
        "vulnerability_scans",
        "security_policies",
        "incident_logs",
        "training_records",
        "asset_inventory"
    ]
    
    # Scoring weights
    function_weights: Dict[str, float] = {
        "identify": 0.2,
        "protect": 0.3,
        "detect": 0.2,
        "respond": 0.15,
        "recover": 0.15
    }
    
    # Reporting settings
    include_recommendations: bool = True
    include_gap_analysis: bool = True
    include_roadmap: bool = True
    
    # Custom categories
    custom_subcategories: Dict[str, Dict[str, Any]] = {}


class NISTPlugin(BaseCompliancePlugin):
    """
    NIST Cybersecurity Framework compliance plugin.
    
    Provides comprehensive NIST CSF compliance assessment including:
    - Five-function framework evaluation (Identify, Protect, Detect, Respond, Recover)
    - Subcategory-level control assessment
    - Maturity level evaluation
    - Gap analysis and remediation planning
    - Continuous monitoring and trending
    - Risk-based prioritization
    """
    
    def __init__(self, config: NISTConfig):
        super().__init__(config)
        self.config = config
        self.name = "nist"
        self.version = "1.1.0"
        self.description = "NIST Cybersecurity Framework compliance assessment and monitoring"
        
        # Supported assessment types
        self.supported_assessments = [
            "full_framework",
            "function_specific",
            "subcategory_specific",
            "maturity_assessment",
            "gap_analysis",
            "continuous_monitoring"
        ]
        
        # NIST Framework structure
        self.framework_structure = self._load_framework_structure()
        
        logger.info("NIST compliance plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the NIST plugin."""
        try:
            # Validate framework structure
            if not self.framework_structure:
                raise RuntimeError("Failed to load NIST framework structure")
            
            # Validate configuration
            await self._validate_configuration()
            
            logger.info("NIST plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize NIST plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup NIST plugin resources."""
        try:
            # No persistent resources to clean up
            logger.info("NIST plugin cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup NIST plugin: {e}")
            return False
    
    @traced("nist_plugin_assess_compliance")
    async def assess_compliance(
        self, 
        assessment_type: str, 
        target: str,
        controls: Optional[List[str]] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ComplianceResult:
        """Assess NIST Cybersecurity Framework compliance."""
        try:
            if assessment_type not in self.supported_assessments:
                raise ValueError(f"Unsupported assessment type: {assessment_type}")
            
            options = options or {}
            start_time = datetime.now(timezone.utc)
            
            # Perform assessment based on type
            if assessment_type == "full_framework":
                assessment_results = await self._assess_full_framework(target, options)
            elif assessment_type == "function_specific":
                function = options.get("function")
                if not function:
                    raise ValueError("Function must be specified for function_specific assessment")
                assessment_results = await self._assess_function(target, function, options)
            elif assessment_type == "subcategory_specific":
                subcategories = controls or options.get("subcategories", [])
                assessment_results = await self._assess_subcategories(target, subcategories, options)
            elif assessment_type == "maturity_assessment":
                assessment_results = await self._assess_maturity(target, options)
            elif assessment_type == "gap_analysis":
                assessment_results = await self._perform_gap_analysis(target, options)
            else:
                raise ValueError(f"Assessment type {assessment_type} not implemented")
            
            # Calculate overall compliance score
            compliance_score = self._calculate_compliance_score(assessment_results)
            
            # Generate findings and recommendations
            findings = await self._generate_findings(assessment_results, options)
            
            result = ComplianceResult(
                plugin_name=self.name,
                plugin_version=self.version,
                framework="NIST",
                assessment_type=assessment_type,
                controls_evaluated=len(assessment_results.get("controls", [])),
                controls_passed=len([c for c in assessment_results.get("controls", []) if c.get("status") == "compliant"]),
                controls_failed=len([c for c in assessment_results.get("controls", []) if c.get("status") == "non_compliant"]),
                compliance_score=compliance_score,
                findings=findings,
                status="success",
                metadata={
                    "framework_version": self.config.framework_version,
                    "assessment_scope": [f.value for f in self.config.assessment_scope],
                    "target_maturity_level": self.config.maturity_level_target.value,
                    "assessment_details": assessment_results
                }
            )
            
            logger.info(f"NIST assessment completed: {compliance_score:.2f} compliance score")
            metrics.nist_assessments_completed.inc()
            
            return result
            
        except Exception as e:
            logger.error(f"NIST assessment failed: {e}")
            metrics.nist_assessment_errors.inc()
            
            return ComplianceResult(
                plugin_name=self.name,
                plugin_version=self.version,
                framework="NIST",
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
        """Get NIST subcategory details."""
        try:
            # Search through framework structure
            for function_id, function_data in self.framework_structure.items():
                for category_id, category_data in function_data.get("categories", {}).items():
                    for subcategory_id, subcategory_data in category_data.get("subcategories", {}).items():
                        if subcategory_id == control_id:
                            return {
                                "id": subcategory_id,
                                "title": subcategory_data.get("title"),
                                "description": subcategory_data.get("description"),
                                "function": function_id,
                                "category": category_id,
                                "informative_references": subcategory_data.get("informative_references", []),
                                "implementation_guidance": subcategory_data.get("guidance", ""),
                                "maturity_indicators": subcategory_data.get("maturity_indicators", {})
                            }
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get control details: {e}")
            return None
    
    async def list_controls(self) -> List[Dict[str, Any]]:
        """List all NIST subcategories."""
        try:
            controls = []
            
            for function_id, function_data in self.framework_structure.items():
                for category_id, category_data in function_data.get("categories", {}).items():
                    for subcategory_id, subcategory_data in category_data.get("subcategories", {}).items():
                        controls.append({
                            "id": subcategory_id,
                            "title": subcategory_data.get("title"),
                            "function": function_id,
                            "category": category_id,
                            "description": subcategory_data.get("description")
                        })
            
            logger.info(f"Retrieved {len(controls)} NIST controls")
            return controls
            
        except Exception as e:
            logger.error(f"Failed to list controls: {e}")
            return []
    
    async def _assess_full_framework(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform full NIST framework assessment."""
        results = {
            "functions": {},
            "controls": [],
            "overall_maturity": NISTMaturityLevel.PARTIAL.value,
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        # Assess each function in scope
        for function in self.config.assessment_scope:
            function_result = await self._assess_function(target, function.value, options)
            results["functions"][function.value] = function_result
            
            # Add controls from this function
            results["controls"].extend(function_result.get("controls", []))
        
        # Calculate overall maturity
        results["overall_maturity"] = self._calculate_overall_maturity(results["functions"])
        
        return results
    
    async def _assess_function(self, target: str, function: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess a specific NIST function."""
        function_data = self.framework_structure.get(function, {})
        if not function_data:
            raise ValueError(f"Unknown NIST function: {function}")
        
        results = {
            "function": function,
            "categories": {},
            "controls": [],
            "function_score": 0.0,
            "maturity_level": NISTMaturityLevel.PARTIAL.value
        }
        
        total_subcategories = 0
        compliant_subcategories = 0
        
        # Assess each category
        for category_id, category_data in function_data.get("categories", {}).items():
            category_result = {
                "category": category_id,
                "subcategories": {},
                "category_score": 0.0
            }
            
            category_compliant = 0
            category_total = 0
            
            # Assess each subcategory
            for subcategory_id, subcategory_data in category_data.get("subcategories", {}).items():
                subcategory_result = await self._assess_subcategory(target, subcategory_id, subcategory_data, options)
                
                category_result["subcategories"][subcategory_id] = subcategory_result
                results["controls"].append(subcategory_result)
                
                category_total += 1
                total_subcategories += 1
                
                if subcategory_result.get("status") == "compliant":
                    category_compliant += 1
                    compliant_subcategories += 1
            
            # Calculate category score
            category_result["category_score"] = category_compliant / category_total if category_total > 0 else 0.0
            results["categories"][category_id] = category_result
        
        # Calculate function score
        results["function_score"] = compliant_subcategories / total_subcategories if total_subcategories > 0 else 0.0
        
        # Determine maturity level for this function
        results["maturity_level"] = self._determine_maturity_level(results["function_score"])
        
        return results
    
    async def _assess_subcategories(self, target: str, subcategories: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess specific NIST subcategories."""
        results = {
            "subcategories": subcategories,
            "controls": [],
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        for subcategory_id in subcategories:
            subcategory_data = await self.get_control_details(subcategory_id)
            if subcategory_data:
                subcategory_result = await self._assess_subcategory(target, subcategory_id, subcategory_data, options)
                results["controls"].append(subcategory_result)
        
        return results
    
    async def _assess_subcategory(
        self, 
        target: str, 
        subcategory_id: str, 
        subcategory_data: Dict[str, Any], 
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess a single NIST subcategory."""
        # Simulate assessment logic - in real implementation, this would:
        # 1. Check for relevant evidence from various sources
        # 2. Evaluate control implementation
        # 3. Assess maturity level
        # 4. Generate findings and recommendations
        
        result = {
            "control_id": subcategory_id,
            "title": subcategory_data.get("title", ""),
            "description": subcategory_data.get("description", ""),
            "function": subcategory_data.get("function", ""),
            "category": subcategory_data.get("category", ""),
            "status": "unknown",
            "implementation_score": 0.0,
            "maturity_level": NISTMaturityLevel.PARTIAL.value,
            "evidence": [],
            "gaps": [],
            "recommendations": [],
            "assessment_date": datetime.now(timezone.utc).isoformat()
        }
        
        # Simulate evidence collection
        evidence_found = await self._collect_evidence(target, subcategory_id, options)
        result["evidence"] = evidence_found
        
        # Evaluate implementation based on evidence
        implementation_score = self._evaluate_implementation(subcategory_id, evidence_found)
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
            result["gaps"] = self._identify_gaps(subcategory_id, evidence_found)
            if self.config.include_recommendations:
                result["recommendations"] = self._generate_recommendations(subcategory_id, result["gaps"])
        
        return result
    
    async def _assess_maturity(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Assess NIST implementation maturity."""
        # Perform full assessment first
        full_results = await self._assess_full_framework(target, options)
        
        # Calculate maturity metrics
        maturity_results = {
            "overall_maturity": full_results["overall_maturity"],
            "function_maturity": {},
            "maturity_indicators": {},
            "improvement_areas": []
        }
        
        # Analyze maturity by function
        for function, function_data in full_results["functions"].items():
            maturity_results["function_maturity"][function] = function_data["maturity_level"]
        
        # Identify improvement areas
        for function, maturity_level in maturity_results["function_maturity"].items():
            if maturity_level != self.config.maturity_level_target.value:
                maturity_results["improvement_areas"].append({
                    "function": function,
                    "current_maturity": maturity_level,
                    "target_maturity": self.config.maturity_level_target.value,
                    "priority": self._calculate_improvement_priority(function, maturity_level)
                })
        
        return maturity_results
    
    async def _perform_gap_analysis(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Perform NIST compliance gap analysis."""
        # Perform full assessment
        full_results = await self._assess_full_framework(target, options)
        
        gap_analysis = {
            "critical_gaps": [],
            "high_priority_gaps": [],
            "medium_priority_gaps": [],
            "low_priority_gaps": [],
            "remediation_roadmap": []
        }
        
        # Analyze gaps from assessment results
        for control in full_results["controls"]:
            if control["status"] != "compliant":
                gap_info = {
                    "control_id": control["control_id"],
                    "title": control["title"],
                    "function": control["function"],
                    "current_score": control["implementation_score"],
                    "gaps": control["gaps"],
                    "recommendations": control["recommendations"],
                    "effort_estimate": self._estimate_remediation_effort(control),
                    "business_impact": self._assess_business_impact(control)
                }
                
                # Categorize gap by priority
                priority = self._calculate_gap_priority(gap_info)
                gap_analysis[f"{priority}_priority_gaps"].append(gap_info)
        
        # Generate remediation roadmap
        if self.config.include_roadmap:
            gap_analysis["remediation_roadmap"] = self._generate_remediation_roadmap(gap_analysis)
        
        return gap_analysis
    
    async def _collect_evidence(self, target: str, subcategory_id: str, options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect evidence for subcategory assessment."""
        evidence = []
        
        # Simulate evidence collection from various sources
        for source in self.config.evidence_sources:
            if source == "vulnerability_scans":
                # Check for vulnerability scan data
                evidence.append({
                    "source": source,
                    "type": "automated_scan",
                    "description": f"Vulnerability scan data for {subcategory_id}",
                    "confidence": 0.8,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif source == "security_policies":
                # Check for relevant policies
                evidence.append({
                    "source": source,
                    "type": "documentation",
                    "description": f"Security policy documentation for {subcategory_id}",
                    "confidence": 0.7,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        
        return evidence
    
    def _evaluate_implementation(self, subcategory_id: str, evidence: List[Dict[str, Any]]) -> float:
        """Evaluate implementation score based on evidence."""
        if not evidence:
            return 0.0
        
        # Simple scoring based on evidence quality and quantity
        score = 0.0
        for item in evidence:
            confidence = item.get("confidence", 0.5)
            score += confidence * 0.3  # Each piece of evidence contributes
        
        return min(score, 1.0)  # Cap at 1.0
    
    def _determine_maturity_level(self, implementation_score: float) -> str:
        """Determine maturity level based on implementation score."""
        if implementation_score >= 0.9:
            return NISTMaturityLevel.ADAPTIVE.value
        elif implementation_score >= 0.7:
            return NISTMaturityLevel.REPEATABLE.value
        elif implementation_score >= 0.5:
            return NISTMaturityLevel.RISK_INFORMED.value
        else:
            return NISTMaturityLevel.PARTIAL.value
    
    def _identify_gaps(self, subcategory_id: str, evidence: List[Dict[str, Any]]) -> List[str]:
        """Identify implementation gaps."""
        gaps = []
        
        # Common gaps based on subcategory
        if "ID." in subcategory_id:
            gaps.append("Asset inventory may be incomplete")
        elif "PR." in subcategory_id:
            gaps.append("Protective controls may need strengthening")
        elif "DE." in subcategory_id:
            gaps.append("Detection capabilities require enhancement")
        elif "RS." in subcategory_id:
            gaps.append("Response procedures need improvement")
        elif "RC." in subcategory_id:
            gaps.append("Recovery processes require development")
        
        return gaps
    
    def _generate_recommendations(self, subcategory_id: str, gaps: List[str]) -> List[str]:
        """Generate recommendations for addressing gaps."""
        recommendations = []
        
        for gap in gaps:
            if "inventory" in gap.lower():
                recommendations.append("Implement automated asset discovery and inventory management")
            elif "controls" in gap.lower():
                recommendations.append("Review and strengthen protective security controls")
            elif "detection" in gap.lower():
                recommendations.append("Deploy advanced threat detection capabilities")
            elif "response" in gap.lower():
                recommendations.append("Develop and test incident response procedures")
            elif "recovery" in gap.lower():
                recommendations.append("Create comprehensive business continuity plans")
        
        return recommendations
    
    def _calculate_compliance_score(self, assessment_results: Dict[str, Any]) -> float:
        """Calculate overall compliance score."""
        if "functions" in assessment_results:
            # Full framework assessment
            total_score = 0.0
            for function, weight in self.config.function_weights.items():
                function_data = assessment_results["functions"].get(function, {})
                function_score = function_data.get("function_score", 0.0)
                total_score += function_score * weight
            return total_score
        elif "controls" in assessment_results:
            # Control-specific assessment
            controls = assessment_results["controls"]
            if not controls:
                return 0.0
            
            total_score = sum(c.get("implementation_score", 0.0) for c in controls)
            return total_score / len(controls)
        
        return 0.0
    
    def _calculate_overall_maturity(self, functions: Dict[str, Any]) -> str:
        """Calculate overall maturity level from function assessments."""
        maturity_scores = {
            NISTMaturityLevel.PARTIAL.value: 1,
            NISTMaturityLevel.RISK_INFORMED.value: 2,
            NISTMaturityLevel.REPEATABLE.value: 3,
            NISTMaturityLevel.ADAPTIVE.value: 4
        }
        
        total_score = 0
        count = 0
        
        for function_data in functions.values():
            maturity = function_data.get("maturity_level", NISTMaturityLevel.PARTIAL.value)
            total_score += maturity_scores.get(maturity, 1)
            count += 1
        
        if count == 0:
            return NISTMaturityLevel.PARTIAL.value
        
        avg_score = total_score / count
        
        if avg_score >= 3.5:
            return NISTMaturityLevel.ADAPTIVE.value
        elif avg_score >= 2.5:
            return NISTMaturityLevel.REPEATABLE.value
        elif avg_score >= 1.5:
            return NISTMaturityLevel.RISK_INFORMED.value
        else:
            return NISTMaturityLevel.PARTIAL.value
    
    async def _generate_findings(self, assessment_results: Dict[str, Any], options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate assessment findings."""
        findings = []
        
        if "controls" in assessment_results:
            for control in assessment_results["controls"]:
                if control["status"] != "compliant":
                    finding = {
                        "finding_id": f"NIST-{control['control_id']}-001",
                        "control_id": control["control_id"],
                        "title": f"Non-compliance with {control['control_id']}: {control['title']}",
                        "severity": self._determine_finding_severity(control),
                        "description": f"Control {control['control_id']} is not fully implemented",
                        "impact": "May result in increased security risk",
                        "recommendations": control.get("recommendations", []),
                        "status": "open"
                    }
                    findings.append(finding)
        
        return findings
    
    def _determine_finding_severity(self, control: Dict[str, Any]) -> str:
        """Determine finding severity based on control assessment."""
        score = control.get("implementation_score", 0.0)
        function = control.get("function", "")
        
        # Critical functions get higher severity
        if function in ["protect", "detect"] and score < 0.3:
            return "high"
        elif score < 0.5:
            return "medium"
        else:
            return "low"
    
    def _estimate_remediation_effort(self, gap_info: Dict[str, Any]) -> str:
        """Estimate effort required for remediation."""
        score = gap_info.get("current_score", 0.0)
        
        if score < 0.3:
            return "high"
        elif score < 0.6:
            return "medium"
        else:
            return "low"
    
    def _assess_business_impact(self, gap_info: Dict[str, Any]) -> str:
        """Assess business impact of the gap."""
        function = gap_info.get("function", "")
        
        if function in ["protect", "detect"]:
            return "high"
        elif function in ["respond", "recover"]:
            return "medium"
        else:
            return "low"
    
    def _calculate_gap_priority(self, gap_info: Dict[str, Any]) -> str:
        """Calculate gap remediation priority."""
        effort = gap_info.get("effort_estimate", "medium")
        impact = gap_info.get("business_impact", "medium")
        
        if impact == "high" and effort != "high":
            return "high"
        elif impact == "high" or effort == "low":
            return "medium"
        else:
            return "low"
    
    def _calculate_improvement_priority(self, function: str, current_maturity: str) -> str:
        """Calculate improvement priority for a function."""
        critical_functions = ["protect", "detect"]
        
        if function in critical_functions and current_maturity == NISTMaturityLevel.PARTIAL.value:
            return "high"
        elif current_maturity == NISTMaturityLevel.PARTIAL.value:
            return "medium"
        else:
            return "low"
    
    def _generate_remediation_roadmap(self, gap_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate remediation roadmap."""
        roadmap = []
        
        # Phase 1: Critical gaps
        if gap_analysis["critical_gaps"]:
            roadmap.append({
                "phase": 1,
                "title": "Address Critical Security Gaps",
                "timeline": "0-3 months",
                "gaps": gap_analysis["critical_gaps"][:5],  # Top 5 critical gaps
                "estimated_effort": "High"
            })
        
        # Phase 2: High priority gaps
        if gap_analysis["high_priority_gaps"]:
            roadmap.append({
                "phase": 2,
                "title": "Implement High Priority Controls",
                "timeline": "3-6 months",
                "gaps": gap_analysis["high_priority_gaps"][:10],
                "estimated_effort": "Medium"
            })
        
        # Phase 3: Medium priority gaps
        if gap_analysis["medium_priority_gaps"]:
            roadmap.append({
                "phase": 3,
                "title": "Enhance Security Posture",
                "timeline": "6-12 months",
                "gaps": gap_analysis["medium_priority_gaps"],
                "estimated_effort": "Medium"
            })
        
        return roadmap
    
    def _load_framework_structure(self) -> Dict[str, Any]:
        """Load NIST Cybersecurity Framework structure."""
        # Simplified framework structure - in real implementation, 
        # this would load from a comprehensive data file
        return {
            "identify": {
                "title": "Identify",
                "description": "Develop organizational understanding to manage cybersecurity risk",
                "categories": {
                    "ID.AM": {
                        "title": "Asset Management",
                        "subcategories": {
                            "ID.AM-1": {
                                "title": "Physical devices and systems within the organization are inventoried",
                                "description": "Hardware inventory with network connections",
                                "informative_references": ["CIS Controls 1", "ISO 27001 A.8.1.1"]
                            },
                            "ID.AM-2": {
                                "title": "Software platforms and applications within the organization are inventoried",
                                "description": "Software inventory and licensing",
                                "informative_references": ["CIS Controls 2", "ISO 27001 A.8.1.2"]
                            }
                        }
                    }
                }
            },
            "protect": {
                "title": "Protect", 
                "description": "Develop and implement appropriate safeguards",
                "categories": {
                    "PR.AC": {
                        "title": "Identity Management, Authentication and Access Control",
                        "subcategories": {
                            "PR.AC-1": {
                                "title": "Identities and credentials are issued, managed, verified, revoked, and audited",
                                "description": "Identity lifecycle management",
                                "informative_references": ["CIS Controls 5", "ISO 27001 A.9.2.1"]
                            }
                        }
                    }
                }
            },
            "detect": {
                "title": "Detect",
                "description": "Develop and implement appropriate activities to identify cybersecurity events",
                "categories": {
                    "DE.AE": {
                        "title": "Anomalies and Events",
                        "subcategories": {
                            "DE.AE-1": {
                                "title": "A baseline of network operations and expected data flows is established",
                                "description": "Network baseline and monitoring",
                                "informative_references": ["CIS Controls 12", "ISO 27001 A.12.4.1"]
                            }
                        }
                    }
                }
            },
            "respond": {
                "title": "Respond",
                "description": "Develop and implement appropriate activities for cybersecurity incidents",
                "categories": {
                    "RS.RP": {
                        "title": "Response Planning",
                        "subcategories": {
                            "RS.RP-1": {
                                "title": "Response plan is executed during or after an incident",
                                "description": "Incident response plan execution",
                                "informative_references": ["CIS Controls 19", "ISO 27001 A.16.1.5"]
                            }
                        }
                    }
                }
            },
            "recover": {
                "title": "Recover",
                "description": "Develop and implement appropriate activities for resilience",
                "categories": {
                    "RC.RP": {
                        "title": "Recovery Planning",
                        "subcategories": {
                            "RC.RP-1": {
                                "title": "Recovery plan is executed during or after a cybersecurity incident",
                                "description": "Recovery plan execution",
                                "informative_references": ["CIS Controls 11", "ISO 27001 A.17.1.2"]
                            }
                        }
                    }
                }
            }
        }
    
    async def _validate_configuration(self):
        """Validate plugin configuration."""
        # Validate framework version
        if self.config.framework_version not in ["1.0", "1.1"]:
            raise ValueError(f"Unsupported NIST framework version: {self.config.framework_version}")
        
        # Validate function weights sum to 1.0
        total_weight = sum(self.config.function_weights.values())
        if abs(total_weight - 1.0) > 0.01:
            raise ValueError(f"Function weights must sum to 1.0, got {total_weight}")
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "framework": "NIST Cybersecurity Framework",
            "framework_version": self.config.framework_version,
            "supported_assessments": self.supported_assessments,
            "assessment_scope": [f.value for f in self.config.assessment_scope],
            "target_maturity_level": self.config.maturity_level_target.value,
            "total_controls": sum(
                len(cat.get("subcategories", {})) 
                for func in self.framework_structure.values() 
                for cat in func.get("categories", {}).values()
            )
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            return {
                "healthy": True,
                "framework_loaded": bool(self.framework_structure),
                "total_functions": len(self.framework_structure),
                "configuration_valid": True,
                "last_error": self.last_error
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }