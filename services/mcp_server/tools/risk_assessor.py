"""
Risk Assessor Tool

Implements AI-powered security risk assessment capabilities.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid

import structlog

logger = structlog.get_logger(__name__)


class RiskAssessorTool:
    """
    Risk Assessor Tool for MCP
    
    Provides AI-powered security risk assessment and analysis.
    """
    
    def __init__(self):
        """Initialize the risk assessor tool."""
        self.assessment_cache = {}
        
    async def assess_risk(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        context: Optional[str] = None,
        criteria: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform AI-powered security risk assessment.
        
        Args:
            vulnerabilities: List of vulnerabilities to assess
            context: Additional context for assessment
            criteria: Specific assessment criteria
            
        Returns:
            Risk assessment results with scores and recommendations
        """
        assessment_id = str(uuid.uuid4())
        logger.info("Starting risk assessment", 
                   assessment_id=assessment_id, vuln_count=len(vulnerabilities))
        
        try:
            assessment_start = datetime.utcnow()
            
            # Perform risk assessment analysis
            risk_analysis = await self._analyze_vulnerabilities(vulnerabilities, context, criteria)
            
            # Calculate overall risk scores
            risk_scores = self._calculate_risk_scores(vulnerabilities, risk_analysis)
            
            # Generate prioritized recommendations
            recommendations = self._generate_risk_recommendations(vulnerabilities, risk_analysis, context)
            
            # Create risk matrix and categorization
            risk_matrix = self._create_risk_matrix(vulnerabilities, risk_analysis)
            
            assessment_end = datetime.utcnow()
            duration = (assessment_end - assessment_start).total_seconds()
            
            # Structure final assessment result
            assessment_result = {
                "assessment_id": assessment_id,
                "assessment_start": assessment_start.isoformat(),
                "assessment_end": assessment_end.isoformat(),
                "duration_seconds": duration,
                "status": "completed",
                "input_summary": {
                    "vulnerability_count": len(vulnerabilities),
                    "context": context,
                    "criteria": criteria or []
                },
                "risk_analysis": risk_analysis,
                "risk_scores": risk_scores,
                "risk_matrix": risk_matrix,
                "recommendations": recommendations,
                "executive_summary": self._generate_executive_summary(risk_scores, recommendations)
            }
            
            # Cache results
            self.assessment_cache[assessment_id] = assessment_result
            
            logger.info("Risk assessment completed", 
                       assessment_id=assessment_id, 
                       overall_risk=risk_scores.get("overall_risk_level"),
                       duration=duration)
            
            return assessment_result
            
        except Exception as e:
            logger.error("Risk assessment failed", 
                        assessment_id=assessment_id, error=str(e))
            return {
                "assessment_id": assessment_id,
                "status": "failed",
                "error": str(e),
                "assessment_start": assessment_start.isoformat() if 'assessment_start' in locals() else None
            }
    
    async def _analyze_vulnerabilities(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        context: Optional[str], 
        criteria: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Analyze vulnerabilities using AI-powered assessment."""
        
        analysis = {
            "vulnerability_analysis": [],
            "threat_landscape": {},
            "exploit_potential": {},
            "business_impact": {},
            "environmental_factors": {}
        }
        
        # Analyze each vulnerability
        for vuln in vulnerabilities:
            vuln_analysis = await self._analyze_single_vulnerability(vuln, context, criteria)
            analysis["vulnerability_analysis"].append(vuln_analysis)
        
        # Aggregate threat landscape analysis
        analysis["threat_landscape"] = self._analyze_threat_landscape(vulnerabilities, context)
        
        # Assess exploit potential
        analysis["exploit_potential"] = self._assess_exploit_potential(vulnerabilities, context)
        
        # Evaluate business impact
        analysis["business_impact"] = self._evaluate_business_impact(vulnerabilities, context)
        
        # Consider environmental factors
        analysis["environmental_factors"] = self._analyze_environmental_factors(vulnerabilities, context)
        
        return analysis
    
    async def _analyze_single_vulnerability(
        self, 
        vulnerability: Dict[str, Any], 
        context: Optional[str], 
        criteria: Optional[List[str]]
    ) -> Dict[str, Any]:
        """Analyze a single vulnerability in detail."""
        
        cve_id = vulnerability.get("cve_id", "")
        severity = vulnerability.get("severity", "unknown").lower()
        package = vulnerability.get("package_name", "")
        description = vulnerability.get("description", "")
        cvss_score = vulnerability.get("cvss_score")
        
        # Base risk factors
        risk_factors = {
            "severity_factor": self._calculate_severity_factor(severity, cvss_score),
            "exploitability_factor": self._calculate_exploitability_factor(vulnerability, context),
            "exposure_factor": self._calculate_exposure_factor(vulnerability, context),
            "impact_factor": self._calculate_impact_factor(vulnerability, context),
            "mitigation_factor": self._calculate_mitigation_factor(vulnerability)
        }
        
        # Calculate composite risk score
        composite_score = self._calculate_composite_risk_score(risk_factors)
        
        # Generate specific analysis
        analysis = {
            "cve_id": cve_id,
            "package": package,
            "severity": severity,
            "cvss_score": cvss_score,
            "risk_factors": risk_factors,
            "composite_risk_score": composite_score,
            "risk_level": self._determine_risk_level(composite_score),
            "exploitability_assessment": self._assess_exploitability(vulnerability, context),
            "business_impact_assessment": self._assess_business_impact(vulnerability, context),
            "remediation_urgency": self._calculate_remediation_urgency(composite_score, risk_factors),
            "contextual_factors": self._identify_contextual_factors(vulnerability, context)
        }
        
        return analysis
    
    def _calculate_severity_factor(self, severity: str, cvss_score: Optional[float]) -> float:
        """Calculate risk factor based on severity and CVSS score."""
        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.6,
            "low": 0.3,
            "negligible": 0.1,
            "unknown": 0.5
        }
        
        base_factor = severity_weights.get(severity, 0.5)
        
        # Adjust based on CVSS score if available
        if cvss_score is not None:
            if cvss_score >= 9.0:
                base_factor = max(base_factor, 1.0)
            elif cvss_score >= 7.0:
                base_factor = max(base_factor, 0.8)
            elif cvss_score >= 4.0:
                base_factor = max(base_factor, 0.6)
        
        return base_factor
    
    def _calculate_exploitability_factor(self, vulnerability: Dict[str, Any], context: Optional[str]) -> float:
        """Calculate exploitability factor based on vulnerability characteristics."""
        base_factor = 0.5
        
        # Check for known exploits
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["remote", "unauthenticated", "buffer overflow", "injection"]):
            base_factor += 0.3
        
        # Check package criticality
        package = vulnerability.get("package_name", "").lower()
        critical_packages = ["kernel", "openssh", "nginx", "apache", "mysql", "postgresql"]
        if any(pkg in package for pkg in critical_packages):
            base_factor += 0.2
        
        # Context-based adjustments
        if context:
            context_lower = context.lower()
            if "production" in context_lower or "public" in context_lower:
                base_factor += 0.2
            elif "internal" in context_lower or "development" in context_lower:
                base_factor -= 0.1
        
        return min(base_factor, 1.0)
    
    def _calculate_exposure_factor(self, vulnerability: Dict[str, Any], context: Optional[str]) -> float:
        """Calculate exposure factor based on deployment and accessibility."""
        base_factor = 0.5
        
        # Package type influences exposure
        package_type = vulnerability.get("package_type", "").lower()
        if package_type in ["library", "framework"]:
            base_factor += 0.1
        elif package_type in ["service", "daemon"]:
            base_factor += 0.3
        
        # Context-based exposure assessment
        if context:
            context_lower = context.lower()
            if any(keyword in context_lower for keyword in ["web", "api", "public", "internet-facing"]):
                base_factor += 0.4
            elif any(keyword in context_lower for keyword in ["internal", "private", "isolated"]):
                base_factor -= 0.2
        
        return min(base_factor, 1.0)
    
    def _calculate_impact_factor(self, vulnerability: Dict[str, Any], context: Optional[str]) -> float:
        """Calculate potential impact factor."""
        base_factor = 0.5
        
        # Severity-based impact
        severity = vulnerability.get("severity", "").lower()
        if severity in ["critical", "high"]:
            base_factor += 0.3
        elif severity == "medium":
            base_factor += 0.1
        
        # Package criticality
        package = vulnerability.get("package_name", "").lower()
        if any(critical in package for critical in ["auth", "security", "crypto", "ssl", "tls"]):
            base_factor += 0.3
        
        # Context-based impact
        if context:
            context_lower = context.lower()
            if any(keyword in context_lower for keyword in ["financial", "healthcare", "critical", "production"]):
                base_factor += 0.3
        
        return min(base_factor, 1.0)
    
    def _calculate_mitigation_factor(self, vulnerability: Dict[str, Any]) -> float:
        """Calculate mitigation availability factor."""
        base_factor = 0.5
        
        # Check for available fixes
        fix_versions = vulnerability.get("fix_versions", [])
        if fix_versions and any(fix_versions):
            base_factor -= 0.3  # Lower risk if fix is available
        
        # Check for workarounds or patches
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["patch", "update", "workaround"]):
            base_factor -= 0.2
        
        return max(base_factor, 0.1)
    
    def _calculate_composite_risk_score(self, risk_factors: Dict[str, float]) -> float:
        """Calculate composite risk score from individual factors."""
        weights = {
            "severity_factor": 0.25,
            "exploitability_factor": 0.25,
            "exposure_factor": 0.20,
            "impact_factor": 0.20,
            "mitigation_factor": 0.10
        }
        
        composite_score = 0.0
        for factor, value in risk_factors.items():
            weight = weights.get(factor, 0.0)
            composite_score += value * weight
        
        return min(composite_score, 1.0)
    
    def _determine_risk_level(self, composite_score: float) -> str:
        """Determine risk level from composite score."""
        if composite_score >= 0.8:
            return "critical"
        elif composite_score >= 0.6:
            return "high"
        elif composite_score >= 0.4:
            return "medium"
        elif composite_score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    def _assess_exploitability(self, vulnerability: Dict[str, Any], context: Optional[str]) -> Dict[str, Any]:
        """Assess exploitability characteristics."""
        return {
            "attack_vector": self._determine_attack_vector(vulnerability),
            "attack_complexity": self._determine_attack_complexity(vulnerability),
            "privileges_required": self._determine_privileges_required(vulnerability),
            "user_interaction": self._determine_user_interaction(vulnerability),
            "exploit_availability": self._check_exploit_availability(vulnerability)
        }
    
    def _assess_business_impact(self, vulnerability: Dict[str, Any], context: Optional[str]) -> Dict[str, Any]:
        """Assess business impact potential."""
        return {
            "confidentiality_impact": self._assess_confidentiality_impact(vulnerability, context),
            "integrity_impact": self._assess_integrity_impact(vulnerability, context),
            "availability_impact": self._assess_availability_impact(vulnerability, context),
            "business_continuity_risk": self._assess_business_continuity_risk(vulnerability, context)
        }
    
    def _calculate_remediation_urgency(self, composite_score: float, risk_factors: Dict[str, float]) -> str:
        """Calculate remediation urgency."""
        if composite_score >= 0.8:
            return "immediate"
        elif composite_score >= 0.6:
            return "within_24_hours"
        elif composite_score >= 0.4:
            return "within_week"
        elif composite_score >= 0.2:
            return "within_month"
        else:
            return "next_maintenance_window"
    
    def _identify_contextual_factors(self, vulnerability: Dict[str, Any], context: Optional[str]) -> List[str]:
        """Identify contextual risk factors."""
        factors = []
        
        if context:
            context_lower = context.lower()
            if "production" in context_lower:
                factors.append("production_environment")
            if "public" in context_lower or "internet" in context_lower:
                factors.append("public_exposure")
            if "financial" in context_lower:
                factors.append("financial_services")
            if "healthcare" in context_lower:
                factors.append("healthcare_data")
        
        return factors
    
    def _calculate_risk_scores(self, vulnerabilities: List[Dict[str, Any]], risk_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk scores and metrics."""
        vuln_analyses = risk_analysis.get("vulnerability_analysis", [])
        
        if not vuln_analyses:
            return {"overall_risk_score": 0.0, "overall_risk_level": "minimal"}
        
        # Calculate aggregate scores
        total_score = sum(v.get("composite_risk_score", 0.0) for v in vuln_analyses)
        max_score = max(v.get("composite_risk_score", 0.0) for v in vuln_analyses)
        avg_score = total_score / len(vuln_analyses)
        
        # Weight the overall score (70% max, 30% average)
        overall_score = (max_score * 0.7) + (avg_score * 0.3)
        
        # Count by risk level
        risk_level_counts = {}
        for analysis in vuln_analyses:
            level = analysis.get("risk_level", "minimal")
            risk_level_counts[level] = risk_level_counts.get(level, 0) + 1
        
        return {
            "overall_risk_score": overall_score,
            "overall_risk_level": self._determine_risk_level(overall_score),
            "max_individual_risk": max_score,
            "average_risk_score": avg_score,
            "risk_level_distribution": risk_level_counts,
            "total_vulnerabilities": len(vulnerabilities),
            "high_risk_vulnerabilities": risk_level_counts.get("high", 0) + risk_level_counts.get("critical", 0)
        }
    
    def _generate_risk_recommendations(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        risk_analysis: Dict[str, Any], 
        context: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized risk remediation recommendations."""
        recommendations = []
        vuln_analyses = risk_analysis.get("vulnerability_analysis", [])
        
        # Sort by risk score
        sorted_analyses = sorted(vuln_analyses, key=lambda x: x.get("composite_risk_score", 0.0), reverse=True)
        
        # Immediate action items for critical/high risk
        critical_high = [v for v in sorted_analyses if v.get("risk_level") in ["critical", "high"]]
        if critical_high:
            recommendations.append({
                "priority": "immediate",
                "category": "critical_remediation",
                "title": "Address Critical and High Risk Vulnerabilities",
                "description": f"Immediately remediate {len(critical_high)} critical/high risk vulnerabilities",
                "vulnerabilities": [v.get("cve_id") for v in critical_high[:5]],
                "estimated_effort": "1-3 days",
                "business_justification": "Prevents potential security incidents and data breaches"
            })
        
        # Patch management strategy
        fixable_vulns = [v for v in vuln_analyses if self._has_available_fix(v)]
        if fixable_vulns:
            recommendations.append({
                "priority": "high",
                "category": "patch_management",
                "title": "Implement Patch Management Process",
                "description": f"Deploy available patches for {len(fixable_vulns)} vulnerabilities",
                "vulnerabilities": [v.get("cve_id") for v in fixable_vulns[:10]],
                "estimated_effort": "1-2 weeks",
                "business_justification": "Reduces attack surface with available security updates"
            })
        
        # Security monitoring enhancement
        recommendations.append({
            "priority": "medium",
            "category": "monitoring",
            "title": "Enhance Security Monitoring",
            "description": "Implement monitoring for vulnerability exploitation attempts",
            "estimated_effort": "2-4 weeks",
            "business_justification": "Early detection of potential security incidents"
        })
        
        return recommendations
    
    def _create_risk_matrix(self, vulnerabilities: List[Dict[str, Any]], risk_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create risk matrix for visualization."""
        matrix = {
            "risk_categories": {
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "minimal": []
            },
            "risk_vectors": {
                "network": 0,
                "local": 0,
                "physical": 0,
                "adjacent": 0
            },
            "affected_components": {}
        }
        
        vuln_analyses = risk_analysis.get("vulnerability_analysis", [])
        
        for analysis in vuln_analyses:
            risk_level = analysis.get("risk_level", "minimal")
            cve_id = analysis.get("cve_id", "")
            package = analysis.get("package", "")
            
            matrix["risk_categories"][risk_level].append({
                "cve_id": cve_id,
                "package": package,
                "score": analysis.get("composite_risk_score", 0.0)
            })
            
            # Track affected components
            if package:
                if package not in matrix["affected_components"]:
                    matrix["affected_components"][package] = {"count": 0, "max_risk": "minimal"}
                matrix["affected_components"][package]["count"] += 1
                if self._risk_level_priority(risk_level) > self._risk_level_priority(matrix["affected_components"][package]["max_risk"]):
                    matrix["affected_components"][package]["max_risk"] = risk_level
        
        return matrix
    
    def _generate_executive_summary(self, risk_scores: Dict[str, Any], recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate executive summary of risk assessment."""
        overall_risk = risk_scores.get("overall_risk_level", "minimal")
        total_vulns = risk_scores.get("total_vulnerabilities", 0)
        high_risk_count = risk_scores.get("high_risk_vulnerabilities", 0)
        
        immediate_actions = len([r for r in recommendations if r.get("priority") == "immediate"])
        
        return {
            "overall_risk_level": overall_risk,
            "total_vulnerabilities": total_vulns,
            "high_risk_vulnerabilities": high_risk_count,
            "immediate_actions_required": immediate_actions,
            "key_findings": [
                f"Identified {total_vulns} total vulnerabilities",
                f"{high_risk_count} vulnerabilities pose high or critical risk",
                f"{immediate_actions} immediate actions required",
                f"Overall security posture: {overall_risk}"
            ],
            "recommended_next_steps": [r.get("title") for r in recommendations[:3]]
        }
    
    # Helper methods for analysis
    def _determine_attack_vector(self, vulnerability: Dict[str, Any]) -> str:
        description = vulnerability.get("description", "").lower()
        if "remote" in description or "network" in description:
            return "network"
        elif "local" in description:
            return "local"
        else:
            return "unknown"
    
    def _determine_attack_complexity(self, vulnerability: Dict[str, Any]) -> str:
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["complex", "race condition", "timing"]):
            return "high"
        elif "simple" in description or "trivial" in description:
            return "low"
        else:
            return "medium"
    
    def _determine_privileges_required(self, vulnerability: Dict[str, Any]) -> str:
        description = vulnerability.get("description", "").lower()
        if "unauthenticated" in description or "no authentication" in description:
            return "none"
        elif "admin" in description or "root" in description:
            return "high"
        else:
            return "low"
    
    def _determine_user_interaction(self, vulnerability: Dict[str, Any]) -> str:
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["click", "user interaction", "social engineering"]):
            return "required"
        else:
            return "none"
    
    def _check_exploit_availability(self, vulnerability: Dict[str, Any]) -> bool:
        # This would typically check exploit databases
        cve_id = vulnerability.get("cve_id", "")
        description = vulnerability.get("description", "").lower()
        return "exploit" in description or "poc" in description
    
    def _assess_confidentiality_impact(self, vulnerability: Dict[str, Any], context: Optional[str]) -> str:
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["disclosure", "leak", "exposure", "read"]):
            return "high"
        else:
            return "low"
    
    def _assess_integrity_impact(self, vulnerability: Dict[str, Any], context: Optional[str]) -> str:
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["modify", "alter", "inject", "write"]):
            return "high"
        else:
            return "low"
    
    def _assess_availability_impact(self, vulnerability: Dict[str, Any], context: Optional[str]) -> str:
        description = vulnerability.get("description", "").lower()
        if any(keyword in description for keyword in ["denial", "crash", "hang", "resource exhaustion"]):
            return "high"
        else:
            return "low"
    
    def _assess_business_continuity_risk(self, vulnerability: Dict[str, Any], context: Optional[str]) -> str:
        severity = vulnerability.get("severity", "").lower()
        if severity in ["critical", "high"] and context and "production" in context.lower():
            return "high"
        else:
            return "medium"
    
    def _has_available_fix(self, analysis: Dict[str, Any]) -> bool:
        # Check if vulnerability has available fix
        return bool(analysis.get("fix_versions"))
    
    def _risk_level_priority(self, risk_level: str) -> int:
        priorities = {"critical": 5, "high": 4, "medium": 3, "low": 2, "minimal": 1}
        return priorities.get(risk_level, 0)
    
    def _analyze_threat_landscape(self, vulnerabilities: List[Dict[str, Any]], context: Optional[str]) -> Dict[str, Any]:
        """Analyze current threat landscape."""
        return {
            "threat_actors": ["APT groups", "Cybercriminals", "Script kiddies"],
            "attack_trends": ["Supply chain attacks", "Zero-day exploits", "Ransomware"],
            "industry_threats": ["Specific to context if provided"],
            "geopolitical_factors": ["Current threat landscape factors"]
        }
    
    def _assess_exploit_potential(self, vulnerabilities: List[Dict[str, Any]], context: Optional[str]) -> Dict[str, Any]:
        """Assess overall exploit potential."""
        high_exploitability = sum(1 for v in vulnerabilities 
                                 if v.get("severity", "").lower() in ["critical", "high"])
        
        return {
            "high_exploitability_count": high_exploitability,
            "exploit_likelihood": "high" if high_exploitability > 5 else "medium",
            "weaponization_potential": "high" if high_exploitability > 3 else "low"
        }
    
    def _evaluate_business_impact(self, vulnerabilities: List[Dict[str, Any]], context: Optional[str]) -> Dict[str, Any]:
        """Evaluate potential business impact."""
        return {
            "operational_impact": "medium",
            "financial_impact": "high" if context and "financial" in context.lower() else "medium",
            "reputational_impact": "high",
            "regulatory_impact": "medium" if context else "low"
        }
    
    def _analyze_environmental_factors(self, vulnerabilities: List[Dict[str, Any]], context: Optional[str]) -> Dict[str, Any]:
        """Analyze environmental risk factors."""
        factors = {
            "deployment_environment": "unknown",
            "network_exposure": "medium",
            "access_controls": "unknown",
            "monitoring_capabilities": "unknown"
        }
        
        if context:
            context_lower = context.lower()
            if "production" in context_lower:
                factors["deployment_environment"] = "production"
                factors["network_exposure"] = "high"
            elif "development" in context_lower:
                factors["deployment_environment"] = "development"
                factors["network_exposure"] = "low"
        
        return factors