"""
Graph Analyzer Service - Advanced dependency graph analysis

This service provides sophisticated analysis capabilities for dependency graphs,
including supply chain risk assessment, vulnerability impact analysis, and 
license compliance checking.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict, deque
import statistics
import networkx as nx

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.graph import (
    ComponentNode, DependencyRelationship, VulnerabilityNode,
    GraphPath, SupplyChainRisk, RiskLevel, ComponentType
)
from .graph_repository import GraphRepository

logger = get_logger(__name__)
metrics = get_metrics()


class GraphAnalyzer:
    """
    Advanced graph analyzer for dependency analysis.
    
    This analyzer provides:
    1. Supply chain risk assessment
    2. Vulnerability impact analysis
    3. License compliance checking
    4. Dependency path analysis
    5. Component popularity scoring
    6. Maintenance health assessment
    """
    
    def __init__(self, repository: GraphRepository):
        self.repository = repository
        
        # Analysis configuration
        self.max_analysis_depth = 10
        self.risk_threshold_high = 7.0
        self.risk_threshold_medium = 4.0
        self.popularity_weight = 0.2
        self.maintenance_weight = 0.3
        self.vulnerability_weight = 0.5
        
        # License policies
        self.license_policies = {
            "permissive": {
                "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"],
                "restricted": [],
                "forbidden": []
            },
            "copyleft_restricted": {
                "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"],
                "restricted": ["LGPL-2.1", "LGPL-3.0", "MPL-2.0"],
                "forbidden": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]
            },
            "strict": {
                "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause"],
                "restricted": [],
                "forbidden": ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"]
            }
        }
        
        # Component analysis cache
        self.component_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        logger.info("Graph analyzer initialized")
    
    @traced("graph_analyzer_analyze_supply_chain_risk")
    async def analyze_supply_chain_risk(
        self, 
        component_id: str, 
        max_depth: int = 5
    ) -> SupplyChainRisk:
        """Analyze supply chain risk for a component and its dependencies."""
        try:
            start_time = datetime.now()
            
            # Get component and its dependency tree
            component = await self.repository.get_component_by_id(component_id)
            if not component:
                raise ValueError(f"Component not found: {component_id}")
            
            dependencies = await self.repository.get_component_dependencies(
                component_id, max_depth
            )
            
            # Analyze component itself
            component_risk = await self._analyze_component_risk(component)
            
            # Analyze dependency risks
            dependency_risks = []
            for dep in dependencies:
                dep_component = ComponentNode(**dep)
                dep_risk = await self._analyze_component_risk(dep_component)
                dep_risk["depth"] = dep["depth"]
                dependency_risks.append(dep_risk)
            
            # Calculate overall risk metrics
            risk_analysis = await self._calculate_supply_chain_risk(
                component_risk, dependency_risks
            )
            
            # Get vulnerability information
            vulnerabilities = await self.repository.get_component_vulnerabilities(component_id)
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            
            supply_chain_risk = SupplyChainRisk(
                component_id=component_id,
                component_name=component.name,
                component_version=component.version,
                overall_risk_score=risk_analysis["overall_risk_score"],
                risk_level=risk_analysis["risk_level"],
                component_risk=component_risk,
                dependency_risks=dependency_risks,
                vulnerability_count=len(vulnerabilities),
                high_risk_dependencies=risk_analysis["high_risk_dependencies"],
                critical_paths=risk_analysis["critical_paths"],
                recommendations=risk_analysis["recommendations"],
                analysis_metadata={
                    "max_depth": max_depth,
                    "total_dependencies": len(dependencies),
                    "execution_time": execution_time,
                    "analysis_timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
            
            logger.debug(f"Supply chain risk analysis completed for {component_id}")
            metrics.graph_analyzer_supply_chain_analyses.inc()
            
            return supply_chain_risk
            
        except Exception as e:
            logger.error(f"Error analyzing supply chain risk: {e}")
            metrics.graph_analyzer_errors.inc()
            raise
    
    @traced("graph_analyzer_find_dependency_paths")
    async def find_dependency_paths(
        self, 
        from_component_id: str, 
        to_component_id: str,
        max_depth: int = 10
    ) -> List[GraphPath]:
        """Find and analyze dependency paths between components."""
        try:
            paths = await self.repository.find_dependency_paths(
                from_component_id, to_component_id, max_depth
            )
            
            # Enhance paths with additional analysis
            enhanced_paths = []
            for path in paths:
                # Calculate additional metrics
                path.vulnerability_count = await self._count_path_vulnerabilities(path)
                path.license_conflicts = await self._detect_license_conflicts(path)
                path.maintenance_issues = await self._assess_path_maintenance(path)
                
                enhanced_paths.append(path)
            
            # Sort by risk score
            enhanced_paths.sort(key=lambda p: p.risk_score, reverse=True)
            
            logger.debug(f"Found {len(enhanced_paths)} dependency paths")
            metrics.graph_analyzer_path_analyses.inc()
            
            return enhanced_paths
            
        except Exception as e:
            logger.error(f"Error finding dependency paths: {e}")
            metrics.graph_analyzer_errors.inc()
            raise
    
    @traced("graph_analyzer_analyze_vulnerability_impact")
    async def analyze_vulnerability_impact(self, vulnerability_id: str) -> Dict[str, Any]:
        """Analyze the impact of a vulnerability across the dependency graph."""
        try:
            # Find all components affected by this vulnerability
            affected_components = await self._get_vulnerability_affected_components(vulnerability_id)
            
            # For each affected component, find what depends on it
            impact_analysis = {
                "vulnerability_id": vulnerability_id,
                "directly_affected_components": len(affected_components),
                "impact_tree": {},
                "risk_assessment": {
                    "total_affected_projects": 0,
                    "critical_paths": [],
                    "blast_radius": 0
                }
            }
            
            for component in affected_components:
                # Find what depends on this component
                dependent_paths = await self._find_dependent_components(component["id"])
                
                impact_analysis["impact_tree"][component["id"]] = {
                    "component": component,
                    "dependent_components": len(dependent_paths),
                    "critical_dependents": [
                        path for path in dependent_paths 
                        if path.get("risk_score", 0) > self.risk_threshold_high
                    ]
                }
                
                impact_analysis["risk_assessment"]["total_affected_projects"] += len(dependent_paths)
                impact_analysis["risk_assessment"]["blast_radius"] = max(
                    impact_analysis["risk_assessment"]["blast_radius"],
                    len(dependent_paths)
                )
            
            logger.debug(f"Vulnerability impact analysis completed for {vulnerability_id}")
            metrics.graph_analyzer_vulnerability_analyses.inc()
            
            return impact_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability impact: {e}")
            metrics.graph_analyzer_errors.inc()
            raise
    
    @traced("graph_analyzer_analyze_license_compliance")
    async def analyze_license_compliance(
        self, 
        component_id: str, 
        policy_name: str = "permissive"
    ) -> Dict[str, Any]:
        """Analyze license compliance for a component and its dependencies."""
        try:
            if policy_name not in self.license_policies:
                raise ValueError(f"Unknown license policy: {policy_name}")
            
            policy = self.license_policies[policy_name]
            
            # Get component and dependencies
            component = await self.repository.get_component_by_id(component_id)
            dependencies = await self.repository.get_component_dependencies(component_id)
            
            compliance_analysis = {
                "component_id": component_id,
                "policy_name": policy_name,
                "compliance_status": "compliant",
                "issues": [],
                "license_distribution": defaultdict(int),
                "recommendations": []
            }
            
            # Check component license
            component_license = component.license_declared or component.license_concluded
            if component_license:
                compliance_analysis["license_distribution"][component_license] += 1
                
                if component_license in policy["forbidden"]:
                    compliance_analysis["compliance_status"] = "non_compliant"
                    compliance_analysis["issues"].append({
                        "component_id": component_id,
                        "component_name": component.name,
                        "license": component_license,
                        "issue_type": "forbidden_license",
                        "severity": "high"
                    })
                elif component_license in policy["restricted"]:
                    if compliance_analysis["compliance_status"] == "compliant":
                        compliance_analysis["compliance_status"] = "review_required"
                    compliance_analysis["issues"].append({
                        "component_id": component_id,
                        "component_name": component.name,
                        "license": component_license,
                        "issue_type": "restricted_license",
                        "severity": "medium"
                    })
            
            # Check dependency licenses
            for dep in dependencies:
                dep_license = dep.get("license_declared") or dep.get("license_concluded")
                if dep_license:
                    compliance_analysis["license_distribution"][dep_license] += 1
                    
                    if dep_license in policy["forbidden"]:
                        compliance_analysis["compliance_status"] = "non_compliant"
                        compliance_analysis["issues"].append({
                            "component_id": dep["id"],
                            "component_name": dep["name"],
                            "license": dep_license,
                            "issue_type": "forbidden_license",
                            "severity": "high",
                            "depth": dep["depth"]
                        })
                    elif dep_license in policy["restricted"]:
                        if compliance_analysis["compliance_status"] == "compliant":
                            compliance_analysis["compliance_status"] = "review_required"
                        compliance_analysis["issues"].append({
                            "component_id": dep["id"],
                            "component_name": dep["name"],
                            "license": dep_license,
                            "issue_type": "restricted_license",
                            "severity": "medium",
                            "depth": dep["depth"]
                        })
                else:
                    # Unknown license
                    compliance_analysis["issues"].append({
                        "component_id": dep["id"],
                        "component_name": dep["name"],
                        "license": "unknown",
                        "issue_type": "unknown_license",
                        "severity": "low",
                        "depth": dep["depth"]
                    })
            
            # Generate recommendations
            compliance_analysis["recommendations"] = self._generate_license_recommendations(
                compliance_analysis["issues"], policy_name
            )
            
            logger.debug(f"License compliance analysis completed for {component_id}")
            metrics.graph_analyzer_license_analyses.inc()
            
            return compliance_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing license compliance: {e}")
            metrics.graph_analyzer_errors.inc()
            raise
    
    async def _analyze_component_risk(self, component: ComponentNode) -> Dict[str, Any]:
        """Analyze risk for a single component."""
        risk_factors = {
            "popularity_score": component.popularity_score or 0.5,
            "maintenance_score": component.maintenance_score or 0.5,
            "age_score": self._calculate_component_age_score(component),
            "vulnerability_score": 0.0,  # Will be calculated separately
            "license_risk": self._assess_license_risk(component.license_declared)
        }
        
        # Get vulnerabilities for this component
        vulnerabilities = await self.repository.get_component_vulnerabilities(component.id)
        risk_factors["vulnerability_score"] = self._calculate_vulnerability_score(vulnerabilities)
        
        # Calculate weighted risk score
        risk_score = (
            (1.0 - risk_factors["popularity_score"]) * self.popularity_weight +
            (1.0 - risk_factors["maintenance_score"]) * self.maintenance_weight +
            risk_factors["vulnerability_score"] * self.vulnerability_weight +
            risk_factors["age_score"] * 0.1 +
            risk_factors["license_risk"] * 0.1
        ) * 10.0
        
        return {
            "component_id": component.id,
            "component_name": component.name,
            "component_version": component.version,
            "risk_score": min(risk_score, 10.0),
            "risk_factors": risk_factors,
            "vulnerability_count": len(vulnerabilities)
        }
    
    async def _calculate_supply_chain_risk(
        self, 
        component_risk: Dict[str, Any], 
        dependency_risks: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate overall supply chain risk metrics."""
        if not dependency_risks:
            overall_risk = component_risk["risk_score"]
        else:
            # Weight component risk higher than dependencies
            component_weight = 0.6
            dependency_weight = 0.4
            
            dependency_scores = [dep["risk_score"] for dep in dependency_risks]
            avg_dependency_risk = statistics.mean(dependency_scores)
            max_dependency_risk = max(dependency_scores)
            
            # Use weighted average with emphasis on worst dependencies
            overall_risk = (
                component_risk["risk_score"] * component_weight +
                (avg_dependency_risk * 0.7 + max_dependency_risk * 0.3) * dependency_weight
            )
        
        # Determine risk level
        if overall_risk >= self.risk_threshold_high:
            risk_level = RiskLevel.HIGH
        elif overall_risk >= self.risk_threshold_medium:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        # Identify high-risk dependencies
        high_risk_dependencies = [
            dep for dep in dependency_risks 
            if dep["risk_score"] >= self.risk_threshold_high
        ]
        
        # Identify critical paths (paths with multiple high-risk components)
        critical_paths = self._identify_critical_paths(dependency_risks)
        
        # Generate recommendations
        recommendations = self._generate_risk_recommendations(
            component_risk, dependency_risks, overall_risk
        )
        
        return {
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": risk_level,
            "high_risk_dependencies": high_risk_dependencies,
            "critical_paths": critical_paths,
            "recommendations": recommendations
        }
    
    def _calculate_component_age_score(self, component: ComponentNode) -> float:
        """Calculate age-based risk score for a component."""
        if not component.created_at:
            return 0.5  # Unknown age, medium risk
        
        age_days = (datetime.now(timezone.utc) - component.created_at).days
        
        # Components older than 2 years get higher risk
        if age_days > 730:
            return min(age_days / 1460, 1.0)  # Max 1.0 at 4 years
        else:
            return age_days / 730 * 0.3  # Lower risk for newer components
    
    def _assess_license_risk(self, license_name: Optional[str]) -> float:
        """Assess risk based on license type."""
        if not license_name:
            return 0.3  # Unknown license has some risk
        
        # Check against different policy levels
        for policy_name, policy in self.license_policies.items():
            if license_name in policy["forbidden"]:
                return 1.0  # High risk
            elif license_name in policy["restricted"]:
                return 0.6  # Medium risk
            elif license_name in policy["allowed"]:
                return 0.1  # Low risk
        
        return 0.4  # Unknown license type
    
    def _calculate_vulnerability_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate vulnerability-based risk score."""
        if not vulnerabilities:
            return 0.0
        
        risk_score = 0.0
        for vuln in vulnerabilities:
            cvss_score = vuln.get("cvss_score", 5.0)
            # Normalize CVSS to 0-1 scale and weight by severity
            normalized_score = cvss_score / 10.0
            
            # Higher weight for exploitable vulnerabilities
            if vuln.get("exploit_available", False):
                normalized_score *= 1.5
            if vuln.get("exploit_in_wild", False):
                normalized_score *= 2.0
            
            risk_score += min(normalized_score, 1.0)
        
        # Cap at 1.0 but allow multiple vulnerabilities to increase risk
        return min(risk_score, 1.0)
    
    def _identify_critical_paths(self, dependency_risks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical dependency paths with multiple high-risk components."""
        critical_paths = []
        
        # Group dependencies by depth to identify paths
        depth_groups = defaultdict(list)
        for dep in dependency_risks:
            if dep["risk_score"] >= self.risk_threshold_medium:
                depth_groups[dep["depth"]].append(dep)
        
        # Look for consecutive high-risk components (potential paths)
        for depth in sorted(depth_groups.keys()):
            if len(depth_groups[depth]) > 1:
                critical_paths.append({
                    "depth": depth,
                    "high_risk_components": depth_groups[depth],
                    "path_risk_score": statistics.mean([
                        dep["risk_score"] for dep in depth_groups[depth]
                    ])
                })
        
        return sorted(critical_paths, key=lambda p: p["path_risk_score"], reverse=True)
    
    def _generate_risk_recommendations(
        self, 
        component_risk: Dict[str, Any],
        dependency_risks: List[Dict[str, Any]], 
        overall_risk: float
    ) -> List[str]:
        """Generate actionable risk mitigation recommendations."""
        recommendations = []
        
        # Component-level recommendations
        if component_risk["risk_score"] >= self.risk_threshold_high:
            recommendations.append("Consider replacing this component with a lower-risk alternative")
            
            if component_risk["vulnerability_count"] > 0:
                recommendations.append("Update to the latest version to address known vulnerabilities")
        
        # Dependency-level recommendations
        high_risk_deps = [dep for dep in dependency_risks if dep["risk_score"] >= self.risk_threshold_high]
        if high_risk_deps:
            recommendations.append(f"Review and potentially replace {len(high_risk_deps)} high-risk dependencies")
        
        if overall_risk >= self.risk_threshold_high:
            recommendations.extend([
                "Implement additional security monitoring for this component",
                "Consider security-focused dependency scanning in CI/CD pipeline",
                "Review dependency update policy to ensure timely security patches"
            ])
        
        return recommendations
    
    def _generate_license_recommendations(
        self, 
        issues: List[Dict[str, Any]], 
        policy_name: str
    ) -> List[str]:
        """Generate license compliance recommendations."""
        recommendations = []
        
        forbidden_issues = [i for i in issues if i["issue_type"] == "forbidden_license"]
        restricted_issues = [i for i in issues if i["issue_type"] == "restricted_license"]
        unknown_issues = [i for i in issues if i["issue_type"] == "unknown_license"]
        
        if forbidden_issues:
            recommendations.append(f"Replace {len(forbidden_issues)} components with forbidden licenses")
        
        if restricted_issues:
            recommendations.append(f"Review {len(restricted_issues)} components with restricted licenses for compliance")
        
        if unknown_issues:
            recommendations.append(f"Identify licenses for {len(unknown_issues)} components with unknown licenses")
        
        if policy_name == "permissive":
            recommendations.append("Consider adopting MIT or Apache-2.0 licensed alternatives")
        
        return recommendations
    
    async def _get_vulnerability_affected_components(self, vulnerability_id: str) -> List[Dict[str, Any]]:
        """Get all components affected by a vulnerability."""
        # This would query the graph for components linked to the vulnerability
        return []  # Placeholder implementation
    
    async def _find_dependent_components(self, component_id: str) -> List[Dict[str, Any]]:
        """Find components that depend on the given component."""
        # This would query the graph for reverse dependencies
        return []  # Placeholder implementation
    
    async def _count_path_vulnerabilities(self, path: GraphPath) -> int:
        """Count vulnerabilities across all components in a path."""
        return 0  # Placeholder implementation
    
    async def _detect_license_conflicts(self, path: GraphPath) -> List[str]:
        """Detect license conflicts in a dependency path."""
        return []  # Placeholder implementation
    
    async def _assess_path_maintenance(self, path: GraphPath) -> Dict[str, Any]:
        """Assess maintenance health across a dependency path."""
        return {}  # Placeholder implementation
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return {
            "max_analysis_depth": self.max_analysis_depth,
            "risk_thresholds": {
                "high": self.risk_threshold_high,
                "medium": self.risk_threshold_medium
            },
            "cache_size": len(self.component_cache),
            "cache_ttl": self.cache_ttl,
            "license_policies": list(self.license_policies.keys()),
            "operations": [
                "analyze_supply_chain_risk", "find_dependency_paths",
                "analyze_vulnerability_impact", "analyze_license_compliance"
            ]
        }