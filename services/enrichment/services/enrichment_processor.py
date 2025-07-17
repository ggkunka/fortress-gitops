"""Enrichment processor for specialized enrichment types."""

import asyncio
import re
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

import structlog
from shared.config import get_settings

from ..schemas.enrichment import DataType
from .caching import CachingService

settings = get_settings()
logger = structlog.get_logger()


class EnrichmentProcessor:
    """Service for performing specialized enrichment analysis."""
    
    def __init__(self):
        self.logger = logger.bind(service="enrichment", component="enrichment_processor")
        self.caching_service = CachingService()
        self.is_running = False
        
        # Vulnerability scoring weights
        self.vulnerability_weights = {
            "cvss_score": 0.4,
            "exploitability": 0.3,
            "impact": 0.2,
            "temporal": 0.1,
        }
        
        # Behavioral analysis patterns
        self.suspicious_patterns = {
            "processes": [
                r".*\.tmp\.(exe|bat|cmd|ps1)",
                r"powershell.*-enc.*",
                r"cmd.*\/c.*echo.*",
                r".*backdoor.*",
                r".*malware.*",
                r".*trojan.*",
            ],
            "network": [
                r".*\.onion$",
                r".*\.bit$",
                r".*suspicious-domain\..*",
                r".*malware-c2\..*",
            ],
            "files": [
                r".*\.exe$",
                r".*\.dll$",
                r".*\.scr$",
                r".*\.vbs$",
                r".*\.js$",
            ],
        }
        
        # Risk assessment factors
        self.risk_factors = {
            "high_risk_components": [
                "openssl", "apache", "nginx", "tomcat", "jenkins",
                "wordpress", "drupal", "joomla", "struts",
            ],
            "critical_paths": [
                "/etc/passwd", "/etc/shadow", "/root/",
                "/home/", "/usr/bin/", "/bin/",
            ],
            "sensitive_data_patterns": [
                r"password", r"secret", r"token", r"key",
                r"credential", r"auth", r"api_key",
            ],
        }
    
    async def start(self) -> None:
        """Start the enrichment processor."""
        try:
            await self.caching_service.start()
            self.is_running = True
            self.logger.info("Enrichment processor started")
        except Exception as e:
            self.logger.error("Failed to start enrichment processor", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the enrichment processor."""
        try:
            await self.caching_service.stop()
            self.is_running = False
            self.logger.info("Enrichment processor stopped")
        except Exception as e:
            self.logger.error("Error stopping enrichment processor", error=str(e))
            raise
    
    async def enrich(self, data: Dict[str, Any], data_type: DataType) -> Dict[str, Any]:
        """Perform enrichment based on the current context."""
        try:
            start_time = datetime.utcnow()
            
            # Route to appropriate enrichment method
            if data_type == DataType.SBOM:
                result = await self._enrich_sbom_vulnerability_analysis(data)
            elif data_type == DataType.CVE:
                result = await self._enrich_cve_vulnerability_analysis(data)
            elif data_type == DataType.RUNTIME:
                result = await self._enrich_runtime_behavioral_analysis(data)
            else:
                result = await self._enrich_contextual_analysis(data)
            
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                "data": result,
                "enriched_data": await self._apply_enrichment(data, result),
                "confidence": result.get("confidence", 0.7),
                "sources": ["enrichment_processor"],
                "metadata": {
                    "processing_time": processing_time,
                    "analysis_type": result.get("analysis_type", "general"),
                }
            }
            
        except Exception as e:
            self.logger.error("Error in enrichment processing", error=str(e))
            raise
    
    async def _enrich_sbom_vulnerability_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform vulnerability analysis on SBOM data."""
        analysis = {
            "analysis_type": "vulnerability_analysis",
            "vulnerability_summary": {},
            "component_risk_scores": {},
            "recommendations": [],
            "confidence": 0.8,
        }
        
        # Analyze components
        components = data.get("components", [])
        total_components = len(components)
        vulnerable_components = 0
        high_risk_components = 0
        
        component_risks = {}
        
        for component in components:
            component_name = component.get("name", "unknown")
            component_version = component.get("version", "unknown")
            
            # Calculate component risk score
            risk_score = await self._calculate_component_risk(component)
            component_risks[component_name] = risk_score
            
            if risk_score > 7.0:
                high_risk_components += 1
            
            # Check for vulnerabilities
            vulnerabilities = component.get("vulnerabilities", [])
            if vulnerabilities:
                vulnerable_components += 1
        
        # Generate vulnerability summary
        analysis["vulnerability_summary"] = {
            "total_components": total_components,
            "vulnerable_components": vulnerable_components,
            "high_risk_components": high_risk_components,
            "vulnerability_ratio": vulnerable_components / max(total_components, 1),
            "high_risk_ratio": high_risk_components / max(total_components, 1),
        }
        
        analysis["component_risk_scores"] = component_risks
        
        # Generate recommendations
        if vulnerable_components > 0:
            analysis["recommendations"].append(
                f"Update {vulnerable_components} vulnerable components to latest versions"
            )
        
        if high_risk_components > 0:
            analysis["recommendations"].append(
                f"Review and mitigate {high_risk_components} high-risk components"
            )
        
        if analysis["vulnerability_summary"]["vulnerability_ratio"] > 0.3:
            analysis["recommendations"].append(
                "Consider implementing automated vulnerability scanning in CI/CD pipeline"
            )
        
        return analysis
    
    async def _enrich_cve_vulnerability_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform detailed vulnerability analysis on CVE data."""
        analysis = {
            "analysis_type": "vulnerability_analysis",
            "vulnerability_assessment": {},
            "exploitation_risk": {},
            "remediation_priority": {},
            "recommendations": [],
            "confidence": 0.9,
        }
        
        # Extract CVE details
        cve_id = data.get("cve_id", "unknown")
        cvss_score = self._extract_cvss_score(data)
        severity = self._extract_severity(data)
        
        # Calculate exploitation risk
        exploitation_risk = await self._calculate_exploitation_risk(data)
        
        # Determine remediation priority
        remediation_priority = await self._calculate_remediation_priority(data, exploitation_risk)
        
        analysis["vulnerability_assessment"] = {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "severity": severity,
            "exploitability_score": exploitation_risk.get("exploitability_score", 0.0),
            "impact_score": exploitation_risk.get("impact_score", 0.0),
            "temporal_score": exploitation_risk.get("temporal_score", 0.0),
        }
        
        analysis["exploitation_risk"] = exploitation_risk
        analysis["remediation_priority"] = remediation_priority
        
        # Generate recommendations
        if cvss_score >= 9.0:
            analysis["recommendations"].append("CRITICAL: Apply patches immediately")
        elif cvss_score >= 7.0:
            analysis["recommendations"].append("HIGH: Apply patches within 24-48 hours")
        elif cvss_score >= 4.0:
            analysis["recommendations"].append("MEDIUM: Apply patches within 1 week")
        else:
            analysis["recommendations"].append("LOW: Apply patches during next maintenance window")
        
        if exploitation_risk.get("has_public_exploit", False):
            analysis["recommendations"].append("WARNING: Public exploits available - prioritize patching")
        
        return analysis
    
    async def _enrich_runtime_behavioral_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform behavioral analysis on runtime data."""
        analysis = {
            "analysis_type": "behavioral_analysis",
            "behavioral_indicators": {},
            "anomaly_analysis": {},
            "threat_assessment": {},
            "recommendations": [],
            "confidence": 0.7,
        }
        
        # Analyze events
        events = data.get("events", [])
        behavioral_indicators = await self._analyze_behavioral_patterns(events)
        
        # Analyze anomalies
        anomalies = data.get("anomalies", [])
        anomaly_analysis = await self._analyze_anomalies(anomalies)
        
        # Assess overall threat level
        threat_assessment = await self._assess_runtime_threat_level(
            behavioral_indicators, anomaly_analysis
        )
        
        analysis["behavioral_indicators"] = behavioral_indicators
        analysis["anomaly_analysis"] = anomaly_analysis
        analysis["threat_assessment"] = threat_assessment
        
        # Generate recommendations
        if threat_assessment.get("threat_level") == "high":
            analysis["recommendations"].append("ALERT: High threat activity detected - investigate immediately")
        elif threat_assessment.get("threat_level") == "medium":
            analysis["recommendations"].append("WARNING: Suspicious activity detected - monitor closely")
        
        if behavioral_indicators.get("suspicious_processes", 0) > 0:
            analysis["recommendations"].append("Review and validate suspicious process executions")
        
        if behavioral_indicators.get("network_anomalies", 0) > 0:
            analysis["recommendations"].append("Investigate unusual network connections")
        
        return analysis
    
    async def _enrich_contextual_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform general contextual analysis."""
        analysis = {
            "analysis_type": "contextual_analysis",
            "context_assessment": {},
            "risk_indicators": {},
            "recommendations": [],
            "confidence": 0.6,
        }
        
        # Analyze data structure and content
        context_assessment = await self._analyze_data_context(data)
        risk_indicators = await self._identify_risk_indicators(data)
        
        analysis["context_assessment"] = context_assessment
        analysis["risk_indicators"] = risk_indicators
        
        # Generate basic recommendations
        if risk_indicators.get("high_risk_elements", 0) > 0:
            analysis["recommendations"].append("Review high-risk elements identified in data")
        
        analysis["recommendations"].append("Continue monitoring for security-relevant changes")
        
        return analysis
    
    async def _calculate_component_risk(self, component: Dict[str, Any]) -> float:
        """Calculate risk score for a component."""
        risk_score = 0.0
        
        # Base risk from vulnerabilities
        vulnerabilities = component.get("vulnerabilities", [])
        if vulnerabilities:
            vuln_scores = []
            for vuln in vulnerabilities:
                cvss_score = self._extract_cvss_score(vuln)
                vuln_scores.append(cvss_score)
            
            if vuln_scores:
                risk_score += max(vuln_scores) * 0.6
        
        # Risk from component name
        component_name = component.get("name", "").lower()
        for high_risk_comp in self.risk_factors["high_risk_components"]:
            if high_risk_comp in component_name:
                risk_score += 2.0
                break
        
        # Risk from component type
        comp_type = component.get("type", "").lower()
        if comp_type in ["library", "framework", "application"]:
            risk_score += 1.0
        
        # Risk from license
        license_info = component.get("license", {})
        if isinstance(license_info, dict):
            license_name = license_info.get("name", "").lower()
            if "commercial" in license_name or "proprietary" in license_name:
                risk_score += 0.5
        
        return min(risk_score, 10.0)
    
    async def _calculate_exploitation_risk(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate exploitation risk for a CVE."""
        risk = {
            "exploitability_score": 0.0,
            "impact_score": 0.0,
            "temporal_score": 0.0,
            "has_public_exploit": False,
            "attack_vector": "unknown",
            "attack_complexity": "unknown",
        }
        
        # Extract CVSS metrics
        metrics = cve_data.get("metrics", {})
        
        # CVSS v3 metrics
        cvss_v3 = metrics.get("cvss_v3", {})
        if cvss_v3:
            risk["exploitability_score"] = cvss_v3.get("exploitabilityScore", 0.0)
            risk["impact_score"] = cvss_v3.get("impactScore", 0.0)
            risk["attack_vector"] = cvss_v3.get("attackVector", "unknown")
            risk["attack_complexity"] = cvss_v3.get("attackComplexity", "unknown")
        
        # Check for public exploits (mock implementation)
        references = cve_data.get("references", [])
        for ref in references:
            url = ref.get("url", "").lower()
            if any(exploit_indicator in url for exploit_indicator in 
                   ["exploit", "poc", "metasploit", "exploit-db"]):
                risk["has_public_exploit"] = True
                risk["temporal_score"] = 1.0
                break
        
        return risk
    
    async def _calculate_remediation_priority(
        self, 
        cve_data: Dict[str, Any], 
        exploitation_risk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate remediation priority."""
        priority = {
            "priority_score": 0.0,
            "priority_level": "low",
            "estimated_effort": "low",
            "business_impact": "low",
        }
        
        cvss_score = self._extract_cvss_score(cve_data)
        
        # Base priority from CVSS score
        priority["priority_score"] = cvss_score
        
        # Increase priority if public exploits exist
        if exploitation_risk.get("has_public_exploit", False):
            priority["priority_score"] += 2.0
        
        # Increase priority for network-based attacks
        if exploitation_risk.get("attack_vector") == "NETWORK":
            priority["priority_score"] += 1.0
        
        # Determine priority level
        if priority["priority_score"] >= 9.0:
            priority["priority_level"] = "critical"
            priority["estimated_effort"] = "high"
            priority["business_impact"] = "high"
        elif priority["priority_score"] >= 7.0:
            priority["priority_level"] = "high"
            priority["estimated_effort"] = "medium"
            priority["business_impact"] = "medium"
        elif priority["priority_score"] >= 4.0:
            priority["priority_level"] = "medium"
            priority["estimated_effort"] = "low"
            priority["business_impact"] = "low"
        else:
            priority["priority_level"] = "low"
            priority["estimated_effort"] = "low"
            priority["business_impact"] = "low"
        
        return priority
    
    async def _analyze_behavioral_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze behavioral patterns in runtime events."""
        indicators = {
            "suspicious_processes": 0,
            "network_anomalies": 0,
            "file_access_anomalies": 0,
            "privilege_escalations": 0,
            "suspicious_patterns": [],
        }
        
        for event in events:
            event_type = event.get("event_type", "")
            event_data = event.get("data", {})
            
            # Check for suspicious processes
            if event_type == "process_start":
                process_name = event_data.get("process_name", "")
                command_line = event_data.get("command_line", "")
                
                for pattern in self.suspicious_patterns["processes"]:
                    if re.search(pattern, process_name, re.IGNORECASE) or \
                       re.search(pattern, command_line, re.IGNORECASE):
                        indicators["suspicious_processes"] += 1
                        indicators["suspicious_patterns"].append({
                            "type": "suspicious_process",
                            "pattern": pattern,
                            "value": process_name or command_line,
                            "event_id": event.get("event_id"),
                        })
            
            # Check for network anomalies
            elif event_type == "network_connection":
                destination = event_data.get("destination_ip", "")
                domain = event_data.get("domain", "")
                
                for pattern in self.suspicious_patterns["network"]:
                    if re.search(pattern, destination, re.IGNORECASE) or \
                       re.search(pattern, domain, re.IGNORECASE):
                        indicators["network_anomalies"] += 1
                        indicators["suspicious_patterns"].append({
                            "type": "network_anomaly",
                            "pattern": pattern,
                            "value": destination or domain,
                            "event_id": event.get("event_id"),
                        })
            
            # Check for privilege escalations
            elif event_type == "privilege_change":
                old_privileges = event_data.get("old_privileges", [])
                new_privileges = event_data.get("new_privileges", [])
                
                if len(new_privileges) > len(old_privileges):
                    indicators["privilege_escalations"] += 1
                    indicators["suspicious_patterns"].append({
                        "type": "privilege_escalation",
                        "value": f"Privileges increased from {len(old_privileges)} to {len(new_privileges)}",
                        "event_id": event.get("event_id"),
                    })
        
        return indicators
    
    async def _analyze_anomalies(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze anomalies in the data."""
        analysis = {
            "total_anomalies": len(anomalies),
            "anomaly_types": defaultdict(int),
            "severity_distribution": defaultdict(int),
            "confidence_distribution": defaultdict(int),
            "high_confidence_anomalies": 0,
        }
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get("type", "unknown")
            severity = anomaly.get("severity", "unknown")
            confidence = anomaly.get("confidence", 0.0)
            
            analysis["anomaly_types"][anomaly_type] += 1
            analysis["severity_distribution"][severity] += 1
            
            # Categorize confidence
            if confidence >= 0.8:
                analysis["confidence_distribution"]["high"] += 1
                analysis["high_confidence_anomalies"] += 1
            elif confidence >= 0.6:
                analysis["confidence_distribution"]["medium"] += 1
            else:
                analysis["confidence_distribution"]["low"] += 1
        
        return dict(analysis)
    
    async def _assess_runtime_threat_level(
        self, 
        behavioral_indicators: Dict[str, Any], 
        anomaly_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess overall threat level for runtime data."""
        threat_score = 0.0
        
        # Score from behavioral indicators
        threat_score += behavioral_indicators.get("suspicious_processes", 0) * 2.0
        threat_score += behavioral_indicators.get("network_anomalies", 0) * 1.5
        threat_score += behavioral_indicators.get("privilege_escalations", 0) * 3.0
        
        # Score from anomalies
        threat_score += anomaly_analysis.get("high_confidence_anomalies", 0) * 2.0
        threat_score += anomaly_analysis.get("anomaly_types", {}).get("suspicious_process", 0) * 2.5
        
        # Determine threat level
        if threat_score >= 10.0:
            threat_level = "critical"
        elif threat_score >= 7.0:
            threat_level = "high"
        elif threat_score >= 4.0:
            threat_level = "medium"
        elif threat_score >= 2.0:
            threat_level = "low"
        else:
            threat_level = "minimal"
        
        return {
            "threat_score": threat_score,
            "threat_level": threat_level,
            "contributing_factors": {
                "behavioral_score": sum([
                    behavioral_indicators.get("suspicious_processes", 0) * 2.0,
                    behavioral_indicators.get("network_anomalies", 0) * 1.5,
                    behavioral_indicators.get("privilege_escalations", 0) * 3.0,
                ]),
                "anomaly_score": sum([
                    anomaly_analysis.get("high_confidence_anomalies", 0) * 2.0,
                    anomaly_analysis.get("anomaly_types", {}).get("suspicious_process", 0) * 2.5,
                ]),
            }
        }
    
    async def _analyze_data_context(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the context of the data."""
        context = {
            "data_size": len(str(data)),
            "field_count": len(data) if isinstance(data, dict) else 0,
            "nested_structures": 0,
            "array_fields": 0,
            "timestamp_fields": 0,
        }
        
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    context["nested_structures"] += 1
                
                if isinstance(value, list):
                    context["array_fields"] += 1
                
                if "time" in key.lower() or "date" in key.lower():
                    context["timestamp_fields"] += 1
        
        return context
    
    async def _identify_risk_indicators(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Identify risk indicators in the data."""
        indicators = {
            "high_risk_elements": 0,
            "sensitive_data_detected": 0,
            "security_relevant_fields": 0,
            "risk_patterns": [],
        }
        
        data_str = str(data).lower()
        
        # Check for sensitive data patterns
        for pattern in self.risk_factors["sensitive_data_patterns"]:
            if re.search(pattern, data_str):
                indicators["sensitive_data_detected"] += 1
                indicators["risk_patterns"].append({
                    "type": "sensitive_data",
                    "pattern": pattern,
                })
        
        # Check for high-risk components
        for component in self.risk_factors["high_risk_components"]:
            if component in data_str:
                indicators["high_risk_elements"] += 1
                indicators["risk_patterns"].append({
                    "type": "high_risk_component",
                    "component": component,
                })
        
        return indicators
    
    def _extract_cvss_score(self, data: Dict[str, Any]) -> float:
        """Extract CVSS score from data."""
        # Try direct cvss_score field
        if "cvss_score" in data:
            return float(data["cvss_score"])
        
        # Try CVSS v3 metrics
        metrics = data.get("metrics", {})
        cvss_v3 = metrics.get("cvss_v3", {})
        if cvss_v3.get("baseScore"):
            return float(cvss_v3["baseScore"])
        
        # Try CVSS v2 metrics
        cvss_v2 = metrics.get("cvss_v2", {})
        if cvss_v2.get("baseScore"):
            return float(cvss_v2["baseScore"])
        
        return 0.0
    
    def _extract_severity(self, data: Dict[str, Any]) -> str:
        """Extract severity from data."""
        # Try direct severity field
        if "severity" in data:
            return data["severity"].lower()
        
        # Try CVSS v3 severity
        metrics = data.get("metrics", {})
        cvss_v3 = metrics.get("cvss_v3", {})
        if cvss_v3.get("baseSeverity"):
            return cvss_v3["baseSeverity"].lower()
        
        # Derive from CVSS score
        cvss_score = self._extract_cvss_score(data)
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0.0:
            return "low"
        else:
            return "unknown"
    
    async def _apply_enrichment(
        self, 
        original_data: Dict[str, Any], 
        analysis_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply enrichment analysis to original data."""
        enriched_data = original_data.copy()
        
        # Add analysis results
        enriched_data["analysis"] = analysis_result
        
        # Add summary fields
        if "vulnerability_summary" in analysis_result:
            enriched_data["vulnerability_summary"] = analysis_result["vulnerability_summary"]
        
        if "threat_assessment" in analysis_result:
            enriched_data["threat_assessment"] = analysis_result["threat_assessment"]
        
        if "behavioral_indicators" in analysis_result:
            enriched_data["behavioral_indicators"] = analysis_result["behavioral_indicators"]
        
        # Add recommendations
        if analysis_result.get("recommendations"):
            enriched_data["recommendations"] = analysis_result["recommendations"]
        
        return enriched_data
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the enrichment processor."""
        health_status = {
            "service": "enrichment_processor",
            "status": "healthy" if self.is_running else "stopped",
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Check caching service
        try:
            cache_health = await self.caching_service.health_check()
            health_status["caching"] = cache_health
        except Exception as e:
            health_status["caching"] = {"status": "unhealthy", "error": str(e)}
        
        return health_status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enrichment processor statistics."""
        return {
            "service": "enrichment_processor",
            "is_running": self.is_running,
            "supported_analysis_types": [
                "vulnerability_analysis",
                "behavioral_analysis", 
                "contextual_analysis",
                "risk_assessment",
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }