"""
Security Data Resource

Provides access to security scan results, vulnerability data, and metrics.
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List
import uuid

import structlog

logger = structlog.get_logger(__name__)


class SecurityDataResource:
    """
    Security Data Resource for MCP
    
    Provides access to security scan results, SBOM data, compliance reports,
    and security metrics through MCP resource URIs.
    """
    
    def __init__(self):
        """Initialize the security data resource."""
        # In a real implementation, these would connect to actual databases
        self.scan_cache = {}
        self.vulnerability_cache = {}
        self.sbom_cache = {}
        self.compliance_cache = {}
        self.metrics_cache = {}
        
        # Initialize with some sample data
        self._initialize_sample_data()
    
    async def get_scan_data(self, uri: str) -> str:
        """
        Retrieve security scan data.
        
        Args:
            uri: Resource URI (e.g., 'security://scans/recent')
            
        Returns:
            JSON string containing scan data
        """
        try:
            if uri == "security://scans/recent":
                return await self._get_recent_scans()
            elif uri.startswith("security://scans/"):
                scan_id = uri.split("/")[-1]
                return await self._get_scan_by_id(scan_id)
            else:
                raise ValueError(f"Unknown scan resource URI: {uri}")
                
        except Exception as e:
            logger.error("Failed to retrieve scan data", uri=uri, error=str(e))
            return json.dumps({"error": f"Failed to retrieve scan data: {str(e)}"})
    
    async def get_vulnerability_data(self, uri: str) -> str:
        """
        Retrieve vulnerability data.
        
        Args:
            uri: Resource URI (e.g., 'security://vulnerabilities/critical')
            
        Returns:
            JSON string containing vulnerability data
        """
        try:
            if uri == "security://vulnerabilities/critical":
                return await self._get_critical_vulnerabilities()
            elif uri == "security://vulnerabilities/recent":
                return await self._get_recent_vulnerabilities()
            elif uri.startswith("security://vulnerabilities/"):
                vuln_id = uri.split("/")[-1]
                return await self._get_vulnerability_by_id(vuln_id)
            else:
                raise ValueError(f"Unknown vulnerability resource URI: {uri}")
                
        except Exception as e:
            logger.error("Failed to retrieve vulnerability data", uri=uri, error=str(e))
            return json.dumps({"error": f"Failed to retrieve vulnerability data: {str(e)}"})
    
    async def get_sbom_data(self, uri: str) -> str:
        """
        Retrieve SBOM data.
        
        Args:
            uri: Resource URI (e.g., 'security://sboms/latest')
            
        Returns:
            JSON string containing SBOM data
        """
        try:
            if uri == "security://sboms/latest":
                return await self._get_latest_sboms()
            elif uri.startswith("security://sboms/"):
                sbom_id = uri.split("/")[-1]
                return await self._get_sbom_by_id(sbom_id)
            else:
                raise ValueError(f"Unknown SBOM resource URI: {uri}")
                
        except Exception as e:
            logger.error("Failed to retrieve SBOM data", uri=uri, error=str(e))
            return json.dumps({"error": f"Failed to retrieve SBOM data: {str(e)}"})
    
    async def get_compliance_data(self, uri: str) -> str:
        """
        Retrieve compliance data.
        
        Args:
            uri: Resource URI (e.g., 'security://compliance/status')
            
        Returns:
            JSON string containing compliance data
        """
        try:
            if uri == "security://compliance/status":
                return await self._get_compliance_status()
            elif uri.startswith("security://compliance/"):
                framework = uri.split("/")[-1]
                return await self._get_compliance_by_framework(framework)
            else:
                raise ValueError(f"Unknown compliance resource URI: {uri}")
                
        except Exception as e:
            logger.error("Failed to retrieve compliance data", uri=uri, error=str(e))
            return json.dumps({"error": f"Failed to retrieve compliance data: {str(e)}"})
    
    async def get_metrics_data(self, uri: str) -> str:
        """
        Retrieve security metrics data.
        
        Args:
            uri: Resource URI (e.g., 'security://metrics/dashboard')
            
        Returns:
            JSON string containing metrics data
        """
        try:
            if uri == "security://metrics/dashboard":
                return await self._get_dashboard_metrics()
            elif uri == "security://metrics/trends":
                return await self._get_trend_metrics()
            elif uri.startswith("security://metrics/"):
                metric_type = uri.split("/")[-1]
                return await self._get_metrics_by_type(metric_type)
            else:
                raise ValueError(f"Unknown metrics resource URI: {uri}")
                
        except Exception as e:
            logger.error("Failed to retrieve metrics data", uri=uri, error=str(e))
            return json.dumps({"error": f"Failed to retrieve metrics data: {str(e)}"})
    
    async def _get_recent_scans(self) -> str:
        """Get recent security scans."""
        recent_scans = list(self.scan_cache.values())[-20:]  # Last 20 scans
        
        return json.dumps({
            "resource": "recent_scans",
            "timestamp": datetime.utcnow().isoformat(),
            "total_scans": len(recent_scans),
            "scans": [
                {
                    "scan_id": scan["scan_id"],
                    "target": scan["image"],
                    "scanner": scan["scanner"],
                    "status": scan["status"],
                    "scan_start": scan["scan_start"],
                    "duration_seconds": scan.get("duration_seconds", 0),
                    "vulnerability_count": len(scan.get("vulnerabilities", [])),
                    "critical_count": len([v for v in scan.get("vulnerabilities", []) 
                                         if v.get("severity", "").lower() == "critical"]),
                    "high_count": len([v for v in scan.get("vulnerabilities", []) 
                                     if v.get("severity", "").lower() == "high"])
                }
                for scan in recent_scans
            ]
        }, indent=2)
    
    async def _get_scan_by_id(self, scan_id: str) -> str:
        """Get specific scan by ID."""
        if scan_id in self.scan_cache:
            return json.dumps(self.scan_cache[scan_id], indent=2)
        else:
            return json.dumps({"error": f"Scan not found: {scan_id}"})
    
    async def _get_critical_vulnerabilities(self) -> str:
        """Get critical severity vulnerabilities."""
        critical_vulns = []
        
        # Collect critical vulnerabilities from all scans
        for scan in self.scan_cache.values():
            for vuln in scan.get("vulnerabilities", []):
                if vuln.get("severity", "").lower() == "critical":
                    critical_vulns.append({
                        "scan_id": scan["scan_id"],
                        "target": scan["image"],
                        "cve_id": vuln.get("cve_id", ""),
                        "severity": vuln.get("severity", ""),
                        "description": vuln.get("description", ""),
                        "package_name": vuln.get("package_name", ""),
                        "package_version": vuln.get("package_version", ""),
                        "cvss_score": vuln.get("cvss_score"),
                        "fix_versions": vuln.get("fix_versions", []),
                        "scan_date": scan["scan_start"]
                    })
        
        return json.dumps({
            "resource": "critical_vulnerabilities",
            "timestamp": datetime.utcnow().isoformat(),
            "total_critical": len(critical_vulns),
            "vulnerabilities": critical_vulns
        }, indent=2)
    
    async def _get_recent_vulnerabilities(self) -> str:
        """Get recently discovered vulnerabilities."""
        recent_vulns = []
        
        # Get vulnerabilities from recent scans
        recent_scans = sorted(self.scan_cache.values(), 
                            key=lambda x: x.get("scan_start", ""), reverse=True)[:10]
        
        for scan in recent_scans:
            for vuln in scan.get("vulnerabilities", []):
                recent_vulns.append({
                    "scan_id": scan["scan_id"],
                    "target": scan["image"],
                    "cve_id": vuln.get("cve_id", ""),
                    "severity": vuln.get("severity", ""),
                    "package_name": vuln.get("package_name", ""),
                    "scan_date": scan["scan_start"]
                })
        
        return json.dumps({
            "resource": "recent_vulnerabilities",
            "timestamp": datetime.utcnow().isoformat(),
            "total_recent": len(recent_vulns),
            "vulnerabilities": recent_vulns[-50:]  # Last 50
        }, indent=2)
    
    async def _get_vulnerability_by_id(self, vuln_id: str) -> str:
        """Get specific vulnerability by ID."""
        # Search through all scans for the vulnerability
        for scan in self.scan_cache.values():
            for vuln in scan.get("vulnerabilities", []):
                if vuln.get("cve_id") == vuln_id:
                    return json.dumps({
                        "resource": f"vulnerability_{vuln_id}",
                        "vulnerability": vuln,
                        "scan_context": {
                            "scan_id": scan["scan_id"],
                            "target": scan["image"],
                            "scan_date": scan["scan_start"]
                        }
                    }, indent=2)
        
        return json.dumps({"error": f"Vulnerability not found: {vuln_id}"})
    
    async def _get_latest_sboms(self) -> str:
        """Get latest SBOM data."""
        latest_sboms = list(self.sbom_cache.values())[-10:]  # Last 10 SBOMs
        
        return json.dumps({
            "resource": "latest_sboms",
            "timestamp": datetime.utcnow().isoformat(),
            "total_sboms": len(latest_sboms),
            "sboms": [
                {
                    "sbom_id": sbom["sbom_id"],
                    "target": sbom["target"],
                    "format": sbom["format"],
                    "generation_date": sbom["generation_start"],
                    "component_count": len(sbom.get("components", [])),
                    "duration_seconds": sbom.get("duration_seconds", 0)
                }
                for sbom in latest_sboms
            ]
        }, indent=2)
    
    async def _get_sbom_by_id(self, sbom_id: str) -> str:
        """Get specific SBOM by ID."""
        if sbom_id in self.sbom_cache:
            return json.dumps(self.sbom_cache[sbom_id], indent=2)
        else:
            return json.dumps({"error": f"SBOM not found: {sbom_id}"})
    
    async def _get_compliance_status(self) -> str:
        """Get overall compliance status."""
        compliance_summary = {
            "resource": "compliance_status",
            "timestamp": datetime.utcnow().isoformat(),
            "frameworks": {}
        }
        
        # Aggregate compliance data by framework
        for compliance in self.compliance_cache.values():
            framework = compliance.get("framework", "unknown")
            if framework not in compliance_summary["frameworks"]:
                compliance_summary["frameworks"][framework] = {
                    "assessments": 0,
                    "latest_score": 0,
                    "trend": "stable"
                }
            
            compliance_summary["frameworks"][framework]["assessments"] += 1
            summary = compliance.get("summary", {})
            if "compliance_score" in summary:
                compliance_summary["frameworks"][framework]["latest_score"] = summary["compliance_score"]
        
        return json.dumps(compliance_summary, indent=2)
    
    async def _get_compliance_by_framework(self, framework: str) -> str:
        """Get compliance data for specific framework."""
        framework_data = []
        
        for compliance in self.compliance_cache.values():
            if compliance.get("framework", "").lower() == framework.lower():
                framework_data.append(compliance)
        
        return json.dumps({
            "resource": f"compliance_{framework}",
            "timestamp": datetime.utcnow().isoformat(),
            "framework": framework,
            "assessments": framework_data
        }, indent=2)
    
    async def _get_dashboard_metrics(self) -> str:
        """Get dashboard metrics."""
        # Calculate metrics from cached data
        total_scans = len(self.scan_cache)
        total_vulnerabilities = sum(len(scan.get("vulnerabilities", [])) 
                                  for scan in self.scan_cache.values())
        
        critical_vulns = sum(len([v for v in scan.get("vulnerabilities", []) 
                                if v.get("severity", "").lower() == "critical"])
                           for scan in self.scan_cache.values())
        
        high_vulns = sum(len([v for v in scan.get("vulnerabilities", []) 
                            if v.get("severity", "").lower() == "high"])
                       for scan in self.scan_cache.values())
        
        return json.dumps({
            "resource": "dashboard_metrics",
            "timestamp": datetime.utcnow().isoformat(),
            "overview": {
                "total_scans": total_scans,
                "total_vulnerabilities": total_vulnerabilities,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "total_sboms": len(self.sbom_cache),
                "compliance_assessments": len(self.compliance_cache)
            },
            "severity_distribution": {
                "critical": critical_vulns,
                "high": high_vulns,
                "medium": total_vulnerabilities - critical_vulns - high_vulns,
                "low": 0,
                "negligible": 0
            },
            "scan_activity": {
                "scans_last_24h": self._count_recent_scans(hours=24),
                "scans_last_week": self._count_recent_scans(hours=168),
                "scans_last_month": self._count_recent_scans(hours=720)
            }
        }, indent=2)
    
    async def _get_trend_metrics(self) -> str:
        """Get trend metrics."""
        return json.dumps({
            "resource": "trend_metrics",
            "timestamp": datetime.utcnow().isoformat(),
            "vulnerability_trends": {
                "daily_new_vulnerabilities": [5, 8, 3, 12, 7, 9, 4],
                "weekly_scan_volume": [45, 52, 38, 61, 47],
                "monthly_compliance_scores": [78, 82, 85, 88, 91]
            },
            "risk_trends": {
                "risk_score_trend": [6.5, 6.2, 5.8, 5.9, 5.4],
                "critical_vulnerability_trend": [12, 8, 5, 7, 3],
                "remediation_rate": [65, 72, 78, 81, 85]
            }
        }, indent=2)
    
    async def _get_metrics_by_type(self, metric_type: str) -> str:
        """Get specific metrics by type."""
        if metric_type == "performance":
            return json.dumps({
                "resource": f"metrics_{metric_type}",
                "scan_performance": {
                    "average_scan_duration": 125.5,
                    "fastest_scan": 45.2,
                    "slowest_scan": 380.7,
                    "scans_per_hour": 12.3
                },
                "system_performance": {
                    "cpu_usage": 65.2,
                    "memory_usage": 78.9,
                    "storage_usage": 45.1
                }
            }, indent=2)
        else:
            return json.dumps({
                "error": f"Unknown metric type: {metric_type}"
            })
    
    def _count_recent_scans(self, hours: int) -> int:
        """Count scans within the last N hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        count = 0
        
        for scan in self.scan_cache.values():
            try:
                scan_time = datetime.fromisoformat(scan["scan_start"].replace("Z", "+00:00"))
                if scan_time.replace(tzinfo=None) >= cutoff:
                    count += 1
            except (ValueError, KeyError):
                continue
        
        return count
    
    def _initialize_sample_data(self):
        """Initialize with sample data for demonstration."""
        # Sample scan data
        sample_scan_id = str(uuid.uuid4())
        self.scan_cache[sample_scan_id] = {
            "scan_id": sample_scan_id,
            "image": "redis:8.0.3",
            "scanner": "grype",
            "status": "completed",
            "scan_start": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
            "scan_end": (datetime.utcnow() - timedelta(hours=2, minutes=-15)).isoformat(),
            "duration_seconds": 125.3,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2023-1234",
                    "severity": "critical",
                    "description": "Buffer overflow in Redis command processing",
                    "package_name": "redis",
                    "package_version": "8.0.3",
                    "cvss_score": 9.1,
                    "fix_versions": ["8.0.4"]
                },
                {
                    "cve_id": "CVE-2023-5678",
                    "severity": "high",
                    "description": "Authentication bypass vulnerability",
                    "package_name": "redis",
                    "package_version": "8.0.3",
                    "cvss_score": 7.8,
                    "fix_versions": ["8.0.4"]
                }
            ]
        }
        
        # Sample SBOM data
        sample_sbom_id = str(uuid.uuid4())
        self.sbom_cache[sample_sbom_id] = {
            "sbom_id": sample_sbom_id,
            "target": "redis:8.0.3",
            "format": "spdx",
            "generation_start": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            "generation_end": (datetime.utcnow() - timedelta(hours=1, minutes=-5)).isoformat(),
            "duration_seconds": 67.2,
            "components": [
                {"name": "redis", "version": "8.0.3", "type": "library"},
                {"name": "openssl", "version": "1.1.1", "type": "library"}
            ]
        }
        
        # Sample compliance data
        sample_compliance_id = str(uuid.uuid4())
        self.compliance_cache[sample_compliance_id] = {
            "analysis_id": sample_compliance_id,
            "framework": "cis",
            "target": "kubernetes-cluster",
            "status": "completed",
            "analysis_start": (datetime.utcnow() - timedelta(hours=3)).isoformat(),
            "summary": {
                "compliance_score": 85.5,
                "total_controls": 20,
                "passed_controls": 17,
                "failed_controls": 3
            }
        }