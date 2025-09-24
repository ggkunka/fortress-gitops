"""
Security Scanner Tool

Implements vulnerability scanning and SBOM generation using existing scanner plugins.
"""

import asyncio
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

import structlog

logger = structlog.get_logger(__name__)


class SecurityScannerTool:
    """
    Security Scanner Tool for MCP
    
    Provides vulnerability scanning and SBOM generation capabilities
    using existing scanner implementations (Grype, Trivy, Syft).
    """
    
    def __init__(self):
        """Initialize the security scanner tool."""
        self.scan_cache = {}
        self.temp_dir = Path(tempfile.gettempdir()) / "mcp-security-scans"
        self.temp_dir.mkdir(exist_ok=True)
        
    async def scan_vulnerabilities(
        self, 
        image: str, 
        scanner: str = "grype", 
        format: str = "json"
    ) -> Dict[str, Any]:
        """
        Scan container image for vulnerabilities.
        
        Args:
            image: Container image to scan
            scanner: Scanner to use (grype, trivy, syft)
            format: Output format (json, table, sarif)
            
        Returns:
            Scan results with vulnerabilities
        """
        scan_id = str(uuid.uuid4())
        logger.info("Starting vulnerability scan", scan_id=scan_id, image=image, scanner=scanner)
        
        try:
            # Generate scan timestamp
            scan_start = datetime.utcnow()
            
            # Execute scanner based on type
            if scanner == "grype":
                scan_result = await self._run_grype_scan(image, format)
            elif scanner == "trivy":
                scan_result = await self._run_trivy_scan(image, format)
            elif scanner == "syft":
                # Syft is primarily for SBOM, but can detect packages for vulnerability context
                scan_result = await self._run_syft_scan(image, format)
            else:
                raise ValueError(f"Unsupported scanner: {scanner}")
            
            scan_end = datetime.utcnow()
            duration = (scan_end - scan_start).total_seconds()
            
            # Process and structure results
            processed_result = {
                "scan_id": scan_id,
                "image": image,
                "scanner": scanner,
                "format": format,
                "scan_start": scan_start.isoformat(),
                "scan_end": scan_end.isoformat(),
                "duration_seconds": duration,
                "status": "completed",
                "raw_output": scan_result,
                "summary": self._generate_scan_summary(scan_result, scanner),
                "vulnerabilities": self._extract_vulnerabilities(scan_result, scanner)
            }
            
            # Cache results
            self.scan_cache[scan_id] = processed_result
            
            logger.info("Vulnerability scan completed", scan_id=scan_id, duration=duration)
            return processed_result
            
        except Exception as e:
            logger.error("Vulnerability scan failed", scan_id=scan_id, error=str(e))
            return {
                "scan_id": scan_id,
                "image": image,
                "scanner": scanner,
                "status": "failed",
                "error": str(e),
                "scan_start": scan_start.isoformat() if 'scan_start' in locals() else None
            }
    
    async def generate_sbom(
        self, 
        target: str, 
        format: str = "spdx", 
        output: str = "json"
    ) -> Dict[str, Any]:
        """
        Generate Software Bill of Materials (SBOM).
        
        Args:
            target: Target to analyze (image, directory, file)
            format: SBOM format (spdx, cyclonedx, syft)
            output: Output format (json, xml, yaml)
            
        Returns:
            SBOM data and metadata
        """
        sbom_id = str(uuid.uuid4())
        logger.info("Starting SBOM generation", sbom_id=sbom_id, target=target, format=format)
        
        try:
            generation_start = datetime.utcnow()
            
            # Use Syft for SBOM generation
            sbom_result = await self._run_syft_sbom(target, format, output)
            
            generation_end = datetime.utcnow()
            duration = (generation_end - generation_start).total_seconds()
            
            # Process SBOM results
            processed_result = {
                "sbom_id": sbom_id,
                "target": target,
                "format": format,
                "output_format": output,
                "generation_start": generation_start.isoformat(),
                "generation_end": generation_end.isoformat(),
                "duration_seconds": duration,
                "status": "completed",
                "sbom_data": sbom_result,
                "summary": self._generate_sbom_summary(sbom_result, format),
                "components": self._extract_components(sbom_result, format)
            }
            
            logger.info("SBOM generation completed", sbom_id=sbom_id, duration=duration)
            return processed_result
            
        except Exception as e:
            logger.error("SBOM generation failed", sbom_id=sbom_id, error=str(e))
            return {
                "sbom_id": sbom_id,
                "target": target,
                "format": format,
                "status": "failed",
                "error": str(e),
                "generation_start": generation_start.isoformat() if 'generation_start' in locals() else None
            }
    
    async def _run_grype_scan(self, image: str, format: str) -> Dict[str, Any]:
        """Run Grype vulnerability scanner."""
        cmd = ["grype", image, "-o", format]
        
        logger.debug("Running Grype command", cmd=cmd)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Grype scan failed: {stderr.decode()}")
        
        if format == "json":
            return json.loads(stdout.decode())
        else:
            return {"output": stdout.decode(), "format": format}
    
    async def _run_trivy_scan(self, image: str, format: str) -> Dict[str, Any]:
        """Run Trivy vulnerability scanner."""
        cmd = ["trivy", "image", "--format", format, image]
        
        if format == "json":
            cmd.extend(["--format", "json"])
        
        logger.debug("Running Trivy command", cmd=cmd)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Trivy scan failed: {stderr.decode()}")
        
        if format == "json":
            return json.loads(stdout.decode())
        else:
            return {"output": stdout.decode(), "format": format}
    
    async def _run_syft_scan(self, image: str, format: str) -> Dict[str, Any]:
        """Run Syft for package discovery (vulnerability context)."""
        cmd = ["syft", image, "-o", format]
        
        logger.debug("Running Syft command", cmd=cmd)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Syft scan failed: {stderr.decode()}")
        
        if format == "json":
            return json.loads(stdout.decode())
        else:
            return {"output": stdout.decode(), "format": format}
    
    async def _run_syft_sbom(self, target: str, format: str, output: str) -> Dict[str, Any]:
        """Generate SBOM using Syft."""
        # Map format to Syft output format
        format_mapping = {
            "spdx": f"spdx-{output}",
            "cyclonedx": f"cyclonedx-{output}",
            "syft": f"syft-{output}"
        }
        
        syft_format = format_mapping.get(format, f"spdx-{output}")
        cmd = ["syft", target, "-o", syft_format]
        
        logger.debug("Running Syft SBOM command", cmd=cmd)
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Syft SBOM generation failed: {stderr.decode()}")
        
        if output == "json":
            return json.loads(stdout.decode())
        else:
            return {"output": stdout.decode(), "format": output}
    
    def _generate_scan_summary(self, scan_result: Dict[str, Any], scanner: str) -> Dict[str, Any]:
        """Generate summary from scan results."""
        summary = {
            "total_vulnerabilities": 0,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "negligible": 0,
                "unknown": 0
            },
            "scanner": scanner
        }
        
        try:
            if scanner == "grype" and "matches" in scan_result:
                vulnerabilities = scan_result["matches"]
                summary["total_vulnerabilities"] = len(vulnerabilities)
                
                for vuln in vulnerabilities:
                    severity = vuln.get("vulnerability", {}).get("severity", "unknown").lower()
                    if severity in summary["severity_counts"]:
                        summary["severity_counts"][severity] += 1
                        
            elif scanner == "trivy" and "Results" in scan_result:
                for result in scan_result["Results"]:
                    if "Vulnerabilities" in result:
                        vulnerabilities = result["Vulnerabilities"]
                        summary["total_vulnerabilities"] += len(vulnerabilities)
                        
                        for vuln in vulnerabilities:
                            severity = vuln.get("Severity", "unknown").lower()
                            if severity in summary["severity_counts"]:
                                summary["severity_counts"][severity] += 1
                                
        except Exception as e:
            logger.warning("Failed to generate scan summary", error=str(e))
            summary["error"] = f"Summary generation failed: {str(e)}"
        
        return summary
    
    def _extract_vulnerabilities(self, scan_result: Dict[str, Any], scanner: str) -> List[Dict[str, Any]]:
        """Extract structured vulnerability data."""
        vulnerabilities = []
        
        try:
            if scanner == "grype" and "matches" in scan_result:
                for match in scan_result["matches"]:
                    vuln = match.get("vulnerability", {})
                    artifact = match.get("artifact", {})
                    
                    vulnerabilities.append({
                        "cve_id": vuln.get("id", ""),
                        "severity": vuln.get("severity", "unknown"),
                        "description": vuln.get("description", ""),
                        "package_name": artifact.get("name", ""),
                        "package_version": artifact.get("version", ""),
                        "package_type": artifact.get("type", ""),
                        "fix_versions": vuln.get("fix", {}).get("versions", []),
                        "urls": vuln.get("urls", []),
                        "cvss_score": vuln.get("cvss", [{}])[0].get("metrics", {}).get("baseScore") if vuln.get("cvss") else None
                    })
                    
            elif scanner == "trivy" and "Results" in scan_result:
                for result in scan_result["Results"]:
                    if "Vulnerabilities" in result:
                        for vuln in result["Vulnerabilities"]:
                            vulnerabilities.append({
                                "cve_id": vuln.get("VulnerabilityID", ""),
                                "severity": vuln.get("Severity", "unknown"),
                                "description": vuln.get("Description", ""),
                                "package_name": vuln.get("PkgName", ""),
                                "package_version": vuln.get("InstalledVersion", ""),
                                "fix_versions": [vuln.get("FixedVersion", "")] if vuln.get("FixedVersion") else [],
                                "urls": [vuln.get("PrimaryURL", "")] if vuln.get("PrimaryURL") else [],
                                "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score") if vuln.get("CVSS") else None
                            })
                            
        except Exception as e:
            logger.warning("Failed to extract vulnerabilities", error=str(e))
        
        return vulnerabilities
    
    def _generate_sbom_summary(self, sbom_result: Dict[str, Any], format: str) -> Dict[str, Any]:
        """Generate summary from SBOM results."""
        summary = {
            "total_components": 0,
            "component_types": {},
            "format": format
        }
        
        try:
            if format == "syft" and "artifacts" in sbom_result:
                artifacts = sbom_result["artifacts"]
                summary["total_components"] = len(artifacts)
                
                for artifact in artifacts:
                    component_type = artifact.get("type", "unknown")
                    summary["component_types"][component_type] = summary["component_types"].get(component_type, 0) + 1
                    
        except Exception as e:
            logger.warning("Failed to generate SBOM summary", error=str(e))
            summary["error"] = f"Summary generation failed: {str(e)}"
        
        return summary
    
    def _extract_components(self, sbom_result: Dict[str, Any], format: str) -> List[Dict[str, Any]]:
        """Extract structured component data from SBOM."""
        components = []
        
        try:
            if format == "syft" and "artifacts" in sbom_result:
                for artifact in sbom_result["artifacts"]:
                    components.append({
                        "name": artifact.get("name", ""),
                        "version": artifact.get("version", ""),
                        "type": artifact.get("type", ""),
                        "language": artifact.get("language", ""),
                        "locations": [loc.get("path", "") for loc in artifact.get("locations", [])],
                        "licenses": artifact.get("licenses", []),
                        "cpes": artifact.get("cpes", []),
                        "purl": artifact.get("purl", "")
                    })
                    
        except Exception as e:
            logger.warning("Failed to extract components", error=str(e))
        
        return components