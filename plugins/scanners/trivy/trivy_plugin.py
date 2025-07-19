"""
Trivy Scanner Plugin - Vulnerability and misconfiguration scanning

This plugin integrates Aqua Security's Trivy scanner for comprehensive
vulnerability scanning of containers, filesystems, and infrastructure.
"""

import asyncio
import json
import tempfile
import os
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from pathlib import Path

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.plugins.base import BaseScannerPlugin, ScanResult, ScannerConfig

logger = get_logger(__name__)
metrics = get_metrics()


class TrivyConfig(ScannerConfig):
    """Trivy scanner configuration."""
    trivy_binary_path: str = "/usr/local/bin/trivy"
    cache_dir: str = "/tmp/trivy-cache"
    timeout_seconds: int = 600
    
    # Scanning options
    scan_types: List[str] = ["vuln", "secret", "misconfig"]
    severity_levels: List[str] = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    ignore_unfixed: bool = False
    skip_db_update: bool = False
    
    # Output options
    format: str = "json"
    template: Optional[str] = None
    
    # Database options
    offline_scan: bool = False
    skip_java_db_update: bool = False
    
    # Security options
    ignore_policy: Optional[str] = None
    policy_namespaces: List[str] = []


class TrivyPlugin(BaseScannerPlugin):
    """
    Trivy vulnerability scanner plugin.
    
    Supports scanning:
    - Container images
    - Filesystem directories
    - Git repositories
    - Kubernetes configurations
    - Docker files
    - Terraform configurations
    """
    
    def __init__(self, config: TrivyConfig):
        super().__init__(config)
        self.config = config
        self.name = "trivy"
        self.version = "0.48.0"
        self.description = "Comprehensive vulnerability scanner for containers and infrastructure"
        
        # Supported scan targets
        self.supported_targets = [
            "image",
            "filesystem", 
            "repository",
            "kubernetes",
            "sbom",
            "config"
        ]
        
        logger.info("Trivy plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the Trivy plugin."""
        try:
            # Verify Trivy binary exists
            if not os.path.exists(self.config.trivy_binary_path):
                logger.error(f"Trivy binary not found at: {self.config.trivy_binary_path}")
                return False
            
            # Create cache directory
            os.makedirs(self.config.cache_dir, exist_ok=True)
            
            # Check Trivy version
            version_result = await self._run_trivy_command(["version", "--format", "json"])
            if version_result.returncode != 0:
                logger.error("Failed to get Trivy version")
                return False
            
            version_info = json.loads(version_result.stdout)
            self.version = version_info.get("Version", "unknown")
            
            # Update vulnerability database unless skipped
            if not self.config.skip_db_update:
                await self._update_database()
            
            logger.info(f"Trivy plugin initialized successfully (version: {self.version})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Trivy plugin: {e}")
            return False
    
    @traced("trivy_plugin_scan")
    async def scan(
        self, 
        target: str, 
        scan_type: str = "image",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Perform a Trivy scan."""
        try:
            start_time = datetime.now(timezone.utc)
            options = options or {}
            
            # Validate scan type
            if scan_type not in self.supported_targets:
                raise ValueError(f"Unsupported scan type: {scan_type}. Supported: {self.supported_targets}")
            
            # Build Trivy command
            command = await self._build_scan_command(target, scan_type, options)
            
            # Execute scan
            logger.info(f"Starting Trivy scan: {scan_type} on {target}")
            result = await self._run_trivy_command(command)
            
            # Parse results
            scan_result = await self._parse_scan_results(result, target, scan_type, start_time)
            
            # Record metrics
            metrics.trivy_scans_completed.inc()
            metrics.trivy_vulnerabilities_found.inc(scan_result.vulnerability_count)
            
            logger.info(f"Trivy scan completed: {scan_result.vulnerability_count} vulnerabilities found")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
            metrics.trivy_scan_errors.inc()
            
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self.version,
                target=target,
                scan_type=scan_type,
                status="failed",
                error_message=str(e),
                started_at=start_time,
                completed_at=datetime.now(timezone.utc)
            )
    
    async def scan_image(self, image: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a container image."""
        return await self.scan(image, "image", options)
    
    async def scan_filesystem(self, path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a filesystem directory."""
        return await self.scan(path, "filesystem", options)
    
    async def scan_repository(self, repo_url: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a Git repository."""
        return await self.scan(repo_url, "repository", options)
    
    async def scan_kubernetes(self, manifest_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan Kubernetes configurations."""
        return await self.scan(manifest_path, "kubernetes", options)
    
    async def scan_sbom(self, sbom_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan an SBOM file."""
        return await self.scan(sbom_path, "sbom", options)
    
    async def scan_config(self, config_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan infrastructure configurations (Terraform, CloudFormation, etc.)."""
        return await self.scan(config_path, "config", options)
    
    async def get_vulnerability_details(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific vulnerability."""
        try:
            # Trivy doesn't have a direct command for this, but we can search the database
            command = ["image", "--format", "json", "--vuln-type", "os,library", "alpine:latest"]
            result = await self._run_trivy_command(command)
            
            if result.returncode == 0:
                scan_data = json.loads(result.stdout)
                # Search for the vulnerability in the results
                for result_item in scan_data.get("Results", []):
                    for vuln in result_item.get("Vulnerabilities", []):
                        if vuln.get("VulnerabilityID") == vulnerability_id:
                            return vuln
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability details: {e}")
            return None
    
    async def update_database(self) -> bool:
        """Update Trivy vulnerability database."""
        try:
            await self._update_database()
            return True
        except Exception as e:
            logger.error(f"Failed to update Trivy database: {e}")
            return False
    
    async def _build_scan_command(
        self, 
        target: str, 
        scan_type: str, 
        options: Dict[str, Any]
    ) -> List[str]:
        """Build Trivy command for scanning."""
        command = [scan_type]
        
        # Add format
        command.extend(["--format", self.config.format])
        
        # Add scan types
        if self.config.scan_types:
            for scan_t in self.config.scan_types:
                if scan_t in ["vuln", "secret", "misconfig"]:
                    command.extend([f"--scanners", scan_t])
        
        # Add severity filter
        if self.config.severity_levels:
            severity_str = ",".join(self.config.severity_levels)
            command.extend(["--severity", severity_str])
        
        # Add cache directory
        command.extend(["--cache-dir", self.config.cache_dir])
        
        # Add timeout
        command.extend(["--timeout", f"{self.config.timeout_seconds}s"])
        
        # Skip database update if configured
        if self.config.skip_db_update:
            command.append("--skip-db-update")
        
        # Ignore unfixed vulnerabilities
        if self.config.ignore_unfixed:
            command.append("--ignore-unfixed")
        
        # Add offline mode
        if self.config.offline_scan:
            command.append("--offline-scan")
        
        # Add ignore policy
        if self.config.ignore_policy:
            command.extend(["--ignorefile", self.config.ignore_policy])
        
        # Add custom options from parameters
        for key, value in options.items():
            if key == "output_file":
                command.extend(["--output", value])
            elif key == "exit_code":
                command.extend(["--exit-code", str(value)])
            elif key == "vuln_type":
                command.extend(["--vuln-type", value])
            elif key == "security_checks":
                command.extend(["--security-checks", value])
            elif key == "compliance":
                command.extend(["--compliance", value])
        
        # Add target
        command.append(target)
        
        return command
    
    async def _run_trivy_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a Trivy command."""
        try:
            full_command = [self.config.trivy_binary_path] + command
            
            logger.debug(f"Running Trivy command: {' '.join(full_command)}")
            
            # Run command with timeout
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.cache_dir
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout_seconds
                )
                
                return subprocess.CompletedProcess(
                    args=full_command,
                    returncode=process.returncode,
                    stdout=stdout.decode('utf-8'),
                    stderr=stderr.decode('utf-8')
                )
                
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError(f"Trivy command timed out after {self.config.timeout_seconds} seconds")
                
        except Exception as e:
            logger.error(f"Failed to run Trivy command: {e}")
            raise
    
    async def _parse_scan_results(
        self, 
        result: subprocess.CompletedProcess, 
        target: str, 
        scan_type: str,
        start_time: datetime
    ) -> ScanResult:
        """Parse Trivy scan results."""
        try:
            if result.returncode != 0:
                return ScanResult(
                    scanner_name=self.name,
                    scanner_version=self.version,
                    target=target,
                    scan_type=scan_type,
                    status="failed",
                    error_message=result.stderr,
                    started_at=start_time,
                    completed_at=datetime.now(timezone.utc)
                )
            
            # Parse JSON output
            scan_data = json.loads(result.stdout) if result.stdout else {}
            
            # Extract vulnerabilities
            vulnerabilities = []
            secrets = []
            misconfigurations = []
            
            for result_item in scan_data.get("Results", []):
                # Process vulnerabilities
                for vuln in result_item.get("Vulnerabilities", []):
                    vulnerabilities.append({
                        "id": vuln.get("VulnerabilityID"),
                        "title": vuln.get("Title"),
                        "description": vuln.get("Description"),
                        "severity": vuln.get("Severity"),
                        "cvss_score": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                        "package_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "references": vuln.get("References", []),
                        "published_date": vuln.get("PublishedDate"),
                        "last_modified_date": vuln.get("LastModifiedDate")
                    })
                
                # Process secrets
                for secret in result_item.get("Secrets", []):
                    secrets.append({
                        "type": secret.get("RuleID"),
                        "title": secret.get("Title"),
                        "severity": secret.get("Severity", "HIGH"),
                        "file": secret.get("StartLine"),
                        "line": secret.get("EndLine"),
                        "match": secret.get("Match")
                    })
                
                # Process misconfigurations
                for misconfig in result_item.get("Misconfigurations", []):
                    misconfigurations.append({
                        "id": misconfig.get("ID"),
                        "title": misconfig.get("Title"),
                        "description": misconfig.get("Description"),
                        "severity": misconfig.get("Severity"),
                        "message": misconfig.get("Message"),
                        "namespace": misconfig.get("Namespace"),
                        "query": misconfig.get("Query"),
                        "resolution": misconfig.get("Resolution"),
                        "references": misconfig.get("References", [])
                    })
            
            # Create scan result
            scan_result = ScanResult(
                scanner_name=self.name,
                scanner_version=self.version,
                target=target,
                scan_type=scan_type,
                status="completed",
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                vulnerability_count=len(vulnerabilities),
                vulnerabilities=vulnerabilities,
                secrets=secrets,
                misconfigurations=misconfigurations,
                raw_output=scan_data,
                metadata={
                    "trivy_version": self.version,
                    "scan_types": self.config.scan_types,
                    "severity_levels": self.config.severity_levels,
                    "target_type": scan_type
                }
            )
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to parse Trivy results: {e}")
            raise
    
    async def _update_database(self):
        """Update Trivy vulnerability database."""
        try:
            logger.info("Updating Trivy vulnerability database...")
            
            command = ["image", "--download-db-only"]
            result = await self._run_trivy_command(command)
            
            if result.returncode != 0:
                logger.warning(f"Database update completed with warnings: {result.stderr}")
            else:
                logger.info("Trivy database updated successfully")
                
        except Exception as e:
            logger.error(f"Failed to update Trivy database: {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_targets": self.supported_targets,
            "scan_types": self.config.scan_types,
            "binary_path": self.config.trivy_binary_path,
            "cache_dir": self.config.cache_dir
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            binary_exists = os.path.exists(self.config.trivy_binary_path)
            cache_dir_exists = os.path.exists(self.config.cache_dir)
            
            return {
                "healthy": binary_exists and cache_dir_exists,
                "binary_exists": binary_exists,
                "cache_dir_exists": cache_dir_exists,
                "last_db_update": "unknown"  # Would track this in real implementation
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }