"""
OSV Scanner Plugin - Open Source Vulnerability scanning

This plugin integrates Google's OSV Scanner for comprehensive vulnerability
scanning using the OSV (Open Source Vulnerabilities) database.
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


class OSVConfig(ScannerConfig):
    """OSV scanner configuration."""
    osv_binary_path: str = "/usr/local/bin/osv-scanner"
    timeout_seconds: int = 600
    
    # Output options
    output_format: str = "json"  # json, table, sarif
    
    # API options
    api_endpoint: str = "https://api.osv.dev"
    batch_size: int = 1000
    
    # Scanning options
    recursive: bool = True
    skip_git: bool = False
    
    # Lockfile scanning
    parse_as_lockfile: Optional[str] = None  # package-lock.json, yarn.lock, etc.
    
    # SBOM scanning
    sbom_format: Optional[str] = None  # cyclonedx, spdx
    
    # Experimental features
    experimental_licenses: bool = False
    experimental_call_analysis: bool = False
    
    # Vulnerability filtering
    ignore_dev_deps: bool = False
    
    # Offline mode
    offline: bool = False
    local_db_path: Optional[str] = None


class OSVPlugin(BaseScannerPlugin):
    """
    OSV (Open Source Vulnerabilities) scanner plugin.
    
    Supports scanning:
    - Git repositories
    - Filesystem directories
    - Individual lockfiles (package-lock.json, yarn.lock, etc.)
    - SBOM files (SPDX, CycloneDX)
    - Container images (via SBOM extraction)
    """
    
    def __init__(self, config: OSVConfig):
        super().__init__(config)
        self.config = config
        self.name = "osv-scanner"
        self.version = "1.4.0"
        self.description = "Open Source Vulnerability scanner using OSV database"
        
        # Supported input types
        self.supported_inputs = [
            "repository",
            "directory", 
            "lockfile",
            "sbom",
            "docker-archive",
            "oci-archive"
        ]
        
        # Supported output formats
        self.supported_formats = [
            "json",
            "table",
            "sarif"
        ]
        
        # Supported lockfile types
        self.supported_lockfiles = [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Gemfile.lock",
            "Pipfile.lock",
            "poetry.lock",
            "requirements.txt",
            "go.mod",
            "go.sum",
            "Cargo.lock",
            "composer.lock",
            "pubspec.lock"
        ]
        
        logger.info("OSV scanner plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the OSV scanner plugin."""
        try:
            # Verify OSV scanner binary exists
            if not os.path.exists(self.config.osv_binary_path):
                logger.error(f"OSV scanner binary not found at: {self.config.osv_binary_path}")
                return False
            
            # Check OSV scanner version
            version_result = await self._run_osv_command(["--version"])
            if version_result.returncode != 0:
                logger.error("Failed to get OSV scanner version")
                return False
            
            # Extract version from output
            version_output = version_result.stdout.strip()
            if version_output:
                self.version = version_output.split()[-1] if version_output.split() else "unknown"
            
            logger.info(f"OSV scanner plugin initialized successfully (version: {self.version})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize OSV scanner plugin: {e}")
            return False
    
    @traced("osv_plugin_scan")
    async def scan(
        self, 
        target: str, 
        scan_type: str = "directory",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Perform an OSV vulnerability scan."""
        try:
            start_time = datetime.now(timezone.utc)
            options = options or {}
            
            # Validate input type
            if scan_type not in self.supported_inputs:
                raise ValueError(f"Unsupported scan type: {scan_type}. Supported: {self.supported_inputs}")
            
            # Build OSV scanner command
            command = await self._build_scan_command(target, scan_type, options)
            
            # Execute scan
            logger.info(f"Starting OSV scan: {scan_type} on {target}")
            result = await self._run_osv_command(command)
            
            # Parse results
            scan_result = await self._parse_scan_results(result, target, scan_type, start_time)
            
            # Record metrics
            metrics.osv_scans_completed.inc()
            metrics.osv_vulnerabilities_found.inc(scan_result.vulnerability_count)
            
            logger.info(f"OSV scan completed: {scan_result.vulnerability_count} vulnerabilities found")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"OSV scan failed: {e}")
            metrics.osv_scan_errors.inc()
            
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
    
    async def scan_repository(self, repo_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a Git repository."""
        return await self.scan(repo_path, "repository", options)
    
    async def scan_directory(self, path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a filesystem directory."""
        return await self.scan(path, "directory", options)
    
    async def scan_lockfile(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a specific lockfile."""
        return await self.scan(file_path, "lockfile", options)
    
    async def scan_sbom(self, sbom_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan an SBOM file."""
        return await self.scan(sbom_path, "sbom", options)
    
    async def scan_docker_archive(self, archive_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a Docker archive file."""
        return await self.scan(archive_path, "docker-archive", options)
    
    async def query_vulnerability(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """Query OSV database for vulnerability details."""
        try:
            # Use OSV API to query vulnerability
            command = ["--format=json", f"--query={vulnerability_id}"]
            result = await self._run_osv_command(command)
            
            if result.returncode == 0 and result.stdout:
                vulnerability_data = json.loads(result.stdout)
                return vulnerability_data
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to query vulnerability: {e}")
            return None
    
    async def list_ecosystems(self) -> List[str]:
        """List supported package ecosystems."""
        # OSV supports many ecosystems - return the main ones
        return [
            "npm",
            "PyPI", 
            "Go",
            "crates.io",
            "Maven",
            "NuGet",
            "RubyGems",
            "Packagist",
            "Pub",
            "ConanCenter",
            "Rocky Linux",
            "AlmaLinux",
            "Debian",
            "Ubuntu",
            "Alpine",
            "Android",
            "GitHub Actions",
            "Hex",
            "Linux kernel",
            "OSS-Fuzz"
        ]
    
    async def get_database_info(self) -> Dict[str, Any]:
        """Get information about the OSV database."""
        try:
            # OSV doesn't provide direct database info command
            # Return general information about OSV
            return {
                "name": "OSV (Open Source Vulnerabilities)",
                "url": "https://osv.dev",
                "api_endpoint": self.config.api_endpoint,
                "description": "Distributed vulnerability database for Open Source",
                "ecosystems": await self.list_ecosystems(),
                "last_updated": "real-time"  # OSV is continuously updated
            }
        except Exception as e:
            logger.error(f"Failed to get database info: {e}")
            return {}
    
    async def _build_scan_command(
        self, 
        target: str, 
        scan_type: str,
        options: Dict[str, Any]
    ) -> List[str]:
        """Build OSV scanner command for scanning."""
        command = []
        
        # Add output format
        output_format = options.get("output_format", self.config.output_format)
        command.extend(["--format", output_format])
        
        # Add output file if specified
        if options.get("output_file"):
            command.extend(["--output", options["output_file"]])
        
        # Add recursive flag
        if self.config.recursive and scan_type in ["directory", "repository"]:
            command.append("--recursive")
        
        # Add skip git flag
        if self.config.skip_git:
            command.append("--skip-git")
        
        # Add lockfile parsing
        if scan_type == "lockfile" and self.config.parse_as_lockfile:
            command.extend(["--lockfile", self.config.parse_as_lockfile])
        
        # Add SBOM format
        if scan_type == "sbom" and self.config.sbom_format:
            command.extend(["--sbom", self.config.sbom_format])
        
        # Add experimental features
        if self.config.experimental_licenses:
            command.append("--experimental-licenses")
        
        if self.config.experimental_call_analysis:
            command.append("--experimental-call-analysis")
        
        # Add dev dependencies filter
        if self.config.ignore_dev_deps:
            command.append("--no-dev")
        
        # Add offline mode
        if self.config.offline:
            command.append("--offline")
            if self.config.local_db_path:
                command.extend(["--local-db", self.config.local_db_path])
        
        # Add scan type specific flags
        if scan_type == "docker-archive":
            command.append("--docker")
        elif scan_type == "oci-archive":
            command.append("--oci")
        
        # Add custom options from parameters
        for key, value in options.items():
            if key == "verbosity":
                if value > 0:
                    command.extend(["-v"] * min(value, 3))  # Max 3 levels
            elif key == "config":
                command.extend(["--config", value])
            elif key == "ignore-file":
                command.extend(["--ignore-file", value])
        
        # Add target
        command.append(target)
        
        return command
    
    async def _run_osv_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run an OSV scanner command."""
        try:
            full_command = [self.config.osv_binary_path] + command
            
            logger.debug(f"Running OSV command: {' '.join(full_command)}")
            
            # Run command with timeout
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
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
                raise RuntimeError(f"OSV command timed out after {self.config.timeout_seconds} seconds")
                
        except Exception as e:
            logger.error(f"Failed to run OSV command: {e}")
            raise
    
    async def _parse_scan_results(
        self, 
        result: subprocess.CompletedProcess, 
        target: str, 
        scan_type: str,
        start_time: datetime
    ) -> ScanResult:
        """Parse OSV scan results."""
        try:
            if result.returncode not in [0, 1]:  # OSV returns 1 when vulnerabilities found
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
            scan_data = {}
            vulnerabilities = []
            packages = []
            
            try:
                if result.stdout:
                    scan_data = json.loads(result.stdout)
                    
                    # Extract vulnerabilities from OSV JSON format
                    for vuln_result in scan_data.get("results", []):
                        source = vuln_result.get("source", {})
                        
                        for package in vuln_result.get("packages", []):
                            package_info = package.get("package", {})
                            
                            # Add package information
                            packages.append({
                                "name": package_info.get("name"),
                                "version": package_info.get("version"),
                                "ecosystem": package_info.get("ecosystem"),
                                "source_file": source.get("path"),
                                "source_type": source.get("type")
                            })
                            
                            # Extract vulnerabilities for this package
                            for vuln in package.get("vulnerabilities", []):
                                vulnerabilities.append({
                                    "id": vuln.get("id"),
                                    "summary": vuln.get("summary"),
                                    "details": vuln.get("details"),
                                    "severity": self._extract_severity(vuln),
                                    "package_name": package_info.get("name"),
                                    "package_version": package_info.get("version"),
                                    "package_ecosystem": package_info.get("ecosystem"),
                                    "affected_ranges": vuln.get("affected", []),
                                    "database_specific": vuln.get("database_specific", {}),
                                    "ecosystem_specific": vuln.get("ecosystem_specific", {}),
                                    "references": vuln.get("references", []),
                                    "aliases": vuln.get("aliases", []),
                                    "modified": vuln.get("modified"),
                                    "published": vuln.get("published"),
                                    "withdrawn": vuln.get("withdrawn")
                                })
                        
            except json.JSONDecodeError as e:
                logger.warning(f"Could not parse OSV JSON output: {e}")
                scan_data = {"raw_output": result.stdout}
            
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
                package_count=len(packages),
                vulnerabilities=vulnerabilities,
                packages=packages,
                raw_output=scan_data,
                metadata={
                    "osv_version": self.version,
                    "output_format": self.config.output_format,
                    "api_endpoint": self.config.api_endpoint,
                    "scan_settings": {
                        "recursive": self.config.recursive,
                        "skip_git": self.config.skip_git,
                        "offline": self.config.offline
                    }
                }
            )
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to parse OSV results: {e}")
            raise
    
    def _extract_severity(self, vulnerability: Dict[str, Any]) -> str:
        """Extract severity from OSV vulnerability data."""
        try:
            # Check for CVSS score in database_specific
            database_specific = vulnerability.get("database_specific", {})
            if "cvss_score" in database_specific:
                score = database_specific["cvss_score"]
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                elif score > 0.0:
                    return "LOW"
            
            # Check for severity in ecosystem_specific
            ecosystem_specific = vulnerability.get("ecosystem_specific", {})
            if "severity" in ecosystem_specific:
                return ecosystem_specific["severity"].upper()
            
            # Default to unknown
            return "UNKNOWN"
            
        except Exception:
            return "UNKNOWN"
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_inputs": self.supported_inputs,
            "supported_formats": self.supported_formats,
            "supported_lockfiles": self.supported_lockfiles,
            "binary_path": self.config.osv_binary_path,
            "default_format": self.config.output_format,
            "api_endpoint": self.config.api_endpoint
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            binary_exists = os.path.exists(self.config.osv_binary_path)
            
            return {
                "healthy": binary_exists,
                "binary_exists": binary_exists,
                "api_endpoint": self.config.api_endpoint,
                "offline_mode": self.config.offline
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }