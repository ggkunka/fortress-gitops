"""
Grype Scanner Plugin - Vulnerability scanning for container images and filesystems

This plugin integrates Anchore's Grype tool for comprehensive vulnerability
scanning using a large vulnerability database derived from multiple sources.
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


class GrypeConfig(ScannerConfig):
    """Grype scanner configuration."""
    grype_binary_path: str = "/usr/local/bin/grype"
    timeout_seconds: int = 600
    
    # Output options
    output_format: str = "json"  # json, table, cyclonedx, sarif, template
    
    # Vulnerability database options
    db_cache_dir: str = "/tmp/grype-db"
    db_update_url: Optional[str] = None
    skip_db_update: bool = False
    
    # Scanning options
    scope: str = "squashed"  # squashed, all-layers
    
    # Filtering options
    only_fixed: bool = False
    only_notfixed: bool = False
    ignore_states: List[str] = []  # ["wont-fix", "unknown"]
    
    # Platform options
    platform: Optional[str] = None
    
    # Registry options
    registry_auth_authority: Optional[str] = None
    registry_auth_username: Optional[str] = None
    registry_auth_password: Optional[str] = None
    registry_auth_token: Optional[str] = None
    
    # File options
    exclude_paths: List[str] = []
    
    # Distro override
    distro: Optional[str] = None


class GrypePlugin(BaseScannerPlugin):
    """
    Grype vulnerability scanner plugin.
    
    Supports scanning:
    - Container images (OCI/Docker)
    - Filesystem directories
    - Archive files (tar, zip, etc.)
    - SBOM files (Syft JSON, SPDX, CycloneDX)
    """
    
    def __init__(self, config: GrypeConfig):
        super().__init__(config)
        self.config = config
        self.name = "grype"
        self.version = "0.74.0"
        self.description = "Vulnerability scanner for container images and filesystems"
        
        # Supported input types
        self.supported_inputs = [
            "image",
            "dir", 
            "file",
            "sbom",
            "registry"
        ]
        
        # Supported output formats
        self.supported_formats = [
            "json",
            "table",
            "cyclonedx",
            "sarif",
            "template"
        ]
        
        logger.info("Grype plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the Grype plugin."""
        try:
            # Verify Grype binary exists
            if not os.path.exists(self.config.grype_binary_path):
                logger.error(f"Grype binary not found at: {self.config.grype_binary_path}")
                return False
            
            # Create database cache directory
            os.makedirs(self.config.db_cache_dir, exist_ok=True)
            
            # Check Grype version
            version_result = await self._run_grype_command(["version"])
            if version_result.returncode != 0:
                logger.error("Failed to get Grype version")
                return False
            
            # Extract version from output
            version_output = version_result.stdout.strip()
            if "version" in version_output.lower():
                self.version = version_output.split()[-1]
            
            # Update vulnerability database unless skipped
            if not self.config.skip_db_update:
                await self._update_database()
            
            logger.info(f"Grype plugin initialized successfully (version: {self.version})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Grype plugin: {e}")
            return False
    
    @traced("grype_plugin_scan")
    async def scan(
        self, 
        target: str, 
        scan_type: str = "image",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Perform a Grype vulnerability scan."""
        try:
            start_time = datetime.now(timezone.utc)
            options = options or {}
            
            # Validate input type
            if scan_type not in self.supported_inputs:
                raise ValueError(f"Unsupported scan type: {scan_type}. Supported: {self.supported_inputs}")
            
            # Build Grype command
            command = await self._build_scan_command(target, scan_type, options)
            
            # Execute scan
            logger.info(f"Starting Grype scan: {scan_type} on {target}")
            result = await self._run_grype_command(command)
            
            # Parse results
            scan_result = await self._parse_scan_results(result, target, scan_type, start_time)
            
            # Record metrics
            metrics.grype_scans_completed.inc()
            metrics.grype_vulnerabilities_found.inc(scan_result.vulnerability_count)
            
            logger.info(f"Grype scan completed: {scan_result.vulnerability_count} vulnerabilities found")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Grype scan failed: {e}")
            metrics.grype_scan_errors.inc()
            
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
    
    async def scan_directory(self, path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan a filesystem directory."""
        return await self.scan(f"dir:{path}", "dir", options)
    
    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan an archive file."""
        return await self.scan(f"file:{file_path}", "file", options)
    
    async def scan_sbom(self, sbom_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Scan an SBOM file."""
        return await self.scan(f"sbom:{sbom_path}", "sbom", options)
    
    async def get_vulnerability_details(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific vulnerability."""
        try:
            # Grype doesn't have a direct command for this, would need to query database
            # For now, return basic structure that would be populated from vulnerability database
            return {
                "id": vulnerability_id,
                "description": "Vulnerability details would be retrieved from database",
                "severity": "unknown",
                "cvss_scores": {},
                "references": [],
                "affected_packages": []
            }
            
        except Exception as e:
            logger.error(f"Failed to get vulnerability details: {e}")
            return None
    
    async def update_database(self) -> bool:
        """Update Grype vulnerability database."""
        try:
            await self._update_database()
            return True
        except Exception as e:
            logger.error(f"Failed to update Grype database: {e}")
            return False
    
    async def list_available_databases(self) -> List[Dict[str, Any]]:
        """List available vulnerability databases."""
        try:
            result = await self._run_grype_command(["db", "list"])
            if result.returncode == 0:
                # Parse database list from output
                databases = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('NAME') and not line.startswith('---'):
                        parts = line.split()
                        if len(parts) >= 2:
                            databases.append({
                                "name": parts[0],
                                "version": parts[1] if len(parts) > 1 else "unknown",
                                "built": parts[2] if len(parts) > 2 else "unknown"
                            })
                return databases
            return []
        except Exception as e:
            logger.error(f"Failed to list databases: {e}")
            return []
    
    async def _build_scan_command(
        self, 
        target: str, 
        scan_type: str,
        options: Dict[str, Any]
    ) -> List[str]:
        """Build Grype command for scanning."""
        command = []
        
        # Add output format
        output_format = options.get("output_format", self.config.output_format)
        command.extend(["-o", output_format])
        
        # Add output file if specified
        if options.get("output_file"):
            command.extend(["--file", options["output_file"]])
        
        # Add scope
        command.extend(["--scope", self.config.scope])
        
        # Add platform if specified
        if self.config.platform:
            command.extend(["--platform", self.config.platform])
        
        # Add distro override if specified
        if self.config.distro:
            command.extend(["--distro", self.config.distro])
        
        # Add vulnerability filtering
        if self.config.only_fixed:
            command.append("--only-fixed")
        
        if self.config.only_notfixed:
            command.append("--only-notfixed")
        
        # Add ignore states
        for state in self.config.ignore_states:
            command.extend(["--ignore-states", state])
        
        # Add exclude paths
        for exclude_path in self.config.exclude_paths:
            command.extend(["--exclude", exclude_path])
        
        # Registry authentication
        if self.config.registry_auth_username and self.config.registry_auth_password:
            auth_str = f"{self.config.registry_auth_username}:{self.config.registry_auth_password}"
            command.extend(["--registry-auth", auth_str])
        elif self.config.registry_auth_token:
            command.extend(["--registry-token", self.config.registry_auth_token])
        
        # Database options
        command.extend(["--cache-dir", self.config.db_cache_dir])
        
        if self.config.skip_db_update:
            command.append("--skip-db-update")
        
        # Add custom options from parameters
        for key, value in options.items():
            if key == "quiet":
                command.append("-q")
            elif key == "verbose":
                command.append("-v")
            elif key == "fail-on":
                command.extend(["--fail-on", value])
            elif key == "template":
                command.extend(["-t", value])
        
        # Add target
        command.append(target)
        
        return command
    
    async def _run_grype_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a Grype command."""
        try:
            full_command = [self.config.grype_binary_path] + command
            
            logger.debug(f"Running Grype command: {' '.join(full_command)}")
            
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
                raise RuntimeError(f"Grype command timed out after {self.config.timeout_seconds} seconds")
                
        except Exception as e:
            logger.error(f"Failed to run Grype command: {e}")
            raise
    
    async def _parse_scan_results(
        self, 
        result: subprocess.CompletedProcess, 
        target: str, 
        scan_type: str,
        start_time: datetime
    ) -> ScanResult:
        """Parse Grype scan results."""
        try:
            if result.returncode not in [0, 1]:  # Grype returns 1 when vulnerabilities found
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
            
            try:
                if result.stdout:
                    scan_data = json.loads(result.stdout)
                    
                    # Extract vulnerabilities from Grype JSON format
                    for match in scan_data.get("matches", []):
                        vulnerability = match.get("vulnerability", {})
                        artifact = match.get("artifact", {})
                        
                        vulnerabilities.append({
                            "id": vulnerability.get("id"),
                            "severity": vulnerability.get("severity"),
                            "description": vulnerability.get("description"),
                            "package_name": artifact.get("name"),
                            "package_version": artifact.get("version"),
                            "package_type": artifact.get("type"),
                            "fixed_version": match.get("vulnerability", {}).get("fix", {}).get("versions", []),
                            "namespace": vulnerability.get("namespace"),
                            "urls": vulnerability.get("urls", []),
                            "cvss": vulnerability.get("cvss", []),
                            "related_vulnerabilities": match.get("relatedVulnerabilities", [])
                        })
                        
            except json.JSONDecodeError as e:
                logger.warning(f"Could not parse Grype JSON output: {e}")
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
                vulnerabilities=vulnerabilities,
                raw_output=scan_data,
                metadata={
                    "grype_version": self.version,
                    "output_format": self.config.output_format,
                    "scope": self.config.scope,
                    "database_info": scan_data.get("descriptor", {})
                }
            )
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to parse Grype results: {e}")
            raise
    
    async def _update_database(self):
        """Update Grype vulnerability database."""
        try:
            logger.info("Updating Grype vulnerability database...")
            
            command = ["db", "update"]
            if self.config.db_update_url:
                command.extend(["--from", self.config.db_update_url])
            
            result = await self._run_grype_command(command)
            
            if result.returncode != 0:
                logger.warning(f"Database update completed with warnings: {result.stderr}")
            else:
                logger.info("Grype database updated successfully")
                
        except Exception as e:
            logger.error(f"Failed to update Grype database: {e}")
            raise
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_inputs": self.supported_inputs,
            "supported_formats": self.supported_formats,
            "binary_path": self.config.grype_binary_path,
            "default_format": self.config.output_format,
            "database_cache_dir": self.config.db_cache_dir
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            binary_exists = os.path.exists(self.config.grype_binary_path)
            cache_dir_exists = os.path.exists(self.config.db_cache_dir)
            
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