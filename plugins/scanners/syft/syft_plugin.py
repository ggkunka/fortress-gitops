"""
Syft Scanner Plugin - Software Bill of Materials (SBOM) generation

This plugin integrates Anchore's Syft tool for generating comprehensive
Software Bill of Materials from container images, filesystems, and archives.
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


class SyftConfig(ScannerConfig):
    """Syft scanner configuration."""
    syft_binary_path: str = "/usr/local/bin/syft"
    timeout_seconds: int = 600
    
    # Output options
    output_format: str = "spdx-json"  # spdx-json, cyclonedx-json, syft-json, table, text
    
    # Cataloging options
    catalogers: List[str] = []  # empty means all catalogers
    scope: str = "squashed"  # squashed, all-layers
    
    # Package discovery
    package_cataloger_enabled: bool = True
    file_cataloger_enabled: bool = True
    secrets_cataloger_enabled: bool = False
    
    # Platform options
    platform: Optional[str] = None
    
    # Registry options
    registry_auth_authority: Optional[str] = None
    registry_auth_username: Optional[str] = None
    registry_auth_password: Optional[str] = None
    registry_auth_token: Optional[str] = None
    
    # File options
    exclude_paths: List[str] = []
    include_paths: List[str] = []


class SyftPlugin(BaseScannerPlugin):
    """
    Syft SBOM generator plugin.
    
    Supports generating SBOMs from:
    - Container images (OCI/Docker)
    - Filesystem directories
    - Archive files (tar, zip, etc.)
    - Git repositories
    """
    
    def __init__(self, config: SyftConfig):
        super().__init__(config)
        self.config = config
        self.name = "syft"
        self.version = "1.0.0"
        self.description = "Software Bill of Materials (SBOM) generator for containers and filesystems"
        
        # Supported input types
        self.supported_inputs = [
            "image",
            "dir",
            "file",
            "registry"
        ]
        
        # Supported output formats
        self.supported_formats = [
            "spdx-json",
            "spdx-tag",
            "cyclonedx-json",
            "cyclonedx-xml",
            "syft-json",
            "table",
            "text",
            "template"
        ]
        
        logger.info("Syft plugin initialized")
    
    async def initialize(self) -> bool:
        """Initialize the Syft plugin."""
        try:
            # Verify Syft binary exists
            if not os.path.exists(self.config.syft_binary_path):
                logger.error(f"Syft binary not found at: {self.config.syft_binary_path}")
                return False
            
            # Check Syft version
            version_result = await self._run_syft_command(["version"])
            if version_result.returncode != 0:
                logger.error("Failed to get Syft version")
                return False
            
            # Extract version from output
            version_output = version_result.stdout.strip()
            if "version" in version_output.lower():
                self.version = version_output.split()[-1]
            
            logger.info(f"Syft plugin initialized successfully (version: {self.version})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Syft plugin: {e}")
            return False
    
    @traced("syft_plugin_generate_sbom")
    async def generate_sbom(
        self, 
        target: str, 
        output_format: Optional[str] = None,
        output_file: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Generate SBOM from a target."""
        try:
            start_time = datetime.now(timezone.utc)
            options = options or {}
            format_to_use = output_format or self.config.output_format
            
            # Validate output format
            if format_to_use not in self.supported_formats:
                raise ValueError(f"Unsupported output format: {format_to_use}")
            
            # Build Syft command
            command = await self._build_sbom_command(target, format_to_use, output_file, options)
            
            # Execute SBOM generation
            logger.info(f"Starting Syft SBOM generation for: {target}")
            result = await self._run_syft_command(command)
            
            # Parse results
            scan_result = await self._parse_sbom_results(
                result, target, format_to_use, output_file, start_time
            )
            
            # Record metrics
            metrics.syft_sboms_generated.inc()
            metrics.syft_packages_discovered.inc(scan_result.package_count)
            
            logger.info(f"Syft SBOM generation completed: {scan_result.package_count} packages found")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Syft SBOM generation failed: {e}")
            metrics.syft_generation_errors.inc()
            
            return ScanResult(
                scanner_name=self.name,
                scanner_version=self.version,
                target=target,
                scan_type="sbom",
                status="failed",
                error_message=str(e),
                started_at=start_time,
                completed_at=datetime.now(timezone.utc)
            )
    
    async def scan(
        self, 
        target: str, 
        scan_type: str = "sbom",
        options: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Perform a Syft scan (SBOM generation)."""
        return await self.generate_sbom(target, options=options)
    
    async def scan_image(self, image: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Generate SBOM from container image."""
        return await self.generate_sbom(image, options=options)
    
    async def scan_directory(self, path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Generate SBOM from filesystem directory."""
        return await self.generate_sbom(f"dir:{path}", options=options)
    
    async def scan_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Generate SBOM from archive file."""
        return await self.generate_sbom(f"file:{file_path}", options=options)
    
    async def list_catalogers(self) -> List[str]:
        """List available package catalogers."""
        try:
            result = await self._run_syft_command(["cataloger", "list"])
            if result.returncode == 0:
                # Parse cataloger list from output
                catalogers = []
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('[') and not line.startswith('NAME'):
                        catalogers.append(line.split()[0])
                return catalogers
            return []
        except Exception as e:
            logger.error(f"Failed to list catalogers: {e}")
            return []
    
    async def validate_sbom(self, sbom_file: str) -> Dict[str, Any]:
        """Validate an SBOM file."""
        try:
            # For now, just check if it's valid JSON/XML
            with open(sbom_file, 'r') as f:
                content = f.read()
            
            validation_result = {
                "valid": False,
                "format": "unknown",
                "errors": [],
                "package_count": 0
            }
            
            # Try to parse as JSON
            try:
                data = json.loads(content)
                validation_result["valid"] = True
                validation_result["format"] = "json"
                
                # Count packages based on format
                if "packages" in data:  # SPDX or CycloneDX
                    validation_result["package_count"] = len(data["packages"])
                elif "artifacts" in data:  # Syft JSON
                    validation_result["package_count"] = len(data["artifacts"])
                
            except json.JSONDecodeError:
                # Try to parse as XML
                try:
                    import xml.etree.ElementTree as ET
                    ET.fromstring(content)
                    validation_result["valid"] = True
                    validation_result["format"] = "xml"
                except ET.ParseError as e:
                    validation_result["errors"].append(f"Invalid XML: {e}")
            
            return validation_result
            
        except Exception as e:
            return {
                "valid": False,
                "format": "unknown",
                "errors": [str(e)],
                "package_count": 0
            }
    
    async def convert_sbom(
        self, 
        input_file: str, 
        output_format: str, 
        output_file: str
    ) -> bool:
        """Convert SBOM from one format to another."""
        try:
            # Syft doesn't have direct conversion, so we'd need to re-scan
            # For now, just copy if same format
            if output_format == self.config.output_format:
                import shutil
                shutil.copy2(input_file, output_file)
                return True
            
            # In a real implementation, would re-scan with different format
            logger.warning("SBOM format conversion not implemented")
            return False
            
        except Exception as e:
            logger.error(f"Failed to convert SBOM: {e}")
            return False
    
    async def _build_sbom_command(
        self, 
        target: str, 
        output_format: str,
        output_file: Optional[str],
        options: Dict[str, Any]
    ) -> List[str]:
        """Build Syft command for SBOM generation."""
        command = ["scan"]
        
        # Add output format
        command.extend(["-o", output_format])
        
        # Add output file if specified
        if output_file:
            command.extend(["--file", output_file])
        
        # Add scope
        command.extend(["--scope", self.config.scope])
        
        # Add catalogers if specified
        if self.config.catalogers:
            catalogers_str = ",".join(self.config.catalogers)
            command.extend(["--catalogers", catalogers_str])
        
        # Add platform if specified
        if self.config.platform:
            command.extend(["--platform", self.config.platform])
        
        # Add exclude paths
        for exclude_path in self.config.exclude_paths:
            command.extend(["--exclude", exclude_path])
        
        # Registry authentication
        if self.config.registry_auth_username and self.config.registry_auth_password:
            auth_str = f"{self.config.registry_auth_username}:{self.config.registry_auth_password}"
            command.extend(["--registry-auth", auth_str])
        elif self.config.registry_auth_token:
            command.extend(["--registry-token", self.config.registry_auth_token])
        
        # Add custom options from parameters
        for key, value in options.items():
            if key == "quiet":
                command.append("-q")
            elif key == "verbose":
                command.append("-v")
            elif key == "name":
                command.extend(["--name", value])
            elif key == "base-path":
                command.extend(["--base-path", value])
        
        # Add target
        command.append(target)
        
        return command
    
    async def _run_syft_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a Syft command."""
        try:
            full_command = [self.config.syft_binary_path] + command
            
            logger.debug(f"Running Syft command: {' '.join(full_command)}")
            
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
                raise RuntimeError(f"Syft command timed out after {self.config.timeout_seconds} seconds")
                
        except Exception as e:
            logger.error(f"Failed to run Syft command: {e}")
            raise
    
    async def _parse_sbom_results(
        self, 
        result: subprocess.CompletedProcess, 
        target: str, 
        output_format: str,
        output_file: Optional[str],
        start_time: datetime
    ) -> ScanResult:
        """Parse Syft SBOM generation results."""
        try:
            if result.returncode != 0:
                return ScanResult(
                    scanner_name=self.name,
                    scanner_version=self.version,
                    target=target,
                    scan_type="sbom",
                    status="failed",
                    error_message=result.stderr,
                    started_at=start_time,
                    completed_at=datetime.now(timezone.utc)
                )
            
            # Parse SBOM data
            sbom_data = None
            packages = []
            files = []
            
            try:
                if output_file and os.path.exists(output_file):
                    # Read from output file
                    with open(output_file, 'r') as f:
                        if output_format.endswith('json'):
                            sbom_data = json.load(f)
                        else:
                            sbom_data = {"raw_content": f.read()}
                else:
                    # Parse from stdout
                    if output_format.endswith('json') and result.stdout:
                        sbom_data = json.loads(result.stdout)
                    else:
                        sbom_data = {"raw_content": result.stdout}
                
                # Extract packages based on format
                if sbom_data:
                    if output_format == "spdx-json":
                        packages = self._extract_spdx_packages(sbom_data)
                    elif output_format == "cyclonedx-json":
                        packages = self._extract_cyclonedx_packages(sbom_data)
                    elif output_format == "syft-json":
                        packages = self._extract_syft_packages(sbom_data)
                        files = self._extract_syft_files(sbom_data)
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logger.warning(f"Could not parse SBOM data: {e}")
                sbom_data = {"raw_content": result.stdout}
            
            # Create scan result
            scan_result = ScanResult(
                scanner_name=self.name,
                scanner_version=self.version,
                target=target,
                scan_type="sbom",
                status="completed",
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
                package_count=len(packages),
                packages=packages,
                files=files,
                sbom_data=sbom_data,
                raw_output=sbom_data,
                metadata={
                    "syft_version": self.version,
                    "output_format": output_format,
                    "scope": self.config.scope,
                    "catalogers": self.config.catalogers,
                    "output_file": output_file
                }
            )
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to parse Syft results: {e}")
            raise
    
    def _extract_spdx_packages(self, sbom_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract packages from SPDX SBOM."""
        packages = []
        for pkg in sbom_data.get("packages", []):
            packages.append({
                "name": pkg.get("name"),
                "version": pkg.get("versionInfo"),
                "type": pkg.get("packageType"),
                "supplier": pkg.get("supplier"),
                "download_location": pkg.get("downloadLocation"),
                "files_analyzed": pkg.get("filesAnalyzed", False),
                "license_concluded": pkg.get("licenseConcluded"),
                "license_declared": pkg.get("licenseDeclared"),
                "copyright": pkg.get("copyrightText"),
                "spdx_id": pkg.get("SPDXID"),
                "checksums": pkg.get("checksums", [])
            })
        return packages
    
    def _extract_cyclonedx_packages(self, sbom_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract packages from CycloneDX SBOM."""
        packages = []
        for component in sbom_data.get("components", []):
            packages.append({
                "name": component.get("name"),
                "version": component.get("version"),
                "type": component.get("type"),
                "namespace": component.get("namespace"),
                "group": component.get("group"),
                "publisher": component.get("publisher"),
                "description": component.get("description"),
                "scope": component.get("scope"),
                "licenses": component.get("licenses", []),
                "cpe": component.get("cpe"),
                "purl": component.get("purl"),
                "bom_ref": component.get("bom-ref"),
                "hashes": component.get("hashes", [])
            })
        return packages
    
    def _extract_syft_packages(self, sbom_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract packages from Syft JSON SBOM."""
        packages = []
        for artifact in sbom_data.get("artifacts", []):
            packages.append({
                "name": artifact.get("name"),
                "version": artifact.get("version"),
                "type": artifact.get("type"),
                "language": artifact.get("language"),
                "locations": artifact.get("locations", []),
                "licenses": artifact.get("licenses", []),
                "cpes": artifact.get("cpes", []),
                "purl": artifact.get("purl"),
                "metadata": artifact.get("metadata", {})
            })
        return packages
    
    def _extract_syft_files(self, sbom_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract files from Syft JSON SBOM."""
        files = []
        for file_entry in sbom_data.get("files", []):
            files.append({
                "path": file_entry.get("path"),
                "layer_id": file_entry.get("layerID"),
                "size": file_entry.get("size"),
                "digests": file_entry.get("digests", []),
                "mime_type": file_entry.get("mimeType"),
                "is_binary": file_entry.get("isBinary", False)
            })
        return files
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "supported_inputs": self.supported_inputs,
            "supported_formats": self.supported_formats,
            "binary_path": self.config.syft_binary_path,
            "default_format": self.config.output_format
        }
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        try:
            binary_exists = os.path.exists(self.config.syft_binary_path)
            
            return {
                "healthy": binary_exists,
                "binary_exists": binary_exists
            }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }