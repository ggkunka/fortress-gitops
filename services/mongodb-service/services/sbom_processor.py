"""
SBOM Processor Service - SBOM document parsing and enrichment

This service handles parsing, validation, and enrichment of SBOM documents
in various formats (SPDX, CycloneDX, etc.).
"""

import json
import xml.etree.ElementTree as ET
import yaml
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from uuid import uuid4

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.sbom import (
    SBOMDocument, ComponentModel, VulnerabilityModel, LicenseModel,
    SBOMFormat, SBOMStatus, ComponentType, SBOMMetadata,
    create_sbom_document, create_component, create_vulnerability, create_license
)
from .sbom_repository import SBOMRepository

logger = get_logger(__name__)
metrics = get_metrics()


class SBOMProcessor:
    """
    SBOM document processor for parsing and enriching SBOM documents.
    
    This processor:
    1. Parses SBOM documents in multiple formats
    2. Validates SBOM structure and content
    3. Enriches components with vulnerability data
    4. Performs license analysis
    5. Generates security metrics
    6. Triggers downstream processing
    """
    
    def __init__(self, repository: SBOMRepository, event_bus: EventBus):
        self.repository = repository
        self.event_bus = event_bus
        
        # Supported formats and their parsers
        self.format_parsers = {
            SBOMFormat.SPDX_JSON: self._parse_spdx_json,
            SBOMFormat.CYCLONEDX_JSON: self._parse_cyclonedx_json,
            SBOMFormat.SPDX_XML: self._parse_spdx_xml,
            SBOMFormat.CYCLONEDX_XML: self._parse_cyclonedx_xml,
            SBOMFormat.SPDX_YAML: self._parse_spdx_yaml,
            SBOMFormat.CYCLONEDX_YAML: self._parse_cyclonedx_yaml,
            SBOMFormat.SPDX_TAG_VALUE: self._parse_spdx_tag_value,
            SBOMFormat.SYFT_JSON: self._parse_syft_json
        }
        
        # Component type mappings
        self.component_type_mappings = {
            # SPDX types
            "APPLICATION": ComponentType.APPLICATION,
            "CONTAINER": ComponentType.CONTAINER,
            "DEVICE": ComponentType.DEVICE,
            "FILE": ComponentType.FILE,
            "FIRMWARE": ComponentType.FIRMWARE,
            "FRAMEWORK": ComponentType.FRAMEWORK,
            "LIBRARY": ComponentType.LIBRARY,
            "OPERATING-SYSTEM": ComponentType.OPERATING_SYSTEM,
            "PLATFORM": ComponentType.PLATFORM,
            "OTHER": ComponentType.OTHER,
            
            # CycloneDX types
            "application": ComponentType.APPLICATION,
            "container": ComponentType.CONTAINER,
            "device": ComponentType.DEVICE,
            "file": ComponentType.FILE,
            "firmware": ComponentType.FIRMWARE,
            "framework": ComponentType.FRAMEWORK,
            "library": ComponentType.LIBRARY,
            "operating-system": ComponentType.OPERATING_SYSTEM,
            "platform": ComponentType.PLATFORM,
            "other": ComponentType.OTHER
        }
        
        logger.info("SBOM processor initialized")
    
    @traced("sbom_processor_process_sbom")
    async def process_sbom(self, sbom: SBOMDocument) -> SBOMDocument:
        """Process and enrich SBOM document."""
        try:
            # Update processing status
            await self.repository.update_processing_status(sbom.id, SBOMStatus.PROCESSING)
            
            # Parse SBOM content
            parsed_content = await self._parse_sbom_content(sbom)
            sbom.parsed_content = parsed_content
            
            # Extract components
            components = await self._extract_components(sbom)
            sbom.components = components
            
            # Enrich components with vulnerability data
            await self._enrich_components_with_vulnerabilities(sbom)
            
            # Perform license analysis
            await self._analyze_licenses(sbom)
            
            # Generate security metrics
            await self._generate_security_metrics(sbom)
            
            # Update SBOM with processed data
            await self.repository.update_sbom(sbom.id, {
                "parsed_content": sbom.parsed_content,
                "components": [comp.dict() for comp in sbom.components],
                "total_components": len(sbom.components),
                "vulnerable_components": len([c for c in sbom.components if c.vulnerabilities]),
                "license_risks": sbom.license_risks or []
            })
            
            # Mark as completed
            await self.repository.update_processing_status(sbom.id, SBOMStatus.COMPLETED)
            
            # Publish processing completed event
            await self.event_bus.publish("sbom.processing.completed", {
                "sbom_id": sbom.id,
                "total_components": len(sbom.components),
                "vulnerable_components": len([c for c in sbom.components if c.vulnerabilities]),
                "processing_duration": sbom.processing_duration
            })
            
            logger.info(f"SBOM processing completed: {sbom.id}")
            metrics.sbom_processor_documents_processed.inc()
            
            return sbom
            
        except Exception as e:
            logger.error(f"Error processing SBOM {sbom.id}: {e}")
            await self.repository.update_processing_status(sbom.id, SBOMStatus.FAILED, str(e))
            metrics.sbom_processor_processing_failed.inc()
            raise
    
    async def _parse_sbom_content(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Parse SBOM content based on format."""
        try:
            parser = self.format_parsers.get(sbom.format)
            if not parser:
                raise ValueError(f"Unsupported SBOM format: {sbom.format}")
            
            parsed_content = await parser(sbom.raw_content)
            return parsed_content
            
        except Exception as e:
            logger.error(f"Error parsing SBOM content: {e}")
            raise
    
    async def _parse_spdx_json(self, content: str) -> Dict[str, Any]:
        """Parse SPDX JSON format."""
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid SPDX JSON format: {e}")
    
    async def _parse_cyclonedx_json(self, content: str) -> Dict[str, Any]:
        """Parse CycloneDX JSON format."""
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid CycloneDX JSON format: {e}")
    
    async def _parse_spdx_xml(self, content: str) -> Dict[str, Any]:
        """Parse SPDX XML format."""
        try:
            root = ET.fromstring(content)
            # Convert XML to dict representation
            return self._xml_to_dict(root)
        except ET.ParseError as e:
            raise ValueError(f"Invalid SPDX XML format: {e}")
    
    async def _parse_cyclonedx_xml(self, content: str) -> Dict[str, Any]:
        """Parse CycloneDX XML format."""
        try:
            root = ET.fromstring(content)
            # Convert XML to dict representation
            return self._xml_to_dict(root)
        except ET.ParseError as e:
            raise ValueError(f"Invalid CycloneDX XML format: {e}")
    
    async def _parse_spdx_yaml(self, content: str) -> Dict[str, Any]:
        """Parse SPDX YAML format."""
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid SPDX YAML format: {e}")
    
    async def _parse_cyclonedx_yaml(self, content: str) -> Dict[str, Any]:
        """Parse CycloneDX YAML format."""
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid CycloneDX YAML format: {e}")
    
    async def _parse_spdx_tag_value(self, content: str) -> Dict[str, Any]:
        """Parse SPDX tag-value format."""
        try:
            parsed = {}
            current_section = None
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key == "PackageName":
                        current_section = "package"
                        if "packages" not in parsed:
                            parsed["packages"] = []
                        parsed["packages"].append({"name": value})
                    elif current_section == "package" and parsed["packages"]:
                        parsed["packages"][-1][key.lower()] = value
                    else:
                        parsed[key.lower()] = value
            
            return parsed
            
        except Exception as e:
            raise ValueError(f"Invalid SPDX tag-value format: {e}")
    
    async def _parse_syft_json(self, content: str) -> Dict[str, Any]:
        """Parse Syft JSON format."""
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid Syft JSON format: {e}")
    
    def _xml_to_dict(self, element: ET.Element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        
        # Handle attributes
        if element.attrib:
            result.update(element.attrib)
        
        # Handle text content
        if element.text and element.text.strip():
            if len(element) == 0:
                return element.text.strip()
            result['text'] = element.text.strip()
        
        # Handle children
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        return result
    
    async def _extract_components(self, sbom: SBOMDocument) -> List[ComponentModel]:
        """Extract components from parsed SBOM content."""
        try:
            components = []
            
            if sbom.format in [SBOMFormat.SPDX_JSON, SBOMFormat.SPDX_XML, SBOMFormat.SPDX_YAML]:
                components = await self._extract_spdx_components(sbom.parsed_content)
            elif sbom.format in [SBOMFormat.CYCLONEDX_JSON, SBOMFormat.CYCLONEDX_XML, SBOMFormat.CYCLONEDX_YAML]:
                components = await self._extract_cyclonedx_components(sbom.parsed_content)
            elif sbom.format == SBOMFormat.SPDX_TAG_VALUE:
                components = await self._extract_spdx_tag_value_components(sbom.parsed_content)
            elif sbom.format == SBOMFormat.SYFT_JSON:
                components = await self._extract_syft_components(sbom.parsed_content)
            
            return components
            
        except Exception as e:
            logger.error(f"Error extracting components: {e}")
            raise
    
    async def _extract_spdx_components(self, parsed_content: Dict[str, Any]) -> List[ComponentModel]:
        """Extract components from SPDX format."""
        components = []
        
        # Extract packages
        packages = parsed_content.get("packages", [])
        if isinstance(packages, dict):
            packages = [packages]
        
        for package in packages:
            component = create_component(
                name=package.get("name", "unknown"),
                component_type=self._map_component_type(package.get("packageType", "OTHER")),
                version=package.get("versionInfo"),
                supplier=package.get("supplier"),
                description=package.get("description"),
                copyright=package.get("copyrightText"),
                homepage=package.get("homepage"),
                download_location=package.get("downloadLocation"),
                file_name=package.get("fileName"),
                package_url=package.get("packageUrl"),
                external_references=package.get("externalRefs", []),
                hashes=self._extract_hashes(package.get("checksums", [])),
                licenses=self._extract_licenses(package.get("licenseConcluded"), package.get("licenseDeclared"))
            )
            components.append(component)
        
        return components
    
    async def _extract_cyclonedx_components(self, parsed_content: Dict[str, Any]) -> List[ComponentModel]:
        """Extract components from CycloneDX format."""
        components = []
        
        # Extract components
        component_list = parsed_content.get("components", [])
        if isinstance(component_list, dict):
            component_list = [component_list]
        
        for comp in component_list:
            licenses = []
            license_list = comp.get("licenses", [])
            for license_item in license_list:
                if isinstance(license_item, dict):
                    license_obj = create_license(
                        id=license_item.get("id"),
                        name=license_item.get("name"),
                        url=license_item.get("url")
                    )
                    licenses.append(license_obj)
            
            component = create_component(
                name=comp.get("name", "unknown"),
                component_type=self._map_component_type(comp.get("type", "library")),
                version=comp.get("version"),
                supplier=comp.get("supplier", {}).get("name"),
                description=comp.get("description"),
                homepage=comp.get("homepage"),
                package_url=comp.get("purl"),
                external_references=comp.get("externalReferences", []),
                hashes=self._extract_cyclonedx_hashes(comp.get("hashes", [])),
                licenses=licenses
            )
            components.append(component)
        
        return components
    
    async def _extract_spdx_tag_value_components(self, parsed_content: Dict[str, Any]) -> List[ComponentModel]:
        """Extract components from SPDX tag-value format."""
        components = []
        
        packages = parsed_content.get("packages", [])
        for package in packages:
            component = create_component(
                name=package.get("name", "unknown"),
                component_type=ComponentType.OTHER,
                version=package.get("packageversion"),
                supplier=package.get("packagesupplier"),
                description=package.get("packagedescription"),
                homepage=package.get("packagehomepage"),
                download_location=package.get("packagedownloadlocation")
            )
            components.append(component)
        
        return components
    
    async def _extract_syft_components(self, parsed_content: Dict[str, Any]) -> List[ComponentModel]:
        """Extract components from Syft format."""
        components = []
        
        artifacts = parsed_content.get("artifacts", [])
        for artifact in artifacts:
            component = create_component(
                name=artifact.get("name", "unknown"),
                component_type=self._map_component_type(artifact.get("type", "unknown")),
                version=artifact.get("version"),
                package_url=artifact.get("purl"),
                properties=artifact.get("metadata", {})
            )
            components.append(component)
        
        return components
    
    def _map_component_type(self, type_str: str) -> ComponentType:
        """Map component type string to enum."""
        return self.component_type_mappings.get(type_str.upper(), ComponentType.OTHER)
    
    def _extract_hashes(self, checksums: List[Dict[str, str]]) -> Dict[str, str]:
        """Extract hashes from SPDX checksums."""
        hashes = {}
        for checksum in checksums:
            algorithm = checksum.get("algorithm", "").lower()
            value = checksum.get("checksumValue", "")
            if algorithm and value:
                hashes[algorithm] = value
        return hashes
    
    def _extract_cyclonedx_hashes(self, hashes_list: List[Dict[str, str]]) -> Dict[str, str]:
        """Extract hashes from CycloneDX format."""
        hashes = {}
        for hash_item in hashes_list:
            algorithm = hash_item.get("alg", "").lower()
            value = hash_item.get("content", "")
            if algorithm and value:
                hashes[algorithm] = value
        return hashes
    
    def _extract_licenses(self, concluded: Optional[str], declared: Optional[str]) -> List[LicenseModel]:
        """Extract licenses from SPDX license fields."""
        licenses = []
        
        if concluded and concluded != "NOASSERTION":
            licenses.append(create_license(name=concluded))
        
        if declared and declared != "NOASSERTION" and declared != concluded:
            licenses.append(create_license(name=declared))
        
        return licenses
    
    async def _enrich_components_with_vulnerabilities(self, sbom: SBOMDocument):
        """Enrich components with vulnerability information."""
        try:
            # This would integrate with vulnerability databases
            # For now, we'll simulate vulnerability enrichment
            
            for component in sbom.components:
                # Simulate vulnerability lookup
                if component.name in ["log4j", "spring-core", "jackson-databind"]:
                    vuln = create_vulnerability(
                        vuln_id=f"CVE-2021-{hash(component.name) % 10000}",
                        severity="high",
                        description=f"Vulnerability in {component.name}",
                        published_date=datetime.now()
                    )
                    component.vulnerabilities.append(vuln)
            
            logger.debug(f"Enriched {len(sbom.components)} components with vulnerability data")
            
        except Exception as e:
            logger.error(f"Error enriching components with vulnerabilities: {e}")
    
    async def _analyze_licenses(self, sbom: SBOMDocument):
        """Analyze licenses for compliance risks."""
        try:
            license_risks = []
            
            for component in sbom.components:
                for license in component.licenses:
                    if license.name:
                        # Check for problematic licenses
                        if any(risky in license.name.lower() for risky in ["gpl", "agpl", "copyleft"]):
                            license_risks.append(f"Copyleft license detected: {license.name}")
            
            sbom.license_risks = license_risks
            
            logger.debug(f"Analyzed licenses, found {len(license_risks)} risks")
            
        except Exception as e:
            logger.error(f"Error analyzing licenses: {e}")
    
    async def _generate_security_metrics(self, sbom: SBOMDocument):
        """Generate security metrics for the SBOM."""
        try:
            total_components = len(sbom.components)
            vulnerable_components = sum(1 for c in sbom.components if c.vulnerabilities)
            
            high_severity_vulns = 0
            medium_severity_vulns = 0
            low_severity_vulns = 0
            
            for component in sbom.components:
                for vuln in component.vulnerabilities:
                    severity = vuln.severity.lower()
                    if severity in ["high", "critical"]:
                        high_severity_vulns += 1
                    elif severity == "medium":
                        medium_severity_vulns += 1
                    elif severity == "low":
                        low_severity_vulns += 1
            
            # Update SBOM metrics
            sbom.total_components = total_components
            sbom.vulnerable_components = vulnerable_components
            sbom.high_severity_vulnerabilities = high_severity_vulns
            sbom.medium_severity_vulnerabilities = medium_severity_vulns
            sbom.low_severity_vulnerabilities = low_severity_vulns
            
            logger.debug(f"Generated security metrics: {total_components} components, {vulnerable_components} vulnerable")
            
        except Exception as e:
            logger.error(f"Error generating security metrics: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            "supported_formats": list(self.format_parsers.keys()),
            "component_types": list(self.component_type_mappings.keys()),
            "processors": [
                "parse_sbom_content", "extract_components", "enrich_vulnerabilities",
                "analyze_licenses", "generate_security_metrics"
            ]
        }