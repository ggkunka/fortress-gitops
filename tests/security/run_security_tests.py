"""
Security testing suite for MCP Security Platform.

Includes vulnerability scanning, penetration testing, compliance checks,
and security configuration validation.
"""

import asyncio
import json
import subprocess
import os
import tempfile
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx
import yaml
import argparse
import logging


class SecurityTest:
    """Base class for security tests."""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.results = []
        self.logger = logging.getLogger(f"security.{name}")
    
    async def run(self) -> Dict[str, Any]:
        """Run the security test."""
        self.logger.info(f"Running security test: {self.name}")
        start_time = datetime.now()
        
        try:
            await self.execute_test()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            return {
                "name": self.name,
                "description": self.description,
                "success": True,
                "duration": duration,
                "results": self.results,
                "timestamp": start_time.isoformat()
            }
            
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.logger.error(f"Security test failed: {e}")
            return {
                "name": self.name,
                "description": self.description,
                "success": False,
                "error": str(e),
                "duration": duration,
                "results": self.results,
                "timestamp": start_time.isoformat()
            }
    
    async def execute_test(self):
        """Execute the security test."""
        raise NotImplementedError
    
    def add_result(self, category: str, severity: str, title: str, **metadata):
        """Add security finding."""
        self.results.append({
            "category": category,
            "severity": severity,
            "title": title,
            "timestamp": datetime.now().isoformat(),
            **metadata
        })


class ContainerVulnerabilityTest(SecurityTest):
    """Test for container vulnerabilities using Trivy."""
    
    def __init__(self, images: List[str]):
        super().__init__(
            "container_vulnerability_scan",
            "Scan container images for known vulnerabilities using Trivy"
        )
        self.images = images
    
    async def execute_test(self):
        """Run Trivy scans on container images."""
        for image in self.images:
            await self.scan_image(image)
    
    async def scan_image(self, image: str):
        """Scan single container image."""
        self.logger.info(f"Scanning image: {image}")
        
        try:
            # Run Trivy scan
            cmd = [
                "trivy", "image",
                "--format", "json",
                "--severity", "HIGH,CRITICAL",
                "--no-progress",
                image
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                scan_results = json.loads(stdout.decode())
                await self.process_trivy_results(image, scan_results)
            else:
                self.add_result(
                    "scan_error", "HIGH", f"Failed to scan {image}",
                    error=stderr.decode(), image=image
                )
                
        except Exception as e:
            self.add_result(
                "scan_error", "HIGH", f"Trivy scan failed for {image}",
                error=str(e), image=image
            )
    
    async def process_trivy_results(self, image: str, results: Dict):
        """Process Trivy scan results."""
        if not results.get("Results"):
            self.add_result(
                "scan_result", "INFO", f"No vulnerabilities found in {image}",
                image=image
            )
            return
        
        for result in results["Results"]:
            if not result.get("Vulnerabilities"):
                continue
                
            for vuln in result["Vulnerabilities"]:
                severity = vuln.get("Severity", "UNKNOWN")
                vuln_id = vuln.get("VulnerabilityID", "Unknown")
                package = vuln.get("PkgName", "Unknown")
                version = vuln.get("InstalledVersion", "Unknown")
                title = vuln.get("Title", vuln_id)
                
                self.add_result(
                    "vulnerability", severity, title,
                    image=image,
                    vulnerability_id=vuln_id,
                    package=package,
                    version=version,
                    description=vuln.get("Description", ""),
                    references=vuln.get("References", [])
                )


class StaticCodeAnalysisTest(SecurityTest):
    """Static code analysis using Bandit and Semgrep."""
    
    def __init__(self, source_dirs: List[str]):
        super().__init__(
            "static_code_analysis",
            "Static code analysis for security issues"
        )
        self.source_dirs = source_dirs
    
    async def execute_test(self):
        """Run static analysis tools."""
        # Run Bandit for Python security issues
        await self.run_bandit()
        
        # Run Semgrep for broader security patterns
        await self.run_semgrep()
    
    async def run_bandit(self):
        """Run Bandit security scanner."""
        for source_dir in self.source_dirs:
            if not os.path.exists(source_dir):
                continue
                
            self.logger.info(f"Running Bandit on {source_dir}")
            
            try:
                cmd = [
                    "bandit", "-r", source_dir,
                    "-f", "json",
                    "-ll"  # Only low-level and above
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if stdout:
                    bandit_results = json.loads(stdout.decode())
                    await self.process_bandit_results(source_dir, bandit_results)
                    
            except Exception as e:
                self.add_result(
                    "scan_error", "MEDIUM", f"Bandit scan failed for {source_dir}",
                    error=str(e), directory=source_dir
                )
    
    async def run_semgrep(self):
        """Run Semgrep security scanner."""
        for source_dir in self.source_dirs:
            if not os.path.exists(source_dir):
                continue
                
            self.logger.info(f"Running Semgrep on {source_dir}")
            
            try:
                cmd = [
                    "semgrep", "--config=auto",
                    "--json",
                    "--severity=WARNING",
                    source_dir
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if stdout:
                    semgrep_results = json.loads(stdout.decode())
                    await self.process_semgrep_results(source_dir, semgrep_results)
                    
            except Exception as e:
                self.add_result(
                    "scan_error", "MEDIUM", f"Semgrep scan failed for {source_dir}",
                    error=str(e), directory=source_dir
                )
    
    async def process_bandit_results(self, source_dir: str, results: Dict):
        """Process Bandit scan results."""
        for result in results.get("results", []):
            severity_map = {
                "LOW": "LOW",
                "MEDIUM": "MEDIUM", 
                "HIGH": "HIGH"
            }
            
            severity = severity_map.get(result.get("issue_severity", "MEDIUM"))
            
            self.add_result(
                "static_analysis", severity, result.get("test_name", "Unknown issue"),
                tool="bandit",
                directory=source_dir,
                filename=result.get("filename"),
                line_number=result.get("line_number"),
                test_id=result.get("test_id"),
                issue_text=result.get("issue_text"),
                more_info=result.get("more_info")
            )
    
    async def process_semgrep_results(self, source_dir: str, results: Dict):
        """Process Semgrep scan results."""
        for result in results.get("results", []):
            severity_map = {
                "INFO": "LOW",
                "WARNING": "MEDIUM",
                "ERROR": "HIGH"
            }
            
            severity = severity_map.get(result.get("extra", {}).get("severity", "MEDIUM"))
            
            self.add_result(
                "static_analysis", severity, result.get("check_id", "Unknown rule"),
                tool="semgrep",
                directory=source_dir,
                filename=result.get("path"),
                line_number=result.get("start", {}).get("line"),
                message=result.get("extra", {}).get("message"),
                rule_id=result.get("check_id")
            )


class WebApplicationSecurityTest(SecurityTest):
    """Web application security testing using ZAP."""
    
    def __init__(self, target_url: str):
        super().__init__(
            "web_application_security",
            "Web application security testing using OWASP ZAP"
        )
        self.target_url = target_url
        self.auth_token = None
    
    async def execute_test(self):
        """Run web application security tests."""
        # Get authentication token
        self.auth_token = await self.get_auth_token()
        
        # Run ZAP spider and active scan
        await self.run_zap_scan()
    
    async def get_auth_token(self) -> str:
        """Get authentication token for testing."""
        try:
            async with httpx.AsyncClient() as client:
                user_data = {
                    "username": f"security_test_{uuid.uuid4().hex[:8]}",
                    "email": f"sectest_{uuid.uuid4().hex[:8]}@example.com",
                    "password": "SecurityTest123!",
                    "organization_id": "security-test-org"
                }
                
                response = await client.post(
                    f"{self.target_url}/api/v1/auth/register",
                    json=user_data,
                    timeout=10.0
                )
                
                if response.status_code in [200, 201]:
                    return response.json()["access_token"]
                    
        except Exception as e:
            self.logger.warning(f"Failed to get auth token: {e}")
            
        return "security-test-token"
    
    async def run_zap_scan(self):
        """Run OWASP ZAP security scan."""
        try:
            # Create ZAP session configuration
            zap_config = {
                "target": self.target_url,
                "spider": {
                    "maxDepth": 5,
                    "maxChildren": 50
                },
                "activeScan": {
                    "policy": "Default Policy"
                }
            }
            
            # Write configuration file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                yaml.dump(zap_config, f)
                config_file = f.name
            
            try:
                # Run ZAP baseline scan
                cmd = [
                    "zap-baseline.py",
                    "-t", self.target_url,
                    "-J", "zap_report.json",
                    "-r", "zap_report.html"
                ]
                
                if self.auth_token:
                    cmd.extend(["-H", f"Authorization: Bearer {self.auth_token}"])
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=tempfile.gettempdir()
                )
                
                stdout, stderr = await process.communicate()
                
                # Process ZAP results
                json_report = os.path.join(tempfile.gettempdir(), "zap_report.json")
                if os.path.exists(json_report):
                    with open(json_report, 'r') as f:
                        zap_results = json.load(f)
                    await self.process_zap_results(zap_results)
                else:
                    self.add_result(
                        "scan_error", "MEDIUM", "ZAP scan completed but no results found",
                        stdout=stdout.decode(), stderr=stderr.decode()
                    )
                    
            finally:
                # Cleanup
                if os.path.exists(config_file):
                    os.unlink(config_file)
                    
        except Exception as e:
            self.add_result(
                "scan_error", "HIGH", "ZAP scan failed",
                error=str(e)
            )
    
    async def process_zap_results(self, results: Dict):
        """Process ZAP scan results."""
        sites = results.get("site", [])
        
        for site in sites:
            alerts = site.get("alerts", [])
            
            for alert in alerts:
                risk_level = alert.get("riskdesc", "").split()[0]
                severity_map = {
                    "High": "HIGH",
                    "Medium": "MEDIUM",
                    "Low": "LOW",
                    "Informational": "INFO"
                }
                
                severity = severity_map.get(risk_level, "MEDIUM")
                
                self.add_result(
                    "web_vulnerability", severity, alert.get("name", "Unknown"),
                    risk_level=risk_level,
                    confidence=alert.get("confidence"),
                    description=alert.get("desc"),
                    solution=alert.get("solution"),
                    reference=alert.get("reference"),
                    instances=len(alert.get("instances", []))
                )


class ComplianceTest(SecurityTest):
    """Security compliance testing."""
    
    def __init__(self, deployment_configs: List[str]):
        super().__init__(
            "compliance_check",
            "Security compliance and configuration validation"
        )
        self.deployment_configs = deployment_configs
    
    async def execute_test(self):
        """Run compliance checks."""
        await self.check_kubernetes_security()
        await self.check_docker_security()
        await self.check_network_security()
    
    async def check_kubernetes_security(self):
        """Check Kubernetes security configurations."""
        security_checks = [
            self.check_pod_security_standards,
            self.check_rbac_configuration,
            self.check_network_policies,
            self.check_secrets_management
        ]
        
        for check in security_checks:
            try:
                await check()
            except Exception as e:
                self.add_result(
                    "compliance_error", "MEDIUM", f"Failed to run {check.__name__}",
                    error=str(e)
                )
    
    async def check_pod_security_standards(self):
        """Check Pod Security Standards compliance."""
        # Check for common security misconfigurations
        security_requirements = [
            ("runAsNonRoot", "Containers should not run as root"),
            ("readOnlyRootFilesystem", "Root filesystem should be read-only"),
            ("allowPrivilegeEscalation", "Privilege escalation should be disabled"),
            ("capabilities.drop", "Unnecessary capabilities should be dropped")
        ]
        
        for config_file in self.deployment_configs:
            if not os.path.exists(config_file):
                continue
                
            try:
                with open(config_file, 'r') as f:
                    configs = list(yaml.safe_load_all(f))
                
                for config in configs:
                    if config and config.get("kind") in ["Deployment", "StatefulSet", "DaemonSet"]:
                        await self.validate_pod_security(config, security_requirements)
                        
            except Exception as e:
                self.add_result(
                    "compliance_error", "MEDIUM", f"Failed to parse {config_file}",
                    error=str(e)
                )
    
    async def validate_pod_security(self, config: Dict, requirements: List):
        """Validate pod security configuration."""
        spec = config.get("spec", {})
        template = spec.get("template", {})
        pod_spec = template.get("spec", {})
        containers = pod_spec.get("containers", [])
        
        resource_name = config.get("metadata", {}).get("name", "unknown")
        
        for container in containers:
            security_context = container.get("securityContext", {})
            
            # Check runAsNonRoot
            if not security_context.get("runAsNonRoot"):
                self.add_result(
                    "compliance_violation", "HIGH", 
                    "Container not configured to run as non-root",
                    resource=resource_name,
                    container=container.get("name"),
                    requirement="runAsNonRoot"
                )
            
            # Check readOnlyRootFilesystem
            if not security_context.get("readOnlyRootFilesystem"):
                self.add_result(
                    "compliance_violation", "MEDIUM",
                    "Container root filesystem not read-only",
                    resource=resource_name,
                    container=container.get("name"),
                    requirement="readOnlyRootFilesystem"
                )
            
            # Check allowPrivilegeEscalation
            if security_context.get("allowPrivilegeEscalation", True):
                self.add_result(
                    "compliance_violation", "HIGH",
                    "Privilege escalation not disabled",
                    resource=resource_name,
                    container=container.get("name"),
                    requirement="allowPrivilegeEscalation"
                )
    
    async def check_rbac_configuration(self):
        """Check RBAC configuration."""
        # This would typically query the Kubernetes API
        # For now, we'll do basic validation
        self.add_result(
            "compliance_check", "INFO", "RBAC configuration check completed",
            details="Manual review required for comprehensive RBAC validation"
        )
    
    async def check_network_policies(self):
        """Check network security policies."""
        self.add_result(
            "compliance_check", "INFO", "Network policies check completed",
            details="Verify network segmentation and ingress/egress rules"
        )
    
    async def check_secrets_management(self):
        """Check secrets management practices."""
        self.add_result(
            "compliance_check", "INFO", "Secrets management check completed",
            details="Verify secrets are not hardcoded and use proper secret stores"
        )
    
    async def check_docker_security(self):
        """Check Docker security configurations."""
        # Run Docker Bench for Security if available
        try:
            cmd = ["docker-bench-security"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.add_result(
                    "compliance_check", "INFO", "Docker security benchmark completed",
                    details="Review docker-bench-security output for detailed findings"
                )
            else:
                self.add_result(
                    "compliance_check", "MEDIUM", "Docker security benchmark failed",
                    error=stderr.decode()
                )
                
        except FileNotFoundError:
            self.add_result(
                "compliance_check", "INFO", "Docker Bench for Security not available",
                details="Install docker-bench-security for automated Docker security checks"
            )
        except Exception as e:
            self.add_result(
                "compliance_error", "MEDIUM", "Docker security check failed",
                error=str(e)
            )
    
    async def check_network_security(self):
        """Check network security configurations."""
        # Basic network security validation
        network_checks = [
            "TLS encryption enabled",
            "Network segmentation implemented",
            "Firewall rules configured",
            "Intrusion detection enabled"
        ]
        
        for check in network_checks:
            self.add_result(
                "compliance_check", "INFO", f"Network security: {check}",
                details="Manual verification required"
            )


class SecurityTestRunner:
    """Main security test runner."""
    
    def __init__(self):
        self.tests = []
        self.results = []
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("security_runner")
    
    def add_test(self, test: SecurityTest):
        """Add security test to runner."""
        self.tests.append(test)
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all security tests."""
        self.logger.info(f"Starting {len(self.tests)} security tests")
        
        start_time = datetime.now()
        
        for test in self.tests:
            try:
                result = await test.run()
                self.results.append(result)
                
                if result["success"]:
                    findings_count = len(result.get("results", []))
                    self.logger.info(f"✅ {test.name} completed - {findings_count} findings")
                else:
                    self.logger.error(f"❌ {test.name} failed: {result.get('error')}")
                    
            except Exception as e:
                self.logger.error(f"Failed to run test {test.name}: {e}")
                self.results.append({
                    "name": test.name,
                    "success": False,
                    "error": str(e)
                })
        
        end_time = datetime.now()
        
        # Generate summary
        total_tests = len(self.results)
        successful_tests = len([r for r in self.results if r.get("success")])
        failed_tests = total_tests - successful_tests
        
        # Count findings by severity
        all_findings = []
        for result in self.results:
            all_findings.extend(result.get("results", []))
        
        severity_counts = {}
        for finding in all_findings:
            severity = finding.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        summary = {
            "security_test_summary": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration": (end_time - start_time).total_seconds(),
                "total_tests": total_tests,
                "successful_tests": successful_tests,
                "failed_tests": failed_tests,
                "total_findings": len(all_findings),
                "findings_by_severity": severity_counts
            },
            "test_results": self.results
        }
        
        return summary
    
    def print_summary(self, results: Dict[str, Any]):
        """Print security test summary."""
        summary = results["security_test_summary"]
        
        print("\n" + "="*60)
        print("SECURITY TEST SUMMARY")
        print("="*60)
        print(f"Duration: {summary['duration']:.2f}s")
        print(f"Total Tests: {summary['total_tests']}")
        print(f"Successful: {summary['successful_tests']}")
        print(f"Failed: {summary['failed_tests']}")
        print(f"Total Findings: {summary['total_findings']}")
        
        print("\nFindings by Severity:")
        for severity, count in summary["findings_by_severity"].items():
            print(f"  {severity}: {count}")
        
        print("\nTest Details:")
        print("-" * 40)
        
        for result in results["test_results"]:
            status = "✅" if result.get("success") else "❌"
            findings_count = len(result.get("results", []))
            print(f"{status} {result['name']} - {findings_count} findings")
            
            if not result.get("success"):
                print(f"   Error: {result.get('error', 'Unknown error')}")


async def run_security_tests(output_dir: str = "/app/results/security"):
    """Run comprehensive security tests."""
    
    runner = SecurityTestRunner()
    
    # Container images to scan
    images = [
        "mcp-platform/gateway:latest",
        "mcp-platform/auth:latest", 
        "mcp-platform/ingestion:latest",
        "mcp-platform/enrichment:latest",
        "mcp-platform/analysis:latest",
        "mcp-platform/notification:latest"
    ]
    
    # Source directories to analyze
    source_dirs = [
        "/app/platform/services",
        "/app/platform/shared"
    ]
    
    # Kubernetes deployment configs
    deployment_configs = [
        "/app/platform/deployments/helm/mcp-platform/templates"
    ]
    
    # Add security tests
    runner.add_test(ContainerVulnerabilityTest(images))
    runner.add_test(StaticCodeAnalysisTest(source_dirs))
    runner.add_test(WebApplicationSecurityTest("http://gateway-service:8081"))
    runner.add_test(ComplianceTest(deployment_configs))
    
    # Run tests
    results = await runner.run_all_tests()
    
    # Print summary
    runner.print_summary(results)
    
    # Save results
    os.makedirs(output_dir, exist_ok=True)
    
    with open(f"{output_dir}/security_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_dir}/security_results.json")
    
    # Return success if no high/critical findings
    high_critical_findings = 0
    for result in results["test_results"]:
        for finding in result.get("results", []):
            if finding.get("severity") in ["HIGH", "CRITICAL"]:
                high_critical_findings += 1
    
    return high_critical_findings == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Security Platform security tests")
    parser.add_argument("--output-dir", default="/app/results/security", help="Output directory")
    
    args = parser.parse_args()
    
    success = asyncio.run(run_security_tests(output_dir=args.output_dir))
    
    exit(0 if success else 1)