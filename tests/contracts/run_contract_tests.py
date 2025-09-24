"""
Contract testing for MCP Security Platform using Pact.

Tests service-to-service communication contracts to ensure
compatibility and prevent breaking changes.
"""

import asyncio
import json
import os
import tempfile
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
import httpx
import pact
from pact import Consumer, Provider, Term, Like, EachLike
import argparse
import logging


class ContractTest:
    """Base class for contract tests."""
    
    def __init__(self, consumer: str, provider: str):
        self.consumer = consumer
        self.provider = provider
        self.pact = None
        self.results = []
        self.logger = logging.getLogger(f"contract.{consumer}.{provider}")
    
    async def setup_pact(self, pact_dir: str = "/tmp/pacts"):
        """Setup Pact for contract testing."""
        os.makedirs(pact_dir, exist_ok=True)
        
        self.pact = Consumer(self.consumer).has_pact_with(
            Provider(self.provider),
            host_name='localhost',
            port=1234,
            pact_dir=pact_dir
        )
        self.pact.start()
    
    async def teardown_pact(self):
        """Teardown Pact."""
        if self.pact:
            self.pact.stop()
    
    async def run_contract_test(self) -> Dict[str, Any]:
        """Run contract test."""
        start_time = datetime.now()
        
        try:
            await self.setup_pact()
            await self.define_contract()
            await self.test_contract()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            return {
                "consumer": self.consumer,
                "provider": self.provider,
                "success": True,
                "duration": duration,
                "results": self.results,
                "timestamp": start_time.isoformat()
            }
            
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.logger.error(f"Contract test failed: {e}")
            return {
                "consumer": self.consumer,
                "provider": self.provider,
                "success": False,
                "error": str(e),
                "duration": duration,
                "results": self.results,
                "timestamp": start_time.isoformat()
            }
        finally:
            await self.teardown_pact()
    
    async def define_contract(self):
        """Define the contract between consumer and provider."""
        raise NotImplementedError
    
    async def test_contract(self):
        """Test the contract."""
        raise NotImplementedError
    
    def add_result(self, interaction: str, success: bool, **metadata):
        """Add test result."""
        self.results.append({
            "interaction": interaction,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            **metadata
        })


class GatewayAuthServiceContract(ContractTest):
    """Contract test between Gateway and Auth Service."""
    
    def __init__(self):
        super().__init__("gateway-service", "auth-service")
    
    async def define_contract(self):
        """Define contract for Gateway -> Auth Service interactions."""
        
        # Contract for token validation
        (
            self.pact
            .given("a valid JWT token exists")
            .upon_receiving("a request to validate token")
            .with_request(
                method="POST",
                path="/api/v1/auth/validate",
                headers={"Content-Type": "application/json"},
                body={
                    "token": Term(
                        matcher=r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
                        generate="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                    )
                }
            )
            .will_respond_with(200, body={
                "valid": True,
                "user_id": Like("user-123"),
                "username": Like("testuser"),
                "organization_id": Like("org-456"),
                "permissions": EachLike("read:data"),
                "expires_at": Term(
                    matcher=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*$",
                    generate="2024-12-31T23:59:59Z"
                )
            })
        )
        
        # Contract for user authentication
        (
            self.pact
            .given("user credentials are valid")
            .upon_receiving("a request to authenticate user")
            .with_request(
                method="POST",
                path="/api/v1/auth/login",
                headers={"Content-Type": "application/json"},
                body={
                    "username": Like("testuser"),
                    "password": Like("password123")
                }
            )
            .will_respond_with(200, body={
                "access_token": Term(
                    matcher=r"^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
                    generate="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                ),
                "token_type": "Bearer",
                "expires_in": Like(3600),
                "user_id": Like("user-123"),
                "username": Like("testuser")
            })
        )
    
    async def test_contract(self):
        """Test the defined contract."""
        async with httpx.AsyncClient() as client:
            
            # Test token validation
            try:
                response = await client.post(
                    f"http://localhost:1234/api/v1/auth/validate",
                    json={
                        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
                    },
                    headers={"Content-Type": "application/json"}
                )
                
                self.add_result("validate_token", response.status_code == 200,
                              status_code=response.status_code)
                
            except Exception as e:
                self.add_result("validate_token", False, error=str(e))
            
            # Test user authentication
            try:
                response = await client.post(
                    f"http://localhost:1234/api/v1/auth/login",
                    json={
                        "username": "testuser",
                        "password": "password123"
                    },
                    headers={"Content-Type": "application/json"}
                )
                
                self.add_result("authenticate_user", response.status_code == 200,
                              status_code=response.status_code)
                
            except Exception as e:
                self.add_result("authenticate_user", False, error=str(e))


class GatewayIngestionServiceContract(ContractTest):
    """Contract test between Gateway and Ingestion Service."""
    
    def __init__(self):
        super().__init__("gateway-service", "ingestion-service")
    
    async def define_contract(self):
        """Define contract for Gateway -> Ingestion Service interactions."""
        
        # Contract for SBOM ingestion
        (
            self.pact
            .given("ingestion service is available")
            .upon_receiving("a request to ingest SBOM data")
            .with_request(
                method="POST",
                path="/api/v1/ingestion/sbom",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": Term(
                        matcher=r"^Bearer .+$",
                        generate="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    )
                },
                body={
                    "data_type": "sbom",
                    "source": Like("test-scanner"),
                    "correlation_id": Term(
                        matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                        generate=str(uuid.uuid4())
                    ),
                    "data": {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.4",
                        "version": Like(1),
                        "components": EachLike({
                            "type": "library",
                            "name": Like("test-component"),
                            "version": Like("1.0.0")
                        })
                    }
                }
            )
            .will_respond_with(202, body={
                "ingestion_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                ),
                "status": "accepted",
                "message": Like("SBOM data queued for processing"),
                "correlation_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                )
            })
        )
        
        # Contract for CVE ingestion
        (
            self.pact
            .given("ingestion service is available")
            .upon_receiving("a request to ingest CVE data")
            .with_request(
                method="POST",
                path="/api/v1/ingestion/cve",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": Term(
                        matcher=r"^Bearer .+$",
                        generate="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    )
                },
                body={
                    "data_type": "cve",
                    "source": Like("nvd-feed"),
                    "correlation_id": Term(
                        matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                        generate=str(uuid.uuid4())
                    ),
                    "data": {
                        "cve_id": Term(
                            matcher=r"^CVE-\d{4}-\d{4,}$",
                            generate="CVE-2023-12345"
                        ),
                        "description": Like("Test CVE description"),
                        "severity": Term(
                            matcher=r"^(LOW|MEDIUM|HIGH|CRITICAL)$",
                            generate="HIGH"
                        ),
                        "cvss_score": Like(8.5)
                    }
                }
            )
            .will_respond_with(202, body={
                "ingestion_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                ),
                "status": "accepted",
                "message": Like("CVE data queued for processing"),
                "correlation_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                )
            })
        )
    
    async def test_contract(self):
        """Test the defined contract."""
        async with httpx.AsyncClient() as client:
            
            # Test SBOM ingestion
            try:
                correlation_id = str(uuid.uuid4())
                response = await client.post(
                    f"http://localhost:1234/api/v1/ingestion/sbom",
                    json={
                        "data_type": "sbom",
                        "source": "test-scanner",
                        "correlation_id": correlation_id,
                        "data": {
                            "bomFormat": "CycloneDX",
                            "specVersion": "1.4",
                            "version": 1,
                            "components": [
                                {
                                    "type": "library",
                                    "name": "test-component",
                                    "version": "1.0.0"
                                }
                            ]
                        }
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    }
                )
                
                self.add_result("ingest_sbom", response.status_code == 202,
                              status_code=response.status_code)
                
            except Exception as e:
                self.add_result("ingest_sbom", False, error=str(e))
            
            # Test CVE ingestion
            try:
                correlation_id = str(uuid.uuid4())
                response = await client.post(
                    f"http://localhost:1234/api/v1/ingestion/cve",
                    json={
                        "data_type": "cve",
                        "source": "nvd-feed",
                        "correlation_id": correlation_id,
                        "data": {
                            "cve_id": "CVE-2023-12345",
                            "description": "Test CVE description",
                            "severity": "HIGH",
                            "cvss_score": 8.5
                        }
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                    }
                )
                
                self.add_result("ingest_cve", response.status_code == 202,
                              status_code=response.status_code)
                
            except Exception as e:
                self.add_result("ingest_cve", False, error=str(e))


class IngestionEnrichmentServiceContract(ContractTest):
    """Contract test between Ingestion and Enrichment Services."""
    
    def __init__(self):
        super().__init__("ingestion-service", "enrichment-service")
    
    async def define_contract(self):
        """Define contract for Ingestion -> Enrichment Service interactions."""
        
        # Contract for enrichment request
        (
            self.pact
            .given("enrichment service is available")
            .upon_receiving("a request to enrich security data")
            .with_request(
                method="POST",
                path="/api/v1/enrichment/enrich",
                headers={"Content-Type": "application/json"},
                body={
                    "request_id": Term(
                        matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                        generate=str(uuid.uuid4())
                    ),
                    "data_type": Term(
                        matcher=r"^(sbom|cve|runtime)$",
                        generate="sbom"
                    ),
                    "data": Like({}),
                    "enrichment_types": EachLike("threat_intelligence")
                }
            )
            .will_respond_with(202, body={
                "enrichment_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                ),
                "status": "processing",
                "request_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                ),
                "estimated_completion": Term(
                    matcher=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*$",
                    generate="2024-01-01T12:00:00Z"
                )
            })
        )
    
    async def test_contract(self):
        """Test the defined contract."""
        async with httpx.AsyncClient() as client:
            
            try:
                request_id = str(uuid.uuid4())
                response = await client.post(
                    f"http://localhost:1234/api/v1/enrichment/enrich",
                    json={
                        "request_id": request_id,
                        "data_type": "sbom",
                        "data": {"test": "data"},
                        "enrichment_types": ["threat_intelligence"]
                    },
                    headers={"Content-Type": "application/json"}
                )
                
                self.add_result("enrich_data", response.status_code == 202,
                              status_code=response.status_code)
                
            except Exception as e:
                self.add_result("enrich_data", False, error=str(e))


class EnrichmentAnalysisServiceContract(ContractTest):
    """Contract test between Enrichment and Analysis Services."""
    
    def __init__(self):
        super().__init__("enrichment-service", "analysis-service")
    
    async def define_contract(self):
        """Define contract for Enrichment -> Analysis Service interactions."""
        
        # Contract for analysis request
        (
            self.pact
            .given("analysis service is available")
            .upon_receiving("a request to analyze enriched data")
            .with_request(
                method="POST",
                path="/api/v1/analysis/analyze",
                headers={"Content-Type": "application/json"},
                body={
                    "analysis_id": Term(
                        matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                        generate=str(uuid.uuid4())
                    ),
                    "enriched_data": Like({}),
                    "analysis_types": EachLike("vulnerability_assessment"),
                    "priority": Term(
                        matcher=r"^(low|medium|high|critical)$",
                        generate="medium"
                    )
                }
            )
            .will_respond_with(202, body={
                "analysis_id": Term(
                    matcher=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    generate=str(uuid.uuid4())
                ),
                "status": "processing",
                "estimated_completion": Term(
                    matcher=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*$",
                    generate="2024-01-01T12:00:00Z"
                ),
                "analysis_types": EachLike("vulnerability_assessment")
            })
        )
    
    async def test_contract(self):
        """Test the defined contract."""
        async with httpx.AsyncClient() as client:
            
            try:
                analysis_id = str(uuid.uuid4())
                response = await client.post(
                    f"http://localhost:1234/api/v1/analysis/analyze",
                    json={
                        "analysis_id": analysis_id,
                        "enriched_data": {"test": "enriched_data"},
                        "analysis_types": ["vulnerability_assessment"],
                        "priority": "medium"
                    },
                    headers={"Content-Type": "application/json"}
                )
                
                self.add_result("analyze_data", response.status_code == 202,
                              status_code=response.status_code)
                
            except Exception as e:
                self.add_result("analyze_data", False, error=str(e))


class ContractTestRunner:
    """Main contract test runner."""
    
    def __init__(self, pact_dir: str = "/tmp/pacts"):
        self.pact_dir = pact_dir
        self.tests = []
        self.results = []
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("contract_runner")
    
    def add_test(self, test: ContractTest):
        """Add contract test to runner."""
        self.tests.append(test)
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all contract tests."""
        self.logger.info(f"Starting {len(self.tests)} contract tests")
        
        start_time = datetime.now()
        
        for test in self.tests:
            try:
                result = await test.run_contract_test()
                self.results.append(result)
                
                if result["success"]:
                    interactions = len(result.get("results", []))
                    self.logger.info(f"✅ {test.consumer} -> {test.provider} - {interactions} interactions")
                else:
                    self.logger.error(f"❌ {test.consumer} -> {test.provider} failed: {result.get('error')}")
                    
            except Exception as e:
                self.logger.error(f"Failed to run contract test {test.consumer} -> {test.provider}: {e}")
                self.results.append({
                    "consumer": test.consumer,
                    "provider": test.provider,
                    "success": False,
                    "error": str(e)
                })
        
        end_time = datetime.now()
        
        # Generate summary
        total_tests = len(self.results)
        successful_tests = len([r for r in self.results if r.get("success")])
        failed_tests = total_tests - successful_tests
        
        # Count interactions
        total_interactions = 0
        successful_interactions = 0
        
        for result in self.results:
            for interaction_result in result.get("results", []):
                total_interactions += 1
                if interaction_result.get("success"):
                    successful_interactions += 1
        
        summary = {
            "contract_test_summary": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration": (end_time - start_time).total_seconds(),
                "total_contracts": total_tests,
                "successful_contracts": successful_tests,
                "failed_contracts": failed_tests,
                "total_interactions": total_interactions,
                "successful_interactions": successful_interactions,
                "pact_files_generated": len(os.listdir(self.pact_dir)) if os.path.exists(self.pact_dir) else 0
            },
            "contract_results": self.results
        }
        
        return summary
    
    def print_summary(self, results: Dict[str, Any]):
        """Print contract test summary."""
        summary = results["contract_test_summary"]
        
        print("\n" + "="*60)
        print("CONTRACT TEST SUMMARY")
        print("="*60)
        print(f"Duration: {summary['duration']:.2f}s")
        print(f"Total Contracts: {summary['total_contracts']}")
        print(f"Successful: {summary['successful_contracts']}")
        print(f"Failed: {summary['failed_contracts']}")
        print(f"Total Interactions: {summary['total_interactions']}")
        print(f"Successful Interactions: {summary['successful_interactions']}")
        print(f"Pact Files Generated: {summary['pact_files_generated']}")
        
        print("\nContract Details:")
        print("-" * 40)
        
        for result in results["contract_results"]:
            status = "✅" if result.get("success") else "❌"
            interactions = len(result.get("results", []))
            print(f"{status} {result['consumer']} -> {result['provider']} ({interactions} interactions)")
            
            if not result.get("success"):
                print(f"   Error: {result.get('error', 'Unknown error')}")


async def run_contract_tests(output_dir: str = "/app/results/contracts"):
    """Run comprehensive contract tests."""
    
    # Setup pact directory
    pact_dir = f"{output_dir}/pacts"
    os.makedirs(pact_dir, exist_ok=True)
    
    runner = ContractTestRunner(pact_dir)
    
    # Add contract tests
    runner.add_test(GatewayAuthServiceContract())
    runner.add_test(GatewayIngestionServiceContract())
    runner.add_test(IngestionEnrichmentServiceContract())
    runner.add_test(EnrichmentAnalysisServiceContract())
    
    # Run tests
    results = await runner.run_all_tests()
    
    # Print summary
    runner.print_summary(results)
    
    # Save results
    os.makedirs(output_dir, exist_ok=True)
    
    with open(f"{output_dir}/contract_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_dir}/contract_results.json")
    print(f"Pact files saved to {pact_dir}/")
    
    # Return success if all contracts passed
    return results["contract_test_summary"]["failed_contracts"] == 0


async def verify_pacts(pact_dir: str, provider_url: str):
    """Verify Pact contracts against provider."""
    try:
        from pact import Verifier
        
        verifier = Verifier(provider=provider_url)
        
        # Get all pact files
        pact_files = [
            os.path.join(pact_dir, f) 
            for f in os.listdir(pact_dir) 
            if f.endswith('.json')
        ]
        
        if not pact_files:
            print("No pact files found for verification")
            return True
        
        print(f"Verifying {len(pact_files)} pact files against {provider_url}")
        
        # Verify each pact
        all_passed = True
        for pact_file in pact_files:
            try:
                result = verifier.verify_pacts(pact_file)
                print(f"✅ Verified: {os.path.basename(pact_file)}")
            except Exception as e:
                print(f"❌ Failed to verify {os.path.basename(pact_file)}: {e}")
                all_passed = False
        
        return all_passed
        
    except ImportError:
        print("Pact verifier not available - skipping verification")
        return True
    except Exception as e:
        print(f"Pact verification failed: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run MCP Security Platform contract tests")
    parser.add_argument("--output-dir", default="/app/results/contracts", help="Output directory")
    parser.add_argument("--verify", help="Provider URL for pact verification")
    
    args = parser.parse_args()
    
    if args.verify:
        # Verify existing pacts
        pact_dir = f"{args.output_dir}/pacts"
        success = asyncio.run(verify_pacts(pact_dir, args.verify))
    else:
        # Run contract tests
        success = asyncio.run(run_contract_tests(output_dir=args.output_dir))
    
    exit(0 if success else 1)