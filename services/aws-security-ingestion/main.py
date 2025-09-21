#!/usr/bin/env python3
"""
Fortress CNAPP - AWS Security Hub Integration
Real production integration with AWS Security Hub, Config, GuardDuty
"""

import asyncio
import json
import boto3
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import structlog
from kafka import KafkaProducer

logger = structlog.get_logger()

class AWSSecurityEvent(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    resource_id: str
    resource_type: str
    region: str
    account_id: str
    compliance_status: str
    title: str
    description: str
    remediation: Dict[str, Any]
    first_observed: datetime
    last_observed: datetime

class AWSSecurityIngestion:
    def __init__(self):
        self.security_hub = boto3.client('securityhub')
        self.config_client = boto3.client('config')
        self.guardduty = boto3.client('guardduty')
        self.inspector = boto3.client('inspector2')
        self.kafka_producer = KafkaProducer(
            bootstrap_servers=['kafka:9092'],
            value_serializer=lambda v: json.dumps(v, default=str).encode('utf-8')
        )
        
    async def collect_security_hub_findings(self) -> List[AWSSecurityEvent]:
        """Collect real findings from AWS Security Hub"""
        events = []
        
        try:
            paginator = self.security_hub.get_paginator('get_findings')
            
            for page in paginator.paginate(
                Filters={
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                    'WorkflowStatus': [{'Value': 'NEW', 'Comparison': 'EQUALS'}]
                }
            ):
                for finding in page['Findings']:
                    event = AWSSecurityEvent(
                        finding_id=finding['Id'],
                        finding_type=finding.get('Types', ['Unknown'])[0],
                        severity=finding.get('Severity', {}).get('Label', 'MEDIUM'),
                        resource_id=finding.get('Resources', [{}])[0].get('Id', ''),
                        resource_type=finding.get('Resources', [{}])[0].get('Type', ''),
                        region=finding.get('Region', ''),
                        account_id=finding.get('AwsAccountId', ''),
                        compliance_status=finding.get('Compliance', {}).get('Status', 'UNKNOWN'),
                        title=finding.get('Title', ''),
                        description=finding.get('Description', ''),
                        remediation=finding.get('Remediation', {}),
                        first_observed=datetime.fromisoformat(finding.get('FirstObservedAt', '').replace('Z', '+00:00')),
                        last_observed=datetime.fromisoformat(finding.get('LastObservedAt', '').replace('Z', '+00:00'))
                    )
                    events.append(event)
                    
            logger.info(f"Collected {len(events)} Security Hub findings")
            return events
            
        except Exception as e:
            logger.error(f"Failed to collect Security Hub findings: {e}")
            return []
    
    async def collect_config_compliance(self) -> List[Dict[str, Any]]:
        """Collect AWS Config compliance data"""
        try:
            response = self.config_client.describe_compliance_by_config_rule()
            compliance_data = []
            
            for rule in response.get('ComplianceByConfigRules', []):
                compliance_data.append({
                    'rule_name': rule.get('ConfigRuleName'),
                    'compliance_type': rule.get('Compliance', {}).get('ComplianceType'),
                    'resource_count': rule.get('Compliance', {}).get('ComplianceContributorCount', {})
                })
                
            return compliance_data
            
        except Exception as e:
            logger.error(f"Failed to collect Config compliance: {e}")
            return []
    
    async def collect_guardduty_findings(self) -> List[Dict[str, Any]]:
        """Collect GuardDuty threat detection findings"""
        try:
            detectors = self.guardduty.list_detectors()
            findings = []
            
            for detector_id in detectors.get('DetectorIds', []):
                response = self.guardduty.list_findings(DetectorId=detector_id)
                finding_ids = response.get('FindingIds', [])
                
                if finding_ids:
                    details = self.guardduty.get_findings(
                        DetectorId=detector_id,
                        FindingIds=finding_ids[:50]  # Limit batch size
                    )
                    
                    for finding in details.get('Findings', []):
                        findings.append({
                            'finding_id': finding.get('Id'),
                            'type': finding.get('Type'),
                            'severity': finding.get('Severity'),
                            'region': finding.get('Region'),
                            'service': finding.get('Service', {}),
                            'resource': finding.get('Resource', {}),
                            'created_at': finding.get('CreatedAt'),
                            'updated_at': finding.get('UpdatedAt')
                        })
            
            return findings
            
        except Exception as e:
            logger.error(f"Failed to collect GuardDuty findings: {e}")
            return []
    
    async def publish_events(self, events: List[AWSSecurityEvent]):
        """Publish events to Kafka topics"""
        for event in events:
            try:
                topic = f"fortress.aws.{event.finding_type.lower().replace(' ', '_')}"
                self.kafka_producer.send(topic, value=event.dict())
                
            except Exception as e:
                logger.error(f"Failed to publish event {event.finding_id}: {e}")

# FastAPI Application
app = FastAPI(title="Fortress AWS Security Ingestion", version="1.0.0")
aws_ingestion = AWSSecurityIngestion()

@app.post("/collect/security-hub")
async def collect_security_hub(background_tasks: BackgroundTasks):
    """Trigger Security Hub data collection"""
    background_tasks.add_task(collect_and_publish_security_hub)
    return {"status": "started", "message": "Security Hub collection initiated"}

@app.post("/collect/all-aws")
async def collect_all_aws_data(background_tasks: BackgroundTasks):
    """Collect all AWS security data"""
    background_tasks.add_task(collect_all_aws_security_data)
    return {"status": "started", "message": "Full AWS security data collection initiated"}

async def collect_and_publish_security_hub():
    """Background task to collect and publish Security Hub data"""
    events = await aws_ingestion.collect_security_hub_findings()
    await aws_ingestion.publish_events(events)

async def collect_all_aws_security_data():
    """Collect all AWS security data sources"""
    # Security Hub findings
    security_events = await aws_ingestion.collect_security_hub_findings()
    await aws_ingestion.publish_events(security_events)
    
    # Config compliance
    config_data = await aws_ingestion.collect_config_compliance()
    
    # GuardDuty findings
    guardduty_data = await aws_ingestion.collect_guardduty_findings()
    
    logger.info(f"Collected: {len(security_events)} Security Hub, {len(config_data)} Config, {len(guardduty_data)} GuardDuty")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "aws-security-ingestion"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
