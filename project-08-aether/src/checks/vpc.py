"""
VPC checks:
  STR-VPC-001  Default VPC in use (has subnets/instances)
  STR-VPC-002  VPC flow logs not enabled
"""

from typing import List

import boto3
from botocore.exceptions import ClientError

from src.checks.base import BaseCheck
from src.models import Finding


class VPCChecks(BaseCheck):
    service = "VPC"

    def run(self, session: boto3.Session, region: str) -> List[Finding]:
        ec2 = session.client("ec2", region_name=region)
        findings: List[Finding] = []

        try:
            vpcs = ec2.describe_vpcs()["Vpcs"]
        except ClientError:
            return findings

        # Build a set of VPC IDs that have flow logs
        try:
            flow_logs = ec2.describe_flow_logs()["FlowLogs"]
            monitored_vpcs = {fl["ResourceId"] for fl in flow_logs}
        except ClientError:
            monitored_vpcs = set()

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            findings += self._check_default_vpc(ec2, vpc, vpc_id, region)
            findings += self._check_flow_logs(vpc_id, monitored_vpcs, region)

        return findings

    # ── STR-VPC-001 ────────────────────────────────────────────────────────────

    def _check_default_vpc(self, ec2, vpc: dict, vpc_id: str, region: str) -> List[Finding]:
        if not vpc.get("IsDefault", False):
            return []
        # Only flag if the default VPC has subnets (i.e. is in use)
        try:
            subnets = ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )["Subnets"]
            if not subnets:
                return []
        except ClientError:
            return []

        return [Finding(
            check_id="STR-VPC-001",
            title="Default VPC In Use",
            severity="low",
            service="VPC",
            resource_type="VPC",
            resource_id=vpc_id,
            region=region,
            description=(
                f"The default VPC ('{vpc_id}') in region '{region}' has subnets and is in use. "
                "Default VPCs come pre-configured with permissive settings (all subnets public, "
                "default security group allows all outbound) and are not designed for production workloads."
            ),
            recommendation=(
                "Migrate workloads to a custom VPC with private/public subnet segregation, "
                "NAT gateways, and restrictive security groups. "
                "Delete the default VPC after migration to prevent accidental deployments into it."
            ),
        )]

    # ── STR-VPC-002 ────────────────────────────────────────────────────────────

    def _check_flow_logs(self, vpc_id: str, monitored_vpcs: set, region: str) -> List[Finding]:
        if vpc_id not in monitored_vpcs:
            return [Finding(
                check_id="STR-VPC-002",
                title="VPC Flow Logs Not Enabled",
                severity="medium",
                service="VPC",
                resource_type="VPC",
                resource_id=vpc_id,
                region=region,
                description=(
                    f"VPC '{vpc_id}' does not have flow logs enabled. "
                    "Flow logs capture metadata for all accepted and rejected traffic. "
                    "Without them, lateral movement, data exfiltration, and port scanning "
                    "within the VPC leave no network-layer audit trail."
                ),
                recommendation=(
                    "Enable VPC flow logs: EC2/VPC console → Your VPCs → select VPC → "
                    "Flow logs → Create flow log. "
                    "Publish to CloudWatch Logs for alerting or S3 for long-term retention. "
                    "Enable for ALL traffic (not just rejected) for maximum visibility."
                ),
                mitre_technique="T1562.008",
                mitre_tactic="Defense Evasion",
                mitre_name="Impair Defenses - Disable Cloud Logs",
            )]
        return []
