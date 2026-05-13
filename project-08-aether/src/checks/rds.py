"""
RDS checks:
  STR-RDS-001  RDS instance publicly accessible
  STR-RDS-002  RDS instance storage not encrypted
"""

from typing import List

import boto3
from botocore.exceptions import ClientError

from src.checks.base import BaseCheck
from src.models import Finding


class RDSChecks(BaseCheck):
    service = "RDS"

    def run(self, session: boto3.Session, region: str) -> List[Finding]:
        rds = session.client("rds", region_name=region)
        findings: List[Finding] = []

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    findings += self._check_public_access(db, region)
                    findings += self._check_encryption(db, region)
        except ClientError:
            pass

        return findings

    # ── STR-RDS-001 ────────────────────────────────────────────────────────────

    def _check_public_access(self, db: dict, region: str) -> List[Finding]:
        if db.get("PubliclyAccessible", False):
            db_id = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            endpoint = db.get("Endpoint", {}).get("Address", "unknown")
            return [Finding(
                check_id="STR-RDS-001",
                title="RDS Instance Publicly Accessible",
                severity="critical",
                service="RDS",
                resource_type="RDS Instance",
                resource_id=db_id,
                region=region,
                description=(
                    f"RDS instance '{db_id}' ({engine}) is publicly accessible "
                    f"at '{endpoint}'. The database endpoint is resolvable and reachable "
                    "from the internet, subject only to security group rules. "
                    "Database services should never be directly internet-facing."
                ),
                recommendation=(
                    "Disable public accessibility: RDS console → Modify → "
                    "Connectivity → Public access → No. "
                    "Move the instance to a private subnet and access via a bastion host, "
                    "VPN, or AWS Systems Manager port forwarding."
                ),
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                mitre_name="Exploit Public-Facing Application",
            )]
        return []

    # ── STR-RDS-002 ────────────────────────────────────────────────────────────

    def _check_encryption(self, db: dict, region: str) -> List[Finding]:
        if not db.get("StorageEncrypted", False):
            db_id = db["DBInstanceIdentifier"]
            engine = db.get("Engine", "unknown")
            return [Finding(
                check_id="STR-RDS-002",
                title="RDS Instance Storage Not Encrypted",
                severity="high",
                service="RDS",
                resource_type="RDS Instance",
                resource_id=db_id,
                region=region,
                description=(
                    f"RDS instance '{db_id}' ({engine}) does not have storage encryption enabled. "
                    "Unencrypted database storage means backups, snapshots, and read replicas "
                    "are also unencrypted, exposing data at rest."
                ),
                recommendation=(
                    "RDS encryption cannot be enabled on existing instances. "
                    "To encrypt: take a snapshot, copy it with encryption enabled, "
                    "restore a new encrypted instance from the copy, and migrate traffic. "
                    "Enable encryption by default for new RDS instances in the account."
                ),
            )]
        return []
