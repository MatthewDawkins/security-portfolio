"""
Scanner — instantiates all check modules and runs them against the target account/region.
"""

from typing import List, Tuple

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, NoRegionError

from src.checks.iam import IAMChecks
from src.checks.s3 import S3Checks
from src.checks.ec2 import EC2Checks
from src.checks.rds import RDSChecks
from src.checks.cloudtrail import CloudTrailChecks
from src.checks.vpc import VPCChecks
from src.models import Finding

CHECK_MODULES = [
    IAMChecks,
    S3Checks,
    EC2Checks,
    RDSChecks,
    CloudTrailChecks,
    VPCChecks,
]


def get_account_identity(session: boto3.Session) -> dict:
    """Return account ID, user ARN, and region from STS."""
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return {
            "account_id": identity.get("Account", "unknown"),
            "arn":        identity.get("Arn", "unknown"),
            "user_id":    identity.get("UserId", "unknown"),
            "region":     session.region_name or "us-east-1",
        }
    except (ClientError, NoCredentialsError):
        return {
            "account_id": "unknown",
            "arn":        "unknown",
            "user_id":    "unknown",
            "region":     session.region_name or "us-east-1",
        }


def run_scan(
    session: boto3.Session,
    region: str,
    progress_callback=None,
) -> Tuple[dict, List[Finding]]:
    """
    Run all check modules and return (identity_info, sorted_findings).

    Args:
        session:           Configured boto3 session
        region:            AWS region to scan (regional checks)
        progress_callback: Optional callable(module_name) called before each module runs
    """
    identity = get_account_identity(session)
    all_findings: List[Finding] = []

    for CheckClass in CHECK_MODULES:
        instance = CheckClass()
        if progress_callback:
            progress_callback(instance.service)
        try:
            findings = instance.run(session, region)
            all_findings.extend(findings)
        except Exception:
            # Never let a single check crash the whole scan
            continue

    all_findings.sort(key=lambda f: (f.severity_rank, f.service, f.check_id))
    return identity, all_findings
