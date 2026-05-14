"""
Scanner — instantiates all check modules and runs them against the target account/region/URL.
"""

from typing import List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from src.checks.iam import IAMChecks
from src.checks.s3 import S3Checks
from src.checks.ec2 import EC2Checks
from src.checks.rds import RDSChecks
from src.checks.cloudtrail import CloudTrailChecks
from src.checks.vpc import VPCChecks
from src.checks.web import WebChecks
from src.checks.dns import DNSChecks
from src.models import Finding

AWS_MODULES = [
    IAMChecks,
    S3Checks,
    EC2Checks,
    RDSChecks,
    CloudTrailChecks,
    VPCChecks,
]

WEB_MODULES = [
    WebChecks,
    DNSChecks,
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
    session: Optional[boto3.Session],
    region: str,
    url: Optional[str] = None,
    progress_callback=None,
) -> Tuple[dict, List[Finding]]:
    """
    Run AWS and/or web/DNS check modules.

    Args:
        session:           boto3 session (None = skip AWS checks)
        region:            AWS region for regional checks
        url:               Target URL for web/DNS checks (None = skip)
        progress_callback: Optional callable(module_name)
    """
    identity = get_account_identity(session) if session else {
        "account_id": "n/a", "arn": "n/a", "user_id": "n/a", "region": region,
    }
    if url:
        identity["url"] = url

    all_findings: List[Finding] = []

    # AWS checks (only if session provided)
    if session:
        for CheckClass in AWS_MODULES:
            instance = CheckClass()
            if progress_callback:
                progress_callback(instance.service)
            try:
                all_findings.extend(instance.run(session, region))
            except Exception:
                continue

    # Web / DNS checks (only if URL provided)
    if url:
        for CheckClass in WEB_MODULES:
            instance = CheckClass()
            if progress_callback:
                progress_callback(f"{instance.service} ({url})")
            try:
                all_findings.extend(instance.run(session, region, url=url))
            except Exception:
                continue

    all_findings.sort(key=lambda f: (f.severity_rank, f.service, f.check_id))
    return identity, all_findings
