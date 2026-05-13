"""
CloudTrail checks:
  STR-CT-001  CloudTrail not enabled in region
  STR-CT-002  CloudTrail log file validation disabled
  STR-CT-003  CloudTrail not configured as multi-region trail
"""

from typing import List

import boto3
from botocore.exceptions import ClientError

from src.checks.base import BaseCheck
from src.models import Finding


class CloudTrailChecks(BaseCheck):
    service = "CloudTrail"

    def run(self, session: boto3.Session, region: str) -> List[Finding]:
        ct = session.client("cloudtrail", region_name=region)
        findings: List[Finding] = []

        try:
            response = ct.describe_trails(includeShadowTrails=False)
            trails = response.get("trailList", [])
        except ClientError:
            return findings

        if not trails:
            return [Finding(
                check_id="STR-CT-001",
                title="CloudTrail Not Enabled in Region",
                severity="high",
                service="CloudTrail",
                resource_type="AWS Region",
                resource_id=region,
                region=region,
                description=(
                    f"No CloudTrail trails are configured in region '{region}'. "
                    "Without CloudTrail, API calls in this region are not logged — "
                    "an attacker can operate without leaving an audit trail."
                ),
                recommendation=(
                    "Create a CloudTrail trail covering all regions: "
                    "CloudTrail console → Create trail → Apply trail to all regions → Enable. "
                    "Store logs in a dedicated S3 bucket with access logging enabled."
                ),
                mitre_technique="T1562.008",
                mitre_tactic="Defense Evasion",
                mitre_name="Impair Defenses - Disable Cloud Logs",
            )]

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            findings += self._check_log_validation(trail, trail_name, region)
            findings += self._check_multi_region(trail, trail_name, region)

        return findings

    # ── STR-CT-002 ────────────────────────────────────────────────────────────

    def _check_log_validation(self, trail: dict, trail_name: str, region: str) -> List[Finding]:
        if not trail.get("LogFileValidationEnabled", False):
            return [Finding(
                check_id="STR-CT-002",
                title="CloudTrail Log File Validation Disabled",
                severity="medium",
                service="CloudTrail",
                resource_type="CloudTrail Trail",
                resource_id=trail_name,
                region=region,
                description=(
                    f"Trail '{trail_name}' does not have log file validation enabled. "
                    "Without validation, there is no way to detect if log files have been "
                    "tampered with or deleted after delivery to S3."
                ),
                recommendation=(
                    "Enable log file validation: "
                    "CloudTrail console → select trail → Edit → Enable log file validation. "
                    "Validation uses SHA-256 hashing and RSA signing to detect tampering."
                ),
                mitre_technique="T1562.008",
                mitre_tactic="Defense Evasion",
                mitre_name="Impair Defenses - Disable Cloud Logs",
            )]
        return []

    # ── STR-CT-003 ────────────────────────────────────────────────────────────

    def _check_multi_region(self, trail: dict, trail_name: str, region: str) -> List[Finding]:
        if not trail.get("IsMultiRegionTrail", False):
            return [Finding(
                check_id="STR-CT-003",
                title="CloudTrail Trail Not Multi-Region",
                severity="medium",
                service="CloudTrail",
                resource_type="CloudTrail Trail",
                resource_id=trail_name,
                region=region,
                description=(
                    f"Trail '{trail_name}' only covers a single region. "
                    "An attacker who provisions resources in an unmonitored region "
                    "can operate without generating any audit log events."
                ),
                recommendation=(
                    "Convert to a multi-region trail: "
                    "CloudTrail console → select trail → Edit → Apply trail to all regions. "
                    "Alternatively, use AWS Organizations trail for organisation-wide coverage."
                ),
                mitre_technique="T1562.008",
                mitre_tactic="Defense Evasion",
                mitre_name="Impair Defenses - Disable Cloud Logs",
            )]
        return []
