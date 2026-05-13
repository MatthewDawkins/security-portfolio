"""
S3 checks:
  STR-S3-001  Bucket publicly accessible via ACL
  STR-S3-002  Bucket Block Public Access settings disabled
  STR-S3-003  Bucket without server-side encryption
  STR-S3-004  Bucket without versioning enabled
"""

from typing import List

import boto3
from botocore.exceptions import ClientError

from src.checks.base import BaseCheck
from src.models import Finding


class S3Checks(BaseCheck):
    service = "S3"

    def run(self, session: boto3.Session, region: str) -> List[Finding]:
        s3 = session.client("s3", region_name="us-east-1")
        findings: List[Finding] = []

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError:
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            findings += self._check_public_acl(s3, name)
            findings += self._check_block_public_access(s3, name)
            findings += self._check_encryption(s3, name)
            findings += self._check_versioning(s3, name)

        return findings

    # ── STR-S3-001 ─────────────────────────────────────────────────────────────

    def _check_public_acl(self, s3, bucket_name: str) -> List[Finding]:
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            public_uris = {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            }
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in public_uris:
                    return [Finding(
                        check_id="STR-S3-001",
                        title="S3 Bucket Publicly Accessible via ACL",
                        severity="critical",
                        service="S3",
                        resource_type="S3 Bucket",
                        resource_id=bucket_name,
                        region="global",
                        description=(
                            f"Bucket '{bucket_name}' grants public access via its ACL "
                            f"(grantee: {grantee.get('URI', 'unknown')}). Any unauthenticated "
                            "internet user can list or read objects in this bucket."
                        ),
                        recommendation=(
                            "Remove the public ACL grant: S3 console → Permissions → ACL → "
                            "Remove public grants. Enable Block Public Access at the bucket and "
                            "account level. Serve public content via CloudFront instead of direct S3."
                        ),
                        mitre_technique="T1530",
                        mitre_tactic="Collection",
                        mitre_name="Data from Cloud Storage",
                    )]
        except ClientError:
            pass
        return []

    # ── STR-S3-002 ─────────────────────────────────────────────────────────────

    def _check_block_public_access(self, s3, bucket_name: str) -> List[Finding]:
        try:
            config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
            disabled = [
                k for k, v in config.items() if not v
            ]
            if disabled:
                return [Finding(
                    check_id="STR-S3-002",
                    title="S3 Bucket Block Public Access Not Fully Enabled",
                    severity="high",
                    service="S3",
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    region="global",
                    description=(
                        f"Bucket '{bucket_name}' has Block Public Access disabled for: "
                        + ", ".join(disabled) + ". "
                        "This allows public bucket policies or ACLs to expose objects."
                    ),
                    recommendation=(
                        "Enable all four Block Public Access settings: "
                        "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. "
                        "S3 console → Permissions → Block public access → Edit."
                    ),
                    mitre_technique="T1530",
                    mitre_tactic="Collection",
                    mitre_name="Data from Cloud Storage",
                )]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return [Finding(
                    check_id="STR-S3-002",
                    title="S3 Bucket Block Public Access Not Configured",
                    severity="high",
                    service="S3",
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    region="global",
                    description=(
                        f"Bucket '{bucket_name}' has no Block Public Access configuration. "
                        "Without this, public ACLs or policies can expose bucket contents."
                    ),
                    recommendation=(
                        "Enable Block Public Access on the bucket and at the account level."
                    ),
                    mitre_technique="T1530",
                    mitre_tactic="Collection",
                    mitre_name="Data from Cloud Storage",
                )]
        return []

    # ── STR-S3-003 ─────────────────────────────────────────────────────────────

    def _check_encryption(self, s3, bucket_name: str) -> List[Finding]:
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if e.response["Error"]["Code"] in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchBucketEncryption",
            ):
                return [Finding(
                    check_id="STR-S3-003",
                    title="S3 Bucket Without Server-Side Encryption",
                    severity="medium",
                    service="S3",
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    region="global",
                    description=(
                        f"Bucket '{bucket_name}' has no default server-side encryption configured. "
                        "Objects are stored unencrypted at rest unless encryption is specified "
                        "per-object at upload time."
                    ),
                    recommendation=(
                        "Enable default SSE-S3 or SSE-KMS encryption: "
                        "S3 console → Properties → Default encryption → Edit. "
                        "Use SSE-KMS with a customer-managed key for compliance requirements."
                    ),
                )]
        return []

    # ── STR-S3-004 ─────────────────────────────────────────────────────────────

    def _check_versioning(self, s3, bucket_name: str) -> List[Finding]:
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "")
            if status != "Enabled":
                return [Finding(
                    check_id="STR-S3-004",
                    title="S3 Bucket Versioning Not Enabled",
                    severity="low",
                    service="S3",
                    resource_type="S3 Bucket",
                    resource_id=bucket_name,
                    region="global",
                    description=(
                        f"Bucket '{bucket_name}' does not have versioning enabled "
                        f"(current status: {status or 'Never enabled'}). "
                        "Without versioning, accidental deletions or ransomware overwrites "
                        "cannot be recovered."
                    ),
                    recommendation=(
                        "Enable versioning: S3 console → Properties → Bucket Versioning → Enable. "
                        "Combine with S3 Object Lock for immutable backup storage."
                    ),
                )]
        except ClientError:
            pass
        return []
