"""
IAM checks:
  STR-IAM-001  Root account MFA not enabled
  STR-IAM-002  Root account access keys exist
  STR-IAM-003  IAM users without MFA enabled
  STR-IAM-004  Access keys older than 90 days (active)
  STR-IAM-005  IAM users with AdministratorAccess policy
  STR-IAM-006  Weak account password policy
"""

from datetime import datetime, timezone
from typing import List

import boto3
from botocore.exceptions import ClientError

from src.checks.base import BaseCheck
from src.models import Finding


class IAMChecks(BaseCheck):
    service = "IAM"

    def run(self, session: boto3.Session, region: str) -> List[Finding]:
        iam = session.client("iam", region_name="us-east-1")  # IAM is global
        findings: List[Finding] = []

        findings += self._check_root_mfa(iam)
        findings += self._check_root_access_keys(iam)
        findings += self._check_users_without_mfa(iam)
        findings += self._check_stale_access_keys(iam)
        findings += self._check_admin_users(iam)
        findings += self._check_password_policy(iam)

        return findings

    # ── STR-IAM-001 ────────────────────────────────────────────────────────────

    def _check_root_mfa(self, iam) -> List[Finding]:
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 0:
                return [Finding(
                    check_id="STR-IAM-001",
                    title="Root Account MFA Not Enabled",
                    severity="critical",
                    service="IAM",
                    resource_type="AWS Account",
                    resource_id="root",
                    region="global",
                    description=(
                        "The root account does not have multi-factor authentication enabled. "
                        "Root has unrestricted access to every resource in the account. "
                        "A compromised root credential with no MFA gives an attacker full control."
                    ),
                    recommendation=(
                        "Enable MFA on the root account immediately: "
                        "IAM console → Security credentials → Assign MFA device. "
                        "Use a hardware token (YubiKey) or virtual authenticator app."
                    ),
                    mitre_technique="T1078",
                    mitre_tactic="Initial Access",
                    mitre_name="Valid Accounts",
                )]
        except ClientError:
            pass
        return []

    # ── STR-IAM-002 ────────────────────────────────────────────────────────────

    def _check_root_access_keys(self, iam) -> List[Finding]:
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                return [Finding(
                    check_id="STR-IAM-002",
                    title="Root Account Access Keys Exist",
                    severity="critical",
                    service="IAM",
                    resource_type="AWS Account",
                    resource_id="root",
                    region="global",
                    description=(
                        "Active access keys exist for the root account. "
                        "Root access keys carry unrestricted privileges and cannot be scoped "
                        "by IAM policies. These keys should never exist in any AWS account."
                    ),
                    recommendation=(
                        "Delete root access keys immediately: "
                        "IAM console → Security credentials → Access keys → Delete. "
                        "Use IAM roles and least-privilege users for all programmatic access."
                    ),
                    mitre_technique="T1078",
                    mitre_tactic="Initial Access",
                    mitre_name="Valid Accounts",
                )]
        except ClientError:
            pass
        return []

    # ── STR-IAM-003 ────────────────────────────────────────────────────────────

    def _check_users_without_mfa(self, iam) -> List[Finding]:
        findings = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    try:
                        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                        if not mfa_devices:
                            findings.append(Finding(
                                check_id="STR-IAM-003",
                                title="IAM User Without MFA",
                                severity="high",
                                service="IAM",
                                resource_type="IAM User",
                                resource_id=username,
                                region="global",
                                description=(
                                    f"IAM user '{username}' has no MFA device assigned. "
                                    "Accounts without MFA are vulnerable to credential stuffing, "
                                    "phishing, and password spray attacks."
                                ),
                                recommendation=(
                                    f"Assign an MFA device to '{username}': "
                                    "IAM console → Users → Security credentials → Assign MFA device. "
                                    "Consider enforcing MFA via an IAM policy condition."
                                ),
                                mitre_technique="T1078",
                                mitre_tactic="Initial Access",
                                mitre_name="Valid Accounts",
                            ))
                    except ClientError:
                        continue
        except ClientError:
            pass
        return findings

    # ── STR-IAM-004 ────────────────────────────────────────────────────────────

    def _check_stale_access_keys(self, iam) -> List[Finding]:
        findings = []
        now = datetime.now(timezone.utc)
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    try:
                        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                        for key in keys:
                            if key["Status"] != "Active":
                                continue
                            age_days = (now - key["CreateDate"]).days
                            if age_days >= 90:
                                findings.append(Finding(
                                    check_id="STR-IAM-004",
                                    title="Active Access Key Older Than 90 Days",
                                    severity="medium",
                                    service="IAM",
                                    resource_type="IAM Access Key",
                                    resource_id=f"{username}/{key['AccessKeyId']}",
                                    region="global",
                                    description=(
                                        f"Access key '{key['AccessKeyId']}' for user '{username}' "
                                        f"is {age_days} days old and still active. "
                                        "Long-lived credentials increase the exposure window if leaked."
                                    ),
                                    recommendation=(
                                        "Rotate access keys every 90 days: create a new key, "
                                        "update all consumers, then deactivate and delete the old key. "
                                        "Prefer IAM roles over long-lived access keys where possible."
                                    ),
                                    mitre_technique="T1078",
                                    mitre_tactic="Initial Access",
                                    mitre_name="Valid Accounts",
                                ))
                    except ClientError:
                        continue
        except ClientError:
            pass
        return findings

    # ── STR-IAM-005 ────────────────────────────────────────────────────────────

    def _check_admin_users(self, iam) -> List[Finding]:
        findings = []
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    try:
                        attached = iam.list_attached_user_policies(UserName=username)
                        for policy in attached["AttachedPolicies"]:
                            if policy["PolicyArn"] == admin_arn:
                                findings.append(Finding(
                                    check_id="STR-IAM-005",
                                    title="IAM User Has AdministratorAccess Policy",
                                    severity="high",
                                    service="IAM",
                                    resource_type="IAM User",
                                    resource_id=username,
                                    region="global",
                                    description=(
                                        f"IAM user '{username}' has the AdministratorAccess managed "
                                        "policy attached directly. This grants unrestricted access to "
                                        "all AWS services and resources."
                                    ),
                                    recommendation=(
                                        "Apply the principle of least privilege. Remove AdministratorAccess "
                                        "and replace with scoped policies granting only the permissions "
                                        "needed. Administrative access should be granted via roles with "
                                        "short session durations, not permanent user policies."
                                    ),
                                    mitre_technique="T1078.004",
                                    mitre_tactic="Privilege Escalation",
                                    mitre_name="Valid Accounts - Cloud Accounts",
                                ))
                    except ClientError:
                        continue
        except ClientError:
            pass
        return findings

    # ── STR-IAM-006 ────────────────────────────────────────────────────────────

    def _check_password_policy(self, iam) -> List[Finding]:
        findings = []
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            issues = []
            if policy.get("MinimumPasswordLength", 0) < 14:
                issues.append(f"minimum length is {policy.get('MinimumPasswordLength', 'unset')} (require 14+)")
            if not policy.get("RequireUppercaseCharacters", False):
                issues.append("uppercase characters not required")
            if not policy.get("RequireLowercaseCharacters", False):
                issues.append("lowercase characters not required")
            if not policy.get("RequireNumbers", False):
                issues.append("numbers not required")
            if not policy.get("RequireSymbols", False):
                issues.append("symbols not required")
            if not policy.get("MaxPasswordAge"):
                issues.append("password expiry not configured")
            if not policy.get("PasswordReusePrevention"):
                issues.append("password reuse prevention not configured")

            if issues:
                findings.append(Finding(
                    check_id="STR-IAM-006",
                    title="Weak IAM Account Password Policy",
                    severity="medium",
                    service="IAM",
                    resource_type="AWS Account",
                    resource_id="password-policy",
                    region="global",
                    description=(
                        "The IAM account password policy does not meet recommended standards: "
                        + "; ".join(issues) + "."
                    ),
                    recommendation=(
                        "Update the password policy: IAM console → Account settings → "
                        "Edit password policy. Require 14+ characters, upper/lower/numbers/symbols, "
                        "90-day expiry, and prevent reuse of the last 24 passwords."
                    ),
                ))
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                # No password policy set at all
                findings.append(Finding(
                    check_id="STR-IAM-006",
                    title="No IAM Account Password Policy Configured",
                    severity="medium",
                    service="IAM",
                    resource_type="AWS Account",
                    resource_id="password-policy",
                    region="global",
                    description=(
                        "No IAM account password policy is configured. AWS applies minimal defaults, "
                        "allowing weak passwords for console users."
                    ),
                    recommendation=(
                        "Configure a password policy: IAM console → Account settings → "
                        "Edit password policy."
                    ),
                ))
        return findings
