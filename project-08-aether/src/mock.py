"""
Mock scan data — simulates a realistic AWS account with common misconfigurations.

Used with `aether.py scan --mock` to generate a demo report without real credentials.
The findings represent a small startup-scale AWS account that has grown organically
without a dedicated security review.
"""

from src.models import Finding

MOCK_IDENTITY = {
    "account_id": "123456789012",
    "arn":        "arn:aws:iam::123456789012:user/security-audit",
    "user_id":    "AIDAIOSFODNN7EXAMPLE",
    "region":     "us-east-1",
}

MOCK_FINDINGS = [
    # ── CRITICAL ────────────────────────────────────────────────────────────────

    Finding(
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
    ),

    Finding(
        check_id="STR-S3-001",
        title="S3 Bucket Publicly Accessible via ACL",
        severity="critical",
        service="S3",
        resource_type="S3 Bucket",
        resource_id="acme-company-backups-2023",
        region="global",
        description=(
            "Bucket 'acme-company-backups-2023' grants public access via its ACL "
            "(grantee: http://acs.amazonaws.com/groups/global/AllUsers). "
            "Any unauthenticated internet user can list or read objects in this bucket."
        ),
        recommendation=(
            "Remove the public ACL grant: S3 console → Permissions → ACL → "
            "Remove public grants. Enable Block Public Access at the bucket and "
            "account level. Serve public content via CloudFront instead of direct S3."
        ),
        mitre_technique="T1530",
        mitre_tactic="Collection",
        mitre_name="Data from Cloud Storage",
    ),

    Finding(
        check_id="STR-EC2-003",
        title="Security Group Allows All Traffic from Internet",
        severity="critical",
        service="EC2",
        resource_type="Security Group",
        resource_id="sg-0f3e2d1c4b (legacy-test-env)",
        region="us-east-1",
        description=(
            "Security group 'sg-0f3e2d1c4b (legacy-test-env)' has an inbound rule allowing ALL "
            "protocols and ALL ports from 0.0.0.0/0. Every service on "
            "instances using this group is exposed to the internet."
        ),
        recommendation=(
            "Remove the all-traffic rule and replace with specific rules "
            "for only the ports and protocols required. This group appears to be "
            "a legacy test configuration — verify it is not attached to any production instances."
        ),
        mitre_technique="T1190",
        mitre_tactic="Initial Access",
        mitre_name="Exploit Public-Facing Application",
    ),

    Finding(
        check_id="STR-RDS-001",
        title="RDS Instance Publicly Accessible",
        severity="critical",
        service="RDS",
        resource_type="RDS Instance",
        resource_id="prod-mysql-01",
        region="us-east-1",
        description=(
            "RDS instance 'prod-mysql-01' (mysql 8.0) is publicly accessible "
            "at 'prod-mysql-01.cxyz1234abcd.us-east-1.rds.amazonaws.com'. "
            "The database endpoint is resolvable and reachable from the internet, "
            "subject only to security group rules. Database services should never be directly internet-facing."
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
    ),

    # ── HIGH ────────────────────────────────────────────────────────────────────

    Finding(
        check_id="STR-IAM-003",
        title="IAM User Without MFA",
        severity="high",
        service="IAM",
        resource_type="IAM User",
        resource_id="deploy-user",
        region="global",
        description=(
            "IAM user 'deploy-user' has no MFA device assigned. "
            "This account has programmatic and console access. "
            "Accounts without MFA are vulnerable to credential stuffing, "
            "phishing, and password spray attacks."
        ),
        recommendation=(
            "Assign an MFA device to 'deploy-user': "
            "IAM console → Users → Security credentials → Assign MFA device. "
            "For service accounts, prefer IAM roles over long-lived user credentials."
        ),
        mitre_technique="T1078",
        mitre_tactic="Initial Access",
        mitre_name="Valid Accounts",
    ),

    Finding(
        check_id="STR-IAM-003",
        title="IAM User Without MFA",
        severity="high",
        service="IAM",
        resource_type="IAM User",
        resource_id="sarah.jenkins",
        region="global",
        description=(
            "IAM user 'sarah.jenkins' has no MFA device assigned. "
            "This account has console access and was last used 3 days ago."
        ),
        recommendation=(
            "Assign an MFA device: IAM console → Users → Security credentials → Assign MFA device. "
            "Consider enforcing MFA via an IAM policy condition (aws:MultiFactorAuthPresent)."
        ),
        mitre_technique="T1078",
        mitre_tactic="Initial Access",
        mitre_name="Valid Accounts",
    ),

    Finding(
        check_id="STR-IAM-005",
        title="IAM User Has AdministratorAccess Policy",
        severity="high",
        service="IAM",
        resource_type="IAM User",
        resource_id="legacy-admin",
        region="global",
        description=(
            "IAM user 'legacy-admin' has the AdministratorAccess managed "
            "policy attached directly. This grants unrestricted access to "
            "all AWS services and resources. This user appears to be inactive "
            "based on last-activity metadata."
        ),
        recommendation=(
            "Investigate whether 'legacy-admin' is still required. If not, disable or delete it. "
            "If required, remove AdministratorAccess and replace with scoped policies. "
            "Administrative access should use IAM roles with short session durations."
        ),
        mitre_technique="T1078.004",
        mitre_tactic="Privilege Escalation",
        mitre_name="Valid Accounts - Cloud Accounts",
    ),

    Finding(
        check_id="STR-S3-002",
        title="S3 Bucket Block Public Access Not Fully Enabled",
        severity="high",
        service="S3",
        resource_type="S3 Bucket",
        resource_id="acme-static-assets",
        region="global",
        description=(
            "Bucket 'acme-static-assets' has Block Public Access disabled for: "
            "BlockPublicAcls, BlockPublicPolicy. "
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
    ),

    Finding(
        check_id="STR-EC2-001",
        title="Security Group Allows SSH from Internet",
        severity="high",
        service="EC2",
        resource_type="Security Group",
        resource_id="sg-0a1b2c3d4e (web-servers)",
        region="us-east-1",
        description=(
            "Security group 'sg-0a1b2c3d4e (web-servers)' allows inbound SSH (port 22) "
            "from 0.0.0.0/0. Any internet host can attempt authentication against "
            "instances using this group. This group is attached to 3 running EC2 instances."
        ),
        recommendation=(
            "Restrict SSH access to specific IP ranges (office NAT, VPN egress). "
            "Prefer AWS Systems Manager Session Manager for interactive access — "
            "it requires no open inbound ports and logs all sessions to CloudWatch."
        ),
        mitre_technique="T1190",
        mitre_tactic="Initial Access",
        mitre_name="Exploit Public-Facing Application",
    ),

    Finding(
        check_id="STR-EC2-001",
        title="Security Group Allows SSH from Internet",
        severity="high",
        service="EC2",
        resource_type="Security Group",
        resource_id="sg-0b9c8d7e6f (bastion-host)",
        region="us-east-1",
        description=(
            "Security group 'sg-0b9c8d7e6f (bastion-host)' allows inbound SSH (port 22) "
            "from 0.0.0.0/0. While intended as a bastion, broad exposure increases the "
            "attack surface. Bastion hosts are high-value targets for credential attacks."
        ),
        recommendation=(
            "Restrict SSH source to your corporate IP range or VPN egress IPs. "
            "Consider replacing the bastion entirely with AWS Systems Manager Session Manager."
        ),
        mitre_technique="T1190",
        mitre_tactic="Initial Access",
        mitre_name="Exploit Public-Facing Application",
    ),

    Finding(
        check_id="STR-CT-001",
        title="CloudTrail Not Enabled in Region",
        severity="high",
        service="CloudTrail",
        resource_type="AWS Region",
        resource_id="eu-west-1",
        region="eu-west-1",
        description=(
            "No CloudTrail trails are configured in region 'eu-west-1'. "
            "Without CloudTrail, API calls in this region are not logged — "
            "an attacker who provisions resources here can operate without leaving an audit trail."
        ),
        recommendation=(
            "Create a multi-region CloudTrail trail: CloudTrail console → Create trail → "
            "Apply trail to all regions → Enable. Store logs in a dedicated S3 bucket "
            "with access logging and MFA delete protection enabled."
        ),
        mitre_technique="T1562.008",
        mitre_tactic="Defense Evasion",
        mitre_name="Impair Defenses - Disable Cloud Logs",
    ),

    Finding(
        check_id="STR-RDS-002",
        title="RDS Instance Storage Not Encrypted",
        severity="high",
        service="RDS",
        resource_type="RDS Instance",
        resource_id="dev-postgres-reporting",
        region="us-east-1",
        description=(
            "RDS instance 'dev-postgres-reporting' (postgres 15.2) does not have storage "
            "encryption enabled. Unencrypted database storage means backups, snapshots, "
            "and read replicas are also unencrypted, exposing data at rest."
        ),
        recommendation=(
            "RDS encryption cannot be enabled on existing instances. "
            "To encrypt: take a snapshot, copy it with encryption enabled, "
            "restore a new encrypted instance from the copy, and migrate traffic. "
            "Enable encryption by default for new RDS instances in the account."
        ),
    ),

    # ── MEDIUM ───────────────────────────────────────────────────────────────────

    Finding(
        check_id="STR-IAM-004",
        title="Active Access Key Older Than 90 Days",
        severity="medium",
        service="IAM",
        resource_type="IAM Access Key",
        resource_id="ci-pipeline/AKIAIOSFODNN7EXAMPLE",
        region="global",
        description=(
            "Access key 'AKIAIOSFODNN7EXAMPLE' for user 'ci-pipeline' is 147 days old "
            "and still active. Long-lived credentials increase the exposure window if leaked "
            "via a git commit, CI log, or environment variable disclosure."
        ),
        recommendation=(
            "Rotate access keys every 90 days: create a new key, update all consumers "
            "(CI/CD environment variables), then deactivate and delete the old key. "
            "Prefer IAM roles for EC2/ECS/Lambda execution environments."
        ),
        mitre_technique="T1078",
        mitre_tactic="Initial Access",
        mitre_name="Valid Accounts",
    ),

    Finding(
        check_id="STR-IAM-006",
        title="Weak IAM Account Password Policy",
        severity="medium",
        service="IAM",
        resource_type="AWS Account",
        resource_id="password-policy",
        region="global",
        description=(
            "The IAM account password policy does not meet recommended standards: "
            "minimum length is 8 (require 14+); password expiry not configured; "
            "password reuse prevention not configured."
        ),
        recommendation=(
            "Update the password policy: IAM console → Account settings → "
            "Edit password policy. Require 14+ characters, upper/lower/numbers/symbols, "
            "90-day expiry, and prevent reuse of the last 24 passwords."
        ),
    ),

    Finding(
        check_id="STR-S3-003",
        title="S3 Bucket Without Server-Side Encryption",
        severity="medium",
        service="S3",
        resource_type="S3 Bucket",
        resource_id="acme-dev-logs-archive",
        region="global",
        description=(
            "Bucket 'acme-dev-logs-archive' has no default server-side encryption configured. "
            "Objects are stored unencrypted at rest unless encryption is specified "
            "per-object at upload time."
        ),
        recommendation=(
            "Enable default SSE-S3 or SSE-KMS encryption: "
            "S3 console → Properties → Default encryption → Edit. "
            "Use SSE-KMS with a customer-managed key for compliance requirements."
        ),
    ),

    Finding(
        check_id="STR-EC2-004",
        title="Unencrypted EBS Volume Attached to Running Instance",
        severity="medium",
        service="EC2",
        resource_type="EBS Volume",
        resource_id="vol-0123456789abcdef0 (attached to i-0abc123def456789a)",
        region="us-east-1",
        description=(
            "EBS volume 'vol-0123456789abcdef0' is attached and unencrypted. "
            "An attacker with access to the underlying host or a snapshot "
            "can read the raw volume data without needing OS credentials."
        ),
        recommendation=(
            "Encrypt EBS volumes at creation. For this existing volume: snapshot, "
            "copy the snapshot with encryption enabled, restore from the encrypted "
            "snapshot, and swap the volume. Enable EC2 default encryption to "
            "automatically encrypt all new volumes in the region."
        ),
    ),

    Finding(
        check_id="STR-CT-002",
        title="CloudTrail Log File Validation Disabled",
        severity="medium",
        service="CloudTrail",
        resource_type="CloudTrail Trail",
        resource_id="management-events-trail",
        region="us-east-1",
        description=(
            "Trail 'management-events-trail' does not have log file validation enabled. "
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
    ),

    Finding(
        check_id="STR-CT-003",
        title="CloudTrail Trail Not Multi-Region",
        severity="medium",
        service="CloudTrail",
        resource_type="CloudTrail Trail",
        resource_id="management-events-trail",
        region="us-east-1",
        description=(
            "Trail 'management-events-trail' only covers a single region. "
            "An attacker who provisions resources in an unmonitored region "
            "can operate without generating any audit log events."
        ),
        recommendation=(
            "Convert to a multi-region trail: "
            "CloudTrail console → select trail → Edit → Apply trail to all regions."
        ),
        mitre_technique="T1562.008",
        mitre_tactic="Defense Evasion",
        mitre_name="Impair Defenses - Disable Cloud Logs",
    ),

    Finding(
        check_id="STR-VPC-002",
        title="VPC Flow Logs Not Enabled",
        severity="medium",
        service="VPC",
        resource_type="VPC",
        resource_id="vpc-0a1b2c3d4e5f67890",
        region="us-east-1",
        description=(
            "VPC 'vpc-0a1b2c3d4e5f67890' does not have flow logs enabled. "
            "Flow logs capture metadata for all accepted and rejected traffic. "
            "Without them, lateral movement, data exfiltration, and port scanning "
            "within the VPC leave no network-layer audit trail."
        ),
        recommendation=(
            "Enable VPC flow logs: EC2/VPC console → Your VPCs → select VPC → "
            "Flow logs → Create flow log. Publish to CloudWatch Logs for alerting "
            "or S3 for long-term retention. Enable for ALL traffic (not just rejected)."
        ),
        mitre_technique="T1562.008",
        mitre_tactic="Defense Evasion",
        mitre_name="Impair Defenses - Disable Cloud Logs",
    ),

    # ── LOW ─────────────────────────────────────────────────────────────────────

    Finding(
        check_id="STR-S3-004",
        title="S3 Bucket Versioning Not Enabled",
        severity="low",
        service="S3",
        resource_type="S3 Bucket",
        resource_id="acme-application-uploads",
        region="global",
        description=(
            "Bucket 'acme-application-uploads' does not have versioning enabled. "
            "Without versioning, accidental deletions or ransomware overwrites "
            "cannot be recovered."
        ),
        recommendation=(
            "Enable versioning: S3 console → Properties → Bucket Versioning → Enable. "
            "Combine with S3 Object Lock for immutable backup storage."
        ),
    ),

    Finding(
        check_id="STR-VPC-001",
        title="Default VPC In Use",
        severity="low",
        service="VPC",
        resource_type="VPC",
        resource_id="vpc-0default1234567890",
        region="us-east-1",
        description=(
            "The default VPC ('vpc-0default1234567890') in region 'us-east-1' has subnets "
            "and is in use. Default VPCs come pre-configured with permissive settings "
            "(all subnets public, default security group allows all outbound) and are "
            "not designed for production workloads."
        ),
        recommendation=(
            "Migrate workloads to a custom VPC with private/public subnet segregation, "
            "NAT gateways, and restrictive security groups. "
            "Delete the default VPC after migration to prevent accidental deployments into it."
        ),
    ),
]
