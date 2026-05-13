"""
EC2 / Security Group checks:
  STR-EC2-001  Security group allows SSH (port 22) from 0.0.0.0/0 or ::/0
  STR-EC2-002  Security group allows RDP (port 3389) from 0.0.0.0/0 or ::/0
  STR-EC2-003  Security group allows all traffic from 0.0.0.0/0
  STR-EC2-004  Unencrypted EBS volume attached to a running instance
"""

from typing import List

import boto3
from botocore.exceptions import ClientError

from src.checks.base import BaseCheck
from src.models import Finding

WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _open_to_world(ip_ranges, ipv6_ranges) -> bool:
    for r in ip_ranges:
        if r.get("CidrIp") in WORLD_CIDRS:
            return True
    for r in ipv6_ranges:
        if r.get("CidrIpv6") in WORLD_CIDRS:
            return True
    return False


class EC2Checks(BaseCheck):
    service = "EC2"

    def run(self, session: boto3.Session, region: str) -> List[Finding]:
        ec2 = session.client("ec2", region_name=region)
        findings: List[Finding] = []

        findings += self._check_security_groups(ec2, region)
        findings += self._check_unencrypted_volumes(ec2, region)

        return findings

    # ── STR-EC2-001 / 002 / 003 ────────────────────────────────────────────────

    def _check_security_groups(self, ec2, region: str) -> List[Finding]:
        findings = []
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", sg_id)
                    label = f"{sg_id} ({sg_name})"

                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", -1)
                        to_port   = rule.get("ToPort", -1)
                        protocol  = rule.get("IpProtocol", "")
                        ip4 = rule.get("IpRanges", [])
                        ip6 = rule.get("Ipv6Ranges", [])

                        if not _open_to_world(ip4, ip6):
                            continue

                        # SSH
                        if protocol in ("tcp", "-1") and (
                            protocol == "-1" or (from_port <= 22 <= to_port)
                        ):
                            findings.append(Finding(
                                check_id="STR-EC2-001",
                                title="Security Group Allows SSH from Internet",
                                severity="high",
                                service="EC2",
                                resource_type="Security Group",
                                resource_id=label,
                                region=region,
                                description=(
                                    f"Security group '{label}' allows inbound SSH (port 22) "
                                    "from 0.0.0.0/0 or ::/0. Any internet host can attempt "
                                    "authentication against instances using this group."
                                ),
                                recommendation=(
                                    "Restrict SSH access to specific IP ranges (office NAT, VPN egress). "
                                    "Prefer AWS Systems Manager Session Manager for interactive access — "
                                    "it requires no open inbound ports and logs all sessions."
                                ),
                                mitre_technique="T1190",
                                mitre_tactic="Initial Access",
                                mitre_name="Exploit Public-Facing Application",
                            ))

                        # RDP
                        if protocol in ("tcp", "-1") and (
                            protocol == "-1" or (from_port <= 3389 <= to_port)
                        ):
                            findings.append(Finding(
                                check_id="STR-EC2-002",
                                title="Security Group Allows RDP from Internet",
                                severity="high",
                                service="EC2",
                                resource_type="Security Group",
                                resource_id=label,
                                region=region,
                                description=(
                                    f"Security group '{label}' allows inbound RDP (port 3389) "
                                    "from 0.0.0.0/0 or ::/0. Exposed RDP is routinely targeted "
                                    "by ransomware operators and credential-stuffing tools."
                                ),
                                recommendation=(
                                    "Close port 3389 to the internet. Use a VPN or AWS Systems Manager "
                                    "Fleet Manager for Windows remote access."
                                ),
                                mitre_technique="T1190",
                                mitre_tactic="Initial Access",
                                mitre_name="Exploit Public-Facing Application",
                            ))

                        # All traffic
                        if protocol == "-1":
                            findings.append(Finding(
                                check_id="STR-EC2-003",
                                title="Security Group Allows All Traffic from Internet",
                                severity="critical",
                                service="EC2",
                                resource_type="Security Group",
                                resource_id=label,
                                region=region,
                                description=(
                                    f"Security group '{label}' has an inbound rule allowing ALL "
                                    "protocols and ALL ports from 0.0.0.0/0. Every service on "
                                    "instances using this group is exposed to the internet."
                                ),
                                recommendation=(
                                    "Remove the all-traffic rule and replace with specific rules "
                                    "for only the ports and protocols required. Default security groups "
                                    "should have no inbound rules."
                                ),
                                mitre_technique="T1190",
                                mitre_tactic="Initial Access",
                                mitre_name="Exploit Public-Facing Application",
                            ))
        except ClientError:
            pass
        return findings

    # ── STR-EC2-004 ────────────────────────────────────────────────────────────

    def _check_unencrypted_volumes(self, ec2, region: str) -> List[Finding]:
        findings = []
        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["in-use"]}]):
                for vol in page["Volumes"]:
                    if not vol.get("Encrypted", False):
                        instance_ids = [
                            a["InstanceId"] for a in vol.get("Attachments", [])
                        ]
                        label = vol["VolumeId"]
                        if instance_ids:
                            label += f" (attached to {', '.join(instance_ids)})"
                        findings.append(Finding(
                            check_id="STR-EC2-004",
                            title="Unencrypted EBS Volume Attached to Running Instance",
                            severity="medium",
                            service="EC2",
                            resource_type="EBS Volume",
                            resource_id=label,
                            region=region,
                            description=(
                                f"EBS volume '{vol['VolumeId']}' is attached and unencrypted. "
                                "An attacker with access to the underlying host or a snapshot "
                                "can read the raw volume data without needing OS credentials."
                            ),
                            recommendation=(
                                "Encrypt EBS volumes at creation. For existing volumes: snapshot, "
                                "copy the snapshot with encryption enabled, restore from the encrypted "
                                "snapshot, and swap the volume. Enable EC2 default encryption to "
                                "automatically encrypt all new volumes in the region."
                            ),
                        ))
        except ClientError:
            pass
        return findings
