"""
CLI entry point for Aether.

Usage:
  python aether.py scan [--url URL] [--region REGION] [--profile PROFILE] [--output FILE]
  python aether.py scan --url https://example.com          # web/DNS only, no AWS creds needed
  python aether.py scan --mock
  python aether.py checks
"""

import argparse
import sys
from collections import defaultdict
from typing import List

import boto3
from botocore.exceptions import NoCredentialsError, NoRegionError, ClientError
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

from src.models import Finding

console = Console()


def _has_aws_credentials() -> bool:
    """Return True if boto3 can resolve credentials from the environment."""
    try:
        session = boto3.Session()
        creds = session.get_credentials()
        return creds is not None and creds.get_frozen_credentials().access_key is not None
    except Exception:
        return False

BANNER = r"""
    _          _   _
   / \   ___  | |_| |__   ___ _ __
  / _ \ / _ \ | __| '_ \ / _ \ '__|
 / ___ \  __/ | |_| | | |  __/ |
/_/   \_\___|  \__|_| |_|\___|_|
  AWS cloud security scanner
"""

SEVERITY_STYLE = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "bold cyan",
    "low":      "bold blue",
    "info":     "dim",
}

CHECK_CATALOG = [
    ("STR-IAM-001", "critical", "Root Account MFA Not Enabled"),
    ("STR-IAM-002", "critical", "Root Account Access Keys Exist"),
    ("STR-IAM-003", "high",     "IAM Users Without MFA"),
    ("STR-IAM-004", "medium",   "Access Keys Older Than 90 Days"),
    ("STR-IAM-005", "high",     "Users With AdministratorAccess Policy"),
    ("STR-IAM-006", "medium",   "Weak Account Password Policy"),
    ("STR-S3-001",  "critical", "Bucket Publicly Accessible via ACL"),
    ("STR-S3-002",  "high",     "Bucket Block Public Access Disabled"),
    ("STR-S3-003",  "medium",   "Bucket Without Server-Side Encryption"),
    ("STR-S3-004",  "low",      "Bucket Without Versioning"),
    ("STR-EC2-001", "high",     "Security Group Allows SSH from Internet"),
    ("STR-EC2-002", "high",     "Security Group Allows RDP from Internet"),
    ("STR-EC2-003", "critical", "Security Group Allows All Traffic from Internet"),
    ("STR-EC2-004", "medium",   "Unencrypted EBS Volume (in-use)"),
    ("STR-RDS-001", "critical", "RDS Instance Publicly Accessible"),
    ("STR-RDS-002", "high",     "RDS Instance Storage Not Encrypted"),
    ("STR-CT-001",  "high",     "CloudTrail Not Enabled in Region"),
    ("STR-CT-002",  "medium",   "CloudTrail Log File Validation Disabled"),
    ("STR-CT-003",  "medium",   "CloudTrail Trail Not Multi-Region"),
    ("STR-VPC-001", "low",      "Default VPC In Use"),
    ("STR-VPC-002", "medium",   "VPC Flow Logs Not Enabled"),
    ("STR-WEB-001", "high",     "HTTPS Not Enforced"),
    ("STR-WEB-002", "medium",   "Missing HSTS Header"),
    ("STR-WEB-003", "medium",   "Missing / Weak Content-Security-Policy"),
    ("STR-WEB-004", "medium",   "Missing X-Frame-Options / frame-ancestors"),
    ("STR-WEB-005", "low",      "Missing X-Content-Type-Options: nosniff"),
    ("STR-WEB-006", "low",      "Server Version Disclosed in Headers"),
    ("STR-WEB-007", "medium",   "CORS Wildcard (Access-Control-Allow-Origin: *)"),
    ("STR-WEB-008", "medium",   "TLS Certificate Expiring Within 30 Days"),
    ("STR-DNS-001", "high",     "Missing or Permissive SPF Record"),
    ("STR-DNS-002", "high",     "Missing or Unenforced DMARC Record"),
    ("STR-DNS-003", "low",      "Missing CAA Record"),
]


def _print_banner():
    console.print(BANNER, style="bold cyan", highlight=False)


def _severity_text(severity: str) -> Text:
    style = SEVERITY_STYLE.get(severity.lower(), "")
    return Text(severity.upper(), style=style)


def _print_findings(findings: List[Finding]):
    if not findings:
        console.print("\n[green]No findings detected.[/green]\n")
        return

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    table.add_column("Check ID",   style="dim", width=14)
    table.add_column("Severity",   width=10)
    table.add_column("Service",    width=12)
    table.add_column("Resource",   width=32)
    table.add_column("Title",      min_width=24)

    for f in findings:
        table.add_row(
            f.check_id,
            _severity_text(f.severity),
            f.service,
            Text(f.resource_id[:40] + ("…" if len(f.resource_id) > 40 else ""), style="cyan"),
            f.title,
        )

    console.print(table)

    # Summary line
    counts = defaultdict(int)
    for f in findings:
        counts[f.severity.lower()] += 1

    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            style = SEVERITY_STYLE[sev]
            parts.append(f"[{style}]{sev.upper()}: {n}[/{style}]")
    console.print("  " + "  ".join(parts) + f"  Total: {len(findings)}\n")


def _cmd_scan(args):
    from src.reporter import generate_report

    _print_banner()

    # ── Mock mode ──────────────────────────────────────────────────────────────
    if getattr(args, "mock", False):
        from src.mock import MOCK_FINDINGS, MOCK_IDENTITY
        console.print("  [yellow]Running in mock mode — no AWS credentials required[/yellow]\n")
        console.print(f"  [dim]Account ID:[/dim] {MOCK_IDENTITY['account_id']} [dim](simulated)[/dim]")
        console.print(f"  [dim]Region:[/dim]     {MOCK_IDENTITY['region']} [dim](simulated)[/dim]\n")
        findings = sorted(MOCK_FINDINGS, key=lambda f: (f.severity_rank, f.service, f.check_id))
        console.print(f"  Done. {len(findings)} findings.\n")
        _print_findings(findings)
        if args.output:
            generate_report(MOCK_IDENTITY, findings, args.output)
            console.print(f"  [green]Report saved:[/green] {args.output}\n")
        return

    # ── Live mode ──────────────────────────────────────────────────────────────
    from src.scanner import run_scan

    region = args.region or "us-east-1"
    profile = args.profile or None
    url = getattr(args, "url", None) or None

    # URL-only mode: no AWS credentials needed
    url_only = url and not profile and not _has_aws_credentials()

    session = None
    if not url_only:
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
        except Exception as e:
            console.print(f"[red]Failed to create boto3 session: {e}[/red]")
            sys.exit(1)

    if url_only:
        console.print(f"  [yellow]No AWS credentials found — running web/DNS checks only[/yellow]")
    else:
        console.print(f"  [dim]Account:[/dim]  resolving...")
        console.print(f"  [dim]Region:[/dim]   {region}")
        console.print(f"  [dim]Profile:[/dim]  {profile or 'default'}")
    if url:
        console.print(f"  [dim]URL:[/dim]      {url}")
    console.print()

    def on_module(service_name: str):
        console.print(f"  [cyan]>[/cyan] Scanning {service_name}...", end="\r")

    try:
        identity, findings = run_scan(session, region, url=url, progress_callback=on_module)
    except NoCredentialsError:
        console.print("\n[red]No AWS credentials found.[/red]")
        console.print("Configure credentials via:")
        console.print("  • Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
        console.print("  • ~/.aws/credentials (aws configure)")
        console.print("  • IAM role (EC2/ECS/Lambda instance profile)")
        if not url:
            sys.exit(1)
        findings = []
        identity = {"account_id": "n/a", "arn": "n/a", "region": region}
    except ClientError as e:
        console.print(f"\n[red]AWS API error: {e}[/red]")
        sys.exit(1)

    if not url_only:
        console.print(f"\n  [dim]Account ID:[/dim] {identity['account_id']}")
        console.print(f"  [dim]Identity:[/dim]   {identity['arn']}")
    console.print(f"\n  Done. {len(findings)} findings.\n")

    _print_findings(findings)

    if args.output:
        generate_report(identity, findings, args.output)
        console.print(f"  [green]Report saved:[/green] {args.output}\n")


def _cmd_checks(_args):
    _print_banner()
    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold white",
    )
    table.add_column("Check ID",  style="dim", width=14)
    table.add_column("Severity",  width=10)
    table.add_column("Title")

    for check_id, severity, title in CHECK_CATALOG:
        table.add_row(check_id, _severity_text(severity), title)

    console.print(table)
    console.print(f"  [dim]{len(CHECK_CATALOG)} checks across IAM, S3, EC2, RDS, CloudTrail, VPC[/dim]\n")


def main():
    parser = argparse.ArgumentParser(
        prog="aether",
        description="Aether — AWS Cloud Security Misconfiguration Scanner",
    )
    sub = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_p = sub.add_parser("scan", help="Scan an AWS account for misconfigurations")
    scan_p.add_argument(
        "--region", "-r",
        default="us-east-1",
        help="AWS region to scan for regional checks (default: us-east-1)",
    )
    scan_p.add_argument(
        "--profile", "-p",
        default=None,
        help="AWS credentials profile name (from ~/.aws/credentials)",
    )
    scan_p.add_argument(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="Write HTML report to FILE (e.g. reports/aether-report.html)",
    )
    scan_p.add_argument(
        "--url", "-u",
        default=None,
        metavar="URL",
        help="Target URL for web/DNS checks (e.g. https://mieza.ai). Can be used without AWS credentials.",
    )
    scan_p.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="Run against pre-built mock findings (no AWS credentials required)",
    )

    # checks subcommand
    checks_p = sub.add_parser("checks", help="List all available checks")

    args = parser.parse_args()

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "checks":
        _cmd_checks(args)
    else:
        parser.print_help()
        sys.exit(1)
