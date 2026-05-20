# Aether — AWS & Web Security Scanner + Bill C-22 Compliance Module

> A Python CLI that scans AWS accounts and web/DNS infrastructure for misconfigurations — and includes a dedicated Bill C-22 (Lawful Access Act) compliance module that identifies metadata collection, tracking, and data residency risks for Canadian electronic service providers. Every finding is severity-ranked with actionable remediation guidance.

---

## What It Does

Aether covers three scan surfaces: AWS infrastructure (via boto3), web/DNS configuration (live HTTP/TLS/DNS probes), and Bill C-22 compliance (metadata and privacy controls). Every finding includes a full risk description, remediation steps, and MITRE ATT&CK mapping where applicable.

| Surface | Checks | Coverage |
|---|---|---|
| **IAM** | 6 | Root MFA, root access keys, users without MFA, stale access keys (90+ days), AdministratorAccess policy, weak password policy |
| **S3** | 4 | Public ACL, Block Public Access disabled, no server-side encryption, no versioning |
| **EC2** | 4 | SSH open to internet, RDP open to internet, all-traffic security group, unencrypted EBS volumes |
| **RDS** | 2 | Publicly accessible instance, unencrypted storage |
| **CloudTrail** | 3 | Not enabled in region, log file validation disabled, not multi-region |
| **VPC** | 2 | Default VPC in use, flow logs not enabled |
| **Web** | 8 | HTTPS enforcement, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, server disclosure, CORS wildcard, TLS expiry |
| **DNS** | 3 | SPF, DMARC, CAA records |
| **C-22** | 6 | Referrer-Policy, third-party trackers, persistent cookies, geolocation permissions, privacy policy, CDN data residency |

---

## Bill C-22 Compliance Module

Bill C-22 (the *Lawful Access Act*, introduced March 2026) requires Canadian electronic service providers to retain transmission metadata for up to one year and build technical capabilities for law enforcement access on demand. The C-22 module helps businesses understand what metadata they currently collect, what third parties receive it, and where privacy controls are missing.

| Check ID | Severity | What It Detects |
|---|---|---|
| C22-WEB-001 | HIGH | Missing or permissive Referrer-Policy — navigation URL data leaking to third parties |
| C22-WEB-002 | HIGH | Third-party tracking scripts (Google Analytics, Meta Pixel, Hotjar, etc.) loading user metadata |
| C22-WEB-003 | HIGH | Persistent cookies (30+ day max-age) without SameSite=Strict — retained user identifiers |
| C22-WEB-004 | HIGH | Geolocation API unrestricted via Permissions-Policy — location metadata collectible by scripts |
| C22-WEB-005 | MEDIUM | No accessible privacy policy page — transparency obligations not met |
| C22-WEB-006 | INFO | US-based CDN/infrastructure detected — cross-border data residency risk |

The C-22 module runs automatically whenever a `--url` is provided. No AWS credentials required.

---

## Demo Output

Against the included mock dataset (simulating a startup account with common misconfigurations + C-22 exposure):

```
26 findings.

CRITICAL: 4   HIGH: 11   MEDIUM: 8   LOW: 2   INFO: 1   Total: 26

STR-IAM-001  CRITICAL  IAM    root              Root Account MFA Not Enabled
STR-S3-001   CRITICAL  S3     acme-backups      S3 Bucket Publicly Accessible via ACL
STR-EC2-003  CRITICAL  EC2    sg-0f3e2d1c4b     Security Group Allows All Traffic from Internet
STR-RDS-001  CRITICAL  RDS    prod-mysql-01     RDS Instance Publicly Accessible
C22-WEB-001  HIGH      C-22   acme-corp.ca      Missing or Permissive Referrer-Policy Header
C22-WEB-002  HIGH      C-22   acme-corp.ca      Third-Party Tracking Scripts Detected
C22-WEB-004  HIGH      C-22   acme-corp.ca      Geolocation API Not Restricted
C22-WEB-005  MEDIUM    C-22   acme-corp.ca      No Accessible Privacy Policy Page Detected
C22-WEB-006  INFO      C-22   acme-corp.ca      Third-Party Infrastructure: Cloudflare (US-based CDN)
...
```

**Demo report:** [aether-demo.html](./reports/aether-demo.html)

---

## Architecture

```
aether.py
└── src/
    ├── cli.py          # argparse entry point — scan (live + mock) and checks subcommands
    ├── scanner.py      # Orchestrates all check modules, calls STS for identity
    ├── reporter.py     # Self-contained dark-theme HTML report generator
    ├── models.py       # Finding dataclass with severity ranking
    ├── mock.py         # Pre-built findings for demo mode (no credentials required)
    └── checks/
        ├── base.py       # BaseCheck ABC
        ├── iam.py        # 6 IAM checks
        ├── s3.py         # 4 S3 checks
        ├── ec2.py        # 4 EC2/security group checks
        ├── rds.py        # 2 RDS checks
        ├── cloudtrail.py # 3 CloudTrail checks
        ├── vpc.py        # 2 VPC checks
        ├── web.py        # 8 web/TLS/header checks
        ├── dns.py        # 3 DNS checks (SPF, DMARC, CAA)
        └── c22.py        # 6 Bill C-22 compliance checks
```

### Key Design Decisions

**Per-module check isolation** — Each service module extends `BaseCheck` and returns a list of `Finding` objects. All boto3 `ClientError` exceptions are caught at the module level so a missing IAM permission or an empty region doesn't abort the entire scan. The scanner orchestrator calls every module and aggregates results regardless of partial failures.

**Mock mode for offline demo** — `--mock` flag bypasses all AWS API calls and uses `src/mock.py`, a curated set of pre-built findings that represent a realistic misconfigured account. This makes the tool demonstrable in any environment, and the mock data documents exactly what the checks look for.

**MITRE ATT&CK mapping on findings** — Findings that correspond to known attacker techniques include `mitre_technique`, `mitre_tactic`, and `mitre_name` fields. The HTML report renders these as linked pills pointing to attack.mitre.org. This aligns the output with SOC/detection team workflows and makes findings actionable in a threat-modelling context.

**Severity-first sorting** — Findings are sorted by `(severity_rank, service, check_id)` so the most critical items always appear at the top of both the terminal output and the HTML report. Security teams should triage in severity order.

**Self-contained HTML report** — All CSS is inlined, there are no external dependencies. Each finding is a `<details>` element — collapsed by default, expanded on click — keeping the report readable even with many findings.

### Stack

- **Language:** Python 3.11+
- **AWS SDK:** `boto3` / `botocore`
- **Terminal UI:** `Rich`
- **IAM permissions required:** `SecurityAudit` managed policy (read-only)

---

## Usage

```bash
pip install -r requirements.txt

# Demo mode — no credentials required
python aether.py scan --mock

# Demo mode with HTML report
python aether.py scan --mock --output reports/aether-demo.html

# Bill C-22 compliance scan — URL only, no AWS credentials needed
python aether.py scan --url https://yoursite.ca --output reports/c22-report.html

# Full scan: AWS + web/DNS + C-22
python aether.py scan --url https://yoursite.ca --region ca-central-1 --profile prod-readonly --output report.html

# Live scan — uses default AWS credentials
python aether.py scan --output reports/my-account.html

# Specify region and credentials profile
python aether.py scan --region eu-west-1 --profile prod-readonly --output report.html

# List all available checks (including C-22 module)
python aether.py checks
```

---

## AWS Credentials

Aether uses the standard boto3 credential chain — no configuration needed if you're already set up:

1. **Environment variables:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
2. **Shared credentials file:** `~/.aws/credentials` (configured via `aws configure`)
3. **IAM role:** Automatically used on EC2, ECS, Lambda, or any instance with an attached role

For a read-only security audit, attach the `SecurityAudit` AWS managed policy to the IAM user or role running the scan.

---

## Adding Custom Checks

1. Create a new module in `src/checks/` extending `BaseCheck`
2. Implement `run(session, region) -> List[Finding]`
3. Import and add the class to `CHECK_MODULES` in `src/scanner.py`
4. Add entries to `CHECK_CATALOG` in `src/cli.py` for the `checks` subcommand

All `ClientError` exceptions should be caught within the module — never let a single API call abort the scan.
