# Aether — AWS Cloud Security Scanner

> A Python CLI that scans AWS accounts for misconfigurations across IAM, S3, EC2, RDS, CloudTrail, and VPC — surfaces findings with severity rankings, MITRE ATT&CK mapping, and remediation guidance — and generates a self-contained dark-theme HTML report.

---

## What It Does

Aether calls the AWS API via boto3, evaluates the account configuration against 21 security checks, and produces a terminal findings table and an HTML report. Every finding includes a full description of the risk, actionable remediation steps, and a MITRE ATT&CK technique mapping where applicable.

| Service | Checks | Coverage |
|---|---|---|
| **IAM** | 6 | Root MFA, root access keys, users without MFA, stale access keys (90+ days), AdministratorAccess policy, weak password policy |
| **S3** | 4 | Public ACL, Block Public Access disabled, no server-side encryption, no versioning |
| **EC2** | 4 | SSH open to internet, RDP open to internet, all-traffic security group, unencrypted EBS volumes |
| **RDS** | 2 | Publicly accessible instance, unencrypted storage |
| **CloudTrail** | 3 | Not enabled in region, log file validation disabled, not multi-region |
| **VPC** | 2 | Default VPC in use, flow logs not enabled |

---

## Demo Output

Against the included mock dataset (simulating a small startup account with common misconfigurations):

```
21 findings.

CRITICAL: 4   HIGH: 8   MEDIUM: 7   LOW: 2   Total: 21

STR-IAM-001  CRITICAL  IAM          root                           Root Account MFA Not Enabled
STR-S3-001   CRITICAL  S3           acme-company-backups-2023      S3 Bucket Publicly Accessible via ACL
STR-EC2-003  CRITICAL  EC2          sg-0f3e2d1c4b (legacy-test)    Security Group Allows All Traffic from Internet
STR-RDS-001  CRITICAL  RDS          prod-mysql-01                  RDS Instance Publicly Accessible
STR-CT-001   HIGH      CloudTrail   eu-west-1                      CloudTrail Not Enabled in Region
STR-EC2-001  HIGH      EC2          sg-0a1b2c3d4e (web-servers)    Security Group Allows SSH from Internet
STR-IAM-005  HIGH      IAM          legacy-admin                   IAM User Has AdministratorAccess Policy
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
        ├── base.py     # BaseCheck ABC
        ├── iam.py      # 6 IAM checks
        ├── s3.py       # 4 S3 checks
        ├── ec2.py      # 4 EC2/security group checks
        ├── rds.py      # 2 RDS checks
        ├── cloudtrail.py # 3 CloudTrail checks
        └── vpc.py      # 2 VPC checks
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

# Live scan — uses default AWS credentials
python aether.py scan --output reports/my-account.html

# Specify region and credentials profile
python aether.py scan --region eu-west-1 --profile prod-readonly --output report.html

# List all available checks
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
