# Erebus — Web Vulnerability Scanner

> A modular Python web vulnerability scanner with a BFS crawler, six independent detection modules, and an HTML report generator — built from scratch to scan intentionally vulnerable targets for hands-on offensive security practice.

---

## What It Does

Erebus crawls a target web application, enumerates URLs and forms, then runs each active module against the collected surface. Results are displayed in a live terminal table and optionally exported as a self-contained HTML report.

| Module | Detects | Severity |
|---|---|---|
| **headers** | Missing/insecure HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server disclosure) | High / Medium / Low / Info |
| **exposure** | Exposed sensitive files and endpoints (.env, .git/config, wp-config.php, backup archives, SQL dumps, Spring Actuator, phpinfo) | Critical / High / Medium |
| **sqli** | Error-based SQL injection in URL parameters and form fields (6 payloads, 14 database error signatures across MySQL/Postgres/Oracle/SQLite/MSSQL) | High |
| **xss** | Reflected XSS in URL parameters and form fields (script tag probe, unescaped reflection check) | High |
| **traversal** | Path traversal in URL parameters (Unix and Windows payloads, file content signature matching) | Critical |
| **redirect** | Open redirects via 18 common redirect parameter names (Location header verification) | Medium |

---

## Architecture

```
erebus.py
└── src/
    ├── cli.py          # argparse entry point, banner, subcommands
    ├── crawler.py      # BFS same-origin crawler — collects URLs and forms
    ├── scanner.py      # Module orchestrator with Rich progress display
    ├── reporter.py     # Self-contained HTML report generator
    ├── models.py       # Finding dataclass, severity ranking
    └── modules/
        ├── base.py     # Abstract BaseModule (session, get/post helpers)
        ├── headers.py
        ├── exposure.py
        ├── sqli.py
        ├── xss.py
        ├── traversal.py
        └── redirect.py
```

### Key Design Decisions

**BFS same-origin crawler** — The crawler uses a deque-based BFS that normalizes URLs (strips fragments), enforces same-origin scoping, and extracts both anchor links and form definitions in a single pass. Forms are collected with full field metadata (name, type, default value) so every module can construct realistic requests without re-fetching pages.

**Module abstraction** — Each module extends `BaseModule`, which wraps the shared `requests.Session` and timeout config. Modules receive the pre-crawled URL list and form list and emit a list of `Finding` objects. This keeps modules stateless and independently testable, and makes the CLI module filter (`--modules`) trivial — it simply skips instantiation.

**Deduplication by (URL, parameter) key** — Both XSS and SQLi modules track a `seen` set of `(url, param)` or `(action, field)` tuples so that multiple payloads triggering the same injection point are collapsed into one finding. This keeps reports readable on high-surface targets.

**HTML reporter as a single file** — `reporter.py` generates a fully self-contained dark-theme HTML report with no external dependencies. The report embeds all CSS inline, making it easy to share or archive without a server.

### Stack

- **Language:** Python 3.11+
- **HTTP:** `requests` (shared session with custom User-Agent)
- **HTML parsing:** `BeautifulSoup4`
- **Terminal UI:** `Rich` (progress bar, live table, styled output)

---

## Installation

```bash
git clone https://github.com/MatthewDawkins/security-portfolio
cd project-05-erebus
pip install -r requirements.txt
```

## Usage

```bash
# Scan with default settings (all modules, 50 pages, HTML report)
python erebus.py scan http://target.example.com --output report.html

# Limit crawl depth and run specific modules only
python erebus.py scan http://target.example.com --max-pages 20 --modules headers,xss,sqli

# List available modules
python erebus.py modules
```

> **Authorization notice:** Only scan systems you own or have explicit written permission to test. Scanning without authorization is illegal.

---

## Demo: AltoroMutual Scan

**Target:** `demo.testfire.net` — AltoroMutual, an intentionally vulnerable banking application published by IBM/HCL as an authorized security testing target.

**Scope:** 50 URLs crawled, 50 forms discovered.

### Findings Summary

| Severity | Count | Findings |
|---|---|---|
| **HIGH** | 3 | Missing HSTS, Reflected XSS on `/search.jsp` (`query` field), Reflected XSS on `/sendFeedback` (`name` field) |
| **MEDIUM** | 2 | Missing Content-Security-Policy, Missing X-Frame-Options |
| **LOW** | 3 | Missing X-Content-Type-Options, Missing Referrer-Policy, Missing Permissions-Policy |
| **INFO** | 1 | Server version disclosure (`Apache-Coyote/1.1`) |

The two reflected XSS findings demonstrate that the application echoes unsanitized form input directly into the response body — a `<script>erebus_xss_probe</script>` probe injected into the `query` and `name` form fields was returned unescaped in the HTML response.

The missing HSTS header means browsers can be forced onto HTTP via a downgrade attack, enabling traffic interception on networks where the attacker controls the path.

Full report: [reports/altoro-report.html](reports/altoro-report.html)

---

## Skills Demonstrated

- Python application architecture (modular design, abstract base classes, dataclasses)
- Web security fundamentals: XSS, SQLi, path traversal, open redirect, clickjacking, header policy
- HTTP internals: request/response handling, session management, redirect detection, form enumeration
- Offensive tooling: crawler design, payload injection, signature-based detection
- Reporting: programmatic HTML generation, severity classification
- Authorized use of intentionally vulnerable applications for security research
