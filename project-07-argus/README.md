# Argus — Detection Rule Engine

> A Sigma-compatible Python detection rule engine that ingests structured log events, evaluates YAML-defined rules (stateless match, sliding-window threshold, and ordered sequence types), fires alerts with MITRE ATT&CK mapping, and generates a self-contained HTML detection report.

---

## What It Does

Argus reads a JSONL log file, evaluates every event against a directory of YAML detection rules, and produces both a live terminal alert table and an HTML report. It ships with 15 production-tuned rules covering the most common Linux attack patterns from initial access through persistence.

| Rule Type | How It Works | Example |
|---|---|---|
| **match** | Fires immediately on a single event matching field/value criteria | Execution of `nc`, `socat`, or `/etc/shadow` read |
| **threshold** | Fires when N+ matching events occur within a sliding time window, grouped by a correlation field | 5 SSH failures from the same source IP in 60 seconds |
| **sequence** | Fires when a defined chain of steps completes in order within a max time span, correlated on a shared field | Shadow file read followed by `nc` execution on the same host |

---

## Rule Library (15 Rules)

| ID | Title | Type | Level | MITRE Technique |
|---|---|---|---|---|
| argus-001 | SSH Brute Force | threshold | high | T1110.001 |
| argus-002 | Password Spray Attack | threshold | high | T1110.003 |
| argus-003 | Repeated Sudo Failure | threshold | medium | T1548.003 |
| argus-004 | New Local User Account Created | match | medium | T1136.001 |
| argus-005 | Cron Job Added or Modified | match | medium | T1053.003 |
| argus-006 | Sensitive Credential File Accessed | match | high | T1003.008 |
| argus-007 | Suspicious Process Execution | match | high | T1059.004 |
| argus-008 | Web Application Auth Brute Force | threshold | medium | T1110 |
| argus-009 | Potential C2 Beacon | threshold | medium | T1071.001 |
| argus-010 | Multiple Account Lockouts | threshold | medium | T1110 |
| argus-011 | SSH Lateral Movement Chain | sequence | critical | T1021.004 |
| argus-012 | Privilege Escalation via Sudo | sequence | high | T1548.003 |
| argus-013 | Credential Dump Pattern | sequence | critical | T1003.008 |
| argus-014 | Recon to Exploitation Chain | sequence | high | T1046 |
| argus-015 | Persistence Backdoor Chain | sequence | high | T1136.001 |

---

## Demo Output

Against the included `logs/demo_attack.log` (an 81-event, 15-phase attack simulation), Argus fires **25 alerts** spanning every tactic from initial access through persistence:

```
81 events processed, 25 alerts fired.

CRITICAL: 2   HIGH: 11   MEDIUM: 12   Total: 25

02:03:52  HIGH     SSH Brute Force                          T1110.001
02:04:30  CRITICAL SSH Lateral Movement Chain               T1021.004
02:05:00  HIGH     Password Spray Attack                    T1110.003
02:08:30  HIGH     Recon to Exploitation Chain              T1046
02:09:24  MEDIUM   Repeated Sudo Failure                    T1548.003
02:10:20  HIGH     Privilege Escalation via Sudo            T1548.003
02:10:40  HIGH     Sensitive Credential File Accessed       T1003.008
02:11:35  CRITICAL Credential Dump Pattern                  T1003.008
02:12:45  MEDIUM   Web Application Authentication Brute Force T1110
02:14:10  MEDIUM   Multiple Account Lockouts                T1110
02:24:55  MEDIUM   Potential C2 Beacon                      T1071.001
02:30:50  MEDIUM   New Local User Account Created           T1136.001
02:31:10  HIGH     Persistence Backdoor Chain               T1136.001
```

---

## Architecture

```
argus.py
└── src/
    ├── cli.py          # argparse entry point — scan and rules subcommands
    ├── engine.py       # Scan orchestrator — loads rules, feeds events to trackers
    ├── correlator.py   # ThresholdTracker, SequenceTracker, MatchTracker
    ├── rules.py        # YAML rule loader and selection_matches() field evaluator
    ├── parser.py       # JSONL log parser with multi-format timestamp support
    ├── reporter.py     # Self-contained dark-theme HTML report generator
    ├── models.py       # LogEvent and Alert dataclasses
    └── mitre.py        # MITRE ATT&CK technique lookup table

rules/
    argus-001-*.yml     # 15 detection rules (match / threshold / sequence)

logs/
    attack_simulation.py  # Generates the demo JSONL attack corpus
    demo_attack.log       # Pre-generated 81-event multi-stage attack log

reports/
    argus-demo.html       # Pre-generated HTML detection report
```

### Key Design Decisions

**Three rule types with a shared YAML schema** — All rules share the same base fields (`id`, `title`, `tags`, `logsource`, `level`, `mitre`, `falsepositives`, `tuning_notes`). The `type` field routes the rule to the correct tracker. This mirrors Sigma's design philosophy and makes rules portable.

**Sigma-compatible field modifiers** — The `selection_matches()` function supports `|contains`, `|startswith`, and `|endswith` modifiers on field names, matching Sigma's transform syntax. List values are treated as OR conditions, matching standard Sigma semantics.

**Sliding-window threshold with de-duplication** — `ThresholdTracker` maintains a `deque` per `(rule_id, group_value)` key. On each new matching event, expired entries are evicted from the left. The tracker fires on first threshold breach, then fires again every N additional events using a `last_fired_count` sentinel — preventing re-alert on every single subsequent event while still surfacing escalating attacks.

**Per-correlate state machine for sequences** — `SequenceTracker` maintains a step index and event list per `(rule_id, correlate_value)`. Each step must match in order; if the `maxspan` window expires between steps, the state resets and the current event is retried as a potential new sequence start. This handles interleaved log streams from multiple sources cleanly.

**Self-contained HTML report** — `reporter.py` generates a dark-theme HTML file with no external dependencies. It includes an ATT&CK tactic breakdown grid, technique pills with links to attack.mitre.org, and a full alert timeline with collapsible evidence rows.

### Stack

- **Language:** Python 3.11+
- **Rule format:** YAML (Sigma-compatible schema)
- **Log format:** JSONL with ISO-8601 timestamps
- **Terminal UI:** `Rich` (styled tables, severity colouring)
- **Dependencies:** `pyyaml`, `rich` (stdlib only beyond these two)

---

## Usage

```bash
pip install -r requirements.txt

# Scan a log file with all rules
python argus.py scan logs/demo_attack.log

# Scan with HTML report output
python argus.py scan logs/demo_attack.log --output reports/my-report.html

# Use a custom rules directory
python argus.py scan logs/my-app.log --rules /path/to/rules --output report.html

# List all loaded rules
python argus.py rules

# Regenerate the demo attack log
python logs/attack_simulation.py
```

---

## Log Format

Argus expects JSONL (one JSON object per line). The only required field is `timestamp` (ISO-8601). All other fields are arbitrary — rule selections match against whatever keys are present in each event.

```jsonl
{"timestamp": "2026-05-13T02:03:52+00:00", "event_type": "auth_failure", "service": "sshd", "src_ip": "185.220.101.47", "dest_host": "web-prod-01", "user": "root"}
{"timestamp": "2026-05-13T02:04:30+00:00", "event_type": "auth_success", "service": "sshd", "src_ip": "185.220.101.47", "dest_host": "web-prod-01", "user": "deploy"}
{"timestamp": "2026-05-13T02:10:40+00:00", "event_type": "file_access", "host": "web-prod-01", "file_path": "/etc/shadow", "access_type": "read"}
```

---

## Rule Format

Rules are YAML files. The `type` field determines which tracker handles the rule.

**Match rule** — fires on any single event matching the selection:
```yaml
type: match
detection:
  selection:
    event_type: user_created
  condition: selection
```

**Threshold rule** — fires when count events match within timewindow seconds:
```yaml
type: threshold
detection:
  selection:
    event_type: auth_failure
    service: sshd
  threshold:
    field: src_ip
    count: 5
    timewindow: 60
  condition: selection | threshold
```

**Sequence rule** — fires when steps complete in order within maxspan seconds:
```yaml
type: sequence
detection:
  sequence:
    steps: [shadow_read, exfil_process]
    correlate: host
    maxspan: 300
  shadow_read:
    event_type: file_access
    file_path|contains: /etc/shadow
  exfil_process:
    event_type: process_exec
    process: [nc, ncat, netcat, socat]
  condition: shadow_read then exfil_process
```

---

## Writing Custom Rules

1. Copy any existing rule as a template
2. Set a unique `id` (e.g. `argus-016`)
3. Define your `detection` block using the appropriate `type`
4. Map to a MITRE technique using the `mitre` block
5. Document `falsepositives` and `tuning_notes` — this is what separates production rules from toy examples

All rules in the `rules/` directory are loaded automatically at scan time.
