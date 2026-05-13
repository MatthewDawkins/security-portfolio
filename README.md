# Security Portfolio — Matthew Dawkins

Hands-on security projects spanning offensive tooling, browser security engineering, SOC analysis, incident response, and detection automation.

---

## Projects

### [Project 06 — Phronesis Adversary Simulation](./project-06-phronesis)
`Python` `Game Theory` `Nash Equilibrium` `Mieza GTO` `Security Decision Modelling`

A Python CLI that models attacker/defender security decisions as two-player normal-form games and solves them for Nash equilibria via the live Mieza GTO API. Four scenarios — patch management, honeypot placement, IDS sensitivity, and phishing training allocation — each produce a parameterisable mixed-strategy recommendation that is provably unexploitable against a rational adversary. Demonstrates applied game theory as a security decision-support tool.

**Demo:** [All-scenarios report](./project-06-phronesis/reports/phronesis-demo.html) — four Nash equilibria solved live against the Mieza GTO engine.

---

### [Project 05 — Erebus Web Vulnerability Scanner](./project-05-erebus)
`Python` `Web Security` `Offensive Tooling` `XSS` `SQLi` `Crawling`

A modular Python web vulnerability scanner built from scratch. Erebus crawls a target with a BFS same-origin crawler, then runs six independent detection modules (XSS, SQLi, path traversal, open redirect, header policy, sensitive file exposure) against the collected surface. Results are displayed in a live Rich terminal table and exported as a self-contained HTML report. Demonstrated against AltoroMutual (IBM/HCL's authorized vulnerable banking app), producing 9 findings including two confirmed reflected XSS vulnerabilities.

**Demo:** [AltoroMutual scan report](./project-05-erebus/reports/altoro-report.html) — 50 URLs, 3 HIGH, 2 MEDIUM, 3 LOW, 1 INFO.

---

### [Project 04 — Eidolon Browser Privacy Extension](./project-04-eidolon)
`TypeScript` `Chrome MV3` `Browser Security` `Fingerprinting` `Privacy`

A production-quality Chrome extension that blocks trackers, spoofs canvas fingerprints, and prevents WebRTC IP leaks. Built from scratch in TypeScript with Manifest V3 — covers network-layer blocking via `declarativeNetRequest`, CSP-bypassing MAIN world script injection via `chrome.scripting`, and per-session canvas noise using an LCG. Includes a live per-tab dashboard, popup, and settings page.

**Verified:** blocks trackers on CNN, changes canvas fingerprint each session, no WebRTC IP leak.

---

### [Project 01 — SSH Brute Force Detection & Response](./project-01-ssh-bruteforce)
`Linux` `Bash` `Fail2Ban` `Incident Response` `MITRE ATT&CK`

Simulated and investigated an SSH brute-force attack in a VirtualBox lab. Analyzed `/var/log/auth.log`, automated detection with a Bash summary script, and contained the attack with Fail2Ban. Documented findings in a structured incident report mapped to MITRE ATT&CK T1110.

---

### [Project 02 — Phishing Email Investigation](./project-02-phishing-investigation)
`Email Analysis` `SPF/DKIM/DMARC` `IOC Extraction` `MITRE ATT&CK`

Investigated a simulated phishing email by parsing headers, validating authentication results (SPF/DKIM/DMARC), identifying spoofing indicators, and extracting IOCs. Produced a structured incident summary following a SOC triage workflow, mapped to MITRE ATT&CK T1566.

---

### [Project 03 — Python SSH Log Parser](./project-03-python-log-parser)
`Python` `Log Analysis` `SOC Automation`

Built a Python script to parse Linux SSH authentication logs, detect repeated failed login attempts, aggregate activity by source IP and username, and output a structured report. Demonstrates automation of a common SOC detection workflow.

---

## Skills

| Area | Tools & Technologies |
|---|---|
| Game Theory / Decision Science | Nash equilibrium, mixed strategies, adversarial modelling, normal-form games |
| Offensive Tooling | Web vulnerability scanning, crawling, payload injection, XSS/SQLi/traversal detection |
| Security Engineering | Chrome MV3, TypeScript, browser APIs, fingerprinting mitigations |
| SOC Analysis | Log analysis, incident response, IOC extraction |
| Detection & Automation | Python, Bash, Fail2Ban, SIEM workflows |
| Frameworks | MITRE ATT&CK |
| Platforms | Linux, VirtualBox, Chrome |
