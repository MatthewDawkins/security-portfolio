# Security Portfolio — Matthew Dawkins

Hands-on security projects spanning browser security engineering, SOC analysis, incident response, and detection automation.

---

## Projects

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
| Security Engineering | Chrome MV3, TypeScript, browser APIs, fingerprinting mitigations |
| SOC Analysis | Log analysis, incident response, IOC extraction |
| Detection & Automation | Python, Bash, Fail2Ban, SIEM workflows |
| Frameworks | MITRE ATT&CK |
| Platforms | Linux, VirtualBox, Chrome |
