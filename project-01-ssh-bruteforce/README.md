# Project 01 — SSH Brute Force Detection & Response

## Overview
This project simulates and investigates an SSH brute-force attack against a Linux host. The attack was generated from a separate machine, analyzed using system authentication logs, and contained using Fail2Ban.

## Environment
- **Attacker:** Kali Linux
- **Target:** Ubuntu Linux
- **Service:** OpenSSH
- **Network:** Host-only VirtualBox lab

## Detection
- Analyzed `/var/log/auth.log` for repeated SSH authentication failures
- Identified attack source IP and targeted user account
- Correlated events over time to confirm brute-force behavior

## Response & Containment
- Enabled Fail2Ban SSH jail
- Automatically blocked the attacking IP at the firewall level
- Verified ban and safely removed it after investigation

## Artifacts
- `ssh_bruteforce_summary.sh` — Bash script to summarize failed SSH attempts
- `ssh_bruteforce_incident_report.md` — Incident report documenting analysis and response

## Skills Demonstrated
- Linux log analysis
- Bash scripting
- Incident response lifecycle
- Brute-force attack detection
- Host-based security controls (Fail2Ban)
- MITRE ATT&CK mapping (T1110 — Brute Force)
