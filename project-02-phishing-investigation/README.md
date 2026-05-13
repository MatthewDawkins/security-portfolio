# Project 02 — Phishing Email Investigation

## Overview
This project investigates a simulated phishing email by analyzing message headers, authentication results (SPF/DKIM/DMARC), sender infrastructure, and indicators of compromise (IOCs).

## Goals
- Extract and interpret email headers
- Identify suspicious sender/return-path details
- Validate SPF/DKIM/DMARC results
- Extract IOCs (domains, URLs, IPs, attachment hashes if present)
- Map findings to MITRE ATT&CK (T1566 — Phishing)
- Produce a short incident summary suitable for a SOC workflow

## Artifacts
- `phishing_incident_report.md` — investigation write-up
- `iocs.txt` — extracted indicators

## Skills Demonstrated
- Email header analysis
- SPF/DKIM/DMARC interpretation
- IOC extraction and documentation
- MITRE ATT&CK mapping (T1566 — Phishing)
- SOC triage workflow
