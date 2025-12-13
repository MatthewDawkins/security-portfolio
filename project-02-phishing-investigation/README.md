# Project 02 - Phising Email Investigation

## Overview
This project investigates a simulated phishing email by analyzing message headers, auth results (SPF/DKIM/DMARC), sender infrastructure, and indicators of compromise (IOCs).

## Goals
- Extract and interpret email headers
- Identify suspicious sender/return-path details
- Validate SPF/DKIM/DMARC results
- Extract IOCs (domains, URLs, IPs, attachment hashes if present)
- Map findings to MITRE ATT&CK (T1566 - Phishing)
- Produce a short incident summmary suitable for a SOC workflow

## Artifacts
- 'phishing_incident_report.md' - investigation write-up
- 'iocs.txt' - extracted indicators
