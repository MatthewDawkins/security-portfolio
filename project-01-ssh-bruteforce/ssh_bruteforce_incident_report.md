# SSH Brute Force Attempt - Incident Report

## Summmary
A suspected SSH brute-force attack was detected against a Linux host.
MMultiple failed authentication attempts were observed targeting a single user account.

## Affected Host
- Host IP: 192.168.56.102
- Operating System: Ubuntu Linux
- Service: OpenSSH

# Attack Details
- Attack Type: SSH Brute Force
- Total Failed Login Attempts: 17
- Source IP Address: 192.168.56.101
- Target Username: md

## Evidence
Evidence was collected from '/var/log/auth.log' showing repeated
'Failed password' authentication events originating from the same source IP.

## Assessment
The activity is consistent with a brute-force authentication attempt.
No successful login was observed during the attack window.

# Recommendations
- Enable rate limiting or account lockout (e.g., Fail2Ban)
- Restrict SSH access by IP where possible
- Disable password authentication and require SSH keys
- Monitor authentication logs for repeated failures

# Timeline
- First failed login attempt: 2025-12-12 15:17:44 UTC
- Last failed login attempt: 2025-12-12 15:42:50 UTC
- Attack duration: Approximately 25 minutes

## Containment
Fail2ban was enabled on the affected host.
The attacking IP (192.168.56.101) was automatically banned after
repeated authentication failures, preventing futher SSH attempts.

## Conclusion
This incident involved a small-scale SSH brute-force attempt originating from a single source IP. The attack was detected  through log analysis, contained automatically using Fail2Ban, and did not result in any unauthorized access.

 The host remains secure, and no further action is reuqired at this time.
