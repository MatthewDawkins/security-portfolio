# MITRE ATT&CK technique reference for techniques used in Vigil rules.
# Source: https://attack.mitre.org

TECHNIQUES: dict = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/004/",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1003.008": {
        "name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/008/",
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1021/004/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1083/",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1136/001/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
}


def lookup(technique_id: str) -> dict:
    return TECHNIQUES.get(technique_id, {
        "name": technique_id,
        "tactic": "Unknown",
        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
    })
