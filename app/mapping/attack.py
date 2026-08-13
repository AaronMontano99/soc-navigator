"""MITRE ATT&CK Enterprise technique metadata used to annotate alerts/incidents.

Kept as a small local lookup (not a live API call) so the app runs fully
offline. IDs and names are drawn from the public ATT&CK Enterprise matrix
(https://attack.mitre.org/matrices/enterprise/).
"""

from __future__ import annotations

ATTACK_TECHNIQUES: dict[str, dict[str, str]] = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
    },
    "T1110.004": {
        "name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/004/",
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    "T1567.002": {
        "name": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1567/002/",
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
    },
}


def describe(technique_id: str) -> dict[str, str]:
    return ATTACK_TECHNIQUES.get(
        technique_id, {"name": technique_id, "tactic": "Unknown", "url": ""}
    )


def tactics_for(technique_ids: list[str]) -> list[str]:
    seen: list[str] = []
    for tid in technique_ids:
        tactic = describe(tid)["tactic"]
        if tactic not in seen:
            seen.append(tactic)
    return seen
