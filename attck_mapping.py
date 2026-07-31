"""
MITRE ATT&CK Mapping - Milestone 10
----------------------------------------
Maps the intent categories from analyzer.py (Milestone 9) onto real
MITRE ATT&CK tactic and technique IDs. This is the same framework real
SOC/threat-intel teams use to describe and communicate attacker
behavior in a standardized way. Reference: https://attack.mitre.org
"""

ATTCK_MAP = {
    "Reconnaissance": {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
    },
    "Download / Staging": {
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
    },
    "Privilege Escalation": {
        "tactic_id": "TA0004",
        "tactic_name": "Privilege Escalation",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
    },
    "Persistence": {
        "tactic_id": "TA0003",
        "tactic_name": "Persistence",
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
    },
    "Defense Evasion": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
    },
    "Destruction": {
        "tactic_id": "TA0040",
        "tactic_name": "Impact",
        "technique_id": "T1485",
        "technique_name": "Data Destruction",
    },
    "Uncategorized": {
        "tactic_id": "-",
        "tactic_name": "-",
        "technique_id": "-",
        "technique_name": "Unclassified behavior",
    },
}


def get_attck_info(category: str) -> dict:
    """Return the ATT&CK tactic/technique info for a given intent category."""
    return ATTCK_MAP.get(category, ATTCK_MAP["Uncategorized"])
